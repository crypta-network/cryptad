package network.crypta.runtime.updater;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringJoiner;
import java.util.TreeMap;
import java.util.regex.Pattern;
import network.crypta.runtime.spi.CoreSupportLifecycleStatus;

/**
 * Strict parser and structural validator for authenticated Stable 1.0 lifecycle descriptors.
 *
 * <p>The parser accepts only schema version 1, the exact closed field sets, canonical UTC
 * timestamps, lowercase public digests, integer build tags, and the configured trusted update-key
 * binding. Unknown fields and lifecycle states fail closed. It performs no network access and does
 * not interpret build lifecycle revocation as update-key revocation.
 *
 * <p>Cross-edition rollback, fork, release-identity, and transition checks are handled by {@link
 * CoreSupportLifecycleState}; this class validates one exact byte sequence in isolation.
 */
public final class CoreSupportLifecycleParser {
  /** Maximum descriptor size accepted by runtime parsing and persistence. */
  public static final int MAX_DESCRIPTOR_BYTES = 1024 * 1024;

  private static final int MAX_ENTRIES = 256;
  private static final int MAX_PUBLIC_IDS = 64;
  private static final int MAX_TEXT_LENGTH = 256;
  private static final Pattern DIGEST = Pattern.compile("sha256:[0-9a-f]{64}");
  private static final Pattern RELEASE_ID = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,127}");
  private static final Pattern SOURCE_COMMIT = Pattern.compile("[0-9a-f]{40,64}");
  private static final Pattern PUBLIC_ID = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}");
  private static final String SCHEMA_VERSION_FIELD = "schemaVersion";
  private static final String PREVIOUS_DESCRIPTOR_EDITION_FIELD = "previousDescriptorEdition";
  private static final String PREVIOUS_DESCRIPTOR_DIGEST_FIELD = "previousDescriptorDigest";
  private static final String RECOVERY_GUIDANCE_FIELD = "recoveryGuidance";
  private static final String SECURITY_REVOCATION_EFFECTIVE_AT_FIELD =
      "securityRevocationEffectiveAt";
  private static final String DESCRIPTOR_DIGEST_FIELD = "descriptorDigest";
  private static final Set<String> DESCRIPTOR_FIELDS =
      Set.of(
          SCHEMA_VERSION_FIELD,
          "kind",
          "stableMilestone",
          "descriptorEdition",
          PREVIOUS_DESCRIPTOR_EDITION_FIELD,
          PREVIOUS_DESCRIPTOR_DIGEST_FIELD,
          "ledgerDigest",
          "inventoryDigest",
          "currentStableBuild",
          "minimumSupportedBuild",
          "minimumSecuritySupportedBuild",
          "recommendedBuild",
          "generatedAt",
          "effectiveAt",
          "staleAt",
          "updateKeyIdentityDigest",
          "updateKeyScope",
          "updateKeyDocName",
          "entries",
          "redaction",
          DESCRIPTOR_DIGEST_FIELD);
  private static final Set<String> ENTRY_FIELDS =
      Set.of(
          "releaseId",
          "buildVersion",
          "tag",
          "sourceCommit",
          "productDigest",
          "publicationReceiptDigest",
          "baselineDigest",
          "publishedAt",
          "lifecycleStatus",
          "statusEffectiveAt",
          "fullSupportUntil",
          "securityFixesUntil",
          "deprecationEffectiveAt",
          "endOfSupportAt",
          SECURITY_REVOCATION_EFFECTIVE_AT_FIELD,
          "replacementBuild",
          RECOVERY_GUIDANCE_FIELD,
          "advisoryIds",
          "reasonCodes");

  /**
   * Parses one fetched descriptor and binds it to the exact trusted fetch context.
   *
   * @param bytes exact immutable descriptor bytes returned from the update-key fetch
   * @param fetchedEdition actual USK edition used to fetch the document
   * @param trust expected public update-key identity digest, normalized scope, and docname
   * @return fully validated immutable descriptor carrying the exact-byte SHA-256 digest
   * @throws IllegalArgumentException if syntax, schema, identity, cardinality, or timing is invalid
   */
  public CoreSupportLifecycleDescriptor parse(
      byte[] bytes, long fetchedEdition, TrustBinding trust) {
    if (fetchedEdition <= 0) {
      throw invalid("descriptor edition must be positive");
    }
    return parseInternal(bytes, fetchedEdition, trust);
  }

  /** Parses a persisted exact-byte descriptor whose edition is carried inside the document. */
  CoreSupportLifecycleDescriptor parsePersisted(byte[] bytes, TrustBinding trust) {
    return parseInternal(bytes, null, trust);
  }

  private CoreSupportLifecycleDescriptor parseInternal(
      byte[] bytes, Long fetchedEdition, TrustBinding trust) {
    if (bytes == null || bytes.length == 0 || bytes.length > MAX_DESCRIPTOR_BYTES) {
      throw invalid("descriptor byte length is outside runtime bounds");
    }
    Map<String, Object> root = JsonMini.parseObject(decodeUtf8(bytes));
    requireExactFields(root, DESCRIPTOR_FIELDS, "descriptor");

    int schemaVersion = requiredSchemaVersion(root);
    if (schemaVersion != 1) {
      throw invalid("unsupported lifecycle descriptor schema");
    }
    String kind = requiredText(root, "kind");
    if (!"stable-1.0-support-lifecycle-descriptor".equals(kind)) {
      throw invalid("unexpected lifecycle descriptor kind");
    }
    String milestone = requiredText(root, "stableMilestone");
    if (!"1.0".equals(milestone)) {
      throw invalid("unexpected stable milestone");
    }
    long edition = requiredLong(root, "descriptorEdition");
    if (edition <= 0 || (fetchedEdition != null && edition != fetchedEdition)) {
      throw invalid("descriptor edition does not match fetched edition");
    }
    Long previousEdition = optionalPreviousDescriptorEdition(root);
    String previousDigest = optionalPreviousDescriptorDigest(root);
    validatePredecessorShape(edition, previousEdition, previousDigest);

    String ledgerDigest = requiredDigest(root, "ledgerDigest");
    String inventoryDigest = requiredDigest(root, "inventoryDigest");
    Integer currentStableBuild = optionalBuild(root, "currentStableBuild");
    Integer minimumSupportedBuild = optionalBuild(root, "minimumSupportedBuild");
    Integer minimumSecuritySupportedBuild = optionalBuild(root, "minimumSecuritySupportedBuild");
    Integer recommendedBuild = optionalBuild(root, "recommendedBuild");
    Instant generatedAt = requiredInstant(root, "generatedAt");
    Instant effectiveAt = requiredInstant(root, "effectiveAt");
    Instant staleAt = requiredInstant(root, "staleAt");
    if (generatedAt.isAfter(effectiveAt) || effectiveAt.isAfter(staleAt)) {
      throw invalid("descriptor timestamps are not ordered");
    }

    TrustBinding expected = java.util.Objects.requireNonNull(trust, "trust");
    String identityDigest = requiredDigest(root, "updateKeyIdentityDigest");
    String scope = requiredText(root, "updateKeyScope");
    String docName = requiredText(root, "updateKeyDocName");
    if (!identityDigest.equals(expected.updateKeyIdentityDigest())
        || !scope.equals(expected.updateKeyScope())
        || !docName.equals(expected.updateKeyDocName())) {
      throw invalid("descriptor update-key binding does not match configured scope");
    }
    validateRedaction(root.get("redaction"));
    String descriptorDigest = requiredDigest(root, DESCRIPTOR_DIGEST_FIELD);
    TreeMap<String, Object> semanticValue = new TreeMap<>(root);
    semanticValue.remove(DESCRIPTOR_DIGEST_FIELD);
    if (!descriptorDigest.equals(semanticDigest(semanticValue))) {
      throw invalid("descriptor semantic digest is invalid");
    }

    List<CoreSupportLifecycleEntry> entries = parseEntries(root.get("entries"));
    validateEntryActivationTimes(entries, effectiveAt);
    validateInventory(
        entries,
        currentStableBuild,
        recommendedBuild,
        minimumSupportedBuild,
        minimumSecuritySupportedBuild);
    return new CoreSupportLifecycleDescriptor(
        schemaVersion,
        kind,
        milestone,
        edition,
        previousEdition,
        previousDigest,
        ledgerDigest,
        inventoryDigest,
        currentStableBuild,
        minimumSupportedBuild,
        minimumSecuritySupportedBuild,
        recommendedBuild,
        generatedAt,
        effectiveAt,
        staleAt,
        identityDigest,
        scope,
        docName,
        entries,
        descriptorDigest,
        exactBytesDigest(bytes));
  }

  private static List<CoreSupportLifecycleEntry> parseEntries(Object value) {
    if (!(value instanceof List<?> raw) || raw.isEmpty() || raw.size() > MAX_ENTRIES) {
      throw invalid("descriptor entries must be a nonempty bounded array");
    }
    ArrayList<CoreSupportLifecycleEntry> entries = new ArrayList<>(raw.size());
    for (Object item : raw) {
      if (!(item instanceof Map<?, ?> untyped)) {
        throw invalid("descriptor entry must be an object");
      }
      @SuppressWarnings("unchecked")
      Map<String, Object> map = (Map<String, Object>) untyped;
      requireExactFields(map, ENTRY_FIELDS, "descriptor entry");
      entries.add(parseEntry(map));
    }
    return List.copyOf(entries);
  }

  private static void validateEntryActivationTimes(
      List<CoreSupportLifecycleEntry> entries, Instant descriptorEffectiveAt) {
    if (entries.stream()
        .anyMatch(entry -> entry.statusEffectiveAt().isAfter(descriptorEffectiveAt))) {
      throw invalid("entry lifecycle status is future-effective at descriptor activation");
    }
  }

  private static CoreSupportLifecycleEntry parseEntry(Map<String, Object> map) {
    String releaseId = requiredMatchingText(map, "releaseId", RELEASE_ID);
    int build = positiveBuild(map, "buildVersion");
    String tag = requiredText(map, "tag");
    if (!tag.equals("v" + build)) {
      throw invalid("entry tag does not match integer build");
    }
    String sourceCommit = requiredMatchingText(map, "sourceCommit", SOURCE_COMMIT);
    String productDigest = requiredDigest(map, "productDigest");
    String receiptDigest = requiredDigest(map, "publicationReceiptDigest");
    String baselineDigest = requiredDigest(map, "baselineDigest");
    Instant publishedAt = requiredInstant(map, "publishedAt");
    CoreSupportLifecycleStatus status =
        CoreSupportLifecycleStatus.fromWireValue(requiredText(map, "lifecycleStatus"))
            .orElseThrow(() -> invalid("unknown lifecycle status"));
    Instant statusEffectiveAt = requiredInstant(map, "statusEffectiveAt");
    Instant fullSupportUntil = requiredInstant(map, "fullSupportUntil");
    Instant securityFixesUntil = requiredInstant(map, "securityFixesUntil");
    Instant deprecationEffectiveAt = requiredInstant(map, "deprecationEffectiveAt");
    Instant endOfSupportAt = requiredInstant(map, "endOfSupportAt");
    Instant securityRevocationEffectiveAt = optionalSecurityRevocationEffectiveAt(map);
    Integer replacementBuild = optionalBuild(map, "replacementBuild");
    String recoveryGuidance = optionalRecoveryGuidance(map);
    List<String> advisoryIds = publicIds(map, "advisoryIds");
    List<String> reasonCodes = publicIds(map, "reasonCodes");
    validateEntryTimes(
        publishedAt,
        statusEffectiveAt,
        fullSupportUntil,
        securityFixesUntil,
        deprecationEffectiveAt,
        endOfSupportAt,
        securityRevocationEffectiveAt);
    validateStatusGuidance(
        status,
        replacementBuild,
        recoveryGuidance,
        advisoryIds,
        reasonCodes,
        securityRevocationEffectiveAt);
    return new CoreSupportLifecycleEntry(
        releaseId,
        build,
        tag,
        sourceCommit,
        productDigest,
        receiptDigest,
        baselineDigest,
        publishedAt,
        status,
        statusEffectiveAt,
        fullSupportUntil,
        securityFixesUntil,
        deprecationEffectiveAt,
        endOfSupportAt,
        securityRevocationEffectiveAt,
        replacementBuild,
        recoveryGuidance,
        advisoryIds,
        reasonCodes);
  }

  private static void validatePredecessorShape(
      long edition, Long previousEdition, String previousDigest) {
    if (edition == 1) {
      if (previousEdition != null || previousDigest != null) {
        throw invalid("root descriptor must not claim a predecessor");
      }
      return;
    }
    if (previousEdition == null || previousEdition != edition - 1 || previousDigest == null) {
      throw invalid("descriptor predecessor is not the immediate prior edition");
    }
  }

  private static void validateInventory(
      List<CoreSupportLifecycleEntry> entries,
      Integer currentStableBuild,
      Integer recommendedBuild,
      Integer minimumSupportedBuild,
      Integer minimumSecuritySupportedBuild) {
    InventoryScan inventory = scanInventory(entries, currentStableBuild);
    CoreSupportLifecycleEntry tip = entries.getLast();
    if (tip.lifecycleStatus() == CoreSupportLifecycleStatus.REVOKED) {
      validateRevokedChainTip(
          entries, tip, inventory.currentCount(), currentStableBuild, recommendedBuild);
    } else {
      validateActiveChainTip(
          entries,
          inventory.tipBuild(),
          inventory.currentCount(),
          currentStableBuild,
          recommendedBuild);
    }
    validateReplacementBuilds(entries);
    validateMinimumBuilds(inventory.builds(), minimumSupportedBuild, minimumSecuritySupportedBuild);
  }

  private static InventoryScan scanInventory(
      List<CoreSupportLifecycleEntry> entries, Integer currentStableBuild) {
    HashSet<Integer> builds = new HashSet<>();
    int previousBuild = 0;
    int currentCount = 0;
    for (CoreSupportLifecycleEntry entry : entries) {
      if (!builds.add(entry.buildVersion()) || entry.buildVersion() <= previousBuild) {
        throw invalid("descriptor builds are duplicated or not strictly increasing");
      }
      previousBuild = entry.buildVersion();
      if (entry.lifecycleStatus() == CoreSupportLifecycleStatus.CURRENT_STABLE) {
        currentCount++;
        if (!java.util.Objects.equals(entry.buildVersion(), currentStableBuild)) {
          throw invalid("current-stable entry does not match descriptor current build");
        }
      }
    }
    return new InventoryScan(Set.copyOf(builds), previousBuild, currentCount);
  }

  private static void validateRevokedChainTip(
      List<CoreSupportLifecycleEntry> entries,
      CoreSupportLifecycleEntry tip,
      int currentCount,
      Integer currentStableBuild,
      Integer recommendedBuild) {
    if (currentCount != 0 || currentStableBuild != null) {
      throw invalid("revoked chain tip must not claim a safe current build");
    }
    if (!java.util.Objects.equals(recommendedBuild, tip.replacementBuild())) {
      throw invalid("revoked chain-tip recommendation must equal its safe replacement");
    }
    if (recommendedBuild != null && !containsSecuritySupportedBuild(entries, recommendedBuild)) {
      throw invalid("revoked chain-tip replacement is not a supported published build");
    }
    validateEmergencyRecoveryProjection(entries, tip, recommendedBuild);
  }

  private static boolean containsSecuritySupportedBuild(
      List<CoreSupportLifecycleEntry> entries, int build) {
    return entries.stream()
        .anyMatch(
            entry -> entry.buildVersion() == build && isSecuritySupported(entry.lifecycleStatus()));
  }

  private static void validateActiveChainTip(
      List<CoreSupportLifecycleEntry> entries,
      int tipBuild,
      int currentCount,
      Integer currentStableBuild,
      Integer recommendedBuild) {
    if (currentCount != 1 || !java.util.Objects.equals(currentStableBuild, tipBuild)) {
      throw invalid("descriptor must identify exactly one chain-tip current-stable build");
    }
    if (!java.util.Objects.equals(recommendedBuild, currentStableBuild)) {
      throw invalid("recommended build must equal authenticated current stable build");
    }
    if (entries.stream().anyMatch(entry -> entry.recoveryGuidance() != null)) {
      throw invalid("recovery-only guidance requires a revoked chain tip");
    }
  }

  private static void validateMinimumBuilds(
      Set<Integer> builds, Integer minimumSupportedBuild, Integer minimumSecuritySupportedBuild) {
    if (minimumSupportedBuild != null && !builds.contains(minimumSupportedBuild)) {
      throw invalid("minimum supported build is not in release inventory");
    }
    if (minimumSecuritySupportedBuild != null && !builds.contains(minimumSecuritySupportedBuild)) {
      throw invalid("minimum security-supported build is not in release inventory");
    }
    if (minimumSupportedBuild != null
        && minimumSecuritySupportedBuild != null
        && minimumSecuritySupportedBuild > minimumSupportedBuild) {
      throw invalid("security-supported minimum cannot exceed fully supported minimum");
    }
  }

  private static void validateEntryTimes(
      Instant publishedAt,
      Instant statusEffectiveAt,
      Instant fullSupportUntil,
      Instant securityFixesUntil,
      Instant deprecationEffectiveAt,
      Instant endOfSupportAt,
      Instant securityRevocationEffectiveAt) {
    if (deadlinePredatesPublication(
        publishedAt,
        statusEffectiveAt,
        fullSupportUntil,
        securityFixesUntil,
        deprecationEffectiveAt,
        endOfSupportAt,
        securityRevocationEffectiveAt)) {
      throw invalid("entry lifecycle deadline predates publication");
    }
    validateDeadlineOrder(
        fullSupportUntil, securityFixesUntil, deprecationEffectiveAt, endOfSupportAt);
  }

  private static boolean deadlinePredatesPublication(
      Instant publishedAt, Instant... lifecycleDates) {
    for (Instant lifecycleDate : lifecycleDates) {
      if (lifecycleDate != null && lifecycleDate.isBefore(publishedAt)) {
        return true;
      }
    }
    return false;
  }

  private static void validateDeadlineOrder(
      Instant fullSupportUntil,
      Instant securityFixesUntil,
      Instant deprecationEffectiveAt,
      Instant endOfSupportAt) {
    if (isBefore(securityFixesUntil, fullSupportUntil)) {
      throw invalid("security-fix deadline predates full-support deadline");
    }
    if (isBefore(endOfSupportAt, deprecationEffectiveAt)) {
      throw invalid("end-of-support predates deprecation");
    }
    if (isBefore(endOfSupportAt, securityFixesUntil)) {
      throw invalid("end-of-support predates security-fix deadline");
    }
  }

  private static boolean isBefore(Instant value, Instant reference) {
    return value != null && reference != null && value.isBefore(reference);
  }

  private static boolean isSecuritySupported(CoreSupportLifecycleStatus status) {
    return status == CoreSupportLifecycleStatus.CURRENT_STABLE
        || status == CoreSupportLifecycleStatus.SUPPORTED_MAINTENANCE
        || status == CoreSupportLifecycleStatus.SECURITY_FIXES_ONLY;
  }

  private static void validateEmergencyRecoveryProjection(
      List<CoreSupportLifecycleEntry> entries,
      CoreSupportLifecycleEntry tip,
      Integer recommendedBuild) {
    String recoveryGuidance = tip.recoveryGuidance();
    if (recommendedBuild != null && recoveryGuidance != null) {
      throw invalid("revoked chain tip cannot mix a safe replacement with recovery-only guidance");
    }
    for (CoreSupportLifecycleEntry entry : entries) {
      if (entry.buildVersion() == tip.buildVersion()
          || entry.lifecycleStatus() == CoreSupportLifecycleStatus.REVOKED
          || entry.recoveryGuidance() == null) {
        continue;
      }
      if (recommendedBuild != null
          || entry.replacementBuild() != null
          || !java.util.Objects.equals(entry.recoveryGuidance(), recoveryGuidance)) {
        throw invalid("non-tip recovery guidance does not match the revoked chain tip");
      }
    }
  }

  private static void validateReplacementBuilds(List<CoreSupportLifecycleEntry> entries) {
    for (CoreSupportLifecycleEntry entry : entries) {
      Integer replacementBuild = entry.replacementBuild();
      if (replacementBuild == null) {
        continue;
      }
      CoreSupportLifecycleEntry replacement =
          entries.stream()
              .filter(candidate -> candidate.buildVersion() == replacementBuild)
              .findFirst()
              .orElseThrow(() -> invalid("replacement build is outside the published inventory"));
      if (replacement.buildVersion() == entry.buildVersion()
          || !isSecuritySupported(replacement.lifecycleStatus())) {
        throw invalid("replacement build is not an authenticated security-supported release");
      }
    }
  }

  private static void validateStatusGuidance(
      CoreSupportLifecycleStatus status,
      Integer replacementBuild,
      String recoveryGuidance,
      List<String> advisoryIds,
      List<String> reasonCodes,
      Instant securityRevocationEffectiveAt) {
    if (status == CoreSupportLifecycleStatus.REVOKED) {
      if (advisoryIds.isEmpty()
          || reasonCodes.isEmpty()
          || (replacementBuild == null && recoveryGuidance == null)
          || (replacementBuild != null && recoveryGuidance != null)
          || securityRevocationEffectiveAt == null) {
        throw invalid("revoked build lacks public advisory, reason, or safe recovery guidance");
      }
    } else if (securityRevocationEffectiveAt != null) {
      throw invalid("non-revoked build carries security revocation metadata");
    }
    if ((status == CoreSupportLifecycleStatus.DEPRECATED
            || status == CoreSupportLifecycleStatus.END_OF_SUPPORT)
        && replacementBuild == null
        && recoveryGuidance == null) {
      throw invalid("deprecated or unsupported build lacks replacement guidance");
    }
  }

  private static String decodeUtf8(byte[] bytes) {
    try {
      return StandardCharsets.UTF_8
          .newDecoder()
          .onMalformedInput(CodingErrorAction.REPORT)
          .onUnmappableCharacter(CodingErrorAction.REPORT)
          .decode(ByteBuffer.wrap(bytes))
          .toString();
    } catch (CharacterCodingException e) {
      throw invalid("descriptor is not canonical UTF-8", e);
    }
  }

  private static void requireExactFields(
      Map<String, Object> value, Set<String> expected, String label) {
    if (!value.keySet().equals(expected)) {
      throw invalid(label + " fields do not match the closed schema");
    }
  }

  private static int requiredSchemaVersion(Map<String, Object> map) {
    long value = requiredLong(map, SCHEMA_VERSION_FIELD);
    if (value < Integer.MIN_VALUE || value > Integer.MAX_VALUE) {
      throw invalid(SCHEMA_VERSION_FIELD + " is outside integer range");
    }
    return (int) value;
  }

  private static int positiveBuild(Map<String, Object> map, String field) {
    String text = requiredText(map, field);
    if (!text.matches("[1-9]\\d*")) {
      throw invalid(field + " must be a canonical decimal build string");
    }
    int value;
    try {
      value = Integer.parseInt(text);
    } catch (NumberFormatException e) {
      throw invalid(field + " is outside integer build range", e);
    }
    if (value <= 0) {
      throw invalid(field + " must be positive");
    }
    return value;
  }

  private static Integer optionalBuild(Map<String, Object> map, String field) {
    Object value = map.get(field);
    if (value == null) {
      return null;
    }
    return positiveBuild(map, field);
  }

  private static long requiredLong(Map<String, Object> map, String field) {
    Object value = map.get(field);
    if (!(value instanceof Long number)) {
      throw invalid(field + " must be an integer");
    }
    return number;
  }

  private static Long optionalPreviousDescriptorEdition(Map<String, Object> map) {
    Object value = map.get(PREVIOUS_DESCRIPTOR_EDITION_FIELD);
    if (value == null) {
      return null;
    }
    return requiredLong(map, PREVIOUS_DESCRIPTOR_EDITION_FIELD);
  }

  private static String requiredText(Map<String, Object> map, String field) {
    Object value = map.get(field);
    if (!(value instanceof String text)
        || text.isBlank()
        || text.length() > MAX_TEXT_LENGTH
        || containsUnsafeText(text)) {
      throw invalid(field + " must be bounded safe text");
    }
    return text;
  }

  private static String optionalRecoveryGuidance(Map<String, Object> map) {
    return map.get(RECOVERY_GUIDANCE_FIELD) == null
        ? null
        : requiredText(map, RECOVERY_GUIDANCE_FIELD);
  }

  private static String requiredMatchingText(
      Map<String, Object> map, String field, Pattern pattern) {
    String value = requiredText(map, field);
    if (!pattern.matcher(value).matches()) {
      throw invalid(field + " has a noncanonical value");
    }
    return value;
  }

  private static boolean containsUnsafeText(String text) {
    int length = text.length();
    for (int offset = 0; offset < length; offset += Character.charCount(text.codePointAt(offset))) {
      int codePoint = text.codePointAt(offset);
      if (Character.isISOControl(codePoint)
          || Character.getType(codePoint) == Character.FORMAT
          || Character.isSurrogate(text.charAt(offset))) {
        return true;
      }
    }
    return false;
  }

  private static String requiredDigest(Map<String, Object> map, String field) {
    String value = requiredText(map, field);
    if (!DIGEST.matcher(value).matches()) {
      throw invalid(field + " must be a normalized SHA-256 digest");
    }
    return value;
  }

  private static String optionalPreviousDescriptorDigest(Map<String, Object> map) {
    return map.get(PREVIOUS_DESCRIPTOR_DIGEST_FIELD) == null
        ? null
        : requiredDigest(map, PREVIOUS_DESCRIPTOR_DIGEST_FIELD);
  }

  private static Instant requiredInstant(Map<String, Object> map, String field) {
    String value = requiredText(map, field);
    try {
      Instant parsed = Instant.parse(value);
      if (!parsed.toString().equals(value)) {
        throw invalid(field + " must be a canonical UTC timestamp");
      }
      return parsed;
    } catch (DateTimeParseException e) {
      throw invalid(field + " must be a canonical UTC timestamp", e);
    }
  }

  private static Instant optionalSecurityRevocationEffectiveAt(Map<String, Object> map) {
    return map.get(SECURITY_REVOCATION_EFFECTIVE_AT_FIELD) == null
        ? null
        : requiredInstant(map, SECURITY_REVOCATION_EFFECTIVE_AT_FIELD);
  }

  private static List<String> publicIds(Map<String, Object> map, String field) {
    Object value = map.get(field);
    if (!(value instanceof List<?> raw) || raw.size() > MAX_PUBLIC_IDS) {
      throw invalid(field + " must be a bounded array");
    }
    ArrayList<String> result = new ArrayList<>(raw.size());
    for (Object item : raw) {
      if (!(item instanceof String text)
          || containsUnsafeText(text)
          || !PUBLIC_ID.matcher(text).matches()) {
        throw invalid(field + " contains an invalid public identifier");
      }
      result.add(text);
    }
    if (new LinkedHashSet<>(result).size() != result.size()
        || !result.equals(result.stream().sorted(Comparator.naturalOrder()).toList())) {
      throw invalid(field + " must be sorted and unique");
    }
    return List.copyOf(result);
  }

  private static void validateRedaction(Object value) {
    if (!(value instanceof Map<?, ?> redaction)
        || !redaction.keySet().equals(Set.of("status", "findingCount", "findings"))
        || !"pass".equals(redaction.get("status"))
        || !Long.valueOf(0L).equals(redaction.get("findingCount"))
        || !(redaction.get("findings") instanceof List<?> findings)
        || !findings.isEmpty()) {
      throw invalid("descriptor redaction result is not the closed passing shape");
    }
  }

  /** Returns normalized SHA-256 for an exact byte sequence. */
  public static String exactBytesDigest(byte[] bytes) {
    try {
      return "sha256:"
          + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 is unavailable", e);
    }
  }

  static String semanticDigest(Object value) {
    return exactBytesDigest(canonicalJson(value).getBytes(StandardCharsets.UTF_8));
  }

  static String canonicalJson(Object value) {
    if (value == null) {
      return "null";
    }
    if (value instanceof String text) {
      return quoteJson(text);
    }
    if (value instanceof Number || value instanceof Boolean) {
      return value.toString();
    }
    if (value instanceof Map<?, ?> map) {
      TreeMap<String, Object> sorted = new TreeMap<>();
      map.forEach((key, item) -> sorted.put(String.valueOf(key), item));
      StringJoiner fields = new StringJoiner(",", "{", "}");
      sorted.forEach((key, item) -> fields.add(quoteJson(key) + ":" + canonicalJson(item)));
      return fields.toString();
    }
    if (value instanceof List<?> list) {
      StringJoiner items = new StringJoiner(",", "[", "]");
      list.forEach(item -> items.add(canonicalJson(item)));
      return items.toString();
    }
    throw invalid("descriptor contains a non-JSON semantic value");
  }

  private static String quoteJson(String value) {
    StringBuilder output = new StringBuilder(value.length() + 2).append('"');
    for (int index = 0; index < value.length(); index++) {
      char character = value.charAt(index);
      switch (character) {
        case '"' -> output.append("\\\"");
        case '\\' -> output.append("\\\\");
        case '\b' -> output.append("\\b");
        case '\f' -> output.append("\\f");
        case '\n' -> output.append("\\n");
        case '\r' -> output.append("\\r");
        case '\t' -> output.append("\\t");
        default -> {
          if (character < 0x20) {
            output.append(String.format("\\u%04x", (int) character));
          } else {
            output.append(character);
          }
        }
      }
    }
    return output.append('"').toString();
  }

  private static IllegalArgumentException invalid(String message) {
    return new IllegalArgumentException(message);
  }

  private static IllegalArgumentException invalid(String message, Exception cause) {
    return new IllegalArgumentException(message, cause);
  }

  private record InventoryScan(Set<Integer> builds, int tipBuild, int currentCount) {}

  /**
   * Expected public update-key binding supplied by {@link NodeUpdateManager} for one parse.
   *
   * @param updateKeyIdentityDigest lowercase SHA-256 of configured public USK key material
   * @param updateKeyScope normalized public USK scope ending in edition zero
   * @param updateKeyDocName exact descriptor docname, currently {@code support-lifecycle}
   */
  public record TrustBinding(
      String updateKeyIdentityDigest, String updateKeyScope, String updateKeyDocName) {
    /** Validates that all three trust-binding fields are nonblank. */
    public TrustBinding {
      if (updateKeyIdentityDigest == null
          || updateKeyIdentityDigest.isBlank()
          || updateKeyScope == null
          || updateKeyScope.isBlank()
          || updateKeyDocName == null
          || updateKeyDocName.isBlank()) {
        throw new IllegalArgumentException("lifecycle trust binding must be complete");
      }
    }
  }
}
