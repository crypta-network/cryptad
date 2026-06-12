package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Immutable registry of reviewer public keys trusted by the current node.
 *
 * <p>The registry is the lookup table used by {@link AppReviewReceiptVerifier} after a receipt has
 * passed catalog-entry binding and expiry checks. It maps reviewer key ids from receipt payloads to
 * {@link TrustedReviewerKey} values that can verify Ed25519 signatures over canonical receipt
 * payload bytes.
 *
 * <p>This is a review trust registry only. It does not trust catalog publishers, app bundle
 * signers, or artifact digests, and it does not make a receipt positive by itself. A trusted
 * reviewer can sign a {@code reviewed}, {@code caution}, or {@code rejected} receipt; the verifier
 * and local {@link AppReviewPolicy} convert that evidence into install and update decisions.
 *
 * <p>The registry is immutable and fail-closed. Duplicate key ids, unsupported algorithms,
 * incomplete property blocks, and non-contiguous file entries are rejected at load time so callers
 * cannot accidentally verify a receipt against an ambiguous or partially configured trust source.
 * Public key bytes remain inside this verification layer and are not included in API summaries.
 */
public final class TrustedReviewerKeys {
  private static final Pattern REVIEWER_PROPERTY_PATTERN =
      Pattern.compile(
          "reviewer\\.(\\d+)\\.(id|algorithm|public\\.key\\.base64|display\\.name|policy\\.id|"
              + "policy\\.version|status|valid\\.from|valid\\.until|revoked\\.at|"
              + "revocation\\.reason|rotates\\.from|rotates\\.to)");
  private static final TrustedReviewerKeys EMPTY = new TrustedReviewerKeys(1, Map.of(), List.of());
  private static final String DUPLICATE_KEY_ID_MESSAGE_PREFIX =
      "duplicate trusted reviewer key id: ";
  private static final String REVIEWER_ENTRY_PREFIX = "reviewer.";
  private static final String REVIEW_REVOCATIONS_PROPERTY = "review.revocations";

  private final int registryVersion;
  private final Map<String, TrustedReviewerKey> keysById;
  private final List<AppReviewReceiptRevocation> receiptRevocations;

  private TrustedReviewerKeys(
      int registryVersion,
      Map<String, TrustedReviewerKey> keysById,
      List<AppReviewReceiptRevocation> receiptRevocations) {
    this.registryVersion = registryVersion;
    this.keysById = Map.copyOf(keysById);
    this.receiptRevocations = List.copyOf(receiptRevocations);
  }

  /**
   * Creates a trusted reviewer registry from a collection.
   *
   * <p>The input order is preserved for deterministic diagnostics, but lookup semantics are by
   * reviewer key id. Two keys with the same id are rejected even if their public key bytes are
   * identical, because duplicate ids would make receipt verification and audit output ambiguous.
   *
   * @param keys reviewer keys to index by id
   * @return immutable reviewer-key registry
   */
  public static TrustedReviewerKeys of(Collection<TrustedReviewerKey> keys) {
    Objects.requireNonNull(keys, "keys");
    Map<String, TrustedReviewerKey> byId = new LinkedHashMap<>();
    for (TrustedReviewerKey key : keys) {
      TrustedReviewerKey trustedKey = Objects.requireNonNull(key, "key");
      TrustedReviewerKey previous = byId.putIfAbsent(trustedKey.keyId(), trustedKey);
      if (previous != null) {
        throw AppCatalogSidecars.invalidEntry(DUPLICATE_KEY_ID_MESSAGE_PREFIX + trustedKey.keyId());
      }
    }
    return new TrustedReviewerKeys(1, byId, List.of());
  }

  /**
   * Creates a registry from individual reviewer keys.
   *
   * <p>This convenience factory is used by tests and direct configuration paths that construct one
   * or a few keys in memory. It applies the same duplicate-id checks as {@link #of(Collection)}.
   *
   * @param keys reviewer keys to trust
   * @return immutable reviewer-key registry
   */
  public static TrustedReviewerKeys of(TrustedReviewerKey... keys) {
    return of(Arrays.asList(keys));
  }

  /**
   * Returns an empty reviewer-key registry.
   *
   * <p>An empty registry is a valid local configuration. It causes review receipt evaluation to
   * report {@link AppReviewTrustStatus#NOT_CONFIGURED} instead of treating publisher advisory
   * metadata as trusted review evidence.
   *
   * @return shared empty registry
   */
  public static TrustedReviewerKeys empty() {
    return EMPTY;
  }

  /**
   * Loads trusted reviewer keys from a local properties sidecar.
   *
   * <p>The file supports {@code trusted.reviewers.version=1} and contiguous {@code reviewer.N.*}
   * entries with {@code id}, {@code algorithm}, {@code public.key.base64}, and optional {@code
   * display.name} and {@code policy.id} fields. Version {@code 2} also accepts policy-version and
   * lifecycle governance fields. Indexes may start at either {@code 0} or {@code 1} so operator
   * examples can use human-friendly numbering while tests can mirror existing app-key fixtures.
   *
   * <p>Only the Ed25519 review receipt algorithm is accepted. Unknown properties, unsupported
   * algorithms, duplicate ids, and incomplete key entries fail the whole load rather than producing
   * a partially trusted registry. The file contains public key material only; private reviewer keys
   * belong in offline signing workflows and are never read here.
   *
   * @param trustedReviewerKeysFile local reviewer-key properties file
   * @return parsed reviewer-key registry
   * @throws IOException if the file cannot be read
   */
  public static TrustedReviewerKeys load(Path trustedReviewerKeysFile) throws IOException {
    byte[] bytes =
        AppCatalogSidecars.readRequiredBytes(
            trustedReviewerKeysFile,
            AppCatalogSidecars.MAX_SIGNATURE_BYTES,
            "trusted reviewer keys file",
            AppCatalogSidecars.INVALID_CATALOG_ENTRY);
    Map<String, String> properties =
        AppCatalogSidecars.parseKeyValueSidecar(
            AppCatalogSidecars.utf8(bytes), "trusted reviewer keys file");
    int version = validateVersion(properties.remove("trusted.reviewers.version"));
    SortedMap<Integer, TrustedReviewerKeyBuilder> builders = readBuilders(properties);
    List<AppReviewReceiptRevocation> receiptRevocations =
        version >= 3 ? readReceiptRevocations(properties) : List.of();
    if (!properties.isEmpty()) {
      throw AppCatalogSidecars.invalidEntry(
          "unsupported trusted reviewer keys property: " + properties.keySet().iterator().next());
    }
    return buildKeys(version, builders, receiptRevocations);
  }

  /**
   * Looks up a reviewer key by id.
   *
   * <p>A missing result is a trust decision input, not an exceptional parser failure. The verifier
   * reports it as an unknown reviewer so API, Web Shell, CLI, and release-certification surfaces
   * can explain that the receipt may be well-formed but is not trusted by this node.
   *
   * @param keyId reviewer key id from a receipt payload
   * @return matching trusted reviewer key, when configured
   */
  public Optional<TrustedReviewerKey> find(String keyId) {
    return Optional.ofNullable(keysById.get(keyId));
  }

  /**
   * Returns whether no reviewer keys are configured.
   *
   * <p>This distinguishes "no local review trust configured" from "a receipt named an unknown key."
   * Both are untrusted outcomes, but they are reported differently so operators know whether to add
   * a trust registry or investigate an unexpected reviewer id.
   *
   * @return {@code true} when this registry is empty
   */
  public boolean isEmpty() {
    return keysById.isEmpty();
  }

  /**
   * Returns the trusted-reviewer registry format version.
   *
   * @return registry version parsed from the properties file, or {@code 1} for programmatic keys
   */
  public int registryVersion() {
    return registryVersion;
  }

  /**
   * Returns configured reviewer keys without exposing public key material through JSON helpers.
   *
   * <p>The returned key objects still contain public verifier material for in-process verification,
   * so callers must use {@link #summaries()} for API, Web Shell, CLI, or certification output.
   *
   * @return configured reviewer keys sorted by key id for deterministic output
   */
  public List<TrustedReviewerKey> all() {
    return keysById.values().stream()
        .sorted(Comparator.comparing(TrustedReviewerKey::keyId))
        .toList();
  }

  /**
   * Returns configured receipt revocations sorted in registry order.
   *
   * @return exact receipt revocation entries
   */
  public List<AppReviewReceiptRevocation> receiptRevocations() {
    return receiptRevocations;
  }

  /**
   * Finds the local revocation entry for a receipt, when configured.
   *
   * @param receipt receipt to evaluate
   * @return matching revocation entry
   */
  public Optional<AppReviewReceiptRevocation> findReceiptRevocation(AppReviewReceipt receipt) {
    Objects.requireNonNull(receipt, "receipt");
    return receiptRevocations.stream()
        .filter(revocation -> revocation.matches(receipt))
        .findFirst();
  }

  /**
   * Returns redacted reviewer-key summaries.
   *
   * @return key summaries sorted by key id
   */
  public List<TrustedReviewerKeySummary> summaries() {
    return all().stream().map(TrustedReviewerKeySummary::from).toList();
  }

  /**
   * Returns a redacted summary of the registry.
   *
   * @return registry version, lifecycle counts, and warnings
   */
  public TrustedReviewerRegistrySummary summary() {
    LinkedHashMap<String, Integer> counts = LinkedHashMap.newLinkedHashMap(3);
    counts.put("active", count(TrustedReviewerKeyStatus.ACTIVE));
    counts.put("retired", count(TrustedReviewerKeyStatus.RETIRED));
    counts.put("revoked", count(TrustedReviewerKeyStatus.REVOKED));
    return new TrustedReviewerRegistrySummary(
        !isEmpty(), registryVersion, counts, receiptRevocations.size(), registryWarnings());
  }

  /**
   * Returns a new registry with one additional reviewer key.
   *
   * <p>The existing registry is not modified. This is used by configuration loading to combine a
   * properties-file registry with one direct key from system properties or environment variables
   * while preserving duplicate-id validation.
   *
   * @param key reviewer key to add
   * @return combined immutable registry
   */
  public TrustedReviewerKeys plus(TrustedReviewerKey key) {
    Map<String, TrustedReviewerKey> combined = new LinkedHashMap<>(keysById);
    TrustedReviewerKey trustedKey = Objects.requireNonNull(key, "key");
    TrustedReviewerKey previous = combined.putIfAbsent(trustedKey.keyId(), trustedKey);
    if (previous != null) {
      throw AppCatalogSidecars.invalidEntry(DUPLICATE_KEY_ID_MESSAGE_PREFIX + trustedKey.keyId());
    }
    return new TrustedReviewerKeys(registryVersion, combined, receiptRevocations);
  }

  private int count(TrustedReviewerKeyStatus status) {
    int count = 0;
    for (TrustedReviewerKey key : keysById.values()) {
      if (key.status() == status) {
        count++;
      }
    }
    return count;
  }

  private List<String> registryWarnings() {
    List<String> warnings = new ArrayList<>();
    for (TrustedReviewerKey key : all()) {
      warnings.addAll(
          key.lifecycle().warnings().stream()
              .map(warning -> key.keyId() + ": " + warning)
              .toList());
      key.lifecycle()
          .rotatesFrom()
          .filter(id -> !keysById.containsKey(id))
          .ifPresent(_ -> warnings.add(key.keyId() + ": rotatesFrom key is not configured."));
      key.lifecycle()
          .rotatesTo()
          .filter(id -> !keysById.containsKey(id))
          .ifPresent(_ -> warnings.add(key.keyId() + ": rotatesTo key is not configured."));
    }
    return List.copyOf(warnings);
  }

  private static int validateVersion(String versionText) {
    if (versionText == null) {
      throw AppCatalogSidecars.invalidEntry("missing trusted.reviewers.version");
    }
    try {
      int version = Integer.parseInt(versionText);
      if (version != 1 && version != 2 && version != 3) {
        throw AppCatalogSidecars.invalidEntry("unsupported trusted.reviewers.version: " + version);
      }
      return version;
    } catch (NumberFormatException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY,
          "invalid trusted.reviewers.version: " + versionText,
          exception);
    }
  }

  private static SortedMap<Integer, TrustedReviewerKeyBuilder> readBuilders(
      Map<String, String> properties) {
    SortedMap<Integer, TrustedReviewerKeyBuilder> builders = new TreeMap<>();
    List<String> keys = properties.keySet().stream().toList();
    for (String propertyName : keys) {
      Matcher matcher = REVIEWER_PROPERTY_PATTERN.matcher(propertyName);
      if (!matcher.matches()) {
        continue;
      }
      int index = parseIndex(matcher.group(1), propertyName);
      TrustedReviewerKeyBuilder builder =
          builders.computeIfAbsent(index, _ -> new TrustedReviewerKeyBuilder());
      setField(builder, matcher.group(2), properties.remove(propertyName));
    }
    return builders;
  }

  private static TrustedReviewerKeys buildKeys(
      int version,
      SortedMap<Integer, TrustedReviewerKeyBuilder> builders,
      List<AppReviewReceiptRevocation> receiptRevocations) {
    if (builders.isEmpty()) {
      return new TrustedReviewerKeys(version, Map.of(), receiptRevocations);
    }
    int start = builders.firstKey();
    if (start != 0 && start != 1) {
      throw AppCatalogSidecars.invalidEntry("trusted reviewer keys must start at index 0 or 1");
    }
    List<TrustedReviewerKey> keys = new ArrayList<>(builders.size());
    for (int offset = 0; offset < builders.size(); offset++) {
      int index = start + offset;
      TrustedReviewerKeyBuilder builder = builders.get(index);
      if (builder == null) {
        throw AppCatalogSidecars.invalidEntry("trusted reviewer keys must use contiguous indexes");
      }
      keys.add(buildKey(version, builder, index));
    }
    Map<String, TrustedReviewerKey> byId = new LinkedHashMap<>();
    for (TrustedReviewerKey key : keys) {
      TrustedReviewerKey previous = byId.putIfAbsent(key.keyId(), key);
      if (previous != null) {
        throw AppCatalogSidecars.invalidEntry(DUPLICATE_KEY_ID_MESSAGE_PREFIX + key.keyId());
      }
    }
    return new TrustedReviewerKeys(version, byId, receiptRevocations);
  }

  private static List<AppReviewReceiptRevocation> readReceiptRevocations(
      Map<String, String> properties) {
    String rawIds = properties.remove(REVIEW_REVOCATIONS_PROPERTY);
    if (rawIds == null || rawIds.isBlank()) {
      return List.of();
    }
    List<String> ids = parseReceiptRevocationIds(rawIds);
    List<AppReviewReceiptRevocation> revocations = new ArrayList<>(ids.size());
    Map<String, AppReviewReceiptRevocation> byFingerprint = new LinkedHashMap<>();
    for (String id : ids) {
      String prefix = "review.revocation." + id + ".";
      AppReviewReceiptRevocation revocation =
          new AppReviewReceiptRevocation(
              id,
              removeRequired(properties, prefix + "receiptFingerprintSha256"),
              removeRequired(properties, prefix + "appId"),
              removeRequired(properties, prefix + "appVersion"),
              removeRequired(properties, prefix + "bundleSha256"),
              removeRequired(properties, prefix + "reviewerKeyId"),
              parseOptionalInstant(
                  removeRequired(properties, prefix + "revokedAt"), prefix + "revokedAt"),
              removeRequired(properties, prefix + "reason"));
      AppReviewReceiptRevocation previous =
          byFingerprint.putIfAbsent(revocation.receiptFingerprintSha256(), revocation);
      if (previous != null) {
        throw AppCatalogSidecars.invalidEntry(
            "duplicate review receipt revocation fingerprint: "
                + revocation.receiptFingerprintSha256());
      }
      revocations.add(revocation);
    }
    return List.copyOf(revocations);
  }

  private static List<String> parseReceiptRevocationIds(String rawIds) {
    List<String> ids = new ArrayList<>();
    java.util.LinkedHashSet<String> unique = new java.util.LinkedHashSet<>();
    for (String token : rawIds.split(",", -1)) {
      String id = AppCatalogSecurityAdvisory.normalizeId(token.trim(), REVIEW_REVOCATIONS_PROPERTY);
      if (!unique.add(id)) {
        throw AppCatalogSidecars.invalidEntry("duplicate review revocation id: " + id);
      }
      ids.add(id);
    }
    return List.copyOf(ids);
  }

  private static String removeRequired(Map<String, String> properties, String key) {
    String value = properties.remove(key);
    if (value == null) {
      throw AppCatalogSidecars.invalidEntry("missing " + key);
    }
    return value;
  }

  private static TrustedReviewerKey buildKey(
      int registryVersion, TrustedReviewerKeyBuilder builder, int index) {
    if (builder.id == null || builder.algorithm == null || builder.publicKeyBase64 == null) {
      throw AppCatalogSidecars.invalidEntry("trusted reviewer key " + index + " is incomplete");
    }
    if (!TrustedReviewerKey.SIGNATURE_ALGORITHM.equals(builder.algorithm)) {
      throw AppCatalogSidecars.invalidEntry(
          "unsupported trusted reviewer key algorithm: " + builder.algorithm);
    }
    if (registryVersion == 1 && builder.hasV2Fields()) {
      throw AppCatalogSidecars.invalidEntry(
          "trusted reviewer key " + index + " uses v2 fields in a v1 registry");
    }
    TrustedReviewerKeyStatus status =
        builder.status == null
            ? TrustedReviewerKeyStatus.ACTIVE
            : TrustedReviewerKeyStatus.parse(builder.status);
    TrustedReviewerKeyLifecycle lifecycle =
        TrustedReviewerKeyLifecycle.of(
            status,
            parseOptionalInstant(builder.validFrom, reviewerFieldName(index, "valid.from")),
            parseOptionalInstant(builder.validUntil, reviewerFieldName(index, "valid.until")),
            parseOptionalInstant(builder.revokedAt, reviewerFieldName(index, "revoked.at")),
            builder.revocationReason,
            builder.rotatesFrom,
            builder.rotatesTo);
    return TrustedReviewerKey.ed25519(
        builder.id,
        builder.publicKeyBase64,
        builder.displayName,
        builder.policyId,
        builder.policyVersion,
        lifecycle);
  }

  private static Instant parseOptionalInstant(String value, String fieldName) {
    if (value == null) {
      return null;
    }
    try {
      return Instant.parse(value);
    } catch (DateTimeParseException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY,
          "invalid " + fieldName + ": " + value,
          exception);
    }
  }

  private static String reviewerFieldName(int index, String fieldName) {
    return REVIEWER_ENTRY_PREFIX + index + "." + fieldName;
  }

  private static int parseIndex(String rawIndex, String propertyName) {
    try {
      return Integer.parseInt(rawIndex);
    } catch (NumberFormatException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY,
          "invalid trusted reviewer key entry index in " + propertyName,
          exception);
    }
  }

  private static void setField(TrustedReviewerKeyBuilder builder, String field, String value) {
    switch (field) {
      case "id" -> builder.id = value;
      case "algorithm" -> builder.algorithm = value;
      case "public.key.base64" -> builder.publicKeyBase64 = value;
      case "display.name" -> builder.displayName = value;
      case "policy.id" -> builder.policyId = value;
      case "policy.version" -> builder.policyVersion = value;
      case "status" -> builder.status = value;
      case "valid.from" -> builder.validFrom = value;
      case "valid.until" -> builder.validUntil = value;
      case "revoked.at" -> builder.revokedAt = value;
      case "revocation.reason" -> builder.revocationReason = value;
      case "rotates.from" -> builder.rotatesFrom = value;
      case "rotates.to" -> builder.rotatesTo = value;
      default -> throw new IllegalArgumentException("unsupported trusted reviewer key field");
    }
  }

  private static final class TrustedReviewerKeyBuilder {
    private String id;
    private String algorithm;
    private String publicKeyBase64;
    private String displayName;
    private String policyId;
    private String policyVersion;
    private String status;
    private String validFrom;
    private String validUntil;
    private String revokedAt;
    private String revocationReason;
    private String rotatesFrom;
    private String rotatesTo;

    private boolean hasV2Fields() {
      return policyVersion != null
          || status != null
          || validFrom != null
          || validUntil != null
          || revokedAt != null
          || revocationReason != null
          || rotatesFrom != null
          || rotatesTo != null;
    }
  }
}
