package network.crypta.platform.appcatalog;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * One redacted local review transparency log record.
 *
 * <p>Records are hash-chained over canonical fields. They intentionally contain only display-safe
 * review identifiers, policy metadata, artifact digest/size, evidence digest/URI, and trust
 * outcomes. They never include raw public keys, private keys, local paths, request bodies, browser
 * sessions, process tokens, or receipt signatures.
 *
 * <p>This record is both the in-memory value and the JSONL persistence contract for the local
 * transparency log. Store implementations assign sequence, creation time, previous hash, and record
 * hash when appending a draft. Verification recomputes the canonical text from these normalized
 * fields, so parser validation must fail closed for unsupported fields, malformed values, and type
 * mismatches instead of silently normalizing tampered lines.
 *
 * <p>The format is local to one host. A valid hash chain proves that the local log file is
 * internally consistent; it does not prove global publication or consensus. Callers should pair a
 * record with the current {@link AppReviewTrustDecision} when explaining why an installation or
 * update is trusted, cautioned, rejected, or blocked.
 *
 * @param schemaVersion local record schema version, currently {@link #SCHEMA_VERSION}
 * @param sequence one-based append sequence, or {@code 0} for an unchained draft
 * @param recordId stable record identifier, assigned from kind and sequence when absent
 * @param createdAt append time assigned by the store, or {@code null} for drafts
 * @param kind stable event kind describing why this record was written
 * @param subjectType redacted subject category such as {@code app}
 * @param appId app id from the receipt, entry, or update candidate
 * @param appVersion app version from the receipt, entry, or update candidate
 * @param catalogId local catalog id associated with the evaluated candidate
 * @param artifactSha256 lowercase SHA-256 artifact digest when known
 * @param artifactSizeBytes artifact size in bytes when known
 * @param reviewerKeyId reviewer key id from the receipt or local decision
 * @param reviewerKeyStatus local lifecycle status for the reviewer key when known
 * @param policyId review policy id from the receipt or local trust decision
 * @param policyVersion review policy version from the receipt or local trust decision
 * @param receiptStatus independent receipt verdict when a receipt exists
 * @param trustStatus local review trust status after policy and lifecycle evaluation
 * @param trusted whether local verification trusted the receipt
 * @param positive whether local verification found a positive trusted review
 * @param requiresAcknowledgement whether local policy requires operator acknowledgement
 * @param blocksInstall whether local policy blocks manual install
 * @param blocksUpdate whether local policy blocks manual update
 * @param blocksPolicyApply whether local policy blocks policy-driven apply
 * @param evidenceSha256 lowercase SHA-256 digest for external evidence when supplied
 * @param evidenceUri evidence URI from the receipt or trust decision when supplied
 * @param previousRecordHash hash of the previous record, or an empty genesis value
 * @param recordHash SHA-256 hash over canonical record fields and previous hash
 * @param warnings bounded display-safe warnings associated with the event
 */
public record AppReviewTransparencyRecord(
    int schemaVersion,
    long sequence,
    String recordId,
    Instant createdAt,
    AppReviewTransparencyEventKind kind,
    String subjectType,
    String appId,
    String appVersion,
    String catalogId,
    String artifactSha256,
    Long artifactSizeBytes,
    String reviewerKeyId,
    String reviewerKeyStatus,
    String policyId,
    String policyVersion,
    String receiptStatus,
    String trustStatus,
    Boolean trusted,
    Boolean positive,
    Boolean requiresAcknowledgement,
    Boolean blocksInstall,
    Boolean blocksUpdate,
    Boolean blocksPolicyApply,
    String evidenceSha256,
    String evidenceUri,
    String previousRecordHash,
    String recordHash,
    List<String> warnings) {
  /**
   * Current local log record schema.
   *
   * <p>The parser accepts only this value. Unsupported future or malformed schema versions fail
   * closed during log verification so older binaries do not accidentally validate records whose
   * canonical form they do not understand.
   */
  public static final int SCHEMA_VERSION = 1;

  private static final int MAX_FIELD_CHARS = 512;
  private static final int MAX_WARNING_CHARS = 256;
  private static final String SCHEMA_VERSION_FIELD = "schemaVersion";
  private static final String SEQUENCE_FIELD = "sequence";
  private static final String RECORD_ID_FIELD = "recordId";
  private static final String CREATED_AT_FIELD = "createdAt";
  private static final String KIND_FIELD = "kind";
  private static final String SUBJECT_TYPE_FIELD = "subjectType";
  private static final String APP_ID_FIELD = "appId";
  private static final String APP_VERSION_FIELD = "appVersion";
  private static final String CATALOG_ID_FIELD = "catalogId";
  private static final String ARTIFACT_SHA256_FIELD = "artifactSha256";
  private static final String ARTIFACT_SIZE_BYTES_FIELD = "artifactSizeBytes";
  private static final String REVIEWER_KEY_ID_FIELD = "reviewerKeyId";
  private static final String REVIEWER_KEY_STATUS_FIELD = "reviewerKeyStatus";
  private static final String POLICY_ID_FIELD = "policyId";
  private static final String POLICY_VERSION_FIELD = "policyVersion";
  private static final String RECEIPT_STATUS_FIELD = "receiptStatus";
  private static final String TRUST_STATUS_FIELD = "trustStatus";
  private static final String TRUSTED_FIELD = "trusted";
  private static final String POSITIVE_FIELD = "positive";
  private static final String REQUIRES_ACKNOWLEDGEMENT_FIELD = "requiresAcknowledgement";
  private static final String BLOCKS_INSTALL_FIELD = "blocksInstall";
  private static final String BLOCKS_UPDATE_FIELD = "blocksUpdate";
  private static final String BLOCKS_POLICY_APPLY_FIELD = "blocksPolicyApply";
  private static final String EVIDENCE_SHA256_FIELD = "evidenceSha256";
  private static final String EVIDENCE_URI_FIELD = "evidenceUri";
  private static final String PREVIOUS_RECORD_HASH_FIELD = "previousRecordHash";
  private static final String RECORD_HASH_FIELD = "recordHash";
  private static final String WARNINGS_FIELD = "warnings";
  private static final List<String> JSON_FIELD_NAMES =
      List.of(
          SCHEMA_VERSION_FIELD,
          SEQUENCE_FIELD,
          RECORD_ID_FIELD,
          CREATED_AT_FIELD,
          KIND_FIELD,
          SUBJECT_TYPE_FIELD,
          APP_ID_FIELD,
          APP_VERSION_FIELD,
          CATALOG_ID_FIELD,
          ARTIFACT_SHA256_FIELD,
          ARTIFACT_SIZE_BYTES_FIELD,
          REVIEWER_KEY_ID_FIELD,
          REVIEWER_KEY_STATUS_FIELD,
          POLICY_ID_FIELD,
          POLICY_VERSION_FIELD,
          RECEIPT_STATUS_FIELD,
          TRUST_STATUS_FIELD,
          TRUSTED_FIELD,
          POSITIVE_FIELD,
          REQUIRES_ACKNOWLEDGEMENT_FIELD,
          BLOCKS_INSTALL_FIELD,
          BLOCKS_UPDATE_FIELD,
          BLOCKS_POLICY_APPLY_FIELD,
          EVIDENCE_SHA256_FIELD,
          EVIDENCE_URI_FIELD,
          PREVIOUS_RECORD_HASH_FIELD,
          RECORD_HASH_FIELD,
          WARNINGS_FIELD);

  /**
   * Creates a normalized record.
   *
   * <p>The constructor validates bounded single-line text, lowercase SHA-256 fields, non-negative
   * sizes and sequences, and immutable warning lists. It accepts nullable optional fields because
   * different event kinds naturally carry different evidence, but malformed non-null values fail
   * closed before they can enter the hash chain.
   */
  public AppReviewTransparencyRecord {
    if (schemaVersion != SCHEMA_VERSION) {
      throw AppCatalogSidecars.invalidEntry(
          "unsupported review transparency schemaVersion: " + schemaVersion);
    }
    if (sequence < 0L) {
      throw AppCatalogSidecars.invalidEntry("review transparency sequence must be >= 0");
    }
    recordId = optionalSingleLine(recordId, "review transparency record id", MAX_FIELD_CHARS);
    Objects.requireNonNull(kind, "kind");
    subjectType = optionalSingleLine(subjectType, "review transparency subject type", 64);
    appId = optionalSingleLine(appId, "review transparency app id", MAX_FIELD_CHARS);
    appVersion = optionalSingleLine(appVersion, "review transparency app version", MAX_FIELD_CHARS);
    catalogId = optionalSingleLine(catalogId, "review transparency catalog id", MAX_FIELD_CHARS);
    artifactSha256 =
        artifactSha256 == null
            ? null
            : AppCatalogSidecars.requireLowercaseSha256(
                artifactSha256, "review transparency artifactSha256");
    if (artifactSizeBytes != null && artifactSizeBytes < 0L) {
      throw AppCatalogSidecars.invalidEntry("review transparency artifactSizeBytes must be >= 0");
    }
    reviewerKeyId =
        optionalSingleLine(reviewerKeyId, "review transparency reviewer key id", MAX_FIELD_CHARS);
    reviewerKeyStatus =
        optionalSingleLine(
            reviewerKeyStatus, "review transparency reviewer key status", MAX_FIELD_CHARS);
    policyId = optionalSingleLine(policyId, "review transparency policy id", MAX_FIELD_CHARS);
    policyVersion =
        optionalSingleLine(policyVersion, "review transparency policy version", MAX_FIELD_CHARS);
    receiptStatus =
        optionalSingleLine(receiptStatus, "review transparency receipt status", MAX_FIELD_CHARS);
    trustStatus =
        optionalSingleLine(trustStatus, "review transparency trust status", MAX_FIELD_CHARS);
    evidenceSha256 =
        evidenceSha256 == null
            ? null
            : AppCatalogSidecars.requireLowercaseSha256(
                evidenceSha256, "review transparency evidenceSha256");
    evidenceUri = optionalSingleLine(evidenceUri, "review transparency evidence URI", 1024);
    previousRecordHash = normalizeHash(previousRecordHash, PREVIOUS_RECORD_HASH_FIELD);
    recordHash = normalizeHash(recordHash, RECORD_HASH_FIELD);
    warnings =
        warnings == null
            ? List.of()
            : warnings.stream()
                .map(
                    value ->
                        AppCatalogSidecars.requireBoundedSingleLine(
                            value,
                            "review transparency warning",
                            AppCatalogSidecars.INVALID_CATALOG_ENTRY,
                            MAX_WARNING_CHARS))
                .toList();
  }

  /**
   * Builds a record from a catalog entry and review trust decision.
   *
   * <p>The draft uses catalog-entry app and artifact fields for gate/evaluation records and uses
   * the embedded receipt payload only for the receipt-status field. Receipt observation records are
   * created separately by {@link AppReviewTransparencyLog} so mismatched receipts can be tied to
   * their own payload instead of inheriting publisher-controlled entry fields.
   *
   * @param kind event kind for the local evaluation or gate decision
   * @param catalogId catalog id associated with the entry being evaluated
   * @param entry catalog entry whose metadata and optional receipt were checked
   * @param decision local trust decision produced by the verifier and policy
   * @param warnings extra bounded warnings to include with decision warnings
   * @return unchained redacted record draft ready for store append
   */
  public static AppReviewTransparencyRecord fromCatalogDecision(
      AppReviewTransparencyEventKind kind,
      String catalogId,
      AppCatalogEntry entry,
      AppReviewTrustDecision decision,
      List<String> warnings) {
    Objects.requireNonNull(entry, "entry");
    Objects.requireNonNull(decision, "decision");
    return new AppReviewTransparencyRecord(
        SCHEMA_VERSION,
        0L,
        null,
        null,
        kind,
        "app",
        entry.appId(),
        entry.version(),
        catalogId,
        entry.bundleSha256(),
        entry.bundleSizeBytes(),
        decision.reviewerKeyId(),
        decision.reviewerKeyStatus(),
        decision.policyId(),
        decision.policyVersion(),
        entry
            .reviewReceipt()
            .map(receipt -> receipt.payload().status().catalogValue())
            .orElse(null),
        decision.status().jsonValue(),
        decision.trusted(),
        decision.positive(),
        decision.requiresAcknowledgement(),
        decision.blocksInstall(),
        decision.blocksUpdate(),
        decision.blocksPolicyApply(),
        decision.evidenceSha256(),
        decision.evidenceUri() == null ? null : decision.evidenceUri().toString(),
        null,
        null,
        warnings);
  }

  /**
   * Builds a record from an app-update candidate review-trust map.
   *
   * <p>This factory is used by scheduler and update code that already carries a JSON-compatible
   * {@code reviewTrust} object. It copies only the stable display-safe keys used by API surfaces
   * and leaves missing values as {@code null}. The constructor still validates digests, warnings,
   * and bounded strings before the draft can be appended.
   *
   * @param kind event kind for the update or policy gate
   * @param appId app id for the update candidate
   * @param appVersion candidate target version displayed to the operator
   * @param catalogId catalog id that supplied the candidate, when known
   * @param artifactSha256 lowercase SHA-256 digest of the candidate artifact
   * @param artifactSizeBytes candidate artifact size in bytes
   * @param reviewTrust JSON-compatible review trust map from API or scheduler code
   * @param warnings bounded event warnings to include on the record
   * @return unchained redacted record draft ready for store append
   */
  public static AppReviewTransparencyRecord fromReviewTrustMap(
      AppReviewTransparencyEventKind kind,
      String appId,
      String appVersion,
      String catalogId,
      String artifactSha256,
      long artifactSizeBytes,
      Map<String, Object> reviewTrust,
      List<String> warnings) {
    Objects.requireNonNull(reviewTrust, "reviewTrust");
    return new AppReviewTransparencyRecord(
        SCHEMA_VERSION,
        0L,
        null,
        null,
        kind,
        "app",
        appId,
        appVersion,
        catalogId,
        artifactSha256,
        artifactSizeBytes,
        stringValue(reviewTrust.get(REVIEWER_KEY_ID_FIELD)),
        stringValue(reviewTrust.get(REVIEWER_KEY_STATUS_FIELD)),
        stringValue(reviewTrust.get(POLICY_ID_FIELD)),
        stringValue(reviewTrust.get(POLICY_VERSION_FIELD)),
        null,
        stringValue(reviewTrust.get("status")),
        optionalBooleanValue(reviewTrust.get(TRUSTED_FIELD)).orElse(null),
        optionalBooleanValue(reviewTrust.get(POSITIVE_FIELD)).orElse(null),
        optionalBooleanValue(reviewTrust.get(REQUIRES_ACKNOWLEDGEMENT_FIELD)).orElse(null),
        optionalBooleanValue(reviewTrust.get(BLOCKS_INSTALL_FIELD)).orElse(null),
        optionalBooleanValue(reviewTrust.get(BLOCKS_UPDATE_FIELD)).orElse(null),
        optionalBooleanValue(reviewTrust.get(BLOCKS_POLICY_APPLY_FIELD)).orElse(null),
        stringValue(reviewTrust.get(EVIDENCE_SHA256_FIELD)),
        stringValue(reviewTrust.get(EVIDENCE_URI_FIELD)),
        null,
        null,
        warnings);
  }

  AppReviewTransparencyRecord withChain(long sequence, String previousHash, Instant createdAt) {
    String assignedRecordId =
        recordId == null || recordId.isBlank() ? kind.jsonValue() + ":" + sequence : recordId;
    AppReviewTransparencyRecord chained =
        new AppReviewTransparencyRecord(
            schemaVersion,
            sequence,
            assignedRecordId,
            createdAt,
            kind,
            subjectType,
            appId,
            appVersion,
            catalogId,
            artifactSha256,
            artifactSizeBytes,
            reviewerKeyId,
            reviewerKeyStatus,
            policyId,
            policyVersion,
            receiptStatus,
            trustStatus,
            trusted,
            positive,
            requiresAcknowledgement,
            blocksInstall,
            blocksUpdate,
            blocksPolicyApply,
            evidenceSha256,
            evidenceUri,
            previousHash == null ? "" : previousHash,
            null,
            warnings);
    return new AppReviewTransparencyRecord(
        chained.schemaVersion,
        chained.sequence,
        chained.recordId,
        chained.createdAt,
        chained.kind,
        chained.subjectType,
        chained.appId,
        chained.appVersion,
        chained.catalogId,
        chained.artifactSha256,
        chained.artifactSizeBytes,
        chained.reviewerKeyId,
        chained.reviewerKeyStatus,
        chained.policyId,
        chained.policyVersion,
        chained.receiptStatus,
        chained.trustStatus,
        chained.trusted,
        chained.positive,
        chained.requiresAcknowledgement,
        chained.blocksInstall,
        chained.blocksUpdate,
        chained.blocksPolicyApply,
        chained.evidenceSha256,
        chained.evidenceUri,
        chained.previousRecordHash,
        chained.computeRecordHash(),
        chained.warnings);
  }

  String computeRecordHash() {
    MessageDigest digest = AppCatalogSidecars.newArtifactSha256Digest();
    digest.update(canonicalBytes());
    return AppCatalogSidecars.lowercaseHex(digest.digest());
  }

  byte[] canonicalBytes() {
    return canonicalText().getBytes(StandardCharsets.UTF_8);
  }

  String canonicalText() {
    StringBuilder builder = new StringBuilder();
    appendCanonical(builder, SCHEMA_VERSION_FIELD, Integer.toString(schemaVersion));
    appendCanonical(builder, SEQUENCE_FIELD, Long.toString(sequence));
    appendCanonical(builder, RECORD_ID_FIELD, recordId);
    appendCanonical(builder, CREATED_AT_FIELD, createdAt == null ? null : createdAt.toString());
    appendCanonical(builder, KIND_FIELD, kind.jsonValue());
    appendCanonical(builder, SUBJECT_TYPE_FIELD, subjectType);
    appendCanonical(builder, APP_ID_FIELD, appId);
    appendCanonical(builder, APP_VERSION_FIELD, appVersion);
    appendCanonical(builder, CATALOG_ID_FIELD, catalogId);
    appendCanonical(builder, ARTIFACT_SHA256_FIELD, artifactSha256);
    appendCanonical(builder, ARTIFACT_SIZE_BYTES_FIELD, artifactSizeBytes);
    appendCanonical(builder, REVIEWER_KEY_ID_FIELD, reviewerKeyId);
    appendCanonical(builder, REVIEWER_KEY_STATUS_FIELD, reviewerKeyStatus);
    appendCanonical(builder, POLICY_ID_FIELD, policyId);
    appendCanonical(builder, POLICY_VERSION_FIELD, policyVersion);
    appendCanonical(builder, RECEIPT_STATUS_FIELD, receiptStatus);
    appendCanonical(builder, TRUST_STATUS_FIELD, trustStatus);
    appendCanonical(builder, TRUSTED_FIELD, trusted);
    appendCanonical(builder, POSITIVE_FIELD, positive);
    appendCanonical(builder, REQUIRES_ACKNOWLEDGEMENT_FIELD, requiresAcknowledgement);
    appendCanonical(builder, BLOCKS_INSTALL_FIELD, blocksInstall);
    appendCanonical(builder, BLOCKS_UPDATE_FIELD, blocksUpdate);
    appendCanonical(builder, BLOCKS_POLICY_APPLY_FIELD, blocksPolicyApply);
    appendCanonical(builder, EVIDENCE_SHA256_FIELD, evidenceSha256);
    appendCanonical(builder, EVIDENCE_URI_FIELD, evidenceUri);
    appendCanonical(builder, PREVIOUS_RECORD_HASH_FIELD, previousRecordHash);
    appendCanonical(builder, WARNINGS_FIELD, canonicalWarnings(warnings));
    return builder.toString();
  }

  /**
   * Converts this record to JSON-compatible values.
   *
   * <p>The map preserves field order for deterministic JSONL output and test assertions. All fields
   * are already redacted and normalized by the record constructor; this method does not expose
   * public key bytes, private key material, local paths, browser sessions, request bodies, receipt
   * signatures, or process tokens.
   *
   * @return redacted transparency record with stable JSON field names
   */
  public Map<String, Object> toJsonValue() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(24);
    json.put(SCHEMA_VERSION_FIELD, schemaVersion);
    json.put(SEQUENCE_FIELD, sequence);
    json.put(RECORD_ID_FIELD, recordId);
    json.put(CREATED_AT_FIELD, createdAt == null ? null : createdAt.toString());
    json.put(KIND_FIELD, kind.jsonValue());
    json.put(SUBJECT_TYPE_FIELD, subjectType);
    json.put(APP_ID_FIELD, appId);
    json.put(APP_VERSION_FIELD, appVersion);
    json.put(CATALOG_ID_FIELD, catalogId);
    json.put(ARTIFACT_SHA256_FIELD, artifactSha256);
    json.put(ARTIFACT_SIZE_BYTES_FIELD, artifactSizeBytes);
    json.put(REVIEWER_KEY_ID_FIELD, reviewerKeyId);
    json.put(REVIEWER_KEY_STATUS_FIELD, reviewerKeyStatus);
    json.put(POLICY_ID_FIELD, policyId);
    json.put(POLICY_VERSION_FIELD, policyVersion);
    json.put(RECEIPT_STATUS_FIELD, receiptStatus);
    json.put(TRUST_STATUS_FIELD, trustStatus);
    json.put(TRUSTED_FIELD, trusted);
    json.put(POSITIVE_FIELD, positive);
    json.put(REQUIRES_ACKNOWLEDGEMENT_FIELD, requiresAcknowledgement);
    json.put(BLOCKS_INSTALL_FIELD, blocksInstall);
    json.put(BLOCKS_UPDATE_FIELD, blocksUpdate);
    json.put(BLOCKS_POLICY_APPLY_FIELD, blocksPolicyApply);
    json.put(EVIDENCE_SHA256_FIELD, evidenceSha256);
    json.put(EVIDENCE_URI_FIELD, evidenceUri);
    json.put(PREVIOUS_RECORD_HASH_FIELD, previousRecordHash);
    json.put(RECORD_HASH_FIELD, recordHash);
    json.put(WARNINGS_FIELD, warnings);
    return json;
  }

  String toJsonLine() {
    return Json.write(toJsonValue());
  }

  static AppReviewTransparencyRecord parseJsonLine(String line) {
    Map<String, Object> json = Json.parse(line);
    rejectUnknownJsonFields(json);
    return new AppReviewTransparencyRecord(
        intValue(json.get(SCHEMA_VERSION_FIELD)),
        longValue(json.get(SEQUENCE_FIELD)),
        stringValue(json.get(RECORD_ID_FIELD)),
        instantValue(json.get(CREATED_AT_FIELD)),
        AppReviewTransparencyEventKind.parse(stringValue(json.get(KIND_FIELD))),
        stringValue(json.get(SUBJECT_TYPE_FIELD)),
        stringValue(json.get(APP_ID_FIELD)),
        stringValue(json.get(APP_VERSION_FIELD)),
        stringValue(json.get(CATALOG_ID_FIELD)),
        stringValue(json.get(ARTIFACT_SHA256_FIELD)),
        longObjectValue(json.get(ARTIFACT_SIZE_BYTES_FIELD)),
        stringValue(json.get(REVIEWER_KEY_ID_FIELD)),
        stringValue(json.get(REVIEWER_KEY_STATUS_FIELD)),
        stringValue(json.get(POLICY_ID_FIELD)),
        stringValue(json.get(POLICY_VERSION_FIELD)),
        stringValue(json.get(RECEIPT_STATUS_FIELD)),
        stringValue(json.get(TRUST_STATUS_FIELD)),
        optionalBooleanValue(json.get(TRUSTED_FIELD)).orElse(null),
        optionalBooleanValue(json.get(POSITIVE_FIELD)).orElse(null),
        optionalBooleanValue(json.get(REQUIRES_ACKNOWLEDGEMENT_FIELD)).orElse(null),
        optionalBooleanValue(json.get(BLOCKS_INSTALL_FIELD)).orElse(null),
        optionalBooleanValue(json.get(BLOCKS_UPDATE_FIELD)).orElse(null),
        optionalBooleanValue(json.get(BLOCKS_POLICY_APPLY_FIELD)).orElse(null),
        stringValue(json.get(EVIDENCE_SHA256_FIELD)),
        stringValue(json.get(EVIDENCE_URI_FIELD)),
        stringValue(json.get(PREVIOUS_RECORD_HASH_FIELD)),
        stringValue(json.get(RECORD_HASH_FIELD)),
        stringListValue(json.get(WARNINGS_FIELD)));
  }

  private static void rejectUnknownJsonFields(Map<String, Object> json) {
    for (String fieldName : json.keySet()) {
      if (!JSON_FIELD_NAMES.contains(fieldName)) {
        throw AppCatalogSidecars.invalidEntry(
            "unknown review transparency record field: " + fieldName);
      }
    }
  }

  private static void appendCanonical(StringBuilder builder, String key, Object value) {
    builder.append(key).append('=').append(value == null ? "" : value).append('\n');
  }

  private static String canonicalWarnings(List<String> warnings) {
    StringBuilder builder = new StringBuilder();
    builder.append(warnings.size()).append(':');
    for (String warning : warnings) {
      String value = Objects.requireNonNullElse(warning, "");
      builder.append(value.getBytes(StandardCharsets.UTF_8).length).append(':').append(value);
    }
    return builder.toString();
  }

  private static String optionalSingleLine(String value, String fieldName, int maxChars) {
    if (value == null || value.isBlank()) {
      return null;
    }
    return AppCatalogSidecars.requireBoundedSingleLine(
        value, fieldName, AppCatalogSidecars.INVALID_CATALOG_ENTRY, maxChars);
  }

  private static String normalizeHash(String value, String fieldName) {
    if (value == null || value.isBlank()) {
      return value == null ? null : "";
    }
    return AppCatalogSidecars.requireLowercaseSha256(value, "review transparency " + fieldName);
  }

  private static String stringValue(Object value) {
    return value == null ? null : value.toString();
  }

  private static Optional<Boolean> optionalBooleanValue(Object value) {
    if (value == null) {
      return Optional.empty();
    }
    if (value instanceof Boolean booleanValue) {
      return Optional.of(booleanValue);
    }
    throw AppCatalogSidecars.invalidEntry("review transparency boolean field must be true/false");
  }

  private static int intValue(Object value) {
    if (value instanceof Number number) {
      long longValue = number.longValue();
      if (longValue < Integer.MIN_VALUE || longValue > Integer.MAX_VALUE) {
        throw AppCatalogSidecars.invalidEntry("review transparency integer field is out of range");
      }
      return Math.toIntExact(longValue);
    }
    try {
      return Integer.parseInt(Objects.requireNonNull(value, "integer value").toString());
    } catch (NumberFormatException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY,
          "invalid review transparency integer field",
          exception);
    }
  }

  private static long longValue(Object value) {
    if (value instanceof Number number) {
      return number.longValue();
    }
    return Long.parseLong(Objects.requireNonNull(value, "long value").toString());
  }

  private static Long longObjectValue(Object value) {
    return value == null ? null : longValue(value);
  }

  private static Instant instantValue(Object value) {
    if (value == null) {
      return null;
    }
    try {
      return Instant.parse(value.toString());
    } catch (DateTimeParseException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY,
          "invalid review transparency createdAt: " + value,
          exception);
    }
  }

  private static List<String> stringListValue(Object value) {
    if (!(value instanceof List<?> items)) {
      return List.of();
    }
    List<String> strings = new ArrayList<>(items.size());
    for (Object item : items) {
      strings.add(item == null ? "" : item.toString());
    }
    return strings;
  }

  private static final class Json {
    private Json() {}

    static String write(Map<String, Object> json) {
      StringBuilder builder = new StringBuilder("{");
      boolean first = true;
      for (Map.Entry<String, Object> entry : json.entrySet()) {
        if (!first) {
          builder.append(',');
        }
        first = false;
        builder.append('"').append(escape(entry.getKey())).append('"').append(':');
        writeValue(builder, entry.getValue());
      }
      return builder.append('}').toString();
    }

    static Map<String, Object> parse(String raw) {
      Parser parser = new Parser(raw);
      Map<String, Object> values = parser.parseObject();
      parser.expectEnd();
      return values;
    }

    private static void writeValue(StringBuilder builder, Object value) {
      if (value == null) {
        builder.append("null");
      } else if (value instanceof Number || value instanceof Boolean) {
        builder.append(value);
      } else if (value instanceof List<?> list) {
        builder.append('[');
        boolean first = true;
        for (Object item : list) {
          if (!first) {
            builder.append(',');
          }
          first = false;
          writeValue(builder, item == null ? null : item.toString());
        }
        builder.append(']');
      } else {
        builder.append('"').append(escape(value.toString())).append('"');
      }
    }

    private static String escape(String value) {
      StringBuilder builder = new StringBuilder(value.length());
      for (int index = 0; index < value.length(); index++) {
        char character = value.charAt(index);
        switch (character) {
          case '"' -> builder.append("\\\"");
          case '\\' -> builder.append("\\\\");
          case '\n' -> builder.append("\\n");
          case '\r' -> builder.append("\\r");
          case '\t' -> builder.append("\\t");
          default -> builder.append(character);
        }
      }
      return builder.toString();
    }
  }

  private static final class Parser {
    private final String text;
    private int index;

    private Parser(String text) {
      this.text = Objects.requireNonNull(text, "text").trim();
    }

    private Map<String, Object> parseObject() {
      expect('{');
      LinkedHashMap<String, Object> values = new LinkedHashMap<>();
      skipWhitespace();
      if (peek('}')) {
        index++;
        return values;
      }
      while (true) {
        String key = parseString();
        skipWhitespace();
        expect(':');
        Object value = parseValue();
        if (values.containsKey(key)) {
          throw AppCatalogSidecars.invalidEntry(
              "duplicate review transparency record field: " + key);
        }
        values.put(key, value);
        skipWhitespace();
        if (peek('}')) {
          index++;
          return values;
        }
        expect(',');
      }
    }

    private Object parseValue() {
      skipWhitespace();
      if (peek('"')) {
        return parseString();
      }
      if (peek('[')) {
        return parseArray();
      }
      if (consumeLiteral("null")) {
        return null;
      }
      if (consumeLiteral("true")) {
        return Boolean.TRUE;
      }
      if (consumeLiteral("false")) {
        return Boolean.FALSE;
      }
      return parseNumber();
    }

    private List<String> parseArray() {
      expect('[');
      List<String> values = new ArrayList<>();
      skipWhitespace();
      if (peek(']')) {
        index++;
        return values;
      }
      while (true) {
        Object value = parseValue();
        values.add(value == null ? null : value.toString());
        skipWhitespace();
        if (peek(']')) {
          index++;
          return values;
        }
        expect(',');
      }
    }

    private String parseString() {
      expect('"');
      StringBuilder builder = new StringBuilder();
      while (index < text.length()) {
        char character = text.charAt(index++);
        if (character == '"') {
          return builder.toString();
        }
        if (character != '\\') {
          builder.append(character);
          continue;
        }
        if (index >= text.length()) {
          throw AppCatalogSidecars.invalidEntry("invalid JSON escape in transparency log");
        }
        char escaped = text.charAt(index++);
        switch (escaped) {
          case '"' -> builder.append('"');
          case '\\' -> builder.append('\\');
          case 'n' -> builder.append('\n');
          case 'r' -> builder.append('\r');
          case 't' -> builder.append('\t');
          default ->
              throw AppCatalogSidecars.invalidEntry("invalid JSON escape in transparency log");
        }
      }
      throw AppCatalogSidecars.invalidEntry("unterminated JSON string in transparency log");
    }

    private Number parseNumber() {
      int start = index;
      if (peek('-')) {
        index++;
      }
      while (index < text.length() && Character.isDigit(text.charAt(index))) {
        index++;
      }
      if (start == index) {
        throw AppCatalogSidecars.invalidEntry("invalid JSON value in transparency log");
      }
      try {
        return Long.parseLong(text.substring(start, index));
      } catch (NumberFormatException exception) {
        throw new AppCatalogException(
            AppCatalogSidecars.INVALID_CATALOG_ENTRY,
            "invalid JSON number in transparency log",
            exception);
      }
    }

    private boolean consumeLiteral(String literal) {
      if (!text.startsWith(literal, index)) {
        return false;
      }
      index += literal.length();
      return true;
    }

    private void expect(char expected) {
      skipWhitespace();
      if (index >= text.length() || text.charAt(index) != expected) {
        throw AppCatalogSidecars.invalidEntry("invalid JSON transparency log record");
      }
      index++;
    }

    private void expectEnd() {
      skipWhitespace();
      if (index != text.length()) {
        throw AppCatalogSidecars.invalidEntry("trailing data after JSON transparency log record");
      }
    }

    private boolean peek(char expected) {
      skipWhitespace();
      return index < text.length() && text.charAt(index) == expected;
    }

    private void skipWhitespace() {
      while (index < text.length() && Character.isWhitespace(text.charAt(index))) {
        index++;
      }
    }
  }
}
