package network.crypta.platform.appcatalog;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Safe metadata for beta catalog candidate staging.
 *
 * <p>The candidate reference is a redacted queue-relative label, not an absolute local path. The
 * record binds the candidate descriptor digest, beta channel, receipt fingerprint, caution policy,
 * and structural install-smoke status without exposing raw bundle bytes or staging directories.
 *
 * @param catalogCandidateDigest SHA-256 digest of the candidate descriptor
 * @param betaCatalogChannel channel used for local beta candidate staging
 * @param betaCatalogCandidateReference redacted queue-relative candidate reference
 * @param reviewReceiptFingerprintSha256 fingerprint of the receipt verified before staging
 * @param createdAt candidate creation timestamp
 * @param cautionAllowed whether a caution decision was explicitly allowed
 * @param installSmokeStatus local structural install-smoke status
 */
public record AppSubmissionCatalogCandidateRecord(
    String catalogCandidateDigest,
    String betaCatalogChannel,
    String betaCatalogCandidateReference,
    String reviewReceiptFingerprintSha256,
    Instant createdAt,
    boolean cautionAllowed,
    String installSmokeStatus) {
  private static final String CATALOG_CANDIDATE_DIGEST_FIELD = "catalogCandidateDigest";
  private static final String BETA_CATALOG_CHANNEL_FIELD = "betaCatalogChannel";
  private static final String BETA_CATALOG_CANDIDATE_REFERENCE_FIELD =
      "betaCatalogCandidateReference";
  private static final String REVIEW_RECEIPT_FINGERPRINT_FIELD = "reviewReceiptFingerprintSha256";
  private static final String CREATED_AT_FIELD = "createdAt";
  private static final String CAUTION_ALLOWED_FIELD = "cautionAllowed";
  private static final String INSTALL_SMOKE_STATUS_FIELD = "installSmokeStatus";

  /** Creates a validated candidate record. */
  public AppSubmissionCatalogCandidateRecord {
    catalogCandidateDigest =
        AppCatalogSidecars.requireLowercaseSha256(
            catalogCandidateDigest, CATALOG_CANDIDATE_DIGEST_FIELD);
    betaCatalogChannel =
        AppCatalogChannel.parse(betaCatalogChannel, BETA_CATALOG_CHANNEL_FIELD).catalogValue();
    betaCatalogCandidateReference =
        AppCatalogSidecars.requireBoundedSingleLine(
            betaCatalogCandidateReference,
            BETA_CATALOG_CANDIDATE_REFERENCE_FIELD,
            AppCatalogSidecars.INVALID_CATALOG_ENTRY,
            256);
    reviewReceiptFingerprintSha256 =
        AppCatalogSidecars.requireLowercaseSha256(
            reviewReceiptFingerprintSha256, REVIEW_RECEIPT_FINGERPRINT_FIELD);
    Objects.requireNonNull(createdAt, CREATED_AT_FIELD);
    installSmokeStatus =
        AppCatalogSidecars.requireBoundedSingleLine(
            installSmokeStatus,
            INSTALL_SMOKE_STATUS_FIELD,
            AppCatalogSidecars.INVALID_CATALOG_ENTRY,
            64);
  }

  Map<String, Object> toJsonValue() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(7);
    json.put(CATALOG_CANDIDATE_DIGEST_FIELD, catalogCandidateDigest);
    json.put(BETA_CATALOG_CHANNEL_FIELD, betaCatalogChannel);
    json.put(BETA_CATALOG_CANDIDATE_REFERENCE_FIELD, betaCatalogCandidateReference);
    json.put(REVIEW_RECEIPT_FINGERPRINT_FIELD, reviewReceiptFingerprintSha256);
    json.put(CREATED_AT_FIELD, createdAt.toString());
    json.put(CAUTION_ALLOWED_FIELD, cautionAllowed);
    json.put(INSTALL_SMOKE_STATUS_FIELD, installSmokeStatus);
    return json;
  }

  static AppSubmissionCatalogCandidateRecord fromJsonValue(Object value) {
    Map<String, Object> json = AppSubmissionJson.requireObject(value, "catalogCandidate");
    return new AppSubmissionCatalogCandidateRecord(
        AppSubmissionJson.requireString(
            json, CATALOG_CANDIDATE_DIGEST_FIELD, CATALOG_CANDIDATE_DIGEST_FIELD),
        AppSubmissionJson.requireString(
            json, BETA_CATALOG_CHANNEL_FIELD, BETA_CATALOG_CHANNEL_FIELD),
        AppSubmissionJson.requireString(
            json, BETA_CATALOG_CANDIDATE_REFERENCE_FIELD, BETA_CATALOG_CANDIDATE_REFERENCE_FIELD),
        AppSubmissionJson.requireString(
            json, REVIEW_RECEIPT_FINGERPRINT_FIELD, REVIEW_RECEIPT_FINGERPRINT_FIELD),
        parseInstant(AppSubmissionJson.requireString(json, CREATED_AT_FIELD, CREATED_AT_FIELD)),
        AppSubmissionJson.requireBoolean(json, CAUTION_ALLOWED_FIELD, CAUTION_ALLOWED_FIELD),
        AppSubmissionJson.requireString(
            json, INSTALL_SMOKE_STATUS_FIELD, INSTALL_SMOKE_STATUS_FIELD));
  }

  private static Instant parseInstant(String value) {
    try {
      return Instant.parse(value);
    } catch (DateTimeParseException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY,
          CREATED_AT_FIELD + " must be an ISO-8601 instant",
          exception);
    }
  }
}
