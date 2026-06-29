package network.crypta.platform.appcatalog;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Safe metadata for a final intake reviewer decision.
 *
 * <p>Decision reason and feedback bodies are represented only by SHA-256 digests. Positive
 * reviewed/caution decisions must carry a review receipt fingerprint. Rejected and resubmission
 * requested decisions deliberately carry no installable candidate evidence.
 *
 * @param decision reviewer decision
 * @param decidedAt decision timestamp
 * @param reviewerKeyId reviewer key id that made the decision
 * @param reviewerPolicy reviewer policy id/version label
 * @param preReviewDigest SHA-256 digest of the pre-review JSON report
 * @param decisionReasonDigest SHA-256 digest of the reviewer reason file
 * @param reviewReceiptFingerprintSha256 review receipt fingerprint for reviewed/caution decisions
 * @param rejectionDigest SHA-256 digest of rejection metadata for rejected decisions
 * @param feedbackDigest SHA-256 digest of resubmission feedback metadata
 * @param nonProduction whether the decision belongs to non-production evidence
 */
public record AppSubmissionReviewDecisionRecord(
    AppSubmissionReviewDecision decision,
    Instant decidedAt,
    String reviewerKeyId,
    String reviewerPolicy,
    String preReviewDigest,
    String decisionReasonDigest,
    Optional<String> reviewReceiptFingerprintSha256,
    Optional<String> rejectionDigest,
    Optional<String> feedbackDigest,
    boolean nonProduction) {
  private static final String DECISION_FIELD = "decision";
  private static final String DECIDED_AT_FIELD = "decidedAt";
  private static final String REVIEWER_KEY_ID_FIELD = "reviewerKeyId";
  private static final String REVIEWER_POLICY_FIELD = "reviewerPolicy";
  private static final String PRE_REVIEW_DIGEST_FIELD = "preReviewDigest";
  private static final String DECISION_REASON_DIGEST_FIELD = "decisionReasonDigest";
  private static final String REVIEW_RECEIPT_FINGERPRINT_FIELD = "reviewReceiptFingerprintSha256";
  private static final String REJECTION_DIGEST_FIELD = "rejectionDigest";
  private static final String FEEDBACK_DIGEST_FIELD = "feedbackDigest";
  private static final String NON_PRODUCTION_FIELD = "nonProduction";

  /** Creates a validated decision record. */
  public AppSubmissionReviewDecisionRecord {
    Objects.requireNonNull(decision, DECISION_FIELD);
    Objects.requireNonNull(decidedAt, DECIDED_AT_FIELD);
    reviewerKeyId = bounded(reviewerKeyId, REVIEWER_KEY_ID_FIELD, 128);
    reviewerPolicy = bounded(reviewerPolicy, REVIEWER_POLICY_FIELD, 160);
    preReviewDigest =
        AppCatalogSidecars.requireLowercaseSha256(preReviewDigest, PRE_REVIEW_DIGEST_FIELD);
    decisionReasonDigest =
        AppCatalogSidecars.requireLowercaseSha256(
            decisionReasonDigest, DECISION_REASON_DIGEST_FIELD);
    Objects.requireNonNull(reviewReceiptFingerprintSha256, REVIEW_RECEIPT_FINGERPRINT_FIELD);
    Objects.requireNonNull(rejectionDigest, REJECTION_DIGEST_FIELD);
    Objects.requireNonNull(feedbackDigest, FEEDBACK_DIGEST_FIELD);
    reviewReceiptFingerprintSha256 =
        reviewReceiptFingerprintSha256.map(
            value ->
                AppCatalogSidecars.requireLowercaseSha256(value, REVIEW_RECEIPT_FINGERPRINT_FIELD));
    rejectionDigest =
        rejectionDigest.map(
            value -> AppCatalogSidecars.requireLowercaseSha256(value, REJECTION_DIGEST_FIELD));
    feedbackDigest =
        feedbackDigest.map(
            value -> AppCatalogSidecars.requireLowercaseSha256(value, FEEDBACK_DIGEST_FIELD));
    if (decision.requiresReceipt() && reviewReceiptFingerprintSha256.isEmpty()) {
      throw AppCatalogSidecars.invalidEntry("reviewed/caution intake decisions require receipt");
    }
    if (!decision.requiresReceipt() && reviewReceiptFingerprintSha256.isPresent()) {
      throw AppCatalogSidecars.invalidEntry("negative intake decisions must not carry receipts");
    }
  }

  Map<String, Object> toJsonValue() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(10);
    json.put(DECISION_FIELD, decision.jsonValue());
    json.put(DECIDED_AT_FIELD, decidedAt.toString());
    json.put(REVIEWER_KEY_ID_FIELD, reviewerKeyId);
    json.put(REVIEWER_POLICY_FIELD, reviewerPolicy);
    json.put(PRE_REVIEW_DIGEST_FIELD, preReviewDigest);
    json.put(DECISION_REASON_DIGEST_FIELD, decisionReasonDigest);
    reviewReceiptFingerprintSha256.ifPresent(
        value -> json.put(REVIEW_RECEIPT_FINGERPRINT_FIELD, value));
    rejectionDigest.ifPresent(value -> json.put(REJECTION_DIGEST_FIELD, value));
    feedbackDigest.ifPresent(value -> json.put(FEEDBACK_DIGEST_FIELD, value));
    json.put(NON_PRODUCTION_FIELD, nonProduction);
    return json;
  }

  static AppSubmissionReviewDecisionRecord fromJsonValue(Object value) {
    Map<String, Object> json = AppSubmissionJson.requireObject(value, DECISION_FIELD);
    return new AppSubmissionReviewDecisionRecord(
        AppSubmissionReviewDecision.parse(
            AppSubmissionJson.requireString(json, DECISION_FIELD, DECISION_FIELD)),
        parseInstant(AppSubmissionJson.requireString(json, DECIDED_AT_FIELD, DECIDED_AT_FIELD)),
        AppSubmissionJson.requireString(json, REVIEWER_KEY_ID_FIELD, REVIEWER_KEY_ID_FIELD),
        AppSubmissionJson.requireString(json, REVIEWER_POLICY_FIELD, REVIEWER_POLICY_FIELD),
        AppSubmissionJson.requireString(json, PRE_REVIEW_DIGEST_FIELD, PRE_REVIEW_DIGEST_FIELD),
        AppSubmissionJson.requireString(
            json, DECISION_REASON_DIGEST_FIELD, DECISION_REASON_DIGEST_FIELD),
        AppSubmissionJson.optionalString(
            json, REVIEW_RECEIPT_FINGERPRINT_FIELD, REVIEW_RECEIPT_FINGERPRINT_FIELD),
        AppSubmissionJson.optionalString(json, REJECTION_DIGEST_FIELD, REJECTION_DIGEST_FIELD),
        AppSubmissionJson.optionalString(json, FEEDBACK_DIGEST_FIELD, FEEDBACK_DIGEST_FIELD),
        AppSubmissionJson.requireBoolean(json, NON_PRODUCTION_FIELD, NON_PRODUCTION_FIELD));
  }

  private static Instant parseInstant(String value) {
    try {
      return Instant.parse(value);
    } catch (DateTimeParseException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY,
          DECIDED_AT_FIELD + " must be an ISO-8601 instant",
          exception);
    }
  }

  private static String bounded(String value, String fieldName, int maxChars) {
    return AppCatalogSidecars.requireBoundedSingleLine(
        value, fieldName, AppCatalogSidecars.INVALID_CATALOG_ENTRY, maxChars);
  }
}
