package network.crypta.platform.appcatalog;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Safe reviewer-assignment metadata for one intake record.
 *
 * <p>The assignment stores reviewer identity, display name, assignment time, and the SHA-256 digest
 * of the assignment reason file. It never contains reviewer private key material or trusted
 * registry paths.
 *
 * @param reviewerKeyId reviewer key id from the trusted reviewer registry
 * @param reviewerDisplayName operator-visible reviewer name
 * @param assignedAt assignment timestamp
 * @param assignmentReasonDigest SHA-256 digest of the assignment reason text
 * @param previousReviewerKeyId prior reviewer id when this assignment is a reassignment
 */
public record AppSubmissionReviewerAssignment(
    String reviewerKeyId,
    String reviewerDisplayName,
    Instant assignedAt,
    String assignmentReasonDigest,
    Optional<String> previousReviewerKeyId) {
  private static final String REVIEWER_KEY_ID_FIELD = "reviewerKeyId";
  private static final String REVIEWER_DISPLAY_NAME_FIELD = "reviewerDisplayName";
  private static final String ASSIGNED_AT_FIELD = "assignedAt";
  private static final String ASSIGNMENT_REASON_DIGEST_FIELD = "assignmentReasonDigest";
  private static final String PREVIOUS_REVIEWER_KEY_ID_FIELD = "previousReviewerKeyId";
  private static final int ASSIGNMENT_TEXT_MAX_CHARS = 128;

  /**
   * Creates a validated assignment value.
   *
   * <p>All text is bounded and single-line so queue JSON and operator API output remain safe.
   */
  public AppSubmissionReviewerAssignment {
    reviewerKeyId = bounded(reviewerKeyId, REVIEWER_KEY_ID_FIELD);
    reviewerDisplayName = bounded(reviewerDisplayName, REVIEWER_DISPLAY_NAME_FIELD);
    Objects.requireNonNull(assignedAt, ASSIGNED_AT_FIELD);
    assignmentReasonDigest =
        AppCatalogSidecars.requireLowercaseSha256(
            assignmentReasonDigest, ASSIGNMENT_REASON_DIGEST_FIELD);
    Objects.requireNonNull(previousReviewerKeyId, PREVIOUS_REVIEWER_KEY_ID_FIELD);
    previousReviewerKeyId =
        previousReviewerKeyId.map(value -> bounded(value, PREVIOUS_REVIEWER_KEY_ID_FIELD));
  }

  Map<String, Object> toJsonValue() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(5);
    json.put(REVIEWER_KEY_ID_FIELD, reviewerKeyId);
    json.put(REVIEWER_DISPLAY_NAME_FIELD, reviewerDisplayName);
    json.put(ASSIGNED_AT_FIELD, assignedAt.toString());
    json.put(ASSIGNMENT_REASON_DIGEST_FIELD, assignmentReasonDigest);
    previousReviewerKeyId.ifPresent(value -> json.put(PREVIOUS_REVIEWER_KEY_ID_FIELD, value));
    return json;
  }

  static AppSubmissionReviewerAssignment fromJsonValue(Object value) {
    Map<String, Object> json = AppSubmissionJson.requireObject(value, "reviewerAssignment");
    return new AppSubmissionReviewerAssignment(
        AppSubmissionJson.requireString(json, REVIEWER_KEY_ID_FIELD, REVIEWER_KEY_ID_FIELD),
        AppSubmissionJson.requireString(
            json, REVIEWER_DISPLAY_NAME_FIELD, REVIEWER_DISPLAY_NAME_FIELD),
        parseInstant(AppSubmissionJson.requireString(json, ASSIGNED_AT_FIELD, ASSIGNED_AT_FIELD)),
        AppSubmissionJson.requireString(
            json, ASSIGNMENT_REASON_DIGEST_FIELD, ASSIGNMENT_REASON_DIGEST_FIELD),
        AppSubmissionJson.optionalString(
            json, PREVIOUS_REVIEWER_KEY_ID_FIELD, PREVIOUS_REVIEWER_KEY_ID_FIELD));
  }

  private static Instant parseInstant(String value) {
    try {
      return Instant.parse(value);
    } catch (DateTimeParseException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY,
          ASSIGNED_AT_FIELD + " must be an ISO-8601 instant",
          exception);
    }
  }

  private static String bounded(String value, String fieldName) {
    return AppCatalogSidecars.requireBoundedSingleLine(
        value, fieldName, AppCatalogSidecars.INVALID_CATALOG_ENTRY, ASSIGNMENT_TEXT_MAX_CHARS);
  }
}
