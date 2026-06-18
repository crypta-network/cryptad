package network.crypta.platform.appcatalog;

import java.util.Objects;
import java.util.Optional;

/**
 * Advisory human-review metadata for one catalog app.
 *
 * <p>Catalog publishers can use this value to describe the human review state they want operators
 * to see before an installation or update. The metadata is authenticated as part of the signed
 * catalog, so an operator can tell which trusted catalog source made the claim. It is still only
 * advisory. It does not turn a catalog into a code-signing authority, bypass artifact digest
 * checks, replace signed-bundle verification, grant app permissions, or block install/update on its
 * own.
 *
 * <p>The status is intentionally small and enumerable so Platform API and Web Shell clients can
 * render consistent badges. The optional note gives the publisher one concise line of context, such
 * as what was reviewed or why the operator should use caution. Longer review reports should use
 * catalog documentation or a changelog URI rather than this field.
 *
 * <p>Instances are immutable and validate the note at construction time. The note is trimmed,
 * bounded, and single-line, which keeps the deterministic catalog sidecar format readable and
 * prevents metadata from introducing extra properties through embedded line breaks.
 *
 * @param status advisory review status declared by the catalog publisher
 * @param note optional single-line review note shown to operators
 * @see AppCatalogReviewStatus
 * @see AppCatalogEntry#review()
 */
public record AppCatalogReviewMetadata(
    AppCatalogReviewStatus status,
    Optional<String> note,
    Optional<String> submissionId,
    Optional<String> submissionSha256,
    Optional<String> preReviewStatus,
    Optional<String> preReviewSha256,
    Optional<String> reviewerKeyId,
    Optional<String> reviewerPolicy,
    Optional<String> receiptFingerprintSha256,
    Optional<String> decisionReasonSha256,
    Optional<String> resubmissionOf,
    boolean nonProduction) {
  private static final int MAX_REVIEW_NOTE_CHARS = 512;
  private static final int MAX_REVIEW_FIELD_CHARS = 128;

  /**
   * Empty advisory review metadata used by catalogs without explicit review fields.
   *
   * <p>This value maps to {@link AppCatalogReviewStatus#UNREVIEWED} with no note. Writers omit
   * review properties for it, while API responses can still expose a stable review object.
   */
  public static final AppCatalogReviewMetadata EMPTY =
      new AppCatalogReviewMetadata(AppCatalogReviewStatus.UNREVIEWED, null);

  /**
   * Creates backward-compatible advisory metadata with no submission workflow fields.
   *
   * <p>Pass {@code null} when no note should be stored. A non-null note is normalized in the same
   * way as the full record constructor: it must be a bounded single line suitable for signed
   * catalog sidecars and Platform API summaries.
   *
   * @param status advisory review status declared by the catalog publisher
   * @param note optional single-line note explaining the status for operators, or {@code null}
   */
  public AppCatalogReviewMetadata(AppCatalogReviewStatus status, String note) {
    this(
        status,
        Optional.ofNullable(note),
        Optional.empty(),
        Optional.empty(),
        Optional.empty(),
        Optional.empty(),
        Optional.empty(),
        Optional.empty(),
        Optional.empty(),
        Optional.empty(),
        Optional.empty(),
        false);
  }

  /**
   * Creates validated review metadata.
   *
   * <p>The constructor does not interpret the review as trust. It only ensures the value is safe to
   * store in a signed catalog sidecar and expose through Platform API JSON. A blank present note is
   * rejected because callers should use {@link Optional#empty()} when no note exists.
   *
   * @param status advisory review status declared by the catalog publisher
   * @param note optional single-line note explaining the status for operators
   * @throws NullPointerException if the status or optional wrapper is {@code null}
   * @throws AppCatalogException if the note is blank, multi-line, or too long
   */
  public AppCatalogReviewMetadata {
    Objects.requireNonNull(status, "status");
    Objects.requireNonNull(note, "note");
    Objects.requireNonNull(submissionId, "submissionId");
    Objects.requireNonNull(submissionSha256, "submissionSha256");
    Objects.requireNonNull(preReviewStatus, "preReviewStatus");
    Objects.requireNonNull(preReviewSha256, "preReviewSha256");
    Objects.requireNonNull(reviewerKeyId, "reviewerKeyId");
    Objects.requireNonNull(reviewerPolicy, "reviewerPolicy");
    Objects.requireNonNull(receiptFingerprintSha256, "receiptFingerprintSha256");
    Objects.requireNonNull(decisionReasonSha256, "decisionReasonSha256");
    Objects.requireNonNull(resubmissionOf, "resubmissionOf");
    note = note.map(rawNote -> normalizeSingleLine(rawNote, "review.note", MAX_REVIEW_NOTE_CHARS));
    submissionId = submissionId.map(value -> normalizeSingleLine(value, "review.submissionId"));
    submissionSha256 =
        submissionSha256.map(value -> normalizeSha256(value, "review.submission.sha256"));
    preReviewStatus =
        preReviewStatus
            .map(value -> normalizeSingleLine(value, "review.preReview.status", 32))
            .map(value -> AppSubmissionPreReviewStatus.parse(value).jsonValue());
    preReviewSha256 =
        preReviewSha256.map(value -> normalizeSha256(value, "review.preReview.sha256"));
    reviewerKeyId =
        reviewerKeyId.map(value -> normalizeSingleLine(value, "review.reviewer.key.id"));
    reviewerPolicy =
        reviewerPolicy.map(value -> normalizeSingleLine(value, "review.reviewer.policy"));
    receiptFingerprintSha256 =
        receiptFingerprintSha256.map(
            value -> normalizeSha256(value, "review.receipt.fingerprint.sha256"));
    decisionReasonSha256 =
        decisionReasonSha256.map(value -> normalizeSha256(value, "review.decision.reason.sha256"));
    resubmissionOf =
        resubmissionOf.map(value -> normalizeSingleLine(value, "review.resubmissionOf"));
  }

  /**
   * Returns whether this value should be written to a catalog sidecar.
   *
   * <p>The minimal catalog format stays compact by omitting default review metadata. A non-default
   * status or any present note is meaningful catalog data and should be serialized so the signed
   * sidecar carries the publisher's advisory review state.
   *
   * @return {@code true} when a non-default status or a note is present
   */
  public boolean hasCatalogFields() {
    return status != AppCatalogReviewStatus.UNREVIEWED
        || note.isPresent()
        || hasSubmissionReviewFields();
  }

  /**
   * Returns whether this metadata carries third-party submission review workflow fields.
   *
   * <p>The predicate intentionally includes status-only workflow states such as {@code submitted},
   * {@code pre_review_passed}, and {@code resubmitted}. API and catalog-version callers should use
   * this method rather than rechecking individual optional fields so status-only workflow metadata
   * is not dropped.
   *
   * @return {@code true} when this metadata belongs to the submission review workflow
   */
  public boolean hasSubmissionReviewFields() {
    return status.requiresSubmissionReviewCatalogVersion()
        || submissionId.isPresent()
        || submissionSha256.isPresent()
        || preReviewStatus.isPresent()
        || preReviewSha256.isPresent()
        || reviewerKeyId.isPresent()
        || reviewerPolicy.isPresent()
        || receiptFingerprintSha256.isPresent()
        || decisionReasonSha256.isPresent()
        || resubmissionOf.isPresent()
        || nonProduction;
  }

  private static String normalizeSingleLine(String value, String fieldName) {
    return normalizeSingleLine(value, fieldName, MAX_REVIEW_FIELD_CHARS);
  }

  private static String normalizeSingleLine(String value, String fieldName, int maxChars) {
    return AppCatalogSidecars.requireBoundedSingleLine(
        value, fieldName, AppCatalogSidecars.INVALID_CATALOG_ENTRY, maxChars);
  }

  private static String normalizeSha256(String value, String fieldName) {
    return AppCatalogSidecars.requireLowercaseSha256(value, fieldName);
  }
}
