package network.crypta.platform.appcatalog;

import java.util.Locale;

/**
 * Reviewer decision values accepted by the public-beta intake queue.
 *
 * <p>Reviewed and caution decisions require signed receipt evidence. Rejected and resubmission
 * requested decisions are negative or change-request outcomes and must not create installable beta
 * catalog candidates.
 */
public enum AppSubmissionReviewDecision {
  /** Reviewer accepted the submission for beta catalog candidate staging. */
  REVIEWED("reviewed"),

  /** Reviewer accepted the submission with operator-visible caution metadata. */
  CAUTION("caution"),

  /** Reviewer rejected the submission. */
  REJECTED("rejected"),

  /** Reviewer requested a future submission linked by {@code resubmissionOf}. */
  RESUBMISSION_REQUESTED("resubmission_requested");

  private final String jsonValue;

  AppSubmissionReviewDecision(String jsonValue) {
    this.jsonValue = jsonValue;
  }

  /**
   * Parses a reviewer decision token.
   *
   * @param raw CLI, JSON, or sidecar decision text
   * @return matching decision
   */
  public static AppSubmissionReviewDecision parse(String raw) {
    String value =
        AppCatalogSidecars.requireBoundedSingleLine(
                raw, "intake.decision", AppCatalogSidecars.INVALID_CATALOG_ENTRY, 48)
            .toLowerCase(Locale.ROOT);
    for (AppSubmissionReviewDecision decision : values()) {
      if (decision.jsonValue.equals(value)) {
        return decision;
      }
    }
    throw AppCatalogSidecars.invalidEntry("unsupported intake decision: " + raw);
  }

  /**
   * Converts this intake decision to a signed receipt status.
   *
   * @return receipt status for reviewed, caution, or rejected decisions
   * @throws AppCatalogException if the decision does not issue review receipts
   */
  public AppReviewReceiptStatus receiptStatus() {
    return switch (this) {
      case REVIEWED -> AppReviewReceiptStatus.REVIEWED;
      case CAUTION -> AppReviewReceiptStatus.CAUTION;
      case REJECTED -> AppReviewReceiptStatus.REJECTED;
      case RESUBMISSION_REQUESTED ->
          throw AppCatalogSidecars.invalidEntry("resubmission requests do not issue receipts");
    };
  }

  /**
   * Returns whether this decision blocks beta catalog candidate staging.
   *
   * @return {@code true} for rejected and resubmission-requested decisions
   */
  public boolean blocksCatalogCandidateStaging() {
    return this == REJECTED || this == RESUBMISSION_REQUESTED;
  }

  /**
   * Returns whether this decision requires a signed review receipt.
   *
   * @return {@code true} for reviewed and caution decisions
   */
  public boolean requiresReceipt() {
    return this == REVIEWED || this == CAUTION;
  }

  /**
   * Returns the persisted JSON value.
   *
   * @return stable lower-case decision value
   */
  public String jsonValue() {
    return jsonValue;
  }
}
