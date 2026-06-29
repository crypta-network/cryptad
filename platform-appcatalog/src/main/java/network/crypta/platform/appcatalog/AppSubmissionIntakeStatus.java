package network.crypta.platform.appcatalog;

import java.util.Locale;

/**
 * Local public-beta intake state for one third-party app submission.
 *
 * <p>The values are persisted in file-backed intake queue records and exposed through operator
 * diagnostics. They describe local reviewer workflow only. They do not replace signed catalog
 * verification, app bundle verification, trusted reviewer receipts, consent snapshots, security
 * advisory checks, or install/update policy.
 */
public enum AppSubmissionIntakeStatus {
  /** A verified submission package was imported into the local intake queue. */
  SUBMITTED("submitted"),

  /** The submission was triaged before assignment or automated review. */
  TRIAGED("triaged"),

  /** A reviewer key id and display name were assigned to the submission. */
  REVIEWER_ASSIGNED("reviewer_assigned"),

  /** Automated pre-review is currently running for the queued submission. */
  PRE_REVIEW_RUNNING("pre_review_running"),

  /** Automated pre-review completed without blocker findings. */
  PRE_REVIEW_PASSED("pre_review_passed"),

  /** Automated pre-review completed with blocker findings. */
  PRE_REVIEW_FAILED("pre_review_failed"),

  /** A reviewer is evaluating the pre-review output and submission metadata. */
  REVIEW_IN_PROGRESS("review_in_progress"),

  /** A reviewer issued a reviewed decision and receipt evidence. */
  REVIEWED("reviewed"),

  /** A reviewer issued a caution decision and receipt evidence. */
  CAUTION("caution"),

  /** A reviewer rejected the submission. */
  REJECTED("rejected"),

  /** A reviewer requested a future linked resubmission. */
  RESUBMISSION_REQUESTED("resubmission_requested"),

  /** A reviewed or caution submission produced beta catalog candidate artifacts. */
  CATALOG_CANDIDATE_CREATED("catalog_candidate_created"),

  /** Candidate artifacts were staged into the beta catalog candidate area. */
  STAGED_TO_BETA_CATALOG("staged_to_beta_catalog"),

  /** Local structural install-from-beta-catalog smoke evidence passed. */
  BETA_INSTALL_SMOKE_PASSED("beta_install_smoke_passed"),

  /** Local reviewer workflow is closed. */
  CLOSED("closed");

  private final String jsonValue;

  AppSubmissionIntakeStatus(String jsonValue) {
    this.jsonValue = jsonValue;
  }

  /**
   * Parses a stable intake status value.
   *
   * @param raw JSON or sidecar status value
   * @return matching intake status
   */
  public static AppSubmissionIntakeStatus parse(String raw) {
    String value =
        AppCatalogSidecars.requireBoundedSingleLine(
                raw, "intake.status", AppCatalogSidecars.INVALID_CATALOG_ENTRY, 48)
            .toLowerCase(Locale.ROOT);
    for (AppSubmissionIntakeStatus status : values()) {
      if (status.jsonValue.equals(value)) {
        return status;
      }
    }
    throw AppCatalogSidecars.invalidEntry("unsupported intake status: " + raw);
  }

  /**
   * Returns the persisted JSON value for this state.
   *
   * @return stable lower-case status value
   */
  public String jsonValue() {
    return jsonValue;
  }
}
