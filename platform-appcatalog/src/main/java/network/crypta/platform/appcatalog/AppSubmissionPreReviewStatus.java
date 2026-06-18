package network.crypta.platform.appcatalog;

import java.util.Locale;

/**
 * Aggregate status for automated third-party app pre-review.
 *
 * <p>The status is derived from findings: blockers become {@link #FAIL}, warnings without blockers
 * become {@link #WARN}, and an empty/blocker-free report becomes {@link #PASS}. Reviewers may still
 * issue a final caution or rejection after a passing automated report.
 *
 * <p>This enum is part of the deterministic pre-review JSON schema and the catalog candidate
 * metadata shown to local operators. It describes automated checks only. It is not a trusted review
 * receipt and does not replace reviewer signatures, reviewer-key policy, or transparency-log
 * records.
 */
public enum AppSubmissionPreReviewStatus {
  /**
   * No blocker or warning findings were produced.
   *
   * <p>Passing automated checks make a submission eligible for reviewer decision, but production
   * catalog promotion still requires the review policy gates for that catalog.
   */
  PASS("pass"),

  /**
   * No blockers were produced, but reviewer-visible warnings remain.
   *
   * <p>A warning status is promotion-ready from the automated pre-review perspective. Reviewers may
   * preserve the warning in a caution decision or request changes.
   */
  WARN("warn"),

  /**
   * At least one blocker prevents promotion or receipt issuance.
   *
   * <p>Failed pre-review reports must not be treated as installable catalog evidence. The finding
   * list carries the actionable blocker ids and redacted details.
   */
  FAIL("fail");

  private final String jsonValue;

  AppSubmissionPreReviewStatus(String jsonValue) {
    this.jsonValue = jsonValue;
  }

  /**
   * Parses a report status value.
   *
   * <p>The parser accepts stable JSON spellings and normalizes case for hand-authored test
   * fixtures. Unknown or malformed values fail closed instead of being interpreted as a pass.
   *
   * @param raw raw report status value read from pre-review JSON
   * @return matching status used by report validation
   */
  public static AppSubmissionPreReviewStatus parse(String raw) {
    String value =
        AppCatalogSidecars.requireBoundedSingleLine(
                raw, "preReview.status", AppCatalogSidecars.INVALID_CATALOG_ENTRY, 16)
            .toLowerCase(Locale.ROOT);
    for (AppSubmissionPreReviewStatus status : values()) {
      if (status.jsonValue.equals(value)) {
        return status;
      }
    }
    throw AppCatalogSidecars.invalidEntry("unsupported pre-review status: " + raw);
  }

  /**
   * Returns the stable JSON spelling.
   *
   * @return lower-case report status token
   */
  public String jsonValue() {
    return jsonValue;
  }
}
