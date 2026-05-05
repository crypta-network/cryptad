package network.crypta.platform.appcatalog;

import java.util.Locale;

/**
 * Local operator policy for converting review-receipt trust into install/update gates.
 *
 * <p>The mode is local node policy. It is not signed by app bundles or catalogs, and it does not
 * change how catalog signatures, bundle signatures, or artifact digests are verified.
 *
 * <p>Each value has a stable lowercase representation used by configuration, Platform API JSON, Web
 * Shell rendering, and release-certification summaries. The values are intentionally explicit about
 * manual operator actions versus policy-driven apply. A deployment can require a trusted receipt
 * before automatic apply without changing the behavior of a deliberate manual install or update
 * request.
 *
 * <ul>
 *   <li>Manual install/update gates use {@code blocksInstall}, {@code blocksUpdate}, and {@code
 *       requiresAcknowledgement}.
 *   <li>Automatic update apply uses {@code blocksPolicyApply} in addition to compatibility and
 *       runtime checks.
 * </ul>
 */
public enum AppReviewPolicyMode {
  /**
   * Show review-trust status without blocking manual install or update.
   *
   * <p>This is the compatibility mode for normal nodes and older catalogs. It still distinguishes
   * publisher advisory metadata from a trusted receipt, but all review-trust decisions remain
   * informational for manual actions.
   */
  ADVISORY("advisory"),

  /**
   * Allow manual install/update only when missing, untrusted, expired, mismatched, or rejected
   * review evidence is explicitly acknowledged by the operator.
   *
   * <p>This mode is useful when operators want the API and Web Shell to force a conscious decision
   * for untrusted review states while still permitting third-party apps that do not have trusted
   * review receipts.
   */
  WARN_UNTRUSTED("warn_untrusted"),

  /**
   * Block manual install/update unless a trusted positive review receipt is present.
   *
   * <p>The only positive state is {@code trusted_reviewed}. Trusted caution, trusted rejection,
   * missing receipts, expired receipts, mismatches, and unknown reviewers all fail closed for
   * manual install, manual update, and policy-driven apply.
   */
  REQUIRE_TRUSTED_REVIEW("require_trusted_review"),

  /**
   * Require a trusted positive review for policy-driven apply-when-stopped updates while allowing
   * manual install/update after operator acknowledgement.
   *
   * <p>This mode separates automation from operator intent. Scheduled apply is conservative, but a
   * person can still stage and apply a catalog update after acknowledging an untrusted review
   * decision.
   */
  REQUIRE_TRUSTED_REVIEW_FOR_APPLY_WHEN_STOPPED("require_trusted_review_for_apply_when_stopped");

  private final String jsonValue;

  AppReviewPolicyMode(String jsonValue) {
    this.jsonValue = jsonValue;
  }

  /**
   * Parses a public policy value.
   *
   * <p>The parser accepts only the stable lowercase values returned by {@link #jsonValue()}, with
   * case folded for operator convenience. Values remain bounded and single-line so configuration
   * errors cannot bleed into logs, API responses, or generated reports.
   *
   * @param value raw policy text from configuration or environment
   * @return parsed policy mode corresponding to the configured value
   * @throws AppCatalogException if the value is blank, multi-line, too long, or unsupported
   */
  public static AppReviewPolicyMode parse(String value) {
    String normalized =
        AppCatalogSidecars.requireBoundedSingleLine(
                value, "app review policy mode", AppCatalogSidecars.INVALID_CATALOG_ENTRY, 80)
            .toLowerCase(Locale.ROOT);
    for (AppReviewPolicyMode mode : values()) {
      if (mode.jsonValue.equals(normalized)) {
        return mode;
      }
    }
    throw AppCatalogSidecars.invalidEntry("unsupported app review policy mode: " + normalized);
  }

  /**
   * Returns the stable API/config value for this mode.
   *
   * <p>The returned string is the only public wire/config spelling for the mode. Keep it stable
   * across releases because operators can store it in node configuration and clients can compare it
   * in Platform API responses.
   *
   * @return lower-case policy value used in configuration and JSON
   */
  public String jsonValue() {
    return jsonValue;
  }
}
