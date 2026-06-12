package network.crypta.platform.appcatalog;

import java.util.Objects;

/**
 * Local review policy used when evaluating signed review receipts.
 *
 * <p>The policy converts a verifier result such as {@code missing_receipt}, {@code
 * trusted_reviewed}, or {@code trusted_rejected} into the booleans shown by Platform API and Web
 * Shell. It is deliberately local node state: catalogs and bundles cannot choose this mode, and
 * changing the policy does not alter catalog signature verification, bundle signature verification,
 * artifact digest checks, or the receipt signature itself.
 *
 * <p>The default mode is advisory so older catalogs and third-party apps remain visible and
 * manually installable. Operators that need stronger controls can switch to acknowledgement or
 * trusted-review modes without changing catalog formats. The object is immutable and safe to share
 * between request handlers; each decision is still recomputed against the current receipt, reviewer
 * registry, and clock.
 *
 * @param mode operator-selected review policy mode
 */
public record AppReviewPolicy(AppReviewPolicyMode mode) {
  /**
   * Default policy for normal nodes.
   *
   * <p>This mode displays review trust results but does not block manual install or update
   * operations. It keeps old catalogs and third-party catalogs usable while still surfacing whether
   * the node verified an independent review receipt.
   */
  public static final AppReviewPolicy DEFAULT = new AppReviewPolicy(AppReviewPolicyMode.ADVISORY);

  /**
   * System property used to select review policy mode.
   *
   * <p>When both the property and environment variable are present, the property wins. This mirrors
   * other local Cryptad configuration flows where process launch arguments intentionally override
   * the surrounding environment.
   */
  public static final String POLICY_MODE_PROPERTY = "cryptad.appreview.policyMode";

  /**
   * Environment variable used to select review policy mode.
   *
   * <p>The value is parsed with {@link AppReviewPolicyMode#parse(String)}. Blank values are ignored
   * so operators can leave the variable unset in shared shell profiles.
   */
  public static final String POLICY_MODE_ENV = "CRYPTAD_APPREVIEW_POLICY_MODE";

  /**
   * Creates a validated immutable policy value.
   *
   * @param mode operator-selected mode used to derive acknowledgement and blocking flags
   */
  public AppReviewPolicy {
    Objects.requireNonNull(mode, "mode");
  }

  /**
   * Loads policy from system property or environment variable, falling back to advisory mode.
   *
   * <p>The lookup is intentionally side-effect-free. It reads only process configuration and does
   * not touch trusted reviewer key files or catalog state. Callers that need deterministic behavior
   * in tests should construct the policy directly instead of changing process-wide properties.
   *
   * @return configured review policy, or {@link #DEFAULT} when no mode is configured
   */
  public static AppReviewPolicy loadFromSystem() {
    String raw = configuredPolicyMode();
    if (raw == null || raw.isBlank()) {
      return DEFAULT;
    }
    return new AppReviewPolicy(AppReviewPolicyMode.parse(raw));
  }

  boolean requiresAcknowledgement(AppReviewTrustStatus status) {
    if (forcedBlock(status)) {
      return false;
    }
    if (trustedPositive(status)) {
      return false;
    }
    return mode == AppReviewPolicyMode.WARN_UNTRUSTED
        || mode == AppReviewPolicyMode.REQUIRE_TRUSTED_REVIEW_FOR_APPLY_WHEN_STOPPED;
  }

  boolean blocksManualInstallOrUpdate(AppReviewTrustStatus status) {
    return forcedBlock(status)
        || (mode == AppReviewPolicyMode.REQUIRE_TRUSTED_REVIEW && !trustedPositive(status));
  }

  boolean blocksPolicyApply(AppReviewTrustStatus status) {
    return forcedBlock(status)
        || ((mode == AppReviewPolicyMode.REQUIRE_TRUSTED_REVIEW
                || mode == AppReviewPolicyMode.REQUIRE_TRUSTED_REVIEW_FOR_APPLY_WHEN_STOPPED)
            && !trustedPositive(status));
  }

  private static boolean trustedPositive(AppReviewTrustStatus status) {
    return status == AppReviewTrustStatus.TRUSTED_REVIEWED;
  }

  private static boolean forcedBlock(AppReviewTrustStatus status) {
    return status == AppReviewTrustStatus.REVOKED_RECEIPT
        || status == AppReviewTrustStatus.REVOKED_REVIEWER;
  }

  private static String configuredPolicyMode() {
    String propertyValue = System.getProperty(POLICY_MODE_PROPERTY);
    if (propertyValue != null && !propertyValue.isBlank()) {
      return propertyValue.trim();
    }
    String environmentValue = System.getenv(POLICY_MODE_ENV);
    return environmentValue == null || environmentValue.isBlank() ? null : environmentValue.trim();
  }
}
