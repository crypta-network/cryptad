package network.crypta.platform.appcatalog;

/**
 * Stable Platform API status for local review-receipt trust evaluation.
 *
 * <p>These values describe the node's local trust decision for one catalog entry. They do not
 * replace catalog signature verification, bundle signature verification, or artifact digest checks.
 * Positive trust requires a valid receipt signature from a configured reviewer key and a positive
 * reviewer status.
 *
 * <p>The values are deliberately specific because Web Shell, Platform API clients, and release
 * certification use them to explain what failed. A status can be trusted without being positive
 * ({@link #TRUSTED_REJECTED}), or visible without being trusted ({@link #PUBLISHER_CLAIM_ONLY}).
 * Treat the lowercase {@link #jsonValue()} as stable API surface.
 */
public enum AppReviewTrustStatus {
  /**
   * A trusted reviewer signed a positive review receipt for this exact artifact.
   *
   * <p>This is the only status that counts as trusted positive review for strict install, update,
   * and policy-driven apply checks.
   */
  TRUSTED_REVIEWED("trusted_reviewed"),

  /**
   * A trusted reviewer signed a caution receipt for this exact artifact.
   *
   * <p>The signature and reviewer are trusted, but the status is not positive. Operators should see
   * the caution warning before deciding whether to proceed under policies that allow overrides.
   */
  TRUSTED_CAUTION("trusted_caution"),

  /**
   * A trusted reviewer signed a rejection receipt for this exact artifact.
   *
   * <p>This is trusted negative evidence. It must not be rendered as reviewed-positive even though
   * the signature verified.
   */
  TRUSTED_REJECTED("trusted_rejected"),

  /**
   * The entry has no review receipt and no publisher review claim.
   *
   * <p>This status is used when reviewer keys are configured and the catalog entry simply lacks
   * independent review evidence.
   */
  MISSING_RECEIPT("missing_receipt"),

  /**
   * The receipt names a reviewer key that is not locally trusted for the receipt policy.
   *
   * <p>This also covers policy id mismatches between the receipt and the configured reviewer key.
   */
  UNKNOWN_REVIEWER("unknown_reviewer"),

  /**
   * The receipt signature is missing, malformed, or does not verify over canonical payload bytes.
   *
   * <p>The receipt might still parse structurally, but the node cannot authenticate the payload
   * with the configured reviewer key.
   */
  INVALID_SIGNATURE("invalid_signature"),

  /**
   * The receipt artifact digest or size does not match the catalog entry.
   *
   * <p>The receipt may belong to another artifact for the same app/version. It is not trusted for
   * the entry being installed or updated.
   */
  ARTIFACT_MISMATCH("artifact_mismatch"),

  /**
   * The receipt app id or app version does not match the catalog entry.
   *
   * <p>This usually means a receipt was attached to the wrong catalog entry or was copied from a
   * different app release.
   */
  APP_MISMATCH("app_mismatch"),

  /**
   * The receipt expired before the local trust decision was computed.
   *
   * <p>Expired receipts fail closed even if their signature and reviewer key are otherwise valid.
   */
  EXPIRED("expired"),

  /**
   * The signed catalog carries only publisher advisory review metadata.
   *
   * <p>This preserves backward compatibility for legacy {@code review.status} and {@code
   * review.note} fields while making clear that no independent reviewer receipt verified.
   */
  PUBLISHER_CLAIM_ONLY("publisher_claim_only"),

  /**
   * The node has no trusted reviewer key material configured for receipt verification.
   *
   * <p>This is different from an unknown reviewer: there is no local review trust registry to check
   * against at all.
   */
  NOT_CONFIGURED("not_configured");

  private final String jsonValue;

  AppReviewTrustStatus(String jsonValue) {
    this.jsonValue = jsonValue;
  }

  /**
   * Returns the stable lower-case Platform API value.
   *
   * <p>The value is used in Platform API JSON, Web Shell display logic, stable error-code mapping,
   * and release-certification evidence. It should not change without a compatibility plan.
   *
   * @return JSON/status value for this trust decision
   */
  public String jsonValue() {
    return jsonValue;
  }
}
