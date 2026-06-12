package network.crypta.platform.appcatalog;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Local governance entry that revokes one exact app review receipt fingerprint.
 *
 * <p>Receipt revocation is distinct from reviewer-key revocation. A reviewer key can remain active
 * while one receipt fingerprint is locally revoked after an advisory or evidence correction. The
 * record is display-safe: it contains bounded identifiers, hashes, timestamps, and a reason, not
 * raw signatures, key bytes, local registry paths, or receipt contents.
 *
 * <p>The fingerprint covers the canonical review payload and detached signature metadata/value, so
 * a revocation identifies one concrete receipt rather than every receipt for the same app version
 * or reviewer. The additional app id, version, bundle digest, and reviewer id fields are diagnostic
 * context for governance screens and release evidence. Verification code treats the fingerprint as
 * authoritative for matching.
 *
 * <p>Instances are loaded from local trusted-reviewer governance configuration. They are immutable
 * after validation and can be rendered safely through API or Web Shell summaries without exposing
 * the raw receipt body.
 *
 * @param id local revocation id from the trusted-reviewer registry
 * @param receiptFingerprintSha256 exact receipt fingerprint to revoke
 * @param appId normalized app id for operator diagnostics
 * @param appVersion app version for operator diagnostics
 * @param bundleSha256 catalog bundle digest named by the revoked receipt
 * @param reviewerKeyId reviewer key id named by the revoked receipt
 * @param revokedAt local revocation timestamp from governance configuration
 * @param reason bounded single-line revocation reason safe for display
 */
public record AppReviewReceiptRevocation(
    String id,
    String receiptFingerprintSha256,
    String appId,
    String appVersion,
    String bundleSha256,
    String reviewerKeyId,
    Instant revokedAt,
    String reason) {
  private static final int MAX_VERSION_CHARS = 128;
  private static final int MAX_REVIEWER_KEY_ID_CHARS = 128;
  private static final int MAX_REASON_CHARS = 512;
  private static final String REVIEW_REVOCATION_PREFIX = "review.revocation.";

  /**
   * Creates a validated receipt revocation entry.
   *
   * <p>The constructor validates every field as bounded, display-safe governance metadata. Hashes
   * must be lowercase SHA-256 strings, ids must be single-line safe tokens, and the timestamp must
   * be present. Invalid configuration fails closed during trusted-reviewer registry loading.
   *
   * @throws AppCatalogException if any revocation field is malformed or unsafe
   */
  public AppReviewReceiptRevocation {
    id = AppCatalogSecurityAdvisory.normalizeId(id, "review revocation id");
    String propertyPrefix = REVIEW_REVOCATION_PREFIX + id + ".";
    receiptFingerprintSha256 =
        AppCatalogSidecars.requireLowercaseSha256(
            receiptFingerprintSha256, propertyPrefix + "receiptFingerprintSha256");
    appId = AppCatalogEntry.normalizeAppId(appId);
    appVersion =
        AppCatalogSidecars.requireBoundedSingleLine(
            appVersion,
            propertyPrefix + "appVersion",
            AppCatalogSidecars.INVALID_CATALOG_ENTRY,
            MAX_VERSION_CHARS);
    bundleSha256 =
        AppCatalogSidecars.requireLowercaseSha256(bundleSha256, propertyPrefix + "bundleSha256");
    reviewerKeyId =
        AppCatalogSidecars.requireBoundedSingleLine(
            reviewerKeyId,
            propertyPrefix + "reviewerKeyId",
            AppCatalogSidecars.INVALID_CATALOG_ENTRY,
            MAX_REVIEWER_KEY_ID_CHARS);
    Objects.requireNonNull(revokedAt, "revokedAt");
    reason =
        AppCatalogSidecars.requireBoundedSingleLine(
            reason,
            propertyPrefix + "reason",
            AppCatalogSidecars.INVALID_CATALOG_ENTRY,
            MAX_REASON_CHARS);
  }

  /**
   * Returns whether this revocation matches the supplied receipt exactly.
   *
   * <p>The comparison intentionally uses only the receipt fingerprint. Diagnostic fields in this
   * record help operators understand the revocation but do not weaken the match or create alternate
   * matching rules. A receipt with the same app id and version but a different signature remains a
   * different receipt for local governance purposes.
   *
   * @param receipt receipt to check against the local revocation entry
   * @return true when the receipt fingerprint is exactly revoked
   */
  public boolean matches(AppReviewReceipt receipt) {
    return receiptFingerprintSha256.equals(receipt.fingerprintSha256());
  }

  /**
   * Converts this revocation to redacted JSON-compatible values.
   *
   * <p>The returned map is suitable for review-history APIs, Web Shell governance views, CLI
   * inspection, and release-certification evidence. It includes stable identifiers and hashes but
   * omits raw signatures, public key bytes, private keys, receipt contents, registry paths, and
   * local filesystem locations.
   *
   * @return safe revocation summary with deterministic field order
   */
  public Map<String, Object> toJsonValue() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(8);
    json.put("id", id);
    json.put("receiptFingerprintSha256", receiptFingerprintSha256);
    json.put("appId", appId);
    json.put("appVersion", appVersion);
    json.put("bundleSha256", bundleSha256);
    json.put("reviewerKeyId", reviewerKeyId);
    json.put("revokedAt", revokedAt.toString());
    json.put("reason", reason);
    return json;
  }
}
