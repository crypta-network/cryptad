package network.crypta.platform.appcatalog;

import java.util.Objects;

/**
 * Independently signed app review receipt carried by a catalog entry.
 *
 * <p>A receipt signature is independent of the catalog signature. Catalog verification proves the
 * catalog bytes came from a trusted catalog signer; receipt verification proves a configured
 * reviewer key signed review evidence for the specific app version and artifact metadata in the
 * payload.
 *
 * <p>This value is intentionally small: it keeps the canonical payload beside the detached
 * signature, but it does not know which reviewer keys are trusted on a node. Callers evaluate a
 * receipt with {@link AppReviewReceiptVerifier}, which checks the local reviewer registry, expiry,
 * and binding to the catalog entry that carried the receipt. That split keeps parsing deterministic
 * and makes trust policy a runtime choice rather than catalog publisher metadata.
 *
 * <p>Instances are immutable after construction. The payload is the exact material that is signed;
 * the signature value is never included in the canonical payload bytes.
 *
 * @param payload canonical receipt payload that binds review evidence to one artifact
 * @param signature detached signature over {@link AppReviewReceiptPayload#canonicalPayloadBytes()}
 */
public record AppReviewReceipt(
    AppReviewReceiptPayload payload, AppReviewReceiptSignature signature) {
  /**
   * Creates a validated receipt value.
   *
   * <p>The constructor enforces only structural presence. It does not verify cryptographic
   * signatures or trust the reviewer key because those operations require a local {@link
   * TrustedReviewerKeys} registry and a policy decision.
   *
   * @param payload canonical payload that the receipt signature covers
   * @param signature detached receipt signature supplied with the payload
   */
  public AppReviewReceipt {
    Objects.requireNonNull(payload, "payload");
    Objects.requireNonNull(signature, "signature");
  }

  /**
   * Confirms this receipt names the exact catalog entry metadata it is attached to.
   *
   * <p>The check is deliberately separate from signature verification. A receipt can be signed by a
   * trusted reviewer and still fail if it was copied to the wrong app, version, digest, or size.
   * App identity mismatches are reported separately from artifact mismatches so API clients can
   * show precise warnings without exposing local paths or scratch directories.
   *
   * @param appId catalog entry app id that the receipt must match after normalization
   * @param appVersion catalog entry version that the receipt must name exactly
   * @param artifactSha256 catalog artifact SHA-256 digest that the receipt must bind
   * @param artifactSizeBytes catalog artifact size in bytes that the receipt must bind
   * @return mismatch status, or {@code null} when the receipt binds to the entry
   */
  AppReviewTrustStatus mismatchStatus(
      String appId, String appVersion, String artifactSha256, long artifactSizeBytes) {
    if (!payload.appId().equals(AppCatalogEntry.normalizeAppId(appId))
        || !payload.appVersion().equals(appVersion)) {
      return AppReviewTrustStatus.APP_MISMATCH;
    }
    if (!payload.artifactSha256().equals(artifactSha256)
        || payload.artifactSizeBytes() != artifactSizeBytes) {
      return AppReviewTrustStatus.ARTIFACT_MISMATCH;
    }
    return null;
  }
}
