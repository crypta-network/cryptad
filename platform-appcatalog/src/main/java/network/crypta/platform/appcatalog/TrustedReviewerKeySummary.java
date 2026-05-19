package network.crypta.platform.appcatalog;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Redacted JSON-facing summary for one trusted reviewer key.
 *
 * <p>This summary intentionally excludes public key bytes and all file provenance. It contains only
 * display-safe governance metadata needed by operators, Web Shell, CLI inspection, and
 * release-certification evidence.
 *
 * <p>The summary is derived from an in-process {@link TrustedReviewerKey}, which still contains
 * public verifier material. Callers should convert to this type before returning reviewer
 * governance data through Platform API, Web Shell, CLI, logs, or certification reports. The summary
 * preserves policy and lifecycle information so operators can explain why a receipt was trusted,
 * historical, revoked, or rejected by local governance.
 *
 * <p>Nullable fields stay present in the JSON output. That lets clients distinguish an omitted
 * lifecycle window or policy version from an unknown key, without exposing registry paths or raw
 * sidecar contents.
 *
 * @param keyId stable local reviewer key id
 * @param displayName optional operator-facing reviewer display name
 * @param algorithm signature algorithm name, currently {@code Ed25519}
 * @param status local lifecycle status for the key
 * @param policyId accepted review policy id, or {@code null} for unconstrained keys
 * @param policyVersion accepted review policy version, or {@code null} when unconstrained
 * @param validFrom optional inclusive validity start instant
 * @param validUntil optional exclusive validity end instant
 * @param revokedAt optional local revocation instant
 * @param revocationReason optional display-safe revocation reason
 * @param rotatesFrom optional predecessor reviewer key id
 * @param rotatesTo optional successor reviewer key id
 */
public record TrustedReviewerKeySummary(
    String keyId,
    String displayName,
    String algorithm,
    TrustedReviewerKeyStatus status,
    String policyId,
    String policyVersion,
    Instant validFrom,
    Instant validUntil,
    Instant revokedAt,
    String revocationReason,
    String rotatesFrom,
    String rotatesTo) {
  /**
   * Builds a redacted summary from a trusted reviewer key.
   *
   * <p>The conversion copies display-safe lifecycle and policy fields only. It deliberately drops
   * public key bytes, registry file paths, and any source provenance so the result can be
   * serialized by operator-facing endpoints.
   *
   * @param key trusted reviewer key that remains usable for in-process verification
   * @return summary without raw key material or local file provenance
   */
  public static TrustedReviewerKeySummary from(TrustedReviewerKey key) {
    TrustedReviewerKeyLifecycle lifecycle = key.lifecycle();
    TrustedReviewerPolicyConstraint constraint = key.policyConstraint();
    return new TrustedReviewerKeySummary(
        key.keyId(),
        key.displayName().orElse(null),
        key.algorithm(),
        lifecycle.status(),
        constraint.policyId().orElse(null),
        constraint.policyVersion().orElse(null),
        lifecycle.validFrom().orElse(null),
        lifecycle.validUntil().orElse(null),
        lifecycle.revokedAt().orElse(null),
        lifecycle.revocationReason().orElse(null),
        lifecycle.rotatesFrom().orElse(null),
        lifecycle.rotatesTo().orElse(null));
  }

  /**
   * Converts this summary to stable JSON-compatible values.
   *
   * <p>The map uses stable field names consumed by Platform API, Web Shell, developer CLI, and
   * release-certification evidence. Timestamp values are rendered as ISO-8601 instants and optional
   * fields remain present with {@code null} values.
   *
   * @return redacted key summary with lifecycle and policy metadata
   */
  public Map<String, Object> toJsonValue() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(12);
    json.put("keyId", keyId);
    json.put("displayName", displayName);
    json.put("algorithm", algorithm);
    json.put("status", status.jsonValue());
    json.put("policyId", policyId);
    json.put("policyVersion", policyVersion);
    json.put("validFrom", validFrom == null ? null : validFrom.toString());
    json.put("validUntil", validUntil == null ? null : validUntil.toString());
    json.put("revokedAt", revokedAt == null ? null : revokedAt.toString());
    json.put("revocationReason", revocationReason);
    json.put("rotatesFrom", rotatesFrom);
    json.put("rotatesTo", rotatesTo);
    return json;
  }
}
