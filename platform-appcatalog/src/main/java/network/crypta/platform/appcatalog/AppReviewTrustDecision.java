package network.crypta.platform.appcatalog;

import java.net.URI;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Safe review-trust summary for one catalog entry.
 *
 * <p>The decision carries only display-safe identifiers, timestamps, evidence digests/URIs, policy
 * flags, and warnings. It never exposes reviewer public key bytes, private key material, local
 * receipt paths, catalog scratch paths, staged bundle paths, rollback paths, or process/session
 * tokens.
 *
 * <p>Instances are immutable snapshots of a verifier result at one point in time. The same receipt
 * can produce a different decision later if the local reviewer registry, policy mode, or clock
 * changes. Consumers should treat the boolean flags as derived policy hints for the current node,
 * not as properties signed by the reviewer or catalog publisher.
 *
 * <p>The fields intentionally separate trust from positivity. A trusted rejected receipt verifies
 * cryptographically but is not positive; a publisher-only claim may be visible but is not trusted.
 * This distinction is the core API contract exposed to Web Shell, install/update gates, and release
 * certification evidence.
 *
 * @param status stable review trust status for the evaluated catalog entry
 * @param trusted whether the receipt signature was verified by a configured reviewer key
 * @param positive whether the trusted receipt is a positive reviewed decision
 * @param requiresAcknowledgement whether local policy requires explicit operator acknowledgement
 * @param blocksInstall whether local policy blocks catalog install
 * @param blocksUpdate whether local policy blocks catalog update/stage
 * @param blocksPolicyApply whether local policy blocks policy-driven apply
 * @param reviewerKeyId display-safe reviewer key id, when known
 * @param reviewerDisplayName display-safe reviewer name, when configured
 * @param policyId receipt policy id, when known
 * @param policyVersion receipt policy version, when known
 * @param reviewedAt receipt reviewed-at instant, when known
 * @param expiresAt receipt expiry instant, when known
 * @param evidenceSha256 evidence digest, when supplied
 * @param evidenceUri evidence URI, when supplied
 * @param warnings display-safe warnings explaining mismatches or untrusted states
 * @param policyMode local policy mode used to derive gate flags
 */
public record AppReviewTrustDecision(
    AppReviewTrustStatus status,
    boolean trusted,
    boolean positive,
    boolean requiresAcknowledgement,
    boolean blocksInstall,
    boolean blocksUpdate,
    boolean blocksPolicyApply,
    String reviewerKeyId,
    String reviewerDisplayName,
    String policyId,
    String policyVersion,
    Instant reviewedAt,
    Instant expiresAt,
    String evidenceSha256,
    URI evidenceUri,
    List<String> warnings,
    AppReviewPolicyMode policyMode) {
  /**
   * Creates a validated decision.
   *
   * <p>The warning list is defensively copied to preserve deterministic API output. Nullable
   * metadata fields remain nullable because untrusted or missing receipt states often do not have a
   * reviewer id, evidence URI, or receipt timestamp to expose.
   *
   * @param status stable review trust status for the entry
   * @param trusted whether the receipt cryptographically verified with a configured key
   * @param positive whether the trusted receipt is a positive review
   * @param requiresAcknowledgement whether local policy requires operator acknowledgement
   * @param blocksInstall whether local policy blocks manual catalog install
   * @param blocksUpdate whether local policy blocks manual catalog update or staging
   * @param blocksPolicyApply whether local policy blocks automatic policy-driven apply
   * @param reviewerKeyId reviewer key id from the receipt payload, when available
   * @param reviewerDisplayName reviewer display name from local trust configuration, when available
   * @param policyId review policy id from the receipt payload, when available
   * @param policyVersion review policy version from the receipt payload, when available
   * @param reviewedAt receipt review timestamp, when available
   * @param expiresAt receipt expiry timestamp, when available
   * @param evidenceSha256 receipt evidence digest, when supplied
   * @param evidenceUri receipt evidence URI, when supplied
   * @param warnings display-safe warning strings for UI and audit summaries
   * @param policyMode local policy mode that produced the gate flags
   */
  public AppReviewTrustDecision {
    Objects.requireNonNull(status, "status");
    warnings = List.copyOf(Objects.requireNonNull(warnings, "warnings"));
    Objects.requireNonNull(policyMode, "policyMode");
  }

  /**
   * Converts this decision to Platform API JSON-compatible values.
   *
   * <p>The map preserves stable field order for tests, documentation examples, and Web Shell
   * rendering. Timestamps and URIs are converted to strings, and nullable fields stay present with
   * {@code null} values so clients can distinguish unavailable metadata from omitted fields.
   *
   * @return safe review trust JSON object without key bytes, private material, paths, or tokens
   */
  public Map<String, Object> toJsonValue() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(17);
    json.put("status", status.jsonValue());
    json.put("trusted", trusted);
    json.put("positive", positive);
    json.put("requiresAcknowledgement", requiresAcknowledgement);
    json.put("blocksInstall", blocksInstall);
    json.put("blocksUpdate", blocksUpdate);
    json.put("blocksPolicyApply", blocksPolicyApply);
    json.put("reviewerKeyId", reviewerKeyId);
    json.put("reviewerDisplayName", reviewerDisplayName);
    json.put("policyId", policyId);
    json.put("policyVersion", policyVersion);
    json.put("policyMode", policyMode.jsonValue());
    json.put("reviewedAt", reviewedAt == null ? null : reviewedAt.toString());
    json.put("expiresAt", expiresAt == null ? null : expiresAt.toString());
    json.put("evidenceSha256", evidenceSha256);
    json.put("evidenceUri", evidenceUri == null ? null : evidenceUri.toString());
    json.put("warnings", warnings);
    return json;
  }
}
