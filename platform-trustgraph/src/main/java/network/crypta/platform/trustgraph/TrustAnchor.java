package network.crypta.platform.trustgraph;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Local trust anchor metadata.
 *
 * <p>Anchors are local process-owned state. Adding an anchor never publishes a trust statement and
 * does not imply global moderation or network-level blocking. The preview scorer treats an anchor
 * as permission for statements from that issuer fingerprint to contribute only when the statement
 * is also unexpired, signature-verified, and has positive confidence.
 *
 * <p>The record stores operator/app-facing labels only. It does not carry private identity
 * material, raw trust statement bodies, app tokens, or a pointer to any local vault path.
 *
 * @param issuerFingerprint public issuer fingerprint selected by the local app/operator
 * @param label optional bounded label
 * @param source bounded local source label
 * @param createdAt anchor creation time
 * @param lifecycleStatus local lifecycle state for this anchor
 * @param updatedAt latest local lifecycle or metadata update time
 * @param reasonCode optional short stable local reason token for the current lifecycle state
 */
public record TrustAnchor(
    String issuerFingerprint,
    String label,
    String source,
    Instant createdAt,
    TrustStatementLifecycleStatus lifecycleStatus,
    Instant updatedAt,
    String reasonCode) {
  /**
   * Creates an active local trust anchor.
   *
   * <p>This overload preserves existing call sites that only supply anchor identity and display
   * metadata. The resulting anchor is active immediately and records a default local reason code.
   */
  public TrustAnchor(String issuerFingerprint, String label, String source, Instant createdAt) {
    this(
        issuerFingerprint,
        label,
        source,
        createdAt,
        TrustStatementLifecycleStatus.ACTIVE,
        createdAt,
        "local-anchor");
  }

  /**
   * Creates a bounded local trust anchor.
   *
   * <p>Blank {@code source} values default to {@code manual}. Label and source text are trimmed,
   * reason codes are normalized to lifecycle-style stable tokens, and all public metadata is
   * checked before storage so anchor summaries stay safe for API responses and release evidence.
   */
  public TrustAnchor {
    issuerFingerprint =
        TrustStatementValidator.requiredText("issuerFingerprint", issuerFingerprint, 128);
    label = TrustStatementValidator.optionalText("label", label, 120);
    source = TrustStatementValidator.optionalText("source", source, 32);
    if (source == null) {
      source = "manual";
    }
    java.util.Objects.requireNonNull(createdAt, "createdAt");
    java.util.Objects.requireNonNull(lifecycleStatus, "lifecycleStatus");
    if (updatedAt == null) {
      updatedAt = createdAt;
    }
    reasonCode =
        TrustStatementLifecycleRecord.normalizeReasonCode(
            reasonCode, defaultReason(lifecycleStatus));
  }

  /**
   * Returns this anchor as an insertion-ordered JSON object.
   *
   * @return public local-anchor metadata without private key or path material
   */
  public Map<String, Object> toJson() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(8);
    json.put("issuerFingerprint", issuerFingerprint);
    json.put("label", label);
    json.put("source", source);
    json.put("createdAt", createdAt.toString());
    json.put("lifecycleStatus", lifecycleStatus.jsonValue());
    json.put("active", lifecycleStatus == TrustStatementLifecycleStatus.ACTIVE);
    json.put("updatedAt", updatedAt.toString());
    json.put("reasonCode", reasonCode);
    return json;
  }

  private static String defaultReason(TrustStatementLifecycleStatus lifecycleStatus) {
    return lifecycleStatus == TrustStatementLifecycleStatus.ACTIVE
        ? "local-anchor"
        : "operator-" + lifecycleStatus.jsonValue();
  }
}
