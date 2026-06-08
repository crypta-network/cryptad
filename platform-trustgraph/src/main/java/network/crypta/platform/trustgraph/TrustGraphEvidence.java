package network.crypta.platform.trustgraph;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Bounded evidence row included in score responses.
 *
 * <p>Evidence rows explain why the local RC scorer did or did not use a retained statement. They
 * expose issuer fingerprint, score, confidence, timestamps, verification status, local anchor
 * status, lifecycle status, contribution status, expiry status, bounded non-contribution reason
 * codes, and a sanitized source label. They do not include raw trust documents, signature values,
 * request bodies, fetched content, local paths, or private issuer material.
 *
 * @param issuerFingerprint public fingerprint claimed by the statement issuer
 * @param score statement score in the inclusive range {@code -100..100}
 * @param confidence statement confidence in the inclusive range {@code 0..100}
 * @param issuedAt statement issue timestamp
 * @param expiresAt optional expiry timestamp
 * @param signatureVerified whether the retained statement signature verified locally
 * @param anchored whether the issuer fingerprint is currently a local anchor
 * @param contributing whether this row affected the final score calculation
 * @param expired whether the statement was expired at scoring time
 * @param lifecycleStatus local lifecycle status for this statement fingerprint
 * @param nonContributingReasons stable reason codes explaining why a matching row did not
 *     contribute
 * @param source sanitized import source label
 */
public record TrustGraphEvidence(
    String issuerFingerprint,
    int score,
    int confidence,
    Instant issuedAt,
    Instant expiresAt,
    boolean signatureVerified,
    boolean anchored,
    boolean contributing,
    boolean expired,
    TrustStatementLifecycleStatus lifecycleStatus,
    List<String> nonContributingReasons,
    String source) {
  /** Creates a validated immutable evidence row. */
  public TrustGraphEvidence {
    java.util.Objects.requireNonNull(lifecycleStatus, "lifecycleStatus");
    nonContributingReasons = List.copyOf(nonContributingReasons);
  }

  /**
   * Returns this evidence row as an insertion-ordered JSON object.
   *
   * @return public evidence metadata suitable for bounded score responses
   */
  public Map<String, Object> toJson() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(12);
    json.put("issuerFingerprint", issuerFingerprint);
    json.put("score", score);
    json.put("confidence", confidence);
    json.put("issuedAt", issuedAt.toString());
    json.put("expiresAt", expiresAt == null ? null : expiresAt.toString());
    json.put("signatureVerified", signatureVerified);
    json.put("anchored", anchored);
    json.put("contributing", contributing);
    json.put("expired", expired);
    json.put("lifecycleStatus", lifecycleStatus.jsonValue());
    json.put("nonContributingReasons", nonContributingReasons);
    json.put("source", source);
    return json;
  }
}
