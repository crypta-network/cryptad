package network.crypta.platform.trustgraph;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Deterministic local score result for one subject/context query.
 *
 * <p>The score result is intentionally descriptive rather than authoritative moderation state. A
 * status of {@code trusted}, {@code distrusted}, or {@code mixed} reflects only direct, local,
 * signature-verified, non-expired evidence from anchored issuers. {@code unknown} means no retained
 * evidence contributed, even if non-anchor, expired, zero-confidence, or unverified evidence was
 * present.
 *
 * @param subject query subject
 * @param context query context
 * @param status trusted, distrusted, mixed, or unknown
 * @param score confidence-weighted score
 * @param confidence average contributing confidence
 * @param evidenceCount total evidence rows considered
 * @param contributingEvidenceCount evidence rows that contributed to the final score
 * @param evidence bounded evidence rows
 */
public record TrustGraphScore(
    TrustSubject subject,
    String context,
    String status,
    int score,
    int confidence,
    int evidenceCount,
    int contributingEvidenceCount,
    List<TrustGraphEvidence> evidence) {
  /** Creates a score result with immutable evidence. */
  public TrustGraphScore {
    java.util.Objects.requireNonNull(subject, "subject");
    context = TrustStatementValidator.requiredContext(context);
    status = TrustStatementValidator.requiredText("status", status, 16);
    evidence = List.copyOf(evidence);
  }

  /**
   * Returns this score as an insertion-ordered JSON object.
   *
   * <p>Evidence rows are optional because callers that only need a status should not receive the
   * bounded evidence array by default.
   *
   * @param includeEvidence whether to include bounded evidence rows in the response
   * @return public score summary suitable for Platform API responses
   */
  public Map<String, Object> toJson(boolean includeEvidence) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(8);
    json.put("subject", subject.toJson());
    json.put("context", context);
    json.put("status", status);
    json.put("score", score);
    json.put("confidence", confidence);
    json.put("evidenceCount", evidenceCount);
    json.put("contributingEvidenceCount", contributingEvidenceCount);
    if (includeEvidence) {
      json.put("evidence", evidence.stream().map(TrustGraphEvidence::toJson).toList());
    }
    return json;
  }
}
