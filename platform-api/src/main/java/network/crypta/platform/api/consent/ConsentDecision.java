package network.crypta.platform.api.consent;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Operator decision for one consent request and snapshot digest.
 *
 * <p>A decision records what a host/operator did after reviewing a consent snapshot. It stores the
 * request id, the digest that was approved or rejected, the actor marker, and the decision time.
 * Mutating routes accept only an approved decision whose request id, digest, app id, and action
 * still match the current prepared snapshot. Rejections and deferrals are returned to clients and
 * audited, but they never satisfy a consent gate.
 *
 * <p>The record is immutable and contains no raw manifest, app-data, service-call, or catalog
 * payloads. It is suitable for process-local decision caches and for conversion into bounded audit
 * events.
 *
 * @param decisionId opaque local id assigned to this operator decision
 * @param consentRequestId request id from the preview that was reviewed
 * @param status stable decision state, such as approved or rejected
 * @param actor redacted local actor marker recorded for audit context
 * @param snapshotDigest digest of the preview the operator acted on
 * @param decidedAt timestamp when the decision was recorded
 * @see ConsentDecisionStatus
 * @see ConsentAuditEvent
 */
public record ConsentDecision(
    String decisionId,
    String consentRequestId,
    ConsentDecisionStatus status,
    String actor,
    String snapshotDigest,
    Instant decidedAt) {
  /**
   * Creates a normalized decision record.
   *
   * <p>All identifiers are trimmed and must be non-blank because they are used as stable cache and
   * response fields. The constructor does not validate that the digest is current; that check
   * occurs when a route asks {@link ConsentService} to consume an approved decision.
   *
   * @throws IllegalArgumentException when an identifier, actor, or digest is blank
   * @throws NullPointerException when any required component is null
   */
  public ConsentDecision {
    decisionId = requireText(decisionId, "decisionId");
    consentRequestId = requireText(consentRequestId, "consentRequestId");
    Objects.requireNonNull(status, "status");
    actor = requireText(actor, "actor");
    snapshotDigest = requireText(snapshotDigest, "snapshotDigest");
    Objects.requireNonNull(decidedAt, "decidedAt");
  }

  /**
   * Converts this decision to the public Platform API JSON shape.
   *
   * <p>The returned map preserves insertion order for deterministic responses. It exposes stable
   * ids, the status token, the actor marker, the digest, and the decision timestamp, but never the
   * full reviewed snapshot.
   *
   * @return ordered JSON-compatible decision summary for Platform API responses
   */
  public Map<String, Object> toJsonValue() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(6);
    json.put("decisionId", decisionId);
    json.put("consentRequestId", consentRequestId);
    json.put("decision", status.jsonValue());
    json.put("actor", actor);
    json.put("snapshotDigest", snapshotDigest);
    json.put("timestamp", decidedAt.toString());
    return json;
  }

  private static String requireText(String value, String fieldName) {
    String text = Objects.requireNonNull(value, fieldName).trim();
    if (text.isEmpty()) {
      throw new IllegalArgumentException(fieldName + " must not be blank");
    }
    return text;
  }
}
