package network.crypta.platform.api.consent;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Redacted audit record for an approval, reject, defer, or expiry decision.
 *
 * <p>Consent audit events are the support-safe trail for operator decisions. They record which app
 * and action were reviewed, the final decision status, the snapshot digest, and a short material
 * risk summary. They intentionally do not store raw manifest JSON, app-service request bodies,
 * app-data values, backup payloads, migration logs, private insert URIs, tokens, or local paths.
 *
 * <p>Events are immutable after construction. The material risk summary is redacted before storage
 * so both in-memory and file-backed stores can expose the same bounded JSON shape to Web Shell,
 * release evidence, and local support tooling.
 *
 * @param decisionId opaque id of the decision being audited
 * @param consentRequestId request id of the reviewed preview
 * @param actor redacted local actor marker, usually the host/operator principal
 * @param appId app id affected by the reviewed operation
 * @param action consent action family that was reviewed
 * @param decision final decision state recorded for the request
 * @param timestamp time when the decision or expiry was recorded
 * @param snapshotDigest digest of the reviewed consent snapshot
 * @param materialRiskSummary redacted stable reason codes or short summaries for material findings
 * @see ConsentAuditStore
 */
public record ConsentAuditEvent(
    String decisionId,
    String consentRequestId,
    String actor,
    String appId,
    ConsentActionType action,
    ConsentDecisionStatus decision,
    Instant timestamp,
    String snapshotDigest,
    List<String> materialRiskSummary) {
  /**
   * Creates a normalized audit event.
   *
   * <p>Identifiers, actor, app id, and digest are trimmed and must be non-blank. The risk summary
   * is copied into an immutable list after applying consent redaction to each element. This keeps
   * file append and in-memory stores from retaining caller-owned mutable lists or sensitive text.
   *
   * @throws IllegalArgumentException when a required string component is blank
   * @throws NullPointerException when any required component or risk-summary list is null
   */
  public ConsentAuditEvent {
    decisionId = requireText(decisionId, "decisionId");
    consentRequestId = requireText(consentRequestId, "consentRequestId");
    actor = requireText(actor, "actor");
    appId = requireText(appId, "appId");
    Objects.requireNonNull(action, "action");
    Objects.requireNonNull(decision, "decision");
    Objects.requireNonNull(timestamp, "timestamp");
    snapshotDigest = requireText(snapshotDigest, "snapshotDigest");
    materialRiskSummary =
        List.copyOf(
            Objects.requireNonNull(materialRiskSummary, "materialRiskSummary").stream()
                .map(ConsentRedactor::redact)
                .toList());
  }

  /**
   * Converts this event to a safe audit JSON record.
   *
   * <p>The returned map is ordered for deterministic JSON-lines output and contains only bounded,
   * redacted fields. It can be returned from {@code /consent/audit} or appended to the local audit
   * store without additional filtering.
   *
   * @return ordered JSON-compatible audit event
   */
  public Map<String, Object> toJsonValue() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(9);
    json.put("decisionId", decisionId);
    json.put("consentRequestId", consentRequestId);
    json.put("actor", actor);
    json.put("appId", appId);
    json.put("action", action.jsonValue());
    json.put("decision", decision.jsonValue());
    json.put("timestamp", timestamp.toString());
    json.put("snapshotDigest", snapshotDigest);
    json.put("materialRiskSummary", materialRiskSummary);
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
