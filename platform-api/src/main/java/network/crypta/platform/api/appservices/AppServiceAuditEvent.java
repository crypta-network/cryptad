package network.crypta.platform.api.appservices;

import java.time.Instant;
import java.util.LinkedHashMap;

/**
 * Redacted local audit event for app-service grant and invocation decisions.
 *
 * <p>Audit events record app ids, service ids, scope/context, status, reason codes, and safe
 * subject hashes. They intentionally omit request bodies, raw subject URIs, raw tokens, local
 * paths, private insert URIs, and provider-private data.
 *
 * <p>The event model is intentionally flat and bounded so it can be written to a simple durable
 * store, surfaced in Web Shell operator views, and included in release-certification evidence
 * without a second redaction pass. Event ids are local identifiers, not secrets. The subject hash
 * is safe for correlation within the local audit stream, but it is not reversible without the
 * original subject string.
 *
 * <p>Audit entries describe authorization decisions, not complete request transcripts. If an
 * invocation is denied before an adapter runs, the event still uses the same redacted shape so
 * operator tools can compare allowed and denied calls without seeing different classes of private
 * input.
 *
 * @param eventId stable local event identifier used as the durable audit record key
 * @param timestamp UTC timestamp for the grant or invocation decision
 * @param eventType normalized event type token such as {@code service_invoked}
 * @param consumerAppId optional consumer app id associated with the decision
 * @param providerAppId optional provider app id associated with the decision
 * @param serviceId optional public service id associated with the decision
 * @param grantId optional local grant id, never a bearer credential
 * @param scope optional scope/action checked for the decision
 * @param context optional invocation context checked for the decision
 * @param status normalized outcome token exposed to operator views
 * @param reasonCode stable machine-readable reason code for filtering and tests
 * @param subjectUriHash optional SHA-256 hash of the subject URI, never the raw URI
 */
public record AppServiceAuditEvent(
    String eventId,
    Instant timestamp,
    String eventType,
    String consumerAppId,
    String providerAppId,
    String serviceId,
    String grantId,
    String scope,
    String context,
    String status,
    String reasonCode,
    String subjectUriHash) {
  /**
   * Creates a validated audit event.
   *
   * <p>All identifier-like fields are normalized with the same parser used for service manifests.
   * Optional fields may be {@code null}; empty or malformed supplied values are rejected. The
   * constructor does not derive a subject hash because callers must decide whether a service
   * request contains any subject material worth recording.
   */
  public AppServiceAuditEvent {
    eventId = AppServiceManifestParser.normalizeEventId(eventId);
    java.util.Objects.requireNonNull(timestamp, "timestamp");
    eventType = AppServiceManifestParser.requiredToken("eventType", eventType, 64);
    consumerAppId =
        consumerAppId == null ? null : AppServiceManifestParser.normalizeAppId(consumerAppId);
    providerAppId =
        providerAppId == null ? null : AppServiceManifestParser.normalizeAppId(providerAppId);
    serviceId = serviceId == null ? null : AppServiceManifestParser.normalizeServiceId(serviceId);
    grantId = grantId == null ? null : AppServiceManifestParser.normalizeGrantId(grantId);
    scope = scope == null ? null : AppServiceManifestParser.normalizeToken("scope", scope);
    context = context == null ? null : AppServiceManifestParser.normalizeToken("context", context);
    status = AppServiceManifestParser.requiredToken("status", status, 32);
    reasonCode = AppServiceManifestParser.requiredToken("reasonCode", reasonCode, 80);
    subjectUriHash = AppServiceManifestParser.optionalText(subjectUriHash, 80);
  }

  /**
   * Returns deterministic JSON-compatible audit metadata.
   *
   * <p>The returned map preserves field order for stable snapshots and release evidence. It carries
   * only the redacted fields stored in this record, so callers can serialize it directly for
   * Platform API and Web Shell responses without adding local paths, request bodies, tokens, or raw
   * subject identifiers.
   *
   * @return public redacted audit event map with stable key order
   */
  public java.util.Map<String, Object> toJson() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(12);
    json.put("eventId", eventId);
    json.put("timestamp", timestamp.toString());
    json.put("eventType", eventType);
    json.put("consumerAppId", consumerAppId);
    json.put("providerAppId", providerAppId);
    json.put("serviceId", serviceId);
    json.put("grantId", grantId);
    json.put("scope", scope);
    json.put("context", context);
    json.put("status", status);
    json.put("reasonCode", reasonCode);
    json.put("subjectUriHash", subjectUriHash);
    return json;
  }
}
