package network.crypta.platform.trustgraph;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Redacted local audit event for Trust Graph Preview mutations and exchange actions.
 *
 * <p>Events are safe for app-facing summaries and release evidence. They carry stable hashes and
 * short status codes, but never raw trust statement JSON, raw signatures, fetched bodies, private
 * insert URIs, private keys, process tokens, browser-session tokens, form passwords, daemon
 * exception text, or local filesystem paths.
 *
 * <p>The record is deliberately flat and JSON-friendly because it crosses from platform-owned
 * storage to app-facing audit routes. Route handlers should derive event types from the server-side
 * workflow that actually ran, then fill in only public hashes, redacted summaries, and stable
 * status codes. Callers must hash or summarize URI-like values before construction; this type
 * validates bounds and control characters but does not transform raw URIs into safe evidence.
 *
 * <p>Typical event types include anchor add/remove, statement import from pasted text, statement
 * import from a fetched URI, local publish queueing, and rejected imports. Audit events are local
 * preview evidence only. They do not make trust global, alter routing, or certify compatibility
 * with the legacy WebOfTrust plugin.
 *
 * @param eventType bounded server-derived event type label, such as {@code statement_imported}
 * @param timestamp event creation time recorded by the handling workflow
 * @param appId optional app id associated with the request or local exchange action
 * @param documentFingerprint optional normalized public statement document fingerprint
 * @param payloadHash optional canonical payload hash for statement-level correlation
 * @param issuerFingerprint optional public issuer fingerprint from the statement payload
 * @param subjectKind optional subject kind value from the statement payload
 * @param subjectUriHash optional SHA-256 hash of a subject URI, never the raw URI
 * @param subjectUriSummary optional bounded redacted subject URI summary for display
 * @param source optional bounded source type label, such as {@code manual} or {@code content-fetch}
 * @param sourceUriHash optional SHA-256 hash of a source URI, never the raw source URI
 * @param sourceSummary optional bounded redacted source summary for display
 * @param signatureVerified optional signature verification flag when a statement was involved
 * @param statusCode safe status or error code that omits exception text and local paths
 */
public record TrustGraphAuditEvent(
    String eventType,
    Instant timestamp,
    String appId,
    String documentFingerprint,
    String payloadHash,
    String issuerFingerprint,
    String subjectKind,
    String subjectUriHash,
    String subjectUriSummary,
    String source,
    String sourceUriHash,
    String sourceSummary,
    Boolean signatureVerified,
    String statusCode) {
  /**
   * Creates a validated redacted event.
   *
   * <p>All string fields are trimmed, bounded, and checked for control characters. URI-like inputs
   * must already be hashed or redacted before they are supplied. Required validation is limited to
   * the event type and timestamp so routes can still record rejected imports that never produced a
   * parsed statement, issuer, or subject.
   *
   * @throws NullPointerException when {@code timestamp} is {@code null}
   * @throws TrustGraphException when a required or optional string field is blank, over its bound,
   *     or contains unsafe control characters
   */
  public TrustGraphAuditEvent {
    eventType = TrustGraphStoreSanitizer.requiredAuditText("eventType", eventType, 64);
    java.util.Objects.requireNonNull(timestamp, "timestamp");
    appId = TrustGraphStoreSanitizer.optionalAuditText("appId", appId, 128);
    documentFingerprint =
        TrustGraphStoreSanitizer.optionalAuditText("documentFingerprint", documentFingerprint, 128);
    payloadHash = TrustGraphStoreSanitizer.optionalAuditText("payloadHash", payloadHash, 128);
    issuerFingerprint =
        TrustGraphStoreSanitizer.optionalAuditText("issuerFingerprint", issuerFingerprint, 128);
    subjectKind = TrustGraphStoreSanitizer.optionalAuditText("subjectKind", subjectKind, 32);
    subjectUriHash =
        TrustGraphStoreSanitizer.optionalAuditText("subjectUriHash", subjectUriHash, 128);
    subjectUriSummary =
        TrustGraphStoreSanitizer.optionalAuditText("subjectUriSummary", subjectUriSummary, 80);
    source = TrustGraphStoreSanitizer.optionalAuditText("source", source, 32);
    sourceUriHash = TrustGraphStoreSanitizer.optionalAuditText("sourceUriHash", sourceUriHash, 128);
    sourceSummary = TrustGraphStoreSanitizer.optionalAuditText("sourceSummary", sourceSummary, 80);
    statusCode = TrustGraphStoreSanitizer.optionalAuditText("statusCode", statusCode, 80);
  }

  /**
   * Returns this event as a deterministic JSON-compatible summary.
   *
   * <p>The insertion order is stable so API responses, tests, and release-certification fixtures do
   * not depend on map implementation details. Optional fields with {@code null} values are omitted
   * rather than emitted as JSON nulls, which keeps the response compact and avoids suggesting that
   * missing data was deliberately captured and redacted.
   *
   * @return redacted event fields with null optional values omitted
   */
  public Map<String, Object> toJson() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(14);
    json.put("eventType", eventType);
    json.put("timestamp", timestamp.toString());
    putIfPresent(json, "appId", appId);
    putIfPresent(json, "documentFingerprint", documentFingerprint);
    putIfPresent(json, "payloadHash", payloadHash);
    putIfPresent(json, "issuerFingerprint", issuerFingerprint);
    putIfPresent(json, "subjectKind", subjectKind);
    putIfPresent(json, "subjectUriHash", subjectUriHash);
    putIfPresent(json, "subjectUriSummary", subjectUriSummary);
    putIfPresent(json, "source", source);
    putIfPresent(json, "sourceUriHash", sourceUriHash);
    putIfPresent(json, "sourceSummary", sourceSummary);
    if (signatureVerified != null) {
      json.put("signatureVerified", signatureVerified);
    }
    putIfPresent(json, "statusCode", statusCode);
    return json;
  }

  private static void putIfPresent(Map<String, Object> json, String key, String value) {
    if (value != null) {
      json.put(key, value);
    }
  }
}
