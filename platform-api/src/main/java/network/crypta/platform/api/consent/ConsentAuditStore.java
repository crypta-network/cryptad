package network.crypta.platform.api.consent;

import java.util.List;

/**
 * Stores redacted consent audit records.
 *
 * <p>The consent service writes one event for approve, reject, defer, and expiry decisions. Store
 * implementations are intentionally narrow: they append bounded, already-redacted {@link
 * ConsentAuditEvent} values and return recent events for Web Shell or Platform API audit views.
 * They do not own snapshot matching, approval consumption, or retention policy beyond their local
 * storage limits.
 *
 * <p>Implementations should avoid exposing request bodies, form passwords, raw app-data values,
 * private insert URIs, local paths, or token material. The provided implementations keep data
 * process-local or append-only JSON-lines, which is sufficient for local operator evidence without
 * creating a durable secret-bearing log.
 *
 * @see InMemoryConsentAuditStore
 * @see FileConsentAuditStore
 */
public interface ConsentAuditStore {
  /**
   * Appends one audit event.
   *
   * <p>Callers pass normalized, redacted events. Implementations may apply retention limits, but
   * they should preserve event order for records that remain available.
   *
   * @param event redacted audit event to store
   */
  void append(ConsentAuditEvent event);

  /**
   * Lists audit events, optionally filtering by app id.
   *
   * <p>A {@code null} app id returns all retained events. A non-null app id returns only entries
   * for that app and must not reveal whether unrelated apps have events in the store.
   *
   * @param appId app id to filter by, or {@code null} to list all retained events
   * @return retained audit events in store order
   */
  List<ConsentAuditEvent> list(String appId);
}
