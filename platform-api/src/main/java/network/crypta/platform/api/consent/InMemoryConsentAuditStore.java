package network.crypta.platform.api.consent;

import java.util.ArrayList;
import java.util.List;

/**
 * Process-local consent audit store used by tests and embedded routers.
 *
 * <p>The store keeps a bounded, append-ordered list of redacted consent audit events. It is
 * suitable for unit tests, transient embedded routers, and the read index inside {@link
 * FileConsentAuditStore}. It is not durable and should not be treated as an authorization cache;
 * approval matching lives in {@link ConsentService}.
 *
 * <p>All public operations are synchronized. Retention is global to the store instance, not per app
 * id, so high decision volume for one app can evict older events for another app. That keeps memory
 * bounded while preserving simple process-local behavior.
 */
public final class InMemoryConsentAuditStore implements ConsentAuditStore {
  /** Maximum number of recent audit events retained by one store instance. */
  static final int MAX_EVENTS = 512;

  private final List<ConsentAuditEvent> events = new ArrayList<>();

  /**
   * Creates an empty process-local audit store.
   *
   * <p>The store starts with no retained events and applies its global retention limit as events
   * are appended. It does not load data from disk or share state with other instances.
   */
  public InMemoryConsentAuditStore() {
    // State is initialized by field declarations; no startup work is required.
  }

  /**
   * Appends one audit event and evicts the oldest entries beyond the retention limit.
   *
   * <p>The event object is already immutable and redacted, so the store keeps the reference rather
   * than copying it. Eviction preserves the most recent {@link #MAX_EVENTS} entries.
   *
   * @param event redacted event to retain
   */
  @Override
  public synchronized void append(ConsentAuditEvent event) {
    events.add(event);
    while (events.size() > MAX_EVENTS) {
      events.removeFirst();
    }
  }

  /**
   * Lists retained events, optionally filtered by app id.
   *
   * <p>A {@code null} filter returns every retained event. A non-null filter returns a new list of
   * events whose {@link ConsentAuditEvent#appId()} equals the supplied app id.
   *
   * @param appId app id to filter by, or {@code null} for all retained events
   * @return retained events in append order
   */
  @Override
  public synchronized List<ConsentAuditEvent> list(String appId) {
    return events.stream().filter(event -> appId == null || event.appId().equals(appId)).toList();
  }
}
