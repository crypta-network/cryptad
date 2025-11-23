package network.crypta.clients.http;

/**
 * Listener that observes lifecycle changes while an FProxy fetch is in progress.
 *
 * <p>This callback interface exists so clients can attach themselves to an {@link
 * FProxyFetchInProgress} instance and be notified whenever the fetch transitions between states
 * such as queued, actively downloading, or completed. Implementations typically store a reference
 * to the associated fetch object when registering, because the listener does not receive the
 * updated status directly; instead, the listener can pull the latest status from the tracked {@code
 * FProxyFetchInProgress}. Callers commonly use this to update UI elements (for example, progress
 * bars), trigger follow-up processing once a fetch settles, or record telemetry about success and
 * failure rates across multiple concurrent fetches.
 *
 * <p>Invocation may occur on worker threads owned by the fetching subsystem, so listeners should
 * return quickly, avoid blocking network threads, and forward heavy work to their own executors.
 * Implementations are expected to be stateless or to synchronize shared state if they are reused
 * across multiple fetches. Repeat notifications can occur when status toggles (e.g., retry cycles);
 * listeners should be tolerant of duplicate or out-of-order events and re-read the authoritative
 * status from the associated fetch before acting.
 *
 * <ul>
 *   <li>Responsibility: receive status-change callbacks while a fetch is running.
 *   <li>Threading: may be invoked from background fetch threads; avoid long blocking work.
 *   <li>Usage: register with {@link FProxyFetchInProgress} and query it for current details.
 * </ul>
 *
 * @see FProxyFetchInProgress
 */
public interface FProxyFetchListener {
  /**
   * Called each time the owning fetch transitions to a new status value.
   *
   * <p>The callback supplies no arguments; implementations should therefore retrieve any required
   * context (such as the new status, progress percentage, or related identifiers) from the {@link
   * FProxyFetchInProgress} instance with which the listener was registered. The method may be
   * invoked multiple times for a single fetch, including during retry cycles or transient state
   * changes. It should avoid throwing exceptions, perform only brief work on the calling thread,
   * and hand off longer tasks to a separate executor. Implementations should also assume that
   * invocations can arrive from different threads over the lifetime of a fetch and guard shared
   * state accordingly.
   */
  void onEvent();
}
