package network.crypta.clients.fcp;

/**
 * Receives lifecycle notifications for client requests handled through the FCP layer.
 *
 * <p>Implementations are typically supplied by components that need to track when a {@link
 * ClientRequest} completes successfully, fails, or is explicitly removed from the queue. Callbacks
 * are invoked by the request scheduler after a request transitions to a terminal state, allowing
 * callers to release resources, update status, or schedule follow-up work. The callback methods are
 * intentionally narrow so that implementors can decide how to record outcomes, whether by
 * persisting metadata, emitting metrics, or notifying UI elements.
 *
 * <p>Invocation order matches the request lifecycle: success or failure callbacks are delivered
 * exactly once per request, and {@link #onRemove(ClientRequest)} communicates explicit removal
 * events. Implementations should be thread-safe because the FCP client may dispatch callbacks from
 * worker threads rather than the UI or application main thread. Avoid blocking for extended periods
 * to keep request dispatch responsive.
 *
 * <ul>
 *   <li>Responsibility: react to terminal request outcomes with minimal latency.
 *   <li>State: receives immutable {@code ClientRequest} snapshots representing the final state.
 *   <li>Threading: may be invoked concurrently for different requests; protect shared state.
 * </ul>
 *
 * @see ClientRequest
 */
public interface RequestCompletionCallback {

  /**
   * Notifies that a request reached a successful terminal state and produced its expected result.
   *
   * <p>This method is invoked once per request when the FCP processing pipeline has fully completed
   * without errors and any payload has been persisted or delivered to downstream consumers.
   * Implementations can update progress indicators, persist completion metadata, or trigger chained
   * requests. The provided {@link ClientRequest} reflects the final state at completion time and
   * should be treated as read-only. Avoid long-running work inside the callback; hand off heavy
   * tasks to separate executors if necessary to preserve request throughput.
   *
   * <pre>{@code
   * // Example: record a successful fetch
   * callback.notifySuccess(request);
   * }</pre>
   *
   * @param req request that reached successful completion; never null; contains identifiers
   */
  void notifySuccess(ClientRequest req);

  /**
   * Notifies that a request ended in failure after exhausting retries or encountering fatal errors.
   *
   * <p>Called exactly once per failed request after the client has determined no further retries
   * will be attempted. Implementations can log diagnostics, surface failure details to users, or
   * schedule alternative remediation work. The {@link ClientRequest} argument captures the terminal
   * failure context; it may include diagnostic messages populated elsewhere. Do not mutate shared
   * request state from within this callback, and keep execution brief to avoid stalling other
   * notifications.
   *
   * @param req request that failed irrecoverably; never null; includes failure context
   */
  void notifyFailure(ClientRequest req);

  /**
   * Signals that a request was removed before or after completion, typically by user action or
   * cleanup.
   *
   * <p>This callback communicates that the request will no longer be tracked by the client, either
   * because it was cancelled, expired, or pruned from internal queues. Implementations can release
   * related resources, remove UI entries, or cancel dependent operations. Depending on the removal
   * reason, this method may follow earlier success or failure notifications; implementations should
   * therefore treat it as a final cleanup hook rather than a distinct outcome.
   *
   * @param req request removed from tracking; never null; represents the removed entry
   */
  void onRemove(ClientRequest req);
}
