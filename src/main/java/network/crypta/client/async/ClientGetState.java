package network.crypta.client.async;

import network.crypta.client.FetchException;

/**
 * Represents a single step in the lifecycle of a client-side fetch request.
 *
 * <p>Implementations encapsulate the mutable state and logic required to advance a fetch through
 * the client request pipeline. A state instance is typically created by higher-level request
 * orchestration code and then scheduled on a {@link ClientRequestScheduler} via {@link
 * #schedule(ClientContext)}. Over its lifetime, a state may be cancelled, resumed after a node
 * restart, or asked to flush any remaining in-memory data during shutdown.
 *
 * <p>The interface focuses on lifecycle hooks rather than policy: implementations decide what work
 * to enqueue and how to react to persistence events, while callers coordinate state transitions and
 * error handling. The execution context is controlled by the client layer; calls may originate from
 * internal scheduling threads. Implementations should therefore avoid unnecessary blocking and
 * protect their internal invariants when accessed concurrently.
 *
 * <ul>
 *   <li>Scheduling: register any required work with the appropriate scheduler.
 *   <li>Cancellation: stop ongoing work and notify downstream callbacks appropriately.
 *   <li>Resume: reconstruct state for persistent requests after a node restart.
 *   <li>Shutdown: persist dirty state needed for a consistent final save.
 * </ul>
 *
 * @see ClientRequestScheduler
 * @see ClientContext
 */
public interface ClientGetState {

  /**
   * Schedule this state on the client request scheduler so that its work can begin or continue.
   *
   * <p>Implementations usually register themselves or subordinate tasks with an appropriate
   * scheduler queue derived from the supplied {@link ClientContext}. The call should be idempotent
   * with respect to repeated invocations that occur before work starts.
   *
   * @param context operational context providing schedulers, executors, and supporting services;
   *     never {@code null} and valid for the duration of the call
   */
  void schedule(ClientContext context);

  /**
   * Cancel the request, and call onFailure() on the callback in order to tell downstream
   * (ultimately the client) that cancel has succeeded, and to allow it to call removeFrom() to
   * avoid a database leak.
   *
   * <p>Implementations should stop any in-flight work associated with this state and ensure that
   * the client-visible callback path observes a terminal failure consistent with a user-initiated
   * cancellation.
   *
   * @param context operational context that can be used to unschedule work and clean up resources;
   *     never {@code null}
   */
  void cancel(ClientContext context);

  /**
   * Get a long value which may be passed around to identify this request (e.g. by the USK fetching
   * code).
   *
   * <p>The token is stable for the lifetime of the request state and can be used in logs or
   * cross-component bookkeeping to correlate events. Its format and uniqueness are implementation
   * details of the underlying request machinery.
   *
   * @return a stable token identifying this request state instance for correlation and tracking
   */
  long getToken();

  /**
   * Called on restarting the node for a persistent request. The request must re-schedule itself, as
   * neither the KeyListener's nor the RGA's are persistent now.
   *
   * <p>Implementations should reconstruct any transient state required to continue processing and
   * promptly re-enqueue work using {@link #schedule(ClientContext)}. If the persisted state cannot
   * be understood or is incomplete, the implementation should surface an error via the declared
   * exception.
   *
   * @param context operational context for accessing schedulers, persistence helpers, and services;
   *     never {@code null}
   * @throws FetchException when persisted state cannot be restored or re-scheduling fails for a
   *     recoverable, fetch-related reason
   */
  void onResume(ClientContext context) throws FetchException;

  /**
   * Called just before the final write of client.dat before the node shuts down. Should write any
   * dirty data to disk etc.
   *
   * <p>This hook allows the implementation to flush in-memory metadata or checkpoints that improve
   * resume time and correctness. It should be fast and best-effort: do not block indefinitely, and
   * prefer to hand off work to the provided context when possible.
   *
   * @param context operational context used to access persistence facilities; never {@code null}
   */
  void onShutdown(ClientContext context);
}
