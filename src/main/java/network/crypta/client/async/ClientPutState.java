package network.crypta.client.async;

import network.crypta.client.InsertException;
import network.crypta.support.io.ResumeFailedException;

/**
 * Represents a unit of state for an asynchronous client-side insert operation.
 *
 * <p>Implementations model a specific step or sub-task within a larger insert request. The parent
 * {@link BaseClientPutter} coordinates one or more {@code ClientPutState} instances to make forward
 * progress, react to failures, and persist enough information to survive restarts. A state can be
 * scheduled, cancelled, resumed after a node restart, and notified of imminent shutdown so it can
 * flush any dirty data to disk.
 *
 * <p>Typical usage is for the owning putter to construct a graph of states and drive them through
 * their lifecycle using a {@link ClientContext}: schedule initial work, propagate cancellation, and
 * later call {@link #onResume(ClientContext)} for persistent requests when the node comes back up.
 * Implementations should be economical with resources and avoid holding long-lived references to
 * large buffers beyond their active window.
 *
 * <ul>
 *   <li><strong>Lifecycle:</strong> schedule → (work) → cancel or complete; resume may re-schedule
 *       persistent work after a restart.
 *   <li><strong>Thread-safety:</strong> Implementations may be invoked from client worker threads;
 *       they should document their own synchronization if state is shared.
 *   <li><strong>Token propagation:</strong> {@link #getToken()} exposes an opaque correlation value
 *       that callers can carry alongside the request.
 * </ul>
 *
 * <p>Example:
 *
 * <pre>{@code
 * ClientPutState state = ...; // created by a BaseClientPutter
 * ClientContext ctx = ...;
 * state.schedule(ctx);        // enqueue or start work for this state
 * }</pre>
 *
 * @see BaseClientPutter
 * @see ClientContext
 * @see InsertException
 * @see ResumeFailedException
 */
public interface ClientPutState {

  /**
   * Returns the {@link BaseClientPutter} that owns and coordinates this request state instance.
   *
   * @return the parent putter instance that owns and coordinates this request state instance
   */
  BaseClientPutter getParent();

  /**
   * Cancels this request state and releases any resources associated with work that has not yet
   * been committed.
   *
   * <p>Implementations should attempt to stop pending scheduling, timers, or queued tasks, and
   * leave the object in a quiescent condition so it can be discarded by the parent safely.
   *
   * @param context the client execution context used to coordinate scheduling and resource
   *     management; never modified by the caller after invocation and must be non-null
   */
  void cancel(ClientContext context);

  /**
   * Schedules this request state for execution within the provided client context.
   *
   * <p>Implementations should enqueue work, register callbacks, or otherwise arrange for progress
   * to be made. If preconditions are not met or queuing fails, an {@link InsertException} is
   * thrown. This method should be cheap in steady state and idempotent with respect to redundant
   * external triggers.
   *
   * @param context the client execution context that provides queues, clocks, and shared services;
   *     must not be {@code null} and should remain valid for the duration of scheduling
   * @throws InsertException if the state cannot be scheduled, prerequisites are invalid, or an
   *     unrecoverable failure occurs while arranging initial work
   */
  void schedule(ClientContext context) throws InsertException;

  /**
   * Returns an opaque token that is carried with the insert and can be used by callers for
   * correlation.
   *
   * <p>The token’s concrete type is application-defined. Implementations should treat it as an
   * immutable value and avoid making behavioral decisions based solely on its contents.
   *
   * @return an opaque, application-defined correlation token associated with this request state
   */
  Object getToken();

  /**
   * Called on restarting the node for a persistent request. The request must re-schedule itself.
   * Caller must ensure that it is safe to call this method more than once, as we recurse through
   * the graph of dependencies.
   *
   * <p>Implementations should verify persisted prerequisites, re-enqueue any required work, and
   * tolerate duplicate invocations during dependency traversal. Any failures should prefer precise
   * exceptions to aid diagnostics and recovery.
   *
   * @param context the client execution context available after restart; provides the facilities
   *     required to re-schedule work safely and consistently
   * @throws InsertException if rescheduling cannot proceed because the request is invalid,
   *     corrupted or otherwise not actionable in the current environment
   * @throws ResumeFailedException if persistent state was found but could not be restored to a
   *     runnable form due to missing data or integrity issues
   */
  void onResume(ClientContext context) throws InsertException, ResumeFailedException;

  /**
   * Called just before the final write of client.dat before the node shuts down. Should write any
   * dirty data to disk etc.
   *
   * <p>Implementations should make best-effort to persist in-memory state that is necessary for a
   * correct resume and to release transient resources. This callback is not a substitute for normal
   * persistence and may be skipped in abrupt termination scenarios.
   *
   * @param context the client execution context at shutdown time, provided for access to
   *     persistence helpers and shared services
   */
  void onShutdown(ClientContext context);
}
