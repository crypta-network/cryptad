package network.crypta.client.async;

/**
 * Callback interface notified when a client request enters or leaves a cooldown period.
 *
 * <p>A <em>cooldown</em> represents a temporary back-off window during which an in-flight client
 * operation (typically a fetch) should not actively retry work. Implementations can use these
 * notifications to persist intent, reschedule the request, or update user-facing state. A common
 * pattern is to enqueue a job on the persistent {@code jobRunner} so that a process restart does
 * not lose the pending wake-up.
 *
 * <p>Typical lifecycle: a request transitions through various {@link ClientGetState} stages while
 * running. When external conditions suggest waiting (e.g., network pressure, peer limits, or local
 * resource caps), it enters cooldown and supplies a target wake-up time. When the wait is no longer
 * required, the request leaves cooldown, either because the wake-up time has been reached and the
 * scheduler resumed it, or because circumstances changed earlier.
 *
 * <p>Thread-safety: implementations may be invoked from scheduler or worker threads. They should be
 * lightweight and avoid blocking for extended periods. If longer work is required, prefer
 * scheduling onto an executor held in {@link ClientContext}.
 *
 * <ul>
 *   <li>Notifications are advisory; the caller does not guarantee exact wake-up semantics.
 *   <li>Implementations should treat {@code wakeupTime} as a best-effort target, not a hard
 *       deadline.
 *   <li>Callbacks must not mutate {@link ClientGetState} invariants beyond what the caller expects.
 * </ul>
 *
 * @see ClientGetState
 * @see ClientContext
 */
public interface WantsCooldownCallback {

  /**
   * Signals that the associated request has entered a cooldown period.
   *
   * <p>The {@code wakeupTime} indicates when the request intends to resume work. Implementations
   * commonly persist this information and schedule a follow-up task so the request can be
   * reactivated even after a process restart. The method should return quickly; any heavy work
   * should be delegated to executors accessed via the provided {@link ClientContext}.
   *
   * <pre>{@code
   * // Example: persist and schedule a wake-up
   * callback.enterCooldown(state, wakeAt, ctx);
   * }</pre>
   *
   * @param state the current {@link ClientGetState} representing the request stage; never {@code
   *     null}. Do not modify internal invariants beyond allowed scheduling actions.
   * @param wakeupTime a target epoch time in milliseconds when work may resume; treat as
   *     best-effort and tolerate early/late wakes as the scheduler permits.
   * @param context the {@link ClientContext} providing executors and persistence helpers; use it to
   *     enqueue follow-up tasks or to record durable state as needed.
   */
  void enterCooldown(ClientGetState state, long wakeupTime, ClientContext context);

  /**
   * Signals that the request has left cooldown earlier than expected.
   *
   * <p>This may occur when external conditions improve or the scheduler decides to advance the
   * request before the nominal wake-up time. Implementations should clear any deferred timers or
   * markers created during {@link #enterCooldown(ClientGetState, long, ClientContext)} and, if
   * appropriate, trigger rescheduling using facilities available through the {@link ClientContext}
   * previously supplied to the request.
   *
   * @param state the current {@link ClientGetState} of the request at the time cooldown ended;
   *     provided for context and correlation with any stored metadata.
   */
  void clearCooldown(ClientGetState state);
}
