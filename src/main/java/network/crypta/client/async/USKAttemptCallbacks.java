package network.crypta.client.async;

import java.util.Random;
import network.crypta.keys.ClientSSKBlock;

/**
 * Callback interface for {@link USKAttempt} lifecycle events.
 *
 * <p>Implementations receive completion and scheduling signals from polling attempts. These hooks
 * allow the owning fetcher to react to success, DNF, cancellation, and cooldown transitions while
 * providing priority information used by the scheduler. The callbacks are intentionally minimal and
 * are expected to be fast, as they are invoked on scheduling or network threads.
 *
 * <p>The interface is stateful in the sense that implementations can depend on the owning fetcher
 * state, but callers should treat each method as a synchronous notification. No concurrency
 * guarantees are enforced beyond what the caller provides, so implementations should provide their
 * own synchronization if they mutate a shared state.
 *
 * <ul>
 *   <li>Signals attempt completion and cancellation events.
 *   <li>Provides polling priority hints for background scheduling.
 *   <li>Controls whether random editions should be probed in a round.
 * </ul>
 */
interface USKAttemptCallbacks {
  /**
   * Notifies that an attempt resulted in a DNF outcome.
   *
   * <p>Implementations may record the failure, reschedule work, or update the UI state. The attempt
   * is already marked as complete when this callback runs.
   *
   * @param attempt attempt that reported the DNF result; never null
   * @param context client context associated with the attempt; must not be null
   */
  void onDNF(USKAttempt attempt, ClientContext context);

  /**
   * Notifies that an attempt succeeded.
   *
   * <p>The callback receives the decoded block if available and a flag indicating that the success
   * should not update internal edition tracking. Implementations typically decide whether to decode
   * or propagate data based on these inputs.
   *
   * @param attempt attempt that reported success; never null
   * @param dontUpdate whether the success should avoid updating edition tracking
   * @param block decoded block returned by the attempt; may be null
   * @param context client context associated with the attempt; must not be null
   */
  void onSuccess(
      USKAttempt attempt, boolean dontUpdate, ClientSSKBlock block, ClientContext context);

  /**
   * Notifies that an attempt was canceled.
   *
   * <p>This callback is invoked after the attempt has been marked canceled and any checker has been
   * shut down.
   *
   * @param attempt attempt that was canceled; never null
   * @param context client context associated with the attempt; must not be null
   */
  void onCancelled(USKAttempt attempt, ClientContext context);

  /**
   * Notifies that an attempt entered a finite cooldown period.
   *
   * <p>This signal is used to determine when a polling round can be treated as finished for now.
   *
   * @param context client context associated with the attempt; must not be null
   */
  void onEnterFiniteCooldown(ClientContext context);

  /**
   * Indicates whether the owning fetcher is running background polling.
   *
   * @return {@code true} when background polling is active
   */
  boolean isBackgroundPoll();

  /**
   * Returns the polling priority used while making progress on a round.
   *
   * @return priority class for progress-oriented polling
   */
  short getProgressPollPriority();

  /**
   * Returns the polling priority used during steady-state background polling.
   *
   * @return priority class for normal background polling
   */
  short getNormalPollPriority();

  /**
   * Determines whether random editions should be added during polling.
   *
   * @param random random source used to sample candidates; must not be null
   * @param firstLoop whether the round is in its initial loop
   * @return {@code true} to schedule random editions, otherwise {@code false}
   */
  boolean shouldAddRandomEditions(Random random, boolean firstLoop);
}
