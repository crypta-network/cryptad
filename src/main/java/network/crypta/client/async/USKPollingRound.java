package network.crypta.client.async;

import network.crypta.keys.USK;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Encapsulates completion checks and background rescheduling for a single USK polling round.
 *
 * <p>This helper owns the lightweight state that bridges store checks, polling attempts, and
 * subscriber notifications while a {@link USKFetcher} progresses through one background polling
 * cycle. It evaluates whether all required checks have finished, ensures that attempts have cooled
 * down at least once, and emits progress callbacks when a round can be treated as finished for now.
 * It also tracks the current backoff interval and decides when to reset the backoff based on
 * observed progress in the manager.
 *
 * <p>The instance is mutable and not internally synchronized; callers are expected to invoke its
 * methods from a scheduling thread or otherwise serialize access. Each instance is scoped to a
 * single fetcher and USK, and it is typically reused across multiple scheduling ticks until the
 * polling cycle completes.
 *
 * <ul>
 *   <li>Checks whether datastore scans, random probes, and DBR hints have settled.
 *   <li>Notifies {@link USKProgressCallback} subscribers when a round becomes idle.
 *   <li>Computes exponential backoff delays with capped sleep times.
 * </ul>
 */
final class USKPollingRound {
  /** Logger for debugging and lifecycle diagnostics. */
  private static final Logger LOG = LoggerFactory.getLogger(USKPollingRound.class);

  /** Coordinates and tracks in-flight polling attempts. */
  private final USKAttemptManager attempts;

  /** Runs datastore check cycles before scheduling attempts. */
  private final USKStoreCheckCoordinator storeChecks;

  /** Tracks date-based hint fetches that gate polling completion. */
  private final USKDateHintFetches dbrHintFetches;

  /** Provides a stable snapshot of subscribed callbacks. */
  private final USKSubscriberRegistry subscribers;

  /** Manager used to query the latest known slots. */
  private final USKManager uskManager;

  /** Base USK that is being polled by this round. */
  private final USK origUSK;

  /** Indicates whether scheduling is biased for real-time activity. */
  private final boolean realTimeFlag;

  /** Baseline sleep duration restored when progress is detected, in milliseconds. */
  private final long origSleepTime;

  /** Maximum sleep duration allowed during backoff, in milliseconds. */
  private final long maxSleepTime;

  /** Current sleep duration used for the next backoff interval, in milliseconds. */
  private long sleepTime;

  /** Tracks whether the round has completed its initial loop. */
  private boolean firstLoop;

  /**
   * Creates a polling round helper for a single fetcher cycle.
   *
   * <p>The helper keeps references to stable collaborators from {@code context} and stores the
   * current backoff window and loop state. The initial sleep time is used for the first delay and
   * is later doubled (with a cap) until progress is observed. The baseline and maximum sleep times
   * are retained so that backoff resets can restore the original interval without consulting the
   * caller again.
   *
   * @param context shared collaborators used to resolve attempts, store checks, and subscribers;
   *     must be non-null and scoped to a single fetcher
   * @param sleepTime initial backoff delay in milliseconds for the first rescheduling attempt
   * @param firstLoop whether the round should treat the next scheduling step as the initial loop
   * @param origSleepTime baseline delay in milliseconds to restore when progress is observed
   * @param maxSleepTime upper bound in milliseconds for exponential backoff delays
   */
  USKPollingRound(
      USKPollingRoundContext context,
      long sleepTime,
      boolean firstLoop,
      long origSleepTime,
      long maxSleepTime) {
    this.attempts = context.attempts();
    this.storeChecks = context.storeChecks();
    this.dbrHintFetches = context.dbrHintFetches();
    this.subscribers = context.subscribers();
    this.uskManager = context.uskManager();
    this.origUSK = context.origUSK();
    this.realTimeFlag = context.realTimeFlag();
    this.sleepTime = sleepTime;
    this.firstLoop = firstLoop;
    this.origSleepTime = origSleepTime;
    this.maxSleepTime = maxSleepTime;
  }

  /**
   * Outcome of resolving polling attempts for a round.
   *
   * <p>The {@link #ready} flag indicates whether all prerequisite checks have finished, and the
   * {@link #attempts} array provides a snapshot of polling attempts relevant to the completion
   * decision. The snapshot may be empty when the round is not ready to complete.
   */
  static final class PollingResolution {
    /** True when the round is eligible for completion checks. */
    final boolean ready;

    /** Snapshot of polling attempts considered for completion. */
    final USKAttempt[] attempts;

    /**
     * Creates a resolution snapshot for the current round.
     *
     * @param ready whether the round is ready for completion evaluation
     * @param attempts snapshot of polling attempts; may be empty but never null
     */
    PollingResolution(boolean ready, USKAttempt[] attempts) {
      this.ready = ready;
      this.attempts = attempts;
    }
  }

  /**
   * Determines whether all prerequisite checks are complete and snapshots polling attempts.
   *
   * <p>The method checks for active datastore scans, running random probes, missing polling
   * attempts, and outstanding DBR hint fetches. If any prerequisite is still in flight, it returns
   * a non-ready resolution with an empty attempt list. When all checks are complete, it returns a
   * ready resolution with a snapshot of current polling attempts for further evaluation.
   *
   * @param cancelled whether the owning fetcher has been canceled and should stop checking
   * @param completed whether the owning fetcher has already completed and should not re-evaluate
   * @return a resolution indicating readiness and a snapshot of polling attempts for the round
   */
  PollingResolution resolvePollingAttemptsIfAllChecksDone(boolean cancelled, boolean completed) {
    if (cancelled || completed) return new PollingResolution(false, new USKAttempt[0]);
    if (storeChecks.isStoreCheckRunning()) {
      if (LOG.isDebugEnabled())
        LOG.debug("Not finished because still running store checker on {}", this);
      return new PollingResolution(false, new USKAttempt[0]);
    }
    if (attempts.hasRunningAttempts()) {
      if (LOG.isDebugEnabled())
        LOG.debug("Not finished because running attempts (random probes) on {}", this);
      return new PollingResolution(false, new USKAttempt[0]);
    }
    if (attempts.hasNoPollingAttempts()) {
      if (LOG.isDebugEnabled())
        LOG.debug("Not finished because no polling attempts (not started???) on {}", this);
      return new PollingResolution(false, new USKAttempt[0]);
    }
    if (dbrHintFetches.hasOutstanding()) {
      if (LOG.isDebugEnabled())
        LOG.debug("Not finished because still waiting for DBR attempts on {}", this);
      return new PollingResolution(false, new USKAttempt[0]);
    }
    return new PollingResolution(true, attempts.snapshotPollingAttempts());
  }

  /**
   * Evaluates whether the current round is finished for now and notifies callbacks if appropriate.
   *
   * <p>This method first resolves whether prerequisite checks have completed, then confirms that
   * every polling attempt has entered a cooldown at least once. If any attempt has not cooled down,
   * the round remains active and no callbacks are fired. When all attempts have cooled down, it
   * delegates to {@link #notifyFinishedForNow(ClientContext, boolean, boolean)} to inform progress
   * subscribers.
   *
   * @param context client context used for callback notifications; must be non-null
   * @param cancelled whether the owning fetcher has been canceled and should halt notifications
   * @param completed whether the owning fetcher has already completed and should not notify
   */
  void checkFinishedForNow(ClientContext context, boolean cancelled, boolean completed) {
    PollingResolution res = resolvePollingAttemptsIfAllChecksDone(cancelled, completed);
    if (!res.ready) return;
    for (USKAttempt a : res.attempts) {
      if (!a.everInCooldown()) {
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Not finished because polling attempt {} never entered cooldown on {}", a, this);
        return;
      }
    }
    notifyFinishedForNow(context, cancelled, completed);
  }

  /**
   * Notifies progress callbacks that the round is finished for now.
   *
   * <p>The notification is skipped when the fetcher has been canceled or completed. When invoked,
   * the method snapshots subscribers and calls {@link USKProgressCallback#onRoundFinished} for each
   * eligible callback, allowing clients to observe that a steady-state polling cycle has settled.
   *
   * @param context client context forwarded to callbacks; must be non-null for valid notifications
   * @param cancelled whether the owning fetcher has been canceled and should suppress callbacks
   * @param completed whether the owning fetcher has completed and should suppress callbacks
   */
  void notifyFinishedForNow(ClientContext context, boolean cancelled, boolean completed) {
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Notifying finished for now on {} for {}{}",
          this,
          origUSK,
          this.realTimeFlag ? " (realtime)" : " (bulk)");
    if (cancelled || completed) return;
    USKCallback[] toCheck = subscribers.snapshotSubscribers();
    for (USKCallback cb : toCheck) {
      if (cb instanceof USKProgressCallback callback) callback.onRoundFinished(context);
    }
  }

  /**
   * Computes the next backoff delay for background polling and updates internal state.
   *
   * <p>The sleep interval is doubled on each call until it reaches {@link #maxSleepTime}. If the
   * manager reports that progress has been made since the round was scheduled, the sleep interval
   * is reset to {@link #origSleepTime}, {@link #firstLoop} is cleared, and the delay is set to zero
   * so the next cycle runs immediately. The returned value is the delay in milliseconds to pass to
   * the scheduler.
   *
   * @param context client context used for randomness when choosing the next delay
   * @param valueAtSchedule latest slot value captured when the round was scheduled
   * @return delay in milliseconds until the next polling cycle should be scheduled
   */
  long rescheduleBackgroundPoll(ClientContext context, long valueAtSchedule) {
    long valAtEnd = uskManager.lookupLatestSlot(origUSK);
    long end;
    long now = System.currentTimeMillis();
    long newSleepTime = sleepTime * 2;
    if (newSleepTime > maxSleepTime) newSleepTime = maxSleepTime;
    sleepTime = newSleepTime;
    end = now + context.random.nextInt((int) sleepTime);

    if (valAtEnd > valueAtSchedule && valAtEnd > origUSK.suggestedEdition) {
      sleepTime = origSleepTime;
      firstLoop = false;
      end = now;
      if (LOG.isDebugEnabled())
        LOG.debug("We have advanced: at start, {} at end, {}", valueAtSchedule, valAtEnd);
    }
    if (LOG.isDebugEnabled())
      LOG.debug("Sleep time is {} this sleep is {} for {}", sleepTime, end - now, this);
    return end - now;
  }

  /**
   * Returns the current backoff sleep interval.
   *
   * @return sleep duration in milliseconds for the next scheduling decision
   */
  @SuppressWarnings("unused")
  long sleepTime() {
    return sleepTime;
  }

  /**
   * Indicates whether the round is still in its initial loop.
   *
   * @return {@code true} when the round has not yet exited the first loop
   */
  boolean firstLoop() {
    return firstLoop;
  }

  /**
   * Updates whether the polling round should treat the next cycle as the first loop.
   *
   * @param value {@code true} to mark the round as being in its first loop, otherwise {@code false}
   */
  @SuppressWarnings({"unused", "SameParameterValue"})
  void setFirstLoop(boolean value) {
    firstLoop = value;
  }
}
