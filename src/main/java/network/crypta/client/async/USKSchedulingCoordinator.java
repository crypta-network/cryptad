package network.crypta.client.async;

/**
 * Coordinates scheduling decisions for a USK polling round.
 *
 * <p>This coordinator encapsulates the state required to decide whether a round should register a
 * datastore check, schedule network activity, or conclude early when store-only checks are
 * complete. Callers provide the current known edition value and an execution context; the
 * coordinator updates its internal flags and returns a {@link SchedulePlan} describing the next
 * action. The class keeps track of whether a scheduling cycle has started, when DBR hint fetches
 * should gate scheduling, and the last value observed at schedule time.
 *
 * <p>The coordinator is mutable and synchronizes its public methods to keep the state consistent.
 * It is typically owned by a {@link USKFetcher} and invoked from scheduling threads, so callers
 * should avoid holding external locks while calling into it. The logic favors correctness over
 * immediate scheduling by deferring actions until prerequisite datastore checks or DBR hint fetches
 * have finished.
 *
 * <ul>
 *   <li>Tracks whether a scheduling cycle has started and when to defer for DBR hints.
 *   <li>Decides when to register datastore checks versus scheduling attempts.
 *   <li>Exposes snapshot flags used to coordinate follow-up scheduling steps.
 * </ul>
 */
final class USKSchedulingCoordinator {
  /** Attempt manager used to schedule or inspect polling attempts. */
  private final USKAttemptManager attempts;

  /** Coordinator responsible for datastore store checks. */
  private final USKStoreCheckCoordinator storeChecks;

  /** DBR hint fetch tracker used to decide when to defer scheduling. */
  private final USKDateHintFetches dbrHintFetches;

  /** Whether the owning fetcher should operate in store-only mode. */
  private final boolean checkStoreOnly;

  /** Latest value captured when a scheduling cycle was built. */
  private long valueAtSchedule;

  /** Tracks whether the coordinator has started at least one scheduling cycle. */
  private boolean started;

  /** Tracks whether scheduling must wait until DBR hint fetches finish. */
  private boolean scheduleAfterDBRsDone;

  /**
   * Creates a scheduling coordinator for a USK polling round.
   *
   * <p>The coordinator holds references to the attempt manager, store check coordinator, and DBR
   * hint fetches so it can build a consistent schedule plan. The {@code checkStoreOnly} flag
   * influences whether network activity is scheduled or whether the coordinator should conclude
   * once datastore checks complete.
   *
   * @param attempts attempt manager that tracks polling attempts; must be non-null
   * @param storeChecks store check coordinator used to register datastore checks; must be non-null
   * @param dbrHintFetches DBR hint fetch tracker used to gate scheduling; must be non-null
   * @param checkStoreOnly whether the round should avoid network fetches and only check the store
   */
  USKSchedulingCoordinator(
      USKAttemptManager attempts,
      USKStoreCheckCoordinator storeChecks,
      USKDateHintFetches dbrHintFetches,
      boolean checkStoreOnly) {
    this.attempts = attempts;
    this.storeChecks = storeChecks;
    this.dbrHintFetches = dbrHintFetches;
    this.checkStoreOnly = checkStoreOnly;
  }

  /**
   * Plan returned by {@link #buildSchedulePlan(long, boolean, ClientContext, boolean)}.
   *
   * <p>The plan indicates whether a datastore check should be registered immediately, whether the
   * caller should conclude the round, and whether store-only checking has completed. The flags are
   * deliberately simple and are interpreted by the caller to decide the next scheduling step.
   */
  static final class SchedulePlan {
    /** Whether to register a datastore check immediately. */
    boolean registerNow;

    /** Whether the caller should stop scheduling and conclude the round. */
    boolean bye;

    /** Whether store-only checking has completed and should be finalized. */
    boolean completeCheckingStore;

    /** Creates an empty plan; fields default to {@code false}. */
    SchedulePlan() {}
  }

  /**
   * Builds the next scheduling plan for the current polling round.
   *
   * <p>The method records the latest observed edition value, ensures polling attempts are scheduled
   * when no attempts are running, and determines whether datastore checks should be registered
   * immediately. When DBR hint fetches are in progress, it may defer scheduling until those hints
   * are complete. In store-only mode, the returned plan can indicate that checking is complete once
   * outstanding datastore checks finish.
   *
   * @param lookedUp latest edition value observed before scheduling; may be negative for unknown
   * @param startedDBRs whether DBR hint fetches have already started for this round
   * @param context client context used to schedule new polling attempts; must be non-null
   * @param firstLoop whether the current scheduling cycle is the first loop of the round
   * @return a schedule plan describing the next action the caller should take
   */
  synchronized SchedulePlan buildSchedulePlan(
      long lookedUp, boolean startedDBRs, ClientContext context, boolean firstLoop) {
    boolean registerNow = false;
    boolean completeCheckingStore;
    valueAtSchedule = Math.max(lookedUp + 1, valueAtSchedule);
    if (!checkStoreOnly
        && !attempts.hasPendingAttempts()
        && !attempts.hasRunningAttempts()
        && attempts.hasNoPollingAttempts()) {
      attempts.addNewAttempts(lookedUp, context, firstLoop);
    }
    started = true;
    if (lookedUp <= 0 && startedDBRs) {
      scheduleAfterDBRsDone = true;
    } else if (!scheduleAfterDBRsDone || !dbrHintFetches.hasOutstanding()) {
      registerNow = !storeChecks.fillKeysWatching(lookedUp, context);
    }
    completeCheckingStore =
        checkStoreOnly && scheduleAfterDBRsDone && !storeChecks.isStoreCheckRunning();
    SchedulePlan plan = new SchedulePlan();
    plan.registerNow = registerNow;
    plan.bye = false;
    plan.completeCheckingStore = completeCheckingStore;
    return plan;
  }

  /**
   * Returns whether a scheduling cycle has been started.
   *
   * @return {@code true} once a scheduling plan has been built for this coordinator
   */
  synchronized boolean isStarted() {
    return started;
  }

  /** Resets the started flag so the next call treats the cycle as not yet started. */
  synchronized void resetStarted() {
    started = false;
  }

  /**
   * Updates whether scheduling should wait for DBR hint fetches to complete.
   *
   * @param value {@code true} to defer scheduling until DBR hint fetches finish
   */
  synchronized void setScheduleAfterDBRsDone(boolean value) {
    scheduleAfterDBRsDone = value;
  }

  /**
   * Returns whether scheduling is currently deferred until DBR hint fetches finish.
   *
   * @return {@code true} when scheduling should wait for DBR hint completion
   */
  synchronized boolean scheduleAfterDBRsDone() {
    return scheduleAfterDBRsDone;
  }

  /**
   * Returns the latest value captured at schedule time.
   *
   * @return the last {@code lookedUp} value recorded when building a schedule plan
   */
  synchronized long valueAtSchedule() {
    return valueAtSchedule;
  }
}
