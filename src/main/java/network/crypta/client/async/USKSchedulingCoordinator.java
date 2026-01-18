package network.crypta.client.async;

/** Coordinates scheduling plan decisions for USK fetchers. */
final class USKSchedulingCoordinator {
  private final USKAttemptManager attempts;
  private final USKStoreCheckCoordinator storeChecks;
  private final USKDateHintFetches dbrHintFetches;
  private final boolean checkStoreOnly;

  private long valueAtSchedule;
  private boolean started;
  private boolean scheduleAfterDBRsDone;

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

  static final class SchedulePlan {
    boolean registerNow;
    boolean bye;
    boolean completeCheckingStore;
  }

  synchronized SchedulePlan buildSchedulePlan(
      long lookedUp, boolean startedDBRs, ClientContext context, boolean firstLoop) {
    boolean registerNow = false;
    boolean completeCheckingStore = false;
    valueAtSchedule = Math.max(lookedUp + 1, valueAtSchedule);
    if ((!checkStoreOnly)
        && !attempts.hasPendingAttempts()
        && !attempts.hasRunningAttempts()
        && attempts.hasNoPollingAttempts()) {
      attempts.addNewAttempts(lookedUp, context, firstLoop);
    }
    started = true;
    if (lookedUp <= 0 && startedDBRs) {
      scheduleAfterDBRsDone = true;
    } else if ((!scheduleAfterDBRsDone) || !dbrHintFetches.hasOutstanding()) {
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

  synchronized boolean isStarted() {
    return started;
  }

  synchronized void resetStarted() {
    started = false;
  }

  synchronized void setScheduleAfterDBRsDone(boolean value) {
    scheduleAfterDBRsDone = value;
  }

  synchronized boolean scheduleAfterDBRsDone() {
    return scheduleAfterDBRsDone;
  }

  synchronized long valueAtSchedule() {
    return valueAtSchedule;
  }
}
