package network.crypta.client.async;

import network.crypta.keys.USK;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Encapsulates polling round completion and background reschedule logic. */
final class USKPollingRound {
  private static final Logger LOG = LoggerFactory.getLogger(USKPollingRound.class);

  private final USKAttemptManager attempts;
  private final USKStoreCheckCoordinator storeChecks;
  private final USKDateHintFetches dbrHintFetches;
  private final USKSubscriberRegistry subscribers;
  private final USKManager uskManager;
  private final USK origUSK;
  private final boolean realTimeFlag;

  private long sleepTime;
  private boolean firstLoop;

  USKPollingRound(
      USKAttemptManager attempts,
      USKStoreCheckCoordinator storeChecks,
      USKDateHintFetches dbrHintFetches,
      USKSubscriberRegistry subscribers,
      USKManager uskManager,
      USK origUSK,
      boolean realTimeFlag,
      long sleepTime,
      boolean firstLoop) {
    this.attempts = attempts;
    this.storeChecks = storeChecks;
    this.dbrHintFetches = dbrHintFetches;
    this.subscribers = subscribers;
    this.uskManager = uskManager;
    this.origUSK = origUSK;
    this.realTimeFlag = realTimeFlag;
    this.sleepTime = sleepTime;
    this.firstLoop = firstLoop;
  }

  static final class PollingResolution {
    final boolean ready;
    final USKAttempt[] attempts;

    PollingResolution(boolean ready, USKAttempt[] attempts) {
      this.ready = ready;
      this.attempts = attempts;
    }
  }

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

  long rescheduleBackgroundPoll(
      ClientContext context, long valueAtSchedule, long origSleepTime, long maxSleepTime) {
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

  long sleepTime() {
    return sleepTime;
  }

  boolean firstLoop() {
    return firstLoop;
  }

  void setFirstLoop(boolean value) {
    firstLoop = value;
  }
}
