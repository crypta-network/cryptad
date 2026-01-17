package network.crypta.client.async;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import network.crypta.client.FetchContext;
import network.crypta.keys.USK;
import network.crypta.support.api.Bucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Manages USK attempt lifecycle, staging, and scheduling.
 *
 * <p>This helper owns the attempt maps and the mechanics for adding, cancelling, and registering
 * probe attempts. It delegates scheduling callbacks to the owning {@link USKFetcher} through the
 * {@link USKAttemptCallbacks} interface.
 */
final class USKAttemptManager {
  /** Logger for attempt scheduling diagnostics. */
  private static final Logger LOG = LoggerFactory.getLogger(USKAttemptManager.class);

  /** Literal used in attempt descriptions to keep log formatting consistent. */
  private static final String FOR_LITERAL = " for ";

  private final USKAttemptCallbacks callbacks;
  private final USK origUSK;
  private final USKManager uskManager;
  private final FetchContext ctx;
  private final FetchContext ctxNoStore;
  private final ClientRequester parent;
  private final USKFetcher.USKWatchingKeys watchingKeys;
  private final boolean checkStoreOnly;
  private final boolean keepLastData;
  private final boolean realTimeFlag;

  /** Attempts staged for immediate scheduling on the next registration cycle. */
  private final ArrayList<USKAttempt> attemptsToStart = new ArrayList<>();

  /** Active random-probe attempts keyed by edition number. */
  private final TreeMap<Long, USKAttempt> runningAttempts = new TreeMap<>();

  /** Polling attempts keyed by edition number for background tracking. */
  private final TreeMap<Long, USKAttempt> pollingAttempts = new TreeMap<>();

  USKAttemptManager(
      USKAttemptCallbacks callbacks,
      USK origUSK,
      USKManager uskManager,
      FetchContext ctx,
      FetchContext ctxNoStore,
      ClientRequester parent,
      USKFetcher.USKWatchingKeys watchingKeys,
      boolean checkStoreOnly,
      boolean keepLastData,
      boolean realTimeFlag) {
    this.callbacks = callbacks;
    this.origUSK = origUSK;
    this.uskManager = uskManager;
    this.ctx = ctx;
    this.ctxNoStore = ctxNoStore;
    this.parent = parent;
    this.watchingKeys = watchingKeys;
    this.checkStoreOnly = checkStoreOnly;
    this.keepLastData = keepLastData;
    this.realTimeFlag = realTimeFlag;
  }

  List<USKAttempt> cancelBefore(long curLatest) {
    List<USKAttempt> v = null;
    int count = 0;
    synchronized (this) {
      for (Iterator<USKAttempt> i = runningAttempts.values().iterator(); i.hasNext(); ) {
        USKAttempt att = i.next();
        if (att.number < curLatest) {
          if (v == null) v = new ArrayList<>(runningAttempts.size() - count);
          v.add(att);
          i.remove();
        }
        count++;
      }
      for (Iterator<Map.Entry<Long, USKAttempt>> i = pollingAttempts.entrySet().iterator();
          i.hasNext(); ) {
        Map.Entry<Long, USKAttempt> entry = i.next();
        if (entry.getKey() < curLatest) {
          if (v == null) v = new ArrayList<>(Math.max(1, pollingAttempts.size() - count));
          v.add(entry.getValue());
          i.remove();
        } else break; // TreeMap is ordered.
      }
    }
    return v;
  }

  void finishCancelBefore(List<USKAttempt> attempts, ClientContext context) {
    if (attempts == null) return;
    for (USKAttempt att : attempts) {
      att.cancel(context);
    }
  }

  void addNewAttempts(long curLatest, ClientContext context, boolean firstLoop) {
    USKFetcher.USKWatchingKeys.ToFetch list =
        watchingKeys.getEditionsToFetch(
            curLatest,
            context.random,
            getRunningFetchEditions(),
            shouldAddRandomEditions(context, firstLoop));
    USKFetcher.Lookup[] toPoll = list.poll;
    USKFetcher.Lookup[] toFetch = list.fetch;
    for (USKFetcher.Lookup lookup : toPoll) {
      if (LOG.isTraceEnabled()) LOG.trace("Polling {} for {}", lookup, origUSK);
      attemptsToStart.add(add(lookup, true));
    }
    for (USKFetcher.Lookup lookup : toFetch) {
      if (LOG.isDebugEnabled()) LOG.debug("Adding checker for edition {} for {}", lookup, origUSK);
      attemptsToStart.add(add(lookup, false));
    }
  }

  boolean shouldAddRandomEditions(ClientContext context, boolean firstLoop) {
    return callbacks.shouldAddRandomEditions(context.random, firstLoop);
  }

  private synchronized USKAttempt add(USKFetcher.Lookup lookup, boolean forever) {
    long edition = lookup.val;
    if (lookup.val < 0)
      throw new IllegalArgumentException(
          "Can't check <0" + FOR_LITERAL + lookup.val + " on " + origUSK);
    if (checkStoreOnly) return null;
    if (LOG.isDebugEnabled()) LOG.debug("Adding USKAttempt for {} for {}", edition, origUSK);
    if (isDuplicateAttempt(forever, edition)) return null;
    USKAttempt attempt =
        new USKAttempt(callbacks, origUSK, ctx, ctxNoStore, parent, lookup, forever, realTimeFlag);
    if (forever) pollingAttempts.put(edition, attempt);
    else {
      runningAttempts.put(edition, attempt);
    }
    if (LOG.isDebugEnabled()) LOG.debug("Added {} for {}", attempt, origUSK);
    return attempt;
  }

  private synchronized boolean isDuplicateAttempt(boolean forever, long edition) {
    if (forever) {
      if (pollingAttempts.containsKey(edition)) {
        if (LOG.isDebugEnabled()) LOG.debug("Already polling edition: {} for {}", edition, origUSK);
        return true;
      }
    } else {
      if (runningAttempts.containsKey(edition)) {
        if (LOG.isDebugEnabled())
          LOG.debug("Returning because already running for {}", origUSK.getURI());
        return true;
      }
    }
    return false;
  }

  synchronized boolean hasRunningAttempts() {
    return !runningAttempts.isEmpty();
  }

  synchronized boolean hasPollingAttempts() {
    return !pollingAttempts.isEmpty();
  }

  synchronized USKAttempt[] snapshotPollingAttempts() {
    return pollingAttempts.values().toArray(new USKAttempt[0]);
  }

  synchronized USKAttempt[] snapshotRunningAttempts() {
    return runningAttempts.values().toArray(new USKAttempt[0]);
  }

  synchronized USKAttempt[] snapshotAttemptsToStart() {
    return attemptsToStart.toArray(new USKAttempt[0]);
  }

  synchronized boolean hasPendingAttempts() {
    return !attemptsToStart.isEmpty();
  }

  synchronized void clearAttemptsToStart() {
    attemptsToStart.clear();
  }

  synchronized void clearAllAttempts() {
    attemptsToStart.clear();
    runningAttempts.clear();
    pollingAttempts.clear();
  }

  synchronized void removeRunningAttempt(long edition) {
    runningAttempts.remove(edition);
  }

  synchronized void removePollingAttempt(long edition) {
    pollingAttempts.remove(edition);
  }

  synchronized int runningAttemptCount() {
    return runningAttempts.size();
  }

  synchronized int pollingAttemptCount() {
    return pollingAttempts.size();
  }

  synchronized String runningAttemptsDescription() {
    StringBuilder sb = new StringBuilder();
    boolean first = true;
    for (USKAttempt attempt : runningAttempts.values()) {
      if (!first) sb.append(", ");
      first = false;
      sb.append(attempt.number);
      if (attempt.cancelled) sb.append("(cancelled)");
      if (attempt.succeeded) sb.append("(succeeded)");
    }
    return sb.toString();
  }

  synchronized List<USKFetcher.Lookup> getRunningFetchEditions() {
    List<USKFetcher.Lookup> ret = new ArrayList<>();
    for (USKAttempt attempt : runningAttempts.values()) {
      if (!ret.contains(attempt.lookup)) ret.add(attempt.lookup);
    }
    for (USKAttempt attempt : pollingAttempts.values()) {
      if (!ret.contains(attempt.lookup)) ret.add(attempt.lookup);
    }
    return ret;
  }

  void registerAttempts(ClientContext context, Bucket lastRequestData, long suggestedEdition) {
    USKAttempt[] attempts;
    int runningCount;
    int pollingCount;
    synchronized (this) {
      attempts = attemptsToStart.toArray(new USKAttempt[0]);
      attemptsToStart.clear();
      runningCount = runningAttempts.size();
      pollingCount = pollingAttempts.size();
    }

    if (attempts.length > 0) parent.toNetwork(context);
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Registering {} USKChecker's for {} running={} polling={}",
          attempts.length,
          origUSK,
          runningCount,
          pollingCount);
    for (USKAttempt attempt : attempts) {
      long lastEd = uskManager.lookupLatestSlot(origUSK);
      if (keepLastData && lastRequestData == null && lastEd == suggestedEdition) lastEd--;
      if (attempt == null) continue;
      if (attempt.number > lastEd) attempt.schedule(context);
      else {
        removeRunningAttempt(attempt.number);
      }
    }
  }

  void processAttemptsAfterStoreCheck(
      USKAttempt[] attempts, ClientContext context, Bucket lastRequestData, long suggestedEdition) {
    for (USKAttempt attempt : attempts) {
      long lastEd = uskManager.lookupLatestSlot(origUSK);
      if (keepLastData && lastRequestData == null && lastEd == suggestedEdition) lastEd--;
      if (attempt == null) continue;
      if (attempt.number > lastEd) attempt.schedule(context);
      else {
        removeRunningAttempt(attempt.number);
        removePollingAttempt(attempt.number);
      }
    }
  }

  void noteAttemptSuccess(USKAttempt attempt) {
    if (attempt == null) return;
    removeRunningAttempt(attempt.number);
  }

  void noteAttemptCancelled(USKAttempt attempt) {
    if (attempt == null) return;
    removeRunningAttempt(attempt.number);
  }

  void reloadPollParameters() {
    USKAttempt[] pollers;
    synchronized (this) {
      pollers = pollingAttempts.values().toArray(new USKAttempt[0]);
    }
    for (USKAttempt attempt : pollers) attempt.reloadPollParameters();
  }
}
