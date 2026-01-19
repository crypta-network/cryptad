package network.crypta.client.async;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Manages USK attempt lifecycle, staging, and scheduling.
 *
 * <p>This helper owns the attempt maps and the mechanics for adding, cancelling, and registering
 * probe attempts. It delegates scheduling callbacks to the owning {@link USKFetcher} through the
 * {@link USKAttemptCallbacks} interface. The manager tracks both short-lived random-probe attempts
 * and long-lived polling attempts, ensuring that duplicate editions are not scheduled twice. It
 * also coordinates the transition from datastore checks to network scheduling.
 *
 * <p>The class is mutable and synchronizes access to attempt collections. Callers typically invoke
 * it from scheduler threads and should avoid holding external locks to prevent deadlocks. It
 * prefers deterministic, ordered behavior by using {@link TreeMap} for edition-keyed attempts and
 * by snapshotting collections before scheduling network work.
 *
 * <ul>
 *   <li>Maintains staged, running, and polling attempts by edition.
 *   <li>Coordinates cancellation and cleanup when editions advance.
 *   <li>Registers attempts for scheduling after store checks.
 * </ul>
 */
final class USKAttemptManager {
  /** Logger for attempt scheduling diagnostics. */
  private static final Logger LOG = LoggerFactory.getLogger(USKAttemptManager.class);

  /** Literal used in attempt descriptions to keep log formatting consistent. */
  private static final String FOR_LITERAL = " for ";

  /** Attempt context shared across all created attempts. */
  private final USKAttemptContext attemptContext;

  /** Manager used to resolve the latest known slot for comparisons. */
  private final USKManager uskManager;

  /** Watch set used to plan which editions should be probed. */
  private final USKKeyWatchSet watchingKeys;

  /** Whether attempts should be suppressed because this is a store-only mode. */
  private final boolean checkStoreOnly;

  /** Whether the fetcher should keep the last data when probing newer editions. */
  private final boolean keepLastData;

  /** Attempts staged for immediate scheduling on the next registration cycle. */
  private final ArrayList<USKAttempt> attemptsToStart = new ArrayList<>();

  /** Active random-probe attempts keyed by edition number. */
  private final TreeMap<Long, USKAttempt> runningAttempts = new TreeMap<>();

  /** Polling attempts keyed by edition number for background tracking. */
  private final TreeMap<Long, USKAttempt> pollingAttempts = new TreeMap<>();

  /**
   * Creates a manager for USK attempts.
   *
   * <p>The manager holds the context and collaborators required to build and schedule attempts. It
   * assumes the provided dependencies remain valid for the lifetime of the owning fetcher.
   *
   * @param attemptContext shared configuration used for new attempt construction; must be non-null
   * @param uskManager manager used to query the latest slots; must be non-null
   * @param watchingKeys watch set used to plan fetch and poll editions; must be non-null
   * @param checkStoreOnly whether to suppress network attempts and only check the store
   * @param keepLastData whether to retain the last data when scheduling new attempts
   */
  USKAttemptManager(
      USKAttemptContext attemptContext,
      USKManager uskManager,
      USKKeyWatchSet watchingKeys,
      boolean checkStoreOnly,
      boolean keepLastData) {
    this.attemptContext = attemptContext;
    this.uskManager = uskManager;
    this.watchingKeys = watchingKeys;
    this.checkStoreOnly = checkStoreOnly;
    this.keepLastData = keepLastData;
  }

  /**
   * Cancels attempts for editions older than the current latest value.
   *
   * <p>The method removes attempts from the internal maps and returns a list of attempts that
   * should be canceled by the caller. It does not perform cancellation itself so that callers can
   * decide when to propagate the cancellation on their own thread.
   *
   * @param curLatest latest edition value used as a cutoff for cancellation
   * @return list of attempts to cancel, or {@code null} when none were removed
   */
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

  /**
   * Cancels the provided attempts by invoking {@link USKAttempt#cancel(ClientContext)}.
   *
   * @param attempts attempts returned by {@link #cancelBefore(long)}; may be null
   * @param context client context used for cancellation; must not be null
   */
  void finishCancelBefore(List<USKAttempt> attempts, ClientContext context) {
    if (attempts == null) return;
    for (USKAttempt att : attempts) {
      att.cancel(context);
    }
  }

  /**
   * Plans and stages new attempts for the next scheduling cycle.
   *
   * <p>The method consults the watch set to determine which editions should be polled or fetched
   * and stages the resulting attempts in {@link #attemptsToStart}. Duplicate editions are filtered
   * out, and no attempts are created when running in store-only mode.
   *
   * @param curLatest latest edition value used to seed scheduling decisions
   * @param context client context providing randomness and scheduling information
   * @param firstLoop whether this is the first scheduling loop in the round
   */
  void addNewAttempts(long curLatest, ClientContext context, boolean firstLoop) {
    USKKeyWatchSet.ToFetch list =
        watchingKeys.getEditionsToFetch(
            curLatest,
            context.random,
            getRunningFetchEditions(),
            shouldAddRandomEditions(context, firstLoop),
            firstLoop);
    USKKeyWatchSet.Lookup[] toPoll = list.poll;
    USKKeyWatchSet.Lookup[] toFetch = list.fetch;
    synchronized (this) {
      for (USKKeyWatchSet.Lookup lookup : toPoll) {
        if (LOG.isTraceEnabled()) LOG.trace("Polling {} for {}", lookup, attemptContext.origUSK());
        USKAttempt attempt = add(lookup, true);
        if (attempt != null) attemptsToStart.add(attempt);
      }
      for (USKKeyWatchSet.Lookup lookup : toFetch) {
        if (LOG.isDebugEnabled())
          LOG.debug("Adding checker for edition {} for {}", lookup, attemptContext.origUSK());
        USKAttempt attempt = add(lookup, false);
        if (attempt != null) attemptsToStart.add(attempt);
      }
    }
  }

  /**
   * Returns whether random editions should be added during scheduling.
   *
   * @param context client context providing randomness for selection
   * @param firstLoop whether this is the first scheduling loop in the round
   * @return {@code true} if random editions should be added, otherwise {@code false}
   */
  boolean shouldAddRandomEditions(ClientContext context, boolean firstLoop) {
    return attemptContext.callbacks().shouldAddRandomEditions(context.random, firstLoop);
  }

  /**
   * Adds a new attempt for the given lookup descriptor.
   *
   * <p>This method enforces duplicate checks and stores the attempt in the appropriate map based on
   * whether it is a polling attempt. It returns {@code null} when the attempt is suppressed (for
   * example, in store-only mode or when a duplicate is detected).
   *
   * @param lookup descriptor containing the edition to probe
   * @param forever whether the attempt should be treated as a polling attempt
   * @return the created attempt, or {@code null} when no attempt was added
   */
  private synchronized USKAttempt add(USKKeyWatchSet.Lookup lookup, boolean forever) {
    long edition = lookup.val;
    if (lookup.val < 0)
      throw new IllegalArgumentException(
          "Can't check <0" + FOR_LITERAL + lookup.val + " on " + attemptContext.origUSK());
    if (checkStoreOnly) return null;
    if (LOG.isDebugEnabled())
      LOG.debug("Adding USKAttempt for {} for {}", edition, attemptContext.origUSK());
    if (isDuplicateAttempt(forever, edition)) return null;
    USKAttempt attempt = new USKAttempt(attemptContext, lookup, forever);
    if (forever) pollingAttempts.put(edition, attempt);
    else {
      runningAttempts.put(edition, attempt);
    }
    if (LOG.isDebugEnabled()) LOG.debug("Added {} for {}", attempt, attemptContext.origUSK());
    return attempt;
  }

  /**
   * Returns whether an attempt already exists for the given edition.
   *
   * @param forever whether the attempt is a polling attempt
   * @param edition edition number to check for duplicates
   * @return {@code true} if a duplicate attempt is already present
   */
  private synchronized boolean isDuplicateAttempt(boolean forever, long edition) {
    if (forever) {
      if (pollingAttempts.containsKey(edition)) {
        if (LOG.isDebugEnabled())
          LOG.debug("Already polling edition: {} for {}", edition, attemptContext.origUSK());
        return true;
      }
    } else {
      if (runningAttempts.containsKey(edition)) {
        if (LOG.isDebugEnabled())
          LOG.debug("Returning because already running for {}", attemptContext.origUSK().getURI());

        return true;
      }
    }
    return false;
  }

  /**
   * Returns whether any random-probe attempts are running.
   *
   * @return {@code true} if there are active running attempts
   */
  synchronized boolean hasRunningAttempts() {
    return !runningAttempts.isEmpty();
  }

  /**
   * Returns whether any polling attempts are registered.
   *
   * @return {@code true} if no polling attempts are registered
   */
  synchronized boolean hasNoPollingAttempts() {
    return pollingAttempts.isEmpty();
  }

  /**
   * Returns a snapshot of polling attempts.
   *
   * @return array of polling attempts; may be empty but never null
   */
  synchronized USKAttempt[] snapshotPollingAttempts() {
    return pollingAttempts.values().toArray(new USKAttempt[0]);
  }

  /**
   * Returns a snapshot of running attempts.
   *
   * @return array of running attempts; may be empty but never null
   */
  synchronized USKAttempt[] snapshotRunningAttempts() {
    return runningAttempts.values().toArray(new USKAttempt[0]);
  }

  /**
   * Returns a snapshot of attempts staged for registration.
   *
   * @return array of attempts staged to start; may be empty but never null
   */
  synchronized USKAttempt[] snapshotAttemptsToStart() {
    return attemptsToStart.toArray(new USKAttempt[0]);
  }

  /**
   * Returns whether any attempts are staged for registration.
   *
   * @return {@code true} when staged attempts are available
   */
  synchronized boolean hasPendingAttempts() {
    return !attemptsToStart.isEmpty();
  }

  /** Clears the staged attempts list. */
  synchronized void clearAttemptsToStart() {
    attemptsToStart.clear();
  }

  /** Clears all attempt collections, removing staged, running, and polling attempts. */
  synchronized void clearAllAttempts() {
    attemptsToStart.clear();
    runningAttempts.clear();
    pollingAttempts.clear();
  }

  /**
   * Removes a running attempt by edition.
   *
   * @param edition edition number to remove
   */
  synchronized void removeRunningAttempt(long edition) {
    runningAttempts.remove(edition);
  }

  /**
   * Removes a polling attempt by edition.
   *
   * @param edition edition number to remove
   */
  synchronized void removePollingAttempt(long edition) {
    pollingAttempts.remove(edition);
  }

  /**
   * Returns the count of running attempts.
   *
   * @return number of running attempts
   */
  @SuppressWarnings("unused")
  synchronized int runningAttemptCount() {
    return runningAttempts.size();
  }

  /**
   * Returns the count of polling attempts.
   *
   * @return number of polling attempts
   */
  @SuppressWarnings("unused")
  synchronized int pollingAttemptCount() {
    return pollingAttempts.size();
  }

  /**
   * Returns a human-readable description of running attempts.
   *
   * @return description string containing edition numbers and flags
   */
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

  /**
   * Returns lookup descriptors for currently running fetch editions.
   *
   * @return list of lookup descriptors associated with running or polling attempts
   */
  synchronized List<USKKeyWatchSet.Lookup> getRunningFetchEditions() {
    List<USKKeyWatchSet.Lookup> ret = new ArrayList<>();
    for (USKAttempt attempt : runningAttempts.values()) {
      if (!ret.contains(attempt.lookup)) ret.add(attempt.lookup);
    }
    for (USKAttempt attempt : pollingAttempts.values()) {
      if (!ret.contains(attempt.lookup)) ret.add(attempt.lookup);
    }
    return ret;
  }

  /**
   * Registers staged attempts with the scheduler.
   *
   * <p>The method drains the staged attempt list, notifies the parent requester when network work
   * is about to start, and schedules each attempt if it is still newer than the latest known slot.
   * Attempts that are already obsolete are removed from the internal maps.
   *
   * @param params registration parameters containing context and edition tracking information
   */
  void registerAttempts(USKAttemptRegistrationParams params) {
    USKAttempt[] attempts;
    int runningCount;
    int pollingCount;
    synchronized (this) {
      attempts = attemptsToStart.toArray(new USKAttempt[0]);
      attemptsToStart.clear();
      runningCount = runningAttempts.size();
      pollingCount = pollingAttempts.size();
    }

    if (attempts.length > 0) attemptContext.parent().toNetwork(params.context());
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Registering {} USKChecker's for {} running={} polling={}",
          attempts.length,
          attemptContext.origUSK(),
          runningCount,
          pollingCount);
    for (USKAttempt attempt : attempts) {
      long lastEd = uskManager.lookupLatestSlot(attemptContext.origUSK());

      if (keepLastData && !params.hasLastRequestData() && lastEd == params.suggestedEdition())
        lastEd--;

      if (attempt == null) continue;
      if (attempt.number > lastEd) attempt.schedule(params.context());
      else {
        removeRunningAttempt(attempt.number);
        removePollingAttempt(attempt.number);
      }
    }
  }

  /**
   * Processes attempts after a datastore store check completes.
   *
   * <p>This method mirrors {@link #registerAttempts(USKAttemptRegistrationParams)} but operates on
   * a provided attempt array after a store check completes. It schedules attempts that remain newer
   * than the latest known slot and removes those that are already obsolete.
   *
   * @param params registration parameters containing context and edition tracking information
   * @param attempts attempts to schedule after the store check; may be empty but not null
   */
  void processAttemptsAfterStoreCheck(USKAttemptRegistrationParams params, USKAttempt[] attempts) {
    for (USKAttempt attempt : attempts) {
      long lastEd = uskManager.lookupLatestSlot(attemptContext.origUSK());
      if (keepLastData && !params.hasLastRequestData() && lastEd == params.suggestedEdition())
        lastEd--;
      if (attempt == null) continue;
      if (attempt.number > lastEd) attempt.schedule(params.context());
      else {
        removeRunningAttempt(attempt.number);
        removePollingAttempt(attempt.number);
      }
    }
  }

  /**
   * Notes that an attempt succeeded and removes it from running attempts.
   *
   * @param attempt attempt that succeeded; may be null
   */
  @SuppressWarnings("unused")
  void noteAttemptSuccess(USKAttempt attempt) {
    if (attempt == null) return;
    removeRunningAttempt(attempt.number);
  }

  /**
   * Notes that an attempt was canceled and removes it from running attempts.
   *
   * @param attempt attempt that was canceled; may be null
   */
  @SuppressWarnings("unused")
  void noteAttemptCancelled(USKAttempt attempt) {
    if (attempt == null) return;
    if (LOG.isDebugEnabled())
      LOG.debug("Attempt {} cancelled for {}", attempt.number, attemptContext.origUSK());
    removeRunningAttempt(attempt.number);
  }

  /** Refreshes poll parameters on all polling attempts. */
  void reloadPollParameters() {
    USKAttempt[] pollers;
    synchronized (this) {
      pollers = pollingAttempts.values().toArray(new USKAttempt[0]);
    }
    for (USKAttempt attempt : pollers) attempt.reloadPollParameters();
  }

  /**
   * Registration parameters used when scheduling or processing attempts.
   *
   * @param context client context for scheduling callbacks and networking
   * @param hasLastRequestData whether the fetcher has retained the last request data
   * @param suggestedEdition edition value suggested by the original USK
   */
  record USKAttemptRegistrationParams(
      ClientContext context, boolean hasLastRequestData, long suggestedEdition) {}
}
