package network.crypta.client.async;

import java.io.IOException;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Random;
import java.util.TreeMap;
import java.util.TreeSet;
import network.crypta.client.FetchContext;
import network.crypta.keys.ClientSSK;
import network.crypta.keys.ClientSSKBlock;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.Key;
import network.crypta.keys.KeyBlock;
import network.crypta.keys.KeyDecodeException;
import network.crypta.keys.NodeSSK;
import network.crypta.keys.SSKBlock;
import network.crypta.keys.SSKVerifyException;
import network.crypta.keys.USK;
import network.crypta.node.RequestStarter;
import network.crypta.node.SendableGet;
import network.crypta.support.RemoveRangeArrayList;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.BucketTools;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Coordinates discovery and fetching of editions for a {@link USK}.
 *
 * <p>USKs (Unique SSKs) advance over time; this class drives the polling and discovery loop that
 * identifies the latest available edition and optionally retrieves its data. It combines
 * datastore-prechecks, targeted slot checks, and Date-Based Request (DBR) hint fetches to balance
 * latency and load. The fetcher can run once for a specific request or continue in background
 * polling mode to track updates over time.
 *
 * <p>Lifecycle and behavior:
 *
 * <ul>
 *   <li>At most one {@code USKFetcher} is active per USK, and it registers itself with the {@code
 *       USKManager} to receive discovery events such as newly found slots.
 *   <li>Subscribers and callbacks do not receive data directly from this class but influence
 *       whether to continue polling and at which priority, enabling interactive workloads to
 *       promote progress checks.
 *   <li>Scheduling begins with datastore checks and DBR hint fetches, then probes multiple nearby
 *       editions. Four consecutive DNFs with no later pending work typically conclude a round.
 *   <li>When running with background polling, the fetcher increases its sleep between rounds unless
 *       progress is made, and can be re-armed after cancellation.
 * </ul>
 *
 * <p>Threading and state: instances are mutable and use fine-grained synchronization around shared
 * fields to coordinate scheduling and callbacks. Cancellation short-circuits pending work and marks
 * the instance as finished. This class is not persistent; persistence of intent is tracked by
 * {@code USKFetcherTag} which recreates fetchers on startup as needed.
 *
 * @see USKManager
 * @see USK
 */
public class USKFetcher implements ClientGetState, USKCallback, HasKeyListener, KeyListener {
  /** Logger for polling, scheduling, and hint-processing diagnostics. */
  private static final Logger LOG = LoggerFactory.getLogger(USKFetcher.class);

  /** Literal used in attempt descriptions to keep log formatting consistent. */
  private static final String FOR_LITERAL = " for ";

  /** USK manager */
  private final USKManager uskManager;

  /** The USK to fetch */
  private final USK origUSK;

  /** Callbacks */
  private final List<USKFetcherCallback> callbacks;

  /** Fetcher context */
  final FetchContext ctx;

  /** Fetcher context ignoring store */
  final FetchContext ctxNoStore;

  /** Fetcher context for DBR hint fetches */
  final FetchContext ctxDBR;

  /** Finished? */
  private boolean completed;

  /** Cancelled? */
  private boolean cancelled;

  /** Whether this instance only checks the local store and avoids network fetches. */
  private final boolean checkStoreOnly;

  /** Parent requester that owns this fetcher and its scheduling priority. */
  final ClientRequester parent;

  // We keep the data from the last (highest number) request.
  /** Last successfully fetched data bucket, retained when {@link #keepLastData} is enabled. */
  private Bucket lastRequestData;

  /** Compression codec used for the last fetched data payload. */
  private short lastCompressionCodec;

  /** Whether the last fetched block represented metadata rather than raw data. */
  private boolean lastWasMetadata;

  /** Structure tracking which keys we want. */
  private final USKWatchingKeys watchingKeys;

  /** Attempts staged for immediate scheduling on the next registration cycle. */
  private final ArrayList<USKAttempt> attemptsToStart;

  /** Maximum number of keys to watch per polling round before pruning. */
  private static final int WATCH_KEYS = 50;

  /**
   * Registers a fetcher-level callback.
   *
   * <p>Callbacks are notified when the overall USK fetch cycle completes. Unless background polling
   * is enabled, they receive {@code onFoundEdition(...)} at most once when the final decision for
   * the current cycle is known. Callbacks also participate in determining the dynamic polling
   * priority via {@link #updatePriorities()} so interactive callers can promote progress checks.
   *
   * <p>Note: When continuous background polling is enabled, consider whether registering a callback
   * is appropriate, as the cycle may not reach a terminal state for long periods.
   *
   * @param cb the callback to add; must remain valid for the lifetime of this fetch cycle; {@code
   *     null} is not permitted
   * @return {@code true} when the callback was added successfully; {@code false} when the fetcher
   *     has already completed and no further callbacks are accepted
   */
  @SuppressWarnings("UnusedReturnValue")
  public boolean addCallback(USKFetcherCallback cb) {
    synchronized (this) {
      if (completed) return false;
      callbacks.add(cb);
    }
    updatePriorities();
    return true;
  }

  // DBR (date-hint) fetching is handled by USKDateHintFetches.

  /**
   * Tracks a single edition probe, including its checker state and polling metadata.
   *
   * <p>Each attempt owns a {@link USKChecker} that performs the actual request and reports
   * completion through {@link USKCheckerCallback}. The attempt records whether it has succeeded,
   * failed (DNF), or been canceled, and it exposes scheduling hooks used by the outer fetcher.
   */
  class USKAttempt implements USKCheckerCallback {
    /** Edition number */
    long number;

    /** Attempt to fetch that edition number (or null if the fetch has finished) */
    USKChecker checker;

    /** Successful fetch? */
    boolean succeeded;

    /** DNF? */
    boolean dnf;

    /** Whether this attempt has been explicitly canceled. */
    boolean cancelled;

    /** Lookup descriptor associated with this attempt. */
    final Lookup lookup;

    /** Whether this attempt is a long-lived polling attempt. */
    final boolean forever;

    /** Whether this attempt has ever entered finite cooldown. */
    private boolean everInCooldown;

    /**
     * Creates a new attempt for the provided lookup descriptor.
     *
     * @param l lookup descriptor containing edition and key information; must not be null
     * @param forever {@code true} to create a polling attempt; {@code false} for a one-off probe
     */
    private USKAttempt(Lookup l, boolean forever) {
      this.lookup = l;
      this.number = l.val;
      this.succeeded = false;
      this.dnf = false;
      this.forever = forever;
      this.checker =
          new USKChecker(
              this,
              l.key,
              forever ? -1 : ctx.maxUSKRetries,
              l.ignoreStore ? ctxNoStore : ctx,
              parent,
              realTimeFlag);
    }

    @Override
    public void onDNF(ClientContext context) {
      synchronized (this) {
        checker = null;
        dnf = true;
      }
      USKFetcher.this.onDNF(this, context);
    }

    @Override
    public void onSuccess(ClientSSKBlock block, ClientContext context) {
      synchronized (this) {
        checker = null;
        succeeded = true;
      }
      USKFetcher.this.onSuccess(this, false, block, context);
    }

    @Override
    public void onFatalAuthorError(ClientContext context) {
      synchronized (this) {
        checker = null;
      }
      // Counts as success except it doesn't update
      USKFetcher.this.onSuccess(this, true, null, context);
    }

    @Override
    public void onNetworkError(ClientContext context) {
      synchronized (this) {
        checker = null;
      }
      // Treat network error as DNF for scheduling purposes
      USKFetcher.this.onDNF(this, context);
    }

    @Override
    public void onCancelled(ClientContext context) {
      synchronized (this) {
        checker = null;
      }
      USKFetcher.this.onCancelled(this, context);
    }

    /**
     * Cancels this attempt and propagates cancellation to the checker if present.
     *
     * @param context client context used to cancel scheduling; must not be null
     */
    public void cancel(ClientContext context) {
      cancelled = true;
      USKChecker c;
      synchronized (this) {
        c = checker;
      }
      if (c != null) c.cancel(context);
      onCancelled(context);
    }

    /**
     * Schedules this attempt with its checker if still active.
     *
     * @param context client context used to schedule the checker; must not be null
     */
    public void schedule(ClientContext context) {
      USKChecker c;
      synchronized (this) {
        c = checker;
      }
      if (c == null) {
        if (LOG.isDebugEnabled()) LOG.debug("Checker == null in schedule() for {}", this);
      } else {
        assert (!c.persistent());
        c.schedule(context);
      }
    }

    @Override
    public String toString() {
      return "USKAttempt for "
          + number
          + FOR_LITERAL
          + origUSK.getURI()
          + FOR_LITERAL
          + USKFetcher.this
          + (forever ? " (forever)" : "");
    }

    @Override
    public short getPriority() {
      if (backgroundPoll) {
        synchronized (this) {
          if (forever) {
            if (!everInCooldown) {
              // Boost the priority initially, so that finding the first edition takes precedence
              // over ongoing polling after we're fairly sure we're not going to find anything.
              // The ongoing polling keeps the ULPRs up to date so that we will get told quickly,
              // but if we are overloaded we won't be able to keep up regardless.
              return progressPollPriority;
            } else {
              return normalPollPriority;
            }
          } else {
            // If !forever, this is a random-probe.
            // It's not that important.
            return normalPollPriority;
          }
        }
      }
      return parent.getPriorityClass();
    }

    @Override
    public void onEnterFiniteCooldown(ClientContext context) {
      synchronized (this) {
        everInCooldown = true;
      }
      USKFetcher.this.onCheckEnteredFiniteCooldown(context);
    }

    /**
     * Reports whether this attempt has ever entered a finite cooldown.
     *
     * @return {@code true} if the attempt has cooled down at least once
     */
    public synchronized boolean everInCooldown() {
      return everInCooldown;
    }

    /** Refreshes cached poll parameters on the underlying checker, if active. */
    public void reloadPollParameters() {
      USKChecker c;
      synchronized (this) {
        c = checker;
      }
      if (c == null) return;
      c.onChangedFetchContext();
    }
  }

  /** Helper for Date-Based Request (DBR) hint scheduling and parsing. */
  private final USKDateHintFetches dbrHintFetches;

  /** Active random-probe attempts keyed by edition number. */
  private final TreeMap<Long, USKAttempt> runningAttempts = new TreeMap<>();

  /** Polling attempts keyed by edition number for background tracking. */
  private final TreeMap<Long, USKAttempt> pollingAttempts = new TreeMap<>();

  /** Highest edition number fetched or attempted during this cycle. */
  private long lastFetchedEdition;

  /** Minimum failures to tolerate before concluding a round. */
  final long origMinFailures;

  /** Whether this is the first polling loop after construction. */
  boolean firstLoop;

  /** Initial sleep interval between polling rounds, in milliseconds. */
  static final long ORIG_SLEEP_TIME = 30L * 60 * 1000;

  /** Maximum sleep interval between polling rounds, in milliseconds. */
  static final long MAX_SLEEP_TIME = 24L * 60 * 60 * 1000;

  /** Current sleep interval between polling rounds, in milliseconds. */
  long sleepTime = ORIG_SLEEP_TIME;

  /** Edition value captured when scheduling a round to detect progress. */
  private long valueAtSchedule;

  /** Keep going forever? */
  private final boolean backgroundPoll;

  /** Keep the last fetched data? */
  final boolean keepLastData;

  /** Whether scheduling has begun for the current polling cycle. */
  private boolean started;

  /** Whether this fetcher uses real-time scheduling policies. */
  private final boolean realTimeFlag;

  /** Default polling priority for normal background checks. */
  private static final short DEFAULT_NORMAL_POLL_PRIORITY = RequestStarter.PREFETCH_PRIORITY_CLASS;

  /** Current polling priority for normal background checks. */
  private short normalPollPriority = DEFAULT_NORMAL_POLL_PRIORITY;

  /** Default polling priority for progress-oriented checks. */
  private static final short DEFAULT_PROGRESS_POLL_PRIORITY = RequestStarter.UPDATE_PRIORITY_CLASS;

  /** Current polling priority for progress-oriented checks. */
  private short progressPollPriority = DEFAULT_PROGRESS_POLL_PRIORITY;

  /** Whether a scheduling attempt is deferred until DBR hints complete. */
  private boolean scheduleAfterDBRsDone;

  // Options flags for constructor to reduce parameter count
  /** Option flag to enable background polling. */
  static final int OPT_POLL_FOREVER = 1;

  /** Option flag to retain the last fetched data in memory. */
  static final int OPT_KEEP_LAST_DATA = 1 << 1;

  /** Option flag to restrict work to datastore checks only. */
  static final int OPT_CHECK_STORE_ONLY = 1 << 2;

  // Note: reserved for potential future use.
  /**
   * Creates a fetcher that probes and optionally polls a single USK namespace.
   *
   * <p>The constructor wires the primary and DBR-specific {@link FetchContext} instances, captures
   * the parent requester, and seeds the initial watch list using the last known slot from {@link
   * USKManager}. It does not start network work; callers must invoke {@link
   * #schedule(ClientContext)} or {@link #schedule(long, ClientContext)} to begin a cycle.
   *
   * @param origUSK base USK to probe for editions; must not be null
   * @param manager manager used to look up and update known slots; must not be null
   * @param ctx base fetch context used for normal and no-store checks; must not be null
   * @param requester parent requester that supplies priority and persistence flags; must not be
   *     null
   * @param minFailures minimum number of DNFs tolerated before concluding a round; non-negative
   *     values are expected
   * @param options bitmask of {@code OPT_*} flags controlling polling and storage behavior
   * @throws IllegalArgumentException if {@code minFailures} exceeds the internal watch limit
   */
  USKFetcher(
      USK origUSK,
      USKManager manager,
      FetchContext ctx,
      ClientRequester requester,
      int minFailures,
      int options) {
    this.parent = requester;
    this.origUSK = origUSK;
    this.uskManager = manager;
    this.origMinFailures = minFailures;
    if (origMinFailures > WATCH_KEYS) throw new IllegalArgumentException();
    firstLoop = true;
    callbacks = new ArrayList<>();
    subscribers = new HashSet<>();
    lastFetchedEdition = -1;
    this.realTimeFlag = parent.realTimeFlag();
    this.backgroundPoll = (options & OPT_POLL_FOREVER) != 0;
    this.keepLastData = (options & OPT_KEEP_LAST_DATA) != 0;
    this.checkStoreOnly = (options & OPT_CHECK_STORE_ONLY) != 0;
    ctxDBR = new FetchContext(ctx, FetchContext.IDENTICAL_MASK, true, null);
    if (ctx.getFollowRedirects()) {
      this.ctx = new FetchContext(ctx, FetchContext.IDENTICAL_MASK, true, null);
      this.ctx.setFollowRedirects(false);
    } else {
      this.ctx = ctx;
    }
    ctxDBR.setMaxOutputLength(1024);
    ctxDBR.setMaxTempLength(32768);
    ctxDBR.setFilterData(false);
    ctxDBR.setMaxArchiveLevels(0);
    ctxDBR.setMaxArchiveRestarts(0);
    if (checkStoreOnly) ctxDBR.setLocalRequestOnly(true);
    if (ctx.getIgnoreStore()) {
      ctxNoStore = this.ctx;
    } else {
      ctxNoStore = new FetchContext(this.ctx, FetchContext.IDENTICAL_MASK, true, null);
      ctxNoStore.setIgnoreStore(true);
    }
    if (checkStoreOnly && LOG.isDebugEnabled()) LOG.debug("Just checking store on {}", this);
    // origUSK is a hint. We *do* want to check the edition given.
    // Whereas latestSlot we've definitely fetched, we don't want to re-check.
    watchingKeys =
        new USKWatchingKeys(origUSK, Math.max(0, uskManager.lookupLatestSlot(origUSK) + 1));
    attemptsToStart = new ArrayList<>();
    dbrHintFetches = new USKDateHintFetches(this, uskManager, origUSK, this.ctx, ctxDBR, parent);
  }

  /**
   * Called when all outstanding DBR hint fetches have either completed or failed.
   *
   * <p>If the main scheduling path was waiting for DBR results, this method triggers the next
   * scheduling step. It also checks whether the current polling round can be considered finished
   * for now and notifies progress callbacks.
   *
   * @param context the client context used for scheduling follow-up work; must not be {@code null}
   */
  public void onDBRsFinished(ClientContext context) {
    boolean needSchedule = false;
    synchronized (this) {
      if (scheduleAfterDBRsDone) needSchedule = true; // Note: additional conditions may apply.
    }
    if (needSchedule) schedule(context);
    checkFinishedForNow(context);
  }

  /**
   * Notifies that a USK slot check entered a finite cooldown.
   *
   * <p>This is used as a progress signal during a polling round to determine whether the round can
   * be considered finished for now when all active checks have cooled down at least once.
   *
   * @param context client context used to perform completion checks; must not be {@code null}
   */
  public void onCheckEnteredFiniteCooldown(ClientContext context) {
    checkFinishedForNow(context);
  }

  /**
   * Evaluates whether the current polling round can be treated as finished.
   *
   * <p>The method consults {@link #resolvePollingAttemptsIfAllChecksDone()} and verifies that all
   * polling attempts have entered a finite cooldown at least once. When those conditions hold, it
   * emits the round-finished callback to interested subscribers.
   *
   * @param context client context used to notify progress callbacks; must not be null
   */
  private void checkFinishedForNow(ClientContext context) {
    PollingResolution res = resolvePollingAttemptsIfAllChecksDone();
    if (!res.ready) return;
    for (USKAttempt a : res.attempts) {
      // All the polling attempts currently running must have entered cooldown once.
      // I.e. they must have done all their fetches at least once.
      // If we check whether they are *currently* in cooldown, then under heavy USK load (the common
      // case!), we can see them overlapping and never notify finished.
      if (!a.everInCooldown()) {
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Not finished because polling attempt {} never entered cooldown on {}", a, this);
        return;
      }
    }
    notifyFinishedForNow(context);
  }

  /**
   * Captures whether a polling round can be considered complete and which attempts remain.
   *
   * <p>The resolution is used to decide when to notify progress callbacks and to gate scheduling
   * decisions that depend on the completion of store checks, random probes, and DBR hints.
   */
  private static final class PollingResolution {
    /** Whether the polling round is ready to be considered finished for now. */
    final boolean ready;

    /** Snapshot of active polling attempts at resolution time. */
    final USKAttempt[] attempts;

    /**
     * Creates a resolution result for the current polling round.
     *
     * @param ready whether all checks are complete for the current round
     * @param attempts snapshot of polling attempts to examine for cooldown state
     */
    PollingResolution(boolean ready, USKAttempt[] attempts) {
      this.ready = ready;
      this.attempts = attempts;
    }
  }

  /**
   * Determines whether all checks for the polling round have completed.
   *
   * <p>The method verifies that there are no running store checks, random probes, or outstanding
   * DBR hints. It also ensures that polling attempts exist before reporting completion. When any of
   * these conditions is not met, it returns a resolution marked not ready.
   *
   * @return a resolution object indicating readiness and the current polling attempts
   */
  private PollingResolution resolvePollingAttemptsIfAllChecksDone() {
    synchronized (this) {
      if (cancelled || completed) return new PollingResolution(false, new USKAttempt[0]);
      if (runningStoreChecker != null) {
        if (LOG.isDebugEnabled())
          LOG.debug("Not finished because still running store checker on {}", this);
        return new PollingResolution(false, new USKAttempt[0]); // Still checking the store
      }
      if (!runningAttempts.isEmpty()) {
        if (LOG.isDebugEnabled())
          LOG.debug("Not finished because running attempts (random probes) on {}", this);
        return new PollingResolution(false, new USKAttempt[0]); // Still running
      }
      if (pollingAttempts.isEmpty()) {
        if (LOG.isDebugEnabled())
          LOG.debug("Not finished because no polling attempts (not started???) on {}", this);
        return new PollingResolution(false, new USKAttempt[0]); // Not started yet
      }
      if (dbrHintFetches.hasOutstanding()) {
        if (LOG.isDebugEnabled())
          LOG.debug("Not finished because still waiting for DBR attempts on {}", this);
        return new PollingResolution(false, new USKAttempt[0]); // DBRs
      }
      return new PollingResolution(true, pollingAttempts.values().toArray(new USKAttempt[0]));
    }
  }

  /**
   * Notifies {@link USKProgressCallback} subscribers that a polling round has completed.
   *
   * <p>The notification is best-effort: if the fetcher has been canceled or completed, the method
   * returns without invoking callbacks. The notification does not imply that the USK has advanced,
   * only that a round of polling work has reached a stable point.
   *
   * @param context client context forwarded to progress callbacks; must not be null
   */
  private void notifyFinishedForNow(ClientContext context) {
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Notifying finished for now on {} for {}{}",
          this,
          origUSK,
          this.realTimeFlag ? " (realtime)" : " (bulk)");
    USKCallback[] toCheck;
    synchronized (this) {
      if (cancelled || completed) return;
      toCheck = subscribers.toArray(new USKCallback[0]);
    }
    for (USKCallback cb : toCheck) {
      if (cb instanceof USKProgressCallback callback) callback.onRoundFinished(context);
    }
  }

  // moved into USKStoreCheckerGetter to satisfy S3398

  /**
   * Handles a "data not found" result from an attempt and advances completion logic.
   *
   * <p>The method updates tracking structures, records the last fetched edition, and determines
   * whether a polling round should be concluded. It treats the DNF as a non-fatal result that
   * influences scheduling decisions rather than an immediate failure.
   *
   * @param att attempt that reported DNF; must not be null
   * @param context client context used for follow-up scheduling; must not be null
   */
  void onDNF(USKAttempt att, ClientContext context) {
    if (LOG.isDebugEnabled()) LOG.debug("DNF: {}", att);
    boolean finished = false;
    long curLatest = uskManager.lookupLatestSlot(origUSK);
    synchronized (this) {
      if (completed || cancelled) return;
      lastFetchedEdition = Math.max(lastFetchedEdition, att.number);
      runningAttempts.remove(att.number);
      if (runningAttempts.isEmpty()) {
        if (LOG.isDebugEnabled())
          LOG.debug(
              "latest: {}, last fetched: {}, curLatest+MIN_FAILURES: {}",
              curLatest,
              lastFetchedEdition,
              curLatest + origMinFailures);
        if (started) {
          finished = true;
        }
      } else if (LOG.isDebugEnabled()) LOG.debug("Remaining: {}", runningAttempts());
    }
    if (finished) {
      finishSuccess(context);
    }
  }

  /**
   * Builds a diagnostic string describing current running attempts.
   *
   * @return a comma-separated description of running attempts and their state flags
   */
  private synchronized String runningAttempts() {
    StringBuilder sb = new StringBuilder();
    boolean first = true;
    for (USKAttempt a : runningAttempts.values()) {
      if (!first) sb.append(", ");
      first = false;
      sb.append(a.number);
      if (a.cancelled) sb.append("(cancelled)");
      if (a.succeeded) sb.append("(succeeded)");
    }
    return sb.toString();
  }

  /**
   * Completes the current round, either by rescheduling or by notifying callbacks.
   *
   * <p>When background polling is enabled, the method computes a new delay and re-arms the
   * scheduler. Otherwise, it finalizes the fetch by invoking completion callbacks and unregistering
   * the fetcher from the manager.
   *
   * @param context client context used to reschedule or finalize work; must not be null
   */
  private void finishSuccess(ClientContext context) {
    if (LOG.isDebugEnabled()) LOG.debug("finishSuccess() on {}", this);
    if (backgroundPoll) {
      rescheduleBackgroundPoll(context);
    } else {
      completeCallbacks(context);
    }
  }

  /**
   * Reschedules a background polling round with exponential backoff.
   *
   * <p>The delay increases up to {@link #MAX_SLEEP_TIME} unless progress is detected, in which case
   * the delay is reset and the next round runs immediately. The method also resets internal flags
   * so that the next round can be evaluated independently.
   *
   * @param context client context used to access randomness and scheduling; must not be null
   */
  private void rescheduleBackgroundPoll(ClientContext context) {
    long valAtEnd = uskManager.lookupLatestSlot(origUSK);
    long end;
    long now = System.currentTimeMillis();
    synchronized (this) {
      started = false; // don't finish before have rescheduled

      // Find out when we should check next ('end'), in an increasing delay (unless we make
      // progress).
      long newSleepTime = sleepTime * 2;
      if (newSleepTime > MAX_SLEEP_TIME) newSleepTime = MAX_SLEEP_TIME;
      sleepTime = newSleepTime;
      end = now + context.random.nextInt((int) sleepTime);

      if (valAtEnd > valueAtSchedule && valAtEnd > origUSK.suggestedEdition) {
        // We have advanced; keep trying as if we just started.
        // Only if we actually DO advance, not if we just confirm our suspicion (valueAtSchedule
        // always starts at 0).
        sleepTime = ORIG_SLEEP_TIME;
        firstLoop = false;
        end = now;
        if (LOG.isDebugEnabled())
          LOG.debug("We have advanced: at start, {} at end, {}", valueAtSchedule, valAtEnd);
      }
      if (LOG.isDebugEnabled())
        LOG.debug("Sleep time is {} this sleep is {} for {}", sleepTime, end - now, this);
    }
    schedule(end - now, context);
    checkFinishedForNow(context);
  }

  /**
   * Finalizes the fetcher and invokes registered callbacks with the latest known data.
   *
   * <p>The method snapshots callbacks, unsubscribes from the manager, removes pending keys, and
   * then invokes each callback with either success or failure. If retained data exists, it is
   * converted to a byte array and the underlying bucket is freed.
   *
   * @param context client context used for scheduler access and callback parameters; must not be
   *     null
   */
  private void completeCallbacks(ClientContext context) {
    USKFetcherCallback[] cb;
    synchronized (this) {
      completed = true;
      cb = callbacks.toArray(new USKFetcherCallback[0]);
    }
    uskManager.unsubscribe(origUSK, this);
    uskManager.onFinished(this);
    context.getSskFetchScheduler(realTimeFlag).schedTransient.removePendingKeys((KeyListener) this);
    long ed = uskManager.lookupLatestSlot(origUSK);
    byte[] data;
    synchronized (this) {
      if (lastRequestData == null) data = null;
      else {
        try {
          data = BucketTools.toByteArray(lastRequestData);
        } catch (IOException e) {
          LOG.error("Unable to turn lastRequestData into byte[]: caught I/O exception: {}", e, e);
          data = null;
        }
        lastRequestData.free();
      }
    }
    for (USKFetcherCallback c : cb) {
      try {
        if (ed == -1) c.onFailure(context);
        else
          c.onFoundEdition(
              ed,
              origUSK.copy(ed),
              context,
              lastWasMetadata,
              lastCompressionCodec,
              data,
              false,
              false);
      } catch (Exception e) {
        LOG.error(
            "An exception occured while dealing with a callback:{}\n{}", c, e.getMessage(), e);
      }
    }
  }

  /**
   * Handles a successful attempt using the attempt's edition as the current latest.
   *
   * <p>This is a convenience overload that forwards to the edition-aware handler and preserves the
   * update flag.
   *
   * @param att attempt that completed successfully; may be null for synthetic successes
   * @param dontUpdate whether to suppress updating the USK manager with this edition
   * @param block block returned by the attempt, or {@code null} for metadata-only successes
   * @param context client context used for scheduling and storage; must not be null
   */
  void onSuccess(
      USKAttempt att, boolean dontUpdate, ClientSSKBlock block, final ClientContext context) {
    onSuccess(att, att.number, dontUpdate, block, context);
  }

  /**
   * Handles a successful attempt and applies updates for the provided edition.
   *
   * <p>The method prepares a success plan, cancels obsolete attempts, optionally decodes payload
   * data, and updates the USK manager unless suppressed. It may also register new attempts to
   * continue probing near the current latest edition.
   *
   * @param att attempt that completed successfully; may be null for synthetic successes
   * @param curLatest edition number discovered by the attempt
   * @param dontUpdate whether to suppress updating the USK manager with this edition
   * @param block fetched block containing metadata or data; may be null for author errors
   * @param context client context used for scheduling and storage; must not be null
   */
  void onSuccess(
      USKAttempt att,
      long curLatest,
      boolean dontUpdate,
      ClientSSKBlock block,
      final ClientContext context) {
    final long lastEd = uskManager.lookupLatestSlot(origUSK);
    if (LOG.isDebugEnabled())
      LOG.debug("Found edition {} for {} official is {} on {}", curLatest, origUSK, lastEd, this);

    SuccessPlan plan = prepareSuccessPlan(att, curLatest, dontUpdate, block, context, lastEd);
    if (plan == null) return; // finished or canceled

    finishCancelBefore(plan.killAttempts, context);

    Bucket data = decodeBlockIfNeeded(plan.decode, block, context);

    applyDecodedData(plan.decode, block, data);

    if (!dontUpdate) uskManager.updateSlot(origUSK, plan.curLatest, context);
    if (plan.registerNow) registerAttempts(context);
  }

  /**
   * Decodes the block into a bucket when decoding is requested.
   *
   * @param decode whether decoding should be attempted for this block
   * @param block block to decode; may be null when decoding is not applicable
   * @param context client context used for bucket allocation; must not be null
   * @return a decoded bucket, or {@code null} when decoding was skipped or failed
   */
  private Bucket decodeBlockIfNeeded(boolean decode, ClientSSKBlock block, ClientContext context) {
    if (!decode || block == null) return null;
    return ClientSSKBlockDecoder.decode(block, context, parent.persistent());
  }

  /**
   * Utility for decoding {@link ClientSSKBlock} instances into buckets.
   *
   * <p>Decoding errors are treated as non-fatal and reported via logging; the caller receives
   * {@code null} when decoding fails or cannot be completed.
   */
  private static final class ClientSSKBlockDecoder {
    /** Utility class; not instantiable. */
    private ClientSSKBlockDecoder() {}

    /**
     * Decodes the provided block using the context's bucket factory.
     *
     * @param block block to decode; must not be null
     * @param context client context used to obtain bucket factories; must not be null
     * @param persistent whether the resulting bucket should be persistent
     * @return the decoded bucket, or {@code null} when decoding fails
     */
    private static Bucket decode(ClientSSKBlock block, ClientContext context, boolean persistent) {
      try {
        return block.decode(context.getBucketFactory(persistent), 1025 /* it's an SSK */, true);
      } catch (KeyDecodeException _) {
        return null;
      } catch (IOException e) {
        LOG.error("An IOE occured while decoding: {}", e.getMessage(), e);
        return null;
      }
    }
  }

  /**
   * Applies decoded payload data to the fetcher's retained state.
   *
   * <p>The method updates compression metadata and either retains or frees the decoded bucket based
   * on {@link #keepLastData}. When decoding was not requested, the method returns without modifying
   * state.
   *
   * @param decode whether decoding was requested for this block
   * @param block block providing metadata such as compression codec; may be null
   * @param data decoded bucket to retain or free; may be null
   */
  private void applyDecodedData(boolean decode, ClientSSKBlock block, Bucket data) {
    synchronized (this) {
      if (!decode) return;
      if (block != null) {
        lastCompressionCodec = block.getCompressionCodec();
        lastWasMetadata = block.isMetadata();
        if (keepLastData) {
          if (lastRequestData != null) lastRequestData.free();
          lastRequestData = data;
        } else if (data != null) {
          data.free();
        }
      } else {
        lastCompressionCodec = -1;
        lastWasMetadata = false;
        lastRequestData = null;
      }
    }
  }

  /**
   * Prepares a plan describing how to process a successful attempt.
   *
   * <p>The plan includes whether to decode the payload, which attempts to cancel, and whether new
   * attempts should be registered. If the fetcher is already completed or canceled, the method
   * returns {@code null}.
   *
   * @param att attempt that completed successfully; may be null for synthetic successes
   * @param curLatest edition number reported by the attempt
   * @param dontUpdate whether to suppress updates to the USK manager
   * @param block fetched block that may carry metadata and data; may be null
   * @param context client context used for scheduling new attempts; must not be null
   * @param lastEd last known edition from the manager at time of success
   * @return a success plan, or {@code null} if the fetcher is completed or canceled
   */
  private SuccessPlan prepareSuccessPlan(
      USKAttempt att,
      long curLatest,
      boolean dontUpdate,
      ClientSSKBlock block,
      ClientContext context,
      long lastEd) {
    boolean decode;
    List<USKAttempt> killAttempts = null;
    boolean registerNow;
    synchronized (this) {
      if (att != null) runningAttempts.remove(att.number);
      if (completed || cancelled) {
        if (LOG.isDebugEnabled())
          LOG.debug("Finished already: completed={} cancelled={}", completed, cancelled);
        return null;
      }
      decode = shouldDecode(curLatest, lastEd, dontUpdate, block);
      curLatest = Math.max(lastEd, curLatest);
      if (LOG.isDebugEnabled()) LOG.debug("Latest: {} in onSuccess", curLatest);
      if (!checkStoreOnly) {
        killAttempts = cancelBefore(curLatest);
        addNewAttempts(curLatest, context);
      }
      if ((!scheduleAfterDBRsDone) || !dbrHintFetches.hasOutstanding())
        registerNow = !fillKeysWatching(curLatest, context);
      else registerNow = false;
    }
    SuccessPlan plan = new SuccessPlan();
    plan.decode = decode;
    plan.curLatest = curLatest;
    plan.registerNow = registerNow;
    plan.killAttempts = killAttempts;
    return plan;
  }

  /**
   * Determines whether a fetched block should be decoded into data.
   *
   * @param curLatest edition reported by the attempt
   * @param lastEd last known edition at the time of processing
   * @param dontUpdate whether the manager should be updated for this result
   * @param block fetched block to evaluate; may be null
   * @return {@code true} when decoding is required for this result
   */
  private static boolean shouldDecode(
      long curLatest, long lastEd, boolean dontUpdate, ClientSSKBlock block) {
    return curLatest >= lastEd && !(dontUpdate && block == null);
  }

  /**
   * Adds new polling and random-probe attempts based on the current latest edition.
   *
   * <p>The method examines watched keys and subscriber hints to determine which editions should be
   * fetched or polled next, and it schedules those attempts immediately.
   *
   * @param curLatest current latest edition used to seed new attempts
   * @param context client context used to schedule new attempts; must not be null
   */
  private void addNewAttempts(long curLatest, ClientContext context) {
    USKWatchingKeys.ToFetch list =
        watchingKeys.getEditionsToFetch(
            curLatest,
            context.random,
            getRunningFetchEditions(),
            shouldAddRandomEditions(context.random));
    Lookup[] toPoll = list.poll;
    Lookup[] toFetch = list.fetch;
    for (Lookup i : toPoll) {
      if (LOG.isTraceEnabled()) LOG.trace("Polling {} for {}", i, this);
      attemptsToStart.add(add(i, true));
    }
    for (Lookup i : toFetch) {
      if (LOG.isDebugEnabled()) LOG.debug("Adding checker for edition {} for {}", i, origUSK);
      attemptsToStart.add(add(i, false));
    }
  }

  /**
   * Describes how to process a successful attempt.
   *
   * <p>The plan tells the caller whether to decode data, which attempts to cancel, and whether new
   * attempts should be registered immediately.
   */
  private static final class SuccessPlan {
    /** Whether the payload should be decoded and retained. */
    boolean decode;

    /** Latest edition value to use for updates and scheduling. */
    long curLatest;

    /** Whether new attempts should be registered after processing. */
    boolean registerNow;

    /** Attempts that should be canceled because they are now obsolete. */
    List<USKAttempt> killAttempts;

    /** Creates an empty success plan. */
    SuccessPlan() {}
  }

  /**
   * Determines whether to add random edition probes during scheduling.
   *
   * @param random random source used for probabilistic scheduling; must not be null
   * @return {@code true} when random probes should be added for this round
   */
  private boolean shouldAddRandomEditions(Random random) {
    return dbrHintFetches.shouldAddRandomEditions(random, firstLoop);
  }

  /**
   * Handles cancellation of an attempt and completes cancellation if needed.
   *
   * @param att attempt that was canceled; must not be null
   * @param context client context used for callback notifications; must not be null
   */
  void onCancelled(USKAttempt att, ClientContext context) {
    synchronized (this) {
      runningAttempts.remove(att.number);
      if (!runningAttempts.isEmpty()) return;

      if (cancelled) finishCancelled(context);
    }
  }

  /**
   * Notifies callbacks that the fetcher has been canceled.
   *
   * @param context client context forwarded to callbacks; must not be null
   */
  private void finishCancelled(ClientContext context) {
    USKFetcherCallback[] cb;
    synchronized (this) {
      completed = true;
      cb = callbacks.toArray(new USKFetcherCallback[0]);
    }
    for (USKFetcherCallback c : cb) c.onCancelled(context);
  }

  /**
   * Removes attempts targeting editions below the provided threshold.
   *
   * <p>The returned list contains the canceled attempts so the caller may propagate cancellation.
   * The method operates on polling attempts only and respects the ordering of the internal map.
   *
   * @param curLatest edition threshold; attempts below this edition are removed
   * @return list of removed attempts, or {@code null} when no removals were necessary
   */
  private List<USKAttempt> cancelBefore(long curLatest) {
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
   * Cancels the provided attempts, if any.
   *
   * @param v list of attempts to cancel; may be null
   * @param context client context used to propagate cancellation; must not be null
   */
  private void finishCancelBefore(List<USKAttempt> v, ClientContext context) {
    if (v != null) {
      for (USKAttempt att : v) {
        att.cancel(context);
      }
    }
  }

  /**
   * Adds a new {@link USKAttempt} for the requested edition.
   *
   * <p>The attempt is inserted into either the polling or running map depending on {@code forever}.
   * The caller is responsible for calling {@link USKAttempt#schedule(ClientContext)} to actually
   * enqueue the attempt.
   *
   * @param l lookup descriptor containing edition and key information; must not be null
   * @param forever {@code true} to register as a polling attempt; {@code false} for a one-off probe
   * @return the created attempt, or {@code null} when duplicates or invalid state prevent creation
   * @throws IllegalArgumentException if the lookup edition is negative
   */
  private synchronized USKAttempt add(Lookup l, boolean forever) {
    long i = l.val;
    if (l.val < 0)
      throw new IllegalArgumentException(
          "Can't check <0" + FOR_LITERAL + l.val + " on " + this + FOR_LITERAL + origUSK);
    if (cancelled) return null;
    if (checkStoreOnly) return null;
    if (LOG.isDebugEnabled()) LOG.debug("Adding USKAttempt for {} for {}", i, origUSK.getURI());
    if (isDuplicateAttempt(forever, i)) return null;
    USKAttempt a = new USKAttempt(l, forever);
    if (forever) pollingAttempts.put(i, a);
    else {
      runningAttempts.put(i, a);
    }
    if (LOG.isDebugEnabled()) LOG.debug("Added {} for {}", a, origUSK);
    return a;
  }

  /**
   * Checks whether an attempt for the given edition is already registered.
   *
   * @param forever {@code true} to check polling attempts; {@code false} to check running probes
   * @param edition edition number to test for duplication
   * @return {@code true} when an attempt already exists for the edition
   */
  private boolean isDuplicateAttempt(boolean forever, long edition) {
    if (forever) {
      if (pollingAttempts.containsKey(edition)) {
        if (LOG.isDebugEnabled()) LOG.debug("Already polling edition: {} for {}", edition, this);
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

  /**
   * Returns the underlying {@link FreenetURI} of the original USK.
   *
   * <p>The returned URI reflects the base USK namespace and does not change as editions advance.
   * Callers can use it for logging, diagnostics, or to derive edition-specific URIs via {@link
   * USK#copy(long)}. The method performs no I/O and does not allocate new objects beyond the
   * returned reference.
   *
   * @return an immutable URI identifying the USK being fetched; callers must not modify the
   *     returned object
   */
  public FreenetURI getURI() {
    return origUSK.getURI();
  }

  /**
   * Reports whether this fetcher has reached a terminal state.
   *
   * <p>Returns {@code true} once the fetcher has been canceled or completed. After that point it no
   * longer schedules work, though background pollers may be re-armed by {@link
   * #schedule(ClientContext)} if applicable. This method is safe to call from any thread and
   * provides a snapshot of state that may change immediately after return.
   *
   * @return {@code true} if canceled or completed; otherwise {@code false}
   */
  public boolean isFinished() {
    synchronized (this) {
      return completed || cancelled;
    }
  }

  /**
   * Returns the original {@link USK} descriptor associated with this fetcher.
   *
   * <p>The returned USK is the root namespace used for all edition lookups and hint processing. It
   * should be treated as immutable by callers; use {@link USK#copy(long)} to derive a specific
   * edition without mutating shared state.
   *
   * @return the non-null {@link USK} this instance tracks; the object is owned by the fetcher and
   *     should be treated as read-only by callers
   */
  public USK getOriginalUSK() {
    return origUSK;
  }

  /**
   * Schedules this fetcher immediately or after a delay.
   *
   * <p>When {@code delay <= 0}, scheduling happens synchronously on the caller's thread. For
   * positive delays, the request is enqueued on the client's timer facility and will schedule later
   * from that context. The method is idempotent and safe to call repeatedly; if the fetcher has
   * already completed or been canceled, the scheduled task will effectively be a no-op.
   *
   * @param delay delay in milliseconds before scheduling; non-positive schedules immediately
   * @param context client context used to reach the scheduler and timing facilities; must not be
   *     {@code null}
   */
  public void schedule(long delay, final ClientContext context) {
    if (delay <= 0) {
      schedule(context);
    } else {
      context.ticker.queueTimedJob(() -> USKFetcher.this.schedule(context), delay);
    }
  }

  /**
   * Schedules this fetcher to run immediately using the provided context.
   *
   * <p>The call registers this instance with the appropriate schedulers, subscribes to the {@link
   * USKManager}, and, depending on configuration, may start DBR hint fetches and targeted edition
   * checks. If the fetcher has already finished or has been canceled, the method returns without
   * scheduling new work. Repeated calls are safe; they re-apply the current dynamic priorities and
   * ensure registration is in place. This method performs no blocking I/O directly; network work is
   * delegated to the schedulers.
   *
   * @param context client context that provides schedulers, timing, and factories required to run
   *     the discovery loop; must not be {@code null}
   */
  @Override
  public void schedule(ClientContext context) {
    if (LOG.isDebugEnabled()) LOG.debug("Scheduling {}", this);
    if (shouldAbortSchedule()) return;
    context.getSskFetchScheduler(realTimeFlag).schedTransient.addPendingKeys(this);
    updatePriorities();
    uskManager.subscribe(origUSK, this, false, parent.getClient());
    boolean startedDBRs = dbrHintFetches.maybeStart(context);
    long lookedUp = uskManager.lookupLatestSlot(origUSK);
    SchedulePlan plan = buildSchedulePlan(lookedUp, startedDBRs, context);
    if (plan.registerNow) registerAttempts(context);
    else if (plan.completeCheckingStore) {
      this.finishSuccess(context);
      return;
    }
    if (!plan.bye) return;
    // We have been canceled.
    uskManager.unsubscribe(origUSK, this);
    context.getSskFetchScheduler(realTimeFlag).schedTransient.removePendingKeys((KeyListener) this);
    uskManager.onFinished(this, true);
  }

  /**
   * Checks whether scheduling should be aborted due to cancellation or completion.
   *
   * @return {@code true} when the fetcher should stop scheduling new work
   */
  private boolean shouldAbortSchedule() {
    synchronized (this) {
      return cancelled || completed;
    }
  }

  /**
   * Builds a plan describing how to proceed with scheduling for this round.
   *
   * <p>The plan determines whether attempts should be registered immediately, whether the fetcher
   * should exit early, and whether store-only checking can be considered complete.
   *
   * @param lookedUp latest slot looked up in the manager
   * @param startedDBRs whether DBR hint fetches were started for this round
   * @param context client context used for scheduling decisions; must not be null
   * @return a schedule plan describing next steps for the caller
   */
  private SchedulePlan buildSchedulePlan(
      long lookedUp, boolean startedDBRs, ClientContext context) {
    boolean registerNow = false;
    boolean bye;
    boolean completeCheckingStore = false;
    synchronized (this) {
      valueAtSchedule = Math.max(lookedUp + 1, valueAtSchedule);
      bye = cancelled || completed;
      if (!bye) {
        // subscribe() above may have called onFoundEdition and thus added a load of stuff. If so,
        // we don't need to do so here.
        if ((!checkStoreOnly)
            && attemptsToStart.isEmpty()
            && runningAttempts.isEmpty()
            && pollingAttempts.isEmpty()) {
          addNewAttempts(lookedUp, context);
        }

        started = true;
        if (lookedUp <= 0 && startedDBRs) {
          // If we don't know anything, do the DBRs first.
          scheduleAfterDBRsDone = true;
        } else if ((!scheduleAfterDBRsDone) || !dbrHintFetches.hasOutstanding()) {
          registerNow = !fillKeysWatching(lookedUp, context);
        }
        completeCheckingStore =
            checkStoreOnly && scheduleAfterDBRsDone && runningStoreChecker == null;
      }
    }
    SchedulePlan plan = new SchedulePlan();
    plan.registerNow = registerNow;
    plan.bye = bye;
    plan.completeCheckingStore = completeCheckingStore;
    return plan;
  }

  /**
   * Captures the actions required to continue or conclude a scheduling pass.
   *
   * <p>This plan is computed under synchronization and then applied without holding locks to avoid
   * long lock hold times.
   */
  private static final class SchedulePlan {
    /** Whether attempts should be registered immediately after planning. */
    boolean registerNow;

    /** Whether the scheduler should exit early due to cancellation or completion. */
    boolean bye;

    /** Whether store-only checking can be marked complete for this round. */
    boolean completeCheckingStore;

    /** Creates an empty schedule plan. */
    SchedulePlan() {}
  }

  /**
   * Cancels this fetcher and releases scheduler registrations.
   *
   * <p>After cancellation the fetcher stops scheduling any further datastore checks, DBR hint
   * fetches, or edition probes, and it unsubscribes from the {@link USKManager}. In-flight attempts
   * are canceled when possible and subsequent calls that would otherwise schedule work become
   * no-ops. This method is idempotent; calling it more than once has no additional effect beyond
   * logging.
   *
   * <p>Cancellation does not delete any previously obtained data. If background polling was
   * configured, it is disabled for the lifetime of this instance. A new {@code USKFetcher} must be
   * created to resume discovery.
   *
   * @param context the client runtime context used to unregister listeners and cancel outstanding
   *     work; must not be {@code null}
   */
  @Override
  public void cancel(ClientContext context) {
    if (LOG.isDebugEnabled()) LOG.debug("Cancelling {}", this);
    uskManager.unsubscribe(origUSK, this);
    context.getSskFetchScheduler(realTimeFlag).schedTransient.removePendingKeys((KeyListener) this);
    USKAttempt[] attempts;
    USKAttempt[] polling;
    uskManager.onFinished(this);
    SendableGet storeChecker;
    Bucket data;
    synchronized (this) {
      if (cancelled) LOG.error("Already cancelled {}", this);
      if (completed) LOG.error("Already completed {}", this);
      cancelled = true;
      attempts = runningAttempts.values().toArray(new USKAttempt[0]);
      polling = pollingAttempts.values().toArray(new USKAttempt[0]);
      attemptsToStart.clear();
      runningAttempts.clear();
      pollingAttempts.clear();
      storeChecker = runningStoreChecker;
      runningStoreChecker = null;
      data = lastRequestData;
      lastRequestData = null;
    }
    for (USKAttempt attempt : attempts) attempt.cancel(context);
    for (USKAttempt p : polling) p.cancel(context);
    dbrHintFetches.cancelAll(context);
    if (storeChecker != null)
      // Remove from the store checker queue.
      storeChecker.unregister(context, storeChecker.getPriorityClass());
    if (data != null) data.free();
  }

  /**
   * Set of interested USKCallbacks. Note that we don't actually send them any information - they
   * are essentially placeholders, an alternative to a refcount. This could be replaced with a Bloom
   * filter or whatever, we only need .exists and .count.
   */
  final HashSet<USKCallback> subscribers;

  /** Map from subscribers to hint editions. */
  final HashMap<USKCallback, Long> subscriberHints = new HashMap<>();

  /**
   * Adds a subscriber and its current edition hint.
   *
   * <p>Subscribers are not directly notified by this class; instead they influence whether and how
   * aggressively the fetcher continues to probe for newer editions. Hints help bias the search and
   * are folded into the key-watching window used for datastore checks and network probes.
   *
   * @param cb the subscriber whose interest influences polling priority and continuation; must not
   *     be {@code null}
   * @param hint the subscriber's best-known edition number; values less than or equal to the last
   *     looked-up slot are ignored; larger values expand the search window
   */
  public void addSubscriber(USKCallback cb, long hint) {
    Long[] hints;
    synchronized (this) {
      subscribers.add(cb);
      subscriberHints.put(cb, hint);
      hints = subscriberHints.values().toArray(new Long[0]);
    }
    updatePriorities();
    watchingKeys.updateSubscriberHints(hints, uskManager.lookupLatestSlot(origUSK));
  }

  /**
   * Recomputes polling priorities based on subscriber and callback preferences.
   *
   * <p>When no callbacks are present, the priorities are reset to defaults. Otherwise, the method
   * selects the most urgent priorities among all interested parties.
   */
  private void updatePriorities() {
    Prio prio = initialPrio();
    USKCallback[] localCallbacks;
    USKFetcherCallback[] fetcherCallbacks;
    synchronized (this) {
      localCallbacks = subscribers.toArray(new USKCallback[0]);
      // Callbacks also determine the fetcher's priority.
      // Otherwise, USKFetcherTag would have no way to tell us the priority we should run at.
      fetcherCallbacks = callbacks.toArray(new USKFetcherCallback[0]);
    }
    if (noCallbacks(localCallbacks, fetcherCallbacks)) {
      setDefaultPriorities();
      return;
    }

    accumulatePriorities(localCallbacks, prio);
    accumulatePriorities(fetcherCallbacks, prio);

    if (LOG.isDebugEnabled())
      LOG.debug(
          "Updating priorities: normal={} progress={} for {} for {}",
          prio.normal,
          prio.progress,
          this,
          origUSK);
    synchronized (this) {
      normalPollPriority = prio.normal;
      progressPollPriority = prio.progress;
    }
  }

  /**
   * Refreshes priorities and returns the current progress polling priority class.
   *
   * @return priority class to use for progress-oriented polling
   */
  short refreshAndGetProgressPollPriority() {
    updatePriorities();
    return getPriorityClass();
  }

  /** Mutable container for derived polling priorities. */
  private static final class Prio {
    /** Normal polling priority class. */
    short normal;

    /** Progress polling priority class. */
    short progress;

    /** Creates a priority container with unset values. */
    Prio() {}
  }

  /**
   * Creates a priority container initialized to the paused priority class.
   *
   * @return a new priority container with paused defaults
   */
  private static Prio initialPrio() {
    Prio p = new Prio();
    p.normal = RequestStarter.PAUSED_PRIORITY_CLASS;
    p.progress = RequestStarter.PAUSED_PRIORITY_CLASS;
    return p;
  }

  /**
   * Checks whether there are no callbacks influencing priority selection.
   *
   * @param localCallbacks subscriber callbacks to test
   * @param fetcherCallbacks fetcher-level callbacks to test
   * @return {@code true} when both callback arrays are empty
   */
  private static boolean noCallbacks(
      USKCallback[] localCallbacks, USKFetcherCallback[] fetcherCallbacks) {
    return localCallbacks.length == 0 && fetcherCallbacks.length == 0;
  }

  /** Restores default polling priorities for normal and progress polling. */
  private void setDefaultPriorities() {
    normalPollPriority = DEFAULT_NORMAL_POLL_PRIORITY;
    progressPollPriority = DEFAULT_PROGRESS_POLL_PRIORITY;
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Updating priorities: normal = {} progress = {} for {} for {}",
          normalPollPriority,
          progressPollPriority,
          this,
          origUSK);
  }

  /**
   * Accumulates priority preferences from subscriber callbacks.
   *
   * @param cbs callbacks providing priority hints; must not be null
   * @param prio mutable container to update with minimum priorities
   */
  private void accumulatePriorities(USKCallback[] cbs, Prio prio) {
    for (USKCallback cb : cbs) {
      short n = cb.getPollingPriorityNormal();
      if (LOG.isTraceEnabled()) LOG.trace("Normal priority for {} : {}", cb, n);
      if (n < prio.normal) prio.normal = n;
      if (LOG.isTraceEnabled()) LOG.trace("Progress priority for {} : {}", cb, n);
      short p = cb.getPollingPriorityProgress();
      if (p < prio.progress) prio.progress = p;
    }
  }

  /**
   * Accumulates priority preferences from fetcher-level callbacks.
   *
   * @param cbs callbacks providing priority hints; must not be null
   * @param prio mutable container to update with minimum priorities
   */
  private void accumulatePriorities(USKFetcherCallback[] cbs, Prio prio) {
    for (USKFetcherCallback cb : cbs) {
      short n = cb.getPollingPriorityNormal();
      if (LOG.isTraceEnabled()) LOG.trace("Normal priority for {} : {}", cb, n);
      if (n < prio.normal) prio.normal = n;
      if (LOG.isTraceEnabled()) LOG.trace("Progress priority for {} : {}", cb, n);
      short p = cb.getPollingPriorityProgress();
      if (p < prio.progress) prio.progress = p;
    }
  }

  /**
   * Returns whether any subscribers remain registered with this fetcher.
   *
   * <p>This is a lightweight state check used by higher-level controllers to decide when it is safe
   * to stop polling or to release references. The result does not imply completion; a fetcher may
   * still be active even when there are no subscribers because fetcher-level callbacks remain or
   * background polling is enabled. The method is synchronized to provide a consistent snapshot of
   * the subscriber set.
   *
   * @return {@code true} when one or more subscribers are present; {@code false} when none remain
   */
  public synchronized boolean hasSubscribers() {
    return !subscribers.isEmpty();
  }

  /**
   * Returns whether any fetcher-level callbacks are registered.
   *
   * <p>This check is useful for diagnostics and for deciding whether priority calculation should
   * fall back to defaults. The result does not imply that subscribers are present; those are
   * tracked separately. The method is synchronized to provide a consistent snapshot of the callback
   * list.
   *
   * @return {@code true} when one or more callbacks are registered; otherwise {@code false}
   */
  @SuppressWarnings("unused")
  public synchronized boolean hasCallbacks() {
    return !callbacks.isEmpty();
  }

  /**
   * Removes a previously added subscriber.
   *
   * <p>The subscriber will no longer influence polling priority or the set of editions watched in
   * the datastore. Removing a non-existent subscriber has no effect. The method also updates
   * internal hint tracking so that future scheduling reflects the reduced interest set, and it
   * recalculates priorities based on remaining subscribers.
   *
   * @param cb the subscriber to remove; {@code null} is ignored
   */
  public void removeSubscriber(USKCallback cb) {
    Long[] hints;
    synchronized (this) {
      subscribers.remove(cb);
      subscriberHints.remove(cb);
      hints = subscriberHints.values().toArray(new Long[0]);
    }
    updatePriorities();
    watchingKeys.updateSubscriberHints(hints, uskManager.lookupLatestSlot(origUSK));
  }

  /**
   * Removes a fetcher-level callback.
   *
   * <p>This implementation removes the callback from the subscriber set and hint map, which stops
   * it from influencing polling decisions. It does not modify the fetcher-level callback list
   * because those callbacks are tracked separately from subscriber callbacks. This behavior mirrors
   * legacy expectations where the same callback instance can be used in both roles.
   *
   * @param cb the callback to remove; {@code null} is ignored
   */
  @SuppressWarnings("unused")
  public void removeCallback(USKCallback cb) {
    Long[] hints;
    synchronized (this) {
      subscribers.remove(cb);
      subscriberHints.remove(cb);
      hints = subscriberHints.values().toArray(new Long[0]);
    }
    watchingKeys.updateSubscriberHints(hints, uskManager.lookupLatestSlot(origUSK));
  }

  /**
   * Returns a scheduling token for this request when applicable.
   *
   * <p>This implementation does not use scheduler tokens and therefore always returns {@code -1}.
   * Callers should not depend on a stable or meaningful value here and should instead rely on the
   * registered key listeners and callbacks to observe progress. The return value is deterministic
   * and safe to call from any thread, but it conveys no identifier or correlation information.
   *
   * @return always {@code -1} because this fetcher does not expose a token
   */
  @Override
  public long getToken() {
    return -1;
  }

  /**
   * Returns the normal polling priority.
   *
   * <p>Not supported for this class: priority is managed internally via {@link #getPriorityClass()}
   * and dynamic adjustments based on subscribers and callbacks. This method is not expected to be
   * called by production code and will throw an exception if invoked. Use {@link
   * #refreshAndGetProgressPollPriority()} when the current progress priority is required, or {@link
   * #getPriorityClass()} when scheduling an immediate task.
   *
   * @return never returns normally
   * @throws UnsupportedOperationException always, because this operation is unsupported here
   */
  @Override
  public short getPollingPriorityNormal() {
    throw new UnsupportedOperationException();
  }

  /**
   * Returns the progress polling priority.
   *
   * <p>Not supported for this class: priority is determined by internal state and the current
   * progress polling class reported by {@link #getPriorityClass()}. This method is not expected to
   * be called by production code and will throw an exception if invoked; callers should consult
   * {@link #refreshAndGetProgressPollPriority()} instead to refresh priorities and obtain the
   * current value.
   *
   * @return never returns normally
   * @throws UnsupportedOperationException always, because this operation is unsupported here
   */
  @Override
  public short getPollingPriorityProgress() {
    throw new UnsupportedOperationException();
  }

  /**
   * {@inheritDoc}
   *
   * <p>When invoked with {@code newKnownGood == true} and {@code newSlotToo == false} the callback
   * is ignored because slot (edition) discovery is the only driver for follow-up work here. For
   * other cases, the method updates the manager and continues the discovery loop as appropriate for
   * the configured mode.
   *
   * @param ed the edition that was discovered or confirmed; non-negative
   * @param key the USK associated with the edition; must not be {@code null}
   * @param context execution context used to schedule any follow-up actions; must not be {@code
   *     null}
   * @param metadata whether the payload represents metadata rather than content; used when decoding
   * @param codec the compression codec identifier, if any, reported by the fetch pipeline
   * @param data optional byte content of the edition when decoding was requested and succeeded; may
   *     be {@code null}
   * @param newKnownGood whether this edition is a new known-good for the USK
   * @param newSlotToo whether a corresponding new slot has been discovered in the index
   */
  @Override
  public void onFoundEdition(
      long ed,
      USK key,
      final ClientContext context,
      boolean metadata,
      short codec,
      byte[] data,
      boolean newKnownGood,
      boolean newSlotToo) {
    if (newKnownGood && !newSlotToo) return; // Only interested in slots
    // Because this is frequently run off-thread, it is actually possible that the looked up edition
    // is not the same as the edition we are being notified of.
    FoundPlan plan = prepareFoundPlan(ed, data, context);
    if (plan == null) return;
    finishCancelBefore(plan.killAttempts, context);
    if (plan.registerNow) registerAttempts(context);
    applyFoundDecodedData(plan.decode, metadata, codec, data, context);
  }

  /**
   * Prepares a plan for handling a newly found edition with optional decoded data.
   *
   * <p>The plan determines whether the payload should be applied, which attempts should be
   * canceled, and whether new attempts should be registered immediately.
   *
   * @param ed edition number that was found
   * @param data decoded payload data, or {@code null} if unavailable
   * @param context client context used for scheduling decisions; must not be null
   * @return a plan describing how to apply the found edition
   */
  private FoundPlan prepareFoundPlan(long ed, byte[] data, ClientContext context) {
    final long lastEd = uskManager.lookupLatestSlot(origUSK);
    boolean decode;
    List<USKAttempt> killAttempts = null;
    boolean registerNow;
    synchronized (this) {
      if (completed || cancelled) return null;
      decode = lastEd == ed && data != null;
      ed = Math.max(lastEd, ed);
      if (LOG.isDebugEnabled()) LOG.debug("Latest: {} in onFoundEdition", ed);

      if (!checkStoreOnly) {
        killAttempts = cancelBefore(ed);
        addNewAttempts(ed, context);
      }
      if ((!scheduleAfterDBRsDone) || !dbrHintFetches.hasOutstanding())
        registerNow = !fillKeysWatching(ed, context);
      else registerNow = false;
    }
    FoundPlan plan = new FoundPlan();
    plan.decode = decode;
    plan.killAttempts = killAttempts;
    plan.registerNow = registerNow;
    return plan;
  }

  /**
   * Applies decoded data from a found edition into retained state.
   *
   * <p>When {@code decode} is {@code true}, the method updates compression metadata and retains the
   * decoded data bucket if configured to keep the last data.
   *
   * @param decode whether decoded data should be applied
   * @param metadata whether the block represents metadata
   * @param codec compression codec used for the decoded data
   * @param data decoded payload data to store; may be null
   * @param context client context used to allocate a bucket; must not be null
   */
  private void applyFoundDecodedData(
      boolean decode, boolean metadata, short codec, byte[] data, ClientContext context) {
    synchronized (this) {
      if (!decode) return;
      lastCompressionCodec = codec;
      lastWasMetadata = metadata;
      if (keepLastData) {
        // Note: converting bucket to byte[] and back is inefficient
        if (lastRequestData != null) lastRequestData.free();
        try {
          lastRequestData = BucketTools.makeImmutableBucket(context.tempBucketFactory, data);
        } catch (IOException e) {
          LOG.error("Caught {}", e, e);
        }
      }
    }
  }

  /** Describes how to apply a found edition and update scheduling state. */
  private static final class FoundPlan {
    /** Whether decoded data should be applied. */
    boolean decode;

    /** Attempts to cancel after accepting the found edition. */
    List<USKAttempt> killAttempts;

    /** Whether to register new attempts immediately. */
    boolean registerNow;

    /** Creates an empty found plan. */
    FoundPlan() {}
  }

  /**
   * Builds a list of lookup descriptors for currently running attempts.
   *
   * @return list of unique lookup descriptors from running and polling attempts
   */
  private synchronized List<Lookup> getRunningFetchEditions() {
    List<Lookup> ret = new ArrayList<>();
    for (USKAttempt a : runningAttempts.values()) {
      if (!ret.contains(a.lookup)) ret.add(a.lookup);
    }
    for (USKAttempt a : pollingAttempts.values()) {
      if (!ret.contains(a.lookup)) ret.add(a.lookup);
    }
    return ret;
  }

  /**
   * Registers all staged attempts with their schedulers.
   *
   * @param context client context used to schedule attempts; must not be null
   */
  private void registerAttempts(ClientContext context) {
    USKAttempt[] attempts;
    synchronized (USKFetcher.this) {
      if (cancelled || completed) return;
      attempts = attemptsToStart.toArray(new USKAttempt[0]);
      attemptsToStart.clear();
    }

    if (attempts.length > 0) parent.toNetwork(context);
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Registering {} USKChecker's for {} running={} polling={}",
          attempts.length,
          this,
          runningAttempts.size(),
          pollingAttempts.size());
    for (USKAttempt attempt : attempts) {
      // Look up on each iteration since scheduling can cause new editions to be found sometimes.
      long lastEd = uskManager.lookupLatestSlot(origUSK);
      synchronized (USKFetcher.this) {
        // Note: condition may require verification in broader contexts
        if (keepLastData && lastRequestData == null && lastEd == origUSK.suggestedEdition)
          lastEd--; // If we want the data, then get it for the known edition, so we always get the
        // data, so USKInserter can compare it and return the old edition if it is
        // identical.
      }
      if (attempt == null) continue;
      if (attempt.number > lastEd) attempt.schedule(context);
      else {
        synchronized (USKFetcher.this) {
          runningAttempts.remove(attempt.number);
        }
      }
    }
  }

  /** Active store checker getter, or {@code null} when no store scan is running. */
  private USKStoreCheckerGetter runningStoreChecker = null;

  /**
   * Bundles datastore sub-checkers used to query the local store for candidate editions.
   *
   * <p>This helper merges keys from multiple sources and forwards completion notifications back to
   * the underlying sub-checkers.
   */
  class USKStoreChecker {

    /** Sub-checkers contributing keys to query in the datastore. */
    final USKWatchingKeys.KeyList.StoreSubChecker[] checkers;

    /**
     * Creates a store checker from a list of sub-checkers.
     *
     * @param c sub-checkers that contribute keys; must not be null
     */
    public USKStoreChecker(List<USKWatchingKeys.KeyList.StoreSubChecker> c) {
      checkers = c.toArray(new USKWatchingKeys.KeyList.StoreSubChecker[0]);
    }

    /**
     * Creates a store checker from an array of sub-checkers.
     *
     * @param checkers2 sub-checker array to use directly; must not be null
     */
    @SuppressWarnings("unused")
    public USKStoreChecker(USKWatchingKeys.KeyList.StoreSubChecker[] checkers2) {
      checkers = checkers2;
    }

    /**
     * Returns the merged list of keys to check in the datastore.
     *
     * @return array of keys to check; may be empty
     */
    public Key[] getKeys() {
      if (checkers.length == 0) return new Key[0];
      if (checkers.length == 1) return checkers[0].keysToCheck;
      return mergeKeysFromCheckers();
    }

    /**
     * Merges keys from all sub-checkers into a de-duplicated array.
     *
     * @return merged array of keys to check in the datastore
     */
    private Key[] mergeKeysFromCheckers() {
      int x = 0;
      for (USKWatchingKeys.KeyList.StoreSubChecker checker : checkers) {
        x += checker.keysToCheck.length;
      }
      Key[] keys = new Key[x];
      int ptr = 0;
      // Note: a more efficient merging algorithm could consider ranges.
      HashSet<Key> check = new HashSet<>();
      for (USKWatchingKeys.KeyList.StoreSubChecker checker : checkers) {
        for (Key k : checker.keysToCheck) {
          if (!check.add(k)) continue;
          keys[ptr++] = k;
        }
      }
      if (keys.length != ptr) {
        keys = Arrays.copyOf(keys, ptr);
      }
      return keys;
    }

    /** Notifies all sub-checkers that their datastore checks have completed. */
    public void checked() {
      for (USKWatchingKeys.KeyList.StoreSubChecker checker : checkers) {
        checker.checked();
      }
    }
  }

  /**
   * Starts or continues datastore checking for watched keys.
   *
   * @param ed latest known edition used to seed datastore checks
   * @param context client context used to register the store checker; must not be null
   * @return {@code true} when a store check is already running or was started; {@code false} when
   *     no store check is required
   */
  @SuppressWarnings("BooleanMethodIsAlwaysInverted")
  private boolean fillKeysWatching(long ed, ClientContext context) {
    synchronized (this) {
      // Do not run a new one until this one has finished.
      // USKStoreCheckerGetter itself will automatically call back to fillKeysWatching so there is
      // no
      // chance of losing it.
      if (runningStoreChecker != null) return true;
      final USKStoreChecker checker = watchingKeys.getDatastoreChecker(ed);
      if (checker == null) {
        if (LOG.isDebugEnabled()) LOG.debug("No datastore checker");
        return false;
      }

      runningStoreChecker = new USKStoreCheckerGetter(this, parent, checker);
    }
    try {
      context
          .getSskFetchScheduler(realTimeFlag)
          .register(null, new SendableGet[] {runningStoreChecker}, false, null, false);
    } catch (Exception t) {
      synchronized (this) {
        runningStoreChecker = null;
      }
      LOG.error("Unable to start: {}", t, t);
      try {
        runningStoreChecker.unregister(context, progressPollPriority);
      } catch (Exception _) {
        // Ignore, hopefully it's already unregistered
      }
    }
    if (LOG.isDebugEnabled()) LOG.debug("Registered {} for {}", runningStoreChecker, this);
    return true;
  }

  /**
   * Completes registration after a datastore checker finishes its pre-registration phase.
   *
   * <p>The method unregisters the checker, marks it complete, then schedules any pending attempts
   * based on the datastore results. When running in store-only mode, it may immediately conclude
   * the round after DBR handling.
   *
   * @param storeChecker active store checker getter instance; must not be null
   * @param checker datastore checker wrapper used to mark completion; must not be null
   * @param context client context used for scheduling and callbacks; must not be null
   * @param toNetwork whether the scheduler intended a network send for the checker
   * @return {@code toNetwork} to preserve scheduler semantics; never sends network requests here
   */
  @SuppressWarnings("java:S3516")
  boolean preRegisterStoreChecker(
      USKStoreCheckerGetter storeChecker,
      USKStoreChecker checker,
      ClientContext context,
      boolean toNetwork) {
    if (cancelled || completed) {
      storeChecker.unregister(context, storeChecker.getPriorityClass());
      synchronized (this) {
        runningStoreChecker = null;
      }
      if (LOG.isDebugEnabled())
        LOG.debug("StoreChecker preRegister aborted: fetcher cancelled/completed");
      return toNetwork; // cancel network send when scheduler planned to send
      // value ignored by scheduler when toNetwork == false
    }

    storeChecker.unregister(context, storeChecker.getPriorityClass());

    USKAttempt[] attempts;
    synchronized (this) {
      runningStoreChecker = null;
      // Note: optionally start USKAttempts only when datastore check shows no progress.
      attempts = attemptsToStart.toArray(new USKAttempt[0]);
      attemptsToStart.clear();
      if (cancelled || completed) attempts = new USKAttempt[0];
    }

    checker.checked();

    if (LOG.isDebugEnabled())
      LOG.debug(
          "Checked datastore, finishing registration for {} checkers for {} for {}",
          attempts.length,
          this,
          origUSK);

    if (attempts.length > 0) {
      parent.toNetwork(context);
      notifySendingToNetwork(context);
    }

    processAttemptsAfterStoreCheck(attempts, context);

    long lastEd = uskManager.lookupLatestSlot(origUSK);
    if (!fillKeysWatching(lastEd, context) && checkStoreOnly) {
      if (LOG.isDebugEnabled()) LOG.debug("Just checking store, terminating {} ...", this);
      if (shouldDeferUntilDBRs()) {
        scheduleAfterDBRsDone = true;
      } else {
        finishSuccess(context);
      }
    }

    return toNetwork; // Store checker never sends network requests itself
    // Value is ignored when toNetwork == false
  }

  /**
   * Notifies progress callbacks that network sending is about to begin.
   *
   * @param context client context forwarded to progress callbacks; must not be null
   */
  private void notifySendingToNetwork(ClientContext context) {
    USKCallback[] toCheck;
    synchronized (this) {
      if (cancelled || completed) return;
      toCheck = subscribers.toArray(new USKCallback[0]);
    }
    for (USKCallback cb : toCheck) {
      if (cb instanceof USKProgressCallback callback) callback.onSendingToNetwork(context);
    }
  }

  /**
   * Processes attempts after the datastore check completes.
   *
   * @param attempts attempts to schedule or drop based on current known edition
   * @param context client context used to schedule attempts; must not be null
   */
  private void processAttemptsAfterStoreCheck(USKAttempt[] attempts, ClientContext context) {
    for (USKAttempt attempt : attempts) {
      long lastEd = uskManager.lookupLatestSlot(origUSK);
      synchronized (this) {
        // Note: condition may need verification.
        if (keepLastData && lastRequestData == null && lastEd == origUSK.suggestedEdition) {
          // If we want the data, then get it for the known edition, so we always get the data, so
          // USKInserter can compare it and return the old edition if it is identical.
          lastEd--;
        }
      }
      if (attempt == null) continue;
      if (attempt.number > lastEd) attempt.schedule(context);
      else {
        synchronized (this) {
          runningAttempts.remove(attempt.number);
          pollingAttempts.remove(attempt.number);
        }
      }
    }
  }

  /**
   * Determines whether scheduling should wait for DBR hint fetches to finish.
   *
   * @return {@code true} when outstanding DBR hint fetches are still running
   */
  private boolean shouldDeferUntilDBRs() {
    return dbrHintFetches.hasOutstanding();
  }

  /**
   * Reports whether this fetcher has been canceled or completed.
   *
   * <p>This is a stronger form of {@link #isFinished()} used by scheduling code that expects a
   * terminal state. The method is synchronized and returns a snapshot that may change immediately
   * after return. It is safe to call frequently from scheduler threads.
   *
   * @return {@code true} when canceled or completed; otherwise {@code false}
   */
  @Override
  public synchronized boolean isCancelled() {
    return completed || cancelled;
  }

  /**
   * Returns the key listener to use for datastore and network key matching.
   *
   * <p>This fetcher acts as its own listener, so the returned reference is always {@code this}. The
   * method performs no allocation and is safe to call from any thread. The parameters are ignored
   * because the listener identity does not vary by startup mode.
   *
   * @param context client context provided by the scheduler; unused by this implementation
   * @param onStartup whether the listener is being created during startup; unused here
   * @return this fetcher as the key listener
   */
  @Override
  public KeyListener makeKeyListener(ClientContext context, boolean onStartup) {
    return this;
  }

  /**
   * Returns the number of keys currently watched by this fetcher.
   *
   * <p>The count reflects the internal watch list and is used by schedulers to estimate work
   * breadth. It does not necessarily equal the number of outstanding network requests and may
   * include keys derived from subscriber hints that are not currently scheduled.
   *
   * @return estimated count of watched keys
   */
  @Override
  public synchronized long countKeys() {
    return watchingKeys.size();
  }

  /**
   * Reports whether a given key is definitely wanted by this fetcher.
   *
   * <p>Keys that match the current watch window return a priority class indicating interest; all
   * others return {@code -1}. The method only handles {@link NodeSSK} keys for the tracked USK. It
   * does not attempt to decode or validate blocks, only to decide scheduling priority.
   *
   * @param key candidate key to evaluate; must not be null
   * @param saltedKey scheduler-provided salted key bytes; unused by this implementation
   * @param context client context used to query current slots; must not be null
   * @return a priority class when wanted, or {@code -1} when not wanted
   */
  @Override
  public short definitelyWantKey(Key key, byte[] saltedKey, ClientContext context) {
    if (!(key instanceof NodeSSK k)) return -1;
    if (!origUSK.samePubKeyHash(k)) return -1;
    long lastSlot = uskManager.lookupLatestSlot(origUSK) + 1;
    synchronized (this) {
      if (watchingKeys.match(k, lastSlot) != -1) return progressPollPriority;
    }
    return -1;
  }

  /**
   * Returns the listener that owns key interest for this fetcher.
   *
   * <p>The returned listener is the fetcher itself, which implements {@link KeyListener} and
   * related interfaces used by the scheduler.
   *
   * @return this fetcher as the owning key listener
   */
  @Override
  public HasKeyListener getHasKeyListener() {
    return this;
  }

  /**
   * Returns the current priority class used for progress polling.
   *
   * <p>The value may change as subscribers and callbacks are added or removed. Call {@link
   * #refreshAndGetProgressPollPriority()} to recalculate before using the value in scheduling.
   *
   * @return priority class for scheduling work associated with this fetcher
   */
  @Override
  public short getPriorityClass() {
    return progressPollPriority;
  }

  /**
   * Returns requests for a key when actively scheduling a specific block.
   *
   * <p>This fetcher does not provide direct requests for keys and therefore returns an empty array.
   * It relies on higher-level scheduling and key matching to trigger checks.
   *
   * @param key key for which requests are being queried; must not be null
   * @param saltedKey scheduler-provided salted key bytes; unused by this implementation
   * @param context client context used for scheduling; unused by this implementation
   * @return an empty array because this fetcher does not expose per-key requests
   */
  @Override
  public SendableGet[] getRequestsForKey(Key key, byte[] saltedKey, ClientContext context) {
    return new SendableGet[0];
  }

  /**
   * Handles a matching block found in the datastore.
   *
   * <p>The method verifies the block type, maps it to a USK edition, and dispatches success
   * handling. If the block does not match the current watch window or cannot be verified, it is
   * ignored.
   *
   * @param key key associated with the found block; must not be null
   * @param saltedKey scheduler-provided salted key bytes; unused by this implementation
   * @param found block returned from the datastore; must not be null
   * @param context client context used for decoding and scheduling; must not be null
   * @return {@code true} if the block was handled as a success; {@code false} otherwise
   */
  @Override
  public boolean handleBlock(Key key, byte[] saltedKey, KeyBlock found, ClientContext context) {
    if (!(found instanceof SSKBlock)) return false;
    long lastSlot = uskManager.lookupLatestSlot(origUSK) + 1;
    long edition = watchingKeys.match((NodeSSK) key, lastSlot);
    if (edition == -1) return false;
    if (LOG.isDebugEnabled()) LOG.debug("Matched edition {} for {}", edition, origUSK);

    ClientSSKBlock data;
    try {
      data = watchingKeys.decode((SSKBlock) found, edition);
    } catch (SSKVerifyException _) {
      data = null;
    }
    onSuccess(null, edition, false, data, context);
    return true;
  }

  /**
   * Reports whether this fetcher has no further work to perform.
   *
   * <p>This is used by scheduling infrastructure to decide whether the request should remain
   * registered. It mirrors {@link #isCancelled()} semantics for this fetcher.
   *
   * @return {@code true} when canceled or completed; otherwise {@code false}
   */
  @Override
  public synchronized boolean isEmpty() {
    return cancelled || completed;
  }

  /**
   * Indicates that this fetcher targets SSK keys.
   *
   * <p>This value is constant for USK fetchers because USK editions map to SSK keys.
   *
   * @return always {@code true}
   */
  @Override
  public boolean isSSK() {
    return true;
  }

  /**
   * Notification hook when the request is removed from schedulers.
   *
   * <p>This implementation does not require cleanup and therefore does nothing. The method is still
   * provided to satisfy the scheduler interface.
   */
  @Override
  public void onRemove() {
    // Ignore
  }

  /**
   * Reports whether this fetcher is persistent across restarts.
   *
   * <p>USKFetcher instances are reconstructed by higher-level components when needed.
   *
   * @return always {@code false} because USKFetcher is not persistent
   */
  @Override
  public boolean persistent() {
    return false;
  }

  /**
   * Returns the routing key used to represent the USK namespace.
   *
   * <p>The returned byte array is the public key hash for the USK and can be used for routing and
   * key matching. Callers should not modify the returned array contents.
   *
   * @return the public key hash for the tracked USK
   */
  @Override
  public byte[] getWantedKey() {
    return origUSK.getPubKeyHash();
  }

  /**
   * Reports whether a key is probably wanted by this fetcher.
   *
   * <p>Unlike {@link #definitelyWantKey(Key, byte[], ClientContext)}, this method returns a boolean
   * and is used for quick filtering. It matches only {@link NodeSSK} keys for the tracked USK. The
   * check is conservative and may return {@code false} for keys outside the current watch window.
   *
   * @param key candidate key to evaluate; must not be null
   * @param saltedKey scheduler-provided salted key bytes; unused by this implementation
   * @return {@code true} when the key appears relevant; otherwise {@code false}
   */
  @Override
  public boolean probablyWantKey(Key key, byte[] saltedKey) {
    if (!(key instanceof NodeSSK k)) return false;
    if (!origUSK.samePubKeyHash(k)) return false;
    long lastSlot = uskManager.lookupLatestSlot(origUSK) + 1;
    synchronized (this) {
      return watchingKeys.match(k, lastSlot) != -1;
    }
  }

  /**
   * Updates the cooldown parameters used by USK polling.
   *
   * <p>This targeted mechanism applies updated cooldown values to the active contexts and live
   * polling attempts so they take effect without reconstructing requests. For broader
   * configuration, see the tracker discussion linked below.
   *
   * <p>See: <a
   * href="https://bugs.freenetproject.org/view.php?id=4984">https://bugs.freenetproject.org/view.php?id=4984</a>
   *
   * @param time cooldown duration in milliseconds applied between retry batches; non-negative
   *     values are expected
   * @param tries number of retries before entering a cooldown; non-negative values are expected
   */
  public void changeUSKPollParameters(long time, int tries) {
    this.ctx.setCooldownRetries(tries);
    this.ctxNoStore.setCooldownRetries(tries);
    this.ctx.setCooldownTime(time);
    this.ctxNoStore.setCooldownTime(time);
    USKAttempt[] pollers;
    synchronized (this) {
      pollers = pollingAttempts.values().toArray(new USKAttempt[0]);
    }
    for (USKAttempt a : pollers) a.reloadPollParameters();
  }

  /**
   * Tracks the list of editions that we want to fetch, from various sources - subscribers, origUSK,
   * last known slot from USKManager, etc.
   *
   * <p>LOCKING: Take the lock on this class last and always pass in lookup values. Do not look up
   * values in USKManager inside this class's lock.
   *
   * @author Matthew Toseland &lt;toad@amphibian.dyndns.org&gt; (0xE43DA450)
   */
  private class USKWatchingKeys {

    // Common for whole USK
    /** Public key hash for the USK namespace being tracked. */
    final byte[] pubKeyHash;

    /** Crypto algorithm identifier for derived SSKs. */
    final byte cryptoAlgorithm;

    // List of slots since the USKManager's current last known good edition.
    /** Key list anchored at the last known good slot. */
    private final KeyList fromLastKnownSlot;

    /** Per-subscriber key lists keyed by hinted edition. */
    private final TreeMap<Long, KeyList> fromSubscribers;

    /** Persistent hint editions that outlive transient subscribers. */
    private final TreeSet<Long> persistentHints = new TreeSet<>();

    // Note: consider additional WeakReference<KeyList> instances: one for the origUSK and
    // one per subscriber-provided edition. These should be cleared when the subscriber goes away
    // or when superseded by the last known edition.

    /**
     * Creates a watcher seeded from the provided USK and last known edition.
     *
     * @param origUSK base USK used to derive key material; must not be null
     * @param lookedUp last known edition slot used to seed key lists
     */
    public USKWatchingKeys(USK origUSK, long lookedUp) {
      this.pubKeyHash = origUSK.getPubKeyHash();
      this.cryptoAlgorithm = origUSK.cryptoAlgorithm;
      if (LOG.isDebugEnabled()) LOG.debug("Creating KeyList from last known good: {}", lookedUp);
      fromLastKnownSlot = new KeyList(lookedUp);
      fromSubscribers = new TreeMap<>();
      if (origUSK.suggestedEdition > lookedUp)
        fromSubscribers.put(origUSK.suggestedEdition, new KeyList(origUSK.suggestedEdition));
    }

    /** Bundles lookup descriptors to fetch immediately and to poll in the background. */
    class ToFetch {

      /**
       * Creates a fetch plan from the provided lookup lists.
       *
       * @param toFetch2 lookups to fetch immediately; must not be null
       * @param toPoll2 lookups to poll without immediate fetch; must not be null
       */
      public ToFetch(List<Lookup> toFetch2, List<Lookup> toPoll2) {
        fetch = toFetch2.toArray(new Lookup[0]);
        poll = toPoll2.toArray(new Lookup[0]);
      }

      /** Lookups to fetch immediately. */
      public final Lookup[] fetch;

      /** Lookups to poll in background cycles. */
      public final Lookup[] poll;
    }

    /**
     * Get a bunch of editions to probe for.
     *
     * @param lookedUp The current best known slot, from USKManager.
     * @param random The random number generator.
     * @param alreadyRunning This will be modified: We will remove anything that should still be
     *     running from it.
     * @param doRandom whether to include random probes in the returned plan
     * @return Editions to fetch and editions to poll for.
     */
    public synchronized ToFetch getEditionsToFetch(
        long lookedUp, Random random, List<Lookup> alreadyRunning, boolean doRandom) {

      if (LOG.isDebugEnabled())
        LOG.debug(
            "Get editions to fetch, latest slot is {} running is {}", lookedUp, alreadyRunning);

      List<Lookup> toFetch = new ArrayList<>();
      List<Lookup> toPoll = new ArrayList<>();

      boolean probeFromLastKnownGood =
          lookedUp > -1 || (backgroundPoll && !firstLoop) || fromSubscribers.isEmpty();

      if (probeFromLastKnownGood)
        fromLastKnownSlot.getNextEditions(toFetch, toPoll, lookedUp, alreadyRunning);

      collectFromSubscribers(lookedUp, toFetch, toPoll, alreadyRunning);

      if (doRandom) {
        collectRandomEditions(
            probeFromLastKnownGood, lookedUp, random, toFetch, toPoll, alreadyRunning);
      }

      return new ToFetch(toFetch, toPoll);
    }

    /**
     * Collects editions contributed by subscribers into fetch and poll lists.
     *
     * @param lookedUp current best-known slot from the manager
     * @param toFetch destination list for immediate fetches; entries are appended
     * @param toPoll destination list for polling attempts; entries are appended
     * @param alreadyRunning lookups already in flight; may be modified by this method
     */
    private void collectFromSubscribers(
        long lookedUp, List<Lookup> toFetch, List<Lookup> toPoll, List<Lookup> alreadyRunning) {
      // If we have moved past the origUSK, then clear the KeyList for it.
      for (Iterator<Entry<Long, KeyList>> it = fromSubscribers.entrySet().iterator();
          it.hasNext(); ) {
        Entry<Long, KeyList> entry = it.next();
        long l = entry.getKey() - 1;
        if (l <= lookedUp) {
          it.remove();
        }
        if (l == 0) {
          // add check for edition 0: this happens if -1 is suggested.
          // Needed because we cannot set -0 for exhaustive search (-0 == 0 in Java).
          entry.getValue().getEditionIfNotAlreadyRunning(toFetch, alreadyRunning, l, false);
        }
        entry.getValue().getNextEditions(toFetch, toPoll, l - 1, alreadyRunning);
      }
    }

    /**
     * Adds randomized edition probes to the fetch/poll lists.
     *
     * @param probeFromLastKnownGood whether to seed probes from the last known good slot
     * @param lookedUp current best-known slot used to bias sampling
     * @param random random source used to sample editions; must not be null
     * @param toFetch destination list for immediate fetches; entries are appended
     * @param toPoll destination list for polling attempts; entries are appended
     * @param alreadyRunning lookups already in flight; may be modified by this method
     */
    private void collectRandomEditions(
        boolean probeFromLastKnownGood,
        long lookedUp,
        Random random,
        List<Lookup> toFetch,
        List<Lookup> toPoll,
        List<Lookup> alreadyRunning) {
      // Now getRandomEditions
      int runningRandom = countRunningRandom(alreadyRunning, toFetch, toPoll);

      int allowedRandom = 1 + fromSubscribers.size();
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Running random requests: {} total allowed: {} looked up is {} for {}",
            runningRandom,
            allowedRandom,
            lookedUp,
            USKFetcher.this);

      allowedRandom -= runningRandom;

      if (allowedRandom > 0 && probeFromLastKnownGood) {
        fromLastKnownSlot.getRandomEditions(toFetch, lookedUp, alreadyRunning, random, 1);
        allowedRandom -= 1;
      }

      for (Iterator<KeyList> it = fromSubscribers.values().iterator();
          allowedRandom >= 2 && it.hasNext(); ) {
        KeyList k = it.next();
        k.getRandomEditions(toFetch, lookedUp, alreadyRunning, random, 1);
        allowedRandom -= 1;
      }
    }

    /**
     * Counts random probes that are already running but not in the current plan.
     *
     * @param alreadyRunning lookups already in flight
     * @param toFetch lookups planned for immediate fetch
     * @param toPoll lookups planned for polling
     * @return number of random probes already running outside the current plan
     */
    private static int countRunningRandom(
        List<Lookup> alreadyRunning, List<Lookup> toFetch, List<Lookup> toPoll) {
      int runningRandom = 0;
      for (Lookup l : alreadyRunning) {
        if (toFetch.contains(l) || toPoll.contains(l)) continue;
        runningRandom++;
      }
      return runningRandom;
    }

    /**
     * Reconciles subscriber hints with current persisted and derived hints.
     *
     * @param hints latest subscriber hint values; must not be null
     * @param lookedUp current best-known slot used to discard stale hints
     */
    public synchronized void updateSubscriberHints(Long[] hints, long lookedUp) {
      List<Long> surviving = collectSurvivingHints(hints, lookedUp);
      mergePersistentHints(surviving, lookedUp);
      ensureSuggestedEditionIncluded(surviving, lookedUp);
      reconcileSubscribersWithSurviving(surviving);
    }

    /**
     * Filters subscriber hints to those that remain relevant beyond {@code lookedUp}.
     *
     * @param hints subscriber hint values to filter; must not be null
     * @param lookedUp current best-known slot used as a cutoff
     * @return list of surviving hints in ascending order
     */
    private static List<Long> collectSurvivingHints(Long[] hints, long lookedUp) {
      List<Long> surviving = new ArrayList<>();
      Arrays.sort(hints);
      long prev = -1;
      for (Long hint : hints) {
        if (hint <= lookedUp) {
          prev = hint;
        } else if (hint != prev) {
          surviving.add(hint);
          prev = hint;
        }
      }
      return surviving;
    }

    /**
     * Merges persistent hints into the surviving list while dropping stale entries.
     *
     * @param surviving list of surviving hints to update; must not be null
     * @param lookedUp current best-known slot used to drop stale hints
     */
    private void mergePersistentHints(List<Long> surviving, long lookedUp) {
      for (Iterator<Long> i = persistentHints.iterator(); i.hasNext(); ) {
        Long hint = i.next();
        if (hint <= lookedUp) {
          i.remove();
        }
        if (surviving.contains(hint)) continue;
        surviving.add(hint);
      }
    }

    /**
     * Ensures the USK's suggested edition is present when it is still ahead.
     *
     * @param surviving list of surviving hints to update; must not be null
     * @param lookedUp current best-known slot used as a cutoff
     */
    private void ensureSuggestedEditionIncluded(List<Long> surviving, long lookedUp) {
      if (origUSK.suggestedEdition > lookedUp && !surviving.contains(origUSK.suggestedEdition))
        surviving.add(origUSK.suggestedEdition);
    }

    /**
     * Reconciles the subscriber map to match the surviving hints list.
     *
     * @param surviving list of surviving hint editions; must not be null
     */
    private void reconcileSubscribersWithSurviving(List<Long> surviving) {
      for (Iterator<Long> it = fromSubscribers.keySet().iterator(); it.hasNext(); ) {
        Long l = it.next();
        if (surviving.contains(l)) continue;
        it.remove();
      }
      for (Long l : surviving) {
        if (fromSubscribers.containsKey(l)) continue;
        fromSubscribers.put(l, new KeyList(l));
      }
    }

    /**
     * Adds a persistent hint edition that is ahead of the current lookup.
     *
     * @param suggestedEdition edition number to add; must be greater than {@code lookedUp}
     * @param lookedUp current best-known slot used to ignore stale hints
     */
    public synchronized void addHintEdition(long suggestedEdition, long lookedUp) {
      if (suggestedEdition <= lookedUp) return;
      if (!persistentHints.add(suggestedEdition)) return;
      if (fromSubscribers.containsKey(suggestedEdition)) return;
      fromSubscribers.put(suggestedEdition, new KeyList(suggestedEdition));
    }

    /**
     * Estimates the number of watched keys based on current subscriber state.
     *
     * @return estimated count of watched keys for scheduling decisions
     */
    public synchronized long size() {
      return WATCH_KEYS
          + (long) fromSubscribers.size() * WATCH_KEYS; // Note: does not account for overlap
    }

    /**
     * A precomputed list of E(H(docname))'s for each slot we might match. This is from an edition
     * number which might be out of date.
     */
    class KeyList {

      /** The USK edition number of the first slot */
      long firstSlot;

      /** The precomputed E(H(docname)) for each such slot. */
      private WeakReference<RemoveRangeArrayList<byte[]>> cache;

      /** We have checked the datastore from this point. */
      private long checkedDatastoreFrom = -1;

      /** We have checked the datastore up to this point. */
      private long checkedDatastoreTo = -1;

      /**
       * Creates a key list anchored at the provided slot.
       *
       * @param slot first slot to include in the cache
       */
      public KeyList(long slot) {
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Creating KeyList from {} on {} {}",
              slot,
              USKFetcher.this,
              this,
              new Exception("debug"));
        firstSlot = slot;
        RemoveRangeArrayList<byte[]> ehDocnames = new RemoveRangeArrayList<>(WATCH_KEYS);
        cache = new WeakReference<>(ehDocnames);
        generate(firstSlot, WATCH_KEYS, ehDocnames);
      }

      /**
       * Add the next set of editions to either {@code toFetch} or {@code toPoll}. If any of those
       * editions are already running, remove them from {@code alreadyRunning}.
       *
       * @param toFetch destination list for editions that should be fetched immediately when not in
       *     background polling mode; entries are appended, not cleared
       * @param toPoll destination list for editions that should be polled (no immediate fetch) when
       *     in background polling mode; entries are appended, not cleared
       * @param lookedUp current best known slot (edition) used as a base for computing the next
       *     candidate editions; values below zero are treated as zero
       * @param alreadyRunning list of lookups currently in progress; this method removes any
       *     edition that remains valid so it is not scheduled twice
       */
      public synchronized void getNextEditions(
          List<Lookup> toFetch, List<Lookup> toPoll, long lookedUp, List<Lookup> alreadyRunning) {
        if (LOG.isDebugEnabled()) LOG.debug("Getting next editions from {}", lookedUp);
        if (lookedUp < 0) lookedUp = 0;
        for (int i = 1; i <= origMinFailures; i++) {
          long ed = i + lookedUp;
          if (backgroundPoll) {
            getEditionIfNotAlreadyRunning(toPoll, alreadyRunning, ed, true);
          } else {
            getEditionIfNotAlreadyRunning(toFetch, alreadyRunning, ed, true);
          }
        }
      }

      /**
       * Adds an edition lookup if it is not already running.
       *
       * @param lookupList destination list for new lookups; entries are appended
       * @param alreadyRunning list of lookups already in progress; this method removes matches
       * @param ed edition number to add
       * @param ignoreStore whether this lookup should bypass store checks
       * @return whether the edition was added
       */
      public boolean getEditionIfNotAlreadyRunning(
          List<Lookup> lookupList, List<Lookup> alreadyRunning, long ed, boolean ignoreStore) {
        Lookup l = new Lookup();
        l.val = ed;
        if (lookupList.contains(l)) {
          if (LOG.isTraceEnabled()) LOG.trace("Ignoring {}", l);
          return false;
        }
        if (alreadyRunning.remove(l)) {
          if (LOG.isTraceEnabled()) LOG.trace("Ignoring (2): {}", l);
          return false;
        }
        ClientSSK key;
        // Note: consider reusing ehDocnames where feasible
        // The problem is we need a ClientSSK for the high level stuff.
        key = origUSK.getSSK(ed);
        l.key = key;
        l.ignoreStore = ignoreStore;
        if (lookupList.contains(l)) {
          if (LOG.isTraceEnabled()) LOG.trace("Ignoring (3): {}", l);
          return false;
        }
        return lookupList.add(l);
      }

      /**
       * Adds random edition probes to the provided list.
       *
       * @param toFetch destination list for random probes; entries are appended
       * @param lookedUp current best-known slot used as a base
       * @param alreadyRunning list of lookups already in progress; used for de-duplication
       * @param random random source used for sampling; must not be null
       * @param allowed maximum number of random editions to add
       */
      public synchronized void getRandomEditions(
          List<Lookup> toFetch,
          long lookedUp,
          List<Lookup> alreadyRunning,
          Random random,
          int allowed) {
        // Then add a couple of random editions for catch-up.
        long baseEdition = lookedUp + origMinFailures;
        for (int i = 0; i < allowed; i++) {
          while (true) { // Note: consider switching to limited for-loop to ensure there can be no
            // infinite loop
            long fetch = sampleGeometric(baseEdition, random);
            if (tryAddRandomEdition(toFetch, lookedUp, alreadyRunning, fetch)) break;
          }
        }
      }

      /**
       * Samples a future edition using a geometric distribution.
       *
       * @param baseEdition base edition offset for sampling
       * @param random random source used to sample; must not be null
       * @return sampled edition number at or above {@code baseEdition}
       */
      private static long sampleGeometric(long baseEdition, Random random) {
        // Geometric distribution.
        // 20% chance of mean 100, 80% chance of mean 10. Thanks evanbd.
        while (true) {
          int mean = random.nextInt(5) == 0 ? 100 : 10;
          double u = uniform01FromLong(random);
          long fetch = baseEdition + (long) Math.floor(Math.log(u) / Math.log(1.0 - 1.0 / mean));
          if (fetch >= baseEdition) return fetch;
        }
      }

      /**
       * Creates a uniform random value in (0,1] using {@link Random#nextLong()}.
       *
       * @param random random source used for sampling; must not be null
       * @return uniform value in the open interval (0,1]
       */
      private static double uniform01FromLong(Random random) {
        long bits = random.nextLong() & Long.MAX_VALUE; // 0 .. 2^63-1
        return (bits + 1.0) / (Long.MAX_VALUE + 1.0);
      }

      /**
       * Attempts to add a random edition if it is not already scheduled.
       *
       * @param toFetch destination list for random probes; entries are appended
       * @param lookedUp current best-known slot used for range decisions
       * @param alreadyRunning list of lookups already in progress; used for de-duplication
       * @param fetch sampled edition to add
       * @return {@code true} when the edition was added to the fetch list
       */
      private boolean tryAddRandomEdition(
          List<Lookup> toFetch, long lookedUp, List<Lookup> alreadyRunning, long fetch) {
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Trying random future edition {} for {} current edition {}",
              fetch,
              origUSK,
              lookedUp);
        return getEditionIfNotAlreadyRunning(
            toFetch, alreadyRunning, fetch, (fetch - lookedUp) < WATCH_KEYS);
      }

      /** Represents a sub-range of datastore keys to check. */
      public class StoreSubChecker {

        /** Keys to check */
        final NodeSSK[] keysToCheck;

        /** The edition from which we will have checked after we have executed this. */
        private final long checkedFrom;

        /** The edition up to which we have checked after we have executed this. */
        private final long checkedTo;

        /**
         * Creates a sub-checker for a contiguous range of editions.
         *
         * @param keysToCheck node keys to check; must not be null
         * @param checkFrom starting edition of the range
         * @param checkTo ending edition (exclusive) of the range
         */
        private StoreSubChecker(NodeSSK[] keysToCheck, long checkFrom, long checkTo) {
          this.keysToCheck = keysToCheck;
          this.checkedFrom = checkFrom;
          this.checkedTo = checkTo;
          if (LOG.isDebugEnabled())
            LOG.debug(
                "Checking datastore from {} to {} for {} on {}",
                checkFrom,
                checkTo,
                USKFetcher.this,
                this);
        }

        /** The keys have been checked. */
        void checked() {
          synchronized (KeyList.this) {
            // Update the start bound only when the previous range does not already cover it.
            if (!(checkedDatastoreTo >= checkedFrom && checkedDatastoreFrom <= checkedFrom)) {
              checkedDatastoreFrom = checkedFrom;
            }
            checkedDatastoreTo = checkedTo;
            if (LOG.isDebugEnabled())
              LOG.debug(
                  "Checked from {} to {} (now overall is {} to {}) for {} for {}",
                  checkedFrom,
                  checkedTo,
                  checkedDatastoreFrom,
                  checkedDatastoreTo,
                  USKFetcher.this,
                  origUSK);
          }
        }
      }

      /**
       * Builds a datastore checker for a window of slots starting at {@code lastSlot}.
       *
       * <p>The method reuses and extends the cached document-name hashes as needed and returns a
       * sub-checker describing the keys to check in the datastore.
       *
       * @param lastSlot starting edition to check from
       * @return a sub-checker describing keys to check, or {@code null} when no work is needed
       */
      public synchronized StoreSubChecker checkStore(long lastSlot) {
        if (LOG.isDebugEnabled())
          LOG.debug("check store from {} current first slot {}", lastSlot, firstSlot);
        long checkFrom = lastSlot;
        long checkTo = lastSlot + WATCH_KEYS;
        if (checkedDatastoreTo >= checkFrom) {
          checkFrom = checkedDatastoreTo;
        }
        if (checkFrom >= checkTo) return null; // Nothing to check.
        // Update the cache.
        RemoveRangeArrayList<byte[]> ehDocnames = updateCache(lastSlot);
        // Now create NodeSSK[] from the part of the cache that
        // ehDocnames[0] is firstSlot
        // ehDocnames[checkFrom-firstSlot] is checkFrom
        int offset = (int) (checkFrom - firstSlot);
        NodeSSK[] keysToCheck = new NodeSSK[WATCH_KEYS - offset];
        for (int x = 0, i = offset; i < WATCH_KEYS; i++, x++) {
          keysToCheck[x] = new NodeSSK(pubKeyHash, ehDocnames.get(i), cryptoAlgorithm);
        }
        return new StoreSubChecker(keysToCheck, checkFrom, checkTo);
      }

      /**
       * Updates the cached document-name hashes based on a new base edition.
       *
       * @param curBaseEdition base edition used to realign the cache
       * @return updated cache containing hashes for the current window
       */
      synchronized RemoveRangeArrayList<byte[]> updateCache(long curBaseEdition) {
        if (LOG.isDebugEnabled())
          LOG.debug("update cache from {} current first slot {}", curBaseEdition, firstSlot);
        RemoveRangeArrayList<byte[]> ehDocnames;
        if (cache == null || (ehDocnames = cache.get()) == null) {
          ehDocnames = new RemoveRangeArrayList<>(WATCH_KEYS);
          cache = new WeakReference<>(ehDocnames);
          firstSlot = curBaseEdition;
          if (LOG.isDebugEnabled()) LOG.debug("Regenerating because lost cached keys");
          generate(firstSlot, WATCH_KEYS, ehDocnames);
          return ehDocnames;
        }
        match(null, curBaseEdition, ehDocnames);
        return ehDocnames;
      }

      /**
       * Updates the cache if needed and attempts to match the provided key.
       *
       * @param key key to match, or {@code null} to only update the cache
       * @param curBaseEdition new base edition used to realign the cache
       * @return edition number for the key, or {@code -1} when not matched
       */
      public synchronized long match(NodeSSK key, long curBaseEdition) {
        if (LOG.isDebugEnabled())
          LOG.debug("match from {} current first slot {}", curBaseEdition, firstSlot);
        RemoveRangeArrayList<byte[]> ehDocnames;
        if (cache == null || (ehDocnames = cache.get()) == null) {
          ehDocnames = new RemoveRangeArrayList<>(WATCH_KEYS);
          cache = new WeakReference<>(ehDocnames);
          firstSlot = curBaseEdition;
          generate(firstSlot, WATCH_KEYS, ehDocnames);
          return key == null ? -1 : innerMatch(key, ehDocnames, 0, ehDocnames.size(), firstSlot);
        }
        // Might as well check first.
        long x = innerMatch(key, ehDocnames, 0, ehDocnames.size(), firstSlot);
        if (x != -1) return x;
        return match(key, curBaseEdition, ehDocnames);
      }

      /**
       * Updates the cache for a new base edition and matches only the changed segments.
       *
       * @param key key to match; may be {@code null} to skip matching
       * @param curBaseEdition edition to align the cache with
       * @param ehDocnames cached document-name hashes to update
       * @return edition number for the key, or {@code -1} when not matched
       */
      private long match(
          NodeSSK key, long curBaseEdition, RemoveRangeArrayList<byte[]> ehDocnames) {
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Matching {} cur base edition {} first slot was {} for {} on {}",
              key,
              curBaseEdition,
              firstSlot,
              origUSK,
              this);
        if (firstSlot < curBaseEdition) {
          return handleFirstSlotBehind(key, curBaseEdition, ehDocnames);
        } else if (firstSlot > curBaseEdition) {
          return handleFirstSlotAhead(key, ehDocnames, curBaseEdition);
        }
        return -1;
      }

      /**
       * Handles the case where {@code firstSlot} is behind the new base edition.
       *
       * @param key key to match; may be {@code null} to skip matching
       * @param curBaseEdition new base edition
       * @param ehDocnames cached document-name hashes to update
       * @return edition number for the key, or {@code -1} when not matched
       */
      private long handleFirstSlotBehind(
          NodeSSK key, long curBaseEdition, RemoveRangeArrayList<byte[]> ehDocnames) {
        if (firstSlot + ehDocnames.size() <= curBaseEdition) {
          // No overlap. Clear it and start again.
          ehDocnames.clear();
          firstSlot = curBaseEdition;
          generate(curBaseEdition, WATCH_KEYS, ehDocnames);
          return key == null ? -1 : innerMatch(key, ehDocnames, 0, ehDocnames.size(), firstSlot);
        } else {
          // There is some overlap. Delete the first part of the array then add stuff at the end.
          // ehDocnames[i] is slot firstSlot + i
          // We want to get rid of anything before curBaseEdition
          // So the first slot that is useful is the slot at i = curBaseEdition - firstSlot
          // Which is the new [0], whose edition is curBaseEdition
          ehDocnames.removeRange(0, (int) (curBaseEdition - firstSlot));
          int size = ehDocnames.size();
          firstSlot = curBaseEdition;
          generate(curBaseEdition + size, WATCH_KEYS - size, ehDocnames);
          return key == null ? -1 : innerMatch(key, ehDocnames, WATCH_KEYS - size, size, firstSlot);
        }
      }

      /**
       * Handles the case where {@code firstSlot} is ahead of the new base edition.
       *
       * @param key key to match; may be {@code null} to skip matching
       * @param ehDocnames cached document-name hashes to consult
       * @param curBaseEdition new base edition that lags behind {@code firstSlot}
       * @return edition number for the key, or {@code -1} when not matched
       */
      private long handleFirstSlotAhead(
          NodeSSK key, RemoveRangeArrayList<byte[]> ehDocnames, long curBaseEdition) {
        // Normal due to race conditions. We don't always report the new edition to the USKManager
        // immediately.
        // So ignore it.
        if (LOG.isTraceEnabled())
          LOG.trace("Ignoring regression in match() from {} to {}", curBaseEdition, firstSlot);
        return key == null ? -1 : innerMatch(key, ehDocnames, 0, ehDocnames.size(), firstSlot);
      }

      /**
       * Matches a key against a slice of the cached hash list.
       *
       * @param key key to match; must not be null
       * @param ehDocnames cached document-name hashes to scan
       * @param offset start offset within the cache
       * @param size number of entries to scan
       * @param firstSlot edition represented by cache index 0
       * @return matched edition number, or {@code -1} when not found
       */
      private long innerMatch(
          NodeSSK key,
          RemoveRangeArrayList<byte[]> ehDocnames,
          int offset,
          int size,
          long firstSlot) {
        byte[] data = key.getKeyBytes();
        for (int i = offset; i < (offset + size); i++) {
          if (Arrays.equals(data, ehDocnames.get(i))) {
            if (LOG.isDebugEnabled()) LOG.debug("Found edition {} for {}", firstSlot + i, origUSK);
            return firstSlot + i;
          }
        }
        return -1;
      }

      /**
       * Appends a series of document-name hashes to the cache.
       *
       * @param baseEdition edition to start from
       * @param keys number of keys to add
       * @param ehDocnames cache to append to; must not be null
       */
      private void generate(long baseEdition, int keys, RemoveRangeArrayList<byte[]> ehDocnames) {
        if (LOG.isDebugEnabled()) LOG.debug("generate() from {} for {}", baseEdition, origUSK);
        assert (baseEdition >= 0);
        for (int i = 0; i < keys; i++) {
          long ed = baseEdition + i;
          ehDocnames.add(origUSK.getSSK(ed).ehDocname);
        }
      }
    }

    /**
     * Builds a datastore checker for the current watch lists.
     *
     * @param lastSlot last known good edition used to seed checks
     * @return store checker to run, or {@code null} when no checks are required
     */
    public synchronized USKStoreChecker getDatastoreChecker(long lastSlot) {
      // Check WATCH_KEYS from last known good slot.
      // Note: does not currently take origUSK or subscribers into account.
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Getting datastore checker from {} for {} on {}",
            lastSlot,
            origUSK,
            USKFetcher.this,
            new Exception("debug"));
      List<KeyList.StoreSubChecker> checkers = new ArrayList<>();
      KeyList.StoreSubChecker c = fromLastKnownSlot.checkStore(lastSlot + 1);
      if (c != null) checkers.add(c);
      // If we have moved past the origUSK, then clear the KeyList for it.
      for (Iterator<Entry<Long, KeyList>> it = fromSubscribers.entrySet().iterator();
          it.hasNext(); ) {
        Entry<Long, KeyList> entry = it.next();
        long l = entry.getKey();
        if (l <= lastSlot) it.remove();
        c = entry.getValue().checkStore(l);
        if (c != null) checkers.add(c);
      }
      if (!checkers.isEmpty()) return new USKStoreChecker(checkers);
      else return null;
    }

    /**
     * Decodes a low-level {@link SSKBlock} into a client-level block for the given edition.
     *
     * @param block low-level block to decode; must not be null
     * @param edition edition number that the block is expected to represent
     * @return decoded client block for the edition
     * @throws SSKVerifyException if the block does not match the expected docname hash
     */
    public ClientSSKBlock decode(SSKBlock block, long edition) throws SSKVerifyException {
      ClientSSK csk = origUSK.getSSK(edition);
      if (!Arrays.equals(csk.ehDocname, block.getKey().getKeyBytes())) {
        throw new SSKVerifyException("Docname hash mismatch for decoded block");
      }
      return ClientSSKBlock.construct(block, csk);
    }

    /**
     * Attempts to match the provided node key against watched key lists.
     *
     * @param key node key to match; must not be null
     * @param lastSlot last known good edition used to prune stale lists
     * @return matched edition number, or {@code -1} when no match is found
     */
    public synchronized long match(NodeSSK key, long lastSlot) {
      if (LOG.isDebugEnabled())
        LOG.debug("Trying to match {} from slot {} for {}", key, lastSlot, origUSK);
      long ret = fromLastKnownSlot.match(key, lastSlot);
      if (ret != -1) return ret;

      for (Iterator<Entry<Long, KeyList>> it = fromSubscribers.entrySet().iterator();
          it.hasNext(); ) {
        Entry<Long, KeyList> entry = it.next();
        long l = entry.getKey();
        if (l <= lastSlot) it.remove();
        ret = entry.getValue().match(key, l);
        if (ret != -1) return ret;
      }
      return -1;
    }
  }

  /**
   * Adds an edition hint to bias future fetch decisions.
   *
   * <p>Hints greater than the current last-known slot are remembered and may expand the search
   * window. Duplicate or stale hints are ignored. This method does not trigger immediate network
   * activity; it only updates the internal watch list used for subsequent scheduling rounds.
   *
   * @param suggestedEdition the edition number to add as a hint; must be greater than the last
   *     looked-up slot to have any effect
   */
  public void addHintEdition(long suggestedEdition) {
    watchingKeys.addHintEdition(suggestedEdition, uskManager.lookupLatestSlot(origUSK));
  }

  /** Describes a specific edition lookup and its derived key. */
  private class Lookup {
    /** Edition value represented by this lookup. */
    long val;

    /** Client SSK key derived for the edition. */
    ClientSSK key;

    /** Whether this lookup should bypass store checks. */
    boolean ignoreStore;

    /** Creates an empty lookup descriptor. */
    Lookup() {}

    @Override
    public boolean equals(Object o) {
      if (o instanceof Lookup lookup) {
        return lookup.val == val;
      } else return false;
    }

    @Override
    public int hashCode() {
      return Long.hashCode(val);
    }

    @Override
    public String toString() {
      return origUSK + ":" + val;
    }
  }

  /**
   * Resumes the request after a restart.
   *
   * <p>USKFetcher does not persist across restarts; callers should recreate it via the manager
   * instead of resuming.
   *
   * @param context client context that would be used for resuming; must not be null
   * @throws UnsupportedOperationException always, because this fetcher is not persistent
   */
  @Override
  public void onResume(ClientContext context) {
    throw new UnsupportedOperationException("Not persistent");
  }

  /**
   * Notifies the fetcher that the node is shutting down.
   *
   * <p>USKFetcher does not persist state, so shutdown handling is not supported.
   *
   * @param context client context associated with shutdown; must not be null
   * @throws UnsupportedOperationException always, because this fetcher is not persistent
   */
  @Override
  public void onShutdown(ClientContext context) {
    throw new UnsupportedOperationException("Not persistent");
  }
}
