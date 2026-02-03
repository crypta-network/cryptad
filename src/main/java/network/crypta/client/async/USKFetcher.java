package network.crypta.client.async;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import network.crypta.client.FetchContext;
import network.crypta.keys.ClientSSKBlock;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.Key;
import network.crypta.keys.KeyBlock;
import network.crypta.keys.NodeSSK;
import network.crypta.keys.USK;
import network.crypta.node.SendableGet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Coordinates discovery, polling, and optional data retrieval for a {@link USK} namespace.
 *
 * <p>This fetcher drives a USK discovery round by consulting the datastore, scheduling edition
 * probes, and applying Date-Based Request (DBR) hints to narrow toward the latest available slot.
 * Callers typically construct one instance per USK, register callbacks or subscribers, and invoke
 * {@link #schedule(ClientContext)} to begin work. The instance may complete a single round or
 * continue background polling; it cooperates with {@link USKManager} and scheduler infrastructure
 * so network I/O stays in scheduler-managed tasks rather than in this class.
 *
 * <p>The internal state model centers on mutable polling state: in-flight attempts, a watch window,
 * the last attempted edition, and optional retained payload data. The fetcher respects a minimum
 * failure threshold before declaring a round finished and may reschedule with backoff when
 * configured. These invariants let callers treat each round as a bounded probe of the USK space.
 *
 * <p>Concurrency is handled with synchronized sections guarding shared fields such as completion
 * flags and watch lists. Cancellation or completion is terminal and makes later schedule requests
 * no-ops, and the fetcher is not persistent across restarts.
 *
 * <ul>
 *   <li>Collects subscriber hints and updates polling priorities for interactive workloads.
 *   <li>Coordinates attempt lifecycle, including store checks, DBR hints, and probe rounds.
 *   <li>Reports progress and completion results to registered callbacks.
 *   <li>Supports background polling with backoff when configured by options.
 * </ul>
 *
 * @see USKManager
 * @see USK
 * @see USKDateHintFetches
 */
public class USKFetcher
    implements ClientGetState, USKCallback, HasKeyListener, KeyListener, USKAttemptCallbacks {
  /** Logger for polling, scheduling, and hint-processing diagnostics. */
  private static final Logger LOG = LoggerFactory.getLogger(USKFetcher.class);

  /** Manager that owns known slot state and subscription coordination. */
  private final USKManager uskManager;

  /** Base USK namespace from which edition keys are derived. */
  private final USK origUSK;

  /** Registered completion callbacks for this fetch cycle. */
  private final List<USKFetcherCallback> callbacks;

  /** Base fetch context for normal network and store checks. */
  final FetchContext ctx;

  /** Context configured to bypass the datastore for probe attempts. */
  final FetchContext ctxNoStore;

  /** Specialized context for Date-Based Request hint fetches. */
  final FetchContext ctxDBR;

  /** Whether this fetch cycle completed successfully or with failure. */
  private boolean completed;

  /** Whether cancellation has been requested and further work should stop. */
  private boolean cancelled;

  /** Whether this instance only checks the local store and avoids network fetches. */
  private final boolean checkStoreOnly;

  /** Parent requester that owns this fetcher and its scheduling priority. */
  final ClientRequester parent;

  /** Structure tracking which keys we want. */
  private final USKKeyWatchSet watchingKeys;

  /** Attempt lifecycle manager for polling and probe attempts. */
  private final USKAttemptManager attempts;

  /** Coordinates datastore store checks. */
  private final USKStoreCheckCoordinator storeChecks;

  /** Tracks subscribers and priority selection. */
  private final USKSubscriberRegistry subscriberRegistry;

  /** Handles data retention and completion callbacks. */
  private final USKCompletionCoordinator completionCoordinator;

  /** Builds plans for handling success and found editions. */
  private final USKSuccessPlanner successPlanner;

  /** Coordinates scheduling state for a polling round. */
  private final USKSchedulingCoordinator schedulingCoordinator;

  /** Manages polling round completion and backoff. */
  private final USKPollingRound pollingRound;

  /**
   * Registers a fetcher-level callback to observe completion results.
   *
   * <p>Callbacks are invoked when a polling round reaches a terminal outcome or when a single-shot
   * fetch completes. They receive {@code onFoundEdition(...)} at most once per lifecycle unless
   * background polling is enabled, in which case the callback may not be notified for long periods.
   * This method also affects dynamic scheduling because callback priority hints are folded into the
   * polling priority calculation and can bias progress checks for interactive users.
   *
   * <p>The call is thread-safe and idempotent with respect to completed instances. Adding callbacks
   * after completion has no effect and returns {@code false} without side effects. Callback
   * instances are expected to remain valid for the life of the fetcher and may be called from
   * scheduler threads rather than the caller's thread. The method does not trigger scheduling on
   * its own, but it does update priorities immediately after the callback is stored.
   *
   * <p>Preconditions are minimal: the callback must be non-null and should tolerate invocation on
   * internal threads. Postconditions are limited to registration and priority refresh; the caller
   * should not expect immediate network activity as a result of this call.
   *
   * @param cb callback instance to register; must be non-null and long-lived
   * @return {@code true} when accepted; {@code false} if already completed
   *     <pre>{@code
   * // Example: register a callback before scheduling
   * fetcher.addCallback(callback);
   * }</pre>
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

  /** Helper for Date-Based Request (DBR) hint scheduling and parsing. */
  private final USKDateHintFetches dbrHintFetches;

  /** Highest edition number fetched or attempted during this cycle. */
  private long lastFetchedEdition;

  /** Minimum consecutive failures tolerated before a polling round concludes. */
  final long origMinFailures;

  /** Initial sleep interval between polling rounds, in milliseconds. */
  static final long ORIG_SLEEP_TIME = 30L * 60 * 1000;

  /** Maximum sleep interval between polling rounds, in milliseconds. */
  static final long MAX_SLEEP_TIME = 24L * 60 * 60 * 1000;

  /** Whether this fetcher continues polling after the first successful round. */
  private final boolean backgroundPoll;

  /** Whether the most recently fetched payload should be retained in memory. */
  final boolean keepLastData;

  /** Whether this fetcher uses real-time scheduling policies. */
  private final boolean realTimeFlag;

  // Options flags for constructor to reduce parameter count
  /** Option flag to enable background polling beyond the first round. */
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
   * #schedule(ClientContext)} or {@link #schedule(long, ClientContext)} to begin a cycle. The
   * resulting instance is mutable and designed to be used by scheduling threads; it is not
   * persistent across restarts.
   *
   * <p>Configuration flags in {@code options} can enable background polling, retain the most recent
   * payload, or restrict work to datastore checks. Invalid combinations are not explicitly
   * rejected, so callers should supply only supported flags.
   *
   * @param origUSK base USK to probe for editions; must be non-null and valid
   * @param manager manager used to look up and update known slots; must be non-null and shared
   * @param ctx base fetch context used for normal and no-store checks; must be non-null
   * @param requester parent requester that supplies priority and persistence flags; must be
   *     non-null
   * @param minFailures minimum DNFs tolerated before concluding a round; non-negative values only
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
    if (origMinFailures > USKKeyWatchSet.WATCH_KEYS) throw new IllegalArgumentException();
    callbacks = new ArrayList<>();
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
    // Whereas the latestSlot we've definitely fetched, we don't want to re-check.
    watchingKeys =
        new USKKeyWatchSet(
            origUSK,
            Math.max(0, uskManager.lookupLatestSlot(origUSK) + 1),
            minFailures,
            backgroundPoll);
    dbrHintFetches = new USKDateHintFetches(this, uskManager, origUSK, this.ctx, ctxDBR, parent);
    attempts =
        new USKAttemptManager(
            new USKAttemptContext(this, origUSK, this.ctx, ctxNoStore, parent, realTimeFlag),
            uskManager,
            watchingKeys,
            checkStoreOnly,
            keepLastData);
    subscriberRegistry = new USKSubscriberRegistry(watchingKeys, uskManager, attempts, origUSK);
    completionCoordinator =
        new USKCompletionCoordinator(
            new USKCompletionHandler(keepLastData), uskManager, origUSK, parent, realTimeFlag);
    successPlanner = new USKSuccessPlanner();
    storeChecks =
        new USKStoreCheckCoordinator(
            USKStoreCheckCoordinator.Params.builder()
                .watchingKeys(watchingKeys)
                .attempts(attempts)
                .parent(parent)
                .checkStoreOnly(checkStoreOnly)
                .uskManager(uskManager)
                .origUSK(origUSK)
                .callbacks(new StoreCheckCallbacks())
                .realTimeFlag(realTimeFlag)
                .build());
    schedulingCoordinator =
        new USKSchedulingCoordinator(attempts, storeChecks, dbrHintFetches, checkStoreOnly);
    pollingRound =
        new USKPollingRound(
            new USKPollingRoundContext(
                attempts,
                storeChecks,
                dbrHintFetches,
                subscriberRegistry,
                uskManager,
                origUSK,
                realTimeFlag),
            ORIG_SLEEP_TIME,
            true,
            ORIG_SLEEP_TIME,
            MAX_SLEEP_TIME);
  }

  /**
   * Called when all outstanding DBR hint fetches have either completed or failed.
   *
   * <p>If the main scheduling path was waiting for DBR results, this method triggers the next
   * scheduling step. It also checks whether the current polling round can be considered finished
   * for now and notifies progress callbacks. The method is safe to call from scheduler threads and
   * performs no blocking work beyond scheduling follow-up tasks.
   *
   * <p>Calling this method multiple times is safe; repeated invocations simply re-evaluate the
   * scheduling state and may become no-ops if the poll round has already advanced. No exceptions
   * are thrown, and the only side effects are scheduling decisions and progress checks.
   *
   * @param context client context used to schedule follow-up work; must be non-null
   */
  public void onDBRsFinished(ClientContext context) {
    boolean needSchedule;
    synchronized (this) {
      needSchedule = schedulingCoordinator.scheduleAfterDBRsDone();
    }
    if (needSchedule) schedule(context);
    pollingRound.checkFinishedForNow(context, cancelled, completed);
  }

  /**
   * Notifies that a USK slot check entered a finite cooldown.
   *
   * <p>This acts as a progress signal during a polling round. When all active checks have cooled
   * down at least once, the round can be treated as finished for now and progress callbacks may be
   * invoked. The method is a lightweight hook and does not trigger network I/O itself.
   *
   * @param context client context used to perform completion checks; must be non-null
   */
  @Override
  public void onEnterFiniteCooldown(ClientContext context) {
    checkFinishedForNow(context);
  }

  /**
   * Evaluates whether the current polling round can be treated as finished.
   *
   * <p>The method consults {@link USKPollingRound} and verifies that all polling attempts have
   * entered a finite cooldown at least once. When those conditions hold, it emits the
   * round-finished callback to interested subscribers.
   *
   * @param context client context used to notify progress callbacks; must not be null
   */
  private void checkFinishedForNow(ClientContext context) {
    pollingRound.checkFinishedForNow(context, cancelled, completed);
  }

  // moved into USKStoreCheckerGetter to satisfy S3398

  /**
   * Handles a "data not found" result from an attempt and advances completion logic.
   *
   * <p>The method updates tracking structures, records the last fetched edition, and determines
   * whether a polling round should be concluded. A DNF is treated as non-fatal and is used only to
   * drive scheduling decisions; it does not terminate the fetcher unless other completion criteria
   * are met. This method is safe to call from worker threads used by individual attempts.
   *
   * <p>DNFs may occur during datastore checks or network probes; the handler treats both sources
   * the same and only examines attempt state, never the payload. The method does not throw and
   * performs no blocking I/O, so callers can invoke it directly from scheduling callbacks. If the
   * last running attempt reports DNF, the method may trigger completion for the current polling
   * round.
   *
   * @param att attempt that reported DNF; must be non-null and associated with this fetcher
   * @param context client context used for follow-up scheduling; must be non-null
   */
  @Override
  public void onDNF(USKAttempt att, ClientContext context) {
    if (LOG.isDebugEnabled()) LOG.debug("DNF: {}", att);
    boolean finished = false;
    long curLatest = uskManager.lookupLatestSlot(origUSK);
    synchronized (this) {
      if (completed || cancelled) return;
      lastFetchedEdition = Math.max(lastFetchedEdition, att.number);
      attempts.removeRunningAttempt(att.number);
      if (!attempts.hasRunningAttempts()) {
        if (LOG.isDebugEnabled())
          LOG.debug(
              "latest: {}, last fetched: {}, curLatest+MIN_FAILURES: {}",
              curLatest,
              lastFetchedEdition,
              curLatest + origMinFailures);
        if (schedulingCoordinator.isStarted()) {
          finished = true;
        }
      } else if (LOG.isDebugEnabled())
        LOG.debug("Remaining: {}", attempts.runningAttemptsDescription());
    }
    if (finished) {
      finishSuccess(context);
    }
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
    schedulingCoordinator.resetStarted();
    long delay =
        pollingRound.rescheduleBackgroundPoll(context, schedulingCoordinator.valueAtSchedule());
    schedule(delay, context);
    pollingRound.checkFinishedForNow(context, cancelled, completed);
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
    completionCoordinator.completeCallbacks(context, this, cb);
  }

  /**
   * Handles a successful attempt using the attempt's edition as the current latest.
   *
   * <p>This is a convenience overload that forwards to the edition-aware handler and preserves the
   * update flag. The method expects that the provided attempt originated from this fetcher; it does
   * not perform deep validation beyond scheduling and tracking updates.
   *
   * <p>The outcome mirrors the full handler: scheduling decisions, decode choices, and manager
   * updates are derived from the attempt's edition and the current slot state. The call is safe
   * from worker threads and does not block beyond enqueuing follow-up work. Passing {@code null}
   * for the attempt is permitted for synthetic success notifications that still carry a block
   * payload.
   *
   * @param att attempt that completed successfully; may be null for synthetic successes
   * @param dontUpdate whether to suppress updating the USK manager with this edition
   * @param block block returned by the attempt, or {@code null} for metadata-only successes
   * @param context client context used for scheduling and storage; must be non-null
   */
  @Override
  public void onSuccess(
      USKAttempt att, boolean dontUpdate, ClientSSKBlock block, final ClientContext context) {
    onSuccess(att, att.number, dontUpdate, block, context);
  }

  /**
   * Handles a successful attempt and applies updates for the provided edition.
   *
   * <p>The method prepares a success plan, cancels obsolete attempts, optionally decodes payload
   * data, and updates the USK manager unless suppressed. It may also register new attempts to
   * continue probing near the current latest edition. When {@code dontUpdate} is {@code true}, the
   * manager is left untouched but local bookkeeping and decode decisions still apply.
   *
   * <p>The method is idempotent with respect to repeated success notifications for the same
   * edition; it only advances the latest slot when the reported edition exceeds the current known
   * value. Callers should pass the same {@link ClientContext} used by related scheduling operations
   * so that follow-up tasks are enqueued on consistent queues. If the fetcher is already completed
   * or canceled, the success is ignored and no additional scheduling occurs.
   *
   * @param att attempt that completed successfully; may be null for synthetic successes
   * @param curLatest edition number discovered by the attempt; non-negative values are expected
   * @param dontUpdate whether to suppress updating the USK manager with this edition
   * @param block fetched block containing metadata or data; may be null for author errors
   * @param context client context used for scheduling and storage; must be non-null
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

    USKSuccessPlanner.SuccessPlan plan =
        prepareSuccessPlan(att, curLatest, dontUpdate, block, context, lastEd);
    if (plan == null) return; // finished or canceled

    attempts.finishCancelBefore(plan.killAttempts, context);

    applyDecodedData(plan.decode, block, context);

    if (!dontUpdate) uskManager.updateSlot(origUSK, plan.curLatest, context);
    if (plan.registerNow) registerAttempts(context);
  }

  /**
   * Decodes the block into a bucket when decoding is requested.
   *
   * @param decode whether decoding should be attempted for this block
   * @param block block to decode; may be null when decoding is not applicable
   * @param context client context used for bucket allocation; must not be null
   */
  private void applyDecodedData(boolean decode, ClientSSKBlock block, ClientContext context) {
    completionCoordinator.applyDecodedData(decode, block, context);
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
  private USKSuccessPlanner.SuccessPlan prepareSuccessPlan(
      USKAttempt att,
      long curLatest,
      boolean dontUpdate,
      ClientSSKBlock block,
      ClientContext context,
      long lastEd) {
    boolean decode;
    List<USKAttempt> killAttempts = null;
    boolean shouldFillKeysWatching;
    long effectiveLatest;
    synchronized (this) {
      if (att != null) attempts.removeRunningAttempt(att.number);
      if (completed || cancelled) {
        if (LOG.isDebugEnabled())
          LOG.debug("Finished already: completed={} cancelled={}", completed, cancelled);
        return null;
      }
      decode = USKSuccessPlanner.shouldDecode(curLatest, lastEd, dontUpdate, block);
      effectiveLatest = Math.max(lastEd, curLatest);
      if (LOG.isDebugEnabled()) LOG.debug("Latest: {} in onSuccess", effectiveLatest);
      if (!checkStoreOnly) {
        killAttempts = attempts.cancelBefore(effectiveLatest);
        attempts.addNewAttempts(effectiveLatest, context, pollingRound.firstLoop());
      }
      shouldFillKeysWatching =
          !schedulingCoordinator.scheduleAfterDBRsDone() || !dbrHintFetches.hasOutstanding();
    }
    boolean registerNow = false;
    if (shouldFillKeysWatching && !isCancelled()) {
      registerNow = !fillKeysWatching(effectiveLatest, context);
    }
    return successPlanner.createSuccessPlan(decode, effectiveLatest, registerNow, killAttempts);
  }

  /**
   * Determines whether to add random edition probes during scheduling.
   *
   * <p>The decision is delegated to the DBR hint subsystem so that hint fetch outcomes influence
   * how aggressively random probing is used. This avoids excessive random probes when hint-driven
   * discovery already provides sufficient coverage.
   *
   * @param random random source used for probabilistic scheduling; must be non-null
   * @param isFirstLoop whether this scheduling pass is the first loop after construction
   * @return {@code true} when random probes should be added for this round
   */
  @Override
  public boolean shouldAddRandomEditions(Random random, boolean isFirstLoop) {
    return dbrHintFetches.shouldAddRandomEditions(random, isFirstLoop);
  }

  /**
   * Handles cancellation of an attempt and completes cancellation if needed.
   *
   * <p>The method removes the attempt from active tracking. If this was the last running attempt
   * and the fetcher has already been marked as canceled, completion callbacks are fired. The call
   * is safe from worker threads and performs no blocking I/O.
   *
   * @param att attempt that was canceled; must be non-null and associated with this fetcher
   * @param context client context used for callback notifications; must be non-null
   */
  @Override
  public void onCancelled(USKAttempt att, ClientContext context) {
    synchronized (this) {
      attempts.removeRunningAttempt(att.number);
      if (attempts.hasRunningAttempts()) return;

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
    completionCoordinator.finishCancelled(context, cb);
  }

  /**
   * Returns the underlying {@link FreenetURI} of the original USK.
   *
   * <p>The returned URI reflects the base USK namespace and does not change as editions advance.
   * Callers can use it for logging, diagnostics, or to derive edition-specific URIs via {@link
   * USK#copy(long)}. The method performs no I/O and does not allocate new objects beyond returning
   * the existing reference.
   *
   * @return immutable URI identifying the tracked USK; callers must not mutate it
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
   * provides a snapshot of the state that may change immediately after return.
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
   * <p>Delays are expressed in milliseconds and are interpreted relative to the caller's clock.
   * This method does not validate whether the fetcher is currently registered; it simply forwards
   * to the scheduler. Delayed scheduling preserves the same priority configuration that would be
   * applied to an immediate call. The caller should avoid scheduling multiple delayed calls for the
   * same instance unless intentional, as each call queues an independent timed job.
   *
   * @param delay delay in milliseconds before scheduling; non-positive schedules immediately
   * @param context client context used to reach the scheduler and timing facilities; must be
   *     non-null
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
   * <p>Callers should supply the same {@link ClientContext} used by related requests so scheduling
   * occurs on the expected queues. The method is idempotent with respect to registration state, but
   * it does not coalesce concurrent calls. If the request is configured for store-only checks, this
   * method may resolve the round immediately after store checks are complete.
   *
   * <pre>{@code
   * // Example: schedule immediately after construction
   * fetcher.schedule(context);
   * }</pre>
   *
   * @param context client context that provides schedulers, timing, and factories required to run
   *     the discovery loop; must be non-null
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
    if (shouldAbortSchedule()) return;
    USKSchedulingCoordinator.SchedulePlan plan = buildSchedulePlan(lookedUp, startedDBRs, context);
    if (plan == null) return;
    synchronized (this) {
      plan.bye = cancelled || completed;
    }
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

  private USKFetcherCallback[] snapshotCallbacks() {
    synchronized (this) {
      return callbacks.toArray(new USKFetcherCallback[0]);
    }
  }

  /**
   * Builds a plan describing how to proceed with scheduling for this round.
   *
   * <p>The plan determines whether attempts should be registered immediately, whether the fetcher
   * should exit early, and whether store-only checking can be considered complete.
   *
   * @param lookedUp the latest slot looked up in the manager
   * @param startedDBRs whether DBR hint fetches were started for this round
   * @param context client context used for scheduling decisions; must not be null
   * @return a schedule plan describing next steps for the caller
   */
  private USKSchedulingCoordinator.SchedulePlan buildSchedulePlan(
      long lookedUp, boolean startedDBRs, ClientContext context) {
    synchronized (this) {
      if (cancelled || completed) return null;
    }
    return schedulingCoordinator.buildSchedulePlan(
        lookedUp, startedDBRs, context, pollingRound.firstLoop());
  }

  /**
   * Cancels this fetcher and releases scheduler registrations.
   *
   * <p>After cancellation the fetcher stops scheduling any further datastore checks, DBR hint
   * fetches, or edition probes, and it unsubscribes from the {@link USKManager}. In-flight attempts
   * are canceled when possible, and later calls that would otherwise schedule work become no-ops.
   * This method is idempotent; calling it more than once has no additional effect beyond logging.
   *
   * <p>Cancellation does not delete any previously obtained data. If background polling was
   * configured, it is disabled for the lifetime of this instance. A new {@code USKFetcher} must be
   * created to resume discovery.
   *
   * <p>Cancellation is synchronous with respect to internal bookkeeping but does not wait for
   * external network operations to finish; those are aborted or left to complete asynchronously by
   * the underlying schedulers. Any retained payload data is cleared, so later callbacks do not
   * reuse stale buffers.
   *
   * @param context client runtime context used to unregister listeners and cancel outstanding work;
   *     must be non-null
   */
  @Override
  public void cancel(ClientContext context) {
    if (LOG.isDebugEnabled()) LOG.debug("Cancelling {}", this);
    uskManager.unsubscribe(origUSK, this);
    context.getSskFetchScheduler(realTimeFlag).schedTransient.removePendingKeys((KeyListener) this);
    USKAttempt[] running;
    USKAttempt[] polling;
    uskManager.onFinished(this);
    synchronized (this) {
      if (cancelled) LOG.error("Already cancelled {}", this);
      if (completed) LOG.error("Already completed {}", this);
      cancelled = true;
      running = attempts.snapshotRunningAttempts();
      polling = attempts.snapshotPollingAttempts();
      attempts.clearAllAttempts();
    }
    for (USKAttempt attempt : running) attempt.cancel(context);
    for (USKAttempt p : polling) p.cancel(context);
    dbrHintFetches.cancelAll(context);
    storeChecks.cancelStoreChecker(context);
    completionCoordinator.clearLastRequestData();
  }

  /**
   * Adds a subscriber and its current edition hint.
   *
   * <p>This class does not directly notify subscribers; instead, they influence whether and how
   * aggressively the fetcher continues to probe for newer editions. Hints help bias the search and
   * are folded into the key-watching window used for datastore checks and network probes. The call
   * is thread-safe and does not trigger immediate network I/O. Repeated registrations of the same
   * callback update its hint and priority contributions without creating duplicate entries.
   *
   * <p>The method only mutates subscription state; it does not schedule new attempts directly. Any
   * new scheduling decisions will happen when priorities are recomputed or when the next scheduling
   * pass runs.
   *
   * @param cb subscriber whose interest influences polling priority and continuation; must be
   *     non-null
   * @param hint subscriber's best-known edition number; larger values expand the watch window
   */
  public void addSubscriber(USKCallback cb, long hint) {
    USKFetcherCallback[] fetcherCallbacks = snapshotCallbacks();
    subscriberRegistry.addSubscriber(cb, hint, fetcherCallbacks, toString());
  }

  /**
   * Recomputes polling priorities based on subscriber and callback preferences.
   *
   * <p>When no callbacks are present, the priorities are reset to defaults. Otherwise, the method
   * selects the most urgent priorities among all interested parties.
   */
  private void updatePriorities() {
    subscriberRegistry.updatePriorities(snapshotCallbacks(), toString());
  }

  /**
   * Refreshes priorities and returns the current progress polling priority class.
   *
   * @return priority class to use for progress-oriented polling
   */
  short refreshAndGetProgressPollPriority() {
    return subscriberRegistry.refreshAndGetProgressPollPriority(snapshotCallbacks(), toString());
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
  public boolean hasSubscribers() {
    return subscriberRegistry.hasSubscribers();
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
  public boolean hasCallbacks() {
    return subscriberRegistry.hasCallbacks(snapshotCallbacks());
  }

  /**
   * Removes a previously added subscriber.
   *
   * <p>The subscriber will no longer influence polling priority or the set of editions watched in
   * the datastore. Removing a non-existent subscriber has no effect. The method also updates
   * internal hint tracking so that future scheduling reflects the reduced interest set, and it
   * recalculates priorities based on remaining subscribers. The call is thread-safe and does not
   * block on network activity.
   *
   * @param cb subscriber to remove; {@code null} is ignored
   */
  public void removeSubscriber(USKCallback cb) {
    subscriberRegistry.removeSubscriber(cb, snapshotCallbacks(), toString());
  }

  /**
   * Removes a fetcher-level callback.
   *
   * <p>This implementation removes the callback from the subscriber set and hint map, which stops
   * it from influencing polling decisions. It does not modify the fetcher-level callback list
   * because those callbacks are tracked separately from subscriber callbacks. This behavior mirrors
   * legacy expectations where the same callback instance can be used in both roles.
   *
   * @param cb callback to remove; {@code null} is ignored
   */
  @SuppressWarnings("unused")
  public void removeCallback(USKCallback cb) {
    subscriberRegistry.removeCallback(cb);
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
   * {@link #refreshAndGetProgressPollPriority()} instead to refresh priorities and get the current
   * value.
   *
   * @return never returns normally
   * @throws UnsupportedOperationException always, because this operation is unsupported here
   */
  @Override
  public short getPollingPriorityProgress() {
    throw new UnsupportedOperationException();
  }

  /**
   * Reacts to a newly discovered USK edition.
   *
   * <p>When invoked with {@code newKnownGood == true} and {@code newSlotToo == false} the callback
   * is ignored because slot (edition) discovery is the only driver for follow-up work here. For
   * other cases, the method updates internal bookkeeping, may cancel stale attempts, and continues
   * the discovery loop as appropriate for the configured mode. This handler does not block; it
   * schedules work via the same mechanisms as regular attempts.
   *
   * @param foundEdition payload describing the discovered edition and its metadata; must be
   *     non-null
   */
  @Override
  public void onFoundEdition(USKFoundEdition foundEdition) {
    if (foundEdition.newKnownGood() && !foundEdition.newSlotToo())
      return; // Only interested in slots
    // Because this is frequently run off-thread, it is actually possible that the looked-up edition
    // is different from the edition we are being notified of.
    USKSuccessPlanner.FoundPlan plan =
        prepareFoundPlan(foundEdition.edition(), foundEdition.data(), foundEdition.context());
    if (plan == null) return;
    attempts.finishCancelBefore(plan.killAttempts, foundEdition.context());
    if (plan.registerNow) registerAttempts(foundEdition.context());
    applyFoundDecodedData(
        plan.decode,
        foundEdition.metadata(),
        foundEdition.codec(),
        foundEdition.data(),
        foundEdition.context());
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
  private USKSuccessPlanner.FoundPlan prepareFoundPlan(
      long ed, byte[] data, ClientContext context) {
    final long lastEd = uskManager.lookupLatestSlot(origUSK);
    boolean decode;
    List<USKAttempt> killAttempts = null;
    boolean shouldFillKeysWatching;
    long effectiveEd;
    synchronized (this) {
      if (completed || cancelled) return null;
      decode = lastEd == ed && data != null;
      effectiveEd = Math.max(lastEd, ed);
      if (LOG.isDebugEnabled()) LOG.debug("Latest: {} in onFoundEdition", effectiveEd);

      if (!checkStoreOnly) {
        killAttempts = attempts.cancelBefore(effectiveEd);
        attempts.addNewAttempts(effectiveEd, context, pollingRound.firstLoop());
      }
      shouldFillKeysWatching =
          !schedulingCoordinator.scheduleAfterDBRsDone() || !dbrHintFetches.hasOutstanding();
    }
    boolean registerNow = false;
    if (shouldFillKeysWatching && !isCancelled()) {
      registerNow = !fillKeysWatching(effectiveEd, context);
    }
    return successPlanner.createFoundPlan(decode, registerNow, killAttempts);
  }

  /**
   * Applies decoded data from a found edition into a retained state.
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
    completionCoordinator.applyFoundDecodedData(decode, metadata, codec, data, context);
  }

  private final class StoreCheckCallbacks
      implements USKStoreCheckCoordinator.USKStoreCheckCallbacks {
    @Override
    public void finishSuccess(ClientContext context) {
      USKFetcher.this.finishSuccess(context);
    }

    @Override
    public void notifySendingToNetwork(ClientContext context) {
      USKCallback[] toCheck;
      synchronized (USKFetcher.this) {
        if (cancelled || completed) return;
      }
      toCheck = subscriberRegistry.snapshotSubscribers();
      for (USKCallback cb : toCheck) {
        if (cb instanceof USKProgressCallback callback) callback.onSendingToNetwork(context);
      }
    }

    @Override
    public void processAttemptsAfterStoreCheck(USKAttempt[] attempts, ClientContext context) {
      USKFetcher.this.attempts.processAttemptsAfterStoreCheck(
          new USKAttemptManager.USKAttemptRegistrationParams(
              context, completionCoordinator.hasLastRequestData(), origUSK.suggestedEdition),
          attempts);
    }

    @Override
    public boolean shouldDeferUntilDBRs() {
      return dbrHintFetches.hasOutstanding();
    }

    @Override
    public void setScheduleAfterDBRsDone(boolean value) {
      USKFetcher.this.schedulingCoordinator.setScheduleAfterDBRsDone(value);
    }

    @Override
    public boolean isCancelled() {
      return USKFetcher.this.isCancelled();
    }

    @Override
    public FetchContext fetcherContext() {
      return USKFetcher.this.ctx;
    }

    @Override
    public USKFetcher fetcher() {
      return USKFetcher.this;
    }
  }

  /**
   * Registers all staged attempts with their schedulers.
   *
   * @param context client context used to schedule attempts; must not be null
   */
  private void registerAttempts(ClientContext context) {
    synchronized (this) {
      if (cancelled || completed) return;
    }
    attempts.registerAttempts(
        new USKAttemptManager.USKAttemptRegistrationParams(
            context, completionCoordinator.hasLastRequestData(), origUSK.suggestedEdition));
  }

  @SuppressWarnings("BooleanMethodIsAlwaysInverted")
  private boolean fillKeysWatching(long ed, ClientContext context) {
    return storeChecks.fillKeysWatching(ed, context);
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
   * include keys derived from subscriber hints that are not currently scheduled. The value is a
   * snapshot that may change immediately after return as subscriptions evolve.
   *
   * @return current estimate of watched keys for scheduling heuristics and diagnostics
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
      if (watchingKeys.match(k, lastSlot) != -1) return subscriberRegistry.progressPriority();
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
    return subscriberRegistry.progressPriority();
  }

  @Override
  public boolean isBackgroundPoll() {
    return backgroundPoll;
  }

  @Override
  public short getProgressPollPriority() {
    return getPriorityClass();
  }

  @Override
  public short getNormalPollPriority() {
    return subscriberRegistry.normalPriority();
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
    long lastSlot = uskManager.lookupLatestSlot(origUSK) + 1;
    USKKeyWatchSet.MatchedBlock matched = watchingKeys.matchBlock(key, found, lastSlot);
    if (matched == null) return false;
    onSuccess(null, matched.edition(), false, matched.block(), context);
    return true;
  }

  /**
   * Reports whether this fetcher has no further work to perform.
   *
   * <p>This is used by scheduling infrastructure to decide whether the request should remain
   * registered. It mirrors {@link #isCancelled()} semantics for this fetcher and returns a snapshot
   * of state that may change immediately after return.
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
   * @param key candidate key to evaluate; must be non-null
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
   * polling attempts so they take effect without reconstructing requests. It updates both the
   * normal and no-store contexts, then refreshes the live polling attempts to adopt the change.
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
    attempts.reloadPollParameters();
  }

  /**
   * Adds an edition hint to bias future fetch decisions.
   *
   * <p>Hints greater than the current last-known slot are remembered and may expand the search
   * window. Duplicate or stale hints are ignored. This method does not trigger immediate network
   * activity; it only updates the internal watch list used for later scheduling rounds.
   *
   * @param suggestedEdition edition number to add as a hint; must be greater than the last
   *     looked-up slot to have any effect
   */
  public void addHintEdition(long suggestedEdition) {
    watchingKeys.addHintEdition(suggestedEdition, uskManager.lookupLatestSlot(origUSK));
  }

  /**
   * Resumes the request after a restart.
   *
   * <p>USKFetcher does not persist across restarts; callers should recreate it via the manager
   * instead of resuming. The method exists to satisfy interface requirements and always throws.
   *
   * @param context client context that would be used for resuming; must be non-null
   * @throws UnsupportedOperationException always, because this fetcher is not persistent
   */
  @Override
  public void onResume(ClientContext context) {
    throw new UnsupportedOperationException("Not persistent");
  }

  /**
   * Notifies the fetcher that the node is shutting down.
   *
   * <p>USKFetcher does not persist state, so shutdown handling is not supported. The method exists
   * to satisfy interface requirements and always throws.
   *
   * @param context client context associated with shutdown; must be non-null
   * @throws UnsupportedOperationException always, because this fetcher is not persistent
   */
  @Override
  public void onShutdown(ClientContext context) {
    throw new UnsupportedOperationException("Not persistent");
  }
}
