package network.crypta.client.async;

import static java.util.concurrent.TimeUnit.HOURS;
import static java.util.concurrent.TimeUnit.MINUTES;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.lang.ref.WeakReference;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
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
import network.crypta.client.ClientMetadata;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.crypt.HashResult;
import network.crypta.keys.ClientKey;
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
import network.crypta.node.KeysFetchingLocally;
import network.crypta.node.LowLevelGetException;
import network.crypta.node.RequestClient;
import network.crypta.node.RequestStarter;
import network.crypta.node.SendableGet;
import network.crypta.node.SendableRequestItem;
import network.crypta.support.RemoveRangeArrayList;
import network.crypta.support.api.Bucket;
import network.crypta.support.compress.Compressor;
import network.crypta.support.compress.DecompressorThreadManager;
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
 *   <li>At most one {@code USKFetcher} is active per USK and it registers itself with the {@code
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
  private static final Logger LOG = LoggerFactory.getLogger(USKFetcher.class);
  private static final String FOR_LITERAL = " for ";

  // Static initializer removed as it was empty and unnecessary.

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

  private final boolean checkStoreOnly;

  final ClientRequester parent;

  // We keep the data from the last (highest number) request.
  private Bucket lastRequestData;
  private short lastCompressionCodec;
  private boolean lastWasMetadata;

  /** Structure tracking which keys we want. */
  private final USKWatchingKeys watchingKeys;

  private final ArrayList<USKAttempt> attemptsToStart;

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

  // DBRFetcher removed: use an anonymous SimpleSingleFileFetcher subclass at call site.

  class DBRAttempt implements GetCompletionCallback {
    final SimpleSingleFileFetcher fetcher;
    final USKDateHint.Type type;

    DBRAttempt(ClientKey key, ClientContext context, USKDateHint.Type type) {
      fetcher =
          new SimpleSingleFileFetcher(
              key,
              ctxDBR.maxUSKRetries,
              ctxDBR,
              parent,
              this,
              false,
              true,
              0,
              context,
              false,
              realTimeFlag) {
            @Override
            public short getPriorityClass() {
              return progressPollPriority;
            }

            @Override
            public KeyListener makeKeyListener(ClientContext context, boolean onStartup) {
              synchronized (this) {
                if (finished) return null;
                if (cancelled) return null;
              }
              if (key == null) {
                if (LOG.isErrorEnabled()) {
                  LOG.error(
                      "Key is null - left over BSSF? on {} in makeKeyListener()",
                      this,
                      new Exception("error"));
                }
                return null;
              }
              Key newKey = key.getNodeKey(true);
              short prio = progressPollPriority;
              return new SingleKeyListener(newKey, this, prio, persistent);
            }
          };
      this.type = type;
      if (LOG.isDebugEnabled()) LOG.debug("Created {} with {}", this, fetcher);
    }

    @Override
    public void onSuccess(
        StreamGenerator streamGenerator,
        ClientMetadata clientMetadata,
        List<? extends Compressor> decompressors,
        ClientGetState state,
        ClientContext context) {
      Bucket data = null;
      long maxLen = Math.max(ctx.maxTempLength, ctx.maxOutputLength);
      try {
        data = context.getBucketFactory(false).makeBucket(maxLen);
        try (PipedInputStream pipeIn = new PipedInputStream();
            PipedOutputStream pipeOut = new PipedOutputStream();
            OutputStream output = data.getOutputStream()) {

          if (decompressors != null) {
            if (LOG.isDebugEnabled()) LOG.debug("decompressing...");
            pipeOut.connect(pipeIn);
            DecompressorThreadManager decompressorManager =
                new DecompressorThreadManager(pipeIn, decompressors, maxLen);
            PipedInputStream newPipeIn = decompressorManager.execute();
            ClientGetWorkerThread worker =
                new ClientGetWorkerThread(
                    new BufferedInputStream(newPipeIn),
                    output,
                    null,
                    null,
                    ctx.getSchemeHostAndPort(),
                    null,
                    false,
                    null,
                    null,
                    null,
                    context.linkFilterExceptionProvider);
            worker.start();
            streamGenerator.writeTo(pipeOut, context);
            decompressorManager.waitFinished();
            worker.waitFinished();
            newPipeIn.close();
          } else {
            streamGenerator.writeTo(output, context);
          }
        }

        // Run directly - we are running on some thread somewhere, don't worry about it.
        innerSuccess(data, context);
      } catch (Throwable t) {
        LOG.error("Caught {}", t, t);
        onFailure(new FetchException(FetchExceptionMode.INTERNAL_ERROR, t), state, context);
      } finally {
        boolean dbrsFinished;
        synchronized (USKFetcher.this) {
          dbrAttempts.remove(this);
          if (LOG.isDebugEnabled()) LOG.debug("Remaining DBR attempts: {}", dbrAttempts);
          dbrsFinished = dbrAttempts.isEmpty();
        }
        if (dbrsFinished) onDBRsFinished(context);
        if (data != null) data.free();
      }
    }

    private void innerSuccess(Bucket bucket, ClientContext context) {
      byte[] data;
      try {
        data = BucketTools.toByteArray(bucket);
      } catch (IOException e) {
        LOG.error(
            "Unable to read hint data because of I/O error, maybe bad decompression?: {}", e, e);
        return;
      }
      String line;
      try {
        line = new String(data, StandardCharsets.UTF_8);
      } catch (Exception t) {
        // Something very bad happened, most likely bogus encoding.
        // Ignore it.
        LOG.error("Impossible throwable - maybe bogus encoding?: {}", t, t);
        return;
      }
      String[] split = line.split("\n");
      if (split.length < 3) {
        LOG.error("Unable to parse hint (not enough lines): \"{}\"", line);
        return;
      }
      if (!split[0].startsWith("HINT")) {
        LOG.error("Unable to parse hint (first line doesn't start with HINT): \"{}\"", line);
        return;
      }
      String value = split[1];
      long hint;
      try {
        hint = Long.parseLong(value);
      } catch (NumberFormatException e) {
        LOG.error("Unable to parse hint \"{}\"", value, e);
        return;
      }
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Found DBR hint edition {} for {} for {}",
            hint,
            this.fetcher.getKey(null).getURI(),
            USKFetcher.this);
      processHint(hint, context, this);
    }

    private void processHint(long hint, ClientContext context, DBRAttempt dbrAttempt) {
      try {
        updatePriorities();
        short prio;
        List<DBRAttempt> toCancel = null;
        synchronized (USKFetcher.this) {
          if (cancelled || completed) return;
          dbrHintsFound++;
          prio = progressPollPriority;
          for (Iterator<DBRAttempt> i = dbrAttempts.iterator(); i.hasNext(); ) {
            DBRAttempt a = i.next();
            if (dbrAttempt.type.alwaysMorePreciseThan(a.type)) {
              if (toCancel == null) toCancel = new ArrayList<>();
              toCancel.add(a);
              i.remove();
            }
          }
        }
        uskManager.hintUpdate(origUSK.copy(hint).getURI(), context, prio);
        if (toCancel != null) {
          for (DBRAttempt a : toCancel) a.cancel(context);
        }
      } catch (MalformedURLException e) {
        // Impossible
      }
    }

    @Override
    public void onFailure(FetchException e, ClientGetState state, ClientContext context) {
      // Okay.
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Failed to fetch hint {} for {} for {}", fetcher.getKey(null), this, USKFetcher.this);
      boolean dbrsFinished;
      synchronized (USKFetcher.this) {
        dbrAttempts.remove(this);
        if (LOG.isDebugEnabled()) LOG.debug("Remaining DBR attempts: {}", dbrAttempts);
        dbrsFinished = dbrAttempts.isEmpty();
      }
      if (dbrsFinished) onDBRsFinished(context);
    }

    @Override
    public void onBlockSetFinished(ClientGetState state, ClientContext context) {
      // Ignore
    }

    @Override
    public void onTransition(
        ClientGetState oldState, ClientGetState newState, ClientContext context) {
      // Ignore
    }

    @Override
    public void onExpectedSize(long size, ClientContext context) {
      // Ignore
    }

    @Override
    public void onExpectedMIME(ClientMetadata meta, ClientContext context) {
      // Ignore
    }

    @Override
    public void onFinalizedMetadata() {
      // Ignore
    }

    @Override
    public void onExpectedTopSize(
        long size, long compressed, int blocksReq, int blocksTotal, ClientContext context) {
      // Ignore
    }

    @Override
    public void onSplitfileCompatibilityMode(
        CompatibilityMode min,
        CompatibilityMode max,
        byte[] customSplitfileKey,
        boolean compressed,
        boolean bottomLayer,
        boolean definitiveAnyway,
        ClientContext context) {
      // Ignore
    }

    @Override
    public void onHashes(HashResult[] hashes, ClientContext context) {
      // Ignore
    }

    public void start(ClientContext context) {
      this.fetcher.schedule(context);
    }

    public void cancel(ClientContext context) {
      this.fetcher.cancel(context);
    }
  }

  class USKAttempt implements USKCheckerCallback {
    /** Edition number */
    long number;

    /** Attempt to fetch that edition number (or null if the fetch has finished) */
    USKChecker checker;

    /** Successful fetch? */
    boolean succeeded;

    /** DNF? */
    boolean dnf;

    boolean cancelled;
    final Lookup lookup;
    final boolean forever;
    private boolean everInCooldown;

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

    public void cancel(ClientContext context) {
      cancelled = true;
      USKChecker c;
      synchronized (this) {
        c = checker;
      }
      if (c != null) c.cancel(context);
      onCancelled(context);
    }

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

    public synchronized boolean everInCooldown() {
      return everInCooldown;
    }

    public void reloadPollParameters() {
      USKChecker c;
      synchronized (this) {
        c = checker;
      }
      if (c == null) return;
      c.onChangedFetchContext();
    }
  }

  private final HashSet<DBRAttempt> dbrAttempts = new HashSet<>();
  private final TreeMap<Long, USKAttempt> runningAttempts = new TreeMap<>();
  private final TreeMap<Long, USKAttempt> pollingAttempts = new TreeMap<>();

  private long lastFetchedEdition;

  final long origMinFailures;
  boolean firstLoop;

  static final long ORIG_SLEEP_TIME = MINUTES.toMillis(30);
  static final long MAX_SLEEP_TIME = HOURS.toMillis(24);
  long sleepTime = ORIG_SLEEP_TIME;

  private long valueAtSchedule;

  /** Keep going forever? */
  private final boolean backgroundPoll;

  /** Keep the last fetched data? */
  final boolean keepLastData;

  private boolean started;

  private final boolean realTimeFlag;

  private static final short DEFAULT_NORMAL_POLL_PRIORITY = RequestStarter.PREFETCH_PRIORITY_CLASS;
  private short normalPollPriority = DEFAULT_NORMAL_POLL_PRIORITY;
  private static final short DEFAULT_PROGRESS_POLL_PRIORITY = RequestStarter.UPDATE_PRIORITY_CLASS;
  private short progressPollPriority = DEFAULT_PROGRESS_POLL_PRIORITY;

  private boolean scheduledDBRs;
  private boolean scheduleAfterDBRsDone;

  // Options flags for constructor to reduce parameter count
  static final int OPT_POLL_FOREVER = 1;
  static final int OPT_KEEP_LAST_DATA = 1 << 1;
  static final int OPT_CHECK_STORE_ONLY = 1 << 2;

  // Note: reserved for potential future use.
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
    ctxDBR = ctx.clone();
    if (ctx.followRedirects) {
      this.ctx = ctx.clone();
      this.ctx.followRedirects = false;
    } else {
      this.ctx = ctx;
    }
    ctxDBR.maxOutputLength = 1024;
    ctxDBR.maxTempLength = 32768;
    ctxDBR.filterData = false;
    ctxDBR.maxArchiveLevels = 0;
    ctxDBR.maxArchiveRestarts = 0;
    if (checkStoreOnly) ctxDBR.localRequestOnly = true;
    if (ctx.ignoreStore) {
      ctxNoStore = this.ctx;
    } else {
      ctxNoStore = this.ctx.clone();
      ctxNoStore.ignoreStore = true;
    }
    if (checkStoreOnly && LOG.isDebugEnabled()) LOG.debug("Just checking store on {}", this);
    // origUSK is a hint. We *do* want to check the edition given.
    // Whereas latestSlot we've definitely fetched, we don't want to re-check.
    watchingKeys =
        new USKWatchingKeys(origUSK, Math.max(0, uskManager.lookupLatestSlot(origUSK) + 1));
    attemptsToStart = new ArrayList<>();
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

  private int dbrHintsFound = 0;
  private int dbrHintsStarted = 0;

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

  private static final class PollingResolution {
    final boolean ready;
    final USKAttempt[] attempts;

    PollingResolution(boolean ready, USKAttempt[] attempts) {
      this.ready = ready;
      this.attempts = attempts;
    }
  }

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
      if (!dbrAttempts.isEmpty()) {
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Not finished because still waiting for DBR attempts on {} : {}", this, dbrAttempts);
        return new PollingResolution(false, new USKAttempt[0]); // DBRs
      }
      return new PollingResolution(true, pollingAttempts.values().toArray(new USKAttempt[0]));
    }
  }

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

  // moved into StoreCheckerGetter to satisfy S3398

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

  private void finishSuccess(ClientContext context) {
    if (LOG.isDebugEnabled()) LOG.debug("finishSuccess() on {}", this);
    if (backgroundPoll) {
      rescheduleBackgroundPoll(context);
    } else {
      completeCallbacks(context);
    }
  }

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

  void onSuccess(
      USKAttempt att, boolean dontUpdate, ClientSSKBlock block, final ClientContext context) {
    onSuccess(att, att.number, dontUpdate, block, context);
  }

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
    if (plan == null) return; // finished or cancelled

    finishCancelBefore(plan.killAttempts, context);

    Bucket data = decodeBlockIfNeeded(plan.decode, block, context);

    applyDecodedData(plan.decode, block, data);

    if (!dontUpdate) uskManager.updateSlot(origUSK, plan.curLatest, context);
    if (plan.registerNow) registerAttempts(context);
  }

  private Bucket decodeBlockIfNeeded(boolean decode, ClientSSKBlock block, ClientContext context) {
    if (!decode || block == null) return null;
    try {
      return block.decode(
          context.getBucketFactory(parent.persistent()), 1025 /* it's an SSK */, true);
    } catch (KeyDecodeException e) {
      return null;
    } catch (IOException e) {
      LOG.error("An IOE occured while decoding: {}", e.getMessage(), e);
      return null;
    }
  }

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
      if ((!scheduleAfterDBRsDone) || dbrAttempts.isEmpty())
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

  private static boolean shouldDecode(
      long curLatest, long lastEd, boolean dontUpdate, ClientSSKBlock block) {
    return curLatest >= lastEd && !(dontUpdate && block == null);
  }

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

  private static final class SuccessPlan {
    boolean decode;
    long curLatest;
    boolean registerNow;
    List<USKAttempt> killAttempts;
  }

  private boolean shouldAddRandomEditions(Random random) {
    if (firstLoop) return false;
    return random.nextInt(dbrHintsStarted + 1) >= dbrHintsFound;
  }

  void onCancelled(USKAttempt att, ClientContext context) {
    synchronized (this) {
      runningAttempts.remove(att.number);
      if (!runningAttempts.isEmpty()) return;

      if (cancelled) finishCancelled(context);
    }
  }

  private void finishCancelled(ClientContext context) {
    USKFetcherCallback[] cb;
    synchronized (this) {
      completed = true;
      cb = callbacks.toArray(new USKFetcherCallback[0]);
    }
    for (USKFetcherCallback c : cb) c.onCancelled(context);
  }

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

  private void finishCancelBefore(List<USKAttempt> v, ClientContext context) {
    if (v != null) {
      for (USKAttempt att : v) {
        att.cancel(context);
      }
    }
  }

  /** Add a USKAttempt for another edition number. Caller is responsible for calling .schedule(). */
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
   * @return an immutable URI identifying the USK being fetched; callers must not modify the
   *     returned object
   */
  public FreenetURI getURI() {
    return origUSK.getURI();
  }

  /**
   * Reports whether this fetcher has reached a terminal state.
   *
   * <p>Returns {@code true} once the fetcher has been cancelled or completed. After that point it
   * no longer schedules work, though background pollers may be re-armed by {@link
   * #schedule(ClientContext)} if applicable.
   *
   * @return {@code true} if cancelled or completed; otherwise {@code false}
   */
  public boolean isFinished() {
    synchronized (this) {
      return completed || cancelled;
    }
  }

  /**
   * Returns the original {@link USK} descriptor associated with this fetcher.
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
   * from that context.
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
   * checks. If the fetcher has already finished or has been cancelled, the method returns without
   * scheduling new work. Repeated calls are safe; they re-apply the current dynamic priorities and
   * ensure registration is in place.
   *
   * @param context client context that provides schedulers, timing, and factories required to run
   *     the discovery loop; must not be {@code null}
   */
  @Override
  public void schedule(ClientContext context) {
    if (LOG.isDebugEnabled()) LOG.debug("Scheduling {}", this);
    if (shouldAbortSchedule()) return;
    DBRAttempt[] atts = maybeAddDBRs(context);
    context.getSskFetchScheduler(realTimeFlag).schedTransient.addPendingKeys(this);
    updatePriorities();
    uskManager.subscribe(origUSK, this, false, parent.getClient());
    if (atts != null) startDBRs(atts, context);
    long lookedUp = uskManager.lookupLatestSlot(origUSK);
    SchedulePlan plan = buildSchedulePlan(lookedUp, atts, context);
    if (plan.registerNow) registerAttempts(context);
    else if (plan.completeCheckingStore) {
      this.finishSuccess(context);
      return;
    }
    if (!plan.bye) return;
    // We have been cancelled.
    uskManager.unsubscribe(origUSK, this);
    context.getSskFetchScheduler(realTimeFlag).schedTransient.removePendingKeys((KeyListener) this);
    uskManager.onFinished(this, true);
  }

  private boolean shouldAbortSchedule() {
    synchronized (this) {
      return cancelled || completed;
    }
  }

  private DBRAttempt[] maybeAddDBRs(ClientContext context) {
    DBRAttempt[] atts = null;
    synchronized (this) {
      if (!scheduledDBRs && !ctx.ignoreUSKDatehints) {
        atts = addDBRs(context);
      }
      scheduledDBRs = true;
    }
    return atts;
  }

  private SchedulePlan buildSchedulePlan(long lookedUp, DBRAttempt[] atts, ClientContext context) {
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
        if (lookedUp <= 0 && atts != null) {
          // If we don't know anything, do the DBRs first.
          scheduleAfterDBRsDone = true;
        } else if ((!scheduleAfterDBRsDone) || dbrAttempts.isEmpty()) {
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

  private static final class SchedulePlan {
    boolean registerNow;
    boolean bye;
    boolean completeCheckingStore;
  }

  /** Call synchronized, then call startDBRs() */
  private DBRAttempt[] addDBRs(ClientContext context) {
    USKDateHint date = USKDateHint.now();
    ClientSSK[] ssks = date.getRequestURIs(this.origUSK);
    DBRAttempt[] atts = new DBRAttempt[ssks.length];
    int x = 0;
    for (int i = 0; i < ssks.length; i++) {
      ClientKey key = ssks[i];
      DBRAttempt att = new DBRAttempt(key, context, USKDateHint.Type.values()[i]);
      this.dbrAttempts.add(att);
      atts[x++] = att;
    }
    dbrHintsStarted = atts.length;
    return atts;
  }

  private void startDBRs(DBRAttempt[] toStart, ClientContext context) {
    for (DBRAttempt att : toStart) att.start(context);
  }

  /**
   * Cancels this fetcher and releases scheduler registrations.
   *
   * <p>After cancellation the fetcher stops scheduling any further datastore checks, DBR hint
   * fetches, or edition probes, and it unsubscribes from the {@link USKManager}. In-flight attempts
   * are cancelled when possible and subsequent calls that would otherwise schedule work become
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
    DBRAttempt[] atts;
    uskManager.onFinished(this);
    SendableGet storeChecker;
    Bucket data;
    synchronized (this) {
      if (cancelled) LOG.error("Already cancelled {}", this);
      if (completed) LOG.error("Already completed {}", this);
      cancelled = true;
      attempts = runningAttempts.values().toArray(new USKAttempt[0]);
      polling = pollingAttempts.values().toArray(new USKAttempt[0]);
      atts = dbrAttempts.toArray(new DBRAttempt[0]);
      attemptsToStart.clear();
      runningAttempts.clear();
      pollingAttempts.clear();
      dbrAttempts.clear();
      storeChecker = runningStoreChecker;
      runningStoreChecker = null;
      data = lastRequestData;
      lastRequestData = null;
    }
    for (USKAttempt attempt : attempts) attempt.cancel(context);
    for (USKAttempt p : polling) p.cancel(context);
    for (DBRAttempt a : atts) a.cancel(context);
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

  private void updatePriorities() {
    Prio prio = initialPrio();
    USKCallback[] localCallbacks;
    USKFetcherCallback[] fetcherCallbacks;
    synchronized (this) {
      localCallbacks = subscribers.toArray(new USKCallback[0]);
      // Callbacks also determine the fetcher's priority.
      // Otherwise USKFetcherTag would have no way to tell us the priority we should run at.
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

  private static final class Prio {
    short normal;
    short progress;
  }

  private static Prio initialPrio() {
    Prio p = new Prio();
    p.normal = RequestStarter.PAUSED_PRIORITY_CLASS;
    p.progress = RequestStarter.PAUSED_PRIORITY_CLASS;
    return p;
  }

  private static boolean noCallbacks(
      USKCallback[] localCallbacks, USKFetcherCallback[] fetcherCallbacks) {
    return localCallbacks.length == 0 && fetcherCallbacks.length == 0;
  }

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
   * @return {@code true} when one or more subscribers are present; {@code false} when none remain
   */
  public synchronized boolean hasSubscribers() {
    return !subscribers.isEmpty();
  }

  /**
   * Returns whether any fetcher-level callbacks are registered.
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
   * the datastore. Removing a non-existent subscriber has no effect.
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
   * <p>After removal, the callback will no longer receive notifications from this fetch cycle. It
   * also stops contributing to dynamic priority calculations.
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
   * registered key listeners and callbacks to observe progress.
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
   * called by production code and will throw an exception if invoked.
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
   * be called by production code and will throw an exception if invoked.
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
      if ((!scheduleAfterDBRsDone) || dbrAttempts.isEmpty())
        registerNow = !fillKeysWatching(ed, context);
      else registerNow = false;
    }
    FoundPlan plan = new FoundPlan();
    plan.decode = decode;
    plan.killAttempts = killAttempts;
    plan.registerNow = registerNow;
    return plan;
  }

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

  private static final class FoundPlan {
    boolean decode;
    List<USKAttempt> killAttempts;
    boolean registerNow;
  }

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

  private StoreCheckerGetter runningStoreChecker = null;

  class USKStoreChecker {

    final USKWatchingKeys.KeyList.StoreSubChecker[] checkers;

    public USKStoreChecker(List<USKWatchingKeys.KeyList.StoreSubChecker> c) {
      checkers = c.toArray(new USKWatchingKeys.KeyList.StoreSubChecker[0]);
    }

    @SuppressWarnings("unused")
    public USKStoreChecker(USKWatchingKeys.KeyList.StoreSubChecker[] checkers2) {
      checkers = checkers2;
    }

    public Key[] getKeys() {
      if (checkers.length == 0) return new Key[0];
      if (checkers.length == 1) return checkers[0].keysToCheck;
      return mergeKeysFromCheckers();
    }

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

    public void checked() {
      for (USKWatchingKeys.KeyList.StoreSubChecker checker : checkers) {
        checker.checked();
      }
    }
  }

  @SuppressWarnings("BooleanMethodIsAlwaysInverted")
  private boolean fillKeysWatching(long ed, ClientContext context) {
    synchronized (this) {
      // Do not run a new one until this one has finished.
      // StoreCheckerGetter itself will automatically call back to fillKeysWatching so there is no
      // chance of losing it.
      if (runningStoreChecker != null) return true;
      final USKStoreChecker checker = watchingKeys.getDatastoreChecker(ed);
      if (checker == null) {
        if (LOG.isDebugEnabled()) LOG.debug("No datastore checker");
        return false;
      }

      runningStoreChecker = new StoreCheckerGetter(parent, checker);
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
      } catch (Exception ignored) {
        // Ignore, hopefully it's already unregistered
      }
    }
    if (LOG.isDebugEnabled()) LOG.debug("Registered {} for {}", runningStoreChecker, this);
    return true;
  }

  class StoreCheckerGetter extends SendableGet {

    public StoreCheckerGetter(ClientRequester parent, USKStoreChecker c) {
      super(parent, USKFetcher.this.realTimeFlag);
      checker = c;
    }

    public final transient USKStoreChecker checker;

    boolean done = false;

    @Override
    public FetchContext getContext() {
      return ctx;
    }

    @Override
    public long getCooldownWakeup(SendableRequestItem token, ClientContext context) {
      return -1;
    }

    @Override
    public ClientKey getKey(SendableRequestItem token) {
      return null;
    }

    @Override
    public Key[] listKeys() {
      return checker.getKeys();
    }

    @Override
    public void onFailure(
        LowLevelGetException e, SendableRequestItem token, ClientContext context) {
      // Ignore
    }

    @Override
    @SuppressWarnings("java:S3516")
    public boolean preRegister(ClientContext context, boolean toNetwork) {
      if (USKFetcher.this.cancelled || USKFetcher.this.completed) {
        unregister(context, getPriorityClass());
        synchronized (USKFetcher.this) {
          runningStoreChecker = null;
        }
        done = true;
        if (LOG.isDebugEnabled())
          LOG.debug("StoreChecker preRegister aborted: fetcher cancelled/completed");
        return toNetwork; // cancel network send when scheduler planned to send
        // value ignored by scheduler when toNetwork == false
      }
      unregister(context, getPriorityClass());
      USKAttempt[] attempts = captureAttemptsToStart();
      checker.checked();

      logStoreChecked(attempts.length);
      notifyNetworkIfNeeded(attempts, context);
      processAttemptsAfterStoreCheck(attempts, context);

      long lastEd = uskManager.lookupLatestSlot(origUSK);
      if (!fillKeysWatching(lastEd, context) && checkStoreOnly) {
        if (LOG.isDebugEnabled())
          LOG.debug("Just checking store, terminating {} ...", USKFetcher.this);
        if (shouldDeferUntilDBRs()) {
          USKFetcher.this.scheduleAfterDBRsDone = true;
        } else {
          finishSuccess(context);
        }
      }
      return toNetwork; // Store checker never sends network requests itself
      // Value is ignored when toNetwork == false
    }

    private USKAttempt[] captureAttemptsToStart() {
      synchronized (USKFetcher.this) {
        runningStoreChecker = null;
        // Note: optionally start USKAttempts only when datastore check shows no progress.
        USKAttempt[] attempts = attemptsToStart.toArray(new USKAttempt[0]);
        attemptsToStart.clear();
        done = true;
        if (cancelled) return new USKAttempt[0];
        return attempts;
      }
    }

    private void logStoreChecked(int attemptsCount) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Checked datastore, finishing registration for {} checkers for {} for {}",
            attemptsCount,
            USKFetcher.this,
            origUSK);
    }

    private void notifyNetworkIfNeeded(USKAttempt[] attempts, ClientContext context) {
      if (attempts.length > 0) {
        parent.toNetwork(context);
        notifySendingToNetwork(context);
      }
    }

    private void processAttemptsAfterStoreCheck(USKAttempt[] attempts, ClientContext context) {
      for (USKAttempt attempt : attempts) {
        long lastEd = uskManager.lookupLatestSlot(origUSK);
        synchronized (USKFetcher.this) {
          // Note: condition may need verification.
          if (keepLastData && lastRequestData == null && lastEd == origUSK.suggestedEdition)
            lastEd--; // If we want the data, then get it for the known edition, so we always get
          // the data, so USKInserter can compare it and return the old edition if it is
          // identical.
        }
        if (attempt == null) continue;
        if (attempt.number > lastEd) attempt.schedule(context);
        else {
          synchronized (USKFetcher.this) {
            runningAttempts.remove(attempt.number);
            pollingAttempts.remove(attempt.number);
          }
        }
      }
    }

    private void notifySendingToNetwork(ClientContext context) {
      USKCallback[] toCheck;
      synchronized (USKFetcher.this) {
        if (cancelled || completed) return;
        toCheck = subscribers.toArray(new USKCallback[0]);
      }
      for (USKCallback cb : toCheck) {
        if (cb instanceof USKProgressCallback callback) callback.onSendingToNetwork(context);
      }
    }

    private boolean shouldDeferUntilDBRs() {
      synchronized (this) {
        return !dbrAttempts.isEmpty();
      }
    }

    @Override
    public SendableRequestItem chooseKey(KeysFetchingLocally keys, ClientContext context) {
      return null;
    }

    @Override
    public long countAllKeys(ClientContext context) {
      return watchingKeys.size();
    }

    @Override
    public long countSendableKeys(ClientContext context) {
      return 0;
    }

    @Override
    public RequestClient getClient() {
      return realTimeFlag ? USKManager.rcRT : USKManager.rcBulk;
    }

    @Override
    public ClientRequester getClientRequest() {
      return parent;
    }

    @Override
    public short getPriorityClass() {
      return progressPollPriority; // Use progress polling priority
    }

    @Override
    public boolean isCancelled() {
      return done || USKFetcher.this.cancelled || USKFetcher.this.completed;
    }

    @Override
    public boolean isSSK() {
      return true;
    }

    @Override
    public long getWakeupTime(ClientContext context, long now) {
      return 0;
    }

    @Override
    protected ClientGetState getClientGetState() {
      return USKFetcher.this;
    }
  }

  @Override
  public synchronized boolean isCancelled() {
    return completed || cancelled;
  }

  @Override
  public KeyListener makeKeyListener(ClientContext context, boolean onStartup) {
    return this;
  }

  @Override
  public synchronized long countKeys() {
    return watchingKeys.size();
  }

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

  @Override
  public HasKeyListener getHasKeyListener() {
    return this;
  }

  @Override
  public short getPriorityClass() {
    return progressPollPriority;
  }

  @Override
  public SendableGet[] getRequestsForKey(Key key, byte[] saltedKey, ClientContext context) {
    return new SendableGet[0];
  }

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
    } catch (SSKVerifyException e) {
      data = null;
    }
    onSuccess(null, edition, false, data, context);
    return true;
  }

  @Override
  public synchronized boolean isEmpty() {
    return cancelled || completed;
  }

  @Override
  public boolean isSSK() {
    return true;
  }

  @Override
  public void onRemove() {
    // Ignore
  }

  @Override
  public boolean persistent() {
    return false;
  }

  @Override
  public byte[] getWantedKey() {
    return origUSK.getPubKeyHash();
  }

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
   * <p>See: https://bugs.freenetproject.org/view.php?id=4984
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
   * <p>LOCKING: Take the lock on this class last and always pass in lookup values. Do not lookup
   * values in USKManager inside this class's lock.
   *
   * @author Matthew Toseland <toad@amphibian.dyndns.org> (0xE43DA450)
   */
  private class USKWatchingKeys {

    // Common for whole USK
    final byte[] pubKeyHash;
    final byte cryptoAlgorithm;

    // List of slots since the USKManager's current last known good edition.
    private final KeyList fromLastKnownSlot;
    private final TreeMap<Long, KeyList> fromSubscribers;
    private final TreeSet<Long> persistentHints = new TreeSet<>();

    // Note: consider additional WeakReference<KeyList> instances: one for the origUSK and
    // one per subscriber-provided edition. These should be cleared when the subscriber goes away
    // or when superseded by the last known edition.

    public USKWatchingKeys(USK origUSK, long lookedUp) {
      this.pubKeyHash = origUSK.getPubKeyHash();
      this.cryptoAlgorithm = origUSK.cryptoAlgorithm;
      if (LOG.isDebugEnabled()) LOG.debug("Creating KeyList from last known good: {}", lookedUp);
      fromLastKnownSlot = new KeyList(lookedUp);
      fromSubscribers = new TreeMap<>();
      if (origUSK.suggestedEdition > lookedUp)
        fromSubscribers.put(origUSK.suggestedEdition, new KeyList(origUSK.suggestedEdition));
    }

    class ToFetch {

      public ToFetch(List<Lookup> toFetch2, List<Lookup> toPoll2) {
        fetch = toFetch2.toArray(new Lookup[0]);
        poll = toPoll2.toArray(new Lookup[0]);
      }

      public final Lookup[] fetch;
      public final Lookup[] poll;
    }

    /**
     * Get a bunch of editions to probe for.
     *
     * @param lookedUp The current best known slot, from USKManager.
     * @param random The random number generator.
     * @param alreadyRunning This will be modified: We will remove anything that should still be
     *     running from it.
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

    private static int countRunningRandom(
        List<Lookup> alreadyRunning, List<Lookup> toFetch, List<Lookup> toPoll) {
      int runningRandom = 0;
      for (Lookup l : alreadyRunning) {
        if (toFetch.contains(l) || toPoll.contains(l)) continue;
        runningRandom++;
      }
      return runningRandom;
    }

    public synchronized void updateSubscriberHints(Long[] hints, long lookedUp) {
      List<Long> surviving = collectSurvivingHints(hints, lookedUp);
      mergePersistentHints(surviving, lookedUp);
      ensureSuggestedEditionIncluded(surviving, lookedUp);
      reconcileSubscribersWithSurviving(surviving);
    }

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

    private void ensureSuggestedEditionIncluded(List<Long> surviving, long lookedUp) {
      if (origUSK.suggestedEdition > lookedUp && !surviving.contains(origUSK.suggestedEdition))
        surviving.add(origUSK.suggestedEdition);
    }

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

    public synchronized void addHintEdition(long suggestedEdition, long lookedUp) {
      if (suggestedEdition <= lookedUp) return;
      if (!persistentHints.add(suggestedEdition)) return;
      if (fromSubscribers.containsKey(suggestedEdition)) return;
      fromSubscribers.put(suggestedEdition, new KeyList(suggestedEdition));
    }

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
       * Add the next bunch of editions to fetch to toFetch and toPoll. If they are already running,
       * REMOVE THEM from the alreadyRunning array.
       *
       * @param toFetch
       * @param toPoll
       * @param lookedUp
       * @param alreadyRunning
       * @param random
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
       * @return whether the edition was added.
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

      private static double uniform01FromLong(Random random) {
        long bits = random.nextLong() & Long.MAX_VALUE; // 0 .. 2^63-1
        return (bits + 1.0) / (Long.MAX_VALUE + 1.0);
      }

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

      public class StoreSubChecker {

        /** Keys to check */
        final NodeSSK[] keysToCheck;

        /** The edition from which we will have checked after we have executed this. */
        private final long checkedFrom;

        /** The edition up to which we have checked after we have executed this. */
        private final long checkedTo;

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
       * Check for WATCH_KEYS from lastSlot, but do not check any slots earlier than
       * checkedDatastoreUpTo. Re-use the cache if possible, and extend it if necessary; all we need
       * to construct a NodeSSK is the base data and the E(H(docname)), and we have that.
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
       * Update the key list if necessary based on the new base edition. Then try to match the given
       * key. If it matches return the edition number.
       *
       * @param key The key we are trying to match. If null, just update the cache, do not do any
       *     matching (used by checkStore(); it is only necessary to update the cache if you are
       *     actually going to use it).
       * @param curBaseEdition The new base edition.
       * @return The edition number for the key, or -1 if the key is not a match.
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
       * Update ehDocnames as needed according to the new curBaseEdition, then innerMatch against
       * *only the changed parts*. The caller must already have done innerMatch over the passed in
       * ehDocnames.
       *
       * @param curBaseEdition The edition to check from. If this is different to firstSlot, we will
       *     update ehDocnames.
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
       * Do the actual match, using the current firstSlot, and a specified offset and length within
       * the array.
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
       * Append a series of E(H(docname))'s to the array.
       *
       * @param baseEdition The edition to start from.
       * @param keys The number of keys to add.
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

    public ClientSSKBlock decode(SSKBlock block, long edition) throws SSKVerifyException {
      ClientSSK csk = origUSK.getSSK(edition);
      if (!Arrays.equals(csk.ehDocname, block.getKey().getKeyBytes())) {
        throw new SSKVerifyException("Docname hash mismatch for decoded block");
      }
      return ClientSSKBlock.construct(block, csk);
    }

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
   * window. Duplicate or stale hints are ignored.
   *
   * @param suggestedEdition the edition number to add as a hint; must be greater than the last
   *     looked-up slot to have any effect
   */
  public void addHintEdition(long suggestedEdition) {
    watchingKeys.addHintEdition(suggestedEdition, uskManager.lookupLatestSlot(origUSK));
  }

  private class Lookup {
    long val;
    ClientSSK key;
    boolean ignoreStore;

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

  @Override
  public void onResume(ClientContext context) {
    throw new UnsupportedOperationException("Not persistent");
  }

  @Override
  public void onShutdown(ClientContext context) {
    throw new UnsupportedOperationException("Not persistent");
  }
}
