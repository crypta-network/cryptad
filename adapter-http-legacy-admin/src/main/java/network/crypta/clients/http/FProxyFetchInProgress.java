package network.crypta.clients.http;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import network.crypta.client.ClientMetadata;
import network.crypta.client.DefaultMIMETypes;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchException;
import network.crypta.client.FetchResult;
import network.crypta.client.async.CacheFetchResult;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientGetCallback;
import network.crypta.client.async.ClientGetter;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.client.events.ClientEvent;
import network.crypta.client.events.ClientEventDispatchContext;
import network.crypta.client.events.ClientEventListener;
import network.crypta.client.events.ExpectedFileSizeEvent;
import network.crypta.client.events.ExpectedMIMEEvent;
import network.crypta.client.events.SendingToNetworkEvent;
import network.crypta.client.events.SplitfileProgressEvent;
import network.crypta.client.filter.ContentFilter;
import network.crypta.client.filter.ContentFilterCallbacks;
import network.crypta.client.filter.ContentFilterRequest;
import network.crypta.client.filter.FilterMIMEType;
import network.crypta.client.filter.UnknownContentTypeException;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.USK;
import network.crypta.node.RequestClient;
import network.crypta.support.api.Bucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.util.concurrent.TimeUnit.SECONDS;

/**
 * Tracks a single FProxy browser fetch from creation until completion or cancellation.
 *
 * <p>This holder coordinates the shared state between the asynchronous {@link ClientGetter} running
 * inside the client layer and the lightweight waiter objects used by the HTTP toadlet. It owns the
 * request lifecycle, forwards network and splitfile events to listeners, and exposes progress
 * snapshots that are rendered into FProxy status pages. Typical callers get a waiter via {@link
 * #getWaiter()}, start the fetch with {@link #start(ClientContext)}, and poll {@link
 * #innerGetResult(boolean)} from the waiter thread until either data or an error arrives.
 *
 * <p>The instance is stateful but confines mutation to synchronized blocks so multiple browser
 * requests can watch the same download safely. After creation the object stays valid for roughly
 * thirty seconds after last access unless {@link #requestImmediateCancel()} is invoked. The class
 * prefers cached data when safe, falls back to live network retrieval otherwise, and optionally
 * re-filters cached content according to the chosen {@link REFILTER_POLICY}.
 *
 * <ul>
 *   <li>Responsibilities: manage a single URI fetch, collect progress, and dispatch listener
 *       events.
 *   <li>Concurrency: the instance monitor guards all externally visible state; callbacks may arrive
 *       from worker threads.
 *   <li>Lifecycle: constructed with immutable fetch parameters, started once, and then either
 *       finishes, fails, or is canceled by the tracker.
 * </ul>
 *
 * <p>LOCKING: The lock on this object is always taken last.
 */
public class FProxyFetchInProgress implements ClientEventListener, ClientGetCallback {
  private static final Logger LOG = LoggerFactory.getLogger(FProxyFetchInProgress.class);

  /**
   * What to do when we find data which matches the request, but it has already been filtered,
   * assuming we want a filtered copy.
   */
  public enum REFILTER_POLICY {
    /**
     * Re-run the content filter even when cached data was already filtered, usually forcing a new
     * temporary bucket allocation to rebuild output with current rules.
     */
    RE_FILTER,
    /**
     * Reuse the previously filtered bytes without reprocessing; correctness depends on the filter
     * version that produced the cached object and may skip newer safety fixes.
     */
    ACCEPT_OLD,
    /**
     * Discard any cached representation and perform a fresh fetch from the network to avoid stale
     * filter artifacts at the cost of extra latency and bandwidth.
     */
    RE_FETCH
  }

  private final REFILTER_POLICY refilterPolicy;

  // Legacy logMINOR removed; use LOG.isDebugEnabled() instead.

  /**
   * The Freenet URI being requested; immutable for the lifetime of this tracker and used as the
   * cache key and progress label when rendering status pages. Contains any edition data for USKs
   * and is never modified in-place.
   */
  public final FreenetURI uri;

  /**
   * Upper bound in bytes that the client is willing to accept for this fetch; enforced both on
   * network retrieval and on cache reuse decisions to avoid returning oversized responses to the
   * browser.
   */
  public final long maxSize;

  /** Fetcher */
  private final ClientGetter getter;

  /**
   * Any request that is waiting for a progress screen or data. We may want to wake requests
   * separately in the future.
   */
  private final ArrayList<FProxyFetchWaiter> waiters;

  private final ArrayList<FProxyFetchResult> results;

  /** Gets notified with every change */
  private final List<FProxyFetchListener> listener =
      Collections.synchronizedList(new ArrayList<>());

  /** The data, if we have it */
  private Bucket data;

  /** Creation time */
  private final long timeStarted;

  /** Finished? */
  private boolean finished;

  /** Size, if known */
  private long size;

  /** MIME type, if known */
  private String mimeType;

  /** Gone to network? */
  private volatile boolean goneToNetwork;

  /** Total blocks */
  private int totalBlocks;

  /** Required blocks */
  private int requiredBlocks;

  /** Fetched blocks */
  private int fetchedBlocks;

  /** Failed blocks */
  private int failedBlocks;

  /** Fatally failed blocks */
  private int fatallyFailedBlocks;

  private int fetchedBlocksPreNetwork;

  /** Finalized the block set? */
  private boolean finalizedBlocks;

  /** Fetch failed */
  private FetchException failed;

  private boolean hasWaited;
  private boolean hasNotifiedFailure;

  /** Last time the fetch was accessed from the fproxy end */
  private long lastTouched;

  final FProxyFetchTracker tracker;

  /**
   * Show even non-fatal failures for 5 seconds. Necessary for JavaScript to work, because it
   * fetches the page and then reloads it if it isn't a progress update.
   */
  private long timeFailed;

  /** If this is set, then it can be removed instantly, doesn't need to wait for 30sec */
  private boolean requestImmediateCancel = false;

  private int fetched = 0;

  /** Stores the fetch context this class was created with */
  private final FetchContext fctx;

  private boolean cancelled = false;
  private final RequestClient rc;

  private final long identifier;
  private final ClientContext initialContext;

  /**
   * Constructs a new in-progress fetch wrapper bound to a single URI and tracker entry.
   *
   * <p>The constructor copies key elements from the supplied {@link FetchContext}, wires up event
   * listeners, and prepares a {@link ClientGetter} with the configured filtering preference. It
   * does not start network activity; callers must invoke {@link #start(ClientContext)} after adding
   * any waiters or listeners.
   *
   * @param tracker the owning tracker that manages cancellation and lifecycle for this fetch
   * @param criteria immutable request criteria containing URI, size limit, and fetch context
   * @param identifier monotonically increasing identifier used for UI correlation and logs
   * @param context initial client context providing caches and factories for the fetch
   * @param rc request client identity used for network scheduling and throttling
   * @param refilter policy describing how cached filtered data should be reused or refreshed
   */
  public FProxyFetchInProgress(
      FProxyFetchTracker tracker,
      FProxyFetchCriteria criteria,
      long identifier,
      ClientContext context,
      RequestClient rc,
      REFILTER_POLICY refilter) {
    this.identifier = identifier;
    this.initialContext = context;
    this.refilterPolicy = refilter;
    this.tracker = tracker;
    this.uri = criteria.key();
    this.maxSize = criteria.maxSize();
    this.timeStarted = System.currentTimeMillis();
    this.fctx = criteria.fetchContext();
    this.rc = rc;
    FetchContext alteredFctx = new FetchContext(fctx, FetchContext.IDENTICAL_MASK);
    alteredFctx.setMaxOutputLength(maxSize);
    fctx.setMaxTempLength(maxSize);
    alteredFctx.getEventProducer().addEventListener(this);
    waiters = new ArrayList<>();
    results = new ArrayList<>();
    getter = new ClientGetter(this, uri, alteredFctx, FProxyToadlet.PRIORITY, null, null, null);
  }

  /**
   * Creates and registers a waiter that can poll this fetch from the FProxy thread.
   *
   * <p>The waiter holds a snapshot pointer into the current fetch state and will be awakened when
   * progress changes or the fetch completes. Multiple waiters can be created for the same fetch to
   * service concurrent browser requests.
   *
   * @return a newly created waiter bound to this fetch and tracked for cleanup
   */
  public synchronized FProxyFetchWaiter getWaiter() {
    lastTouched = System.currentTimeMillis();
    FProxyFetchWaiter waiter = new FProxyFetchWaiter(this);
    waiters.add(waiter);
    return waiter;
  }

  /**
   * Returns the tracker that owns this fetch instance for lifecycle management and cancellation.
   *
   * <p>The tracker mediates deduplication across concurrent browser requests, queues cancellation
   * when idle, and exposes context needed for {@link ClientGetter#cancel(ClientContext)}. Keeping a
   * reference allows callers to navigate back to the controlling structure without holding
   * additional state.
   *
   * @return tracker coordinating cancel queues and fetch deduplication for this object
   */
  public FProxyFetchTracker getTracker() {
    return tracker;
  }

  /**
   * Adds an externally created waiter to the tracking list so it participates in wake-ups.
   *
   * <p>This is useful for custom integration tests or alternate UI paths that want to supply their
   * own waiter instance rather than calling {@link #getWaiter()}. The waiter is treated identically
   * to internally created ones and will be awakened on state changes.
   *
   * @param waiter waiter instance already constructed for this fetch; must not be null
   */
  @SuppressWarnings("unused")
  public synchronized void addCustomWaiter(FProxyFetchWaiter waiter) {
    waiters.add(waiter);
  }

  synchronized FProxyFetchResult innerGetResult(boolean hasWaited) {
    lastTouched = System.currentTimeMillis();
    FProxyFetchSnapshotInfo info =
        new FProxyFetchSnapshotInfo(mimeType, timeStarted, goneToNetwork, getETA(), hasWaited);
    FProxyFetchResult res;
    if (data != null) {
      res = new FProxyFetchResult(this, data, info);
    } else {
      FProxyFetchProgressCounts counts =
          new FProxyFetchProgressCounts(
              totalBlocks,
              requiredBlocks,
              fetchedBlocks,
              failedBlocks,
              fatallyFailedBlocks,
              finalizedBlocks);
      res = new FProxyFetchResult(this, info, size, counts, failed);
    }
    results.add(res);
    if (data != null || failed != null) {
      res.setFetchCount(fetched);
      fetched++;
    }
    return res;
  }

  /**
   * Begins the fetch by consulting caches and, if necessary, scheduling network retrieval.
   *
   * <p>The method is idempotent for a given instance: it will only trigger the underlying {@link
   * ClientGetter} once, and later calls simply reflect the first result. Cache hits may immediately
   * complete the fetch and notify listeners. Checked exceptions indicate startup failures such as
   * malformed URIs or context misconfiguration and leave the instance marked as failed.
   *
   * @param context client context supplying caches, temp bucket factories, and scheduler access
   * @throws FetchException if initial validation or network scheduling fails before fetching starts
   */
  public void start(ClientContext context) throws FetchException {
    try {
      if (!checkCache(context)) context.start(getter);
    } catch (FetchException e) {
      synchronized (this) {
        this.failed = e;
        this.finished = true;
      }
    } catch (PersistenceDisabledException e) {
      // Impossible
      LOG.error("Failed to start: {}", e.toString());
      synchronized (this) {
        this.failed = new FetchException(FetchExceptionMode.INTERNAL_ERROR, e);
        this.finished = true;
      }
    }
  }

  /**
   * Look up the key in the Downloads queue.
   *
   * @return True if it was found, and we don't need to start the request.
   */
  private boolean checkCache(ClientContext context) {
    // Fproxy uses lookupInstant() with mustCopy = false. I.e., it can reuse stuff unsafely. If the
    // user frees, it's their fault.
    if (bogusUSK(context)) return false;

    CacheFetchResult result = lookupCachedResult(context);
    if (result == null) return false;

    if (tryUseUnfilteredResult(result)) {
      return true;
    }

    if (result.alreadyFiltered && !canReuseFilteredResult(result)) {
      return false;
    }

    if (result.alreadyFiltered && refilterPolicy == REFILTER_POLICY.ACCEPT_OLD) {
      tracker.removeFetcher(this);
      onSuccess(result, null);
      return true;
    }

    return processCachedResult(context, result);
  }

  private CacheFetchResult lookupCachedResult(ClientContext context) {
    if (context.getDownloadCache() == null) {
      return null;
    }
    return context.getDownloadCache().lookupInstant(uri, !fctx.getFilterData(), false, null);
  }

  private boolean tryUseUnfilteredResult(CacheFetchResult result) {
    if (fctx.getFilterData() || result.alreadyFiltered) {
      return false;
    }

    String cachedMime = result.getMimeType();
    String overrideMime = fctx.getOverrideMIME();
    if (overrideMime == null || overrideMime.equals(cachedMime)) {
      tracker.removeFetcher(this);
      onSuccess(result, null);
      return true;
    }

    tracker.removeFetcher(this);
    onSuccess(FetchResult.create(new ClientMetadata(overrideMime), result.asBucket()), null);
    return true;
  }

  private boolean canReuseFilteredResult(CacheFetchResult result) {
    if (refilterPolicy == REFILTER_POLICY.RE_FETCH || !fctx.getFilterData()) {
      return false;
    }
    return shouldAcceptCachedFilteredData(fctx, result);
  }

  private boolean processCachedResult(ClientContext context, CacheFetchResult result) {
    try (Bucket cachedData = result.asBucket()) {
      String cachedMimeType = result.getMimeType();
      if (cachedMimeType == null || cachedMimeType.isEmpty()) {
        cachedMimeType = DefaultMIMETypes.DEFAULT_MIME_TYPE;
      }
      if (fctx.getOverrideMIME() != null && !result.alreadyFiltered) {
        cachedMimeType = fctx.getOverrideMIME();
      } else if (fctx.getOverrideMIME() != null && !cachedMimeType.equals(fctx.getOverrideMIME())) {
        return false;
      }

      String fullMimeType = cachedMimeType;
      String strippedMimeType = ContentFilter.stripMIMEType(cachedMimeType);
      FilterMIMEType type = ContentFilter.getMIMEType(strippedMimeType);
      if (type == null || (!type.safeToRead && type.readFilter == null)) {
        UnknownContentTypeException e = new UnknownContentTypeException(strippedMimeType);
        onFailure(
            new FetchException(e.getFetchErrorCode(), cachedData.size(), e, strippedMimeType));
        return true;
      }
      if (type.safeToRead) {
        tracker.removeFetcher(this);
        onSuccess(FetchResult.create(new ClientMetadata(strippedMimeType), cachedData), null);
        return true;
      }
      return filterCachedData(context, fullMimeType, cachedData);
    }
  }

  private boolean filterCachedData(ClientContext context, String fullMimeType, Bucket cachedData) {
    try (Bucket output = context.tempBucketFactory.makeBucket(-1);
        InputStream is = cachedData.getInputStream();
        OutputStream os = output.getOutputStream()) {
      ContentFilterRequest request =
          new ContentFilterRequest(
              is, os, fullMimeType, fctx.getCharset(), fctx.getSchemeHostAndPort(), null);
      ContentFilterCallbacks callbacks =
          new ContentFilterCallbacks(
              uri.toURI("/"), null, null, context.linkFilterExceptionProvider);
      ContentFilter.filter(request, callbacks);
      // Since we are not re-using the data bucket, we can happily stay in the
      // FProxyFetchTracker.
      this.onSuccess(FetchResult.create(new ClientMetadata(fullMimeType), output), null);
      return true;
    } catch (IOException _) {
      LOG.info("Failed filtering coalesced data in fproxy");
      return false;
    } catch (URISyntaxException e) {
      LOG.error("Impossible: {}", e, e);
      return false;
    }
  }

  /**
   * If the key is a USK and (a) we are requested to do an exhaustive search, or (b) there is a
   * later version, then we can't use the download queue as a cache.
   *
   * @return True if we can't use the download queue, false if we can.
   */
  private boolean bogusUSK(ClientContext context) {
    if (!uri.isUSK()) return false;
    long edition = uri.getSuggestedEdition();
    if (edition < 0) return true; // Need to do the fetch.
    USK usk;
    try {
      usk = USK.create(uri);
    } catch (MalformedURLException _) {
      return false; // Will fail later.
    }
    long ret = context.uskManager.lookupKnownGood(usk);
    if (ret == -1) return false;
    return ret > edition;
  }

  private boolean shouldAcceptCachedFilteredData(FetchContext fctx, CacheFetchResult result) {
    // We currently reject cached filtered data when a charset is requested to avoid mismatches.
    if (fctx.getCharset() != null) return false;
    if (fctx.getOverrideMIME() == null) {
      return true;
    } else {
      String finalMIME = result.getMimeType();
      if (fctx.getOverrideMIME().equals(finalMIME)) return true;
      else
        return ContentFilter.stripMIMEType(finalMIME).equals(fctx.getOverrideMIME())
            && fctx.getCharset() == null;
      // Additional cases could be supported if override MIME handling expands.
    }
  }

  @Override
  public void receive(ClientEvent ce, ClientEventDispatchContext context) {
    try {
      switch (ce) {
        case SplitfileProgressEvent split -> {
          synchronized (this) {
            int oldReq = requiredBlocks - (fetchedBlocks + failedBlocks + fatallyFailedBlocks);
            totalBlocks = split.totalBlocks;
            fetchedBlocks = split.succeedBlocks;
            requiredBlocks = split.getMinSuccessfulBlocks();
            failedBlocks = split.failedBlocks;
            fatallyFailedBlocks = split.fatallyFailedBlocks;
            finalizedBlocks = split.finalizedTotal;
            int req = requiredBlocks - (fetchedBlocks + failedBlocks + fatallyFailedBlocks);
            if (!(req > 1024 && oldReq <= 1024)) return;
          }
        }
        case SendingToNetworkEvent _ -> {
          synchronized (this) {
            if (goneToNetwork) return;
            goneToNetwork = true;
            fetchedBlocksPreNetwork = fetchedBlocks;
          }
        }
        case ExpectedMIMEEvent event1 -> {
          synchronized (this) {
            this.mimeType = event1.expectedMIMEType;
          }
          if (!goneToNetwork) return;
        }
        case ExpectedFileSizeEvent event -> {
          synchronized (this) {
            this.size = event.expectedSize;
          }
          if (!goneToNetwork) return;
        }
        case null, default -> {
          return;
        }
      }
      wakeWaiters(false);
    } finally {
      for (FProxyFetchListener l : new ArrayList<>(listener)) {
        l.onEvent();
      }
    }
  }

  private void wakeWaiters(boolean finished) {
    FProxyFetchWaiter[] waiting;
    synchronized (this) {
      waiting = waiters.toArray(new FProxyFetchWaiter[0]);
    }
    for (FProxyFetchWaiter w : waiting) {
      w.wakeUp(finished);
    }
    if (finished) {
      for (FProxyFetchListener l : new ArrayList<>(listener)) {
        l.onEvent();
      }
    }
  }

  @Override
  public void onFailure(FetchException e) {
    synchronized (this) {
      this.failed = e;
      this.finished = true;
      this.timeFailed = System.currentTimeMillis();
    }
    wakeWaiters(true);
  }

  @Override
  public void onSuccess(FetchResult result, ClientGetter state) {
    Bucket bucket = result.asBucket();
    boolean shouldFree = false;
    synchronized (this) {
      if (cancelled) {
        shouldFree = true;
      } else {
        this.data = bucket;
      }
      this.mimeType = result.getMimeType();
      this.finished = true;
    }
    wakeWaiters(true);
    if (shouldFree) {
      bucket.free();
    }
  }

  /**
   * Indicates whether the fetch has produced data that can be returned to callers.
   *
   * <p>The flag only flips when {@link #onSuccess(FetchResult, ClientGetter)} stores the bucket and
   * remains stable thereafter. It does not imply listeners have been notified yet, but it
   * guarantees that {@link #innerGetResult(boolean)} will produce a {@link FProxyFetchResult}
   * carrying the final bucket rather than progress info.
   *
   * @return {@code true} when the fetch succeeded and stored a non-null data bucket
   */
  public synchronized boolean hasData() {
    return data != null;
  }

  /**
   * Reports whether the fetch reached a terminal state, either success or failure.
   *
   * <p>Terminal states are set by success, failure, or cancellation flows and never revert. The
   * method does not differentiate between fatal and retryable failures; callers should inspect the
   * stored {@link FetchException} through {@link #innerGetResult(boolean)} for details before
   * deciding whether to retry.
   *
   * @return {@code true} once data has arrived, an error was set, or the fetch was canceled
   */
  public synchronized boolean finished() {
    return finished;
  }

  /**
   * Releases a waiter and schedules cancellation if no other observers remain.
   *
   * <p>FProxy pages typically close waiters when the user navigates away. The method checks
   * remaining waiters and previously created results to decide whether the fetch can be canceled
   * immediately or should continue running for other subscribers.
   *
   * @param waiter the waiter to remove from the active list; ignored if already absent
   */
  public void close(FProxyFetchWaiter waiter) {
    synchronized (this) {
      waiters.remove(waiter);
      if (!results.isEmpty()) return;
      if (!waiters.isEmpty()) return;
    }
    tracker.queueCancel(this);
  }

  /** Keep for 30 seconds after last access */
  static final long LIFETIME = SECONDS.toMillis(30);

  /**
   * Determines whether the fetch can be canceled safely without racing active observers.
   *
   * <p>Callers must first hold the outer {@code FProxyToadlet.fetchers} lock to avoid conflicts
   * with concurrent additions. A {@code true} return signals that no waiters, listeners, or
   * result-holders remain and the entry is old enough (unless immediate cancel is requested), so
   * the tracker may proceed with {@link #finishCancel()} outside the shared lock.
   *
   * @return {@code true} when no observers remain and the grace period has elapsed
   */
  public synchronized boolean canCancel() {
    if (!waiters.isEmpty()) return false;
    if (!results.isEmpty()) return false;
    if (!listener.isEmpty()) return false;
    if (lastTouched + LIFETIME >= System.currentTimeMillis() && !requestImmediateCancel) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Not able to cancel for {} : {} : {}", this, uri, maxSize);
      }
      return false;
    }
    if (LOG.isDebugEnabled()) LOG.debug("Can cancel for {} : {} : {}", this, uri, maxSize);
    return true;
  }

  /**
   * Completes cancellation by signaling the getter, marking the fetch as canceled, and freeing any
   * held data bucket.
   *
   * <p>The tracker must remove this instance before calling to ensure no future waiters reuse it.
   * Errors during cancellation are logged but do not prevent resource cleanup.
   */
  public void finishCancel() {
    if (LOG.isDebugEnabled()) LOG.debug("Finishing cancel for {} : {} : {}", this, uri, maxSize);
    try {
      getter.cancel(tracker.context);
    } catch (Exception e) {
      // Ensure we get to the next bit
      LOG.error("Failed to cancel: {}", e, e);
    }
    Bucket d;
    synchronized (this) {
      d = data;
      cancelled = true;
    }
    if (d != null) {
      try {
        d.free();
      } catch (Exception e) {
        // Ensure we get to the next bit
        LOG.error("Failed to free: {}", e, e);
      }
    }
  }

  /**
   * Releases a result handle and schedules cancellation if no other observers are present.
   *
   * <p>Results are created by {@link #innerGetResult(boolean)} and should be closed by the renderer
   * once the associated browser request finishes. If both waiters and other results are gone, the
   * tracker will cancel the underlying getter to reclaim resources.
   *
   * @param result the result object being discarded by the caller
   */
  public void close(FProxyFetchResult result) {
    synchronized (this) {
      results.remove(result);
      if (!results.isEmpty()) return;
      if (!waiters.isEmpty()) return;
    }
    tracker.queueCancel(this);
  }

  /**
   * Estimates remaining download time based on splitfile block progress since network contact.
   *
   * <p>The estimate appears only after a minimum number of blocks have been fetched post-network
   * contact to avoid misleading early values. It returns {@code -1} when timing data is
   * insufficient or when the fetch has already completed.
   *
   * @return milliseconds remaining, or {@code -1} when estimation is unavailable or complete
   */
  public synchronized long getETA() {
    if (!goneToNetwork) return -1;
    if (requiredBlocks <= 0) return -1;
    if (fetchedBlocks >= requiredBlocks) return -1;
    if (fetchedBlocks - fetchedBlocksPreNetwork < 5) return -1;
    return ((System.currentTimeMillis() - timeStarted) * (requiredBlocks - fetchedBlocksPreNetwork))
        / (fetchedBlocks - fetchedBlocksPreNetwork);
  }

  /**
   * Indicates whether the fetch should continue to be displayed because it is pending or recently
   * failed.
   *
   * <p>This is primarily used by the FProxy UI to decide whether progress pages should still show a
   * row for the fetch. It returns true while work continues, when fatal failures require user
   * acknowledgement, or for a short window after a non-fatal error so JavaScript refreshes can pick
   * up the status.
   *
   * @return {@code true} when work is ongoing, failure was fatal, or a recent error needs display
   */
  public synchronized boolean notFinishedOrFatallyFinished() {
    if (data == null && failed == null) return true;
    if (failed != null && failed.isFatal()) return true;
    if (failed != null && !hasNotifiedFailure) {
      hasNotifiedFailure = true;
      return true;
    }
    // Once for JavaScript and once for the user when it re-pulls.
    return failed != null && (System.currentTimeMillis() - timeFailed < 1000 || fetched < 2);
  }

  /**
   * Placeholder indicating that failure notifications have been emitted to interested parties.
   *
   * <p>The current implementation always returns {@code true}; the method exists to mirror historic
   * behavior expected by callers and may be expanded in future when finer-grained notification
   * tracking is required.
   *
   * @return {@code true} because failures are treated as already communicated
   */
  @SuppressWarnings("unused")
  public synchronized boolean hasNotifiedFailure() {
    return true;
  }

  /**
   * Returns whether any waiter has already waited for progress, used to throttle UI refreshes.
   *
   * <p>The flag is set when a waiter first signals it is blocking, so later HTTP refreshes can
   * avoid duplicate latency compensation. It remains true for the lifetime of the fetch because a
   * single wait indicates user interest that should not be throttled twice.
   *
   * @return {@code true} once a waiter reported waiting at least once for this fetch
   */
  public synchronized boolean hasWaited() {
    return hasWaited;
  }

  /**
   * Marks that a waiter has waited at least once, avoiding duplicate throttling.
   *
   * <p>The flag reduces spurious UI refreshes by signaling that the associated browser request has
   * already paused for progress. Subsequent calls are idempotent and keep the fetch state intact,
   * ensuring race-free cooperation between multiple waiter threads that may report waits
   * concurrently.
   */
  public synchronized void setHasWaited() {
    hasWaited = true;
  }

  /**
   * Registers a listener that will be notified whenever fetch state changes or events arrive.
   *
   * <p>Listeners are invoked outside the synchronized blocks but may still be called from worker
   * threads that deliver {@link ClientEvent}s, so implementations must be thread-safe and quick. If
   * a listener slows down excessively, it can delay UI refresh notifications for other watchers.
   *
   * @param listener the callback to add; must be thread-safe because notifications may cross
   *     threads
   */
  public synchronized void addListener(FProxyFetchListener listener) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("Registered listener:{}", listener);
    }
    this.listener.add(listener);
  }

  /**
   * Unregisters a previously added listener and logs whether cancellation is now possible.
   *
   * <p>If this removal empties the listener set, the tracker may soon cancel the fetch once waiters
   * and results are also gone. Logging is performed at debug level to aid lifecycle diagnostics
   * without noisy production output.
   *
   * @param listener the callback to remove; ignored if not currently registered
   */
  public synchronized void removeListener(FProxyFetchListener listener) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("Removed listener:{}", listener);
    }
    this.listener.remove(listener);
    if (LOG.isDebugEnabled()) {
      LOG.debug("can cancel now?:{}", canCancel());
    }
  }

  /**
   * Allows the fetch to be removed immediately.
   *
   * <p>Setting this flag bypasses the usual thirty-second grace period used to serve late browser
   * refreshes. It is intended for explicit user cancellation or cleanup operations where keeping
   * the entry alive provides no value.
   */
  public synchronized void requestImmediateCancel() {
    requestImmediateCancel = true;
  }

  /**
   * Returns the timestamp (milliseconds since epoch) of the most recent waiter or result access.
   *
   * <p>The tracker uses this value to decide when the fetch entry has been idle long enough to
   * cancel. It is updated on waiter creation, and the result reads; callers should treat it as a
   * monotonic indicator of user interest.
   *
   * @return epoch millisecond timestamp of the last interaction with this fetch
   */
  @SuppressWarnings("unused")
  public synchronized long lastTouched() {
    return lastTouched;
  }

  /**
   * Compares a fetch context against the stored one to determine deduplication compatibility.
   *
   * <p>Only a subset of {@link FetchContext} fields influence deduplication: filtering toggle,
   * output/temp limits, charset override, and MIME override. The method ignores other options such
   * as priority and persistent request flags because FProxy reuse focuses on data equivalence. Null
   * and non-null charsets are compared carefully to avoid unintended mismatches.
   *
   * @param context candidate context to compare; may contain charset and MIME overrides
   * @return {@code true} when filtering, sizing, and charset rules are semantically identical
   */
  public boolean fetchContextEquivalent(FetchContext context) {
    if (this.fctx.getFilterData() != context.getFilterData()) return false;
    if (this.fctx.getMaxOutputLength() != context.getMaxOutputLength()) return false;
    if (this.fctx.getMaxTempLength() != context.getMaxTempLength()) return false;
    if (this.fctx.getCharset() == null && context.getCharset() != null) return false;
    if (this.fctx.getCharset() != null && !this.fctx.getCharset().equals(context.getCharset()))
      return false;
    if (this.fctx.getOverrideMIME() == null && context.getOverrideMIME() != null) return false;
    return this.fctx.getOverrideMIME() == null
        || this.fctx.getOverrideMIME().equals(context.getOverrideMIME());
  }

  /**
   * Unsupported resume hook because FProxy fetchers are intentionally non-persistent.
   *
   * <p>Resume callbacks are part of the {@link ClientGetCallback} contract for persistent requests.
   * Because FProxy fetches are transient and tied to browser interactions, persistence is disabled
   * and any attempt to resume would indicate a misuse. The exception keeps this behavior explicit
   * for maintainers.
   *
   * @param context unused context supplied by the persistence mechanism
   * @throws UnsupportedOperationException always, to signal the lifecycle limitation
   */
  @Override
  public void onResume(ClientContext context) {
    throw new UnsupportedOperationException(); // Not persistent.
  }

  /**
   * Exposes the {@link RequestClient} identity used for quota enforcement and statistics.
   *
   * <p>The request client anchors the fetch within node-level accounting such as bandwidth
   * throttling or trust metrics. It is set during construction and remains constant so auxiliary
   * components can attribute traffic correctly.
   *
   * @return request client associated with this fetch; never null after construction
   */
  @Override
  public RequestClient getRequestClient() {
    return rc;
  }

  /**
   * Returns a diagnostic string containing the identifier, URI, and initial client context.
   *
   * <p>The format is stable enough for logging and troubleshooting but not intended as a
   * serialization contract. It avoids revealing the internal mutable state and therefore remains
   * safe to print even while callbacks mutate other fields.
   *
   * @return human-readable summary suitable for debug logging and progress pages
   */
  @Override
  public String toString() {
    return "FProxyFetchInProgress{"
        + "identifier="
        + identifier
        + ", uri="
        + uri
        + ", context="
        + initialContext
        + '}';
  }
}
