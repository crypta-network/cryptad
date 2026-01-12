package network.crypta.clients.http;

import java.util.List;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.async.ClientContext;
import network.crypta.clients.http.FProxyFetchInProgress.REFILTER_POLICY;
import network.crypta.keys.FreenetURI;
import network.crypta.node.RequestClient;
import network.crypta.support.MultiValueTable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tracks, reuses, and eventually cancels in-flight FProxy fetches keyed by {@link FreenetURI}.
 *
 * <p>The tracker owns a small registry of {@link FProxyFetchInProgress} instances so callers can
 * share results when multiple requests target the same key and constraints. It coordinates creation
 * of new fetchers, hands back {@link FProxyFetchWaiter} handles, and schedules time-based cleanup
 * of stale work. Internally the registry is guarded by the {@code fetchers} monitor while lifecycle
 * state changes rely on {@link ClientContext#ticker} to avoid blocking the calling thread.
 *
 * <p>Typical call flow: a servlet asks for a fetcher via {@link #makeFetcher(FProxyFetchCriteria,
 * REFILTER_POLICY)}, obtains a waiter, and later the tracker culls abandoned instances through
 * {@link #run()}. Instances are intentionally short-lived; they are cancelled when a fetch
 * completes, fails fatally, or the scheduled cleanup fires.
 *
 * <ul>
 *   <li>Responsibility: deduplicate fetch requests and manage their lifetime.
 *   <li>Concurrency: access to the registry is synchronized; cancellation runs on the ticker
 *       thread.
 *   <li>Mutability: the tracker holds mutable state per fetch but exposes only waiter handles to
 *       callers.
 * </ul>
 */
public class FProxyFetchTracker implements Runnable {
  private static final Logger LOG = LoggerFactory.getLogger(FProxyFetchTracker.class);

  private final MultiValueTable<FreenetURI, FProxyFetchInProgress> fetchers =
      new MultiValueTable<>();
  final ClientContext context;
  private long fetchIdentifiers;
  private final FetchContext fctx;
  private final RequestClient rc;
  private boolean queuedJob;
  private boolean requeue;

  /**
   * Creates a tracker bound to the given asynchronous client context and default fetch settings.
   *
   * <p>The constructor wires together the runtime services needed by each fetcher: the {@link
   * ClientContext} supplies schedulers, timers, and random sources; the baseline {@link
   * FetchContext} seeds new fetches when callers do not supply overrides; and the {@link
   * RequestClient} links requests to the owning client identity. Callers typically create a single
   * tracker per HTTP handler or node instance and reuse it for all inbound requests to maximize
   * fetch deduplication and to centralize lifecycle management.
   *
   * @param context underlying client runtime that provides scheduling and random utilities; must
   *     not be {@code null}.
   * @param fctx baseline {@link FetchContext} applied when callers do not override it; reused for
   *     deduplication.
   * @param rc request client used by new {@link FProxyFetchInProgress} instances to submit network
   *     fetches.
   */
  public FProxyFetchTracker(ClientContext context, FetchContext fctx, RequestClient rc) {
    this.context = context;
    this.fctx = fctx;
    this.rc = rc;
  }

  /**
   * Creates or reuses a fetcher for the supplied key and returns its waiter handle.
   *
   * <p>If an active fetch with equivalent size constraints and fetch context already exists, the
   * existing waiter is returned immediately. Otherwise, a new {@link FProxyFetchInProgress} is
   * created, registered, and started before handing back its waiter. Fetch creation occurs while
   * holding the registry lock to avoid races; network work is started after releasing the lock to
   * minimize contention.
   *
   * @param criteria immutable criteria containing URI, size limit, and optional fetch context. When
   *     the context is {@code null}, the tracker default context is used.
   * @param refilterPolicy policy describing how client-side refiltering should be applied when the
   *     fetch completes.
   * @return waiter that exposes progress and completion for the matching or newly created fetch.
   * @throws FetchException if the underlying fetch cannot be started or the request client rejects
   *     the parameters.
   */
  public FProxyFetchWaiter makeFetcher(FProxyFetchCriteria criteria, REFILTER_POLICY refilterPolicy)
      throws FetchException {
    FProxyFetchInProgress progress;
    FProxyFetchCriteria effectiveCriteria = resolveCriteria(criteria);
    /* LOCKING:
     * Call getWaiter() inside the fetchers lock, since we will purge old
     * fetchers inside that lock, hence avoid a race condition. FetchInProgress
     * lock is always taken last. */
    synchronized (fetchers) {
      FProxyFetchWaiter waiter = makeWaiterForFetchInProgress(effectiveCriteria);
      if (waiter != null) {
        return waiter;
      }
      progress =
          new FProxyFetchInProgress(
              this, effectiveCriteria, fetchIdentifiers++, context, rc, refilterPolicy);
      fetchers.put(effectiveCriteria.key(), progress);
    }
    try {
      progress.start(context);
    } catch (FetchException e) {
      synchronized (fetchers) {
        fetchers.removeElement(effectiveCriteria.key(), progress);
      }
      throw e;
    }
    if (LOG.isDebugEnabled()) LOG.debug("Created new fetcher: {}", progress);
    return progress.getWaiter();
  }

  private FProxyFetchCriteria resolveCriteria(FProxyFetchCriteria criteria) {
    FetchContext resolvedContext =
        criteria.fetchContext() != null ? criteria.fetchContext() : this.fctx;
    if (resolvedContext == criteria.fetchContext()) {
      return criteria;
    }
    return new FProxyFetchCriteria(criteria.key(), criteria.maxSize(), resolvedContext);
  }

  void removeFetcher(FProxyFetchInProgress progress) {
    synchronized (fetchers) {
      fetchers.removeElement(progress.uri, progress);
    }
  }

  /**
   * Returns a waiter for an already-running fetch that matches the supplied criteria.
   *
   * <p>The lookup matches on URI, exact {@code maxSize}, and (when provided) a fetch context that
   * is equivalent according to {@link FProxyFetchInProgress#fetchContextEquivalent(FetchContext)}.
   * Callers use this to piggyback on in-flight work instead of launching a duplicate download.
   *
   * @param criteria immutable criteria containing URI, size limit, and optional fetch context.
   * @return waiter for the matching fetch, or {@code null} when no acceptable fetch exists.
   */
  public FProxyFetchWaiter makeWaiterForFetchInProgress(FProxyFetchCriteria criteria) {
    FProxyFetchInProgress progress = getFetchInProgress(criteria);
    if (progress != null) {
      return progress.getWaiter();
    }
    return null;
  }

  /**
   * Locates an existing {@link FProxyFetchInProgress} by URI, size limit, and optional context.
   *
   * <p>The lookup runs under the registry lock to avoid races with creation or cleanup. Only
   * fetches that are still usable (not finished fatally, or already holding data) and satisfy the
   * size and context constraints are returned. This helper underpins both waiter lookups and fetch
   * reuse decisions elsewhere in the tracker.
   *
   * @param criteria immutable criteria containing URI, size limit, and optional fetch context.
   * @return an active {@link FProxyFetchInProgress} if one matches, otherwise {@code null} when
   *     none qualify.
   */
  public FProxyFetchInProgress getFetchInProgress(FProxyFetchCriteria criteria) {
    synchronized (fetchers) {
      for (FProxyFetchInProgress fetch : fetchers.getAllAsList(criteria.key())) {
        if (matchesFetch(fetch, criteria.maxSize(), criteria.fetchContext())) {
          return fetch;
        }
      }
    }
    return null;
  }

  private boolean matchesFetch(FProxyFetchInProgress fetch, long maxSize, FetchContext fctx) {
    if (!isSizeAndStateAcceptable(fetch, maxSize)) {
      logSkipping(fetch);
      return false;
    }
    if (isFetchContextMismatch(fetch, fctx)) {
      logContextMismatch(fetch);
      return false;
    }
    logUsing(fetch);
    return true;
  }

  private boolean isSizeAndStateAcceptable(FProxyFetchInProgress fetch, long maxSize) {
    boolean acceptable =
        (fetch.maxSize == maxSize && fetch.notFinishedOrFatallyFinished()) || fetch.hasData();
    if (acceptable && LOG.isDebugEnabled()) {
      LOG.debug("Found {}", fetch);
    }
    return acceptable;
  }

  private boolean isFetchContextMismatch(FProxyFetchInProgress fetch, FetchContext fctx) {
    return fctx != null && !fetch.fetchContextEquivalent(fctx);
  }

  private void logContextMismatch(FProxyFetchInProgress fetch) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("Fetch context does not match. Skipping {}", fetch);
    }
  }

  private void logUsing(FProxyFetchInProgress fetch) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("Using {}", fetch);
    }
  }

  private void logSkipping(FProxyFetchInProgress fetch) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("Skipping {}", fetch);
    }
  }

  /**
   * Schedules cancellation of the given fetch on the ticker thread.
   *
   * <p>When invoked, the tracker either enqueues a cleanup job or marks that a previously queued
   * job should run again, preventing unbounded queuing. The actual removal and cancellation occur
   * in {@link #run()}, which is executed by {@link ClientContext#ticker} after the configured
   * lifetime delay.
   *
   * @param progress fetch instance to cancel when it becomes eligible; ignored when {@code null}.
   */
  public void queueCancel(FProxyFetchInProgress progress) {
    if (progress == null) {
      return;
    }
    if (LOG.isDebugEnabled()) LOG.debug("Queueing removal of old FProxyFetchInProgress's");
    synchronized (this) {
      if (queuedJob) {
        requeue = true;
        return;
      }
      queuedJob = true;
    }
    context.ticker.queueTimedJob(this, FProxyFetchInProgress.LIFETIME);
  }

  /**
   * Executes the timed cleanup cycle that removes and cancels stale fetchers.
   *
   * <p>The method gathers cancellable entries under the registry lock, removes their references,
   * and then calls {@link FProxyFetchInProgress#finishCancel()} outside the lock to avoid blocking
   * new lookups. If removals requested a requeue, the job schedules itself again using the ticker
   * so that future stale fetches are also collected.
   */
  @Override
  public void run() {
    if (LOG.isDebugEnabled()) LOG.debug("Removing old FProxyFetchInProgress's");
    FetcherCleanupResult cleanupResult = collectAndRemoveCancellableFetchers();
    cancelFetchers(cleanupResult.toRemove());
    if (cleanupResult.needRequeue()) {
      context.ticker.queueTimedJob(this, FProxyFetchInProgress.LIFETIME);
    }
  }

  private FetcherCleanupResult collectAndRemoveCancellableFetchers() {
    synchronized (fetchers) {
      boolean needRequeue = updateQueueFlags();
      List<FProxyFetchInProgress> toRemove =
          fetchers.values().stream().filter(FProxyFetchInProgress::canCancel).toList();

      for (FProxyFetchInProgress fetch : toRemove) {
        if (LOG.isDebugEnabled()) LOG.debug("Removed fetchinprogress:{}", fetch);
        fetchers.removeElement(fetch.uri, fetch);
      }
      return new FetcherCleanupResult(toRemove, needRequeue);
    }
  }

  private boolean updateQueueFlags() {
    if (requeue) {
      requeue = false;
      return true;
    }
    queuedJob = false;
    return false;
  }

  private void cancelFetchers(List<FProxyFetchInProgress> toRemove) {
    for (FProxyFetchInProgress fetch : toRemove) {
      if (LOG.isDebugEnabled()) LOG.debug("Cancelling for {}", fetch);
      fetch.finishCancel();
    }
  }

  private record FetcherCleanupResult(List<FProxyFetchInProgress> toRemove, boolean needRequeue) {}

  /**
   * Generates a random element identifier suitable for tagging fetch-related objects.
   *
   * <p>The value is produced by {@link ClientContext#fastWeakRandom}, which favors speed over
   * cryptographic strength. Callers should treat the result as best-effort unique within the
   * current process and avoid persisting it where strong randomness is required.
   *
   * @return a pseudo-random 32-bit integer drawn from the fast weak random source.
   */
  public int makeRandomElementID() {
    return context.fastWeakRandom.nextInt();
  }
}
