package network.crypta.client.async;

import static java.util.concurrent.TimeUnit.SECONDS;

import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;
import java.util.TreeMap;
import java.util.WeakHashMap;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.FetchResult;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.NullClientCallback;
import network.crypta.clients.http.FProxyToadlet;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.USK;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestClient;
import network.crypta.node.RequestClientBuilder;
import network.crypta.node.RequestStarter;
import network.crypta.support.LRUMap;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.NullBucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Maintains the latest known state for {@link USK} keys and coordinates background update
 * monitoring.
 *
 * <p>This manager resolves and tracks two notions of “latest”:
 *
 * <ul>
 *   <li><em>Latest slot</em> — the most recent SSK slot observed to be authored for a given USK,
 *       regardless of whether its target content has been successfully fetched.
 *   <li><em>Known good</em> — the most recent edition that has been fetched successfully and
 *       verified as usable.
 * </ul>
 *
 * It exposes subscription APIs that notify callers when new editions are discovered, and optional
 * background polling that continues to search for newer editions. Background fetchers can be
 * created in a “sparse” mode that reduces bandwidth by reporting only after a discovery round
 * stabilizes.
 *
 * <p>Lifecycle and storage: this class is <strong>transient</strong>. It keeps only in-memory
 * state; no subscriptions or fetchers are persisted across restarts. Callers should obtain an
 * instance from the node’s client context rather than constructing it directly.
 *
 * <p>Concurrency: public methods that return cached state perform minimal synchronization to
 * maintain internal maps. Callbacks may be invoked on executor threads; implementations should be
 * thread-safe and return quickly.
 *
 * @see USKFetcher
 * @see USKRetriever
 * @see USK
 */
public class USKManager {
  private static final Logger LOG = LoggerFactory.getLogger(USKManager.class);
  private static final String LOG_PUT = "Put {}";
  private static final String LOG_SUBSCRIBING_TO_FOR = "Subscribing to {} for {}";

  static RequestClient rcRT = new RequestClientBuilder().realTime().build();

  static RequestClient rcBulk = new RequestClientBuilder().build();

  /** Latest version successfully fetched by blanked-edition-number USK */
  final Map<USK, Long> latestKnownGoodByClearUSK;

  /** Latest SSK slot known to be by the author by blanked-edition-number USK */
  final Map<USK, Long> latestSlotByClearUSK;

  /** Subscribers by clear USK */
  final Map<USK, USKCallback[]> subscribersByClearUSK;

  /**
   * Backgrounded USKFetchers by USK. These have pollForever=true and are only created when
   * subscribe(,true) is called.
   */
  final Map<USK, USKFetcher> backgroundFetchersByClearUSK;

  /**
   * Temporary fetchers, started when a USK (with a positive edition number) is fetched. These have
   * pollForever=false. Keyed by the clear USK, i.e. one per USK, not one per {USK, start edition},
   * unlike fetchersByUSK.
   */
  final LRUMap<USK, USKFetcher> temporaryBackgroundFetchersLRU;

  /**
   * Temporary fetchers where we have been asked to prefetch content. We track the time we last had
   * a new last-slot, so that if there is no new last-slot found in 60 seconds, we start
   * prefetching. We delete the entry when the fetcher finishes. Note: this could be TreeMap-based
   * to prevent hash collision DoS'es, but it also needs to be weak; consider an approach that
   * balances both requirements.
   */
  final WeakHashMap<USK, Long> temporaryBackgroundFetchersPrefetch;

  final FetchContext backgroundFetchContext;
  final FetchContext backgroundFetchContextIgnoreDBR;

  /** This one actually fetches data */
  final FetchContext realFetchContext;

  final PriorityAwareExecutor executor;

  private ClientContext context;

  /**
   * Creates a manager bound to the provided node core. The constructor wires light-weight fetch
   * contexts for background probes and a real fetch context for content prefetch, and prepares
   * internal maps that track known-good and latest-slot editions per clear USK.
   *
   * @param core The node client core used to create request clients and executors; must be a live
   *     instance associated with the current node lifecycle.
   */
  public USKManager(NodeClientCore core) {
    HighLevelSimpleClient client =
        core.makeClient(RequestStarter.UPDATE_PRIORITY_CLASS, false, false);
    client.setMaxIntermediateLength(FProxyToadlet.getMaxLengthNoProgress());
    client.setMaxLength(FProxyToadlet.getMaxLengthNoProgress());
    backgroundFetchContext = client.getFetchContext();
    backgroundFetchContext.setFollowRedirects(false);
    backgroundFetchContextIgnoreDBR =
        new FetchContext(backgroundFetchContext, FetchContext.IDENTICAL_MASK, true, null);
    backgroundFetchContextIgnoreDBR.setIgnoreUSKDatehints(true);
    realFetchContext = client.getFetchContext();
    // Performance: I'm pretty sure there is no spatial locality in the underlying data, so it's
    // okay to use the FAST_COMPARATOR here.
    // That is, even if two USKs are by the same author, they won't necessarily be updated or polled
    // at the same time.
    latestKnownGoodByClearUSK = new TreeMap<>(USK.FAST_COMPARATOR);
    latestSlotByClearUSK = new TreeMap<>(USK.FAST_COMPARATOR);
    subscribersByClearUSK = new TreeMap<>(USK.FAST_COMPARATOR);
    backgroundFetchersByClearUSK = new TreeMap<>(USK.FAST_COMPARATOR);
    temporaryBackgroundFetchersLRU = LRUMap.createSafeMap(USK.FAST_COMPARATOR);
    temporaryBackgroundFetchersPrefetch = new WeakHashMap<>();
    executor = core.getExecutor();
  }

  /**
   * Initializes the manager with the ambient {@link ClientContext}. Must be called once before
   * scheduling fetchers or issuing hint/check operations that need the ticker and executors.
   *
   * @param context Non-null client context used for queueing jobs and starting requests.
   */
  public void init(ClientContext context) {
    this.context = context;
  }

  /**
   * Returns the latest edition that was fetched successfully for the given USK.
   *
   * <p>The query is performed against in-memory state only; no network requests are issued. When no
   * successful fetch is known yet, {@code -1} is returned.
   *
   * @param usk The key to query; only the clear (editionless) identity is considered. The provided
   *     instance is not retained, a cleared copy is used for lookups.
   * @return The highest known-good edition or {@code -1} when nothing has been fetched
   *     successfully.
   */
  public synchronized long lookupKnownGood(USK usk) {
    Long l = latestKnownGoodByClearUSK.get(usk.clearCopy());
    if (l != null) return l;
    else return -1;
  }

  /**
   * Returns the most recent SSK slot observed for the given USK.
   *
   * <p>This value may point past the last edition that has been fetched successfully; it reflects
   * the newest slot believed to be authored by the key’s owner.
   *
   * @param usk The key to query; only the clear (editionless) identity is considered. The provided
   *     instance is not retained, a cleared copy is used for lookups.
   * @return The latest known slot edition or {@code -1} when nothing has been seen so far.
   */
  public synchronized long lookupLatestSlot(USK usk) {
    Long l = latestSlotByClearUSK.get(usk.clearCopy());
    if (l != null) return l;
    else return -1;
  }

  /**
   * Builds a {@link USKFetcherTag} describing a fetcher with the requested behavior.
   *
   * <p>The tag encapsulates fetch options such as persistence, real-time scheduling and whether to
   * keep the last data. It does not schedule any work by itself; callers must submit the tag to the
   * appropriate mechanisms that accept it.
   *
   * @param usk The USK to monitor or fetch; the suggested edition may be used as a starting point.
   * @param ctx Fetch context controlling limits, timeouts, and local-only behavior; never mutated.
   * @param keepLast When true, requests that the last data be retained for callbacks or inspection.
   * @param persistent Whether the fetch should survive restarts when supported by the client.
   * @param realTime If true, schedules using the real-time client; otherwise bulk scheduling.
   * @param callback Optional callback notified of fetcher events; may be {@code null}.
   * @param ownFetchContext If true, clones the provided context to isolate fetcher mutations.
   * @param context The client context used by some implementations; may be {@code null}.
   * @param checkStoreOnly When true or when {@code ctx.localRequestOnly} is true, restricts lookups
   *     to the local store and avoids network access.
   * @return A tag describing the configured fetcher; immutable and safe to share across threads.
   */
  public USKFetcherTag getFetcher(
      USK usk,
      FetchContext ctx,
      boolean keepLast,
      boolean persistent,
      boolean realTime,
      USKFetcherCallback callback,
      boolean ownFetchContext,
      ClientContext context,
      boolean checkStoreOnly) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(
          "getFetcher flags: ownFetchContext={}, contextPresent={}",
          ownFetchContext,
          context != null);
    }
    return USKFetcherTag.create(
        usk,
        callback,
        ctx,
        0,
        persistent ? USKFetcherTag.Flag.PERSISTENT : null,
        realTime ? USKFetcherTag.Flag.REAL_TIME : null,
        keepLast ? USKFetcherTag.Flag.KEEP_LAST_DATA : null,
        (checkStoreOnly || ctx.getLocalRequestOnly()) ? USKFetcherTag.Flag.CHECK_STORE_ONLY : null);
  }

  USKFetcher getFetcher(
      USK usk,
      FetchContext ctx,
      ClientRequester requester,
      boolean keepLastData,
      boolean checkStoreOnly) {
    int options = 0;
    if (keepLastData) options |= USKFetcher.OPT_KEEP_LAST_DATA;
    if (checkStoreOnly) options |= USKFetcher.OPT_CHECK_STORE_ONLY;
    return new USKFetcher(usk, this, ctx, requester, 3, options);
  }

  /**
   * Prepares a {@link USKFetcherTag} suitable for insert flows without scheduling it immediately.
   *
   * <p>When {@code persistent} is true, a defensive copy of the background fetch context is used.
   * The resulting tag can be submitted by the caller at the appropriate time during an insert.
   *
   * @param usk Target key to watch for insert coordination; suggested edition may be honored.
   * @param prioClass Priority class used for scheduling; higher values are typically lower
   *     priority.
   * @param cb Callback notified of fetcher events during the insert lifecycle; may be {@code null}.
   * @param client Request client whose persistence/real-time flags are applied to the tag.
   * @param context Client context available to consumers of the tag; may be {@code null}.
   * @param persistent If true, the fetch context is cloned to isolate subsequent mutations.
   * @param ignoreUSKDatehints If true, ignores date hints when probing for editions.
   * @return A fetcher tag configured for insert-time use; the tag itself performs no work.
   */
  public USKFetcherTag getFetcherForInsertDontSchedule(
      USK usk,
      short prioClass,
      USKFetcherCallback cb,
      RequestClient client,
      ClientContext context,
      boolean persistent,
      boolean ignoreUSKDatehints) {
    if (LOG.isTraceEnabled()) {
      LOG.trace("getFetcherForInsertDontSchedule prioClass={}", prioClass);
    }
    FetchContext fctx =
        ignoreUSKDatehints ? backgroundFetchContextIgnoreDBR : backgroundFetchContext;
    return getFetcher(
        usk,
        persistent ? new FetchContext(fctx, FetchContext.IDENTICAL_MASK) : fctx,
        true,
        client.persistent(),
        client.realTimeFlag(),
        cb,
        true,
        context,
        false);
  }

  /**
   * Provides a non-authoritative hint that a specific edition <em>might</em> exist.
   *
   * <p>The manager issues a lightweight fetch of the SSK block only; content is not downloaded. A
   * background {@code USKFetcher} may race to probe the same block. This method is best-effort and
   * does not guarantee that the hinted edition actually exists.
   *
   * @param usk The USK whose edition is being hinted; the suggested edition is ignored here.
   * @param edition Edition number to probe for existence; non-negative and monotonic per caller.
   * @param context Client context used to start the hint request and schedule callbacks.
   */
  @SuppressWarnings("unused")
  public void hintUpdate(USK usk, long edition, ClientContext context) {
    if (edition < lookupLatestSlot(usk)) return;
    FreenetURI uri = usk.copy(edition).getURI().sskForUSK();
    final ClientGetter get =
        new ClientGetter(
            new NullClientCallback(rcBulk),
            uri,
            new FetchContext(backgroundFetchContext, FetchContext.IDENTICAL_MASK),
            RequestStarter.UPDATE_PRIORITY_CLASS,
            new NullBucket(),
            null,
            null);
    try {
      get.start(context);
    } catch (FetchException e) {
      // Ignore
    }
  }

  /**
   * Issues a best-effort hint for the provided USK/SSK {@link FreenetURI} at the default update
   * priority. If a USK is supplied it is converted to the corresponding SSK.
   *
   * @param uri A USK or SSK URI; USK inputs are converted to their SSK form for probing.
   * @param context Client context used to start the hint request and schedule callbacks.
   * @throws IllegalArgumentException If the URI does not represent a valid USK when conversion is
   *     attempted.
   */
  @SuppressWarnings("unused")
  public void hintUpdate(FreenetURI uri, ClientContext context) {
    try {
      hintUpdate(uri, context, RequestStarter.UPDATE_PRIORITY_CLASS);
    } catch (MalformedURLException e) {
      // USK creation failed for the provided URI; propagate as an unchecked argument error.
      throw new IllegalArgumentException(e);
    }
  }

  /**
   * Provides a non-authoritative hint that a specific edition <em>might</em> exist using an
   * explicit priority.
   *
   * <p>This variant accepts either a USK or SSK URI; USK inputs are converted to a derived SSK for
   * the probe. The method fetches only the block header, not the content payload.
   *
   * @param uri A USK or SSK URI identifying the edition to probe; USK is converted to SSK.
   * @param context Client context used to start the hint request and schedule callbacks.
   * @param priority Request priority used for scheduling; values map to request priority classes.
   * @throws MalformedURLException If the uri passed in is not a valid USK when conversion is
   *     attempted.
   */
  public void hintUpdate(FreenetURI uri, ClientContext context, short priority)
      throws MalformedURLException {
    if (uri.getSuggestedEdition() < lookupLatestSlot(USK.create(uri))) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Ignoring hint because edition is {} but latest is {}",
            uri.getSuggestedEdition(),
            lookupLatestSlot(USK.create(uri)));
      return;
    }
    uri = uri.sskForUSK();
    if (LOG.isDebugEnabled()) LOG.debug("Doing hint fetch for {}", uri);
    final ClientGetter get =
        new ClientGetter(
            new NullClientCallback(rcBulk),
            uri,
            new FetchContext(backgroundFetchContext, FetchContext.IDENTICAL_MASK),
            priority,
            new NullBucket(),
            null,
            null);
    try {
      get.start(context);
    } catch (FetchException e) {
      if (LOG.isDebugEnabled()) LOG.debug("Cannot start hint fetch for {} : {}", uri, e, e);
      // Ignore
    }
  }

  /**
   * Callback interface for {@link #hintCheck(FreenetURI, Object, ClientContext, short,
   * HintCallback)} results. Implementations should return quickly; methods are typically invoked on
   * executor threads.
   */
  public interface HintCallback {

    /**
     * The SSK block exists. The USK tracker will have been updated. We did not try to fetch the
     * rest of the key.
     *
     * @param origURI The original FreenetURI object.
     * @param token The token object passed in by the caller.
     */
    void success(FreenetURI origURI, Object token);

    /**
     * The SSK block does not exist. We got a DNF, DNF with RecentlyFailed, check store only, and it
     * wasn't in the datastore etc.
     *
     * @param origURI The original FreenetURI object.
     * @param token The token object passed in by the caller.
     * @param e The exception.
     */
    void dnf(FreenetURI origURI, Object token, FetchException e);

    /**
     * Some other error. We don't necessarily know that it doesn't exist.
     *
     * @param origURI The original FreenetURI object.
     * @param token The token object passed in by the caller.
     * @param e The exception.
     */
    void failed(FreenetURI origURI, Object token, FetchException e);
  }

  /**
   * Checks whether the referenced block exists without downloading its full content.
   *
   * <p>On success the internal USK tracker is updated so any active fetchers see the new edition.
   * The {@code uri} may be a USK or an SSK; USK inputs are converted to SSK for the probe.
   *
   * @param uri A USK or SSK URI to probe for existence without retrieving payload data.
   * @param token Opaque token echoed to the callback to correlate responses with the caller.
   * @param context Client context used to start the hint request and schedule callbacks.
   * @param priority Request priority used when performing the probe; higher values are lower
   *     priority.
   * @param cb Callback that receives success, DNF, or generic failure notifications.
   */
  @SuppressWarnings("unused")
  public void hintCheck(
      FreenetURI uri,
      final Object token,
      ClientContext context,
      short priority,
      final HintCallback cb) {
    final FreenetURI origURI = uri;
    if (uri.isUSK()) uri = uri.sskForUSK();
    if (LOG.isDebugEnabled()) LOG.debug("Doing hint fetch for {}", uri);
    final ClientGetter get =
        new ClientGetter(
            new ClientGetCallback() {

              @Override
              public void onSuccess(FetchResult result, ClientGetter state) {
                cb.success(origURI, token);
              }

              @Override
              public void onFailure(FetchException e, ClientGetter state) {
                if (e.isDataFound()) cb.success(origURI, token);
                else if (e.isDNF()) cb.dnf(origURI, token, e);
                else cb.failed(origURI, token, e);
              }

              @Override
              public void onResume(ClientContext context) {
                // Do nothing.
              }

              @Override
              public RequestClient getRequestClient() {
                return rcBulk;
              }
            },
            uri,
            new FetchContext(backgroundFetchContext, FetchContext.IDENTICAL_MASK),
            priority,
            new NullBucket(),
            null,
            null);
    try {
      get.start(context);
    } catch (FetchException e) {
      if (LOG.isDebugEnabled()) LOG.debug("Cannot start hint fetch for {} : {}", uri, e, e);
      if (e.isDataFound()) cb.success(origURI, token);
      else if (e.isDNF()) cb.dnf(origURI, token, e);
      else cb.failed(origURI, token, e);
    }
  }

  /**
   * Starts or refreshes a temporary background fetcher for the given USK.
   *
   * <p>Temporary fetchers run with limited lifetime and are trimmed by an internal LRU. When {@code
   * prefetchContent} is true, content prefetching is armed and may start after a quiet period if a
   * new slot is not discovered.
   *
   * @param usk The USK to track temporarily; the clear identity is used to de-duplicate.
   * @param context Client context used for scheduling and starting the fetcher.
   * @param fctx Fetch context applied to the fetcher; limits and flags are honored.
   * @param prefetchContent Enables content prefetch after a delay if new slots stop appearing.
   * @param realTimeFlag When true, schedules using the real-time client; otherwise bulk scheduling.
   */
  public void startTemporaryBackgroundFetcher(
      USK usk,
      ClientContext context,
      final FetchContext fctx,
      boolean prefetchContent,
      boolean realTimeFlag) {
    FetcherPlan plan = planTemporaryBackgroundFetcher(usk, fctx, prefetchContent, realTimeFlag);
    if (plan.toCancel != null || plan.toSchedule != null) {
      executor.execute(
          () -> {
            if (plan.toCancel != null) {
              for (int i = 0; i < plan.toCancel.size(); i++) {
                USKFetcher fetcher = plan.toCancel.get(i);
                fetcher.cancel(context);
              }
            }
            if (plan.toSchedule != null) plan.toSchedule.schedule(context);
          });
    }
  }

  private record FetcherPlan(ArrayList<USKFetcher> toCancel, USKFetcher toSchedule) {}

  private synchronized FetcherPlan planTemporaryBackgroundFetcher(
      USK usk, FetchContext fctx, boolean prefetchContent, boolean realTimeFlag) {
    final USK clear = usk.clearCopy();
    FetcherInfo info = ensureTemporaryFetcher(clear, usk, fctx, realTimeFlag);
    if (prefetchContent) updatePrefetchFor(clear);
    refreshRecency(clear, info.fetcher);
    ArrayList<USKFetcher> toCancel = trimTemporaryFetchers();
    return new FetcherPlan(toCancel, info.created ? info.fetcher : null);
  }

  private record FetcherInfo(USKFetcher fetcher, boolean created) {}

  private FetcherInfo ensureTemporaryFetcher(
      USK clear, USK usk, FetchContext fctx, boolean realTimeFlag) {
    USKFetcher existing = temporaryBackgroundFetchersLRU.get(clear);
    if (existing == null) {
      USKFetcher created =
          new USKFetcher(
              usk,
              this,
              fctx.getIgnoreUSKDatehints()
                  ? backgroundFetchContextIgnoreDBR
                  : backgroundFetchContext,
              new USKFetcherWrapper(
                  usk, RequestStarter.UPDATE_PRIORITY_CLASS, realTimeFlag ? rcRT : rcBulk),
              3,
              0);
      temporaryBackgroundFetchersLRU.push(clear, created);
      return new FetcherInfo(created, true);
    } else {
      existing.addHintEdition(usk.suggestedEdition);
      return new FetcherInfo(existing, false);
    }
  }

  private void refreshRecency(USK clear, USKFetcher fetcher) {
    // Update recency again, matching original behavior
    temporaryBackgroundFetchersLRU.push(clear, fetcher);
  }

  private ArrayList<USKFetcher> trimTemporaryFetchers() {
    ArrayList<USKFetcher> toCancel = null;
    while (temporaryBackgroundFetchersLRU.size() > NodeClientCore.getMaxBackgroundUSKFetchers()) {
      USKFetcher fetcher = temporaryBackgroundFetchersLRU.popValue();
      if (fetcher == null) {
        // Defensive: LRU returned no value; exit trimming loop
        break;
      }
      USK orig = fetcher.getOriginalUSK();
      if (orig != null) {
        temporaryBackgroundFetchersPrefetch.remove(orig.clearCopy());
      }
      if (!fetcher.hasSubscribers()) {
        if (toCancel == null) toCancel = new ArrayList<>(2);
        toCancel.add(fetcher);
      } else {
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Allowing temporary background fetcher to continue as it has subscribers... {}",
              fetcher);
      }
    }
    return toCancel;
  }

  private void updatePrefetchFor(USK clear) {
    long fetchTime = -1;
    long slot = lookupLatestSlot(clear);
    long good = lookupKnownGood(clear);
    if (slot > -1 && good != slot) fetchTime = System.currentTimeMillis();
    temporaryBackgroundFetchersPrefetch.put(clear, fetchTime);
    if (LOG.isDebugEnabled()) LOG.debug("Prefetch: set {} for {}", fetchTime, clear);
    schedulePrefetchChecker();
  }

  static final long PREFETCH_DELAY = SECONDS.toMillis(60);

  private void schedulePrefetchChecker() {
    context.ticker.queueTimedJob(
        prefetchChecker, "Check for USKs to prefetch", PREFETCH_DELAY, false, true);
  }

  private final Runnable prefetchChecker = this::runPrefetchChecker;

  private void runPrefetchChecker() {
    if (LOG.isTraceEnabled()) LOG.trace("Running prefetch checker...");
    long now = System.currentTimeMillis();
    final boolean scheduleAgain;
    final ArrayList<USK> toFetch;
    synchronized (USKManager.this) {
      scheduleAgain = !temporaryBackgroundFetchersPrefetch.isEmpty();
      toFetch = collectPrefetchTargetsLocked(now);
    }
    if (toFetch == null) return;
    for (final USK key : toFetch) {
      startPrefetchFor(key, key.suggestedEdition);
    }
    if (scheduleAgain) schedulePrefetchChecker();
  }

  private void startPrefetchFor(final USK key, final long edition) {
    if (LOG.isDebugEnabled())
      LOG.debug("Prefetching content for background fetch for edition {} on {}", edition, key);
    FetchContext fctx = new FetchContext(realFetchContext, FetchContext.IDENTICAL_MASK);
    final ClientGetter get =
        new ClientGetter(
            createPrefetchCallback(key, edition, context),
            key.getURI().sskForUSK() /* Note: add getSSKURI() when available */,
            fctx,
            RequestStarter.UPDATE_PRIORITY_CLASS,
            new NullBucket(),
            null,
            null);
    try {
      get.start(context);
    } catch (FetchException e) {
      if (LOG.isDebugEnabled()) LOG.debug("Prefetch failed: {}", e, e);
      // Ignore
    }
  }

  private ClientGetCallback createPrefetchCallback(
      final USK key, final long edition, final ClientContext ctx) {
    return new ClientGetCallback() {
      @Override
      public void onFailure(FetchException e, ClientGetter state) {
        if (e.newURI != null) {
          if (LOG.isDebugEnabled()) LOG.debug("Prefetch succeeded with redirect for {}", key);
          updateKnownGood(key, edition, ctx);
        } else {
          if (LOG.isDebugEnabled()) LOG.debug("Prefetch failed later: {} for {}", e, key, e);
          // Ignore
        }
      }

      @Override
      public void onSuccess(FetchResult result, ClientGetter state) {
        if (LOG.isDebugEnabled()) LOG.debug("Prefetch succeeded for {}", key);
        //noinspection EmptyTryBlock
        try (Bucket ignored = result.asBucket()) {
          // release via AutoCloseable
        }
        updateKnownGood(key, edition, ctx);
      }

      @Override
      public void onResume(ClientContext context) {
        // Do nothing. Not persistent.
      }

      @Override
      public RequestClient getRequestClient() {
        return rcBulk;
      }
    };
  }

  private ArrayList<USK> collectPrefetchTargetsLocked(long now) {
    ArrayList<USK> toFetch = null;
    for (Map.Entry<USK, Long> entry : temporaryBackgroundFetchersPrefetch.entrySet()) {
      Long last = entry.getValue();
      if (last > 0 && now - last >= PREFETCH_DELAY) {
        if (toFetch == null) toFetch = new ArrayList<>();
        USK clear = entry.getKey();
        long l = lookupLatestSlot(clear);
        if (lookupKnownGood(clear) < l) toFetch.add(clear.copy(l));
        entry.setValue(-1L); // Reset counter until new data comes in
      } else {
        if (LOG.isDebugEnabled()) LOG.debug("Not prefetching: {} : {}", entry.getKey(), last);
      }
    }
    return toFetch;
  }

  void updateKnownGood(final USK origUSK, final long number, final ClientContext context) {
    if (LOG.isDebugEnabled()) LOG.debug("Updating (known good) {} : {}", origUSK.getURI(), number);
    USK clear = origUSK.clearCopy();
    final USKCallback[] callbacks;
    boolean newSlot = false;
    synchronized (this) {
      Long l = latestKnownGoodByClearUSK.get(clear);
      if (LOG.isDebugEnabled()) LOG.debug("Old known good: {}", l);
      if ((l == null) || (number > l)) {
        l = number;
        latestKnownGoodByClearUSK.put(clear, l);
        if (LOG.isDebugEnabled()) LOG.debug(LOG_PUT, number);
      } else return; // If it's in KnownGood, it will also be in Slot

      l = latestSlotByClearUSK.get(clear);
      if (LOG.isDebugEnabled()) LOG.debug("Old slot: {}", l);
      if ((l == null) || (number > l)) {
        l = number;
        latestSlotByClearUSK.put(clear, l);
        if (LOG.isDebugEnabled()) LOG.debug(LOG_PUT, number);
        newSlot = true;
      }

      callbacks = subscribersByClearUSK.get(clear);
    }
    if (callbacks != null) {
      // Run off-thread, because of locking, and because client callbacks may take some time
      final USK usk = origUSK.copy(number);
      final boolean newSlotToo = newSlot;
      for (final USKCallback callback : callbacks)
        context
            .getMainExecutor()
            .execute(
                () ->
                    callback.onFoundEdition(
                        number,
                        usk, // non-persistent
                        context,
                        false,
                        (short) -1,
                        null,
                        true,
                        newSlotToo),
                "USKManager callback executor for " + callback);
    }
  }

  void updateSlot(final USK origUSK, final long number, final ClientContext context) {
    if (LOG.isDebugEnabled()) LOG.debug("Updating (slot) {} : {}", origUSK.getURI(), number);
    USK clear = origUSK.clearCopy();
    final USKCallback[] callbacks;
    synchronized (this) {
      Long l = latestSlotByClearUSK.get(clear);
      if (LOG.isDebugEnabled()) LOG.debug("Old slot: {}", l);
      if ((l == null) || (number > l)) {
        l = number;
        latestSlotByClearUSK.put(clear, l);
        if (LOG.isDebugEnabled()) LOG.debug(LOG_PUT, number);
      } else return;

      callbacks = subscribersByClearUSK.get(clear);
      temporaryBackgroundFetchersPrefetch.computeIfPresent(
          clear,
          (k, v) -> {
            schedulePrefetchChecker();
            return System.currentTimeMillis();
          });
    }
    if (callbacks != null) {
      // Run off-thread, because of locking, and because client callbacks may take some time
      final USK usk = origUSK.copy(number);
      for (final USKCallback callback : callbacks)
        context
            .getMainExecutor()
            .execute(
                () ->
                    callback.onFoundEdition(
                        number,
                        usk, // non-persistent
                        context,
                        false,
                        (short) -1,
                        null,
                        false,
                        false),
                "USKManager callback executor for " + callback);
    }
  }

  /**
   * Subscribe to a given USK, and poll it in the background, but only report new editions when
   * we've been through a round and are confident that we won't find more in the near future. Note
   * that it will ignore KnownGood, it only cares about latest slot.
   *
   * @param origUSK The USK to poll; sparse updates reduce bandwidth by batching notifications.
   * @param cb Callback notified when stable editions are discovered during polling rounds.
   * @param ignoreUSKDatehints If true, ignores date hints while probing for new editions.
   * @param client Request client used for scheduling; must be non-persistent in this context.
   * @return The proxy object which was actually subscribed. The caller MUST record this and pass it
   *     in to unsubscribe() when unsubscribing.
   */
  public USKSparseProxyCallback subscribeSparse(
      USK origUSK, USKCallback cb, boolean ignoreUSKDatehints, RequestClient client) {
    USKSparseProxyCallback proxy = new USKSparseProxyCallback(cb, origUSK);
    subscribe(origUSK, proxy, true, ignoreUSKDatehints, client);
    return proxy;
  }

  /**
   * Convenience overload for {@link #subscribeSparse(USK, USKCallback, boolean, RequestClient)}
   * that uses the default behavior for {@code ignoreUSKDatehints}.
   *
   * @param origUSK The USK to poll using sparse background updates.
   * @param cb Callback notified when stable editions are discovered during polling.
   * @param client Request client used for scheduling; must be non-persistent.
   * @return The proxy object that was actually subscribed. Retain it for unsubscription.
   */
  @SuppressWarnings("unused")
  public USKSparseProxyCallback subscribeSparse(USK origUSK, USKCallback cb, RequestClient client) {
    return subscribeSparse(origUSK, cb, false, client);
  }

  /**
   * Subscribes to a USK and optionally starts background polling for new editions.
   *
   * <p>When {@code runBackgroundFetch} is true a background fetcher is started. If {@code
   * ignoreUSKDatehints} is also true, date hints are ignored during probing. The callback is
   * invoked for discovered “known good” editions or when a newer slot becomes available.
   *
   * @param origUSK The USK to subscribe to; negative suggested editions are normalized to positive.
   * @param cb Callback receiving notifications about discovered editions and slots.
   * @param runBackgroundFetch When true, starts a long-lived background fetcher for the USK.
   * @param ignoreUSKDatehints If true, date hints are ignored by the background fetcher.
   * @param client Request client used to schedule polling; must not be persistent.
   */
  public void subscribe(
      USK origUSK,
      USKCallback cb,
      boolean runBackgroundFetch,
      boolean ignoreUSKDatehints,
      RequestClient client) {
    if (LOG.isDebugEnabled()) LOG.debug(LOG_SUBSCRIBING_TO_FOR, origUSK, cb);
    if (client.persistent())
      throw new UnsupportedOperationException("USKManager subscriptions cannot be persistent");
    long ed = origUSK.suggestedEdition;
    if (ed < 0) {
      LOG.error("Subscribing to USK with negative edition number: {}", ed);
      ed = -ed;
    }
    long curEd = lookupLatestSlot(origUSK);
    long goodEd = lookupKnownGood(origUSK);

    SubscribePlan plan =
        subscribeLocked(
            origUSK, cb, runBackgroundFetch, ignoreUSKDatehints, client, ed, curEd, goodEd);
    if (plan.earlyReturn) return;

    if (goodEd > ed)
      cb.onFoundEdition(
          goodEd, origUSK.copy(curEd), context, false, (short) -1, null, true, curEd > ed);
    else if (curEd > ed)
      cb.onFoundEdition(curEd, origUSK.copy(curEd), context, false, (short) -1, null, false, false);

    final USKFetcher fetcher = plan.toSchedule;
    if (fetcher != null) {
      executor.execute(
          () -> {
            if (LOG.isDebugEnabled()) LOG.debug("Starting {}", fetcher);
            fetcher.schedule(context);
          },
          "USKManager.schedule for " + fetcher);
    }
  }

  private record SubscribePlan(USKFetcher toSchedule, boolean earlyReturn) {}

  private synchronized SubscribePlan subscribeLocked(
      USK origUSK,
      USKCallback cb,
      boolean runBackgroundFetch,
      boolean ignoreUSKDatehints,
      RequestClient client,
      long ed,
      long curEd,
      long goodEd) {
    USK clear = origUSK.clearCopy();
    USKCallback[] callbacks = ensureSubscriberList(clear, cb, ed, curEd, goodEd);
    if (callbacks.length == 0) return new SubscribePlan(null, true);
    subscribersByClearUSK.put(clear, callbacks);

    USKFetcher toSchedule = null;
    if (runBackgroundFetch) {
      FetcherInfo info = ensureBackgroundFetcher(clear, origUSK, ignoreUSKDatehints, client);
      toSchedule = info.created ? info.fetcher : null;
      info.fetcher.addSubscriber(cb, origUSK.suggestedEdition);
    }

    return new SubscribePlan(toSchedule, false);
  }

  private USKCallback[] ensureSubscriberList(
      USK clear, USKCallback cb, long ed, long curEd, long goodEd) {
    USKCallback[] callbacks = subscribersByClearUSK.get(clear);
    if (callbacks == null) return new USKCallback[] {cb};
    boolean mustAdd = true;
    for (USKCallback callback : callbacks) {
      if (callback == cb) {
        if (!(curEd > ed || goodEd > ed)) return EMPTY_CALLBACKS;
        mustAdd = false;
      }
    }
    if (!mustAdd) return callbacks;
    USKCallback[] expanded = Arrays.copyOf(callbacks, callbacks.length + 1);
    expanded[expanded.length - 1] = cb;
    return expanded;
  }

  private static final USKCallback[] EMPTY_CALLBACKS = new USKCallback[0];

  private FetcherInfo ensureBackgroundFetcher(
      USK clear, USK origUSK, boolean ignoreUSKDatehints, RequestClient client) {
    USKFetcher f = backgroundFetchersByClearUSK.get(clear);
    if (f == null) {
      int options = USKFetcher.OPT_POLL_FOREVER;
      f =
          new USKFetcher(
              origUSK,
              this,
              ignoreUSKDatehints ? backgroundFetchContextIgnoreDBR : backgroundFetchContext,
              new USKFetcherWrapper(origUSK, RequestStarter.UPDATE_PRIORITY_CLASS, client),
              3,
              options);
      backgroundFetchersByClearUSK.put(clear, f);
      return new FetcherInfo(f, true);
    }
    return new FetcherInfo(f, false);
  }

  /**
   * Subscribes to a USK. Equivalent to calling {@link #subscribe(USK, USKCallback, boolean,
   * boolean, RequestClient)} with {@code ignoreUSKDatehints=false}.
   *
   * @param origUSK The USK to subscribe to.
   * @param cb Callback receiving notifications about discovered editions and slots.
   * @param runBackgroundFetch When true, starts a long-lived background fetcher for the USK.
   * @param client Request client used to schedule polling; must not be persistent.
   */
  public void subscribe(
      USK origUSK, USKCallback cb, boolean runBackgroundFetch, RequestClient client) {
    subscribe(origUSK, cb, runBackgroundFetch, false, client);
  }

  /**
   * Unsubscribes the given callback from updates related to the USK.
   *
   * <p>If a background fetcher remains with no subscribers it is cancelled; temporary background
   * fetchers are unaffected because they self-terminate.
   *
   * @param origUSK The USK to unsubscribe from.
   * @param cb The previously subscribed callback to remove.
   */
  public void unsubscribe(USK origUSK, USKCallback cb) {
    UnsubscribePlan plan = unsubscribeLocked(origUSK, cb);
    if (plan.notSubscribed) {
      if (LOG.isDebugEnabled()) LOG.debug("No longer subscribed");
      return;
    }
    if (plan.toCancel != null) {
      plan.toCancel.cancel(context);
    } else {
      if (LOG.isDebugEnabled()) LOG.debug("Not found unsubscribing: {} for {}", cb, origUSK);
    }
  }

  private record UnsubscribePlan(USKFetcher toCancel, boolean notSubscribed) {}

  private synchronized UnsubscribePlan unsubscribeLocked(USK origUSK, USKCallback cb) {
    USK clear = origUSK.clearCopy();
    USKCallback[] callbacks = subscribersByClearUSK.get(clear);
    if (callbacks == null) {
      return new UnsubscribePlan(null, true);
    }
    int j = 0;
    for (USKCallback c : callbacks) {
      if ((c != null) && (c != cb)) {
        callbacks[j++] = c;
      }
    }
    USKCallback[] newCallbacks = Arrays.copyOf(callbacks, j);
    if (newCallbacks.length > 0) subscribersByClearUSK.put(clear, newCallbacks);
    else subscribersByClearUSK.remove(clear);

    USKFetcher f = backgroundFetchersByClearUSK.get(clear);
    if (f != null) {
      f.removeSubscriber(cb);
      if (!f.hasSubscribers()) {
        backgroundFetchersByClearUSK.remove(clear);
        return new UnsubscribePlan(f, false);
      }
    }
    // Temporary background fetchers run once and then die. They do not care about callbacks.
    return new UnsubscribePlan(null, false);
  }

  /**
   * Subscribe to a USK. When it is updated, the content will be fetched (subject to the limits in
   * fctx), and returned to the callback. If we are asked to do a background fetch, we will only
   * fetch editions when we are fairly confident there are no more to fetch.
   *
   * @param origUSK The USK to poll for content updates.
   * @param cb Callback invoked when a new edition’s content is downloaded successfully.
   * @param runBackgroundFetch If true, starts a background fetcher that runs until unsubscribed;
   *     editions are downloaded conservatively using a sparse strategy.
   * @param fctx Fetch context used for content retrieval; polling itself does not use this.
   * @param prio Priority used for content requests; consult {@link RequestStarter} constants.
   * @param client Request client used to schedule both polling and content retrieval.
   * @return A retriever that represents the subscription and coordinates content downloading.
   */
  public USKRetriever subscribeContent(
      USK origUSK,
      USKRetrieverCallback cb,
      boolean runBackgroundFetch,
      FetchContext fctx,
      short prio,
      RequestClient client) {
    USKRetriever ret = new USKRetriever(fctx, prio, client, cb, origUSK);
    USKCallback toSub = ret;
    if (LOG.isDebugEnabled()) LOG.debug(LOG_SUBSCRIBING_TO_FOR, origUSK, cb);
    if (runBackgroundFetch) {
      USKSparseProxyCallback proxy = new USKSparseProxyCallback(ret, origUSK);
      ret.setProxy(proxy);
      toSub = proxy;
    }
    subscribe(origUSK, toSub, runBackgroundFetch, fctx.getIgnoreUSKDatehints(), client);
    return ret;
  }

  /**
   * Subscribes to a USK using a custom fetch context and without starting the default background
   * fetcher.
   *
   * <p>This method creates a dedicated {@link USKFetcher} wired to the supplied {@code fctx}. The
   * background fetcher is not started implicitly; callers manage the returned {@link USKRetriever}.
   *
   * @param origUSK The USK to poll for content updates.
   * @param cb Callback invoked when a new edition’s content is downloaded successfully.
   * @param fctx Custom fetch context applied to the internal fetcher.
   * @param prio Priority used for content requests; consult {@link RequestStarter} constants.
   * @param client Request client used to schedule polling and content retrieval.
   * @return A retriever that represents the subscription and coordinates content downloading.
   */
  @SuppressWarnings("unused")
  public USKRetriever subscribeContentCustom(
      USK origUSK, USKRetrieverCallback cb, FetchContext fctx, short prio, RequestClient client) {
    USKRetriever ret = new USKRetriever(fctx, prio, client, cb, origUSK);
    if (LOG.isDebugEnabled()) LOG.debug(LOG_SUBSCRIBING_TO_FOR, origUSK, cb);
    USKSparseProxyCallback proxy = new USKSparseProxyCallback(ret, origUSK);
    ret.setProxy(proxy);
    /* runBackgroundFetch=false -> ignoreUSKDatehints unused */
    subscribe(origUSK, proxy, false, client);
    int options = USKFetcher.OPT_POLL_FOREVER;
    USKFetcher f =
        new USKFetcher(
            origUSK, this, fctx, new USKFetcherWrapper(origUSK, prio, client), 3, options);
    ret.setFetcher(f);
    return ret;
  }

  /**
   * Cancels a content subscription and detaches any proxy created for sparse background fetching.
   *
   * <p>The {@code runBackgroundFetch} flag is logged diagnostically; the implementation
   * unsubscribes the retriever from this manager regardless of the flag value.
   *
   * @param origUSK The USK whose content subscription should be removed.
   * @param ret The retriever returned by {@code subscribeContent*}; used to perform unsubscription.
   * @param runBackgroundFetch Whether a background fetcher was running; used for logging context.
   */
  public void unsubscribeContent(USK origUSK, USKRetriever ret, boolean runBackgroundFetch) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(
          "unsubscribeContent runBackgroundFetch={} uskPresent={}",
          runBackgroundFetch,
          origUSK != null);
    }
    ret.unsubscribe(this);
  }

  /**
   * Returns the number of long-lived background fetchers keyed by clear USK.
   *
   * <p>Intended for operational visibility. Values fluctuate as subscriptions are added or removed.
   *
   * @return The count of active background fetchers currently tracked by this manager.
   */
  public int getBackgroundFetcherByUSKSize() {
    return backgroundFetchersByClearUSK.size();
  }

  /**
   * Returns the current size of the LRU that holds temporary background fetchers.
   *
   * <p>Intended for operational visibility. Temporary fetchers are trimmed when capacity limits are
   * exceeded and when no subscribers remain.
   *
   * @return The number of temporary background fetchers currently retained in the LRU.
   */
  public int getTemporaryBackgroundFetchersLRU() {
    return temporaryBackgroundFetchersLRU.size();
  }

  /**
   * Notifies the manager that a fetcher has finished and allows internal bookkeeping to remove it
   * from the appropriate maps.
   *
   * @param fetcher The fetcher that has completed; used to resolve the original USK and cleanup.
   */
  public void onFinished(USKFetcher fetcher) {
    onFinished(fetcher, false);
  }

  /**
   * Variant of {@link #onFinished(USKFetcher)} used when the completion follows a cancellation or
   * other non-error path and error logging should be suppressed.
   *
   * @param fetcher The fetcher that has completed; used to resolve the original USK and cleanup.
   * @param ignoreError When true, suppresses error logging if the fetcher was still registered.
   */
  public void onFinished(USKFetcher fetcher, boolean ignoreError) {
    USK orig = fetcher.getOriginalUSK();
    USK clear = orig.clearCopy();
    synchronized (this) {
      if (backgroundFetchersByClearUSK.get(clear) == fetcher) {
        backgroundFetchersByClearUSK.remove(clear);
        if (!ignoreError) {
          // This shouldn't happen, it's a sanity check: the only way we get cancelled is from
          // USKManager, which removes us before calling cancel().
          LOG.error(
              "onCancelled for {} - was still registered, how did this happen??",
              fetcher,
              new Exception("debug"));
        }
      }
      if (temporaryBackgroundFetchersLRU.get(clear) == fetcher) {
        temporaryBackgroundFetchersLRU.removeKey(clear);
        temporaryBackgroundFetchersPrefetch.remove(clear);
      }
    }
  }

  /**
   * Reports whether this manager is persistent across process restarts.
   *
   * @return Always {@code false}; all state is in-memory and transient by design.
   */
  public boolean persistent() {
    return false;
  }

  ClientContext getContext() {
    return context;
  }

  /**
   * Processes a USK/SSK observed elsewhere and updates slot/known-good trackers accordingly.
   *
   * <p>If {@code isMetadata} is false, the edition is marked known-good; otherwise only the slot is
   * updated because metadata presence does not imply payload fetchability.
   *
   * @param uri A USK or SSK URI from which the clear USK and edition are derived.
   * @param persistent Whether the originating request was persistent; used for tracing.
   * @param isMetadata True if the observation originated from metadata rather than content.
   */
  public void checkUSK(FreenetURI uri, boolean persistent, boolean isMetadata) {
    if (LOG.isTraceEnabled()) {
      LOG.trace("checkUSK persistent={}, isMetadata={}", persistent, isMetadata);
    }
    try {
      FreenetURI uu;
      if (uri.isSSK() && uri.isSSKForUSK()) {
        uu = uri.setMetaString(null).uskForSSK();
      } else if (uri.isUSK()) {
        uu = uri;
      } else {
        return;
      }
      USK usk = USK.create(uu);
      if (!isMetadata) context.uskManager.updateKnownGood(usk, uu.getSuggestedEdition(), context);
      else
        // We don't know whether the metadata is fetchable.
        // Consider adding a callback so if the rest of the request completes we updateKnownGood().
        context.uskManager.updateSlot(usk, uu.getSuggestedEdition(), context);
    } catch (MalformedURLException e) {
      LOG.error("Caught {}", e, e);
    } catch (Exception t) {
      // Don't let the USK hint cause us to not succeed on the block.
      LOG.error("Caught {}", t, t);
    }
  }
}
