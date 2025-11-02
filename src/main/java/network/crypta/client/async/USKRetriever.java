package network.crypta.client.async;

import java.io.*;
import java.net.MalformedURLException;
import java.util.List;
import network.crypta.client.ArchiveContext;
import network.crypta.client.ClientMetadata;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchResult;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.crypt.HashResult;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.USK;
import network.crypta.node.PrioRunnable;
import network.crypta.node.RequestClient;
import network.crypta.support.api.Bucket;
import network.crypta.support.compress.Compressor;
import network.crypta.support.compress.DecompressorThreadManager;
import network.crypta.support.io.InsufficientDiskSpaceException;
import network.crypta.support.io.NativeThread;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Polls a {@link USK} (Updatable Subspace Key) and, whenever a new edition is discovered, fetches
 * the corresponding content on behalf of a client.
 *
 * <p>This retriever acts as a small orchestrator that subscribes to USK updates, reacts when a
 * newer edition is announced, and then performs a single-file fetch of the concrete SSK that
 * represents that edition. The result is returned to the supplied callback together with the
 * edition token. The class is designed for short‑lived, non‑persistent use; it should not be stored
 * across process restarts.
 *
 * <p>Typical usage is to construct the retriever with a {@link FetchContext}, a priority and a
 * {@link RequestClient}, subscribe it through a {@code USKManager}, and wait for {@linkplain
 * #onFoundEdition(long, USK, ClientContext, boolean, short, byte[], boolean, boolean) edition
 * notifications}. When an edition equal to or newer than the requested one is seen, the retriever
 * schedules a {@code SingleFileFetcher} to download the data, decompresses it when needed, and
 * reports a {@link FetchResult} to the provided {@link USKRetrieverCallback}.
 *
 * <ul>
 *   <li>Thread safety: instances are not documented as thread‑safe. Callbacks are invoked on
 *       internal executors provided by the client context.
 *   <li>Lifecycle: the retriever is non‑persistent and must be unsubscribed explicitly when no
 *       longer needed.
 *   <li>Error handling: transient and permanent failures are surfaced through {@link
 *       #onFailure(FetchException, ClientGetState, ClientContext)} and logged with context.
 * </ul>
 */
public class USKRetriever extends BaseClientGetter implements USKCallback {
  private static final Logger LOG = LoggerFactory.getLogger(USKRetriever.class);
  private static final String LOG_CAUGHT = "Caught {}";

  @Serial private static final long serialVersionUID = 5913500655676487409L;

  /**
   * Context used for fetch operations initiated by this retriever. It defines limits such as
   * maximum output/temp sizes, retry policy and link filtering behavior. The instance is provided
   * by the caller and is not modified.
   */
  final FetchContext ctx;

  final transient USKRetrieverCallback cb;

  /**
   * The original USK supplied at construction time. This is the reference key used to determine the
   * minimum acceptable edition. It is not updated to reflect newly discovered editions; callers may
   * retrieve the value via {@link #getOriginalUSK()} to preserve the initial request semantics.
   */
  final USK origUSK;

  // In wierd
  /**
   * The USKCallback that is actually subscribed. This is used when we may be going through a
   * USKSparseProxyCallback.
   */
  private transient USKCallback proxy;

  /**
   * Alternatively, we may be driving a USKFetcher directly. This happens when the client subscribes
   * with a custom FetchContext.
   */
  private transient USKFetcher fetcher;

  /**
   * Creates a new retriever that will watch the supplied USK and fetch newly published editions
   * when discovered.
   *
   * <p>The retriever is explicitly non‑persistent. If a persistent {@link RequestClient} is
   * provided this constructor throws {@link UnsupportedOperationException}.
   *
   * @param fctx fetch configuration that defines size limits, retries and filtering; must remain
   *     valid for the lifetime of the retriever
   * @param prio request priority used when scheduling network activity; higher values generally
   *     indicate greater urgency
   * @param client the request client identity representing the caller; must be non‑persistent for
   *     this retriever type
   * @param cb callback invoked when an eligible edition is fetched successfully or when progress
   *     information is needed by the USK manager
   * @param origUSK the USK to monitor; its {@code suggestedEdition} sets the minimum edition that
   *     will be accepted and fetched
   */
  public USKRetriever(
      FetchContext fctx,
      short prio,
      final RequestClient client,
      USKRetrieverCallback cb,
      USK origUSK) {
    super(prio, client);
    if (client.persistent())
      throw new UnsupportedOperationException("USKRetriever cannot be persistent");
    this.ctx = fctx;
    this.cb = cb;
    this.origUSK = origUSK;
    this.proxy = this;
  }

  @Override
  public void onFoundEdition(
      long l,
      USK key,
      ClientContext context,
      boolean metadata,
      short codec,
      byte[] data,
      boolean newKnownGood,
      boolean newSlotToo) {
    if (l < 0) {
      LOG.error("Found negative edition: {} for {} !!!", l, key);
      return;
    }
    if (l < origUSK.suggestedEdition) {
      LOG.info("Found edition {} < requested {} for {}", l, origUSK.suggestedEdition, origUSK);
      return;
    }
    if (LOG.isDebugEnabled()) LOG.debug("Found edition {} for {} - fetching...", l, this);
    // Create a SingleFileFetcher for the key (as an SSK).
    // Put the edition number into its context object.
    // Put ourselves as callback.
    // Fetch it. If it fails, ignore it, if it succeeds, return the data with the edition # to the
    // client.
    FreenetURI uri = key.getSSK(l).getURI();
    try {
      SingleFileFetcher getter =
          (SingleFileFetcher)
              SingleFileFetcher.create(
                  this,
                  this,
                  uri,
                  ctx,
                  new ArchiveContext(ctx.maxTempLength, ctx.maxArchiveLevels),
                  ctx.maxNonSplitfileRetries,
                  0,
                  true,
                  l,
                  true,
                  false,
                  context,
                  realTimeFlag,
                  false);
      getter.schedule(context);
    } catch (MalformedURLException e) {
      LOG.error("Impossible: {}", e, e);
    } catch (FetchException e) {
      LOG.error("Could not start fetcher for {} : {}", uri, e, e);
    }
  }

  @Override
  public void onSuccess(
      StreamGenerator streamGenerator,
      ClientMetadata clientMetadata,
      List<? extends Compressor> decompressors,
      final ClientGetState state,
      ClientContext context) {
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Success on {} from {} : length {}mime type {}",
          this,
          state,
          streamGenerator.size(),
          clientMetadata.getMIMEType());
    DecompressorThreadManager decompressorManager;
    Bucket finalResult;
    long maxLen = Math.max(ctx.maxTempLength, ctx.maxOutputLength);
    try {
      finalResult = context.getBucketFactory(persistent()).makeBucket(maxLen);
    } catch (InsufficientDiskSpaceException e) {
      onFailure(new FetchException(FetchExceptionMode.NOT_ENOUGH_DISK_SPACE), state, context);
      return;
    } catch (IOException e) {
      LOG.error(LOG_CAUGHT, e, e);
      onFailure(new FetchException(FetchExceptionMode.BUCKET_ERROR, e), state, context);
      return;
    } catch (Exception e) {
      LOG.error(LOG_CAUGHT, e, e);
      onFailure(new FetchException(FetchExceptionMode.INTERNAL_ERROR, e), state, context);
      return;
    }

    try (OutputStream output = finalResult.getOutputStream()) {
      // Decompress
      if (decompressors != null) {
        if (LOG.isDebugEnabled()) LOG.debug("Decompressing...");
        try (PipedInputStream pipeIn = new PipedInputStream();
            PipedOutputStream pipeOut = new PipedOutputStream(pipeIn)) {
          decompressorManager = new DecompressorThreadManager(pipeIn, decompressors, maxLen);
          PipedInputStream decompressedInput = decompressorManager.execute();
          ClientGetWorkerThread worker =
              new ClientGetWorkerThread(
                  new BufferedInputStream(decompressedInput),
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
          awaitWorkerCompletion(worker);
        }
      } else {
        streamGenerator.writeTo(output, context);
      }
    } catch (IOException e) {
      LOG.error(LOG_CAUGHT, e, e);
      onFailure(new FetchException(FetchExceptionMode.INTERNAL_ERROR, e), state, context);
    } catch (Exception e) {
      LOG.error(LOG_CAUGHT, e, e);
      onFailure(new FetchException(FetchExceptionMode.INTERNAL_ERROR, e), state, context);
      return;
    }

    final FetchResult result = new FetchResult(clientMetadata, finalResult);
    context.uskManager.updateKnownGood(origUSK, state.getToken(), context);
    context
        .getMainExecutor()
        .execute(
            new PrioRunnable() {

              @Override
              public void run() {
                cb.onFound(origUSK, state.getToken(), result);
              }

              @Override
              public int getPriority() {
                return NativeThread.PriorityLevel.NORM_PRIORITY.value;
              }
            });
  }

  @Override
  public void onFailure(FetchException e, ClientGetState state, ClientContext context) {
    if (e.mode == FetchExceptionMode.NOT_ENOUGH_PATH_COMPONENTS
        || e.mode == FetchExceptionMode.PERMANENT_REDIRECT) {
      context.uskManager.updateKnownGood(origUSK, state.getToken(), context);
      return;
    }
    LOG.warn("Found edition {} but failed to fetch edition: {}", state.getToken(), e, e);
  }

  @Override
  public void onBlockSetFinished(ClientGetState state, ClientContext context) {
    // Ignore
  }

  /**
   * Returns the original {@link USK} supplied at construction time.
   *
   * <p>The returned object represents the caller’s initial request and is not updated as new
   * editions are discovered.
   *
   * @return the unmodified original USK that established the minimum edition threshold for this
   *     retriever’s activity
   */
  public USK getOriginalUSK() {
    return origUSK;
  }

  /**
   * Gets the URI form of the original {@link USK} that was supplied when this retriever was
   * created. It does not reflect later editions.
   *
   * @return the URI derived from the original USK used to seed the retrieval process
   */
  @Override
  public FreenetURI getURI() {
    // Return the original USK URI.
    return origUSK.getURI();
  }

  @Override
  public boolean isFinished() {
    return false;
  }

  @Override
  protected void innerNotifyClients(ClientContext context) {
    // Ignore for now
  }

  @Override
  public void onTransition(
      ClientGetState oldState, ClientGetState newState, ClientContext context) {
    // Ignore
  }

  @Override
  public void onExpectedMIME(ClientMetadata meta, ClientContext context) {
    // Ignore
  }

  @Override
  public void onExpectedSize(long size, ClientContext context) {
    // Ignore
  }

  @Override
  public void onFinalizedMetadata() {
    // Ignore
  }

  @Override
  public short getPollingPriorityNormal() {
    return cb.getPollingPriorityNormal();
  }

  @Override
  public short getPollingPriorityProgress() {
    return cb.getPollingPriorityProgress();
  }

  @Override
  public void cancel(ClientContext context) {
    super.cancel();
  }

  @Override
  protected void innerToNetwork(ClientContext context) {
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
      byte[] splitfileKey,
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

  /**
   * Called when we subscribe() in USKManager, if we don't directly subscribe the USKRetriever.
   * Usually this happens when we put a proxy between them, e.g. USKProxyCompletionCallback, which
   * hides updates for efficiency.
   *
   * @param cb The callback that is actually USKManager.subscribe()'ed.
   */
  synchronized void setProxy(USKCallback cb) {
    proxy = cb;
  }

  synchronized USKCallback getProxy() {
    return proxy;
  }

  synchronized void setFetcher(USKFetcher f) {
    fetcher = f;
  }

  synchronized USKFetcher getFetcher() {
    return fetcher;
  }

  /**
   * Unsubscribes this retriever from the given manager and cancels any active fetcher associated
   * with it.
   *
   * <p>After this call the retriever will no longer receive edition updates and will not schedule
   * further network activity.
   *
   * @param manager the manager from which the retriever should be detached; must be non‑null and
   *     correspond to the manager used for subscription
   */
  public void unsubscribe(USKManager manager) {
    USKFetcher f;
    USKCallback p;
    synchronized (this) {
      f = fetcher;
      p = proxy;
    }
    if (f != null) f.cancel(manager.getContext());
    if (p != null) manager.unsubscribe(origUSK, p);
  }

  /**
   * Adjusts polling parameters of the underlying USK fetcher.
   *
   * <p>This takes effect only when a fetcher has been installed via {@code setFetcher(...)} (for
   * example, when created through {@code USKManager.subscribeContentCustom()}).
   *
   * @param time the new cooldown interval between polling cycles, in milliseconds; values shorter
   *     than roughly 30 minutes are rejected
   * @param tries the number of attempts performed after each cooldown; must be greater than zero
   *     and less than three or an exception is thrown
   * @param context execution context used to apply the change; provides access to manager state and
   *     scheduling facilities and must be non‑null
   * @throws IllegalStateException if no fetcher has been associated with this instance via {@code
   *     setFetcher}
   */
  public void changeUSKPollParameters(long time, int tries, ClientContext context) {
    USKFetcher f;
    synchronized (this) {
      f = fetcher;
    }
    if (f == null) throw new IllegalStateException();
    f.changeUSKPollParameters(time, tries, context);
  }

  @Override
  public void innerOnResume(ClientContext context) {
    LOG.error("Cannot be persistent");
    // Do nothing. Cannot be persistent.
  }

  @Override
  protected ClientBaseCallback getCallback() {
    // Not persistent.
    return null;
  }

  private static void awaitWorkerCompletion(ClientGetWorkerThread worker) throws FetchException {
    try {
      worker.waitFinished();
    } catch (Throwable t) {
      throw new FetchException(FetchExceptionMode.INTERNAL_ERROR, t);
    }
  }

  @Override
  public boolean equals(Object other) {
    return super.equals(other);
  }

  @Override
  public int hashCode() {
    return super.hashCode();
  }
}
