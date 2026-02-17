package network.crypta.client.async;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serial;
import java.io.Serializable;
import java.util.List;
import network.crypta.client.ClientMetadata;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.client.Metadata;
import network.crypta.crypt.CRCChecksumChecker;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.crypt.ChecksumFailedException;
import network.crypta.keys.ClientCHKBlock;
import network.crypta.keys.FreenetURI;
import network.crypta.node.BaseSendableGet;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.FileUtil;
import network.crypta.support.io.InsufficientDiskSpaceException;
import network.crypta.support.io.PooledFileRandomAccessBuffer;
import network.crypta.support.io.ResumeFailedException;
import network.crypta.support.io.StorageFormatException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Fetches split files by keeping most state, especially downloaded blocks, in a single on‑disk
 * structure.
 *
 * <p>This implementation focuses on two goals. First, it minimizes disk seeks by co-locating data
 * that is produced and consumed together, avoiding the fragmentation and copying typical of
 * abstracted block stores. Second, it prioritizes robustness against moderate on‑disk corruption by
 * validating data where practical (for example, checking blocks against their expected CHKs). This
 * improves the odds of recovery during segment decoding and helps keep the design efficient even in
 * the presence of partial failures.
 *
 * <p>The companion {@code SplitFileFetcher*Storage} classes handle persistence of the raw data and
 * forward‑error‑correction (FEC) decoding. This class coordinates the higher‑level lifecycle:
 * selecting and scheduling keys to fetch, reacting to block arrivals and failures, and driving
 * completion callbacks. It is designed for predictable disk usage until completion and to isolate
 * state per split file.
 *
 * <p><strong>Locking:</strong> synchronize on {@code this} last; it is used by {@link
 * SplitFileFetcherGet#isCancelled()} and other callbacks.
 *
 * <ul>
 *   <li>Responsibilities: orchestration and progress reporting; scheduling and cooldown control.
 *   <li>Notable behaviors: optional completion via file truncation; resumable after corruption.
 *   <li>Thread-safety: external methods may be called from multiple threads; internal state changes
 *       are synchronized where necessary, and long‑running work is delegated to schedulers.
 * </ul>
 *
 * @author toad
 * @see SplitFileFetcherStorage
 * @see SplitFileFetcherGet
 * @see FetchContext
 */
public final class SplitFileFetcher
    implements ClientGetState, SplitFileFetcherStorageCallback, Serializable {
  private static final Logger LOG = LoggerFactory.getLogger(SplitFileFetcher.class);
  @Serial private static final long serialVersionUID = 1L;

  /** Simple holder for completion-via-truncation configuration. */
  private record TruncationConfig(FileGetCompletionCallback callback, File tempFile) {}

  /**
   * Stores the progress of the download, including the actual data, in a separate file. Created in
   * onResume() or in the constructor, so must be volatile.
   */
  @SuppressWarnings("java:S3077")
  private transient volatile SplitFileFetcherStorage storage;

  /**
   * Backing random access buffer for the active download state, enabling resume without scanning
   * all data structures. The buffer instance is supplied by the storage layer and is valid until
   * shutdown or cancellation.
   */
  private transient LockableRandomAccessBuffer raf;

  /**
   * Request owner providing user‑level callbacks, priority, and cancellation checks. Methods on the
   * parent may be invoked from different threads but are expected to be thread‑safe.
   */
  final ClientRequester parent;

  /**
   * Primary completion callback for non‑truncation paths. The callback receives a streaming
   * generator when the split file is fully reconstructed or an error with context on failure.
   */
  final transient GetCompletionCallback cb;

  /** If non-null, we will complete via truncation. */
  final transient FileGetCompletionCallback callbackCompleteViaTruncation;

  /**
   * Temporary output file used when completing by truncation. When non‑null, storage writes into
   * this file and truncates to the final length before the callback consumes it.
   */
  final File fileCompleteViaTruncation;

  /** True when the request uses real‑time scheduling semantics in the fetch scheduler. */
  final boolean realTimeFlag;

  /**
   * Fetch context specialized for splitfile block retrieval. It determines routing, retry policy,
   * and whether only local sources are permitted.
   */
  final FetchContext blockFetchContext;

  /** Opaque token used to correlate client requests and progress notifications. */
  final long token;

  /** The original request key for logging and provenance; may be {@code null} on resume. */
  private final FreenetURI requestKey;

  /** Storage doesn't have a ClientContext so we need one here. */
  private transient ClientContext context;

  /**
   * Issues actual block requests and manages registration with the sending layer. It is created in
   * the constructor or during {@link #onResume(ClientContext)} and may outlive intermediate
   * failures. Volatile for safe visibility across threads.
   */
  @SuppressWarnings("java:S3077")
  private transient volatile SplitFileFetcherGet getter;

  /** Indicates that the fetch has failed permanently and callbacks have been informed. */
  private boolean failed;

  /** Set when completion was signaled successfully; prevents duplicate notifications. */
  private boolean succeeded;

  /** Whether the parent wants keys collected into a binary blob during fetching. */
  private final boolean wantBinaryBlob;

  /** True, when the fetcher and on‑disk state should survive node restarts. */
  private final boolean persistent;

  static final class InitParams {
    Metadata metadata;
    GetCompletionCallback rcb;
    ClientRequester parent;
    FetchContext fetchContext;
    boolean realTimeFlag;
    List<COMPRESSOR_TYPE> decompressors;
    ClientMetadata clientMetadata;
    long token;
    boolean topDontCompress;
    short topCompatibilityMode;
    boolean persistent;
    FreenetURI thisKey;
    boolean isFinalFetch;
    ClientContext context;
  }

  SplitFileFetcher(InitParams p) throws FetchException {
    this.persistent = p.persistent;
    this.cb = p.rcb;
    this.parent = p.parent;
    this.realTimeFlag = p.realTimeFlag;
    this.token = p.token;
    this.context = p.context;
    this.requestKey = p.thisKey;
    if (parent instanceof ClientGetter clientGetter) {
      wantBinaryBlob = clientGetter.collectingBinaryBlob();
    } else {
      wantBinaryBlob = false;
    }
    blockFetchContext =
        new FetchContext(p.fetchContext, FetchContext.SPLITFILE_DEFAULT_BLOCK_MASK, true, null);
    if (parent.isCancelled()) throw new FetchException(FetchExceptionMode.CANCELLED);

    try {
      TruncationConfig trunc =
          prepareTruncation(p.isFinalFetch, cb, p.decompressors, p.fetchContext);
      callbackCompleteViaTruncation = trunc.callback();
      fileCompleteViaTruncation = trunc.tempFile();

      storage = buildStorage(p, fileCompleteViaTruncation);
    } catch (InsufficientDiskSpaceException _) {
      throw new FetchException(FetchExceptionMode.NOT_ENOUGH_DISK_SPACE);
    } catch (IOException e) {
      throw new FetchException(FetchExceptionMode.BUCKET_ERROR, e);
    }
    notifyExpectedSizeAndMetadata(p.metadata, p.clientMetadata, p.fetchContext);
    getter = new SplitFileFetcherGet(this, storage);
    raf = storage.getRAF();
    logCreated();
    lastNotifiedStoreFetch = System.currentTimeMillis();
  }

  private void logCreated() {
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Created {} download for {} on {} for {}",
          persistent ? "persistent" : "transient",
          requestKey,
          raf,
          this);
    }
  }

  private void notifyExpectedSizeAndMetadata(
      Metadata metadata, ClientMetadata clientMetadata, FetchContext fetchContext)
      throws FetchException {
    long eventualLength = Math.max(storage.decompressedLength, metadata.uncompressedDataLength());
    cb.onExpectedSize(eventualLength, context);
    if (metadata.uncompressedDataLength() > 0) cb.onFinalizedMetadata();
    if (eventualLength > 0
        && fetchContext.getMaxOutputLength() > 0
        && eventualLength > fetchContext.getMaxOutputLength()) {
      throw new FetchException(
          FetchExceptionMode.TOO_BIG, eventualLength, true, clientMetadata.getMIMEType());
    }
  }

  private TruncationConfig prepareTruncation(
      boolean isFinalFetch,
      GetCompletionCallback cb,
      List<COMPRESSOR_TYPE> decompressors,
      FetchContext fetchContext)
      throws IOException {
    if (isFinalFetch
        && cb instanceof FileGetCompletionCallback fileCallback
        && (decompressors == null || decompressors.isEmpty())
        && !fetchContext.getFilterData()) {
      File targetFile = fileCallback.getCompletionFile();
      if (targetFile != null) {
        File tmp =
            FileUtil.createTempFile(
                targetFile.getName(), ".freenet-tmp", targetFile.getParentFile());
        return new TruncationConfig(fileCallback, tmp);
      }
    }
    return new TruncationConfig(null, null);
  }

  private SplitFileFetcherStorage buildStorage(InitParams params, File fileCompleteViaTruncation)
      throws IOException, FetchException {
    ChecksumChecker checker = new CRCChecksumChecker();
    return new SplitFileFetcherStorage(
        new SplitFileFetcherStorageInitParams.Builder()
            .metadata(params.metadata)
            .fetcher(this)
            .decompressors(params.decompressors)
            .clientMetadata(params.clientMetadata)
            .topDontCompress(params.topDontCompress)
            .topCompatibilityMode(params.topCompatibilityMode)
            .fetchContext(params.fetchContext)
            .salt(getSalter())
            .thisKey(requestKey)
            .origKey(parent.getURI())
            .isFinalFetch(params.isFinalFetch)
            .clientDetails(parent.getClientDetail(checker))
            .random(context.random)
            .tempBucketFactory(context.tempBucketFactory)
            .rafFactory(persistent ? context.persistentRAFFactory : context.tempRAFFactory)
            .exec(context.getJobRunner(persistent))
            .ticker(context.ticker)
            .memoryLimitedJobRunner(context.memoryLimitedJobRunner)
            .checker(checker)
            .persistent(persistent)
            .storageFile(fileCompleteViaTruncation)
            .diskSpaceCheckingRAFFactory(context.getFileRandomAccessBufferFactory(persistent))
            .keysFetching(context.getChkFetchScheduler(realTimeFlag).fetchingKeys())
            .build());
  }

  /**
   * Serialization-only constructor used by the persistence layer. It does not establish a working
   * fetcher instance; callers must invoke {@link #onResume(ClientContext)} to reattach runtime
   * resources and resume operation. Do not call directly in regular code.
   */
  SplitFileFetcher() {
    // For serialization only.
    parent = null;
    cb = null;
    realTimeFlag = false;
    blockFetchContext = null;
    token = 0;
    requestKey = null;
    wantBinaryBlob = false;
    persistent = true;
    callbackCompleteViaTruncation = null;
    fileCompleteViaTruncation = null;
  }

  @Serial
  private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    this.raf = null;
    this.getter = null;
  }

  /**
   * Schedules initial fetching work with the underlying sendable getter and storage.
   *
   * <p>If storage signals readiness (for example, after probing the local store), this method
   * delegates to {@link SplitFileFetcherGet#schedule(ClientContext, boolean)} to register the
   * request and begin or continue downloading. Calling this method repeatedly is safe; scheduling
   * will only proceed when appropriate.
   *
   * @param context runtime services and schedulers needed to register the request and perform work
   */
  @Override
  public void schedule(ClientContext context) {
    if (storage.start(false)) getter.schedule(context, false);
  }

  /**
   * Fail the whole splitfile request when we get an IOException on writing to or reading from the
   * on-disk storage. Can be called asynchronously by SplitFileFetcher*Storage if an off-thread job
   * (e.g., FEC decoding) breaks, or may be called when SplitFileFetcher*Storage throws.
   *
   * @param e The IOException, generated when accessing the on-disk storage.
   */
  @Override
  public void failOnDiskError(IOException e) {
    fail(new FetchException(FetchExceptionMode.BUCKET_ERROR));
  }

  /**
   * Fails the request when on‑disk corruption is detected and cannot be recovered cheaply.
   *
   * @param e checksum failure raised by the storage layer while reading or validating persisted
   *     state that is required to continue fetching
   */
  @Override
  public void failOnDiskError(ChecksumFailedException e) {
    fail(new FetchException(FetchExceptionMode.BUCKET_ERROR));
  }

  /**
   * Moves the fetcher to a terminal failed state, cancelling any pending work and notifying the
   * client callback exactly once.
   *
   * <p>Subsequent invocations are ignored. Any pending keys are removed from the scheduler, the
   * sendable getter is canceled, and storage is asked to cancel outstanding jobs. The provided
   * exception is delivered to the client with context.
   *
   * @param e reason for failure to report to the client; must not be {@code null}
   */
  @Override
  public void fail(FetchException e) {
    synchronized (this) {
      if (succeeded || failed) return;
      failed = true;
    }
    if (storage != null)
      context.getChkFetchScheduler(realTimeFlag).removePendingKeys(storage.keyListener, true);
    if (getter != null) getter.cancel(context);
    if (storage != null) storage.cancel();
    cb.onFailure(e, this, context);
  }

  /**
   * Cancels the request at the client’s direction and reports a canceled failure to listeners.
   *
   * <p>Cancellation is treated as a terminal state. Any scheduled work is withdrawn and storage
   * cleanup is initiated. The callback receives a {@link FetchExceptionMode#CANCELLED} result.
   *
   * @param context runtime services used during cancellation
   */
  @Override
  public void cancel(ClientContext context) {
    fail(new FetchException(FetchExceptionMode.CANCELLED));
  }

  /**
   * Returns the opaque token associated with this request.
   *
   * @return an application‑defined token useful for correlating progress and completion events
   */
  @Override
  public long getToken() {
    return token;
  }

  /**
   * The splitfile download succeeded. Generate a stream and send it to the GetCompletionCallback.
   * See bug #6063 for a better way that probably is too much complexity for the benefit.
   */
  @Override
  public void onSuccess() {
    boolean fail = false;
    synchronized (this) {
      if (failed) {
        fail = true;
      } else {
        if (succeeded) {
          LOG.warn("Called onSuccess() twice on {}", this);
          return;
        } else {
          if (LOG.isDebugEnabled()) LOG.debug("onSuccess() on {}", this);
        }
        succeeded = true;
      }
    }
    if (fail) {
      storage.finishedFetcher();
      return;
    }
    context.getChkFetchScheduler(realTimeFlag).removePendingKeys(storage.keyListener, true);
    getter.cancel(context);
    if (this.callbackCompleteViaTruncation != null) {
      long finalLength = storage.finalLength;
      this.callbackCompleteViaTruncation.onSuccess(
          fileCompleteViaTruncation, finalLength, storage.clientMetadata, this, context);
      // Don't need to call storage.finishedFetcher().
    } else {
      cb.onSuccess(
          storage.streamGenerator(), storage.clientMetadata, storage.decompressors, this, context);
      storage.finishedFetcher();
    }
  }

  /**
   * Called when the underlying stream is closed. No action is required here because completion is
   * coordinated by {@link #onSuccess()} and failure paths.
   */
  @Override
  public void onClosed() {
    // No-op.
  }

  /**
   * Returns the priority class propagated from the parent requester.
   *
   * <p>The value is used by schedulers to order work relative to other requests.
   *
   * @return a priority identifier; higher values may imply lower scheduling priority
   */
  @Override
  public short getPriorityClass() {
    return this.parent.getPriorityClass();
  }

  /**
   * Updates the parent with the number of blocks required to complete and those remaining to fetch.
   *
   * @param requiredBlocks blocks that must be successfully decoded for the current segment or file
   * @param remainingBlocks total blocks still outstanding, including redundancy and store lookups
   */
  @Override
  public void setSplitfileBlocks(int requiredBlocks, int remainingBlocks) {
    parent.addMustSucceedBlocks(requiredBlocks);
    parent.addBlocks(remainingBlocks);
    parent.notifyClients(context);
  }

  /**
   * Notifies listeners of the determined splitfile compatibility parameters once known.
   *
   * @param min lowest supported compatibility mode observed in the stream
   * @param max highest supported compatibility mode observed in the stream
   * @param customSplitfileKey optional custom key; may be {@code null} if not in use
   * @param compressed whether the splitfile is compressed at this layer
   * @param bottomLayer {@code true} if this pertains to the bottom layer
   * @param definitiveAnyway {@code true} if the metadata is definitive despite partial information
   */
  @Override
  public void onSplitfileCompatibilityMode(
      CompatibilityMode min,
      CompatibilityMode max,
      byte[] customSplitfileKey,
      boolean compressed,
      boolean bottomLayer,
      boolean definitiveAnyway) {
    cb.onSplitfileCompatibilityMode(
        min, max, customSplitfileKey, compressed, bottomLayer, definitiveAnyway, context);
  }

  /**
   * Queues a healing block for persistence so future requests can benefit from local recovery.
   *
   * <p>Errors while enqueuing are logged and otherwise ignored; they do not impact the current
   * request’s outcome.
   *
   * @param data full healing block payload; the method takes ownership for persistence
   * @param cryptoKey key associated with the block for later verification or use
   * @param cryptoAlgorithm algorithm identifier for interpreting {@code cryptoKey}
   */
  @Override
  public void queueHeal(byte[] data, byte[] cryptoKey, byte cryptoAlgorithm) {
    try {
      Bucket dataBucket = BucketTools.makeImmutableBucket(context.tempBucketFactory, data);
      context.healingQueue.queue(dataBucket, cryptoKey, cryptoAlgorithm, context);
    } catch (IOException e) {
      // Nothing to be done, but need to log the error.
      LOG.error("I/O error, failed to queue healing block: {}", e, e);
    }
  }

  /**
   * Indicates whether this fetch should use only local sources when requesting blocks.
   *
   * <p>When {@code true}, network traffic is avoided and only on-disk or otherwise local caches are
   * consulted. This may reduce coverage and increase the chance of partial results.
   *
   * @return {@code true} when remote network requests are disabled for block retrieval
   */
  public boolean localRequestOnly() {
    return blockFetchContext.getLocalRequestOnly();
  }

  /**
   * Transitions the request to allow network access if previously restricted.
   *
   * <p>Clients typically call this after an initial local‑only pass to broaden the search. The
   * parent requester coordinates the actual scheduling changes.
   */
  public void toNetwork() {
    parent.toNetwork(context);
  }

  /**
   * Reports whether the fetcher has reached a terminal state (success or failure).
   *
   * <p>The result is idempotent and can be polled by user interfaces to update progress indicators
   * without subscribing to callbacks.
   *
   * @return {@code true} once either {@link #onSuccess()} or {@link #fail(FetchException)} occurred
   */
  public synchronized boolean hasFinished() {
    return failed || succeeded;
  }

  /** Incremented whenever we fetch a block from the store */
  private int storeFetchCounter;

  /** Time when we last passed through a block fetch from the store */
  private long lastNotifiedStoreFetch;

  static final int STORE_NOTIFY_BLOCKS = 100;
  static final long STORE_NOTIFY_INTERVAL = 200;

  /**
   * Reports a successfully retrieved or found block and notifies the parent while rate‑limiting UI
   * updates to avoid excessive churn.
   */
  @Override
  public void onFetchedBlock() {
    boolean dontNotify = true;
    if (getter.hasQueued()) {
      dontNotify = false;
    } else {
      synchronized (this) {
        if (storeFetchCounter++ == STORE_NOTIFY_BLOCKS) {
          storeFetchCounter = 0;
          dontNotify = false;
          lastNotifiedStoreFetch = System.currentTimeMillis();
        } else {
          long now = System.currentTimeMillis();
          if (now - lastNotifiedStoreFetch >= STORE_NOTIFY_INTERVAL) {
            dontNotify = false;
            lastNotifiedStoreFetch = now;
          }
        }
      }
    }
    parent.completedBlock(dontNotify, context);
  }

  /** Reports that block retrieval failed so the parent can update progress. */
  @Override
  public void onFailedBlock() {
    parent.failedBlock(context);
  }

  /**
   * Restores high‑level progress counters and notifies the client of expected metadata after a
   * storage resuming.
   *
   * @param succeededBlocks number of blocks already completed at resume time
   * @param failedBlocks number of blocks known to have failed at resume time
   * @param meta client‑visible metadata inferred from the splitfile structure
   * @param finalSize expected decompressed size when known; {@code 0} if unknown
   */
  @Override
  public void onResume(int succeededBlocks, int failedBlocks, ClientMetadata meta, long finalSize) {
    for (int i = 0; i < succeededBlocks - 1; i++) parent.completedBlock(true, context);
    if (succeededBlocks > 0) parent.completedBlock(false, context);
    for (int i = 0; i < failedBlocks - 1; i++) parent.failedBlock(true, context);
    if (failedBlocks > 0) parent.failedBlock(false, context);
    parent.blockSetFinalized(context);
    try {
      cb.onExpectedMIME(meta, context);
    } catch (FetchException e) {
      fail(e);
      return;
    }
    cb.onExpectedSize(finalSize, context);
  }

  /**
   * Adds a block to the parent’s binary blob collector when that mode is enabled.
   *
   * @param block block descriptor representing a fetched CHK
   */
  @Override
  public void maybeAddToBinaryBlob(ClientCHKBlock block) {
    if (parent instanceof ClientGetter clientGetter) {
      clientGetter.addKeyToBinaryBlob(block, context);
    }
  }

  @Override
  public boolean wantBinaryBlob() {
    return wantBinaryBlob;
  }

  /**
   * Returns the active sendable getter responsible for issuing network requests.
   *
   * @return a non‑null handle to the request engine backing this fetcher
   */
  @Override
  public BaseSendableGet getSendableGet() {
    return getter;
  }

  /**
   * Re‑registers the request after storage reported data corruption and a reset took place.
   *
   * <p>The getter is unregistered and re‑scheduled so that additional blocks can be requested; some
   * may be satisfied from the local store.
   */
  @Override
  public void restartedAfterDataCorruption() {
    if (hasFinished()) return;
    LOG.error("Restarting download {} after data corruption", this);
    // We need to fetch more blocks. Some of them may even be in the datastore.
    getter.unregister(context, getPriorityClass());
    getter.schedule(context, false);
    context.jobRunner.setCheckpointASAP();
  }

  /** Clears any wakeup delay so pending work can be considered immediately by the scheduler. */
  @Override
  public void clearCooldown() {
    if (hasFinished()) return;
    getter.clearWakeupTime(context);
  }

  /**
   * Lowers the scheduled wakeup time to the given value if it wakes the request earlier.
   *
   * @param wakeupTime target absolute time (milliseconds since epoch) to consider work again
   */
  @Override
  public void reduceCooldown(long wakeupTime) {
    getter.reduceWakeupTime(wakeupTime, context);
  }

  /**
   * Exposes a key‑presence listener used by schedulers to notify about available blocks.
   *
   * @return a listener adapter backed by the current {@link #getSendableGet()}
   */
  @Override
  public HasKeyListener getHasKeyListener() {
    return (HasKeyListener) getSendableGet();
  }

  /**
   * Reattaches resources and reconstructs storage and scheduling state after a persisted resuming.
   *
   * <p>On success the getter is recreated and, if storage indicates readiness, the request is
   * scheduled using the stored knowledge of blocks present in the local store. Errors from invalid
   * storage or missing resources are converted to a {@link FetchException}.
   *
   * @param context runtime context to provide factories, schedulers, and randomness
   * @throws FetchException if storage cannot be resumed or prerequisite resources are unavailable
   */
  @Override
  public void onResume(ClientContext context) throws FetchException {
    if (LOG.isDebugEnabled()) LOG.debug("Restarting SplitFileFetcher from storage...");
    boolean resumed = parent instanceof ClientGetter cg && cg.resumedFetcher();
    this.context = context;
    try {
      raf.onResume(context);
      this.storage =
          new SplitFileFetcherStorage(
              new SplitFileFetcherStorageResumeParams.Builder()
                  .raf(raf)
                  .callback(this)
                  .context(blockFetchContext)
                  .random(context.random)
                  .exec(context.jobRunner)
                  .keysFetching(context.getChkFetchScheduler(realTimeFlag).fetchingKeys())
                  .ticker(context.ticker)
                  .memoryLimitedJobRunner(context.memoryLimitedJobRunner)
                  .checker(new CRCChecksumChecker())
                  .newSalt(context.jobRunner.newSalt())
                  .completeViaTruncation(callbackCompleteViaTruncation != null)
                  .build());
    } catch (ResumeFailedException | IOException e) {
      raf.free();
      throw new FetchException(FetchExceptionMode.BUCKET_ERROR, e);
    } catch (StorageFormatException e) {
      raf.free();
      throw new FetchException(FetchExceptionMode.INTERNAL_ERROR, "Resume failed: " + e, e);
    } catch (FetchException e) {
      raf.free();
      throw e;
    }
    synchronized (this) {
      lastNotifiedStoreFetch = System.currentTimeMillis();
    }
    getter = new SplitFileFetcherGet(this, storage);
    if (storage.start(resumed)) {
      getter.schedule(context, storage.hasCheckedStore());
    }
  }

  /**
   * Returns the key salter used to decorrelate requests as determined by the global scheduler.
   *
   * @return a stable salter instance appropriate for the {@link #persistent} policy
   */
  @Override
  public KeySalter getSalter() {
    return context.getChkFetchScheduler(realTimeFlag).getGlobalKeySalter(persistent);
  }

  /**
   * Writes a compact snapshot of progress sufficient to resume the fetcher later.
   *
   * <p>The format records whether truncation is used, how to locate the storage, and a token for
   * correlation. Callers should only invoke this while the fetch is active.
   *
   * @param dos output stream that will receive the snapshot; must remain writable for the entire
   *     operation and is not closed by this method
   * @return {@code true} when progress was written because the fetch is ongoing; {@code false} when
   *     the fetch has already finished and no snapshot is produced
   * @throws IOException if writing to the provided stream fails for any reason, including short
   *     writes or storage I/O errors
   */
  public boolean writeTrivialProgress(DataOutputStream dos) throws IOException {
    boolean done;
    synchronized (this) {
      done = failed || succeeded;
    }
    if (done) {
      dos.writeBoolean(false);
      return false;
    }
    dos.writeBoolean(true);
    if (callbackCompleteViaTruncation == null) {
      dos.writeBoolean(false);
      raf.storeTo(dos);
    } else {
      dos.writeBoolean(true);
      dos.writeUTF(fileCompleteViaTruncation.toString());
      dos.writeLong(raf.size());
    }
    dos.writeLong(token);
    return true;
  }

  /**
   * Reconstructs a fetcher from a previously persisted snapshot created by {@link
   * #writeTrivialProgress(DataOutputStream)}.
   *
   * <p>This constructor validates the presence and size of any backing file used for completion by
   * truncation and restores the random access buffer or file reference accordingly. After
   * construction, callers must invoke {@link #onResume(ClientContext)} to bind runtime services and
   * continue the download.
   *
   * @param getter parent/get callback that owns this fetcher and will receive progress updates;
   *     must be non‑null and consistent with the snapshot
   * @param dis input stream positioned at the snapshot written by {@link
   *     #writeTrivialProgress(DataOutputStream)}; the stream is consumed but not closed here
   * @param context client context providing factories, schedulers, and secrets required to restore
   *     storage and register callbacks
   * @throws StorageFormatException when the snapshot is structurally invalid or references cannot
   *     be interpreted for this build
   * @throws ResumeFailedException if referenced files are missing, have unexpected length, or
   *     cannot be safely reopened for random access
   * @throws IOException if reading the snapshot fails due to I/O problems on the input stream
   */
  public SplitFileFetcher(ClientGetter getter, DataInputStream dis, ClientContext context)
      throws StorageFormatException, ResumeFailedException, IOException {
    LOG.info("Resuming splitfile download for {}", this);
    boolean completeViaTruncation = dis.readBoolean();
    if (completeViaTruncation) {
      fileCompleteViaTruncation = new File(dis.readUTF());
      if (!fileCompleteViaTruncation.exists())
        throw new ResumeFailedException(
            "Storage file does not exist: " + fileCompleteViaTruncation);
      callbackCompleteViaTruncation = getter;
      long rafSize = dis.readLong();
      if (fileCompleteViaTruncation.length() != rafSize)
        throw new ResumeFailedException("Storage file is not of the correct length");
      // Note: Could verify against finalLength to finish immediately if it matches.
      this.raf =
          new PooledFileRandomAccessBuffer(fileCompleteViaTruncation, false, rafSize, -1, true);
    } else {
      this.raf =
          BucketTools.restoreRAFFrom(
              dis,
              context.persistentFG,
              context.getPersistentFileTracker(),
              context.getPersistentMasterSecret());
      fileCompleteViaTruncation = null;
      callbackCompleteViaTruncation = null;
    }
    this.parent = getter;
    this.cb = getter;
    this.persistent = true;
    this.realTimeFlag = parent.realTimeFlag();
    this.requestKey = null;
    token = dis.readLong();
    this.blockFetchContext = getter.ctx;
    this.wantBinaryBlob = getter.collectingBinaryBlob();
    // onResume() will do the rest.
    LOG.info("Resumed splitfile download for {}", this);
    lastNotifiedStoreFetch = System.currentTimeMillis();
  }

  /**
   * Signals shutdown so that background jobs and file handles can be released in an orderly way.
   *
   * @param context client context providing any additional services needed for a clean shutdown
   */
  @Override
  public void onShutdown(ClientContext context) {
    storage.onShutdown(context);
  }
}
