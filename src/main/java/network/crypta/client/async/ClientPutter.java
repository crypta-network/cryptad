package network.crypta.client.async;

import java.io.IOException;
import java.io.Serial;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import network.crypta.client.ClientMetadata;
import network.crypta.client.InsertBlock;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.client.InsertException;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.Metadata;
import network.crypta.client.events.SendingToNetworkEvent;
import network.crypta.client.events.SplitfileProgressCounts;
import network.crypta.client.events.SplitfileProgressEvent;
import network.crypta.client.events.SplitfileProgressTimestamps;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.keys.BaseClientKey;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.Key;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.ResumeFailedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * High-level client-side inserter for publishing data to the network.
 *
 * <p>This class coordinates the full lifecycle of a user-initiated insert, including building the
 * appropriate {@code ClientPutState}, scheduling work on the client request schedulers, tracking
 * progress and failures, and notifying a {@link ClientPutCallback} as key milestones occur. It
 * supports inserting single files as splitfiles, optional manifest metadata with a target filename,
 * and an alternative binary-blob flow used by specific protocols. Callers typically construct a
 * {@code ClientPutter} with the data source ({@link RandomAccessBucket}), a target {@link
 * FreenetURI}, client-visible {@link ClientMetadata}, and an {@link InsertContext}, and then invoke
 * {@link #start(ClientContext)} or {@link #start(boolean, ClientContext)}.
 *
 * <p>Typical usage is one-shot: create, start, and wait for callbacks. Instances are restartable
 * via {@link #restart(ClientContext)} when supported by the underlying state. The class is stateful
 * and not thread-safe for concurrent external mutation; callers should synchronize externally if
 * multiple threads may call lifecycle methods. Internally, short synchronized blocks protect state
 * transitions to avoid races between cancellation, restart, and progress updates. Once finished
 * (success or failure), the instance will not schedule further work unless explicitly restarted.
 *
 * <ul>
 *   <li>Generates and reports the final URI as soon as it is known.
 *   <li>Optionally returns compact metadata instead of a URI below a size threshold.
 *   <li>Accounts for successful/failed blocks and emits progress events for observers.
 *   <li>Supports randomized splitfile keys depending on {@link InsertContext.CompatibilityMode}.
 * </ul>
 *
 * @see BaseClientPutter
 * @see ClientPutCallback
 * @see InsertContext
 */
public class ClientPutter extends BaseClientPutter implements PutCompletionCallback {
  private static final Logger LOG = LoggerFactory.getLogger(ClientPutter.class);
  private static final AtomicIntegerFieldUpdater<ClientPutter> MIN_SUCCESS_FETCH_BLOCKS_UPDATER =
      AtomicIntegerFieldUpdater.newUpdater(ClientPutter.class, "minSuccessFetchBlocks");

  @Serial private static final long serialVersionUID = 2L;

  /**
   * Callback invoked for lifecycle events of the insert, including success, failure, intermediate
   * progress, and when the final URI or compact metadata becomes available. The callback reference
   * is provided by the caller and is not owned by this instance.
   */
  @SuppressWarnings("java:S1948")
  final ClientPutCallback callback;

  /**
   * The data to insert. Implementations of {@link RandomAccessBucket} must remain readable for the
   * duration of the insert. The bucket will be freed after completion, regardless of the outcome.
   * Wrap the bucket in {@link network.crypta.support.io.NoFreeBucket} if the insert pipeline should
   * not free the underlying storage.
   */
  @SuppressWarnings("java:S1948")
  final RandomAccessBucket data;

  /**
   * The target URI to insert to. Maybe a {@code CHK@}, {@code SSK@}, {@code KSK@} or {@code USK@}
   * form depending on caller configuration; validations occur during start.
   */
  final FreenetURI targetURI;

  /**
   * Client-visible metadata such as MIME type and auxiliary attributes. When persistence is
   * enabled, the metadata may be cloned to decouple from caller mutations.
   */
  final ClientMetadata cm;

  /**
   * Configuration for the insert, including splitfile policy, priority, compatibility mode, and
   * other tunable that influence block layout and scheduling behavior.
   */
  final InsertContext ctx;

  /**
   * Target filename. If specified, we create manifest metadata so that the file can be accessed at
   * [ final key ] / [ target filename ].
   */
  final String targetFilename;

  /** The current state of the insert. */
  @SuppressWarnings("java:S1948")
  private ClientPutState currentState;

  /** Whether the insert has finished. */
  private boolean finished;

  /** Are we inserting metadata? */
  private final boolean isMetadata;

  /**
   * Guard that prevents overlapping calls to {@link #start(ClientContext)} or restarts while a
   * start sequence is already in progress. Accessed under this instance's monitor.
   */
  private boolean startedStarting;

  /** Are we inserting a binary blob? */
  private final boolean binaryBlob;

  /**
   * The final URI for the inserted data once known. This is set after encoding of the top block
   * completes. For manifests, the filename segment may be appended to the base URI.
   */
  private FreenetURI uri;

  /**
   * Optional caller-specified splitfile crypto key. When present, it must be exactly 32 bytes and
   * overrides random key generation. This class does not copy the array reference.
   */
  private final byte[] overrideSplitfileCrypto;

  /**
   * The effective splitfile crypto key used by the insert. Populated during start either from
   * {@link #overrideSplitfileCrypto} or generated randomly. Valid only after start completes.
   */
  private byte[] cryptoKey;

  /**
   * When positive, means we will return metadata rather than a URI, once the metadata is under this
   * length. If it is too short, it is still possible to return a URI, but we won't return both.
   */
  private final long metadataThreshold;

  /**
   * Tracks whether compact metadata has already been delivered to the callback. Used to avoid
   * double-reporting when both a URI and metadata might otherwise be produced in rare flows.
   */
  private boolean gotFinalMetadata;

  // No static initialization required.

  /**
   * Creates a new inserter for the provided data and target URI.
   *
   * <p>The {@code data} bucket is consumed asynchronously and will be freed when the insert
   * completes. If the underlying storage must not be freed, wrap it in {@link
   * network.crypta.support.io.NoFreeBucket}. When {@code targetFilename} is provided, a one-file
   * manifest is created so clients can retrieve the file as {@code <final-key>/<targetFilename>}.
   *
   * @param request bundled request parameters including callback, data, target URI, and insert
   *     context; values are stored without validation to preserve legacy behavior.
   * @param options optional settings for filename hints, binary-blob behavior, splitfile crypto
   *     overrides, and metadata thresholding; use {@link ClientPutterOptions#defaults()} for
   *     standard behavior.
   */
  public ClientPutter(ClientPutterRequest request, ClientPutterOptions options) {
    super(
        request.requestParams().priorityClass(),
        request.requestParams().callback().getRequestClient());
    this.cm = request.clientMetadata();
    this.isMetadata = request.isMetadata();
    this.callback = request.requestParams().callback();
    this.data = request.data();
    this.targetURI = request.requestParams().targetURI();
    this.ctx = request.requestParams().insertContext();
    this.finished = false;
    this.cancelled = false;
    this.targetFilename = options.targetFilename();
    this.binaryBlob = options.binaryBlob();
    this.overrideSplitfileCrypto = options.overrideSplitfileCrypto();
    this.metadataThreshold = options.metadataThreshold();
  }

  /**
   * Starts the insert using the provided client context.
   *
   * <p>The insert is scheduled on the client request infrastructure contained in {@code context}.
   * If the insert has previously completed, use {@link #start(boolean, ClientContext)} with {@code
   * restart=true}. On error during initial preparation (e.g., invalid URI, bucket errors), the
   * callback will receive {@link ClientPutCallback#onFailure(InsertException, BaseClientPutter)}.
   *
   * @param context execution context providing schedulers, randomness, and transient services; must
   *     be non-null and valid for the lifetime of the scheduled work.
   * @throws InsertException if validation fails or the insert cannot be started due to a
   *     precondition such as missing data or incompatible settings.
   */
  public void start(ClientContext context) throws InsertException {
    start(false, context);
  }

  /**
   * Starts or restarts the insert depending on the {@code restart} flag.
   *
   * <p>When {@code restart} is {@code true}, internal counters are reset and the insert is
   * re-scheduled if the previous attempt has finished. The method returns {@code false} when guards
   * reject a start (e.g., already starting, currently running, or canceled). If an {@link
   * InsertException} occurs during preparation, the callback is notified and the method returns
   * {@code true} only when scheduling has successfully begun.
   *
   * @param restart when {@code true}, attempts to restart an insert that has already finished; when
   *     {@code false}, performs a normal first start subject to guard checks.
   * @param context execution context with schedulers and utilities required by the insert; must be
   *     non-null and remain valid while the insert is active.
   * @return {@code true} if the insert was accepted and scheduled; {@code false} if a guard
   *     prevented starting or the operation was canceled before scheduling.
   * @throws InsertException if validation, bucket access, or other preconditions fail during
   *     preparation; the callback is notified with the same exception instance.
   */
  public boolean start(boolean restart, ClientContext context) throws InsertException {
    if (LOG.isDebugEnabled()) LOG.debug("Insert start requested: {} target={}", this, targetURI);
    final byte cryptoAlgorithm = selectCryptoAlgorithm();
    try {
      targetURI.checkInsertURI();
      final boolean randomiseKeys = randomiseSplitfileKeys(targetURI, ctx);
      if (data == null)
        throw new InsertException(InsertExceptionMode.BUCKET_ERROR, "No data to insert", null);

      if (!prepareAndBuildState(restart, context, cryptoAlgorithm, randomiseKeys)) {
        // If the insert was actually canceled, report cancellation; otherwise this was a guard
        // rejection (e.g., already starting/running) and should not notify failure.
        synchronized (this) {
          if (cancelled) {
            onFailure(new InsertException(InsertExceptionMode.CANCELLED), null, context);
          }
        }
        return false;
      }

      if (isCancelled()) {
        onFailure(new InsertException(InsertExceptionMode.CANCELLED), null, context);
        return false;
      }

      scheduleCurrentState(context);

      if (isCancelled()) {
        onFailure(new InsertException(InsertExceptionMode.CANCELLED), null, context);
        return false;
      }
    } catch (InsertException e) {
      handleStartFailure(e);
    } catch (IOException e) {
      handleStartFailure(new InsertException(InsertExceptionMode.BUCKET_ERROR, e, null));
    } catch (BinaryBlobFormatException e) {
      handleStartFailure(
          new InsertException(InsertExceptionMode.BINARY_BLOB_FORMAT_ERROR, e, null));
    }
    if (LOG.isDebugEnabled()) LOG.debug("Insert start scheduled: {}", this);
    return true;
  }

  private byte selectCryptoAlgorithm() {
    CompatibilityMode mode = ctx.getCompatibilityMode();
    return (mode == CompatibilityMode.COMPAT_CURRENT
            || mode.code >= CompatibilityMode.COMPAT_1416.code)
        ? Key.ALGO_AES_CTR_256_SHA256
        : Key.ALGO_AES_PCFB_256_SHA256;
  }

  private boolean prepareAndBuildState(
      boolean restart, ClientContext context, byte cryptoAlgorithm, boolean randomiseSplitfileKeys)
      throws InsertException, IOException, BinaryBlobFormatException {
    synchronized (this) {
      return doPrepareAndBuildStateLocked(
          restart, context, cryptoAlgorithm, randomiseSplitfileKeys);
    }
  }

  private boolean doPrepareAndBuildStateLocked(
      boolean restart, ClientContext context, byte cryptoAlgorithm, boolean randomiseSplitfileKeys)
      throws InsertException, IOException, BinaryBlobFormatException {
    if (!handleRestartGuard(restart)) return false;
    if (!guardStartFlags(restart)) return false;
    boolean cancel = this.cancelled;
    setupCryptoKeyLocked(context, randomiseSplitfileKeys);
    if (!cancel) buildCurrentStateLocked(context, cryptoAlgorithm);
    return !cancel;
  }

  private void scheduleCurrentState(ClientContext context) throws InsertException {
    if (LOG.isDebugEnabled()) LOG.debug("Scheduling insert state: {}", currentState);
    if (currentState instanceof SingleFileInserter inserter) inserter.start(context);
    else currentState.schedule(context);
  }

  private boolean handleRestartGuard(boolean restart) {
    if (restart) {
      clearCountersOnRestart();
      if (currentState != null && !finished) {
        if (LOG.isDebugEnabled())
          LOG.debug("Restart blocked: insert still running with state {}", currentState);
        return false;
      }
      if (finished) startedStarting = false;
      finished = false;
    }
    return true;
  }

  private boolean guardStartFlags(boolean restart) {
    if (startedStarting) {
      if (LOG.isDebugEnabled())
        LOG.debug("Start guard rejected {}: already starting", restart ? "restart" : "start");
      return false;
    }
    startedStarting = true;
    if (currentState != null) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Start guard rejected {}: existing state {}",
            restart ? "restart" : "start",
            currentState);
      return false;
    }
    return true;
  }

  private void setupCryptoKeyLocked(ClientContext context, boolean randomiseSplitfileKeys)
      throws InsertException {
    cryptoKey = null;
    if (overrideSplitfileCrypto != null) {
      cryptoKey = overrideSplitfileCrypto;
      if (cryptoKey.length != 32)
        throw new InsertException(
            InsertExceptionMode.INVALID_URI,
            "overrideSplitfileCryptoKey must be of length 32",
            null);
    } else if (randomiseSplitfileKeys) {
      cryptoKey = new byte[32];
      context.random.nextBytes(cryptoKey);
    }
  }

  private void buildCurrentStateLocked(ClientContext context, byte cryptoAlgorithm)
      throws IOException, BinaryBlobFormatException {
    if (!binaryBlob) {
      ClientMetadata meta = cm;
      if (meta != null) meta = persistent() ? ClientMetadata.copyOf(meta) : meta;
      InsertExecutionOptions execOptions =
          new InsertExecutionOptions(false, false, null, cryptoKey, cryptoAlgorithm, realTimeFlag);
      SingleFileInserterParams params =
          new SingleFileInserterParams()
              .withParent(this)
              .withCallback(this)
              .withBlock(new InsertBlock(data, meta, targetURI))
              .withMetadata(isMetadata)
              .withCtx(ctx)
              .withExecutionOptions(execOptions)
              .withToken(null)
              .withFreeData(false)
              .withTargetFilename(targetFilename)
              .withForSplitfile(false)
              .withPersistent(persistent())
              .withOrigDataLength(0)
              .withOrigCompressedDataLength(0)
              .withOrigHashes(null)
              .withMetadataThreshold(metadataThreshold);
      currentState = new SingleFileInserter(params);
    } else {
      currentState =
          new BinaryBlobInserter(data, this, getClient(), false, priorityClass, ctx, context);
    }
  }

  private void handleStartFailure(InsertException e) {
    LOG.error("Failed to start insert: {}", e, e);
    synchronized (this) {
      finished = true;
      currentState = null;
    }
    if (this.callback != null) this.callback.onFailure(e, this);
  }

  /**
   * Determines whether splitfile keys for child blocks should be randomized.
   *
   * <p>Randomizing CHK keys beneath SSK/KSK/USK top-level keys makes it significantly harder to
   * identify blocks via known-plaintext analysis. The decision also depends on {@link
   * InsertContext.CompatibilityMode} so older compatibility settings may disable randomization.
   *
   * @param targetURI the top-level target URI for the insert; SSK, KSK, and USK typically enable
   *     randomization of subordinate CHK keys for better privacy properties.
   * @param ctx the insert context providing the compatibility mode and related settings that can
   *     influence whether randomization is allowed.
   * @return {@code true} when subordinate splitfile keys should be randomized; {@code false} when
   *     randomization is disallowed for compatibility or the target does not warrant it.
   */
  public static boolean randomiseSplitfileKeys(FreenetURI targetURI, InsertContext ctx) {
    // If the top level key is an SSK, all CHK blocks and particularly splitfiles below it should
    // have
    // randomized keys. This substantially improves security by making it impossible to identify
    // blocks
    // even if you know the content. In the user interface, we will offer the option of inserting as
    // a
    // random SSK to take advantage of this.
    boolean randomiseSplitfileKeys = targetURI.isSSK() || targetURI.isKSK() || targetURI.isUSK();
    if (randomiseSplitfileKeys) {
      CompatibilityMode cmode = ctx.getCompatibilityMode();
      if (!(cmode == CompatibilityMode.COMPAT_CURRENT
          || cmode.code >= CompatibilityMode.COMPAT_1255.code)) randomiseSplitfileKeys = false;
    }
    return randomiseSplitfileKeys;
  }

  /**
   * Called by {@link ClientPutState} when the insert completes successfully. Marks the request as
   * finished, clears internal state, and notifies the registered callback of success.
   */
  @Override
  public void onSuccess(ClientPutState state, ClientContext context) {
    synchronized (this) {
      finished = true;
      currentState = null;
    }
    if ((super.failedBlocks > 0
            || super.fatallyFailedBlocks > 0
            || super.successfulBlocks < super.totalBlocks)
        && !uri.isUSK()
        && !ctx.isGetCHKOnly())
      // USK auxiliary inserts are allowed to fail.
      // If only generating the key, the splitfile may not have reported the blocks as inserted.
      LOG.error(
          "Failed blocks: {}, Fatally failed blocks: {}, Successful blocks: {}, Total blocks: {}"
              + " but success?! on {} from {}",
          failedBlocks,
          fatallyFailedBlocks,
          successfulBlocks,
          totalBlocks,
          this,
          state,
          new Exception("debug"));
    callback.onSuccess(this);
  }

  /**
   * Called by {@link ClientPutState} when the insert fails irrecoverably. Marks the request as
   * finished, clears internal state, and notifies the registered callback with the error.
   */
  @Override
  public void onFailure(InsertException e, ClientPutState state, ClientContext context) {
    if (LOG.isDebugEnabled()) LOG.debug("onFailure() for {} : {} : {}", this, state, e, e);
    synchronized (this) {
      finished = true;
      currentState = null;
    }
    callback.onFailure(e, this);
  }

  /**
   * Called when the final URI becomes known during encoding. The URI may be augmented with the
   * {@link #targetFilename} if present, and is delivered to the callback exactly once.
   */
  @Override
  public void onEncode(BaseClientKey key, ClientPutState state, ClientContext context) {
    FreenetURI u;
    synchronized (this) {
      u = key.getURI();
      if (gotFinalMetadata) {
        LOG.error("URI generated after metadata already sent: {} from {}", this, state);
      }
      if (targetFilename != null) u = u.pushMetaString(targetFilename);
      if (this.uri != null) {
        if (!this.uri.equals(u)) {
          LOG.error(
              "onEncode() called twice with different URIs: {} -> {} for {}",
              this.uri,
              u,
              this,
              new Exception("error"));
        }
        return;
      }
      this.uri = u;
    }
    callback.onGeneratedURI(u, this);
  }

  /**
   * Called when {@link #metadataThreshold} is set and the final compact metadata is returned
   * instead of a URI because its length falls below the threshold.
   */
  @Override
  public void onMetadata(Bucket finalMetadata, ClientPutState state, ClientContext context) {
    boolean freeIt = false;
    synchronized (this) {
      if (uri != null) {
        LOG.error("Metadata generated after URI already sent: {} from {}", this, state);
      }
      if (gotFinalMetadata) {
        LOG.error("onMetadata called twice - already sent metadata to client for {}", this);
        freeIt = true;
      } else {
        gotFinalMetadata = true;
      }
    }
    if (freeIt) {
      finalMetadata.free();
      return;
    }
    callback.onGeneratedMetadata(finalMetadata, this);
  }

  /**
   * Cancels the insert if it has not already finished. This triggers a failure callback with a
   * {@link InsertExceptionMode#CANCELLED} reason unless the request was already canceled.
   */
  @Override
  public void cancel(ClientContext context) {
    if (LOG.isDebugEnabled()) LOG.debug("Cancelling {}", this);
    ClientPutState oldState;
    synchronized (this) {
      if (cancelled) return;
      if (finished) return;
      super.cancel();
      oldState = currentState;
    }
    if (oldState != null) oldState.cancel(context);
    onFailure(new InsertException(InsertExceptionMode.CANCELLED), null, context);
  }

  /**
   * Indicates whether the insert has completed or was canceled. The return value becomes stable
   * after completion; callers may poll to drive UI state while waiting for callbacks.
   */
  @Override
  public synchronized boolean isFinished() {
    return finished || cancelled;
  }

  /**
   * Returns the data bucket used by this inserter.
   *
   * @return the original {@link Bucket} backing the insert. Ownership remains with the caller, but
   *     the bucket will be freed after completion unless wrapped to prevent freeing.
   */
  public Bucket getData() {
    return data;
  }

  /**
   * Returns the target URI used to initialize this insert.
   *
   * @return the caller-provided {@link FreenetURI} that identifies the intended destination; may be
   *     a CHK/SSK/KSK/USK insert URI depending on configuration.
   */
  public FreenetURI getTargetURI() {
    return targetURI;
  }

  /**
   * Returns the final URI of the inserted data, when known.
   *
   * @return a {@link FreenetURI} for the completed insert or {@code null} until encoding has
   *     produced the top-level key; includes a filename segment when applicable.
   */
  @Override
  public FreenetURI getURI() {
    return uri;
  }

  /**
   * Returns the splitfile crypto key actually used by the insert.
   *
   * @return a 32-byte key when available; {@code null} before start or when no splitfile key is
   *     required. The returned array is the live reference used internally; do not modify.
   */
  public byte[] getSplitfileCryptoKey() {
    return cryptoKey;
  }

  /**
   * Notifies this inserter of a state transition within the put pipeline. If the transition applies
   * to the current root state, it is adopted; subsidiary transitions are ignored.
   */
  @Override
  public void onTransition(
      ClientPutState oldState, ClientPutState newState, ClientContext context) {
    if (newState == null) throw new NullPointerException();

    synchronized (this) {
      if (currentState == oldState) {
        currentState = newState;
        return;
      }
    }
    if (persistent()) context.jobRunner.setCheckpointASAP();
    LOG.info("onTransition: cur={}, old={}, new={}", currentState, oldState, newState);
  }

  /**
   * Called when metadata is generated for the insert without being stored. This path is not
   * expected for normal inserts because metadata should be inserted instead of returned here.
   */
  @Override
  public void onMetadata(Metadata m, ClientPutState state, ClientContext context) {
    LOG.error(
        "Got metadata on {} from {} (this means the metadata won't be inserted)", this, state);
  }

  /**
   * The number of blocks that will be needed to fetch the data. We put this in the top block
   * metadata.
   */
  protected volatile int minSuccessFetchBlocks;

  @Override
  public int getMinSuccessFetchBlocks() {
    return minSuccessFetchBlocks;
  }

  @Override
  public void addBlock() {
    synchronized (this) {
      MIN_SUCCESS_FETCH_BLOCKS_UPDATER.incrementAndGet(this);
    }
    super.addBlock();
  }

  @Override
  public void addBlocks(int num) {
    synchronized (this) {
      minSuccessFetchBlocks += num;
    }
    super.addBlocks(num);
  }

  /**
   * Adds one or more blocks to the number of required blocks without notifying clients. Used for
   * internal accounting where progress events are not desirable.
   */
  @Override
  public synchronized void addMustSucceedBlocks(int blocks) {
    synchronized (this) {
      minSuccessFetchBlocks += blocks;
    }
    super.addMustSucceedBlocks(blocks);
  }

  /**
   * Adds redundant blocks to the insert accounting without affecting the requestor's required fetch
   * count. Client listeners are not notified of this internal adjustment.
   */
  @Override
  public synchronized void addRedundantBlocksInsert(int blocks) {
    super.addMustSucceedBlocks(blocks);
  }

  @Override
  protected void clearCountersOnRestart() {
    minSuccessFetchBlocks = 0;
    super.clearCountersOnRestart();
  }

  @Override
  protected void innerNotifyClients(ClientContext context) {
    SplitfileProgressEvent e;
    synchronized (this) {
      e =
          new SplitfileProgressEvent(
              new SplitfileProgressCounts(
                  this.totalBlocks,
                  this.successfulBlocks,
                  this.failedBlocks,
                  this.fatallyFailedBlocks,
                  this.minSuccessBlocks,
                  this.minSuccessFetchBlocks,
                  this.blockSetFinalized),
              new SplitfileProgressTimestamps(this.latestSuccess, this.latestFailure));
    }
    ctx.getEventProducer().produceEvent(e, context);
  }

  /**
   * Notifies listening clients that an insert has been sent to the network. This is emitted when
   * the first network transmission for the request occurs.
   */
  @Override
  protected void innerToNetwork(ClientContext context) {
    ctx.getEventProducer().produceEvent(new SendingToNetworkEvent(), context);
  }

  /** Called when we know exactly how many blocks will be needed. */
  @Override
  public void onBlockSetFinished(ClientPutState state, ClientContext context) {
    if (LOG.isDebugEnabled()) LOG.debug("Set finished");
    blockSetFinalized(context);
  }

  /**
   * Called when enough of the data has been inserted that the file can be fetched. This is most
   * useful when the pipeline is configured to expose the final URI early.
   */
  @Override
  public void onFetchable(ClientPutState state) {
    callback.onFetchable(this);
  }

  /**
   * Indicates whether the insert can be restarted. Returns {@code false} while an insert is in
   * progress or when no data bucket is available to re-use.
   *
   * @return {@code true} if a further call to {@link #restart(ClientContext)} may succeed; {@code
   *     false} otherwise.
   */
  public boolean canRestart() {
    if (currentState != null && !finished) {
      LOG.debug("Cannot restart because not finished for {}", uri);
      return false;
    }
    return data != null;
  }

  /**
   * Restarts the insert by delegating to {@link #start(boolean, ClientContext)} with {@code
   * restart=true}.
   *
   * @param context execution context with schedulers and utilities required by the insert; must be
   *     non-null and valid for rescheduling.
   * @return {@code true} if the restart was accepted and scheduled; {@code false} if guards
   *     rejected the attempt or the request was canceled.
   * @throws InsertException if validation or preparation fails during restart; the callback is
   *     notified with the thrown exception.
   */
  public boolean restart(ClientContext context) throws InsertException {
    return start(true, context);
  }

  @Override
  public void onTransition(
      ClientGetState oldState, ClientGetState newState, ClientContext context) {
    // Ignore, at the moment
    // This exists here because e.g., USKInserter does request as well as inserts.
  }

  @Override
  public void dump() {
    LOG.info("URI: {}", uri);
    LOG.info("Client: {}", callback);
    LOG.info("Finished: {}", finished);
    LOG.info("Data: {}", data);
  }

  @Override
  public byte[] getClientDetail(ChecksumChecker checker) throws IOException {
    if (callback instanceof PersistentClientCallback persistentCallback) {
      return getClientDetail(persistentCallback, checker);
    } else return new byte[0];
  }

  @Override
  public void innerOnResume(ClientContext context) throws ResumeFailedException {
    super.innerOnResume(context);
    if (currentState != null) {
      try {
        currentState.onResume(context);
      } catch (InsertException e) {
        this.onFailure(e, null, context);
        return;
      }
    }
    if (data != null) data.onResume(context);
    notifyClients(context);
  }

  @Override
  protected ClientBaseCallback getCallback() {
    return callback;
  }

  @Override
  public void onShutdown(ClientContext context) {
    ClientPutState state;
    synchronized (this) {
      state = currentState;
    }
    if (state != null) state.onShutdown(context);
  }

  @Override
  public boolean equals(Object obj) {
    return super.equals(obj);
  }

  @Override
  public int hashCode() {
    return super.hashCode();
  }

  /* ===== Java serialization support ===== */

  /**
   * Custom Java deserialization hook to restore transient/runtime links for backward compatibility.
   *
   * <p>Older serialized forms of {@link SingleFileInserter} stored as the current state may lack a
   * callback (it was transient). When resuming a top-level insert, default that callback to this
   * {@link ClientPutter} so lifecycle events are delivered correctly.
   */
  @Serial
  private void readObject(java.io.ObjectInputStream in)
      throws java.io.IOException, ClassNotFoundException {
    in.defaultReadObject();
    if (currentState instanceof SingleFileInserter sfi && sfi.cb == null) {
      sfi.cb = this;
    }
  }
}
