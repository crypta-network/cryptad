package network.crypta.client.async;

import java.io.IOException;
import java.io.Serial;
import java.io.Serializable;
import java.net.MalformedURLException;
import java.util.Arrays;
import java.util.Objects;
import network.crypta.client.FailureCodeTracker;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertException;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.CHKEncodeException;
import network.crypta.keys.ClientCHKBlock;
import network.crypta.keys.ClientKey;
import network.crypta.keys.ClientKeyBlock;
import network.crypta.keys.ClientSSK;
import network.crypta.keys.ClientSSKBlock;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.InsertableClientSSK;
import network.crypta.keys.KeyBlock;
import network.crypta.keys.KeyDecodeException;
import network.crypta.keys.KeyEncodeException;
import network.crypta.keys.KeyVerifyException;
import network.crypta.keys.SSKBlock;
import network.crypta.keys.SSKEncodeException;
import network.crypta.node.KeysFetchingLocally;
import network.crypta.node.LowLevelPutException;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestClient;
import network.crypta.node.RequestScheduler;
import network.crypta.node.SendableInsert;
import network.crypta.node.SendableRequestItem;
import network.crypta.node.SendableRequestItemKey;
import network.crypta.node.SendableRequestSender;
import network.crypta.store.KeyCollisionException;
import network.crypta.support.Fields;
import network.crypta.support.api.Bucket;
import network.crypta.support.compress.InvalidCompressionCodecException;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.ResumeFailedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Inserts a single content block into the network.
 *
 * <p>This stateful helper performs the full lifecycle for inserting exactly one block: it encodes
 * the provided {@link Bucket} into a {@link ClientKeyBlock} (CHK/SSK depending on the supplied
 * {@link FreenetURI}), registers the request with the {@link RequestScheduler}, and notifies a
 * {@link PutCompletionCallback} when the block has been encoded and when the request succeeds or
 * fails. It is typically created by higher-level putters and is not reused across inserts.
 *
 * <p>Typical usage is to construct an instance with the desired {@link InsertContext} and
 * parameters, call {@link #schedule(ClientContext)} to register it with the scheduler, and rely on
 * callbacks to observe progress. Callers may also proactively trigger encoding via {@link
 * #tryEncode(ClientContext)} when operating in modes that prefer early CHK discovery.
 *
 * <p>Concurrency and state: methods synchronize on {@code this} to guard the internal state ({@code
 * finished}, {@code resultingKey}, and buffering). Public methods are safe to call from the client
 * thread and from scheduler/executor threads, but they assume the surrounding framework provides
 * ordering guarantees for callbacks. Instances are single-use and become terminal once {@link
 * #onSuccess(SendableRequestItem, ClientKey, ClientContext)} or a failure path marks them as
 * finished.
 *
 * <ul>
 *   <li>Encodes input via the configured compression and optional encryption parameters.
 *   <li>Schedules a single sendable request and tracks retries and error codes.
 *   <li>Propagates early-encode notifications and final completion to the provided callback.
 * </ul>
 *
 * <p>WARNING: Changing non-transient members on classes that are {@link Serializable} can result in
 * restarting downloads or losing uploads.
 *
 * @see BaseClientPutter
 * @see PutCompletionCallback
 * @see ClientKeyBlock
 * @see RequestScheduler
 */
public class SingleBlockInserter extends SendableInsert implements ClientPutState, Serializable {
  private static final Logger LOG = LoggerFactory.getLogger(SingleBlockInserter.class);
  private static final String LOG_CAUGHT = "Caught {}";
  private static final String LOG_CAUGHT_WHEN_CHECKING_COLLISION =
      "Caught {} when checking collision!";

  @Serial private static final long serialVersionUID = 1L;

  // no static initialization required

  /**
   * The source bytes for this single insert. Implementations may create lightweight shadows during
   * request scheduling; when {@link #freeData} is true the bucket is {@link Bucket#free() freed} on
   * terminal completion.
   */
  private Bucket sourceData;

  /**
   * Compression codec identifier used when encoding. A value of {@code -1} delegates to the
   * context/implementation to decide whether and how to compress the block.
   */
  final short compressionCodec;

  /**
   * Target URI that determines the key type (e.g., {@code CHK}, {@code SSK}, or {@code KSK}).
   *
   * <p>Uses essentially no RAM in the common case of a CHK because we use {@link
   * FreenetURI#EMPTY_CHK_URI}.
   */
  final FreenetURI uri; // uses essentially no RAM in the common case of a CHK because we use

  // FreenetURI.EMPTY_CHK_URI
  /** The client key produced by a successful encode, or {@code null} until available. */
  private ClientKey resultingKey;

  /**
   * Observer notified when the block has been encoded (URI available) and when the insert either
   * succeeds or fails. Implementations should be fast; callbacks are executed on framework threads.
   */
  final PutCompletionCallback cb;

  /** Parent request that owns this inserter and aggregates progress and failure accounting. */
  final BaseClientPutter parent;

  /** Insert policy and tunables used by the encoding and request scheduler paths. */
  final InsertContext ctx;

  /** Number of insert retry attempts performed so far for this block. */
  private int retries;

  /** Tracks encountered failure modes for reporting and for persistent error aggregation. */
  private final FailureCodeTracker errors;

  /** Whether this inserter reached a terminal state (success, cancel, or failure). */
  private boolean finished;

  /**
   * When {@code true}, suppresses the early {@link PutCompletionCallback#onEncode} notification
   * even when a {@link ClientKey} has been derived.
   */
  private final boolean dontSendEncoded;

  /** Per-block integer token used by higher-level constructs (e.g., splitfiles). */
  final int token; // for e.g. splitfiles

  /** Opaque scheduling token returned by {@link #getToken()} to identify this request. */
  private final Object tokenObject;

  /** Whether the source data should be treated as metadata for encoding purposes. */
  final boolean isMetadata;

  /** Length of the original uncompressed data, in bytes, if known by the caller. */
  final int sourceLength;

  /** Consecutive route-not-found counters, used by heuristics that consider RNFs a success. */
  private int consecutiveRNFs;

  /** Cached key-type predicate derived from {@link #uri} to avoid repeated string checks. */
  private final boolean isSSK;

  /** If {@code true}, frees {@link #sourceData} once a terminal state is reached. */
  private final boolean freeData;

  /** Number of successful insert completions so far when {@link #extraInserts} is positive. */
  private int completedInserts;

  /**
   * Additional times to perform the insert beyond the first success; {@code 0} disables repeats.
   */
  final int extraInserts;

  /**
   * Optional per-block cryptographic key material; semantics depend on the encoder implementation.
   */
  final byte[] cryptoKey;

  /** Identifier for the cryptographic algorithm associated with {@link #cryptoKey}, if any. */
  final byte cryptoAlgorithm;

  /**
   * Creates a new inserter for a single block.
   *
   * <p>The instance is single-use. After construction, invoke {@link #schedule(ClientContext)} to
   * register it with the scheduler or {@link #tryEncode(ClientContext)} to trigger an early encode
   * when the context enables it.
   *
   * @param parent The owning putter; must be active and used for progress aggregation.
   * @param data The source {@link Bucket} containing the bytes to encode and insert; never null.
   * @param compressionCodec Compression codec id; {@code -1} delegates to context/implementation.
   * @param uri Base URI whose key type determines CHK/SSK/KSK behavior and encoding rules.
   * @param ctx Insert policy and limits (retries, RNF heuristics, compressor descriptor, etc.).
   * @param realTimeFlag Whether to schedule this insert as real-time in the underlying framework.
   * @param cb Callback notified on encode and when the request finally succeeds or fails.
   * @param isMetadata Whether the data should be encoded as metadata rather than ordinary content.
   * @param sourceLength Length of the original, uncompressed data (bytes), or {@code -1} if
   *     unknown.
   * @param token Integer token used by callers to correlate this block (e.g., splitfile indices).
   * @param addToParent When true, increments the parent's must-succeed counter and notifies
   *     clients.
   * @param dontSendEncoded Suppress the early on-encode callback even if a key is available.
   * @param tokenObject Opaque token exposed via {@link #getToken()} to identify this request.
   * @param context Runtime context used immediately for parent notifications on construction.
   * @param persistent Whether this request is persistent across restarts in the client framework.
   * @param freeData Whether to free {@code data} when the request reaches a terminal state.
   * @param extraInserts Number of additional successful inserts to perform after the first success.
   * @param cryptoAlgorithm Identifier for optional per-block cryptography; {@code 0} for none.
   * @param cryptoKey Raw key bytes used with {@code cryptoAlgorithm}; {@code null} when not used.
   */
  public SingleBlockInserter(
      BaseClientPutter parent,
      Bucket data,
      short compressionCodec,
      FreenetURI uri,
      InsertContext ctx,
      boolean realTimeFlag,
      PutCompletionCallback cb,
      boolean isMetadata,
      int sourceLength,
      int token,
      boolean addToParent,
      boolean dontSendEncoded,
      Object tokenObject,
      ClientContext context,
      boolean persistent,
      boolean freeData,
      int extraInserts,
      byte cryptoAlgorithm,
      byte[] cryptoKey) {
    super(persistent, realTimeFlag);
    this.consecutiveRNFs = 0;
    this.tokenObject = tokenObject;
    this.token = token;
    this.parent = parent;
    this.dontSendEncoded = dontSendEncoded;
    this.retries = 0;
    this.finished = false;
    this.ctx = ctx;
    this.freeData = freeData;
    errors = new FailureCodeTracker(true);
    this.cb = cb;
    this.uri = uri;
    this.compressionCodec = compressionCodec;
    this.sourceData = data;
    if (sourceData == null) throw new NullPointerException();
    this.isMetadata = isMetadata;
    this.sourceLength = sourceLength;
    isSSK = uri.getKeyType().equalsIgnoreCase("SSK");
    if (addToParent) {
      parent.addMustSucceedBlocks(1);
      parent.notifyClients(context);
    }
    this.extraInserts = extraInserts;
    this.cryptoAlgorithm = cryptoAlgorithm;
    this.cryptoKey = cryptoKey;
  }

  /**
   * Encodes the current {@link #sourceData} into a {@link ClientKeyBlock} using the instance
   * configuration.
   *
   * <p>On failure, low-level causes are mapped to an {@link InsertException} with an appropriate
   * mode. The resulting {@link ClientKey} is latched on first success and may be reported to the
   * callback depending on configuration.
   *
   * @param random Source of randomness used by the encoders and key generation logic; never null.
   * @return The encoded client key block representing the input data.
   * @throws InsertException If encoding fails due to URI, bucket I/O, codec, or internal errors.
   */
  protected ClientKeyBlock innerEncode(RandomSource random) throws InsertException {
    try {
      return innerEncode(
          random,
          uri,
          sourceData,
          isMetadata,
          compressionCodec,
          sourceLength,
          ctx.getCompressorDescriptor(),
          cryptoAlgorithm,
          cryptoKey);
    } catch (KeyEncodeException | InvalidCompressionCodecException e) {
      throw new InsertException(InsertExceptionMode.INTERNAL_ERROR, e, null);
    } catch (MalformedURLException e) {
      throw new InsertException(InsertExceptionMode.INVALID_URI, e, null);
    } catch (IOException e) {
      throw new InsertException(InsertExceptionMode.BUCKET_ERROR, e, null);
    }
  }

  /**
   * Static helper to encode the provided data and parameters into a {@link ClientKeyBlock}.
   *
   * <p>For {@code CHK} URIs, this delegates to {@link
   * ClientCHKBlock#encode(network.crypta.support.api.Bucket, boolean, boolean, short, long, String,
   * byte[], byte)}. For {@code SSK} and {@code KSK} URIs, it creates an {@link InsertableClientSSK}
   * and delegates to its encoder. The {@code compressionCodec} of {@code -1} indicates that the
   * implementation may choose whether to compress. Callers must provide a non-null {@code random}.
   *
   * @param random Randomness provider required by the encoders; must not be {@code null}.
   * @param uri Target URI whose key type selects the encoding path (CHK/SSK/KSK).
   * @param sourceData Bucket containing the bytes to encode; implementations may read it multiple
   *     times.
   * @param isMetadata Whether the content should be marked as metadata in the encoded block.
   * @param compressionCodec Compression codec id; {@code -1} lets the encoder decide.
   * @param sourceLength Uncompressed source length in bytes, when known; {@code -1} if unknown.
   * @param compressorDescriptor Human-readable compressor descriptor used by encoders and logs.
   * @param cryptoAlgorithm Optional algorithm id for per-block cryptography; {@code 0} for none.
   * @param cryptoKey Raw key material for {@code cryptoAlgorithm}; may be {@code null} when unused.
   * @return Encoded block ready for scheduling and transmission.
   * @throws InsertException If the URI type is unknown or otherwise invalid for insertion.
   * @throws CHKEncodeException If CHK encoding fails due to content or configuration issues.
   * @throws IOException If the source bucket cannot be read or copied as required.
   * @throws SSKEncodeException If SSK/KSK encoding fails for key-related reasons.
   * @throws InvalidCompressionCodecException If the codec id is not recognized by encoders.
   */
  protected static ClientKeyBlock innerEncode(
      RandomSource random,
      FreenetURI uri,
      Bucket sourceData,
      boolean isMetadata,
      short compressionCodec,
      int sourceLength,
      String compressorDescriptor,
      byte cryptoAlgorithm,
      byte[] cryptoKey)
      throws InsertException,
          CHKEncodeException,
          IOException,
          SSKEncodeException,
          InvalidCompressionCodecException {
    Objects.requireNonNull(random, "random");
    String uriType = uri.getKeyType();
    if (uriType.equals("CHK")) {
      return ClientCHKBlock.encode(
          sourceData,
          isMetadata,
          compressionCodec == -1,
          compressionCodec,
          sourceLength,
          compressorDescriptor,
          cryptoKey,
          cryptoAlgorithm);
    } else if (uriType.equals("SSK") || uriType.equals("KSK")) {
      InsertableClientSSK ik = InsertableClientSSK.create(uri);
      return ik.encode(
          sourceData,
          isMetadata,
          compressionCodec == -1,
          compressionCodec,
          sourceLength,
          compressorDescriptor);
    } else {
      throw new InsertException(
          InsertExceptionMode.INVALID_URI, "Unknown keytype " + uriType, null);
    }
  }

  /**
   * Latches and publishes the first derived {@link ClientKey} for this insert.
   *
   * <p>When not persistent, the notification is executed on the main executor; for persistent
   * inserts the notification is scheduled via the job runner and may be replayed on resume.
   * Subsequent calls are ignored.
   *
   * @param key The client key derived from encoding, used to construct the final URI.
   * @param context Runtime context used to post the notification on the appropriate executor.
   */
  protected void onEncode(final ClientKey key, final ClientContext context) {
    synchronized (this) {
      if (finished) return;
      if (resultingKey != null) return;
      resultingKey = key;
    }
    if (!persistent) {
      context
          .getMainExecutor()
          .execute(() -> cb.onEncode(key, SingleBlockInserter.this, context), "Got URI");
    } else {
      // Will be reported on restart in innerOnResume() if necessary.
      context.jobRunner.queueNormalOrDrop(
          context1 -> {
            cb.onEncode(key, SingleBlockInserter.this, context1);
            return false;
          });
    }
  }

  /**
   * Encodes the current source data into a {@link ClientKeyBlock} and optionally notifies the
   * callback.
   *
   * <p>This method latches the resulting {@link ClientKey} atomically, and, unless suppressed by
   * {@link #dontSendEncoded}, delivers an early {@link PutCompletionCallback#onEncode} event when a
   * new key becomes available.
   *
   * @param context Runtime state providing randomness, temporary storage factories, and executors.
   * @return The newly encoded block, or {@code null} when the inserter is already finished.
   * @throws InsertException If the URI is invalid, the bucket cannot be read, or encoding fails.
   */
  protected ClientKeyBlock encode(ClientContext context) throws InsertException {
    ClientKeyBlock block;
    boolean shouldSend;
    synchronized (this) {
      if (finished) return null;
      if (sourceData == null) {
        LOG.error("Source data is null on {} but not finished!", this);
        return null;
      }
      block = innerEncode(context.random);
      shouldSend = (resultingKey == null);
      resultingKey = block.getClientKey();
    }
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Encoded {} for {} shouldSend={} dontSendEncoded={}",
          resultingKey.getURI(),
          this,
          shouldSend,
          dontSendEncoded);
    if (shouldSend && !dontSendEncoded) cb.onEncode(block.getClientKey(), this, context);
    return block;
  }

  @Override
  public short getPriorityClass() {
    return parent.getPriorityClass(); // Not much point deactivating
  }

  @Override
  public void onFailure(LowLevelPutException e, SendableRequestItem keyNum, ClientContext context) {
    synchronized (this) {
      if (finished) return;
    }
    if (parent.isCancelled()) {
      fail(new InsertException(InsertExceptionMode.CANCELLED), context);
      return;
    }
    if (LOG.isDebugEnabled()) LOG.debug("onFailure() on {} for {}", e, this);
    if (handleErrorCode(e, context)) return;
    if (handleRouteNotFound(e, keyNum, context)) return;
    if (LOG.isDebugEnabled()) LOG.debug("Failed: {}", String.valueOf(e));
    retries++;
    if ((retries > ctx.getMaxInsertRetries()) && (ctx.getMaxInsertRetries() != -1)) {
      fail(
          InsertException.construct(persistent ? FailureCodeTracker.copyOf(errors) : errors),
          context);
      return;
    }
    clearWakeupTime(context);
  }

  private boolean handleErrorCode(LowLevelPutException e, ClientContext context) {
    switch (e.code) {
      case LowLevelPutException.COLLISION -> {
        fail(new InsertException(InsertExceptionMode.COLLISION), context);
        return true;
      }
      case LowLevelPutException.INTERNAL_ERROR -> {
        fail(new InsertException(InsertExceptionMode.INTERNAL_ERROR), context);
        return true;
      }
      case LowLevelPutException.REJECTED_OVERLOAD ->
          errors.inc(InsertExceptionMode.REJECTED_OVERLOAD);
      case LowLevelPutException.ROUTE_NOT_FOUND -> errors.inc(InsertExceptionMode.ROUTE_NOT_FOUND);
      case LowLevelPutException.ROUTE_REALLY_NOT_FOUND ->
          errors.inc(InsertExceptionMode.ROUTE_REALLY_NOT_FOUND);
      default -> {
        LOG.error("Unknown LowLevelPutException code: {}", e.code);
        errors.inc(InsertExceptionMode.INTERNAL_ERROR);
      }
    }
    return false;
  }

  private boolean handleRouteNotFound(
      LowLevelPutException e, SendableRequestItem keyNum, ClientContext context) {
    if (e.code == LowLevelPutException.ROUTE_NOT_FOUND
        || e.code == LowLevelPutException.ROUTE_REALLY_NOT_FOUND) {
      consecutiveRNFs++;
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Consecutive RNFs: {} / {}", consecutiveRNFs, ctx.getConsecutiveRNFsCountAsSuccess());
      if (consecutiveRNFs >= ctx.getConsecutiveRNFsCountAsSuccess()) {
        if (LOG.isDebugEnabled())
          LOG.debug("Consecutive RNFs: {} - counting as success", consecutiveRNFs);
        onSuccess(keyNum, getKeyNoEncode(), context);
        return true;
      }
    } else {
      consecutiveRNFs = 0;
    }
    return false;
  }

  private void fail(InsertException e, ClientContext context) {
    synchronized (this) {
      if (finished) return;
      finished = true;
    }
    if (e.isFatal()) parent.fatallyFailedBlock(context);
    else parent.failedBlock(context);
    unregister(context, getPriorityClass());
    if (freeData) {
      sourceData.free();
      sourceData = null;
    }
    cb.onFailure(e, this, context);
  }

  /**
   * Returns the encoded block for this inserter, encoding on demand.
   *
   * <p>On encoding or scheduling failures, the registered callback is notified with the error and
   * {@code null} is returned. When already finished, {@code null} is also returned.
   *
   * @param context Runtime context used for encoding and error reporting.
   * @return The {@link ClientKeyBlock} if available; {@code null} when finished or on error.
   */
  public ClientKeyBlock getBlock(ClientContext context) {
    try {
      synchronized (this) {
        if (finished) return null;
      }
      return encode(context);
    } catch (InsertException e) {
      cb.onFailure(e, this, context);
      return null;
    } catch (Exception t) {
      LOG.error(LOG_CAUGHT, t, t);
      cb.onFailure(new InsertException(InsertExceptionMode.INTERNAL_ERROR, t, null), this, context);
      return null;
    }
  }

  @Override
  public void schedule(ClientContext context) throws InsertException {
    synchronized (this) {
      if (finished) {
        if (LOG.isDebugEnabled()) LOG.debug("Finished already: {}", this);
        return;
      }
    }
    if (ctx.isGetCHKOnly() || ctx.isEarlyEncode()) {
      tryEncode(context);
    }
    if (ctx.isGetCHKOnly()) {
      onSuccess(null, getKeyNoEncode(), context);
    } else {
      getScheduler(context).registerInsert(this, persistent);
    }
  }

  @Override
  public boolean isSSK() {
    return isSSK;
  }

  /**
   * Returns the resulting URI for this block, encoding first if necessary.
   *
   * <p>If the key has not yet been derived, this method triggers encoding by calling {@link
   * #getBlock(ClientContext)} and then returns the URI once available.
   *
   * @param context Runtime context used to perform an on-demand encode.
   * @return The final content URI for the inserted block.
   */
  public FreenetURI getURI(ClientContext context) {
    synchronized (this) {
      if (resultingKey != null) {
        return resultingKey.getURI();
      }
    }
    getBlock(context);
    synchronized (this) {
      return resultingKey.getURI();
    }
  }

  /**
   * Returns the resulting URI if already known without triggering a new encode.
   *
   * @return The content URI or {@code null} when encoding has not yet produced a key.
   */
  public synchronized FreenetURI getURINoEncode() {
    return resultingKey == null ? null : resultingKey.getURI();
  }

  /**
   * Returns the resulting {@link ClientKey} if already known without triggering a new encode.
   *
   * @return The client key instance or {@code null} when not yet derived.
   */
  public synchronized ClientKey getKeyNoEncode() {
    return resultingKey;
  }

  @Override
  public void onSuccess(SendableRequestItem keyNum, ClientKey key, ClientContext context) {
    onEncode(key, context);
    if (LOG.isDebugEnabled()) LOG.debug("Succeeded ({}): {}", this, token);
    if (parent.isCancelled()) {
      fail(new InsertException(InsertExceptionMode.CANCELLED), context);
      return;
    }
    boolean shouldSendKey;
    synchronized (this) {
      SuccessDecision decision = decideOnSuccessLocked(key);
      if (decision.returnEarly) return;
      shouldSendKey = decision.shouldSendKey;
    }
    if (freeData) {
      sourceData.free();
      sourceData = null;
    }
    parent.completedBlock(false, context);
    unregister(context, getPriorityClass());
    if (LOG.isDebugEnabled()) LOG.debug("Calling onSuccess for {}", cb);
    if (shouldSendKey)
      cb.onEncode(
          key, this, context); // In case of race conditions etc., especially for LocalRequestOnly.
    cb.onSuccess(this, context);
  }

  private record SuccessDecision(boolean returnEarly, boolean shouldSendKey) {}

  /**
   * Decides control flow for {@link #onSuccess(SendableRequestItem, ClientKey, ClientContext)}
   * while holding this instance's monitor.
   */
  private SuccessDecision decideOnSuccessLocked(ClientKey key) {
    if (extraInserts > 0 && !ctx.isGetCHKOnly() && ++completedInserts <= extraInserts) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Completed inserts {} of extra inserts {} on {}", completedInserts, extraInserts, this);
      // Let it repeat until we've done enough inserts. It hasn't been unregistered yet.
      return new SuccessDecision(true, false);
    }
    if (finished) {
      // Normal with persistence.
      LOG.info("Block already completed: {}", this);
      return new SuccessDecision(true, false);
    }
    finished = true;
    if (resultingKey == null) {
      resultingKey = key;
      return new SuccessDecision(false, true);
    } else {
      if (!resultingKey.equals(key))
        LOG.error("Different key: {} -> {} for {}", resultingKey, key, this);
      return new SuccessDecision(false, false);
    }
  }

  @Override
  public BaseClientPutter getParent() {
    return parent;
  }

  @Override
  public void cancel(ClientContext context) {
    synchronized (this) {
      if (finished) return;
      finished = true;
    }
    if (freeData) {
      sourceData.free();
      sourceData = null;
    }
    super.unregister(context, getPriorityClass());
    cb.onFailure(new InsertException(InsertExceptionMode.CANCELLED), this, context);
  }

  @Override
  public synchronized boolean isEmpty() {
    return finished;
  }

  @Override
  public synchronized boolean isCancelled() {
    return isEmpty();
  }

  static class MySendableRequestSender implements SendableRequestSender {

    final String compressorDescriptor;
    // Only use when sure it is available!
    final SingleBlockInserter orig;

    MySendableRequestSender(String compress, SingleBlockInserter orig) {
      compressorDescriptor = compress;
      this.orig = orig;
    }

    @Override
    public boolean send(
        NodeClientCore core,
        RequestScheduler sched,
        final ClientContext context,
        final ChosenBlock req) {
      // Ignore keyNum, key, since we're only sending one block.
      ClientKeyBlock encodedBlock;
      KeyBlock b;
      final ClientKey key;
      ClientKey k = null;
      if (LOG.isDebugEnabled()) LOG.debug("Starting request");
      BlockItem block = (BlockItem) req.token;
      try {
        encodedBlock = orig.encodeBlock(block, context, compressorDescriptor);
        b = encodedBlock.getBlock();
        if (b == null) {
          LOG.error("Asked to send empty block");
          return false;
        }
        key = encodedBlock.getClientKey();
        k = key;
        orig.scheduleOnEncodeCallback(key, block, context);
        orig.putToStore(core, req, b, k);
      } catch (LowLevelPutException e) {
        if (LOG.isDebugEnabled()) LOG.debug(LOG_CAUGHT, e, e);
        if (e.code == LowLevelPutException.COLLISION
            && orig.handleCollision(e, block, k, context, req)) return true;
        req.onFailure(e, context);
        if (LOG.isDebugEnabled()) LOG.debug("Request failed for {}", String.valueOf(e));
        return true;
      } finally {
        block.copyBucket.free();
      }
      if (LOG.isDebugEnabled()) LOG.debug("Request succeeded");
      req.onInsertSuccess(k, context);
      return true;
    }

    @Override
    public boolean sendIsBlocking() {
      return true;
    }
  }

  private ClientKeyBlock encodeBlock(
      BlockItem block, ClientContext context, String compressorDescriptor)
      throws LowLevelPutException {
    try {
      return innerEncode(
          context.random,
          block.uri,
          block.copyBucket,
          block.isMetadata,
          block.compressionCodec,
          block.sourceLength,
          compressorDescriptor,
          block.cryptoAlgorithm,
          block.cryptoKey);
    } catch (CHKEncodeException
        | SSKEncodeException
        | InsertException
        | IOException
        | InvalidCompressionCodecException e) {
      throw new LowLevelPutException(
          LowLevelPutException.INTERNAL_ERROR, e + ":" + e.getMessage(), e);
    }
  }

  private void scheduleOnEncodeCallback(ClientKey key, BlockItem block, ClientContext context) {
    context
        .getJobRunner(block.persistent)
        .queueNormalOrDrop(
            context1 -> {
              onEncode(key, context1);
              return true;
            });
  }

  private void putToStore(NodeClientCore core, ChosenBlock req, KeyBlock b, ClientKey k)
      throws LowLevelPutException {
    if (req.localRequestOnly)
      try {
        core.getNode().store(b, false, req.canWriteClientCache, true, false);
      } catch (KeyCollisionException e) {
        KeyBlock collided =
            core.getNode().fetch(k.getNodeKey(), true, req.canWriteClientCache, false, false, null);
        if (collided == null) {
          LOG.error("Collided but no key?!");
          // Could be a race condition.
          try {
            core.getNode().store(b, false, req.canWriteClientCache, true, false);
          } catch (KeyCollisionException _) {
            LOG.error("Collided but no key and still collided!");
            throw new LowLevelPutException(
                LowLevelPutException.INTERNAL_ERROR,
                "Collided, can't find block, but still collides!",
                e);
          }
        }

        throw new LowLevelPutException(collided);
      }
    else
      core.getTransfers()
          .realPut(
              b,
              req.canWriteClientCache,
              req.forkOnCacheable,
              Node.PREFER_INSERT_DEFAULT,
              Node.IGNORE_LOW_BACKOFF_DEFAULT,
              req.realTimeFlag);
  }

  private boolean handleCollision(
      LowLevelPutException e,
      BlockItem block,
      ClientKey k,
      ClientContext context,
      ChosenBlock req) {
    try {
      ClientSSKBlock collided =
          ClientSSKBlock.construct(((SSKBlock) e.getCollidedBlock()), (ClientSSK) k);
      byte[] data = collided.memoryDecode(true);
      byte[] inserting = BucketTools.toByteArray(block.copyBucket);
      if (collided.isMetadata() == block.isMetadata
          && collided.getCompressionCodec() == block.compressionCodec
          && Arrays.equals(data, inserting)) {
        if (LOG.isDebugEnabled()) LOG.debug("Collided with identical data");
        req.onInsertSuccess(k, context);
        return true;
      } else {
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Apparently real collision: collided.isMetadata={} block.isMetadata={}"
                  + " collided.codec={} block.codec={} collided.datalength={}"
                  + " block.datalength={} H(collided)={} H(inserting)={}",
              collided.isMetadata(),
              block.isMetadata,
              collided.getCompressionCodec(),
              block.compressionCodec,
              data.length,
              inserting.length,
              Fields.hashCode(data),
              Fields.hashCode(inserting));
      }
    } catch (KeyVerifyException | KeyDecodeException | IOException e1) {
      LOG.error(LOG_CAUGHT_WHEN_CHECKING_COLLISION, e1, e1);
    }
    return false;
  }

  @Override
  public SendableRequestSender getSender(ClientContext context) {
    String compress;
    compress = ctx.getCompressorDescriptor();
    return new MySendableRequestSender(compress, this);
  }

  @Override
  public RequestClient getClient() {
    return parent.getClient();
  }

  @Override
  public ClientRequester getClientRequest() {
    return parent;
  }

  @Override
  public Object getToken() {
    return tokenObject;
  }

  /**
   * Attempt to encode the block if it has not been encoded yet.
   *
   * <p>Exceptions are captured and reported via {@link #fail(InsertException, ClientContext)}. This
   * helper does not requeue the request on background encoders.
   *
   * @param context Runtime context used for encoding.
   */
  public void tryEncode(ClientContext context) {
    synchronized (this) {
      if (resultingKey != null) return;
      if (finished) return;
    }
    try {
      encode(context);
    } catch (InsertException e) {
      fail(e, context);
    } catch (Exception t) {
      LOG.error(LOG_CAUGHT, t, t);
      // Don't requeue on BackgroundBlockEncoder.
      // Not necessary to do so (we'll ask again when we need it), and it'll probably just break
      // again.
    }
  }

  @Override
  public synchronized long countSendableKeys(ClientContext context) {
    if (finished) return 0;
    else return 1;
  }

  @Override
  public synchronized long countAllKeys(ClientContext context) {
    return countSendableKeys(context);
  }

  @Override
  public SendableRequestItem chooseKey(KeysFetchingLocally ignored, ClientContext context) {
    try {
      BlockItemKey key;
      synchronized (this) {
        if (finished) return null;
        key = new BlockItemKey(this, hashCode());
        if (ignored.hasInsert(key)) return null;
        return getBlockItem(key, context);
      }
    } catch (InsertException e) {
      fail(e, context);
      return null;
    }
  }

  @Override
  public long getWakeupTime(ClientContext context, long now) {
    KeysFetchingLocally keysFetching = getScheduler(context).fetchingKeys();
    synchronized (this) {
      if (finished) return -1;
      BlockItemKey key = new BlockItemKey(this, hashCode());
      if (keysFetching.hasInsert(key)) return Long.MAX_VALUE;
      return 0;
    }
  }

  private BlockItem getBlockItem(BlockItemKey key, ClientContext context) throws InsertException {
    try {
      synchronized (this) {
        if (finished) return null;
      }
      if (persistent && sourceData == null) {
        LOG.error("getBlockItem(): sourceData = null");
        fail(new InsertException(InsertExceptionMode.INTERNAL_ERROR), context);
        return null;
      }
      Bucket data = sourceData.createShadow();
      FreenetURI u = uri;
      if (u.getKeyType().equals("CHK")) u = FreenetURI.EMPTY_CHK_URI;
      if (shouldCopyFrom(data)) {
        data = context.tempBucketFactory.makeBucket(sourceData.size());
        BucketTools.copy(sourceData, data);
      }
      return new BlockItem(
          key,
          data,
          isMetadata,
          compressionCodec,
          sourceLength,
          u,
          persistent,
          cryptoAlgorithm,
          cryptoKey);
    } catch (IOException e) {
      throw new InsertException(InsertExceptionMode.BUCKET_ERROR, e, null);
    }
  }

  /** Everything needed to check whether we are already running a request */
  private static class BlockItemKey implements SendableRequestItemKey {
    private final int hashCode;

    /** STRICTLY for purposes of equals() !!! */
    private final SingleBlockInserter parent;

    BlockItemKey(SingleBlockInserter parent, int hashCode) {
      this.parent = parent;
      this.hashCode = hashCode;
    }

    @Override
    public int hashCode() {
      return hashCode;
    }

    @Override
    public boolean equals(Object o) {
      if (o instanceof BlockItemKey key) {
        return key.parent == parent;
      }
      return false;
    }
  }

  /**
   * Everything needed to actually run a request, without access to the SingleBlockInserter (this is
   * why we copy the Bucket).
   */
  private static class BlockItem implements SendableRequestItem {

    private final Bucket copyBucket;
    final BlockItemKey key;
    private final FreenetURI uri;
    private final boolean persistent;
    private final boolean isMetadata;
    private final short compressionCodec;
    private final int sourceLength;
    private final byte cryptoAlgorithm;
    private final byte[] cryptoKey;

    BlockItem(
        BlockItemKey key,
        Bucket bucket,
        boolean meta,
        short codec,
        int srclen,
        FreenetURI u,
        boolean persistent,
        byte cryptoAlgorithm,
        byte[] cryptoKey) {
      this.key = key;
      this.copyBucket = bucket;
      this.uri = u;
      this.isMetadata = meta;
      this.compressionCodec = codec;
      this.sourceLength = srclen;
      this.persistent = persistent;
      this.cryptoAlgorithm = cryptoAlgorithm;
      this.cryptoKey = cryptoKey;
    }

    @Override
    public void dump() {
      copyBucket.free();
    }

    @Override
    public SendableRequestItemKey getKey() {
      return key;
    }
  }

  @Override
  public boolean canWriteClientCache() {
    return ctx.isCanWriteClientCache();
  }

  @Override
  public boolean localRequestOnly() {
    return ctx.isLocalRequestOnly();
  }

  @Override
  public boolean forkOnCacheable() {
    return ctx.isForkOnCacheable();
  }

  @Override
  public void onEncode(SendableRequestItem token, ClientKey key, ClientContext context) {
    onEncode(key, context);
  }

  @Override
  public void innerOnResume(ClientContext context) throws InsertException, ResumeFailedException {
    sourceData.onResume(context);
    if (cb != parent) cb.onResume(context);
    if (resultingKey != null) cb.onEncode(resultingKey, SingleBlockInserter.this, context);
    this.schedule(context);
  }

  @Override
  public void onShutdown(ClientContext context) {
    // Ignore.
  }

  /**
   * Helper to determine whether a deep copy is required because createShadow() did not provide a
   * view.
   */
  private static boolean shouldCopyFrom(Bucket shadow) {
    return shadow == null;
  }

  /* ===== Java serialization hooks ===== */

  /**
   * Custom Java serialization hook delegating to default serialization.
   *
   * <p>Bucket serialization behavior remains unchanged; if the chosen {@link Bucket} implementation
   * is not {@link java.io.Serializable} and this instance is being persisted, the same {@link
   * java.io.NotSerializableException} is thrown as before.
   *
   * @param out Object stream receiving the serialized form of this instance.
   * @throws java.io.IOException If the underlying stream fails while writing object data.
   */
  @Serial
  private void writeObject(java.io.ObjectOutputStream out) throws java.io.IOException {
    // Delegate to default serialization. Bucket serialization behavior remains unchanged; if the
    // chosen Bucket implementation is not Serializable and this instance is being persisted, the
    // same NotSerializableException will be thrown as before.
    out.defaultWriteObject();
  }

  /**
   * Custom Java deserialization hook delegating to default deserialization.
   *
   * @param in Object stream providing the serialized form of this instance.
   * @throws java.io.IOException If the underlying stream fails while reading object data.
   * @throws ClassNotFoundException If a required class cannot be resolved during deserialization.
   */
  @Serial
  private void readObject(java.io.ObjectInputStream in)
      throws java.io.IOException, ClassNotFoundException {
    in.defaultReadObject();
  }
}
