package network.crypta.clients.fcp;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.Serial;
import java.io.Serializable;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchException;
import network.crypta.client.FetchResult;
import network.crypta.client.InsertContext;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientGetter;
import network.crypta.client.async.ClientRequester;
import network.crypta.clients.fcp.RequestIdentifier.RequestType;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.keys.FreenetURI;
import network.crypta.node.NodeClientCore;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ResumeFailedException;
import network.crypta.support.io.StorageFormatException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Coordinates a single FCP GET request over the asynchronous client interface.
 *
 * <p>This request owns its {@link FetchContext}, {@link ClientGetter}, progress caches, and
 * persistence metadata so it can migrate cleanly between a connection queue, the global queue, and
 * durable storage across node restarts. It translates client-side events into higher-level FCP
 * messages, tracks retry and restart policy, and resolves the selected delivery strategy (direct
 * bucket, disk file, chunked stream, or acknowledgement only). The class therefore acts as the
 * boundary between long-lived persistent jobs and transient FCP sessions.
 *
 * <p>The request behaves as a long-lived, mutable state machine. Mutable fields and persistence
 * snapshots are guarded by a single request lock, so lifecycle updates, replay, and serialization
 * observe a consistent state. Accessors return point-in-time views; callers should avoid mutating
 * returned objects or assuming immediate cross-thread visibility without synchronization.
 *
 * <p>Typical usage is to construct the request from a {@link ClientGetMessage}, register it with
 * the owning client queue, and then invoke {@link #start(ClientContext)}. The request may persist
 * across reconnections, and callers should treat it as a long-lived state machine whose outputs are
 * FCP messages rather than synchronous return values.
 *
 * <ul>
 *   <li><strong>Queueing and persistence</strong>: registers against either the connection-scoped
 *       or global queue and emits persistent tags.
 *   <li><strong>Progress and metadata</strong>: consumes splitfile events to project hashes, sizes,
 *       and MIME types for status reporting.
 *   <li><strong>Delivery</strong>: enforces {@link ReturnType} semantics when writing buckets or
 *       emitting {@link AllDataMessage} payloads.
 * </ul>
 *
 * @see ClientRequest
 * @see ClientGetter
 * @see network.crypta.client.async.ClientGetCallback
 */
public final class ClientGet extends ClientRequest {
  private static final Logger LOG = LoggerFactory.getLogger(ClientGet.class);

  @Serial private static final long serialVersionUID = 1L;

  /**
   * Fetch context. Never passed in: always created new by the ClientGet. Therefore, we can safely
   * delete it in requestWasRemoved().
   */
  private final FetchContext fctx;

  /** Underlying asynchronous fetcher responsible for talking to the node core. */
  private final ClientGetter getter;

  /** Selected return strategy describing how result data should be surfaced to the caller. */
  private final ReturnType returnType;

  /** Destination file when {@link ReturnType#DISK} is in effect; {@code null} otherwise. */
  private final File targetFile;

  /** Holds mutable state such as progress snapshots and cached buckets. */
  private final ClientGetState state;

  /** Stable lock used for persistence-related synchronization. */
  private final PersistenceLock persistenceLock = new PersistenceLock();

  /** Indicates that the caller expects the result as a BinaryBlob stream rather than a bucket. */
  private final boolean binaryBlob;

  /** Optional client-provided filename extension used to validate post-filtering output. */
  private final String extensionCheck;

  /** Metadata bucket supplied at creation time, relayed untouched to the {@link ClientGetter}. */
  @SuppressWarnings("java:S1948")
  private final Bucket initialMetadata;

  private transient ClientGetMessageReplay messageReplay;
  private transient ClientGetLifecycle lifecycle;
  private transient ClientGetStatusSnapshotBuilder statusSnapshotBuilder;
  private transient ClientGetRestartCoordinator restartCoordinator;
  private transient ClientGetStatusReporter statusReporter;

  // Verbosity bitmasks
  static final int VERBOSITY_SPLITFILE_PROGRESS = 1;
  static final int VERBOSITY_SENT_TO_NETWORK = 2;
  static final int VERBOSITY_COMPATIBILITY_MODE = 4;
  static final int VERBOSITY_EXPECTED_HASHES = 8;
  static final int VERBOSITY_EXPECTED_TYPE = 32;
  static final int VERBOSITY_EXPECTED_SIZE = 64;
  static final int VERBOSITY_ENTER_FINITE_COOLDOWN = 128;

  // Legacy threshold callback removed.

  /**
   * Defines how fetched bytes are delivered to the remote FCP caller.
   *
   * <p>This enum is serialized into compact short codes so persistent requests can be restored
   * exactly across restarts and reconnections. It also drives which message types are emitted (such
   * as {@link AllDataMessage} versus metadata-only status updates) and whether the request
   * allocates disk buckets up front. Callers choose a value based on the desired delivery
   * semantics, expected payload size, and whether they need immediate access to the content or only
   * completion status.
   *
   * <p>Because the value is persisted, any changes must remain backward compatible with the stored
   * codes.
   */
  public enum ReturnType {
    /**
     * Returns the downloaded data immediately as an {@link AllDataMessage} bucket.
     *
     * <p>This mode is appropriate for direct client reads where the connection is expected to
     * remain open until completion. The payload is surfaced as a bucket that the connection handler
     * streams to the caller, and callers should treat the bucket contents as read-only.
     */
    DIRECT((short) 0),
    /**
     * Suppresses data transfer entirely and reports only success or failure metadata.
     *
     * <p>This mode is useful for probes or availability checks where only status, sizes, or MIME
     * hints are needed. The request still performs validation and updates progress caches, but it
     * does not emit the payload itself.
     */
    NONE((short) 1),
    /**
     * Streams the fully downloaded payload into a caller-provided file on disk.
     *
     * <p>Disk output is gated by DDA and node policy checks, and the target path is validated
     * before the fetch starts. Callers should ensure the destination is writable and stable across
     * restarts because the request may resume or restart.
     */
    DISK((short) 2),
    /**
     * Provides the payload over the chunked transfer protocol extension.
     *
     * <p>This mode streams bytes in chunks rather than a single terminal message, enabling large
     * downloads over long-lived connections. Progress and completion events are still emitted so
     * clients can reconcile final status with partial chunk delivery.
     */
    CHUNKED((short) 3);

    final short code;

    ReturnType(short code) {
      this.code = code;
    }

    /**
     * Maps a serialized return-type code back to the corresponding enum constant.
     *
     * <p>Persistence files and FCP messages store a short code to minimize storage and bandwidth.
     * This helper converts that compact value into the strongly typed enum used by the rest of the
     * request pipeline. Unknown codes indicate corrupt persistence data or an incompatible sender
     * and are rejected immediately to avoid ambiguous delivery behavior.
     *
     * <p>This method is pure and has no side effects. It should be used whenever decoding persisted
     * state or remote inputs so that return-type semantics remain centralized and consistent.
     *
     * @param x numeric tag from persistence or FCP messages; expected range 0-3.
     * @return matching {@link ReturnType} describing the delivery semantics for the code.
     * @throws IllegalArgumentException if the code is outside the recognized return-type range.
     */
    public static ReturnType getByCode(short x) {
      return switch (x) {
        case 0 -> DIRECT;
        case 1 -> NONE;
        case 2 -> DISK;
        case 3 -> CHUNKED;
        default -> throw new IllegalArgumentException();
      };
    }
  }

  /**
   * Bundles configuration for persistent global GET requests to keep constructors concise.
   *
   * <p>Instances capture all per-request tuning parameters that are otherwise passed positionally.
   * The record is intentionally immutable, so callers can safely reuse it across retries or
   * validation steps without worrying about concurrent mutation. Callers typically populate it from
   * parsed FCP messages or persisted metadata before invoking the global-queue constructor, and the
   * values are meant to be safe for logging or storage because they avoid holding live buckets.
   *
   * <ul>
   *   <li>Queue scope: persistence flags, identifiers, and real-time scheduling hints.
   *   <li>Data handling: maximum output sizes, return type, and disk destination path.
   *   <li>Behavior flags: datastore reachability, filtering, and cache-write preferences.
   * </ul>
   *
   * @param dsOnly true to restrict fetches to the local datastore only.
   * @param ignoreDS true to bypass datastore reads when evaluating availability hints.
   * @param filterData true to apply content filtering before delivery or disk write.
   * @param maxSplitfileRetries maximum retry count per splitfile block; must be non-negative.
   * @param maxNonSplitfileRetries maximum retry count for non-splitfile requests; must be
   *     non-negative.
   * @param maxOutputLength maximum bytes allowed for payload and temporary storage.
   * @param returnType delivery mode describing how payload bytes are surfaced.
   * @param persistRebootOnly true to persist across reboots, false for forever.
   * @param identifier caller-supplied identifier echoed in progress and status messages.
   * @param verbosity bitmask controlling which progress events are emitted.
   * @param prioClass priority class guiding scheduler ordering and bandwidth share.
   * @param returnFilename disk destination path used only when ReturnType.DISK applies.
   * @param charset legacy charset hint; ignored but preserved for compatibility logging.
   * @param writeToClientCache true to allow writing the payload into the client cache.
   * @param realTimeFlag true for realtime scheduler lane, false for bulk queue.
   * @param binaryBlob true to return BinaryBlob output instead of a raw bucket.
   */
  public record GlobalRequestConfig(
      boolean dsOnly,
      boolean ignoreDS,
      boolean filterData,
      int maxSplitfileRetries,
      int maxNonSplitfileRetries,
      long maxOutputLength,
      ReturnType returnType,
      boolean persistRebootOnly,
      String identifier,
      int verbosity,
      short prioClass,
      File returnFilename,
      String charset,
      boolean writeToClientCache,
      boolean realTimeFlag,
      boolean binaryBlob) {}

  /** Bundles construction inputs to keep request constructors compact. */
  record ClientGetSetup(
      FetchContext fetchContext,
      ClientGetReturnPlanner.ReturnSetup returnSetup,
      ReturnType returnType,
      boolean binaryBlob,
      Bucket initialMetadata,
      NodeClientCore core) {}

  /**
   * Creates a new request that has already been validated and configured by {@link
   * ClientGetFactory}.
   *
   * <p>Callers are expected to supply an initialized {@link FetchContext}, return routing data, and
   * any initial metadata buckets. The constructor wires up request state, event listeners, and the
   * underlying {@link ClientGetter} but performs no validation on the inputs.
   */
  ClientGet(ClientRequestParams params, PersistentRequestClient globalClient, ClientGetSetup setup)
      throws IOException {
    super(prepareConstructorInit(params, null, globalClient));
    state = new ClientGetState(this);
    fctx = setup.fetchContext();
    fctx.getEventProducer().addEventListener(new ClientGetEventHandling(this));
    this.returnType = setup.returnType();
    this.binaryBlob = setup.binaryBlob();
    ClientGetReturnPlanner.ReturnSetup returnSetup = setup.returnSetup();
    this.targetFile = returnSetup.targetFile();
    this.extensionCheck = returnSetup.extension();
    this.initialMetadata = setup.initialMetadata();
    getter = makeGetter(setup.core(), returnSetup.bucket());
    initHelpers();
  }

  /**
   * Creates a connection-scoped request that has already been validated and configured by {@link
   * ClientGetFactory}.
   */
  ClientGet(ClientRequestParams params, FCPConnectionHandler handler, ClientGetSetup setup)
      throws IOException {
    super(prepareConstructorInit(params, handler));
    state = new ClientGetState(this);
    fctx = setup.fetchContext();
    fctx.getEventProducer().addEventListener(new ClientGetEventHandling(this));
    this.returnType = setup.returnType();
    this.binaryBlob = setup.binaryBlob();
    ClientGetReturnPlanner.ReturnSetup returnSetup = setup.returnSetup();
    this.targetFile = returnSetup.targetFile();
    this.extensionCheck = returnSetup.extension();
    this.initialMetadata = setup.initialMetadata();
    getter = makeGetter(setup.core(), returnSetup.bucket());
    initHelpers();
  }

  private ClientGetter makeGetter(Bucket ret) throws IOException {
    return makeGetter(null, ret);
  }

  private ClientGetter makeGetter(NodeClientCore core, Bucket ret) throws IOException {
    return ClientGetGetterFactory.createGetterForRequest(this, ret, core);
  }

  ClientGetter makeGetterForPersistence(Bucket ret) throws IOException {
    return makeGetter(ret);
  }

  /**
   * Serialization-only constructor used when reconstructing requests from persistent storage.
   *
   * <p>All fields are intentionally left {@code null} (or primitive defaults) so that the
   * deserialization helpers can populate them explicitly via {@link #innerResume(ClientContext)}
   * and related restoration methods. Production code should never invoke this constructor directly;
   * always use one of the fully parameterized alternatives that configure a {@link FetchContext}
   * and {@link ClientGetter}. This constructor exists solely to satisfy the Java serialization
   * framework and keep field initialization centralized in the resume path.
   */
  ClientGet() {
    // For serialization.
    state = new ClientGetState(this);
    fctx = null;
    getter = null;
    returnType = null;
    targetFile = null;
    binaryBlob = false;
    extensionCheck = null;
    initialMetadata = null;
  }

  private void initHelpers() {
    if (messageReplay == null) {
      messageReplay = new ClientGetMessageReplay(this);
    }
    if (lifecycle == null) {
      lifecycle = new ClientGetLifecycle(this);
    }
    if (statusSnapshotBuilder == null) {
      statusSnapshotBuilder = new ClientGetStatusSnapshotBuilder(this);
    }
    if (restartCoordinator == null) {
      restartCoordinator = new ClientGetRestartCoordinator(this);
    }
    if (statusReporter == null) {
      statusReporter = new ClientGetStatusReporter(this);
    }
  }

  private ClientGetMessageReplay messageReplay() {
    initHelpers();
    return messageReplay;
  }

  private ClientGetLifecycle lifecycle() {
    initHelpers();
    return lifecycle;
  }

  private ClientGetStatusSnapshotBuilder statusSnapshotBuilder() {
    initHelpers();
    return statusSnapshotBuilder;
  }

  private ClientGetRestartCoordinator restartCoordinator() {
    initHelpers();
    return restartCoordinator;
  }

  private ClientGetStatusReporter statusReporter() {
    initHelpers();
    return statusReporter;
  }

  ClientGetState state() {
    return state;
  }

  Object persistenceLock() {
    return persistenceLock;
  }

  /**
   * Returns the lock that guards shared request lifecycle state.
   *
   * <p>The base request class mutates the started and finished flags under this lock, and this
   * subclass uses the same lock for persistence snapshots and replay data. Using a single lock
   * establishes a consistent happens-before relationship across lifecycle updates and
   * serialization. Callers should synchronize only for short, state-centric operations and should
   * not expose this lock outside the request.
   *
   * @return stable lock object shared by base and subclass state transitions.
   */
  @Override
  protected Object requestLock() {
    return persistenceLock;
  }

  private static final class PersistenceLock implements Serializable {
    @Serial private static final long serialVersionUID = 1L;
  }

  /**
   * Must be called just after construction but within a transaction.
   *
   * @throws IdentifierCollisionException If the identifier is already in use.
   */
  @Override
  void register(boolean noTags) throws IdentifierCollisionException {
    assert client == null || (this.persistence == client.persistence);
    if (persistence != Persistence.CONNECTION) {
      if (client == null) {
        throw new NullPointerException("Persistent client must be available to register");
      }
      PersistentRequestClient persistentClient = client;
      persistentClient.register(this);
      if (!noTags) {
        FCPMessage msg = persistentTagMessage();
        persistentClient.queueClientRequestMessage(msg, 0);
      }
    }
  }

  /**
   * Starts the asynchronous fetch if it has not yet reached a terminal state.
   *
   * <p>This method synchronizes briefly to avoid racing with completion logic, kicks off the
   * underlying {@link ClientGetter}, and emits a persistent tag when the request is tracked beyond
   * the connection scope. It updates {@link RequestStatusCache} listeners so UIs can reflect the
   * {@code started} flag even if the fetch fails before any progress callbacks are produced. The
   * call is idempotent with respect to terminal state: if the request is already finished, it
   * returns immediately without side effects. Exceptions raised by the getter are translated into
   * {@link FetchException} instances and routed through {@link #onFailure(FetchException)} to
   * ensure consistent cleanup.
   *
   * <p>On success, this call merely schedules work; it does not block for results. If a failure is
   * raised before progress events fire, the request is still marked as started so external status
   * caches remain consistent. Callers may invoke this multiple times safely; only the first call
   * before completion has any effect.
   *
   * @param context client context providing schedulers, bucket factories, and execution lanes.
   */
  @Override
  public void start(ClientContext context) {
    try {
      synchronized (persistenceLock) {
        if (finished) return;
      }
      getter.start(context);
      if (shouldSendPersistentTag()) {
        FCPMessage msg = persistentTagMessage();
        client.queueClientRequestMessage(msg, 0);
      }
      synchronized (persistenceLock) {
        started = true;
      }
      if (client != null) {
        RequestStatusCache cache = client.getRequestStatusCache();
        if (cache != null) {
          cache.updateStarted(identifier, true);
        }
      }
    } catch (FetchException e) {
      synchronized (persistenceLock) {
        started = true;
      } // before the failure handler
      onFailure(e);
    } catch (Exception t) {
      synchronized (persistenceLock) {
        started = true;
      }
      onFailure(new FetchException(FetchExceptionMode.INTERNAL_ERROR, t));
    }
  }

  private boolean shouldSendPersistentTag() {
    synchronized (persistenceLock) {
      return persistence != Persistence.CONNECTION && !finished;
    }
  }

  /**
   * Handles disconnections from the node core scheduler or client transport.
   *
   * <p>If the request uses connection-scoped persistence, the loss of transport means the request
   * can no longer deliver results to that client, so it is canceled immediately. Global queue
   * requests continue running and rely on later reconnection to deliver any pending messages. This
   * method does not attempt to resume or restart; it only decides whether the request remains
   * active based on the persistence model. The call is safe to invoke multiple times.
   *
   * <p>The method has no effect on finished requests and does not modify request metadata beyond a
   * possible cancellation. It exists primarily so connection handlers can dispose of
   * connection-scoped work without leaking persistent tasks.
   *
   * @param context client context owning the request and its scheduler association.
   */
  @Override
  public void onLostConnection(ClientContext context) {
    if (persistence == Persistence.CONNECTION) cancel(context);
    // Otherwise ignore
  }

  /**
   * Processes a successful fetch completion and notifies all interested parties.
   *
   * <p>The method snapshots final MIME type, payload length, completion timestamp, and the bucket
   * or blob handle returned by {@link ClientGetter}. Depending on {@link ReturnType}, it either
   * retains the bucket for {@link AllDataMessage} delivery or leaves the bytes on disk. It then
   * emits {@link DataFoundMessage} and {@link AllDataMessage} as appropriate, updates status
   * caches, and informs the owning {@link FCPConnectionHandler} or {@link PersistentRequestClient}.
   * Any secondary calls are ignored defensively to prevent double frees or duplicate notifications.
   *
   * <p>For BinaryBlob requests, the MIME type is forced to the blob MIME and the bucket length is
   * derived from the blob bucket rather than the decoded metadata bucket. The method always updates
   * completion time before any outbound messages so that emitted timestamps remain consistent.
   *
   * @param result result wrapper providing MIME metadata and the decoded data bucket.
   * @param state client getter instance used to access BinaryBlob payload buckets.
   */
  public void onSuccess(FetchResult result, ClientGetter state) {
    lifecycle().onSuccess(result, state);
  }

  /**
   * Forces the request into a successful state when migrating legacy persistence records.
   *
   * <p>This helper is used by upgrade tooling that replays on-disk state and needs stronger
   * validation than regular resume paths. It checks that disk targets or direct buckets already
   * match the recorded {@code foundDataLength}, captures the supplied completion timestamp, and
   * stores the provided bucket when {@link ReturnType#DIRECT} applies. Any mismatch results in a
   * {@link ResumeFailedException}, forcing the caller to restart the download rather than trusting
   * potentially corrupted state. This method is intended for controlled migration flows only.
   *
   * <p>The method does not trigger network activity and does not emit FCP messages; it only updates
   * cached fields so that later status queries and persistence writes reflect the migrated success
   * state.
   *
   * @param context client context performing migration validation and bucket operations.
   * @param completionTime epoch milliseconds for the recorded completion instant.
   * @param data bucket containing the downloaded payload for direct delivery.
   * @throws ResumeFailedException when stored output does not match recorded metadata.
   */
  @SuppressWarnings("unused")
  public void setSuccessForMigration(ClientContext context, long completionTime, Bucket data)
      throws ResumeFailedException {
    lifecycle().setSuccessForMigration(context, completionTime, data);
  }

  void trySendDataFoundOrGetFailed(
      FCPConnectionOutputHandler handler, String listRequestIdentifier) {
    messageReplay().trySendDataFoundOrGetFailed(handler, listRequestIdentifier);
  }

  void trySendAllDataMessage(FCPConnectionOutputHandler handler, String listRequestIdentifier) {
    messageReplay().trySendAllDataMessage(handler, listRequestIdentifier);
  }

  void queueProgressMessageInner(FCPMessage msg, int verbosityMask) {
    messageReplay().queueProgressMessageInner(msg, verbosityMask);
  }

  /**
   * Flushes whatever queued state should be replayed to a reconnecting FCP client.
   *
   * <p>The replay mirrors the initial sequence: persistent tags, the latest splitter progress,
   * optional {@link SendingToNetworkMessage}, final success or failure notifications, and (when
   * requested) the {@link AllDataMessage}. It also ships compatibility metadata, hashes, MIME
   * hints, and expected lengths so late subscribers observe the same state as live listeners. When
   * the caller only wants data, the method enforces {@link ReturnType#DIRECT} and otherwise emits a
   * {@link ProtocolErrorMessage}. The method is idempotent and only reflects the cached request
   * state at the time of invocation.
   *
   * <p>The call does not mutate the request state; it simply replays cached snapshots and queued
   * flags. Callers should ensure the handler is ready to accept messages because the method may
   * emit multiple frames in quick succession.
   *
   * @param handler output handler representing the destination connection for replay.
   * @param listRequestIdentifier optional identifier for list or batch operations.
   * @param includeData {@code true} to include {@link AllDataMessage} bodies when present.
   * @param onlyData {@code true} to send only payload frames, skipping metadata.
   */
  @Override
  public void sendPendingMessages(
      FCPConnectionOutputHandler handler,
      String listRequestIdentifier,
      boolean includeData,
      boolean onlyData) {
    messageReplay().sendPendingMessages(handler, listRequestIdentifier, includeData, onlyData);
  }

  FCPMessage persistentTagMessage() {
    return statusSnapshotBuilder().persistentTagMessage();
  }

  // Mirrors ClientPut/ClientPutDir to keep low-level scheduling flags accessible to subclasses.
  boolean isRealTime() {
    if (lowLevelClient == null) {
      // This can happen but only due to data corruption - old databases on which various bugs have
      // resulted in it getting deleted and also possibly failed deletions.
      LOG.warn("lowLevelClient == null");
      return false;
    }
    return lowLevelClient.realTimeFlag();
  }

  /**
   * Handles failure notifications from the {@link ClientGetter} and propagates them to clients.
   *
   * <p>The failure path caches any expected size or MIME hints exposed by the exception, builds a
   * {@link GetFailedMessage}, records completion timestamps, and marks the request as finished so
   * restart logic can take over. It then emits {@link DataFoundMessage} or {@link GetFailedMessage}
   * equivalents, intentionally leaving buckets intact so restart attempts can reuse cached blocks.
   * Secondary invocations after completion are ignored to preserve idempotency.
   *
   * <p>Callers should treat this as terminal for the current attempt; a later restart will clear
   * the cached failure and reinitialize progress tracking.
   *
   * @param e failure descriptor that supplies the expected size, MIME type, and mode.
   */
  public void onFailure(FetchException e) {
    lifecycle().onFailure(e);
  }

  /**
   * Cleans up when the owning queue removes the request, either manually or due to shut down.
   *
   * <p>If the fetch was still running, it fabricates a cancellation {@link FetchException} so the
   * client receives a {@link GetFailedMessage} with an explicit code. Afterward it notifies the
   * connection or persistent client that the entry disappeared, frees associated buckets, and calls
   * the superclass hook so shared accounting (such as tag persistence) also runs. This method is
   * safe to invoke once per removal event.
   *
   * <p>The removal path does not attempt to stop network activity directly; it assumes the owning
   * scheduler has already detached the underlying {@link ClientGetter}.
   *
   * @param context client context invoking the removal for lifecycle bookkeeping.
   */
  @Override
  public void requestWasRemoved(ClientContext context) {
    lifecycle().requestWasRemoved();
    super.requestWasRemoved(context);
  }

  ReturnType returnTypeForReplay() {
    return returnType;
  }

  File targetFileForLifecycle() {
    return targetFile;
  }

  /**
   * Exposes the underlying {@link ClientRequester} for base-class scheduling operations.
   *
   * <p>The base {@link ClientRequest} infrastructure uses this accessor to determine which
   * requester instance owns the in-flight operation for persistence, cancellation, and stats
   * tracking. The returned object is the request's active {@link ClientGetter} and should be
   * treated as read-only by callers outside the request lifecycle.
   *
   * @return client requester instance used to run this request.
   */
  @Override
  protected ClientRequester getClientRequest() {
    return getter;
  }

  /**
   * Releases in-memory buckets owned by the request once completion is finalized.
   *
   * <p>This method intentionally does not remove data written to disk, because disk-backed requests
   * are expected to leave the payload in place for the caller. It clears and frees any
   * direct-return buckets and the initial metadata bucket if present. The method is safe to call
   * multiple times; later invocations become no-ops.
   */
  @Override
  protected void freeData() {
    // We don't remove the data if written to a file.
    Bucket data;
    synchronized (persistenceLock) {
      data = state.takeReturnBucketDirect();
    }
    if (data != null) {
      data.close();
    }
    if (initialMetadata != null) initialMetadata.free();
  }

  /**
   * Reports whether the request has completed successfully and retained its payload metadata.
   *
   * <p>The value remains {@code true} even after {@link #freeData()} releases buckets so that
   * clients can distinguish between cleanly finished requests and those canceled during restart. It
   * is set when {@link #onSuccess(FetchResult, ClientGetter)} records the terminal state and never
   * reset unless a restart is initiated.
   *
   * <p>This flag is a snapshot of the most recent attempt; it does not imply that payload data is
   * still available in memory. Callers should consult {@link #getBucket()} or {@link
   * #getDestFilename()} if they need access to the payload itself.
   *
   * @return {@code true} once final success has been recorded for this request.
   */
  @Override
  public boolean hasSucceeded() {
    return state.hasSucceeded();
  }

  /**
   * Indicates whether the request expects {@link ReturnType#DIRECT} delivery semantics.
   *
   * <p>Direct mode keeps the downloaded bucket resident so reconnecting clients can still replay an
   * {@link AllDataMessage}. Disk-bound and chunked requests, by contrast, cannot ship the payload
   * back through the queue once the transfer has completed. This flag is informational and does not
   * initiate any I/O.
   *
   * <p>Use this as a hint when deciding whether to request replayed data from a persistent queue.
   *
   * @return {@code true} when AllData messages should be emitted upon completion.
   */
  public boolean isDirect() {
    return this.returnType == ReturnType.DIRECT;
  }

  /**
   * Indicates whether the payload should be written directly to the caller's disk path.
   *
   * <p>{@link ReturnType#DISK} requests rely on {@link #targetFile} for their lifecycle checks,
   * including restart validation to ensure partially written files are safe to reuse. This flag
   * mirrors the configured return type and does not check whether the file already exists.
   *
   * <p>Callers should treat this as configuration metadata, not proof of a completed download.
   *
   * @return {@code true} when this request writes into a caller-specified file.
   */
  public boolean isToDisk() {
    return this.returnType == ReturnType.DISK;
  }

  /**
   * Returns the current URI the request is fetching, including redirects applied after restarts.
   *
   * <p>The URI may change over time if redirects are followed during retries or restarts. The
   * returned instance is the live reference used by this request, so callers should treat it as
   * read-only and avoid mutating it. This accessor is side-effect free and can be called at any
   * time, but it does not synchronize with concurrent updates beyond the request's own locking.
   *
   * <p>Use this value for status displays or persistence serialization rather than for mutation.
   *
   * @return current {@link FreenetURI} reference describing the active fetch target.
   */
  public FreenetURI getURI() {
    return uri;
  }

  /**
   * Exposes the fetch context for package-local helpers.
   *
   * @return live {@link FetchContext} backing this request for internal helper access.
   */
  FetchContext fetchContextForGetter() {
    return fctx;
  }

  /**
   * Exposes the metadata bucket associated with this request.
   *
   * @return initial metadata bucket, or {@code null} when no metadata is provided.
   */
  Bucket initialMetadataBucket() {
    return initialMetadata;
  }

  /**
   * Returns the optional filename extension hint used for validation.
   *
   * @return extension hint or {@code null} when none is set.
   */
  String extensionCheckForGetter() {
    return extensionCheck;
  }

  /**
   * Returns the configured delivery strategy for the request.
   *
   * @return configured {@link ReturnType} used to decide how results are delivered.
   */
  ReturnType returnTypeForGetter() {
    return returnType;
  }

  /**
   * Indicates whether Binary Blob recording is enabled for this request.
   *
   * @return {@code true} when Binary Blob output is expected for this request.
   */
  boolean binaryBlobRequested() {
    return binaryBlob;
  }

  /**
   * Returns the best-known payload size in bytes, either from splitter hints or the final download.
   *
   * <p>The value is persisted between restarts and updated whenever {@link FetchException}
   * discloses an expected size, allowing clients to show progress even before real data arrives. A
   * value of {@code -1} means the size is still unknown. This accessor does not trigger any network
   * activity and simply returns the latest cached estimate.
   *
   * <p>The reported value may be provisional early in the fetch and should be treated as an
   * estimate rather than a guarantee of final size.
   *
   * @return recorded payload length in bytes, or {@code -1} when unknown.
   */
  public long getDataSize() {
    if (state.getFoundDataLength() > 0) return state.getFoundDataLength();
    return -1;
  }

  /**
   * Returns the MIME type detected so far for the payload.
   *
   * <p>Splitter hints, {@code ExpectedMIMEEvent} notifications, and the final {@link FetchResult}
   * metadata all update this string, which is persisted to help clients decide whether to stream or
   * store results. The value can be {@code null} if no MIME information has been reported yet. This
   * accessor returns the latest cached value without forcing any additional validation.
   *
   * <p>Callers should be prepared for {@code null} or generic MIME types when content is still
   * being discovered.
   *
   * @return MIME type reported for the payload, or {@code null} if undetermined.
   */
  public String getMIMEType() {
    if (state.getFoundDataMimeType() != null) return state.getFoundDataMimeType();
    return null;
  }

  /**
   * Returns the on-disk destination file if the request was configured for disk output.
   *
   * <p>The file reference is established during request construction and remains stable across
   * restarts. It may not exist until the download succeeds, and callers should not assume it is
   * created or populated. When the return type is not {@link ReturnType#DISK}, this method returns
   * {@code null}.
   *
   * <p>Use this to locate persisted output only after completion has been reported.
   *
   * @return destination file for disk downloads, or {@code null} otherwise.
   */
  public File getDestFilename() {
    return targetFile;
  }

  /**
   * Returns the fraction of splitfile blocks downloaded successfully.
   *
   * <p>The metric reflects the most recent {@code SplitfileProgressEvent} cached by the request,
   * making it useful for dashboards that prefer percentages to raw block counts. When no progress
   * has been recorded it returns {@code -1} to signal an unknown fraction. The value is a snapshot
   * and may lag behind the underlying fetcher in highly concurrent flows.
   *
   * @return value between {@code 0.0} and {@code 1.0}, or {@code -1} when unavailable.
   */
  @Override
  public double getSuccessFraction() {
    return statusReporter().getSuccessFraction();
  }

  /**
   * Returns the total number of blocks expected for the splitfile once finalized.
   *
   * <p>The count is derived from the latest progress snapshot and is intended for UI display or
   * coarse scheduling decisions. If no progress snapshot exists yet, this method returns {@code 1}
   * as a neutral nonzero denominator to avoid division by zero in callers.
   *
   * @return total block count from the latest progress event, or {@code 1} when unknown.
   */
  @Override
  public double getTotalBlocks() {
    return statusReporter().getTotalBlocks();
  }

  /**
   * Returns the minimum number of blocks that must be fetched before decode succeeds.
   *
   * <p>The value comes from the most recent splitfile progress snapshot and may be lower than the
   * total block count when redundancy is available. If the request has not reported progress yet,
   * this method returns {@code 1} to represent an unknown, nonzero minimum.
   *
   * @return minimum required blocks based on progress, or {@code 1} if unspecified.
   */
  @Override
  public double getMinBlocks() {
    return statusReporter().getMinBlocks();
  }

  /**
   * Returns the number of blocks that have failed but might be retried successfully later.
   *
   * <p>This value is taken from the most recent progress message and represents blocks that have
   * failed during reconstruction. It may reset or change as retries occur. If no progress has been
   * recorded, the method returns {@code 0} to indicate an unknown or empty failure count.
   *
   * @return count of non-fatal failed blocks, defaulting to {@code 0} when unknown.
   */
  @Override
  public double getFailedBlocks() {
    return statusReporter().getFailedBlocks();
  }

  /**
   * Returns the number of blocks that failed permanently and will never be retried.
   *
   * <p>Fatal failures represent blocks that cannot be recovered with additional retries or
   * redundancy. The value is taken from the last progress snapshot and may remain {@code 0} for
   * successful or in-progress requests. If no progress has been recorded, {@code 0} is returned.
   *
   * @return fatal failure block count, defaulting to {@code 0} when no data exists yet.
   */
  @Override
  public double getFatalyFailedBlocks() {
    return statusReporter().getFatalyFailedBlocks();
  }

  /**
   * Returns how many blocks have been successfully fetched so far.
   *
   * <p>The count reflects the most recent progress snapshot and is useful for rough throughput or
   * completion estimates. It does not represent the number of blocks already delivered to the
   * client, only those retrieved by the fetcher. If no progress has been recorded, {@code 0} is
   * returned.
   *
   * @return number of fetched blocks, defaulting to {@code 0} when progress is unavailable.
   */
  @Override
  public double getFetchedBlocks() {
    return statusReporter().getFetchedBlocks();
  }

  /**
   * Returns the compatibility modes detected while traversing splitfile metadata.
   *
   * <p>The values are accumulated as splitfile metadata is parsed and are persisted across
   * restarts. They help reinsertion logic or UI surfaces decide whether a retrieved file can be
   * reinserted using legacy encodings. The returned array is owned by the compatibility analyzer,
   * so callers should treat it as read-only.
   *
   * @return array of compatibility modes; may be empty but never {@code null}.
   */
  public InsertContext.CompatibilityMode[] getCompatibilityMode() {
    return state.getCompatibilityMode();
  }

  /**
   * Indicates whether reinsertion should skip compression because the source data was
   * precompressed.
   *
   * <p>This flag is derived from splitfile metadata analysis and is persisted across restarts. It
   * is intended for downstream insert flows that want to preserve the original byte structure
   * rather than applying a second compression pass. The value is informational and does not affect
   * the fetch itself.
   *
   * @return {@code true} when compression should not be applied to later insert contexts.
   */
  public boolean getDontCompress() {
    return state.getDontCompress();
  }

  /**
   * Returns the crypto key inferred while parsing splitfile metadata, if one was embedded.
   *
   * <p>The key is extracted from compatibility hints and is useful for reinsertion workflows that
   * need to preserve the original encryption parameters. It may be {@code null} if no override was
   * present. Callers should treat the returned bytes as immutable.
   *
   * @return copy of the crypto key bytes, or {@code null} when no override was observed.
   */
  public byte[] getOverriddenSplitfileCryptoKey() {
    return state.getOverriddenSplitfileCryptoKey();
  }

  /**
   * Returns a textual explanation for the most recent failure, if any.
   *
   * <p>The summary is derived from the cached {@link GetFailedMessage} and may include additional
   * diagnostic text when requested. It returns {@code null} when no failure has been recorded,
   * which typically means the request is still running or has completed successfully. The returned
   * text is suitable for UI display and is not guaranteed to be stable across versions.
   *
   * <p>This accessor does not alter the request state. Callers should treat the value as a snapshot
   * of the last recorded failure rather than a live view of the underlying fetcher.
   *
   * @param longDescription {@code true} to append extended diagnostic detail when available.
   * @return human-readable failure summary, or {@code null} when no failure exists.
   */
  @Override
  public String getFailureReason(boolean longDescription) {
    return statusReporter().getFailureReason(longDescription);
  }

  GetFailedMessage getFailureMessage() {
    return state.getFailedMessage();
  }

  /**
   * Returns the {@link FetchExceptionMode} associated with the last failure.
   *
   * <p>This classification is recorded when a failure is handled and remains available for status
   * reporting until the request is restarted. It can be {@code null} if the request has not failed
   * or if no failure has been recorded yet. Callers should treat the value as a snapshot rather
   * than a live view of the underlying fetcher.
   *
   * <p>The returned value is useful for UI classification or retry policy decisions.
   *
   * @return failure classification mode, or {@code null} when no failure exists.
   */
  public FetchExceptionMode getFailureReasonCode() {
    return statusReporter().getFailureReasonCode();
  }

  /**
   * Indicates whether the splitter has reported a finalized total block count.
   *
   * <p>This is primarily a progress-reporting flag. A value of {@code true} means the total block
   * count is stable and suitable for percent-based UI calculations. Completed successful requests
   * are treated as finalized even if no explicit progress snapshot is present. The value may be
   * {@code false} early in a fetch when metadata is incomplete.
   *
   * <p>This method does not force any progress updates; it reports only cached values.
   *
   * @return {@code true} once progress reporting marked the total as finalized or upon success.
   */
  @Override
  public boolean isTotalFinalized() {
    return statusReporter().isTotalFinalized();
  }

  /**
   * Returns a {@link Bucket} representing the downloaded payload according to the return type.
   *
   * <p>Direct requests hand back the in-memory bucket, disk requests wrap the destination file, and
   * other return types yield {@code null}. Callers should treat the returned bucket as read-only
   * and should not assume it is non-null unless the return type requires it. The returned instance
   * reflects the most recent stored payload and does not trigger additional disk or network work.
   *
   * <p>For disk-based downloads, the returned bucket is a lightweight wrapper over the file path.
   *
   * @return bucket containing the payload, or {@code null} when no bucket form exists.
   */
  public Bucket getBucket() {
    return makeBucket(true);
  }

  Bucket makeBucket(boolean readOnly) {
    return switch (returnType) {
      case DIRECT -> {
        synchronized (persistenceLock) {
          yield state.getReturnBucketDirect();
        }
      }
      case DISK -> ClientGetGetterFactory.diskBucket(targetFile, readOnly);
      default -> null;
    };
  }

  /**
   * Indicates whether the request can be restarted after a failure.
   *
   * <p>The getter must support restart semantics, the request must have finished, and it must not
   * have succeeded yet. Success cases require manual deletion or explicit reset before another
   * attempt. This method performs the minimal checks needed to decide if {@link
   * #restart(ClientContext, boolean)} is likely to proceed without immediate failure.
   *
   * <p>This method does not modify the state; it is intended for UI or scheduler decisions before
   * initiating a restart.
   *
   * @return {@code true} when the request is finished, failed, and restartable.
   */
  @Override
  public boolean canRestart() {
    return restartCoordinator().canRestart();
  }

  /**
   * Attempts to restart the request after a failure or redirect.
   *
   * <p>The method clears cached errors, resets compatibility tracking, optionally disables
   * filtering, and hands the restart request to the underlying {@link ClientGetter}. Cache
   * observers are updated so that frontends show the new redirect or restarted state immediately.
   * If the underlying getter fails to restart, the failure is routed through {@link
   * #onFailure(FetchException)} and the method returns {@code false}.
   *
   * <p>Restarting does not guarantee success; it merely schedules a new attempt with the updated
   * parameters. The method returns quickly once the getter acknowledges the restart request.
   *
   * @param context client context providing schedulers and bucket factories for restart logic.
   * @param disableFilterData {@code true} to disable filtering for the next attempt.
   * @return {@code true} when the restart is accepted and scheduled by the getter.
   */
  @Override
  public boolean restart(ClientContext context, final boolean disableFilterData) {
    return restartCoordinator().restart(context, disableFilterData);
  }

  /**
   * Indicates whether the last failure provided a permanent redirect URI.
   *
   * <p>This flag is derived from the most recent {@link GetFailedMessage} and is used by restart
   * logic to decide whether a redirect should be applied automatically. The value is only
   * meaningful after a failure has been recorded; otherwise it will return {@code false}. A {@code
   * false} result means no redirect hint was captured for the last failure and no further redirect
   * inference is attempted here. The method is synchronized to read the cached failure state
   * consistently.
   *
   * <p>Callers should treat the result as a hint rather than a definitive redirect requirement.
   *
   * @return {@code true} when a permanent redirect URI is stored in failure state.
   */
  public synchronized boolean hasPermRedirect() {
    return restartCoordinator().hasPermRedirect();
  }

  /**
   * Returns whether filterData is currently enabled on the {@link FetchContext}.
   *
   * <p>The flag controls whether content filtering is applied before delivery. It can be toggled
   * during restart flows to temporarily disable filtering for a retry. This method simply reads the
   * current {@link FetchContext} setting and does not alter any state. Because restarts can change
   * the flag between attempts, callers should treat the value as a point-in-time snapshot rather
   * than a promise about future retries.
   *
   * <p>Use this to reflect the current filtering state in status reporting.
   *
   * @return {@code true} when payloads should be filtered before delivery.
   */
  public boolean filterData() {
    return fctx.getFilterData();
  }

  @Override
  RequestStatus getStatus() {
    synchronized (persistenceLock()) {
      return statusReporter().getStatus();
    }
  }

  /**
   * Serializes the request state for persistence so that it can be resumed later.
   *
   * <p>Only {@link Persistence#FOREVER} requests write detail entries. The method records URIs,
   * return types, binary-blob preferences, fetch contexts, metadata buckets, and—when finished—
   * either the success bucket or the failure descriptor. It also streams recent progress snapshots
   * so restarts can resume without re-downloading already verified blocks. Callers should provide a
   * stream already framed by the persistence layer.
   *
   * <p>The serialization format is versioned; if it changes, the version constants in {@link
   * ClientGetPersistenceCodec} must be updated in lockstep with the restore logic.
   *
   * @param dos destination stream receiving the serialized form with checksums embedded.
   * @param checker checksum helper that wraps streams to guard against corruption.
   * @throws IOException when serialization fails or a bucket cannot be stored.
   */
  @Override
  public void getClientDetail(DataOutputStream dos, ChecksumChecker checker) throws IOException {
    if (persistence != Persistence.FOREVER) return;
    super.getClientDetail(dos, checker);
    ClientGetPersistenceCodec.writeClientDetail(this, dos, checker);
  }

  ClientGet(
      DataInputStream dis, RequestIdentifier reqID, ClientContext context, ChecksumChecker checker)
      throws IOException, StorageFormatException, ResumeFailedException {
    super(dis, reqID, context);
    state = new ClientGetState(this);
    ClientGetPersistenceCodec.BasicRestoreData restoreData =
        ClientGetPersistenceCodec.readBasicRestoreData(this, dis, context, checker);
    uri = restoreData.uri();
    returnType = restoreData.returnType();
    targetFile = restoreData.targetFile();
    binaryBlob = restoreData.binaryBlob();
    fctx = restoreData.fetchContext();
    extensionCheck = restoreData.extensionCheck();
    initialMetadata = restoreData.initialMetadata();
    ClientGetter restoredGetter =
        ClientGetPersistenceCodec.restoreState(this, dis, reqID, context, checker);
    state.ensureCompatibilityMode();
    if (restoredGetter == null) {
      restoredGetter = makeGetterForPersistence(makeBucket(false));
    }
    getter = restoredGetter;
    initHelpers();
  }

  /**
   * Rehydrates transient state after a persistent resuming has restored core fields.
   *
   * <p>This hook is invoked by the base resume flow once serialization has recreated the request
   * and the {@link ClientGetter}. It forwards the resume signal to any retained buckets and then
   * repopulates size and MIME hints from the getter if they were not stored explicitly. The method
   * does not trigger network activity; it only rebinds state so later status queries are
   * consistent.
   *
   * <p>Callers should invoke this only during resume flows and not during normal execution.
   *
   * @param context client context used for bucket resume callbacks and defaults.
   * @throws ResumeFailedException if bucket resume logic reports unrecoverable failure.
   */
  @Override
  protected void innerResume(ClientContext context) throws ResumeFailedException {
    if (state.getReturnBucketDirect() != null) state.getReturnBucketDirect().onResume(context);
    if (initialMetadata != null) initialMetadata.onResume(context);
    // We might already have these if we've just restored.
    if (state.getFoundDataLength() <= 0) state.setFoundDataLength(getter.expectedSize());
    if (state.getFoundDataMimeType() == null) state.setFoundDataMimeType(getter.expectedMIME());
  }

  @Override
  RequestType getType() {
    return RequestType.GET;
  }

  /**
   * Indicates whether every component of the request has been restored successfully after resume.
   *
   * <p>This is a lightweight health check used by persistence logic to decide whether the request
   * can continue without restarting. It delegates to {@link ClientGetter#resumedFetcher()} and also
   * ensures the getter itself is present. A {@code false} return indicates that the request should
   * be restarted or rebuilt.
   *
   * <p>The method has no side effects and should be safe to call repeatedly.
   *
   * @return {@code true} when the getter reports a valid, fully resumed fetcher.
   */
  @Override
  public boolean fullyResumed() {
    return getter != null && getter.resumedFetcher();
  }

  /**
   * Compares this request to another object for equality using the base implementation.
   *
   * <p>Equality is defined by {@link ClientRequest} and typically reflects request identity rather
   * than mutable progress state. This override exists to preserve the base semantics while keeping
   * the contract explicit in this subtype. The comparison is side-effect-free.
   *
   * <p>Because the result is identity-based, two requests with identical progress snapshots may
   * still compare as unequal. This method does not synchronize; callers that need a stable view of
   * the mutable state should take a snapshot under the request lock separately.
   *
   * @param obj object to compare against, possibly {@code null}.
   * @return {@code true} when the base implementation considers the objects equal.
   */
  @Override
  public boolean equals(Object obj) {
    return super.equals(obj);
  }

  /**
   * Computes the hash code for this request using the base implementation.
   *
   * <p>The hash code is stable for the identity fields used by {@link ClientRequest} and does not
   * incorporate mutable progress state. This makes the value suitable for hash-based collections
   * that store requests by identity. The computation has no side effects.
   *
   * <p>Callers should not cache the value across serialization boundaries unless the identifier is
   * known to remain constant. The method avoids synchronization because identity fields are
   * immutable after construction.
   *
   * @return hash code derived from {@link ClientRequest} identity fields and stability rules.
   */
  @Override
  public int hashCode() {
    return super.hashCode();
  }
}
