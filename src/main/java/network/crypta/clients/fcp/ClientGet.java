package network.crypta.clients.fcp;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.Serial;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchResult;
import network.crypta.client.InsertContext;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientGetter;
import network.crypta.client.async.ClientRequester;
import network.crypta.client.async.CompatibilityAnalyser;
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
 * <p>The request owns its {@link FetchContext}, {@link ClientGetter}, progress caches, and
 * persistence metadata so it can migrate cleanly between the connection queue, the global queue,
 * and durable storage across node restarts. It translates raw client events into the higher-level
 * FCP messages required by remote clients, tracks retry policy, and resolves whatever output
 * strategy the caller selected (direct bucket, disk file, chunked stream, or acknowledgement only).
 * The class is therefore the boundary between long-lived persistent jobs and transient FCP
 * sessions.
 *
 * <p>The implementation is largely thread-safe through fine-grained {@code synchronized} sections.
 * State transitions such as success, failure, or cancellation update cached progress snapshots and
 * immediately propagate notifications to any registered event listeners. During restarts, it
 * rehydrates buckets, metadata, and compatibility hints from the serialized form before delegating
 * back to {@link ClientGetter}.
 *
 * <ul>
 *   <li>Queueing and persistence: registers against either the connection-scoped or global queue.
 *   <li>Progress and metadata: consumes splitter events to project hashes, sizes, and MIME types.
 *   <li>Delivery: enforces {@link ReturnType} semantics when writing buckets or emitting AllData.
 * </ul>
 *
 * @see ClientRequest
 * @see ClientGetter
 * @see network.crypta.client.async.ClientGetCallback
 */
public class ClientGet extends ClientRequest {
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

  /** Bucket returned when the request was completed, if returnType == RETURN_TYPE_DIRECT. */
  @SuppressWarnings("java:S1948")
  private Bucket returnBucketDirect;

  /** Indicates that the caller expects the result as a BinaryBlob stream rather than a bucket. */
  private final boolean binaryBlob;

  /** Optional client-provided filename extension used to validate post-filtering output. */
  private final String extensionCheck;

  /** Metadata bucket supplied at creation time, relayed untouched to the {@link ClientGetter}. */
  @SuppressWarnings("java:S1948")
  private final Bucket initialMetadata;

  // Verbosity bitmasks
  static final int VERBOSITY_SPLITFILE_PROGRESS = 1;
  static final int VERBOSITY_SENT_TO_NETWORK = 2;
  static final int VERBOSITY_COMPATIBILITY_MODE = 4;
  static final int VERBOSITY_EXPECTED_HASHES = 8;
  static final int VERBOSITY_EXPECTED_TYPE = 32;
  static final int VERBOSITY_EXPECTED_SIZE = 64;
  static final int VERBOSITY_ENTER_FINITE_COOLDOWN = 128;

  // Stuff waiting for reconnection
  /** Did the request succeed? Valid if finished. */
  private boolean succeeded;

  /**
   * Length of the found data. Will be updated from ClientGetter in onResume(), but we persist it
   * anyway.
   */
  private long foundDataLength = -1;

  /**
   * MIME type of the found data. Will be updated from ClientGetter in onResume(), but we persist it
   * anyway.
   */
  private String foundDataMimeType;

  /** Details of the request failure. */
  private GetFailedMessage getFailedMessage;

  /** Last progress message. Not persistently, ClientGetter will update on onResume(). */
  private transient SimpleProgressMessage progressPending;

  /** Have we received a SendingToNetworkEvent? */
  private boolean sentToNetwork;

  /**
   * Current compatibility mode. This is updated over time as the request progresses and can be used
   * e.g., to reinsert the file. This is NOT transient, as the ClientGetter does not retain this
   * information.
   */
  private CompatibilityAnalyser compatMode;

  /**
   * Expected hashes of the final data. Will be updated from ClientGetter in onResume(), but we
   * persist it anyway.
   */
  private ExpectedHashes expectedHashes;

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
     * @param x numeric tag emitted by persistent storage or remote clients to decode.
     * @return matching {@link ReturnType} describing the expected delivery semantics.
     * @throws IllegalArgumentException if the provided code does not map to a known constant.
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
   * @param dsOnly true to confine fetching to the local datastore only.
   * @param ignoreDS bypasses the datastore entirely when evaluating availability hints.
   * @param filterData applies MIME filtering before writing or returning data.
   * @param maxSplitfileRetries maximum block retries for splitfile reconstruction attempts.
   * @param maxNonSplitfileRetries retry the ceiling for non-splitfile requests before failing.
   * @param maxOutputLength upper bound in bytes for payload and temporary storage usage.
   * @param returnType delivery strategy describing whether bytes stream, persist, or skip.
   * @param persistRebootOnly true to persist only across reboots instead of forever.
   * @param identifier application-supplied identifier echoed through FCP status events.
   * @param verbosity bitmask controlling which progress events get forwarded back.
   * @param prioClass priority class guiding scheduler fairness and bandwidth allocation.
   * @param returnFilename destination filesystem path used solely when disk output requested.
   * @param charset legacy charset hint ignored but retained for compatibility logging.
   * @param writeToClientCache allows writing the payload into the client HTTP cache.
   * @param realTimeFlag true when the request participates in the realtime scheduler lane.
   * @param binaryBlob enables BinaryBlob writer semantics instead of classic bucket delivery.
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

  /**
   * Builds a persistent GET request for callers that enqueue work outside live FCP sessions.
   *
   * <p>This constructor clones the node's default {@link FetchContext}, wires up event listeners,
   * normalizes retry limits, and resolves the return path before handing everything to a dedicated
   * {@link ClientGetter}. It is typically used by built-in services that want their requests to be
   * restartable across reboots and obey the global queue semantics rather than the per-connection
   * queue. The supplied {@link GlobalRequestConfig} controls datastore reachability, filtering,
   * cache writes, and the maximum size of the temporary buckets allocated for the request. The
   * resulting instance is ready to register and start once constructed.
   *
   * @param globalClient persistent client facade owning the global queue slot.
   * @param uri FreenetURI describing the content key and optional metadata.
   * @param requestConfig configuration bundle describing retry limits and return handling.
   * @param core node client core providing factories, permission checks, and trackers.
   * @throws IdentifierCollisionException identifier already present on the owning persistent
   *     client.
   * @throws NotAllowedException download target rejected by DDA or security policy.
   * @throws IOException filesystem errors while preparing disk buckets or output locations.
   */
  public ClientGet(
      PersistentRequestClient globalClient,
      FreenetURI uri,
      GlobalRequestConfig requestConfig,
      NodeClientCore core)
      throws IdentifierCollisionException, NotAllowedException, IOException {
    super(
        new ClientRequestParams(
            uri,
            requestConfig.identifier(),
            requestConfig.verbosity(),
            requestConfig.prioClass(),
            (requestConfig.persistRebootOnly() ? Persistence.REBOOT : Persistence.FOREVER),
            requestConfig.realTimeFlag(),
            null,
            true),
        null,
        globalClient);

    ensureGlobalIdentifierAvailable(globalClient, requestConfig.identifier());
    fctx = core.getClientContext().getDefaultPersistentFetchContext();
    fctx.getEventProducer().addEventListener(new ClientGetEventHandling(this));
    fctx.setLocalRequestOnly(requestConfig.dsOnly());
    fctx.setIgnoreStore(requestConfig.ignoreDS());
    fctx.setMaxNonSplitfileRetries(requestConfig.maxNonSplitfileRetries());
    fctx.setMaxSplitfileBlockRetries(requestConfig.maxSplitfileRetries());
    fctx.setFilterData(requestConfig.filterData());
    fctx.setMaxOutputLength(requestConfig.maxOutputLength());
    fctx.setMaxTempLength(requestConfig.maxOutputLength());
    fctx.setCanWriteClientCache(requestConfig.writeToClientCache());
    compatMode = new CompatibilityAnalyser();
    // USK date hints are configured explicitly for FCP messages.
    this.returnType = requestConfig.returnType();
    this.binaryBlob = requestConfig.binaryBlob();
    if (requestConfig.charset() != null && LOG.isDebugEnabled()) {
      LOG.debug(
          "Charset parameter is ignored for ClientGet global queue requests: {}",
          requestConfig.charset());
    }
    ClientGetReturnPlanner.ReturnSetup setup =
        ClientGetGetterFactory.planReturnForGlobal(
            identifier,
            global,
            fctx,
            returnType,
            requestConfig.returnFilename(),
            requestConfig.filterData(),
            core);
    Bucket returnBucket = setup.bucket();
    this.targetFile = setup.targetFile();
    this.extensionCheck = setup.extension();
    this.initialMetadata = null;
    getter = makeGetter(core, returnBucket);
  }

  /**
   * Creates a {@code ClientGet} sourced from an incoming {@link ClientGetMessage} on an FCP link.
   *
   * <p>This path mirrors the caller's parameters as closely as possible: it validates DDA
   * permissions, copies {@link FetchContext} overrides, seeds allowed MIME lists, and prepares any
   * disk buckets before instantiating the {@link ClientGetter}. Identifiers can be scoped either to
   * the connection or to the global queue, so both handler-level and persistent collision checks
   * are performed before the request becomes visible to other components. The resulting request is
   * ready to register and start immediately.
   *
   * @param handler connection handler responsible for per-client identifiers and DDA checks.
   * @param message parsed message containing caller preferences, flags, and return settings.
   * @param core node client core granting fetch contexts, caches, and permission evaluators.
   * @throws IdentifierCollisionException identifier already active on this handler or its client.
   * @throws MessageInvalidException message failed validation or violated configured DDA policies.
   */
  public ClientGet(FCPConnectionHandler handler, ClientGetMessage message, NodeClientCore core)
      throws IdentifierCollisionException, MessageInvalidException {
    super(
        new ClientRequestParams(
            message.uri,
            message.identifier,
            message.verbosity,
            message.priorityClass,
            message.persistence,
            message.realTimeFlag,
            message.clientToken,
            message.global),
        handler);
    if (message.persistence == Persistence.CONNECTION) {
      ensureConnectionIdentifierAvailable(handler, message.identifier);
    }
    // Create a Fetcher directly to get more fine-grained control,
    // since the client may override a few context elements.
    fctx = core.getClientContext().getDefaultPersistentFetchContext();
    fctx.getEventProducer().addEventListener(new ClientGetEventHandling(this));
    // ignoreDS
    fctx.setLocalRequestOnly(message.dsOnly);
    fctx.setIgnoreStore(message.ignoreDS);
    fctx.setMaxNonSplitfileRetries(message.maxRetries);
    fctx.setMaxSplitfileBlockRetries(message.maxRetries);
    // Verbosity has already been validated upstream.
    fctx.setMaxOutputLength(message.maxSize);
    fctx.setMaxTempLength(message.maxTempSize);
    fctx.setCanWriteClientCache(message.shouldWriteToClientCache());
    fctx.setFilterData(message.filterData);
    fctx.setIgnoreUSKDatehints(message.ignoreUSKDatehints);
    compatMode = new CompatibilityAnalyser();

    ClientGetGetterFactory.applyAllowedMimeTypes(fctx, message.allowedMIMETypes);

    this.returnType = message.returnType;
    this.binaryBlob = message.binaryBlob;
    ClientGetReturnPlanner.ReturnSetup setup =
        ClientGetGetterFactory.planReturnForMessage(
            identifier, global, fctx, message, core, handler);
    Bucket returnBucket = setup.bucket();
    this.targetFile = setup.targetFile();
    this.extensionCheck = setup.extension();
    initialMetadata = message.getInitialMetadata();
    try {
      getter = makeGetter(core, returnBucket);
    } catch (IOException e) {
      throw bucketCreationFailure(e);
    }
  }

  private MessageInvalidException bucketCreationFailure(IOException e) {
    MessageInvalidException mie =
        new MessageInvalidException(
            ProtocolErrorMessage.INTERNAL_ERROR,
            "Cannot create bucket for temporary storage (out of disk space?): " + e,
            identifier,
            global);
    mie.initCause(e);
    return mie;
  }

  private void ensureGlobalIdentifierAvailable(PersistentRequestClient client, String identifier)
      throws IdentifierCollisionException {
    if (client != null && client.getRequest(identifier) != null) {
      throw new IdentifierCollisionException();
    }
  }

  private void ensureConnectionIdentifierAvailable(FCPConnectionHandler handler, String identifier)
      throws IdentifierCollisionException {
    if (handler != null && handler.requestsByIdentifier.containsKey(identifier)) {
      throw new IdentifierCollisionException();
    }
  }

  private ClientGetter makeGetter(Bucket ret) throws IOException {
    return makeGetter(null, ret);
  }

  private ClientGetter makeGetter(NodeClientCore core, Bucket ret) throws IOException {
    return ClientGetGetterFactory.createGetterForRequest(this, ret, core);
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
  protected ClientGet() {
    // For serialization.
    fctx = null;
    getter = null;
    returnType = null;
    targetFile = null;
    binaryBlob = false;
    extensionCheck = null;
    initialMetadata = null;
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
   * @param context client context providing schedulers and bucket factories for execution.
   */
  @Override
  public void start(ClientContext context) {
    try {
      synchronized (this) {
        if (finished) return;
      }
      getter.start(context);
      if (shouldSendPersistentTag()) {
        FCPMessage msg = persistentTagMessage();
        client.queueClientRequestMessage(msg, 0);
      }
      synchronized (this) {
        started = true;
      }
      if (client != null) {
        RequestStatusCache cache = client.getRequestStatusCache();
        if (cache != null) {
          cache.updateStarted(identifier, true);
        }
      }
    } catch (FetchException e) {
      synchronized (this) {
        started = true;
      } // before the failure handler
      onFailure(e);
    } catch (Exception t) {
      synchronized (this) {
        started = true;
      }
      onFailure(new FetchException(FetchExceptionMode.INTERNAL_ERROR, t));
    }
  }

  private boolean shouldSendPersistentTag() {
    synchronized (this) {
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
   * @param context client context owning the request; unused but retained for parity.
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
   * @param result result wrapper exposing MIME metadata and bucket accessors.
   * @param state client getter instance used for blob access during BinaryBlob transfers.
   */
  public void onSuccess(FetchResult result, ClientGetter state) {
    LOG.debug("Succeeded: {}", identifier);
    Bucket data = binaryBlob ? state.getBlobBucket() : result.asBucket();
    synchronized (this) {
      if (succeeded) {
        LOG.error("onSuccess called twice for {} ({})", this, identifier);
        return; // We might be called twice; ignore it if so.
      }
      started = true;
      if (!binaryBlob) this.foundDataMimeType = result.getMimeType();
      else this.foundDataMimeType = ClientGetGetterFactory.binaryBlobMimeType();

      // completionTime is set here rather than in finish() for two reasons:
      // 1. It must be set inside the lock.
      // 2. It must be set before AllData is sent so it is consistent.
      completionTime = System.currentTimeMillis();
      progressPending = null;
      this.foundDataLength = data.size();
      this.succeeded = true;
      finished = true;
      if (returnType == ReturnType.DIRECT) returnBucketDirect = data;
    }
    trySendDataFoundOrGetFailed(null, null);
    trySendAllDataMessage(null, null);
    finish();
    if (client != null) client.notifySuccess(this);
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
   * @param context client context performing the migration and validation checks.
   * @param completionTime epoch milliseconds representing the recorded completion instant.
   * @param data bucket already holding the downloaded payload for direct returns.
   * @throws ResumeFailedException validation failed because existing output looked inconsistent.
   */
  @SuppressWarnings("unused")
  public void setSuccessForMigration(ClientContext context, long completionTime, Bucket data)
      throws ResumeFailedException {
    if (context == null) {
      throw new NullPointerException("context");
    }
    synchronized (this) {
      succeeded = true;
      started = true;
      finished = true;
      this.completionTime = completionTime;
      switch (returnType) {
        case ReturnType type when type == ReturnType.NONE -> {
          // Nothing to validate.
        }
        case ReturnType type
            when type == ReturnType.DISK
                && (!targetFile.exists() || targetFile.length() != foundDataLength) ->
            throw new ResumeFailedException("Success but target file doesn't exist or isn't valid");
        case ReturnType type when type == ReturnType.DISK -> {
          // Validation already passed.
        }
        case ReturnType type when type == ReturnType.DIRECT && data.size() != foundDataLength -> {
          returnBucketDirect = data;
          throw new ResumeFailedException(
              "Success but temporary data bucket doesn't exist or isn't valid");
        }
        case ReturnType type when type == ReturnType.DIRECT -> returnBucketDirect = data;
        case ReturnType type when type == ReturnType.CHUNKED ->
            throw new ResumeFailedException("Chunked return type not supported for migration");
        default -> throw new IllegalStateException("Unexpected return type: " + returnType);
      }
    }
  }

  private void trySendDataFoundOrGetFailed(
      FCPConnectionOutputHandler handler, String listRequestIdentifier) {
    FCPMessage msg;

    // Don't need to lock. succeeded is only ever set, never unset.
    // and succeeded and getFailedMessage are both atomic.
    if (succeeded) {
      // Mirrors AllDataMessage so connection-scoped clients receive DataFound with consistent
      // timestamps even if completionTime was not set by finish().
      msg =
          new DataFoundMessage(
              foundDataLength,
              foundDataMimeType,
              identifier,
              global,
              startupTime,
              completionTime != 0 ? completionTime : System.currentTimeMillis());
    } else {
      msg = getFailedMessage;
    }

    if (handler == null && persistence == Persistence.CONNECTION) {
      if (origHandler != null)
        origHandler.send(FCPMessage.withListRequestIdentifier(msg, listRequestIdentifier));
    } else if (handler != null) {
      handler.handler.send(FCPMessage.withListRequestIdentifier(msg, listRequestIdentifier));
    } else
      client.queueClientRequestMessage(
          FCPMessage.withListRequestIdentifier(msg, listRequestIdentifier), 0);
  }

  private synchronized AllDataMessage getAllDataMessage() {
    if (returnType != ReturnType.DIRECT) return null;
    AllDataMessage msg =
        new AllDataMessage(
            returnBucketDirect, identifier, global, startupTime, completionTime, foundDataMimeType);
    if (persistence == Persistence.CONNECTION) msg.setFreeOnSent();
    return msg;
  }

  private void trySendAllDataMessage(
      FCPConnectionOutputHandler handler, String listRequestIdentifier) {
    if (persistence == Persistence.CONNECTION && handler == null) {
      if (origHandler != null) {
        FCPMessage allData =
            FCPMessage.withListRequestIdentifier(getAllDataMessage(), listRequestIdentifier);
        if (allData != null) origHandler.send(allData);
      }
      return;
    }
    if (handler != null) {
      FCPMessage allData =
          FCPMessage.withListRequestIdentifier(getAllDataMessage(), listRequestIdentifier);
      if (allData != null) handler.handler.send(allData);
    }
  }

  void queueProgressMessageInner(FCPMessage msg, int verbosityMask) {
    if (persistence == Persistence.CONNECTION) {
      if (origHandler != null) {
        origHandler.send(msg);
      }
      return;
    }
    client.queueClientRequestMessage(msg, verbosityMask);
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
   * @param handler output handler representing the destination connection to replay into.
   * @param listRequestIdentifier optional secondary identifier for multi-request list operations.
   * @param includeData true to include {@link AllDataMessage} bodies when available.
   * @param onlyData true to request data frames exclusively, skipping metadata messages.
   */
  @Override
  public void sendPendingMessages(
      FCPConnectionOutputHandler handler,
      String listRequestIdentifier,
      boolean includeData,
      boolean onlyData) {
    if (!onlyData) {
      FCPMessage msg = persistentTagMessage();
      handler.handler.send(FCPMessage.withListRequestIdentifier(msg, listRequestIdentifier));
      if (progressPending != null) {
        handler.handler.send(
            FCPMessage.withListRequestIdentifier(progressPending, listRequestIdentifier));
      }
      if (sentToNetwork)
        handler.handler.send(
            FCPMessage.withListRequestIdentifier(
                new SendingToNetworkMessage(identifier, global), listRequestIdentifier));
      if (finished) trySendDataFoundOrGetFailed(handler, listRequestIdentifier);
    } else if (returnType != ReturnType.DIRECT) {
      FCPMessage msg =
          new ProtocolErrorMessage(
              ProtocolErrorMessage.WRONG_RETURN_TYPE, false, "No AllData", identifier, global);
      handler.handler.send(msg);
      return;
    }

    if (includeData) {
      trySendAllDataMessage(handler, listRequestIdentifier);
    }

    CompatibilityMode cmsg;
    ExpectedHashes hashesMessage;
    ExpectedMIME mimeMsg = null;
    ExpectedDataLength lengthMsg = null;
    synchronized (this) {
      cmsg = new CompatibilityMode(identifier, global, compatMode);
      hashesMessage = this.expectedHashes;
      if (foundDataMimeType != null)
        mimeMsg = new ExpectedMIME(identifier, global, foundDataMimeType);
      if (foundDataLength > 0)
        lengthMsg = new ExpectedDataLength(identifier, global, foundDataLength);
    }
    handler.handler.send(FCPMessage.withListRequestIdentifier(cmsg, listRequestIdentifier));

    if (hashesMessage != null) {
      handler.handler.send(
          FCPMessage.withListRequestIdentifier(hashesMessage, listRequestIdentifier));
    }

    if (mimeMsg != null) {
      handler.handler.send(FCPMessage.withListRequestIdentifier(mimeMsg, listRequestIdentifier));
    }
    if (lengthMsg != null) {
      handler.handler.send(FCPMessage.withListRequestIdentifier(lengthMsg, listRequestIdentifier));
    }
  }

  private FCPMessage persistentTagMessage() {
    return new PersistentGet(
        identifier,
        uri,
        verbosity,
        priorityClass,
        returnType,
        persistence,
        targetFile,
        clientToken,
        client.isGlobalQueue,
        started,
        fctx.getMaxNonSplitfileRetries(),
        binaryBlob,
        fctx.getMaxOutputLength(),
        isRealTime());
  }

  // Mirrors ClientPut/ClientPutDir to keep low-level scheduling flags accessible to subclasses.
  private boolean isRealTime() {
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
   * @param e detailed {@link FetchException} describing the failure classification.
   */
  public void onFailure(FetchException e) {
    if (finished) return;
    synchronized (this) {
      if (e.getExpectedSize() != 0) this.foundDataLength = e.getExpectedSize();
      if (e.getExpectedMimeType() != null) this.foundDataMimeType = e.getExpectedMimeType();
      succeeded = false;
      getFailedMessage = new GetFailedMessage(e, identifier, global);
      finished = true;
      started = true;
      completionTime = System.currentTimeMillis();
    }
    if (LOG.isDebugEnabled()) LOG.debug("Caught {}", e, e);
    trySendDataFoundOrGetFailed(null, null);
    // We do not want the data to be removed on failure, because the request
    // may be restarted, and the bucket persists on the getter, even if we get rid of it here.
    finish();
    if (client != null) client.notifyFailure(this);
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
   * @param context client context invoking the removal for lifecycle bookkeeping.
   */
  @Override
  public void requestWasRemoved(ClientContext context) {
    // if the request is still running, send a GetFailed with code=canceled
    if (!finished) {
      synchronized (this) {
        succeeded = false;
        finished = true;
        FetchException cancelled = new FetchException(FetchExceptionMode.CANCELLED);
        getFailedMessage = new GetFailedMessage(cancelled, identifier, global);
      }
      trySendDataFoundOrGetFailed(null, null);
    }
    // notify client that the request was removed
    FCPMessage msg = new PersistentRequestRemovedMessage(getIdentifier(), global);
    if (persistence != Persistence.CONNECTION) {
      client.queueClientRequestMessage(msg, 0);
    }

    freeData();

    super.requestWasRemoved(context);
  }

  synchronized void markSentToNetwork() {
    sentToNetwork = true;
  }

  synchronized void recordSplitfileProgress(SimpleProgressMessage message) {
    progressPending = message;
  }

  synchronized boolean trySetExpectedHashes(ExpectedHashes message) {
    if (expectedHashes != null) {
      LOG.warn("Got a new ExpectedHashes");
      return false;
    }
    expectedHashes = message;
    return true;
  }

  synchronized void recordExpectedMimeType(String mimeType) {
    foundDataMimeType = mimeType;
  }

  synchronized void recordExpectedDataLength(long length) {
    foundDataLength = length;
  }

  void mergeCompatibilityMode(
      InsertContext.CompatibilityMode minCompatibilityMode,
      InsertContext.CompatibilityMode maxCompatibilityMode,
      byte[] splitfileCryptoKey,
      boolean dontCompress,
      boolean bottomLayer) {
    compatMode.merge(
        minCompatibilityMode, maxCompatibilityMode, splitfileCryptoKey, dontCompress, bottomLayer);
    if (client != null) {
      RequestStatusCache cache = client.getRequestStatusCache();
      if (cache != null) {
        cache.updateDetectedCompatModes(
            identifier,
            compatMode.getModes(),
            compatMode.getCryptoKey(),
            compatMode.dontCompress());
      }
    }
    if ((verbosity & VERBOSITY_COMPATIBILITY_MODE) != 0) {
      queueProgressMessageInner(
          new CompatibilityMode(identifier, global, compatMode), VERBOSITY_COMPATIBILITY_MODE);
    }
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
    synchronized (this) {
      data = returnBucketDirect;
      returnBucketDirect = null;
    }
    if (data != null) {
      data.free();
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
   * @return {@code true} once final success has been recorded for this request.
   */
  @Override
  public boolean hasSucceeded() {
    return succeeded;
  }

  /**
   * Indicates whether the request expects {@link ReturnType#DIRECT} delivery semantics.
   *
   * <p>Direct mode keeps the downloaded bucket resident so reconnecting clients can still replay an
   * {@link AllDataMessage}. Disk-bound and chunked requests, by contrast, cannot ship the payload
   * back through the queue once the transfer has completed. This flag is informational and does not
   * initiate any I/O.
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
   * @return current {@link FreenetURI} reference describing the active fetch target.
   */
  public FreenetURI getURI() {
    return uri;
  }

  /**
   * Exposes the fetch context for package-local helpers.
   *
   * @return live {@link FetchContext} backing this request.
   */
  FetchContext fetchContextForGetter() {
    return fctx;
  }

  /**
   * Exposes the metadata bucket associated with this request.
   *
   * @return initial metadata bucket, or {@code null} when unset.
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
   * @return configured {@link ReturnType} for result delivery.
   */
  ReturnType returnTypeForGetter() {
    return returnType;
  }

  /**
   * Indicates whether Binary Blob recording is enabled for this request.
   *
   * @return {@code true} when Binary Blob output is expected.
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
   * @return recorded payload length in bytes, or {@code -1} when unknown.
   */
  public long getDataSize() {
    if (foundDataLength > 0) return foundDataLength;
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
   * @return MIME type reported for the payload, or {@code null} if undetermined.
   */
  public String getMIMEType() {
    if (foundDataMimeType != null) return foundDataMimeType;
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
   * @return destination file for disk downloads, or {@code null} otherwise.
   */
  public File getDestFilename() {
    return targetFile;
  }

  /**
   * Returns the fraction of splitfile blocks downloaded successfully.
   *
   * <p>The metric reflects the most recent {@code SplitfileProgressEvent} cached via {@link
   * #progressPending}, making it useful for dashboards that prefer percentages to raw block counts.
   * When no progress has been recorded it returns {@code -1} to signal an unknown fraction. The
   * value is a snapshot and may lag behind the underlying fetcher in highly concurrent flows.
   *
   * @return value between {@code 0.0} and {@code 1.0}, or {@code -1} when unavailable.
   */
  @Override
  public double getSuccessFraction() {
    if (progressPending != null) {
      return progressPending.getFraction();
    } else return -1;
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
    if (progressPending != null) {
      return progressPending.getTotalBlocks();
    } else return 1;
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
    if (progressPending != null) {
      return progressPending.getMinBlocks();
    } else return 1;
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
    if (progressPending != null) {
      return progressPending.getFailedBlocks();
    } else return 0;
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
    if (progressPending != null) {
      return progressPending.getFatalyFailedBlocks();
    } else return 0;
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
    if (progressPending != null) {
      return progressPending.getFetchedBlocks();
    } else return 0;
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
    return compatMode.getModes();
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
    return compatMode.dontCompress();
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
    return compatMode.getCryptoKey();
  }

  /**
   * Returns a textual explanation for the most recent failure, if any.
   *
   * <p>The summary is derived from the cached {@link GetFailedMessage} and may include additional
   * diagnostic text when requested. It returns {@code null} when no failure has been recorded,
   * which typically means the request is still running or has completed successfully. The returned
   * text is suitable for UI display and is not guaranteed to be stable across versions.
   *
   * @param longDescription {@code true} to include any extended diagnostic text when available.
   * @return human-readable failure summary, or {@code null} when no failure exists.
   */
  @Override
  public String getFailureReason(boolean longDescription) {
    if (getFailedMessage == null) return null;
    String s = getFailedMessage.getShortFailedMessage();
    if (longDescription && getFailedMessage.extraDescription != null)
      s += ": " + getFailedMessage.extraDescription;
    return s;
  }

  GetFailedMessage getFailureMessage() {
    if (getFailedMessage == null) return null;
    return getFailedMessage;
  }

  /**
   * Returns the {@link FetchExceptionMode} associated with the last failure.
   *
   * <p>This classification is recorded when a failure is handled and remains available for status
   * reporting until the request is restarted. It can be {@code null} if the request has not failed
   * or if no failure has been recorded yet. Callers should treat the value as a snapshot rather
   * than a live view of the underlying fetcher.
   *
   * @return failure classification mode, or {@code null} when no failure exists.
   */
  public FetchExceptionMode getFailureReasonCode() {
    if (getFailedMessage == null) return null;
    return getFailedMessage.failureMode;
  }

  /**
   * Indicates whether the splitter has reported a finalized total block count.
   *
   * <p>This is primarily a progress-reporting flag. A value of {@code true} means the total block
   * count is stable and suitable for percent-based UI calculations. Completed successful requests
   * are treated as finalized even if no explicit progress snapshot is present. The value may be
   * {@code false} early in a fetch when metadata is incomplete.
   *
   * @return {@code true} once progress reporting marked the total as finalized or upon success.
   */
  @Override
  public boolean isTotalFinalized() {
    if (finished && succeeded) return true;
    if (progressPending == null) return false;
    else {
      return progressPending.isTotalFinalized();
    }
  }

  /**
   * Returns a {@link Bucket} representing the downloaded payload according to the return type.
   *
   * <p>Direct requests hand back the in-memory bucket, disk requests wrap the destination file, and
   * other return types yield {@code null}. Callers should treat the returned bucket as read-only
   * and should not assume it is non-null unless the return type requires it. The returned instance
   * reflects the most recent stored payload and does not trigger additional disk or network work.
   *
   * @return bucket containing the payload, or {@code null} when no bucket form exists.
   */
  public Bucket getBucket() {
    return makeBucket(true);
  }

  private Bucket makeBucket(boolean readOnly) {
    return switch (returnType) {
      case DIRECT -> {
        synchronized (this) {
          yield returnBucketDirect;
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
   * @return {@code true} when {@link #restart(ClientContext, boolean)} may be invoked.
   */
  @Override
  public boolean canRestart() {
    if (!finished) {
      LOG.debug("Cannot restart because not finished for {}", identifier);
      return false;
    }
    if (succeeded) {
      LOG.debug("Cannot restart because succeeded for {}", identifier);
      return false;
    }
    return getter.canRestart();
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
   * @param context client context providing schedulers and persistent storage for restart logic.
   * @param disableFilterData {@code true} to temporarily disable filtering for the next attempt.
   * @return {@code true} when the restart was initiated successfully.
   */
  @Override
  public boolean restart(ClientContext context, final boolean disableFilterData) {
    if (!canRestart()) return false;
    FreenetURI redirect = resetStateForRestart(disableFilterData);
    notifyCacheAboutRedirect(redirect);
    try {
      if (getter.restart(redirect, fctx.getFilterData(), context)) {
        markRestarted(redirect);
      }
      notifyCacheStartedFlag();
      return true;
    } catch (FetchException e) {
      onFailure(e);
      return false;
    }
  }

  private FreenetURI resetStateForRestart(boolean disableFilterData) {
    synchronized (this) {
      finished = false;
      FreenetURI redirect = getFailedMessage == null ? null : getFailedMessage.redirectURI;
      getFailedMessage = null;
      progressPending = null;
      compatMode = new CompatibilityAnalyser();
      expectedHashes = null;
      started = false;
      if (disableFilterData) {
        fctx.setFilterData(false);
      }
      return redirect;
    }
  }

  private void markRestarted(FreenetURI redirect) {
    synchronized (this) {
      if (redirect != null) {
        this.uri = redirect;
      }
      started = true;
    }
  }

  private void notifyCacheAboutRedirect(FreenetURI redirect) {
    if (client == null) {
      return;
    }
    RequestStatusCache cache = client.getRequestStatusCache();
    if (cache != null) {
      cache.updateStarted(identifier, redirect);
    }
  }

  private void notifyCacheStartedFlag() {
    if (client == null) {
      return;
    }
    RequestStatusCache cache = client.getRequestStatusCache();
    if (cache != null) {
      cache.updateStarted(identifier, true);
    }
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
   * @return {@code true} when {@link GetFailedMessage#redirectURI} is non-null.
   */
  public synchronized boolean hasPermRedirect() {
    return getFailedMessage != null && getFailedMessage.redirectURI != null;
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
   * @return {@code true} when payloads should be filtered before delivery.
   */
  public boolean filterData() {
    return fctx.getFilterData();
  }

  @Override
  synchronized RequestStatus getStatus() {
    return ClientGetGetterFactory.buildStatus(
        new ClientGetStatusSnapshot(
            identifier,
            persistence,
            started,
            finished,
            succeeded,
            progressPending,
            getFailedMessage,
            foundDataMimeType,
            foundDataLength,
            getDestFilename(),
            getBucket(),
            fctx,
            priorityClass,
            getCompatibilityMode(),
            getOverriddenSplitfileCryptoKey(),
            getURI(),
            getDontCompress()));
  }

  private static final long CLIENT_DETAIL_MAGIC = 0x67145b675d2e22f4L;
  private static final int CLIENT_DETAIL_VERSION = 1;

  /**
   * Serializes the request state for persistence so that it can be resumed later.
   *
   * <p>Only {@link Persistence#FOREVER} requests write detail entries. The method records URIs,
   * return types, binary-blob preferences, fetch contexts, metadata buckets, and—when finished—
   * either the success bucket or the failure descriptor. It also streams recent progress snapshots
   * so restarts can resume without re-downloading already verified blocks. Callers should provide a
   * stream already framed by the persistence layer.
   *
   * @param dos destination stream receiving the serialized form with embedded checksums.
   * @param checker checksum helper that wraps streams to guard against corruption.
   * @throws IOException if serialization fails or a bucket cannot be stored.
   */
  @Override
  public void getClientDetail(DataOutputStream dos, ChecksumChecker checker) throws IOException {
    if (persistence != Persistence.FOREVER) return;
    super.getClientDetail(dos, checker);
    dos.writeLong(CLIENT_DETAIL_MAGIC);
    dos.writeInt(CLIENT_DETAIL_VERSION);
    dos.writeUTF(uri.toString());
    // Basic details needed for restarting the request.
    dos.writeShort(returnType.code);
    if (returnType == ReturnType.DISK) {
      dos.writeUTF(targetFile.toString());
    }
    dos.writeBoolean(binaryBlob);
    try (DataOutputStream ctxStream = ClientGetGetterFactory.checksummedWriter(dos, checker)) {
      fctx.writeTo(ctxStream);
    }
    if (extensionCheck != null) {
      dos.writeBoolean(true);
      dos.writeUTF(extensionCheck);
    } else {
      dos.writeBoolean(false);
    }
    if (initialMetadata != null) {
      dos.writeBoolean(true);
      try (DataOutputStream metadataStream =
          ClientGetGetterFactory.checksummedWriter(dos, checker)) {
        initialMetadata.storeTo(metadataStream);
      }
    } else {
      dos.writeBoolean(false);
    }
    synchronized (this) {
      if (finished) {
        dos.writeBoolean(succeeded);
        writeTransientProgressFields(dos);
        if (succeeded) {
          if (returnType == ReturnType.DIRECT) {
            try (DataOutputStream bucketStream =
                ClientGetGetterFactory.checksummedWriter(dos, checker)) {
              returnBucketDirect.storeTo(bucketStream);
            }
          }
        } else {
          try (DataOutputStream failureStream =
              ClientGetGetterFactory.checksummedWriter(dos, checker)) {
            getFailedMessage.writeTo(failureStream);
          }
        }
        return;
      }
    }
    // Not finished, or was recently not finished.
    // Don't hold the lock while calling getter.
    // If it's just finished, we get a race and restart. That's okay.
    try (DataOutputStream progressStream = ClientGetGetterFactory.checksummedWriter(dos, checker)) {
      if (getter.writeTrivialProgress(progressStream)) {
        writeTransientProgressFields(progressStream);
      }
    }
  }

  /**
   * Recreates a {@link ClientGet} from serialized persistent storage.
   *
   * <p>This factory method is used during startup to restore previously persisted requests. It
   * validates the serialized header, rebuilds the {@link FetchContext}, restores progress state,
   * and reconstructs the underlying {@link ClientGetter} where possible. If the stored data is
   * incomplete or inconsistent, it throws a {@link ResumeFailedException} to signal that the
   * request should restart rather than trust corrupted state.
   *
   * @param dis input stream positioned at the serialized client detail block.
   * @param reqID identifier tuple describing the owner and reference type.
   * @param context client context supplying factories used during restoration.
   * @param checker checksum helper verifying the integrity of embedded buckets.
   * @return fully reconstructed {@link ClientRequest} instance ready for resumption.
   * @throws StorageFormatException serialized data failed validation or used unknown versions.
   * @throws IOException stream IO failed while reading buckets or metadata.
   * @throws ResumeFailedException request could not be reconstructed and must restart.
   */
  public static ClientRequest restartFrom(
      DataInputStream dis, RequestIdentifier reqID, ClientContext context, ChecksumChecker checker)
      throws StorageFormatException, IOException, ResumeFailedException {
    return new ClientGet(dis, reqID, context, checker);
  }

  private ClientGet(
      DataInputStream dis, RequestIdentifier reqID, ClientContext context, ChecksumChecker checker)
      throws IOException, StorageFormatException, ResumeFailedException {
    super(dis, reqID, context);
    validateClientDetailHeader(dis);
    uri = parseUri(dis.readUTF());
    returnType = parseReturnType(dis.readShort());
    targetFile = returnType == ReturnType.DISK ? new File(dis.readUTF()) : null;
    binaryBlob = dis.readBoolean();
    this.fctx = ClientGetGetterFactory.readFetchContextOrDefault(dis, context, checker);
    fctx.getEventProducer().addEventListener(new ClientGetEventHandling(this));
    extensionCheck = dis.readBoolean() ? dis.readUTF() : null;
    initialMetadata = ClientGetGetterFactory.readInitialMetadata(dis, context, checker);
    ClientGetter restoredGetter = restoreState(dis, reqID, context, checker);
    if (compatMode == null) {
      compatMode = new CompatibilityAnalyser();
    }
    if (restoredGetter == null) {
      restoredGetter = makeGetter(makeBucket(false));
    }
    this.getter = restoredGetter;
  }

  private void validateClientDetailHeader(DataInputStream dis)
      throws IOException, StorageFormatException {
    long magic = dis.readLong();
    if (magic != CLIENT_DETAIL_MAGIC) {
      throw new StorageFormatException("Bad magic for request");
    }
    int version = dis.readInt();
    if (version != CLIENT_DETAIL_VERSION) {
      throw new StorageFormatException("Bad version " + version);
    }
  }

  private FreenetURI parseUri(String serializedUri) throws StorageFormatException {
    try {
      return new FreenetURI(serializedUri);
    } catch (Exception _) {
      throw new StorageFormatException("Bad URI");
    }
  }

  private ReturnType parseReturnType(short code) throws StorageFormatException {
    try {
      return ReturnType.getByCode(code);
    } catch (IllegalArgumentException _) {
      throw new StorageFormatException("Bad return type " + code);
    }
  }

  private ClientGetter restoreState(
      DataInputStream dis, RequestIdentifier reqID, ClientContext context, ChecksumChecker checker)
      throws IOException, StorageFormatException, ResumeFailedException {
    if (finished) {
      restoreFinishedState(dis, reqID, context, checker);
      return null;
    }
    ClientGetter inProgressGetter = makeGetter(makeBucket(false));
    ClientGetGetterFactory.restoreInProgressState(dis, context, checker, inProgressGetter, this);
    return inProgressGetter;
  }

  private void restoreFinishedState(
      DataInputStream dis, RequestIdentifier reqID, ClientContext context, ChecksumChecker checker)
      throws IOException, StorageFormatException, ResumeFailedException {
    succeeded = dis.readBoolean();
    readTransientProgressFields(dis);
    if (succeeded) {
      if (returnType == ReturnType.DIRECT) {
        Bucket restoredBucket =
            ClientGetGetterFactory.restoreCompletedDirectBucketOrNull(dis, context, checker);
        if (restoredBucket != null) {
          returnBucketDirect = restoredBucket;
        } else {
          returnBucketDirect = null;
          succeeded = false;
          finished = false;
        }
      }
    } else {
      GetFailedMessage restoredMessage =
          ClientGetGetterFactory.restoreFailureMessageOrNull(
              dis, reqID, foundDataLength, foundDataMimeType, context, checker);
      if (restoredMessage != null) {
        getFailedMessage = restoredMessage;
        started = true;
      } else {
        finished = false;
        getFailedMessage = null;
      }
    }
  }

  void readTransientProgressFields(DataInputStream dis) throws IOException, StorageFormatException {
    foundDataLength = dis.readLong();
    if (dis.readBoolean()) foundDataMimeType = dis.readUTF();
    else foundDataMimeType = null;
    compatMode = new CompatibilityAnalyser(dis);
    expectedHashes = ClientGetGetterFactory.readExpectedHashes(dis, identifier, global);
  }

  private synchronized void writeTransientProgressFields(DataOutputStream dos) throws IOException {
    dos.writeLong(foundDataLength);
    if (foundDataMimeType != null) {
      dos.writeBoolean(true);
      dos.writeUTF(foundDataMimeType);
    } else {
      dos.writeBoolean(false);
    }
    compatMode.writeTo(dos);
    ClientGetGetterFactory.writeExpectedHashes(dos, expectedHashes);
  }

  /**
   * Rehydrates transient state after a persistent resume has restored core fields.
   *
   * <p>This hook is invoked by the base resume flow once serialization has recreated the request
   * and the {@link ClientGetter}. It forwards the resume signal to any retained buckets and then
   * repopulates size and MIME hints from the getter if they were not stored explicitly. The method
   * does not trigger network activity; it only rebinds state so later status queries are
   * consistent.
   *
   * @param context client context used for bucket resume callbacks and defaults.
   * @throws ResumeFailedException if bucket resume logic reports unrecoverable failure.
   */
  @Override
  protected void innerResume(ClientContext context) throws ResumeFailedException {
    if (returnBucketDirect != null) returnBucketDirect.onResume(context);
    if (initialMetadata != null) initialMetadata.onResume(context);
    // We might already have these if we've just restored.
    if (foundDataLength <= 0) this.foundDataLength = getter.expectedSize();
    if (foundDataMimeType == null) this.foundDataMimeType = getter.expectedMIME();
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
   * @return {@code true} when {@link ClientGetter#resumedFetcher()} confirms a valid resume.
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
   * @return hash code derived from {@link ClientRequest} identity fields.
   */
  @Override
  public int hashCode() {
    return super.hashCode();
  }
}
