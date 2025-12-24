package network.crypta.clients.fcp;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.Serial;
import java.net.MalformedURLException;
import java.nio.file.Files;
import java.util.Date;
import java.util.HashSet;
import java.util.Objects;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchResult;
import network.crypta.client.InsertContext;
import network.crypta.client.async.BinaryBlob;
import network.crypta.client.async.BinaryBlobWriter;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientGetCallback;
import network.crypta.client.async.ClientGetter;
import network.crypta.client.async.ClientRequester;
import network.crypta.client.async.CompatibilityAnalyser;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.client.async.PersistentClientCallback;
import network.crypta.client.async.PersistentJob;
import network.crypta.client.events.ClientEvent;
import network.crypta.client.events.ClientEventListener;
import network.crypta.client.events.EnterFiniteCooldownEvent;
import network.crypta.client.events.ExpectedFileSizeEvent;
import network.crypta.client.events.ExpectedHashesEvent;
import network.crypta.client.events.ExpectedMIMEEvent;
import network.crypta.client.events.SendingToNetworkEvent;
import network.crypta.client.events.SplitfileCompatibilityModeEvent;
import network.crypta.client.events.SplitfileProgressEvent;
import network.crypta.clients.fcp.RequestIdentifier.RequestType;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.crypt.ChecksumFailedException;
import network.crypta.crypt.HashResult;
import network.crypta.keys.FreenetURI;
import network.crypta.node.NodeClientCore;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ArrayBucketFactory;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.FileBucket;
import network.crypta.support.io.NativeThread;
import network.crypta.support.io.NullBucket;
import network.crypta.support.io.ResumeFailedException;
import network.crypta.support.io.StorageFormatException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Coordinates a single FCP GET request over the asynchronous client interface.
 *
 * <p>The request owns its {@link FetchContext}, {@link ClientGetter}, progress caches, and
 * persistence metadata so it can migrate cleanly between the connection queue, the global queue,
 * and durable storage across node restarts. It translates raw {@link ClientEvent}s into the
 * higher-level FCP messages required by remote clients, tracks retry policy, and resolves whatever
 * output strategy the caller selected (direct bucket, disk file, chunked stream, or acknowledgement
 * only). The class is therefore the boundary between long-lived persistent jobs and transient FCP
 * sessions.
 *
 * <p>The implementation is largely thread-safe through fine-grained {@code synchronized} sections.
 * State transitions such as success, failure, or cancellation update cached progress snapshots and
 * immediately propagate notifications to any registered {@link ClientEventListener}. During
 * restarts, it rehydrates buckets, metadata, and compatibility hints from the serialized form
 * before delegating back to {@link ClientGetter}.
 *
 * <ul>
 *   <li>Queueing and persistence: registers against either the connection-scoped or global queue.
 *   <li>Progress and metadata: consumes splitter events to project hashes, sizes, and MIME types.
 *   <li>Delivery: enforces {@link ReturnType} semantics when writing buckets or emitting AllData.
 * </ul>
 *
 * @see ClientRequest
 * @see ClientGetter
 * @see ClientGetCallback
 */
public class ClientGet extends ClientRequest
    implements ClientGetCallback, ClientEventListener, PersistentClientCallback {
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
  private static final int VERBOSITY_SPLITFILE_PROGRESS = 1;
  private static final int VERBOSITY_SENT_TO_NETWORK = 2;
  private static final int VERBOSITY_COMPATIBILITY_MODE = 4;
  private static final int VERBOSITY_EXPECTED_HASHES = 8;
  private static final int VERBOSITY_EXPECTED_TYPE = 32;
  private static final int VERBOSITY_EXPECTED_SIZE = 64;
  private static final int VERBOSITY_ENTER_FINITE_COOLDOWN = 128;

  // Stuff waiting for reconnection
  /** Did the request succeed? Valid if finished. */
  private boolean succeeded;

  /**
   * Length of the found data. Will be updated from ClientGetter in onResume() but we persist it
   * anyway.
   */
  private long foundDataLength = -1;

  /**
   * MIME type of the found data. Will be updated from ClientGetter in onResume() but we persist it
   * anyway.
   */
  private String foundDataMimeType;

  /** Details of request failure. */
  private GetFailedMessage getFailedMessage;

  /** Last progress message. Not persistent, ClientGetter will update on onResume(). */
  private transient SimpleProgressMessage progressPending;

  /** Have we received a SendingToNetworkEvent? */
  private boolean sentToNetwork;

  /**
   * Current compatibility mode. This is updated over time as the request progresses, and can be
   * used e.g. to reinsert the file. This is NOT transient, as the ClientGetter does not retain this
   * information.
   */
  private CompatibilityAnalyser compatMode;

  /**
   * Expected hashes of the final data. Will be updated from ClientGetter in onResume() but we
   * persist it anyway.
   */
  private ExpectedHashes expectedHashes;

  // Legacy threshold callback removed.

  private static final String COMPLETED_DOWNLOAD_RESTORE_FAILURE =
      "Failed to restore completed download-to-temp-space request, restarting instead";
  private static final String FETCH_SETTINGS_FALLBACK_MESSAGE =
      "Unable to read fetch settings, will use default settings";

  /**
   * Return-handling strategies that drive how response bytes are surfaced to the FCP caller.
   *
   * <p>The enum combines with serialized {@link #code} values so persistent queues can restore the
   * original delivery semantics quickly during restarts.
   */
  public enum ReturnType {
    /** Returns the downloaded data immediately as an {@link AllDataMessage} bucket. */
    DIRECT((short) 0),
    /** Suppresses data transfer entirely and reports only success or failure metadata. */
    NONE((short) 1),
    /** Streams the fully downloaded payload into a caller-provided file on disk. */
    DISK((short) 2),
    /** Provides the payload over the chunked transfer protocol extension. */
    CHUNKED((short) 3);

    final short code;

    ReturnType(short code) {
      this.code = code;
    }

    /**
     * Maps a serialized return-type code back to the corresponding enum constant.
     *
     * <p>Persistence files and FCP messages use compact shorts to save bandwidth, so this helper
     * restores the strongly typed enum and fails fast when unexpected values surface.
     *
     * @param x numeric tag emitted by persistent storage or remote clients.
     * @return matching {@link ReturnType} describing how the caller expects data to be delivered.
     * @throws IllegalArgumentException if the code is not recognized.
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

  private record ReturnSetup(Bucket bucket, File targetFile, String extension) {}

  private record EventProgress(FCPMessage message, int verbosityMask) {}

  /**
   * Builds a persistent GET request for callers that enqueue work outside live FCP sessions.
   *
   * <p>The constructor clones the node's default {@link FetchContext}, wires up event listeners,
   * normalizes retry limits, and resolves the return path before handing everything to a dedicated
   * {@link ClientGetter}. It is typically used by built-in services that want their requests to be
   * restartable across reboots and obey the global queue semantics rather than the per-connection
   * queue. The supplied flags tightly control datastore reachability, filtering, cache writes, and
   * the maximum size of the temporary buckets allocated on behalf of this request.
   *
   * @param globalClient Persistent client facade owning the global queue slot.
   * @param uri FreenetURI describing the content key and optional metadata.
   * @param dsOnly True to confine fetching to the local datastore only.
   * @param ignoreDS Bypasses the datastore entirely when evaluating availability hints.
   * @param filterData Applies on-the-fly MIME filtering before writing or returning data.
   * @param maxSplitfileRetries Maximum block retries for splitfile reconstruction attempts.
   * @param maxNonSplitfileRetries Retry ceiling for simple non-splitfile requests before failing.
   * @param maxOutputLength Upper bound in bytes for payload and temporary storage usage.
   * @param returnType Delivery strategy describing whether bytes stream, persist, or skip.
   * @param persistRebootOnly True to persist only across reboots instead of fully forever.
   * @param identifier Application supplied identifier echoed through FCP status events.
   * @param verbosity Bitmask controlling which progress events get forwarded back.
   * @param prioClass Priority class guiding scheduler fairness and bandwidth allocation.
   * @param returnFilename Destination filesystem path used solely when disk output requested.
   * @param charset Legacy charset hint ignored here but preserved for compatibility logging.
   * @param writeToClientCache Allows writing the payload into the client HTTP cache.
   * @param realTimeFlag True when the request participates in the realtime scheduler lane.
   * @param binaryBlob Enables BinaryBlob writer semantics instead of classic bucket delivery.
   * @param core Node client core providing factories, permission checks, and trackers.
   * @throws IdentifierCollisionException Identifier already present on the owning persistent
   *     client.
   * @throws NotAllowedException Download target rejected by DDA or security policy.
   * @throws IOException Filesystem errors while preparing disk buckets or output locations.
   */
  public ClientGet(
      PersistentRequestClient globalClient,
      FreenetURI uri,
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
      boolean binaryBlob,
      NodeClientCore core)
      throws IdentifierCollisionException, NotAllowedException, IOException {
    super(
        uri,
        identifier,
        verbosity,
        null,
        globalClient,
        prioClass,
        (persistRebootOnly ? Persistence.REBOOT : Persistence.FOREVER),
        realTimeFlag,
        null,
        true);

    ensureGlobalIdentifierAvailable(globalClient, identifier);
    fctx = core.getClientContext().getDefaultPersistentFetchContext();
    fctx.getEventProducer().addEventListener(this);
    fctx.setLocalRequestOnly(dsOnly);
    fctx.setIgnoreStore(ignoreDS);
    fctx.setMaxNonSplitfileRetries(maxNonSplitfileRetries);
    fctx.setMaxSplitfileBlockRetries(maxSplitfileRetries);
    fctx.setFilterData(filterData);
    fctx.setMaxOutputLength(maxOutputLength);
    fctx.setMaxTempLength(maxOutputLength);
    fctx.setCanWriteClientCache(writeToClientCache);
    compatMode = new CompatibilityAnalyser();
    // USK date hints are configured explicitly for FCP messages.
    this.returnType = returnType;
    this.binaryBlob = binaryBlob;
    if (charset != null && LOG.isDebugEnabled()) {
      LOG.debug("Charset parameter is ignored for ClientGet global queue requests: {}", charset);
    }
    ReturnSetup setup =
        configureReturnHandlingForGlobalRequest(returnType, returnFilename, filterData, core);
    this.targetFile = setup.targetFile();
    this.extensionCheck = setup.extension();
    this.initialMetadata = null;
    getter = makeGetter(core, setup.bucket());
  }

  /**
   * Creates a {@code ClientGet} sourced from an incoming {@link ClientGetMessage} on an FCP link.
   *
   * <p>This path mirrors the original client parameters as closely as possible: it validates DDA
   * permissions, copies all caller-defined {@link FetchContext} overrides, seeds allowed MIME
   * lists, and prepares any disk buckets before instantiating the {@link ClientGetter}. Identifiers
   * can be scoped either to the connection or to the global queue, so both handler-level and
   * persistent collision checks are performed before the request becomes visible to other
   * components.
   *
   * @param handler Connection handler responsible for per-client identifiers and DDA checks.
   * @param message Parsed ClientGetMessage containing all caller preferences and flags.
   * @param core Node client core granting fetch contexts, caches, and permission evaluators.
   * @throws IdentifierCollisionException Identifier already active on this handler or its client.
   * @throws MessageInvalidException Message failed validation or violated configured DDA policies.
   */
  public ClientGet(FCPConnectionHandler handler, ClientGetMessage message, NodeClientCore core)
      throws IdentifierCollisionException, MessageInvalidException {
    super(
        message.uri,
        message.identifier,
        message.verbosity,
        handler,
        message.priorityClass,
        message.persistence,
        message.realTimeFlag,
        message.clientToken,
        message.global);
    if (message.persistence == Persistence.CONNECTION) {
      ensureConnectionIdentifierAvailable(handler, message.identifier);
    }
    // Create a Fetcher directly in order to get more fine-grained control,
    // since the client may override a few context elements.
    fctx = core.getClientContext().getDefaultPersistentFetchContext();
    fctx.getEventProducer().addEventListener(this);
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

    if (message.allowedMIMETypes != null) {
      fctx.setAllowedMIMETypes(new HashSet<>());
      for (String mime : message.allowedMIMETypes) {
        fctx.getAllowedMIMETypes().add(mime);
      }
    }

    this.returnType = message.returnType;
    this.binaryBlob = message.binaryBlob;
    ReturnSetup setup = configureReturnHandlingForMessage(message, core, handler);
    this.targetFile = setup.targetFile();
    this.extensionCheck = setup.extension();
    initialMetadata = message.getInitialMetadata();
    try {
      getter = makeGetter(core, setup.bucket());
    } catch (IOException e) {
      throw bucketCreationFailure(e);
    }
  }

  private ReturnSetup configureReturnHandlingForGlobalRequest(
      ReturnType type, File returnFilename, boolean filterData, NodeClientCore core)
      throws NotAllowedException, IOException {
    return switch (type) {
      case DISK -> {
        File file = Objects.requireNonNull(returnFilename, "returnFilename");
        ensureDownloadAllowed(core, file);
        yield createDiskReturnSetup(file, filterData);
      }
      case NONE -> new ReturnSetup(new NullBucket(), null, null);
      default -> new ReturnSetup(null, null, null);
    };
  }

  private ReturnSetup configureReturnHandlingForMessage(
      ClientGetMessage message, NodeClientCore core, FCPConnectionHandler handler)
      throws MessageInvalidException {
    return switch (message.returnType) {
      case DISK -> buildDiskSetupForMessage(message, core, handler);
      case NONE -> new ReturnSetup(new NullBucket(), null, null);
      default -> new ReturnSetup(null, null, null);
    };
  }

  private ReturnSetup buildDiskSetupForMessage(
      ClientGetMessage message, NodeClientCore core, FCPConnectionHandler handler)
      throws MessageInvalidException {
    File diskFile = message.diskFile;
    if (!core.allowDownloadTo(diskFile)) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.ACCESS_DENIED,
          "Not allowed to download to " + diskFile,
          identifier,
          global);
    }
    if (!handler.ddaAccessController().allowDDAFrom(diskFile, true)) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.DIRECT_DISK_ACCESS_DENIED,
          "Not allowed to download to "
              + diskFile
              + ". You might need to do a "
              + TestDdaRequestMessage.NAME
              + " first.",
          identifier,
          global);
    }
    try {
      handleExistingTargetFile(diskFile);
    } catch (IOException e) {
      MessageInvalidException mie =
          new MessageInvalidException(
              ProtocolErrorMessage.INTERNAL_ERROR,
              "Target filename exists already: " + diskFile,
              identifier,
              global);
      mie.initCause(e);
      throw mie;
    }
    return createDiskReturnSetup(diskFile, fctx.getFilterData());
  }

  private ReturnSetup createDiskReturnSetup(File file, boolean filterData) {
    Bucket bucket = new FileBucket(file, false, true, false, false);
    return new ReturnSetup(bucket, file, filterData ? deriveExtension(file) : null);
  }

  private static String deriveExtension(File file) {
    String name = file.getName();
    int idx = name.lastIndexOf('.');
    if (idx == -1 || idx == name.length() - 1) {
      return null;
    }
    return name.substring(idx + 1);
  }

  private void ensureDownloadAllowed(NodeClientCore core, File file)
      throws NotAllowedException, IOException {
    if (!core.allowDownloadTo(file)) {
      throw new NotAllowedException();
    }
    handleExistingTargetFile(file);
  }

  private void handleExistingTargetFile(File file) throws IOException {
    if (!file.exists()) {
      return;
    }
    if (file.length() == 0) {
      Files.delete(file.toPath());
      LOG.error("Target file already exists but is zero length, deleting...");
    }
    if (file.exists()) {
      throw new IOException("Target filename exists already: " + file);
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
    if (binaryBlob && ret == null) {
      //noinspection resource
      ret =
          core.getClientContext()
              .getBucketFactory(persistence == Persistence.FOREVER)
              .makeBucket(fctx.getMaxOutputLength());
    }

    return new ClientGetter(
        this,
        uri,
        fctx,
        priorityClass,
        binaryBlob ? new NullBucket() : ret,
        binaryBlob ? new BinaryBlobWriter(ret) : null,
        false,
        initialMetadata,
        extensionCheck);
  }

  /**
   * Serialization-only constructor used when reconstructing requests from persistent storage.
   *
   * <p>All fields are intentionally left {@code null} (or primitive defaults) so that
   * deserialization helpers can populate them explicitly via {@link #innerResume(ClientContext)}
   * and related restoration methods. Production code should never invoke this constructor directly;
   * always use one of the fully parameterized alternatives that configure a {@link FetchContext}
   * and getter.
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
   * Must be called just after construction, but within a transaction.
   *
   * @throws IdentifierCollisionException If the identifier is already in use.
   */
  @Override
  void register(boolean noTags) throws IdentifierCollisionException {
    assert client == null || (this.persistence == client.persistence);
    if (persistence != Persistence.CONNECTION) {
      PersistentRequestClient persistentClient =
          Objects.requireNonNull(client, "Persistent client must be available to register");
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
   * <p>The method synchronizes briefly to avoid racing with completion logic, kicks off the
   * underlying {@link ClientGetter}, and emits a persistent tag when the request is tracked beyond
   * the connection scope. It also updates {@link RequestStatusCache} listeners so GUIs immediately
   * reflect the {@code started} flag even if the fetch fails before any progress callbacks are
   * produced. Exceptions raised by the getter are translated into {@link FetchException}s which are
   * handled by {@link #onFailure(FetchException, ClientGetter)} to guarantee consistent cleanup.
   *
   * @param context Client context providing schedulers and bucket factories for execution.
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
      onFailure(e, null);
    } catch (Exception t) {
      synchronized (this) {
        started = true;
      }
      onFailure(new FetchException(FetchExceptionMode.INTERNAL_ERROR, t), null);
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
   * <p>If the request was scoped to the connection persistence model, the loss of transport means
   * the request can never complete for that client, so it is cancelled immediately. Global queue
   * requests simply continue running and rely on later reconnection to deliver pending messages.
   *
   * @param context Client context owning the request; unused but kept for contract parity.
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
   * retains the bucket for {@link AllDataMessage} delivery or leaves the bytes on disk. Afterward
   * it emits {@link DataFoundMessage}, {@link AllDataMessage}, marks statistics caches, and informs
   * the owning {@link FCPConnectionHandler} or {@link PersistentRequestClient}. Any secondary calls
   * are ignored defensively to avoid double frees.
   *
   * @param result Result wrapper exposing MIME metadata and bucket accessors.
   * @param state ClientGetter instance used for blob access during binary-blob transfers.
   */
  @Override
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
      else this.foundDataMimeType = BinaryBlob.MIME_TYPE;

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
   * potentially corrupted state.
   *
   * @param context Client context performing the migration and validation checks.
   * @param completionTime Epoch milliseconds representing the recorded completion instant.
   * @param data Bucket already holding the downloaded payload for direct returns.
   * @throws ResumeFailedException Validation failed because existing output looked inconsistent.
   */
  @SuppressWarnings("unused")
  public void setSuccessForMigration(ClientContext context, long completionTime, Bucket data)
      throws ResumeFailedException {
    Objects.requireNonNull(context, "context");
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

  private void queueProgressMessageInner(FCPMessage msg, int verbosityMask) {
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
   * {@link ProtocolErrorMessage}.
   *
   * @param handler Output handler representing the destination connection to replay into.
   * @param listRequestIdentifier Optional secondary identifier for multi-request list operations.
   * @param includeData True to include {@link AllDataMessage} bodies when available.
   * @param onlyData True to request data frames exclusively, skipping metadata messages.
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
      ProtocolErrorMessage msg =
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
      // resulted in it getting deleted, and also possibly failed deletions.
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
   *
   * @param e Detailed {@link FetchException} describing the failure classification.
   * @param state Optional getter supplying buckets to retain across restarts; may be {@code null}.
   */
  @Override
  public void onFailure(FetchException e, ClientGetter state) {
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
   * Cleans up when the owning queue removes the request, either manually or due to shutdown.
   *
   * <p>If the fetch was still running it fabricates a cancellation {@link FetchException} so the
   * client receives a {@link GetFailedMessage} with an explicit code. Afterward it notifies the
   * connection or persistent client that the entry disappeared, frees associated buckets, and calls
   * the superclass hook so shared accounting (such as tag persistence) also runs.
   *
   * @param context Client context invoking the removal.
   */
  @Override
  public void requestWasRemoved(ClientContext context) {
    // if request is still running, send a GetFailed with code=cancelled
    if (!finished) {
      synchronized (this) {
        succeeded = false;
        finished = true;
        FetchException cancelled = new FetchException(FetchExceptionMode.CANCELLED);
        getFailedMessage = new GetFailedMessage(cancelled, identifier, global);
      }
      trySendDataFoundOrGetFailed(null, null);
    }
    // notify client that request was removed
    FCPMessage msg = new PersistentRequestRemovedMessage(getIdentifier(), global);
    if (persistence != Persistence.CONNECTION) {
      client.queueClientRequestMessage(msg, 0);
    }

    freeData();

    super.requestWasRemoved(context);
  }

  /**
   * Consumes {@link ClientEvent}s streamed by the {@link ClientGetter} and forwards the relevant
   * ones to the remote client according to verbosity flags.
   *
   * <p>Compatibility mode updates may need to be handled within the persistence job runner to avoid
   * blocking IO threads, while other events are translated into {@link SimpleProgressMessage},
   * {@link ExpectedHashes}, or size/type notifications. Verbosity masks ensure clients only see the
   * signals they subscribed to, keeping reconnections lightweight. Unknown events are logged to aid
   * diagnosis without breaking the stream.
   *
   * @param ce Event describing progress, compatibility hints, or splitter metadata.
   * @param context Client context whose job runner may execute deferred compatibility processing.
   */
  @Override
  public void receive(ClientEvent ce, ClientContext context) {
    if (LOG.isDebugEnabled()) LOG.debug("Receiving {} on {}", ce, this);
    if (ce instanceof SplitfileCompatibilityModeEvent compatibilityModeEvent) {
      handleCompatibilityMode(compatibilityModeEvent, context);
      return;
    }
    EventProgress eventProgress = createEventProgress(ce);
    if (eventProgress == null) {
      return;
    }
    if ((verbosity & eventProgress.verbosityMask()) == 0) {
      return;
    }
    queueProgressMessageInner(eventProgress.message(), eventProgress.verbosityMask());
  }

  private EventProgress createEventProgress(ClientEvent event) {
    if (event instanceof SplitfileProgressEvent progressEvent) {
      return handleSplitfileProgress(progressEvent);
    }
    if (event instanceof SendingToNetworkEvent) {
      synchronized (this) {
        sentToNetwork = true;
      }
      return new EventProgress(
          new SendingToNetworkMessage(identifier, global), VERBOSITY_SENT_TO_NETWORK);
    }
    if (event instanceof ExpectedHashesEvent hashesEvent) {
      return handleExpectedHashes(hashesEvent);
    }
    if (event instanceof ExpectedMIMEEvent mimeEvent) {
      return handleExpectedMime(mimeEvent);
    }
    if (event instanceof ExpectedFileSizeEvent sizeEvent) {
      return handleExpectedSize(sizeEvent);
    }
    if (event instanceof EnterFiniteCooldownEvent cooldownEvent) {
      return new EventProgress(
          new EnterFiniteCooldown(identifier, global, cooldownEvent.wakeupTime),
          VERBOSITY_ENTER_FINITE_COOLDOWN);
    }
    LOG.error("Unknown event {}", event);
    return null;
  }

  private EventProgress handleSplitfileProgress(SplitfileProgressEvent event) {
    SimpleProgressMessage message;
    synchronized (this) {
      message = progressPending = new SimpleProgressMessage(identifier, global, event);
    }
    if (client != null) {
      RequestStatusCache cache = client.getRequestStatusCache();
      if (cache != null) {
        cache.updateStatus(identifier, progressPending.getEvent());
      }
    }
    return new EventProgress(message, VERBOSITY_SPLITFILE_PROGRESS);
  }

  private EventProgress handleExpectedHashes(ExpectedHashesEvent event) {
    synchronized (this) {
      if (expectedHashes != null) {
        LOG.warn("Got a new ExpectedHashes");
        return null;
      }
      expectedHashes = new ExpectedHashes(event, identifier, global);
      return new EventProgress(expectedHashes, VERBOSITY_EXPECTED_HASHES);
    }
  }

  private EventProgress handleExpectedMime(ExpectedMIMEEvent event) {
    synchronized (this) {
      foundDataMimeType = event.expectedMIMEType;
    }
    if (client != null) {
      RequestStatusCache cache = client.getRequestStatusCache();
      if (cache != null) {
        cache.updateExpectedMIME(identifier, foundDataMimeType);
      }
    }
    return new EventProgress(
        new ExpectedMIME(identifier, global, event.expectedMIMEType), VERBOSITY_EXPECTED_TYPE);
  }

  private EventProgress handleExpectedSize(ExpectedFileSizeEvent event) {
    synchronized (this) {
      foundDataLength = event.expectedSize;
    }
    if (client != null) {
      RequestStatusCache cache = client.getRequestStatusCache();
      if (cache != null) {
        cache.updateExpectedDataLength(identifier, foundDataLength);
      }
    }
    return new EventProgress(
        new ExpectedDataLength(identifier, global, event.expectedSize), VERBOSITY_EXPECTED_SIZE);
  }

  private void handleCompatibilityMode(
      final SplitfileCompatibilityModeEvent ce, ClientContext context) {
    if (persistence == Persistence.FOREVER && context.jobRunner.hasLoaded()) {
      try {
        context.jobRunner.queue(
            (PersistentJob)
                context1 -> {
                  innerHandleCompatibilityMode(ce);
                  return false;
                },
            NativeThread.PriorityLevel.HIGH_PRIORITY.value);
      } catch (PersistenceDisabledException _) {
        // Not much we can do
      }
    } else {
      innerHandleCompatibilityMode(ce);
    }
  }

  private void innerHandleCompatibilityMode(SplitfileCompatibilityModeEvent ce) {
    compatMode.merge(
        ce.minCompatibilityMode,
        ce.maxCompatibilityMode,
        ce.splitfileCryptoKey,
        ce.dontCompress,
        ce.bottomLayer);
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
    if ((verbosity & VERBOSITY_COMPATIBILITY_MODE) != 0)
      queueProgressMessageInner(
          new CompatibilityMode(identifier, global, compatMode), VERBOSITY_COMPATIBILITY_MODE);
  }

  @Override
  protected ClientRequester getClientRequest() {
    return getter;
  }

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
   * clients can distinguish between cleanly finished requests and those cancelled during restart.
   *
   * @return {@code true} once {@link #onSuccess(FetchResult, ClientGetter)} recorded final state.
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
   * back through the queue once the transfer has completed.
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
   * including restart validation to ensure partially written files are safe to reuse.
   *
   * @return {@code true} when this request writes into a caller-specified file.
   */
  public boolean isToDisk() {
    return this.returnType == ReturnType.DISK;
  }

  /**
   * Returns the current URI the request is fetching, including redirects applied after restarts.
   *
   * @return Mutable {@link FreenetURI} instance representing the active key being chased.
   */
  public FreenetURI getURI() {
    return uri;
  }

  /**
   * Returns the best-known payload size in bytes, either from splitter hints or the final download.
   *
   * <p>The value is persisted between restarts and updated whenever {@link FetchException}
   * discloses an expected size, allowing clients to show progress even before real data arrives.
   *
   * @return Byte length recorded for the fetched data, or {@code -1} if still unknown.
   */
  public long getDataSize() {
    if (foundDataLength > 0) return foundDataLength;
    return -1;
  }

  /**
   * Returns the MIME type detected so far for the payload.
   *
   * <p>Splitter hints, {@link ExpectedMIMEEvent}s, and final {@link FetchResult} metadata all
   * update this string, which is persisted to help clients decide whether to stream or store
   * results.
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
   * @return Absolute file path reserved for disk downloads, or {@code null} otherwise.
   */
  public File getDestFilename() {
    return targetFile;
  }

  /**
   * Returns the fraction of splitfile blocks downloaded successfully.
   *
   * <p>The metric reflects the most recent {@link SplitfileProgressEvent} cached via {@link
   * #progressPending}, making it useful for dashboards that prefer percentages over raw block
   * counts. When no progress has been recorded it returns {@code -1} to signal "unknown".
   *
   * @return Value between {@code 0.0} and {@code 1.0}, or {@code -1} when unavailable.
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
   * @return Total block count from the latest progress event, or {@code 1} when unknown.
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
   * @return Minimum required blocks based on splitter metadata, or {@code 1} if unspecified.
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
   * @return Count of non-fatal failed blocks, defaulting to {@code 0} when unknown.
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
   * @return Fatal failure block count, defaulting to {@code 0} when no data exists yet.
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
   * @return Number of fetched blocks, defaulting to {@code 0} when progress is unavailable.
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
   * <p>The values help reinsertion logic or UI surfaces decide whether a retrieved file can be
   * reinserted using legacy encodings.
   *
   * @return Array of compatibility modes; may be empty but never {@code null}.
   */
  public InsertContext.CompatibilityMode[] getCompatibilityMode() {
    return compatMode.getModes();
  }

  /**
   * Indicates whether reinsertion should skip compression because the source data was
   * precompressed.
   *
   * @return {@code true} when compression should not be applied to subsequent insert contexts.
   */
  public boolean getDontCompress() {
    return compatMode.dontCompress();
  }

  /**
   * Returns the crypto key inferred while parsing splitfile metadata, if one was embedded.
   *
   * @return Copy of the crypto key bytes, or {@code null} when no override was observed.
   */
  public byte[] getOverriddenSplitfileCryptoKey() {
    return compatMode.getCryptoKey();
  }

  /**
   * Returns a textual explanation for the most recent failure, if any.
   *
   * @param longDescription {@code true} to include any extended diagnostic text when available.
   * @return Human-readable failure summary, or {@code null} when the request has not failed.
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
   * @return {@link FetchExceptionMode} describing the failure classification, or {@code null} if
   *     the request has not failed.
   */
  public FetchExceptionMode getFailureReasonCode() {
    if (getFailedMessage == null) return null;
    return getFailedMessage.failureMode;
  }

  /**
   * Indicates whether the splitter has reported a finalized total block count.
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
   * other return types yield {@code null}. Callers should treat the returned bucket as read-only.
   *
   * @return Bucket containing the payload, or {@code null} when no bucket form exists.
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
      case DISK -> new FileBucket(targetFile, readOnly, false, false, false);
      default -> null;
    };
  }

  /**
   * Indicates whether the request can be restarted after a failure.
   *
   * <p>The getter must support restart semantics, the request must have finished, and it must not
   * have succeeded already. Success cases require manual deletion before another attempt.
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
   * <p>It clears cached errors, resets compatibility tracking, optionally disables filtering, and
   * hands the restart request to the underlying {@link ClientGetter}. Cache observers are updated
   * so that frontends show the new redirect or restarted state immediately.
   *
   * @param context Client context providing schedulers and persistent storage for restart logic.
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
      onFailure(e, null);
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
   * @return {@code true} when {@link GetFailedMessage#redirectURI} is non-null.
   */
  public synchronized boolean hasPermRedirect() {
    return getFailedMessage != null && getFailedMessage.redirectURI != null;
  }

  /**
   * Returns whether filterData is currently enabled on the {@link FetchContext}.
   *
   * @return {@code true} when payloads should be filtered before delivery.
   */
  public boolean filterData() {
    return fctx.getFilterData();
  }

  @Override
  synchronized RequestStatus getStatus() {
    boolean totalFinalized = false;
    int total = 0;
    int min = 0;
    int fetched = 0;
    int fatal = 0;
    int failed = 0;
    // See ClientRequester.getLatestSuccess() for why this defaults to current time.
    Date latestSuccess = new Date();
    Date latestFailure = null;

    if (progressPending != null) {
      totalFinalized = progressPending.isTotalFinalized();
      // The progress API reports doubles to preserve partial block counts from the splitter.
      total = (int) progressPending.getTotalBlocks();
      min = (int) progressPending.getMinBlocks();
      fetched = (int) progressPending.getFetchedBlocks();
      latestSuccess = progressPending.getLatestSuccess();
      fatal = (int) progressPending.getFatalyFailedBlocks();
      failed = (int) progressPending.getFailedBlocks();
      latestFailure = progressPending.getLatestFailure();
    }
    if (finished && succeeded) totalFinalized = true;
    FetchExceptionMode failureCode = null;
    String failureReasonShort = null;
    String failureReasonLong = null;
    if (getFailedMessage != null) {
      failureCode = getFailedMessage.failureMode;
      failureReasonShort = getFailedMessage.getShortFailedMessage();
      failureReasonLong = getFailedMessage.getLongFailedMessage();
    }
    String mimeType = foundDataMimeType;
    long dataSize = foundDataLength;
    File target = getDestFilename();
    if (target != null) target = new File(target.getPath());

    Bucket shadow = (finished && succeeded) ? getBucket() : null;
    if (shadow != null) {
      if (dataSize != shadow.size()) {
        LOG.error(
            "Size of downloaded data has changed: {} -> {} on {}", dataSize, shadow.size(), shadow);
        shadow = null;
      } else {
        shadow = shadow.createShadow();
      }
    }

    boolean filterData;
    boolean overriddenDataType;
    filterData = fctx.getFilterData();
    overriddenDataType = fctx.getOverrideMIME() != null || fctx.getCharset() != null;

    return new DownloadRequestStatus(
        identifier,
        persistence,
        started,
        finished,
        succeeded,
        total,
        min,
        fetched,
        latestSuccess,
        fatal,
        failed,
        latestFailure,
        totalFinalized,
        priorityClass,
        failureCode,
        mimeType,
        dataSize,
        target,
        getCompatibilityMode(),
        getOverriddenSplitfileCryptoKey(),
        getURI(),
        failureReasonShort,
        failureReasonLong,
        overriddenDataType,
        shadow,
        filterData,
        getDontCompress());
  }

  private static final long CLIENT_DETAIL_MAGIC = 0x67145b675d2e22f4L;
  private static final int CLIENT_DETAIL_VERSION = 1;

  /**
   * Serializes the request state for persistence so that it can be resumed later.
   *
   * <p>Only FOREVER-persistence requests write detail entries. The method records URIs, return
   * types, binary-blob preferences, fetch contexts, metadata buckets, and—when finished—either the
   * success bucket or the failure descriptor. It also streams recent progress snapshots so restarts
   * can resume without re-downloading already verified blocks.
   *
   * @param dos Destination stream receiving the serialized form with embedded checksums.
   * @param checker Checksum helper that wraps streams to guard against corruption.
   * @throws IOException If any of the serialization steps fail or a bucket cannot be stored.
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
    try (DataOutputStream ctxStream =
        new DataOutputStream(checker.checksumWriterWithLength(dos, new ArrayBucketFactory()))) {
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
          new DataOutputStream(checker.checksumWriterWithLength(dos, new ArrayBucketFactory()))) {
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
                new DataOutputStream(
                    checker.checksumWriterWithLength(dos, new ArrayBucketFactory()))) {
              returnBucketDirect.storeTo(bucketStream);
            }
          }
        } else {
          try (DataOutputStream failureStream =
              new DataOutputStream(
                  checker.checksumWriterWithLength(dos, new ArrayBucketFactory()))) {
            getFailedMessage.writeTo(failureStream);
          }
        }
        return;
      }
    }
    // Not finished, or was recently not finished.
    // Don't hold lock while calling getter.
    // If it's just finished we get a race and restart. That's okay.
    try (DataOutputStream progressStream =
        new DataOutputStream(checker.checksumWriterWithLength(dos, new ArrayBucketFactory()))) {
      if (getter.writeTrivialProgress(progressStream)) {
        writeTransientProgressFields(progressStream);
      }
    }
  }

  /**
   * Recreates a {@link ClientGet} from serialized persistent storage.
   *
   * @param dis Input stream positioned at the serialized client detail block.
   * @param reqID Identifier tuple describing the owner and reference type.
   * @param context Client context supplying factories used during restoration.
   * @param checker Checksum helper verifying integrity of embedded buckets.
   * @return Fully reconstructed {@link ClientRequest} instance ready for resumption.
   * @throws StorageFormatException Serialized data failed validation or used unknown versions.
   * @throws IOException Stream IO failed while reading buckets or metadata.
   * @throws ResumeFailedException Request could not be reconstructed and must restart from scratch.
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
    this.fctx = readFetchContext(dis, context, checker);
    fctx.getEventProducer().addEventListener(this);
    extensionCheck = dis.readBoolean() ? dis.readUTF() : null;
    initialMetadata = readInitialMetadata(dis, context, checker);
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
    } catch (MalformedURLException _) {
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

  private FetchContext readFetchContext(
      DataInputStream dis, ClientContext context, ChecksumChecker checker) {
    try (DataInputStream inner = createChecksummedInput(dis, context, checker)) {
      return new FetchContext(inner);
    } catch (StorageFormatException | IOException e) {
      LOG.error(FETCH_SETTINGS_FALLBACK_MESSAGE, e);
    } catch (ChecksumFailedException _) {
      LOG.error(FETCH_SETTINGS_FALLBACK_MESSAGE);
    }
    return context.getDefaultPersistentFetchContext();
  }

  private Bucket readInitialMetadata(
      DataInputStream dis, ClientContext context, ChecksumChecker checker)
      throws IOException, StorageFormatException, ResumeFailedException {
    if (!dis.readBoolean()) {
      return null;
    }
    try (DataInputStream metadataStream = createChecksummedInput(dis, context, checker)) {
      return BucketTools.restoreFrom(
          metadataStream,
          context.persistentFG,
          context.getPersistentFileTracker(),
          context.getPersistentMasterSecret());
    } catch (ChecksumFailedException e) {
      StorageFormatException sfe = new StorageFormatException("Unable to restore initial metadata");
      sfe.initCause(e);
      throw sfe;
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
    restoreInProgressState(dis, context, checker, inProgressGetter);
    return inProgressGetter;
  }

  private void restoreFinishedState(
      DataInputStream dis, RequestIdentifier reqID, ClientContext context, ChecksumChecker checker)
      throws IOException, StorageFormatException, ResumeFailedException {
    succeeded = dis.readBoolean();
    readTransientProgressFields(dis);
    if (succeeded) {
      restoreCompletedBucket(dis, context, checker);
    } else {
      restoreFailureMessage(dis, reqID, context, checker);
    }
  }

  private void restoreCompletedBucket(
      DataInputStream dis, ClientContext context, ChecksumChecker checker)
      throws ResumeFailedException {
    if (returnType != ReturnType.DIRECT) {
      return;
    }
    try (DataInputStream inner = createChecksummedInput(dis, context, checker)) {
      returnBucketDirect =
          BucketTools.restoreFrom(
              inner,
              context.persistentFG,
              context.getPersistentFileTracker(),
              context.getPersistentMasterSecret());
    } catch (IOException | ChecksumFailedException | StorageFormatException e) {
      LOG.error(COMPLETED_DOWNLOAD_RESTORE_FAILURE, e);
      returnBucketDirect = null;
      succeeded = false;
      finished = false;
    }
  }

  private void restoreFailureMessage(
      DataInputStream dis,
      RequestIdentifier reqID,
      ClientContext context,
      ChecksumChecker checker) {
    try (DataInputStream inner = createChecksummedInput(dis, context, checker)) {
      getFailedMessage = new GetFailedMessage(inner, reqID, foundDataLength, foundDataMimeType);
      started = true;
    } catch (IOException | ChecksumFailedException | StorageFormatException e) {
      LOG.error("Unable to restore reason for failure, restarting request", e);
      finished = false;
      getFailedMessage = null;
    }
  }

  private void restoreInProgressState(
      DataInputStream dis,
      ClientContext context,
      ChecksumChecker checker,
      ClientGetter inProgressGetter)
      throws StorageFormatException {
    try (DataInputStream inner = createChecksummedInput(dis, context, checker)) {
      if (inProgressGetter.resumeFromTrivialProgress(inner, context)) {
        readTransientProgressFields(inner);
      }
    } catch (IOException e) {
      LOG.error("Unable to restore splitfile, restarting: {}", e.toString());
    } catch (ChecksumFailedException _) {
      LOG.error("Unable to restore splitfile, restarting (checksum failed)");
    }
  }

  private DataInputStream createChecksummedInput(
      DataInputStream dis, ClientContext context, ChecksumChecker checker)
      throws IOException, ChecksumFailedException {
    return new DataInputStream(
        checker.checksumReaderWithLength(dis, context.tempBucketFactory, 65536));
  }

  private void readTransientProgressFields(DataInputStream dis)
      throws IOException, StorageFormatException {
    foundDataLength = dis.readLong();
    if (dis.readBoolean()) foundDataMimeType = dis.readUTF();
    else foundDataMimeType = null;
    compatMode = new CompatibilityAnalyser(dis);
    HashResult[] hashes = HashResult.readHashes(dis);
    if (hashes == null || hashes.length == 0) {
      expectedHashes = null;
    } else {
      expectedHashes = new ExpectedHashes(hashes, identifier, global);
    }
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
    HashResult.write(expectedHashes == null ? null : expectedHashes.hashes, dos);
  }

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
   * Indicates whether every component of the request—especially the {@link ClientGetter}—has been
   * restored successfully after a persistence resume.
   *
   * @return {@code true} when {@link ClientGetter#resumedFetcher()} confirms a valid resume.
   */
  @Override
  public boolean fullyResumed() {
    return getter != null && getter.resumedFetcher();
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    return obj instanceof ClientGet && super.equals(obj);
  }

  @Override
  public int hashCode() {
    return super.hashCode();
  }
}
