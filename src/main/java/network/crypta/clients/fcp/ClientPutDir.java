package network.crypta.clients.fcp;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serial;
import java.net.MalformedURLException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import network.crypta.client.DefaultMIMETypes;
import network.crypta.client.InsertException;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.Metadata;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientRequester;
import network.crypta.client.async.ContainerInserter;
import network.crypta.client.async.DefaultManifestPutter;
import network.crypta.client.async.ManifestPutter;
import network.crypta.client.async.ManifestPutterParams;
import network.crypta.client.async.TooManyFilesInsertException;
import network.crypta.clients.fcp.RequestIdentifier.RequestType;
import network.crypta.keys.FreenetURI;
import network.crypta.node.NodeClientCore;
import network.crypta.support.api.ManifestElement;
import network.crypta.support.io.FileBucket;
import network.crypta.support.io.ResumeFailedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Coordinates the lifecycle of inserting an entire directory tree into Crypta via the Freenet
 * Client Protocol (FCP).
 *
 * <p>Instances bundle files into a manifest, track sizes, and feed work to a {@link ManifestPutter}
 * so that complex directory uploads can be paused, resumed, and monitored without re-enumerating
 * the source tree. Typical callers construct this class either from a {@link ClientPutDirMessage}
 * delivered by the network stack or from an on-disk directory chosen by an operator, register it
 * with a {@code PersistentRequestClient}, and finally invoke {@link #start(ClientContext)} to
 * launch the asynchronous transfer. The object records defaults such as the preferred manifest
 * name, cryptographic overrides, persistence flavor, and file counts so that serialized requests
 * can survive node restarts.
 *
 * <p>The class is not thread-safe; the owning request scheduler must serialize calls such as {@link
 * #start(ClientContext)}, {@link #restart(ClientContext, boolean)}, and {@link
 * #requestWasRemoved(ClientContext)}. Internal caches are mutable until {@link #freeData()} runs,
 * after which the manifest tree is eligible for garbage collection.
 *
 * <ul>
 *   <li>Builds manifests from disk or pre-parsed maps.
 *   <li>Publishes progress and final URIs for FCP clients.
 *   <li>Persists enough metadata to resume inserts after restarts.
 * </ul>
 *
 * @see ClientPutBase
 * @see ManifestPutter
 */
public class ClientPutDir extends ClientPutBase {
  private static final Logger LOG = LoggerFactory.getLogger(ClientPutDir.class);

  @Serial private static final long serialVersionUID = 1L;

  /** Mutable tree describing pending manifest elements keyed by child name. */
  private Map<String, Object> manifestElements;

  /**
   * Worker responsible for chunking content, scheduling inserts, and reporting progress back to the
   * client request cache.
   */
  private ManifestPutter putter;

  /** Default manifest name used when callers omit an explicit index document. */
  private final String defaultName;

  /** Aggregate byte size of every file discovered when the manifest was created. */
  private final long totalSize;

  /** Number of discrete files queued for upload, or {@code -1} when unknown. */
  private final int numberOfFiles;

  /** Flag indicating whether the manifest originated from a local disk scan. */
  private final boolean wasDiskPut;

  /** Optional caller-provided symmetric key overriding the generated splitfile key ladder. */
  private final byte[] overrideSplitfileCryptoKey;

  // Legacy threshold callback removed.

  /**
   * Creates a directory insert request that mirrors an incoming FCP {@link ClientPutDirMessage}.
   *
   * <p>Use this constructor when the remote client already described the directory layout and
   * optional {@link ManifestElement} entries. The initializer validates the URI, copies the
   * manifest tree locally, wires persistence, throttling, and crypto settings as requested, and
   * instantiates a {@link ManifestPutter} so file counts and total sizes are available for quick
   * replies. Typical callers construct the object, register it with the persistent client cache,
   * and then call {@link #start(ClientContext)} to launch asynchronous transmission toward peers.
   *
   * <pre>{@code
   * var request = new ClientPutDir(handler, msg, msg.manifest, false, server);
   * request.start(core.getClientContext());
   * }</pre>
   *
   * @param handler the connection handler responsible for routing progress replies to the caller.
   * @param message parsed message supplying URI, identifiers, persistence mode, and limits.
   * @param manifestElements manifest tree contributed by the caller, keyed by child names.
   * @param wasDiskPut true if the manifest originated from a disk enumeration on the node.
   * @param server FCP server reference providing access to the shared node client core.
   * @throws MalformedURLException if the request URI cannot be parsed or canonicalized.
   * @throws TooManyFilesInsertException if the manifest exceeds the allowed file count budget.
   */
  public ClientPutDir(
      FCPConnectionHandler handler,
      ClientPutDirMessage message,
      Map<String, Object> manifestElements,
      boolean wasDiskPut,
      FCPServer server)
      throws MalformedURLException, TooManyFilesInsertException {
    FcpInsertOptions options =
        new FcpInsertOptions(
            message.getCHKOnly,
            message.dontCompress,
            message.localRequestOnly,
            message.maxRetries,
            message.earlyEncode,
            message.canWriteClientCache,
            message.forkOnCacheable,
            message.compressorDescriptor,
            message.extraInsertsSingleBlock,
            message.extraInsertsSplitfileHeaderBlock,
            message.realTimeFlag,
            message.compatibilityMode,
            message.ignoreUSKDatehints,
            message.overrideSplitfileCryptoKey);
    ClientRequestParams requestParams =
        new ClientRequestParams(
            checkEmptySSK(
                message.uri,
                message.targetFilename != null ? message.targetFilename : "site",
                server.getCore().getClientContext()),
            message.identifier,
            message.verbosity,
            message.priorityClass,
            message.persistence,
            options.realTimeFlag(),
            message.clientToken,
            message.global);
    super(requestParams, null, options, handler, server);
    // debug level captured via LOG.isDebugEnabled()
    this.wasDiskPut = wasDiskPut;
    this.overrideSplitfileCryptoKey = message.overrideSplitfileCryptoKey;

    // objectOnNew is called once, objectOnUpdate is never called, yet manifestElements get blanked
    // anyway!

    this.manifestElements = new HashMap<>();
    this.manifestElements.putAll(manifestElements);

    this.defaultName = message.defaultName;
    makePutter(server.getCore().getClientContext());
    if (putter != null) {
      numberOfFiles = putter.countFiles();
      totalSize = putter.totalSize();
    } else {
      numberOfFiles = -1;
      totalSize = -1;
    }
    if (LOG.isDebugEnabled())
      LOG.debug("Init put-dir from FCP message id={} priority={}", identifier, priorityClass);
  }

  /**
   * Scans a local directory tree and schedules it for encrypted asynchronous insertion.
   *
   * <p>This overload inspects the filesystem on behalf of desktop or node-local tooling. It walks
   * the directory, optionally skipping hidden files, builds {@link ManifestElement} instances
   * backed by {@link FileBucket}s, and configures retry, compression, and persistence knobs before
   * the request is registered with a {@link PersistentRequestClient}. The constructor immediately
   * counts files and bytes, so progress meters have deterministic totals, and it captures the
   * optional override splitfile key for callers who precompute keys. After construction, invoke
   * {@link #start(ClientContext)} to stream blocks while leveraging the provided {@link
   * NodeClientCore}.
   *
   * <pre>{@code
   * var request =
   *     new ClientPutDir(
   *         new FcpInsertRequest(
   *             client, uri, "upload", 1, null, priority, Persistence.CONNECTION, token, false),
   *         new FcpInsertOptions(
   *             false,
   *             false,
   *             false,
   *             3,
   *             false,
   *             true,
   *             false,
   *             null,
   *             0,
   *             0,
   *             false,
   *             InsertContext.CompatibilityMode.COMPAT_DEFAULT,
   *             false,
   *             null),
   *         new File("site"),
   *         "index.html",
   *         false,
   *         false,
   *         core);
   * request.start(core.getClientContext());
   * }</pre>
   *
   * @param request persistent insert request metadata for the directory insert.
   * @param options insert tuning options such as retries and compression choices.
   * @param dir root directory that will be enumerated and uploaded recursively.
   * @param defaultName default manifest document served when consumers fetch the directory.
   * @param allowUnreadableFiles true to skip unreadable entries instead of aborting immediately.
   * @param includeHiddenFiles true to include filesystem entries marked hidden by the OS.
   * @param core node client core providing context services and cryptographic settings.
   * @throws FileNotFoundException if unreadable files are encountered while not permitted.
   * @throws MalformedURLException if the URI cannot be parsed, normalized, or validated.
   * @throws TooManyFilesInsertException if the directory exceeds the configured file limit.
   */
  public ClientPutDir(
      FcpInsertRequest request,
      FcpInsertOptions options,
      File dir,
      String defaultName,
      boolean allowUnreadableFiles,
      boolean includeHiddenFiles,
      NodeClientCore core)
      throws FileNotFoundException, MalformedURLException, TooManyFilesInsertException {
    ClientRequestParams requestParams =
        new ClientRequestParams(
            checkEmptySSK(request.uri(), "site", core.getClientContext()),
            request.identifier(),
            request.verbosity(),
            request.priorityClass(),
            request.persistence(),
            options.realTimeFlag(),
            request.clientToken(),
            request.global());
    super(requestParams, request.charset(), options, null, request.client(), core);
    wasDiskPut = true;
    this.overrideSplitfileCryptoKey = options.overrideSplitfileCryptoKey();
    // debug level captured via LOG.isDebugEnabled()
    this.manifestElements = makeDiskDirManifest(dir, "", allowUnreadableFiles, includeHiddenFiles);
    this.defaultName = defaultName;
    makePutter(core.getClientContext());
    if (putter != null) {
      numberOfFiles = putter.countFiles();
      totalSize = putter.totalSize();
    } else {
      numberOfFiles = -1;
      totalSize = -1;
    }
    if (LOG.isDebugEnabled())
      LOG.debug("Init put-dir from disk scan id={} priority={}", identifier, priorityClass);
  }

  /**
   * Serialization constructor that allows persisted requests to be rehydrated before field
   * injection.
   *
   * <p>Binary persistence frameworks such as {@link java.io.ObjectInputStream} invoke this
   * constructor before restoring field values. No heavy initialization or client context wiring
   * occurs here because deserialization will immediately assign definitive values when {@code
   * readObject(ObjectInputStream)} runs. All primitive fields are initialized to benign defaults so
   * that partially restored instances remain stable even if deserialization fails midway.
   */
  protected ClientPutDir() {
    // For serialization.
    defaultName = null;
    totalSize = 0;
    numberOfFiles = 0;
    wasDiskPut = false;
    overrideSplitfileCryptoKey = null;
  }

  /**
   * Writes the minimal serialization form so persistent request queues can be resumed verbatim.
   *
   * <p>The implementation delegates to {@link ObjectOutputStream#defaultWriteObject()} because all
   * mutable fields participate in standard Java serialization. No transient handles are written, so
   * callers must reconstruct runtime collaborators (such as {@link ManifestPutter}) separately.
   *
   * @param out destination stream that will receive the serialized state for this object.
   * @throws IOException if the stream fails, is closed, or otherwise rejects the serialized data.
   */
  @Serial
  private void writeObject(ObjectOutputStream out) throws IOException {
    out.defaultWriteObject();
  }

  /**
   * Restores persisted fields so the request can rejoin the scheduler after JVM restarts.
   *
   * <p>Only the raw data required to reconstruct manifests and statistics is restored here; higher
   * level collaborators will be rebuilt later through {@link #makePutter(ClientContext)} or other
   * initialization paths. The method intentionally leaves runtime caches null to avoid premature
   * resource allocation during deserialization.
   *
   * @param in source stream from which serialized field values are read sequentially.
   * @throws IOException if the serialized form is truncated or cannot be read.
   * @throws ClassNotFoundException if embedded types referenced by the stream are unavailable.
   */
  @Serial
  private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.defaultReadObject();
  }

  @Override
  void register(boolean noTags) throws IdentifierCollisionException {
    if (persistence != Persistence.CONNECTION) client.register(this);
    if (persistence != Persistence.CONNECTION && !noTags) {
      FCPMessage msg = persistentTagMessage();
      client.queueClientRequestMessage(msg, 0);
    }
  }

  private Map<String, Object> makeDiskDirManifest(
      File dir, String prefix, boolean allowUnreadableFiles, boolean includeHiddenFiles)
      throws FileNotFoundException {

    Map<String, Object> map = new HashMap<>();
    File[] files = dir.listFiles();

    if (files == null) throw new IllegalArgumentException("No such directory");

    for (File file : files) {
      if (shouldSkipHiddenFile(file, includeHiddenFiles)) {
        continue;
      }

      if (!file.exists() || !file.canRead()) {
        handleUnreadableFile(file, allowUnreadableFiles);
      } else if (file.isFile()) {
        addFileEntry(map, file, prefix);
      } else if (file.isDirectory()) {
        addDirectoryEntry(map, file, prefix, allowUnreadableFiles, includeHiddenFiles);
      } else {
        handleUnsupportedEntry(file, allowUnreadableFiles);
      }
    }

    return map;
  }

  private boolean shouldSkipHiddenFile(File file, boolean includeHiddenFiles) {
    return file.isHidden() && !includeHiddenFiles;
  }

  private void handleUnreadableFile(File file, boolean allowUnreadableFiles)
      throws FileNotFoundException {
    if (!allowUnreadableFiles) {
      throw new FileNotFoundException("The file does not exist or is unreadable : " + file);
    }
  }

  private void handleUnsupportedEntry(File file, boolean allowUnreadableFiles)
      throws FileNotFoundException {
    if (!allowUnreadableFiles) {
      throw new FileNotFoundException("Not a file and not a directory : " + file);
    }
  }

  private void addFileEntry(Map<String, Object> map, File file, String prefix) {
    FileBucket bucket = new FileBucket(file, true, false, false, false);
    if (LOG.isDebugEnabled()) LOG.debug("Manifest add file path={}", file.getAbsolutePath());

    map.put(
        file.getName(),
        new ManifestElement(
            file.getName(),
            prefix + file.getName(),
            bucket,
            DefaultMIMETypes.guessMIMEType(file.getName(), true),
            file.length()));
  }

  private void addDirectoryEntry(
      Map<String, Object> map,
      File directory,
      String prefix,
      boolean allowUnreadableFiles,
      boolean includeHiddenFiles)
      throws FileNotFoundException {
    if (LOG.isDebugEnabled())
      LOG.debug("Manifest add directory path={}", directory.getAbsolutePath());

    map.put(
        directory.getName(),
        makeDiskDirManifest(
            directory,
            prefix + directory.getName() + "/",
            allowUnreadableFiles,
            includeHiddenFiles));
  }

  private void makePutter(ClientContext context) throws TooManyFilesInsertException {
    putter =
        new DefaultManifestPutter(
            new ManifestPutterParams(
                this,
                manifestElements,
                priorityClass,
                uri,
                defaultName,
                ctx,
                overrideSplitfileCryptoKey,
                context),
            persistence == Persistence.FOREVER);
  }

  /**
   * Begins manifest insertion by arming the {@link ManifestPutter} and notifying interested
   * clients.
   *
   * <p>The method is idempotent: repeated calls after the first successful start are ignored. It
   * configures the request cache so that CALL/RESULT messages reflect the running state, queues a
   * persistent tag message when applicable, and handles {@link InsertException}s by reporting
   * immediate failure. Callers should provide the same {@link ClientContext} used during
   * construction so caches, thread pools, and retry policies remain consistent.
   *
   * @param context client context supplying thread pools and scheduler knobs for this transfer.
   */
  @Override
  public void start(ClientContext context) {
    if (finished) return;
    if (started) return;
    try {
      if (putter != null) putter.start(context);

      started = true;
      if (client != null) {
        RequestStatusCache cache = client.getRequestStatusCache();
        if (cache != null) {
          cache.updateStarted(identifier, true);
        }
      }
      if (LOG.isDebugEnabled())
        LOG.debug("Started {} for {} persistence={}", putter, this, persistence);
      if (persistence != Persistence.CONNECTION && !finished) {
        FCPMessage msg = persistentTagMessage();
        client.queueClientRequestMessage(msg, 0);
      }
    } catch (InsertException e) {
      started = true;
      onFailure(e, null);
    }
  }

  /**
   * Releases manifest buckets and writable resources so large trees do not retain memory.
   *
   * <p>This hook is invoked once the request either finishes or transitions into a persisted state
   * where the manifest can be lazily rebuilt later. It recursively traverses the manifest map,
   * frees {@link ManifestElement} buckets, and nulls the root reference to allow garbage
   * collection. The logic is conservative about synchronization, so callers may invoke it
   * regardless of the current persistence mode without risking double-free behavior.
   */
  @Override
  protected void freeData() {
    if (LOG.isDebugEnabled())
      LOG.debug("Free-data begin request={} persistence={}", this, persistence);
    synchronized (this) {
      if (manifestElements == null) {
        if (LOG.isDebugEnabled())
          LOG.debug("Free-data skipped; manifestElements={}", manifestElements);
        return;
      }
    }
    if (LOG.isDebugEnabled())
      LOG.debug("Free-data continue request={} persistence={}", this, persistence);
    // We have to commit everything, so activating everything here costs us little memory...?
    freeData(manifestElements);
    manifestElements = null;
  }

  private void freeData(Map<String, Object> manifestElements) {
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Free-data recurse request={} persistence={} size={}",
          this,
          persistence,
          manifestElements.size());
    for (Object o : manifestElements.values()) {
      if (o instanceof Map) {
        freeData(Metadata.forceMap(o));
      } else {
        ManifestElement e = (ManifestElement) o;
        if (LOG.isDebugEnabled()) LOG.debug("Free-data release element={}", e);
        e.freeData();
      }
    }
  }

  /**
   * Exposes the underlying {@link ClientRequester} so schedulers can introspect progress.
   *
   * <p>The manifest putter encapsulates all block scheduling and retry logic. Returning it here
   * lets the superclass manage cross-cutting behaviors such as throttling, serialization, and
   * statistics updates uniformly. Callers should treat the returned instance as transient; once
   * {@link #freeData()} runs or the request completes, the putter may be {@code null} and should
   * not be reused.
   *
   * @return currently active requester coordinating splitfile inserts, or {@code null} when torn
   *     down.
   */
  @Override
  protected ClientRequester getClientRequest() {
    return putter;
  }

  /**
   * Builds the on-disk representation of this request for persistence queues and FCP resumes.
   *
   * <p>The generated {@link PersistentPutDir} snapshot mirrors the state visible to external
   * clients, including URIs, retry policies, and the manifest tree (when still available). Because
   * the manifest map can be large, a defensive copy is taken so later mutations do not race with
   * the serialization logic. Callers rely on the resulting message when rehydrating requests after
   * crashes or storing them across sessions.
   *
   * @return serialized view of the request suitable for writing to persistent queues or replies.
   */
  @Override
  protected FCPMessage persistentTagMessage() {
    if (lowLevelClient == null) LOG.warn("Persistent snapshot missing low-level client");
    if (putter == null) LOG.warn("Persistent snapshot missing putter");
    HashMap<String, Object> manifestSnapshot =
        manifestElements != null ? new HashMap<>(manifestElements) : null;
    ClientRequestParams requestParams =
        new ClientRequestParams(
            publicURI,
            identifier,
            verbosity,
            priorityClass,
            persistence,
            isRealTime(),
            clientToken,
            global);
    PersistentPutRequestMetadata metadata =
        new PersistentPutRequestMetadata(
            uri,
            started,
            ctx.getMaxInsertRetries(),
            this.ctx.getCompatibilityMode(),
            ctx.isDontCompress(),
            ctx.getCompressorDescriptor(),
            putter != null ? putter.getSplitfileCryptoKey() : null);
    return new PersistentPutDir(requestParams, metadata, defaultName, manifestSnapshot, wasDiskPut);
  }

  private boolean isRealTime() {
    if (lowLevelClient == null) {
      // This can happen but only due to data corruption - old databases on which various bugs have
      // resulted in it getting deleted and also possibly failed deletions.
      LOG.warn("Realtime flag unavailable: lowLevelClient is null");
      return false;
    }
    return lowLevelClient.realTimeFlag();
  }

  /**
   * Reports whether the insert completed successfully according to the latest status snapshot.
   *
   * <p>The flag is updated by the {@link ManifestPutter} when the final block commits or when a
   * fatal error occurs. Consumers should treat the value as monotonic: once {@code true}, the
   * request will not revert even if further callbacks arrive. A {@code false} value may still mean
   * work is ongoing, so callers should also consult the general completion flags exposed by the FCP
   * status APIs before deciding whether retries or restarts are appropriate.
   *
   * @return {@code true} after every file has been inserted and the final URI has been published.
   */
  @Override
  public boolean hasSucceeded() {
    return succeeded;
  }

  /**
   * Returns the final {@link FreenetURI} assigned to the inserted directory once available.
   *
   * <p>The URI is determined by the key type (CHK or SSK) chosen during construction and becomes
   * immutable as soon as the manifest finishes encoding. For CHK requests the value may be
   * generated before network transmission completes, whereas for SSK-based inserts it only appears
   * after the last block is committed. Callers should check {@link #hasSucceeded()} before acting
   * on the URI to avoid presenting incomplete links.
   *
   * @return immutable URI for the uploaded directory, {@code null} while generation continues.
   */
  public FreenetURI getFinalURI() {
    return generatedURI;
  }

  /**
   * Reports how many discrete files were counted when the manifest was constructed.
   *
   * <p>The count is derived from the {@link ManifestPutter} during initialization and therefore
   * reflects the directory structure at scan time, not real-time filesystem changes. When the
   * manifest is provided by a remote client, the number reflects that client's enumeration. A value
   * of {@code -1} indicates that counting was skipped because the putter could not be created.
   *
   * @return non-negative number of file entries, or {@code -1} when unavailable.
   */
  public int getNumberOfFiles() {
    return numberOfFiles;
  }

  /**
   * Returns the aggregate byte size of all files captured in the manifest at creation time.
   *
   * <p>The value is precalculated to provide deterministic progress percentages and is not updated
   * when files change on disk after scanning. For remotely supplied manifests, the total comes from
   * the transmitted metadata and may be {@code -1} when the client omitted sizes. Callers can use
   * this figure to estimate upload duration or validate quotas before starting the request.
   *
   * @return total number of bytes scheduled for upload, or {@code -1} if measurement failed.
   */
  public long getTotalDataSize() {
    return totalSize;
  }

  /**
   * Determines whether the request can be restarted without violating persistence guarantees.
   *
   * <p>The method blocks restarts while work is still running or after success, only allowing
   * retries for finished-but-failed requests. It also emits debug logging so operators can diagnose
   * why a restart attempt was rejected. Callers should check this flag before invoking {@link
   * #restart(ClientContext, boolean)} to avoid unnecessarily rebuilding manifests.
   *
   * @return {@code true} when the request is finished, not successful, and eligible for restart.
   */
  @Override
  public boolean canRestart() {
    if (!finished) {
      LOG.debug("Restart blocked: request not finished id={}", identifier);
      return false;
    }
    if (succeeded) {
      LOG.debug("Restart blocked: request already succeeded id={}", identifier);
      return false;
    }
    return true;
  }

  /**
   * Rebuilds transient state and re-queues the request after a recoverable failure.
   *
   * <p>The restart sequence verifies eligibility via {@link #canRestart()}, resets counters,
   * refreshes persistent cache entries, and constructs a new {@link ManifestPutter}. If manifest
   * enumeration now exceeds configured limits, the method surfaces an {@link InsertException} and
   * aborts. Successful restarts immediately call {@link #start(ClientContext)} so callers do not
   * need to issue two API operations.
   *
   * @param context client context used for thread pools, throttling, and crypto settings.
   * @param disableFilterData ignored flag maintained for backwards compatibility with filters.
   * @return {@code true} when the restart was scheduled; {@code false} if prerequisites failed.
   */
  @Override
  public boolean restart(ClientContext context, final boolean disableFilterData) {
    if (!canRestart()) return false;
    setVarsRestart();
    if (client != null) {
      RequestStatusCache cache = client.getRequestStatusCache();
      if (cache != null) {
        cache.updateStarted(identifier, false);
      }
    }
    try {
      makePutter(context);
    } catch (TooManyFilesInsertException _) {
      this.onFailure(
          new InsertException(
              InsertException.InsertExceptionMode.TOO_MANY_FILES, (String) null, null),
          null);
    }
    start(context);
    return true;
  }

  /**
   * Handles eviction from the scheduler or request cache by releasing runtime helpers.
   *
   * <p>Persistent FOREVER requests can survive removal events, so this hook nulls out the {@link
   * ManifestPutter} to avoid holding on to stale channels until a later resuming occurs. The
   * superclass observes the event as well, ensuring that shared bookkeeping such as rate limiting
   * and identifier mappings stay consistent.
   *
   * @param context client context associated with the scheduler issuing the removal.
   */
  @Override
  public void requestWasRemoved(ClientContext context) {
    if (persistence == Persistence.FOREVER) {
      putter = null;
    }
    super.requestWasRemoved(context);
  }

  /**
   * Intentionally left empty because directory inserts rely on {@link ManifestPutter} compression
   * reporting instead of request-level callbacks.
   *
   * <p>The {@link ContainerInserter} owns all compressor instances for manifests, so there is no
   * additional bookkeeping required when compression starts or stops. The override exists only to
   * acknowledge the lifecycle hook and documents that no state transition occurs here.
   */
  @Override
  protected void onStartCompressing() {
    // Ignore
  }

  /**
   * Intentionally left empty because no per-request cleanup is needed when compression stops.
   *
   * <p>Directory inserts delegate to {@link ManifestPutter}, which owns the compressor lifetime and
   * frees its resources once chunks are flushed. Leaving this hook empty prevents duplicate
   * bookkeeping while still satisfying the superclass contract.
   */
  @Override
  protected void onStopCompressing() {
    // Ignore
  }

  @Override
  RequestStatus getStatus() {
    FreenetURI finalURI = getFinalURI();
    InsertExceptionMode failureCode = null;
    String failureReasonShort = null;
    if (putFailedMessage != null) {
      failureCode = putFailedMessage.failureMode;
      failureReasonShort = putFailedMessage.getLongFailedMessage();
    }

    int total = 0;
    int min = 0;
    int fetched = 0;
    int fatal = 0;
    int failed = 0;
    // See ClientRequester.getLatestSuccess() for why this defaults to the current time.
    Instant latestSuccess = Instant.now();
    Instant latestFailure = null;
    boolean totalFinalized = false;

    if (progressMessage instanceof SimpleProgressMessage msg) {
      total = (int) msg.getTotalBlocks();
      min = (int) msg.getMinBlocks();
      fetched = (int) msg.getFetchedBlocks();
      latestSuccess = msg.getLatestSuccess();
      fatal = (int) msg.getFatalyFailedBlocks();
      failed = (int) msg.getFailedBlocks();
      latestFailure = msg.getLatestFailure();
      totalFinalized = msg.isTotalFinalized();
    }

    RequestStatusSnapshot statusSnapshot =
        new RequestStatusSnapshot(
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
            priorityClass);
    UploadRequestStatusDetails details =
        new UploadRequestStatusDetails(finalURI, uri, failureCode, failureReasonShort, null);
    return new UploadDirRequestStatus(statusSnapshot, details, totalSize, numberOfFiles);
  }

  /**
   * Reattaches persisted manifests to a live {@link ClientContext} during resume sequences.
   *
   * <p>The method delegates to {@link ContainerInserter#resumeMetadata(Map, ClientContext)}, which
   * rebuilds transient metadata for each {@link ManifestElement} so the putter can continue where
   * it left off. Any metadata mismatch triggers a {@link ResumeFailedException}, signaling that the
   * request should be abandoned or rebuilt from disk.
   *
   * @param context context supplying the memory pools and cryptographic providers required for
   *     resumed manifests.
   * @throws ResumeFailedException if the persisted manifest cannot be revalidated or restored.
   */
  @Override
  public void innerResume(ClientContext context) throws ResumeFailedException {
    ContainerInserter.resumeMetadata(manifestElements, context);
  }

  @Override
  RequestType getType() {
    return RequestType.PUTDIR;
  }

  /**
   * Indicates whether every component of the request has been fully restored after resuming.
   *
   * <p>Directory inserts currently resume lazily, rebuilding manifest metadata only when {@link
   * #innerResume(ClientContext)} is invoked later in the lifecycle. Consequently, this method
   * always returns {@code false}, signaling to higher layers that additional resume work may be
   * pending.
   *
   * @return always {@code false} because manifest metadata is resumed incrementally.
   */
  @Override
  public boolean fullyResumed() {
    return false;
  }

  @Override
  public boolean equals(Object obj) {
    return super.equals(obj);
  }

  @Override
  public int hashCode() {
    return super.hashCode();
  }
}
