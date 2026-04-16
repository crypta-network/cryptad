package network.crypta.clients.fcp;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamField;
import java.io.Serial;
import java.net.MalformedURLException;
import java.util.HashMap;
import java.util.Map;
import network.crypta.client.InsertException;
import network.crypta.clients.fcp.RequestIdentifier.RequestType;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.ManifestElement;
import network.crypta.support.io.ResumeFailedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Coordinates the lifecycle of inserting an entire directory tree into Crypta via the Freenet
 * Client Protocol (FCP).
 *
 * <p>Instances bundle files into a manifest, track sizes, and feed work to an opaque execution
 * handle so that complex directory uploads can be paused, resumed, and monitored without
 * re-enumerating the source tree. Typical callers construct this class either from a {@link
 * ClientPutDirMessage} delivered by the network stack or from an on-disk directory chosen by an
 * operator, register it with a {@code PersistentRequestClient}, and finally invoke {@link
 * #start(network.crypta.client.async.ClientContext)} to launch the asynchronous transfer. The
 * object records defaults such as the preferred manifest name, cryptographic overrides, persistence
 * flavor, and file counts so that serialized requests can survive node restarts.
 *
 * <p>The class is not thread-safe; the owning request scheduler must serialize calls such as {@link
 * #start(network.crypta.client.async.ClientContext)}, {@link
 * #restart(network.crypta.client.async.ClientContext, boolean)}, and {@link
 * #requestWasRemoved(network.crypta.client.async.ClientContext)}. Internal caches are mutable until
 * {@link #freeData()} runs, after which the manifest tree is eligible for garbage collection.
 *
 * <ul>
 *   <li>Builds manifests from disk or pre-parsed maps.
 *   <li>Publishes progress and final URIs for FCP clients.
 *   <li>Persists enough metadata to resume inserts after restarts.
 * </ul>
 *
 * @see ClientPutBase
 */
public final class ClientPutDir extends ClientPutBase {
  private static final Logger LOG = LoggerFactory.getLogger(ClientPutDir.class);

  @Serial private static final long serialVersionUID = 1L;

  private static final String LEGACY_PUTTER_TYPE = "network.crypta.client.async.ManifestPutter";

  private static final String FIELD_MANIFEST_ELEMENTS = "manifestElements";
  private static final String FIELD_PUTTER = "putter";
  private static final String FIELD_DEFAULT_NAME = "defaultName";
  private static final String FIELD_TOTAL_SIZE = "totalSize";
  private static final String FIELD_NUMBER_OF_FILES = "numberOfFiles";
  private static final String FIELD_WAS_DISK_PUT = "wasDiskPut";
  private static final String FIELD_OVERRIDE_SPLITFILE_CRYPTO_KEY = "overrideSplitfileCryptoKey";

  @SuppressWarnings("UnusedVariable")
  @Serial
  private static final ObjectStreamField[] serialPersistentFields =
      new ObjectStreamField[] {
        new ObjectStreamField(FIELD_MANIFEST_ELEMENTS, Map.class),
        new ObjectStreamField(FIELD_PUTTER, requiredLegacyPutterClass()),
        new ObjectStreamField(FIELD_DEFAULT_NAME, String.class),
        new ObjectStreamField(FIELD_TOTAL_SIZE, long.class),
        new ObjectStreamField(FIELD_NUMBER_OF_FILES, int.class),
        new ObjectStreamField(FIELD_WAS_DISK_PUT, boolean.class),
        new ObjectStreamField(FIELD_OVERRIDE_SPLITFILE_CRYPTO_KEY, byte[].class)
      };

  /** Mutable tree describing pending manifest elements keyed by child name. */
  private Map<String, Object> manifestElements;

  /** Worker responsible for chunking content, scheduling inserts, and reporting progress. */
  private ClientPutDirExecution putter;

  /** Default manifest name used when callers omit an explicit index document. */
  private String defaultName;

  /** Aggregate byte size of every file discovered when the manifest was created. */
  private long totalSize;

  /** Number of discrete files queued for upload, or {@code -1} when unknown. */
  private int numberOfFiles;

  /** Flag indicating whether the manifest originated from a local disk scan. */
  private boolean wasDiskPut;

  /** Optional caller-provided symmetric key overriding the generated splitfile key ladder. */
  private byte[] overrideSplitfileCryptoKey;

  // Legacy threshold callback removed.

  /**
   * Creates a directory insert request that mirrors an incoming FCP {@link ClientPutDirMessage}.
   *
   * <p>Use this constructor when the remote client already described the directory layout and
   * optional {@link ManifestElement} entries. The initializer validates the URI, copies the
   * manifest tree locally, wires persistence, throttling, and crypto settings as requested, and
   * instantiates the backing {@link ClientPutDirExecution} so file counts and total sizes are
   * available for quick replies. Typical callers construct the object, register it with the
   * persistent client cache, and then call {@link #start(network.crypta.client.async.ClientContext)
   * start(ClientContext)} to launch asynchronous transmission toward peers.
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
   * @throws network.crypta.client.async.TooManyFilesInsertException if the manifest exceeds the
   *     allowed file count budget.
   */
  public ClientPutDir(
      FCPConnectionHandler handler,
      ClientPutDirMessage message,
      Map<String, Object> manifestElements,
      boolean wasDiskPut,
      FCPServer server)
      throws MalformedURLException, network.crypta.client.async.TooManyFilesInsertException {
    FcpInsertRuntimeSupport runtimeSupport = server.insertRuntimeSupport();
    FcpInsertOptions options =
        new FcpInsertOptions(
            new FcpInsertBehaviorOptions(
                message.getCHKOnly,
                message.dontCompress,
                message.localRequestOnly,
                message.maxRetries,
                message.earlyEncode,
                message.realTimeFlag,
                message.ignoreUSKDatehints),
            new FcpInsertTuningOptions(
                message.canWriteClientCache,
                message.forkOnCacheable,
                message.compressorDescriptor,
                message.extraInsertsSingleBlock,
                message.extraInsertsSplitfileHeaderBlock,
                message.compatibilityMode),
            message.overrideSplitfileCryptoKey);
    ClientRequestParams requestParams =
        new ClientRequestParams(
            checkEmptySSK(
                message.uri,
                message.targetFilename != null ? message.targetFilename : "site",
                runtimeSupport),
            message.identifier,
            message.verbosity,
            message.priorityClass,
            message.persistence,
            options.realTimeFlag(),
            message.clientToken,
            message.global);
    super(
        requestParams,
        null,
        options,
        handler,
        runtimeSupport,
        derivePublicURI(requestParams.uri()));
    // debug level captured via LOG.isDebugEnabled()
    this.wasDiskPut = wasDiskPut;
    this.overrideSplitfileCryptoKey = message.overrideSplitfileCryptoKey;

    // objectOnNew is called once, objectOnUpdate is never called, yet manifestElements get blanked
    // anyway!

    this.manifestElements = new HashMap<>();
    this.manifestElements.putAll(manifestElements);

    this.defaultName = message.defaultName;
    makePutter(runtimeSupport, requestParams);
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
   * the directory, optionally skipping hidden files, builds {@link ManifestElement} instances for
   * local files, and configures retry, compression, and persistence knobs before the request is
   * registered with a {@link PersistentRequestClient}. The constructor immediately counts files and
   * bytes, so progress meters have deterministic totals, and it captures the optional override
   * splitfile key for callers who precompute keys. After construction, invoke {@link
   * #start(network.crypta.client.async.ClientContext) start(ClientContext)} to stream blocks while
   * leveraging the provided {@link FCPServer}.
   *
   * <pre>{@code
   * var request =
   *     new ClientPutDir(
   *         new FcpInsertRequest(
   *             client, uri, "upload", 1, null, priority, Persistence.CONNECTION, token, false),
   *         new FcpInsertOptions(
   *             new FcpInsertBehaviorOptions(false, false, false, 3, false, false, false),
   *             new FcpInsertTuningOptions(
   *                 true,
   *                 false,
   *                 null,
   *                 0,
   *                 0,
   *                 FcpCompatibilityMode.COMPAT_DEFAULT),
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
   * @param server owning server providing insert runtime support and cryptographic settings.
   * @throws FileNotFoundException if unreadable files are encountered while not permitted.
   * @throws MalformedURLException if the URI cannot be parsed, normalized, or validated.
   * @throws network.crypta.client.async.TooManyFilesInsertException if the directory exceeds the
   *     configured file limit.
   */
  public ClientPutDir(
      FcpInsertRequest request,
      FcpInsertOptions options,
      File dir,
      String defaultName,
      boolean allowUnreadableFiles,
      boolean includeHiddenFiles,
      FCPServer server)
      throws FileNotFoundException,
          MalformedURLException,
          network.crypta.client.async.TooManyFilesInsertException {
    FcpInsertRuntimeSupport runtimeSupport = server.insertRuntimeSupport();
    ClientRequestParams requestParams =
        new ClientRequestParams(
            checkEmptySSK(request.uri(), "site", runtimeSupport),
            request.identifier(),
            request.verbosity(),
            request.priorityClass(),
            request.persistence(),
            options.realTimeFlag(),
            request.clientToken(),
            request.global());
    super(
        requestParams,
        request.charset(),
        options,
        null,
        request.client(),
        runtimeSupport,
        derivePublicURI(requestParams.uri()));
    wasDiskPut = true;
    this.overrideSplitfileCryptoKey = options.overrideSplitfileCryptoKey();
    // debug level captured via LOG.isDebugEnabled()
    this.manifestElements =
        ClientPutDirManifestSupport.buildDiskManifest(
            dir, allowUnreadableFiles, includeHiddenFiles);
    this.defaultName = defaultName;
    makePutter(runtimeSupport, requestParams);
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
  ClientPutDir() {
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
   * mutable fields participate in standard Java serialization. The serialized form deliberately
   * avoids eagerly rebuilding bridge-owned runtime collaborators during persistence operations.
   *
   * @param out destination stream that will receive the serialized state for this object.
   * @throws IOException if the stream fails, is closed, or otherwise rejects the serialized data.
   */
  @Serial
  private void writeObject(ObjectOutputStream out) throws IOException {
    ObjectOutputStream.PutField fields = out.putFields();
    fields.put(FIELD_MANIFEST_ELEMENTS, manifestElements);
    fields.put(FIELD_PUTTER, legacyPutterForSerialization());
    fields.put(FIELD_DEFAULT_NAME, defaultName);
    fields.put(FIELD_TOTAL_SIZE, totalSize);
    fields.put(FIELD_NUMBER_OF_FILES, numberOfFiles);
    fields.put(FIELD_WAS_DISK_PUT, wasDiskPut);
    fields.put(FIELD_OVERRIDE_SPLITFILE_CRYPTO_KEY, overrideSplitfileCryptoKey);
    out.writeFields();
  }

  /**
   * Restores persisted fields so the request can rejoin the scheduler after JVM restarts.
   *
   * <p>Only the raw data required to reconstruct manifests and statistics is restored here; higher
   * level collaborators will be rebuilt later through {@link #makePutter(FcpInsertRuntimeSupport,
   * ClientRequestParams)} or other initialization paths. The method intentionally leaves runtime
   * caches null to avoid premature resource allocation during deserialization.
   *
   * @param in source stream from which serialized field values are read sequentially.
   * @throws IOException if the serialized form is truncated or cannot be read.
   * @throws ClassNotFoundException if embedded types referenced by the stream are unavailable.
   */
  @Serial
  private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    ObjectInputStream.GetField fields = in.readFields();
    manifestElements = castManifestElements(fields.get(FIELD_MANIFEST_ELEMENTS, null));
    defaultName = (String) fields.get(FIELD_DEFAULT_NAME, null);
    totalSize = fields.get(FIELD_TOTAL_SIZE, 0L);
    numberOfFiles = fields.get(FIELD_NUMBER_OF_FILES, 0);
    wasDiskPut = fields.get(FIELD_WAS_DISK_PUT, false);
    overrideSplitfileCryptoKey = (byte[]) fields.get(FIELD_OVERRIDE_SPLITFILE_CRYPTO_KEY, null);
    putter =
        LegacyInsertExecutionBridgeLoader.load()
            .wrapLegacyDirectoryExecution(
                fields.get(FIELD_PUTTER, null),
                new ClientPutDirExecutionSpec(
                    this, currentRequestParams(), ctx, defaultName, overrideSplitfileCryptoKey));
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> castManifestElements(Object manifestElements) {
    return manifestElements == null ? null : (Map<String, Object>) manifestElements;
  }

  private Object legacyPutterForSerialization() throws NotSerializableException {
    if (putter == null) {
      return null;
    }
    Object requester = putter.legacySerializableRequester();
    if (requester == null) {
      return null;
    }
    if (!requiredLegacyPutterClass().isInstance(requester)) {
      throw new NotSerializableException(
          "Directory putter requester is not compatible with "
              + LEGACY_PUTTER_TYPE
              + ": "
              + requester.getClass().getName());
    }
    return requester;
  }

  private ClientRequestParams currentRequestParams() {
    return new ClientRequestParams(
        uri, identifier, verbosity, priorityClass, persistence, realTime, clientToken, global);
  }

  private static Class<?> requiredLegacyPutterClass() {
    try {
      return Class.forName(LEGACY_PUTTER_TYPE);
    } catch (ClassNotFoundException e) {
      throw new ExceptionInInitializerError(e);
    }
  }

  @Override
  void register(boolean noTags) throws IdentifierCollisionException {
    if (persistence != Persistence.CONNECTION) client.register(this);
    if (persistence != Persistence.CONNECTION && !noTags) {
      FCPMessage msg = persistentTagMessage();
      client.queueClientRequestMessage(msg, 0);
    }
  }

  private void makePutter(FcpInsertRuntimeSupport runtimeSupport, ClientRequestParams requestParams)
      throws network.crypta.client.async.TooManyFilesInsertException {
    putter =
        runtimeSupport.createDirectoryExecution(
            new ClientPutDirExecutionSpec(
                this, requestParams, ctx, defaultName, overrideSplitfileCryptoKey));
  }

  Map<String, Object> manifestElementsForExecution() {
    return manifestElements;
  }

  /**
   * Begins manifest insertion by arming the {@link ClientPutDirExecution} and notifying interested
   * clients.
   *
   * <p>The method is idempotent: repeated calls after the first successful start are ignored. It
   * configures the request cache so that CALL/RESULT messages reflect the running state, queues a
   * persistent tag message when applicable, and handles {@link InsertException}s by reporting
   * immediate failure. Callers should provide the same {@link
   * network.crypta.client.async.ClientContext ClientContext} used during construction so caches,
   * thread pools, and retry policies remain consistent.
   *
   * @param context client context supplying thread pools and scheduler knobs for this transfer.
   */
  @Override
  public void start(network.crypta.client.async.ClientContext context) {
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
      onFailure(e, (FcpInsertCallbackState) null);
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
    ClientPutDirManifestSupport.freeManifest(manifestElements);
    manifestElements = null;
  }

  /**
   * Exposes the underlying requester handle so schedulers can introspect progress.
   *
   * <p>The manifest putter encapsulates all block scheduling and retry logic. Returning it here
   * lets the superclass manage cross-cutting behaviors such as throttling, serialization, and
   * statistics updates uniformly. Callers should treat the returned instance as transient; once
   * {@link #freeData()} runs or the request completes, the putter may be {@code null} and should
   * not be reused.
   *
   * @return currently active requester handle coordinating splitfile inserts, or {@code null} when
   *     torn down.
   */
  @Override
  protected FcpRequesterHandle getClientRequest() {
    return putter == null ? null : putter.requester();
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
    return new ClientPutDirPersistentTagBuilder(this).persistentTagMessage();
  }

  /**
   * Reports whether the insert completed successfully according to the latest status snapshot.
   *
   * <p>The flag is updated by the backing {@link ClientPutDirExecution} when the final block
   * commits or when a fatal error occurs. Consumers should treat the value as monotonic: once
   * {@code true}, the request will not revert even if further callbacks arrive. A {@code false}
   * value may still mean work is ongoing, so callers should also consult the general completion
   * flags exposed by the FCP status APIs before deciding whether retries or restarts are
   * appropriate.
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
   * <p>The count is derived from the {@link ClientPutDirExecution} during initialization and
   * therefore reflects the directory structure at scan time, not real-time filesystem changes. When
   * the manifest is provided by a remote client, the number reflects that client's enumeration. A
   * value of {@code -1} indicates that counting was skipped because the putter could not be
   * created.
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
   * #restart(network.crypta.client.async.ClientContext, boolean) restart(ClientContext, boolean)}.
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
    return putter != null && putter.canRestart();
  }

  /**
   * Rebuilds transient state and re-queues the request after a recoverable failure.
   *
   * <p>The restart sequence verifies eligibility via {@link #canRestart()}, resets counters,
   * refreshes persistent cache entries, and delegates the retry to the existing {@link
   * ClientPutDirExecution}. Successful persistent restarts also emit a fresh {@link
   * PersistentPutDir} tag so connected FCP clients observe the renewed {@code Started} state and
   * any updated splitfile key. If the bridge reports an {@link InsertException}, the method aborts
   * and surfaces the failure through the usual request path.
   *
   * @param context client context used for thread pools, throttling, and crypto settings.
   * @param disableFilterData ignored flag maintained for backwards compatibility with filters.
   * @return {@code true} when the restart was scheduled; {@code false} if prerequisites failed.
   */
  @Override
  public boolean restart(
      network.crypta.client.async.ClientContext context, final boolean disableFilterData) {
    if (!canRestart()) return false;
    setVarsRestart();
    if (client != null) {
      RequestStatusCache cache = client.getRequestStatusCache();
      if (cache != null) {
        cache.updateStarted(identifier, false);
      }
    }
    try {
      if (putter.restart(context)) {
        synchronized (this) {
          generatedURI = null;
          started = true;
        }
      }
    } catch (InsertException e) {
      this.onFailure(e, (FcpInsertCallbackState) null);
      return false;
    }
    if (client != null) {
      RequestStatusCache cache = client.getRequestStatusCache();
      if (cache != null) {
        cache.updateStarted(identifier, true);
      }
    }
    if (persistence != Persistence.CONNECTION && !finished) {
      FCPMessage msg = persistentTagMessage();
      client.queueClientRequestMessage(msg, 0);
    }
    return true;
  }

  /**
   * Handles eviction from the scheduler or request cache by releasing runtime helpers.
   *
   * <p>Persistent FOREVER requests can survive removal events, so this hook nulls out the {@link
   * ClientPutDirExecution} to avoid holding on to stale channels until a later resuming occurs. The
   * superclass observes the event as well, ensuring that shared bookkeeping such as rate limiting
   * and identifier mappings stay consistent.
   *
   * @param context client context associated with the scheduler issuing the removal.
   */
  @Override
  public void requestWasRemoved(network.crypta.client.async.ClientContext context) {
    if (persistence == Persistence.FOREVER) {
      putter = null;
    }
    super.requestWasRemoved(context);
  }

  /**
   * Intentionally left empty because directory inserts rely on the backing {@link
   * ClientPutDirExecution} for compression reporting instead of request-level callbacks.
   *
   * <p>The bridge-owned manifest execution owns all compressor instances for manifests, so there is
   * no additional bookkeeping required when compression starts or stops. The override exists only
   * to acknowledge the lifecycle hook and documents that no state transition occurs here.
   */
  @Override
  protected void onStartCompressing() {
    // Ignore
  }

  /**
   * Intentionally left empty because no per-request cleanup is needed when compression stops.
   *
   * <p>Directory inserts delegate to the backing {@link ClientPutDirExecution}, which owns the
   * compressor lifetime and frees its resources once chunks are flushed. Leaving this hook empty
   * prevents duplicate bookkeeping while still satisfying the superclass contract.
   */
  @Override
  protected void onStopCompressing() {
    // Ignore
  }

  @Override
  RequestStatus getStatus() {
    return ClientPutDirStatusSnapshotBuilder.build(this);
  }

  /**
   * Reattaches persisted manifests to a live {@link network.crypta.client.async.ClientContext
   * ClientContext} during resume sequences.
   *
   * <p>The method delegates to {@link ClientPutDirExecution#resumeMetadata(Map,
   * network.crypta.client.async.ClientContext)}, which rebuilds transient metadata for each {@link
   * ManifestElement} so the putter can continue where it left off. Any metadata mismatch triggers a
   * {@link ResumeFailedException}, signaling that the request should be abandoned or rebuilt from
   * disk.
   *
   * @param context context supplying the memory pools and cryptographic providers required for
   *     resumed manifests.
   * @throws ResumeFailedException if the persisted manifest cannot be revalidated or restored.
   */
  @Override
  public void innerResume(network.crypta.client.async.ClientContext context)
      throws ResumeFailedException {
    if (putter != null) {
      putter.resumeMetadata(manifestElements, context);
    }
  }

  @Override
  RequestType getType() {
    return RequestType.PUTDIR;
  }

  /**
   * Indicates whether every component of the request has been fully restored after resuming.
   *
   * <p>Directory inserts currently resume lazily, rebuilding manifest metadata only when {@link
   * #innerResume(network.crypta.client.async.ClientContext) innerResume(ClientContext)} is invoked
   * later in the lifecycle. Consequently, this method always returns {@code false}, signaling to
   * higher layers that additional resume work may be pending.
   *
   * @return always {@code false} because manifest metadata is resumed incrementally.
   */
  @Override
  public boolean fullyResumed() {
    return false;
  }

  ClientPutDirExecution persistentTagExecution() {
    return putter;
  }

  String persistentTagDefaultName() {
    return defaultName;
  }

  boolean persistentTagWasDiskPut() {
    return wasDiskPut;
  }

  Map<String, Object> persistentTagManifestElements() {
    return manifestElements;
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
