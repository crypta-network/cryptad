package network.crypta.clients.fcp;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serial;
import java.net.MalformedURLException;
import java.nio.charset.Charset;
import java.nio.charset.IllegalCharsetNameException;
import java.util.HashMap;
import java.util.Map;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertException;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.async.BaseClientPutter;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientPutCallback;
import network.crypta.client.events.ClientEvent;
import network.crypta.client.events.ClientEventListener;
import network.crypta.client.events.ExpectedHashesEvent;
import network.crypta.client.events.FinishedCompressionEvent;
import network.crypta.client.events.SplitfileProgressEvent;
import network.crypta.client.events.StartedCompressionEvent;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.InsertableClientSSK;
import network.crypta.node.NodeClientCore;
import network.crypta.support.api.Bucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Coordinates the lifecycle of FCP insert requests that persist across reconnects and restarts.
 *
 * <p>The class centralizes common state tracking for {@link ClientPut} and {@link ClientPutDir},
 * wiring FCP-facing identifiers, scheduling metadata, persistence constraints, and node callbacks
 * into a single state machine. Instances travel through connection-bound and forever-persistent
 * modes, reattaching to {@link ClientContext}s after deserialization, driving {@link
 * BaseClientPutter} progress, and translating internal events into client-visible FCP messages. It
 * is designed to be thread-aware: mutations happen under synchronization, while outbound messages
 * are dispatched via handler abstractions to avoid deadlocks.
 *
 * <p>Typical usage involves subclassing to provide data-specific logic (single file or directory
 * tree) while relying on {@code ClientPutBase} to manage retries, metadata capture, and reporting.
 * The class enforces invariants such as “no metadata without a URI” and defers expensive resources
 * until necessary. Persistent requests are expected to survive JVM shutdowns; the class supplies
 * serialization hooks and restart helpers for that scenario.
 *
 * <ul>
 *   <li>Translates node events into progress, hash, and completion messages.
 *   <li>Guards persistent state (URIs, metadata, progress snapshots) under synchronization.
 *   <li>Delegates compression-state notifications to subclasses so they can update UI or metrics.
 * </ul>
 *
 * @see ClientPut
 * @see ClientPutDir
 */
public abstract class ClientPutBase extends ClientRequest
    implements ClientPutCallback, ClientEventListener {
  private static final Logger LOG = LoggerFactory.getLogger(ClientPutBase.class);

  @Serial private static final long serialVersionUID = 1L;

  /**
   * Per-request insert context seeded from the node defaults. It carries retry rules, redundancy
   * knobs, and compatibility flags and therefore must be explicitly cleaned up in {@link
   * #requestWasRemoved(ClientContext)} to avoid leaking stale listeners.
   */
  final InsertContext ctx;

  // Verbosity bitmasks
  private static final int VERBOSITY_SPLITFILE_PROGRESS = 1;

  private static final int VERBOSITY_EXPECTED_HASHES = 8; // same as ClientGet
  private static final int VERBOSITY_PUT_FETCHABLE = 256;
  private static final int VERBOSITY_COMPRESSION_START_END = 512;

  // Stuff waiting for reconnection
  /**
   * Flag recording whether the insert eventually succeeded; guarded by {@code synchronized} blocks
   * so that completion callbacks, resume logic, and FCP responders see a consistent snapshot.
   */
  protected boolean succeeded;

  /**
   * Failure payload stored when an insert terminates with an {@link InsertException}. The message
   * is kept rather than the raw exception so that reconnecting clients can receive concise codes
   * without exposing stack traces, yet can still inspect extended descriptions.
   */
  protected PutFailedMessage putFailedMessage;

  /**
   * Final URI published by the inserter. The field remains {@code null} until {@link
   * #onGeneratedURI(FreenetURI, BaseClientPutter)} runs, after which it never changes. Subclasses
   * and clients should treat it as immutable and safe for reuse across threads.
   */
  protected FreenetURI generatedURI;

  /**
   * Snapshot of the last verbosity-gated progress message that should be replayed to reconnecting
   * clients. It intentionally excludes storage serialization to avoid bloating persistent blobs.
   */
  // This could be a SimpleProgress, or it could be started/finished compression.
  // Not that important, so not saved on persistence.
  // Probably saving it would conflict with later changes (full persistence at
  // ClientPutter level).
  protected transient FCPMessage progressMessage;

  /**
   * Request-specific public URI derived from the private insert URI, used when reporting status to
   * clients that are not authorized to see the full CHK/SSK details. It is computed once per
   * instance and therefore safe to cache for UI purposes.
   */
  protected final FreenetURI publicURI;

  /** Metadata returned instead of URI */
  private Bucket generatedMetadata;

  /**
   * Name of the FCP field carrying the SHA-256 hash of source data when clients request that value
   * instead of a final URI.
   */
  public static final String FILE_HASH = "FileHash";

  // Legacy threshold callback removed.

  private static final Map<Integer, UploadFrom> uploadFromByCode = new HashMap<>();

  /**
   * Enumerates where the bytes for a put operation originate, which drives validation and bucket
   * ownership rules during persistence and resume scenarios. The value is serialized with
   * persistent requests so future versions can continue applying consistent invariants.
   */
  public enum UploadFrom { // Codes must be constant at least for migration
    /**
     * Bytes arrive directly from an FCP stream associated with this request, meaning the node must
     * buffer and possibly encrypt incoming data before the client disconnects.
     */
    DIRECT(0),
    /**
     * Bytes are read from a previously staged on-disk file owned by the client, allowing the
     * request to reopen the file during restart without needing the original socket.
     */
    DISK(1),
    /**
     * The put represents a redirect and leverages an existing URI rather than raw data, so
     * insert-time validation is minimal and no bucket ownership is required.
     */
    REDIRECT(2);

    final int code;

    UploadFrom(int code) {
      if (uploadFromByCode.containsKey(code)) {
        throw new IllegalStateException("Duplicate upload-from code: " + code);
      }
      uploadFromByCode.put(code, this);
      this.code = code;
    }

    /**
     * Resolves a serialized upload source code back into the enum constant used to stage buckets
     * and stubs after a restart. The helper keeps a static map so the conversion is O(1) even when
     * invoked frequently. Callers typically load the integer from disk and feed it here before
     * reconstructing bucket ownership policy.
     *
     * @param x integer code stored with persistent state or received via FCP, expected to be one of
     *     the constants defined in this enum
     * @return matching enum instance; never {@code null} for valid codes because results are cached
     * @throws IllegalArgumentException when the caller supplies an unknown code, signalling corrupt
     *     or out-of-date persistence data that the caller must handle separately
     */
    public static UploadFrom getByCode(int x) {
      UploadFrom u = uploadFromByCode.get(x);
      if (u == null) throw new IllegalArgumentException();
      return u;
    }
  }

  /**
   * Builds a connection-scoped put request from raw FCP input streamed through a server handler.
   *
   * <p>This constructor is used while a client socket is still attached. It wires transient handler
   * state, derives a baseline {@link InsertContext}, subscribes to progress events, and records
   * every tunable requested by the remote peer. Subclasses can immediately begin staging data once
   * control returns because scheduling metadata, verbosity flags, and caches have all been
   * populated consistently.
   *
   * @param uri canonical insert URI requested by the client; must not be {@code null}
   * @param identifier unique identifier echoed back on all FCP messages for this insert
   * @param verbosity bitmask describing which progress categories should be emitted
   * @param charset optional declared source charset; unsupported values trigger warnings only
   * @param handler owning connection handler responsible for queuing outbound replies
   * @param priorityClass scheduler priority class; must be within the node-supported range
   * @param persistence requested persistence mode determining how long the request survives
   * @param clientToken opaque token mirrored back during {@code ListPersistentRequests}
   * @param global whether the request participates in the shared global queue instead of per-client
   * @param getCHKOnly true when the caller only needs a CHK hash instead of storing data
   * @param dontCompress true to forcefully disable on-the-fly compression stages
   * @param localRequestOnly true to avoid advertising blocks beyond the local node
   * @param maxRetries maximum block retries before surfacing failure to clients
   * @param earlyEncode whether the inserter should pre-encode splitfiles before contacting peers
   * @param canWriteClientCache true if the insert may touch the persistent client-side cache
   * @param forkOnCacheable instructs the inserter to spawn redundancy when payloads are cacheable
   * @param compressorDescriptor comma-separated list of compressor identifiers to attempt
   * @param extraInsertsSingleBlock redundancy factor for standalone blocks outside splitfiles
   * @param extraInsertsSplitfileHeader redundancy factor for splitfile header blocks
   * @param realTimeFlag true to schedule the job in the latency-sensitive queue
   * @param compatibilityMode compatibility profile that dictates metadata layouts and crypto tweaks
   * @param ignoreUSKDatehints true to skip USK DATEHINT emission and consumption
   * @param server server providing node context, bucket factories, and persistent insert defaults
   * @throws MalformedURLException if {@code uri} cannot be normalized into an insertable form
   */
  protected ClientPutBase(
      FreenetURI uri,
      String identifier,
      int verbosity,
      String charset,
      FCPConnectionHandler handler,
      short priorityClass,
      Persistence persistence,
      String clientToken,
      boolean global,
      boolean getCHKOnly,
      boolean dontCompress,
      boolean localRequestOnly,
      int maxRetries,
      boolean earlyEncode,
      boolean canWriteClientCache,
      boolean forkOnCacheable,
      String compressorDescriptor,
      int extraInsertsSingleBlock,
      int extraInsertsSplitfileHeader,
      boolean realTimeFlag,
      InsertContext.CompatibilityMode compatibilityMode,
      boolean ignoreUSKDatehints,
      FCPServer server)
      throws MalformedURLException {
    super(
        uri,
        identifier,
        verbosity,
        handler,
        priorityClass,
        persistence,
        realTimeFlag,
        clientToken,
        global);
    warnIfUnsupportedCharset(charset);
    ctx = server.getCore().getClientContext().getDefaultPersistentInsertContext();
    ctx.setGetCHKOnly(getCHKOnly);
    ctx.setDontCompress(dontCompress);
    ctx.getEventProducer().addEventListener(this);
    ctx.setMaxInsertRetries(maxRetries);
    ctx.setCanWriteClientCache(canWriteClientCache);
    ctx.setCompressorDescriptor(compressorDescriptor);
    ctx.setForkOnCacheable(forkOnCacheable);
    ctx.setExtraInsertsSingleBlock(extraInsertsSingleBlock);
    ctx.setExtraInsertsSplitfileHeaderBlock(extraInsertsSplitfileHeader);
    ctx.setCompatibilityMode(compatibilityMode);
    ctx.setLocalRequestOnly(localRequestOnly);
    ctx.setEarlyEncode(earlyEncode);
    ctx.setIgnoreUSKDatehints(ignoreUSKDatehints);
    publicURI = this.uri.deriveRequestURIFromInsertURI();
  }

  /**
   * Reserved for Java serialization frameworks that instantiate the class reflectively before
   * invoking {@link #readObject(ObjectInputStream)}. Regular callers must use one of the explicit
   * constructors.
   */
  protected ClientPutBase() {
    // For serialization.
    ctx = null;
    publicURI = null;
  }

  /**
   * Normalizes SSK URIs that omit routing or document names by synthesizing a random key pair and
   * applying the provided filename. This mirrors the behavior expected by the legacy FCP API when
   * clients send {@code SSK@} placeholders.
   *
   * @param uri candidate URI that may lack routing data; callers must not pass {@code null}
   * @param filename optional document name; when missing the method chooses {@code "key"}
   * @param context client context providing the randomness source used to mint new keys
   * @return original URI when already complete or a freshly derived insert URI with the filename
   *     applied; the result is never {@code null}
   */
  static FreenetURI checkEmptySSK(FreenetURI uri, String filename, ClientContext context) {
    if ("SSK".equals(uri.getKeyType()) && uri.getDocName() == null && uri.getRoutingKey() == null) {
      if (filename == null || filename.isEmpty()) filename = "key";
      // SSK@ = use a random SSK.
      InsertableClientSSK key = InsertableClientSSK.createRandom(context.random, "");
      return key.getInsertURI().setDocName(filename);
    } else {
      return uri;
    }
  }

  /**
   * Reconstructs a persistent insert owned by a {@link PersistentRequestClient} when resuming from
   * disk or migrating between schedulers.
   *
   * <p>The constructor receives a fully resolved persistent client handle and reuses the
   * persistence-aware {@link InsertContext} provided by {@link NodeClientCore}. It mirrors the
   * connection-bound constructor but skips server-specific bookkeeping, allowing REST API callers
   * or resuming jobs to bypass socket handlers entirely while preserving the same configuration
   * surface.
   *
   * @param uri canonical insert URI previously persisted for this request
   * @param identifier client-supplied correlation identifier used across restarts
   * @param verbosity bitmask of progress categories to forward to the persistent queue
   * @param charset optional charset hint that influences metadata generation when meaningful
   * @param handler connection handler for immediate responses during the resume handshake
   * @param client persistent request owner used to enqueue outbound messages after resumption
   * @param priorityClass scheduler priority class remembered from the original request
   * @param persistence persistence tier expected for the resumed job; usually {@code FOREVER}
   * @param clientToken opaque identifier mirrored to external monitoring dashboards
   * @param global whether the resumed request rejoins the global queue or remains client-local
   * @param getCHKOnly true to compute a CHK and drop payload storage like the connection variant
   * @param dontCompress true when the resumed job must avoid compression for deterministic output
   * @param maxRetries retry count retained from the previous incarnation for fairness
   * @param earlyEncode whether pre-encoding should resume immediately, matching stored state
   * @param canWriteClientCache true when cached blocks may be written again post-resume
   * @param forkOnCacheable indicates whether cacheable content may spawn redundancy jobs
   * @param localRequestOnly true when inserts must remain within the local node for privacy
   * @param extraInsertsSingleBlock redundancy factor for single-block inserts that persists
   * @param extraInsertsSplitfileHeader redundancy factor for splitfile headers that persists
   * @param realTimeFlag true to push the resumed job into the real-time scheduler lanes
   * @param compressorDescriptor list of compressor names that continue to apply
   * @param compatMode compatibility mode pinned earlier to guarantee deterministic hashes
   * @param ignoreUSKDatehints true when the job must avoid writing or reading USK hints
   * @param core node core used to obtain shared factories and contexts for resumed jobs
   * @throws MalformedURLException if {@code uri} cannot be normalized into a supported insert type
   */
  protected ClientPutBase(
      FreenetURI uri,
      String identifier,
      int verbosity,
      String charset,
      FCPConnectionHandler handler,
      PersistentRequestClient client,
      short priorityClass,
      Persistence persistence,
      String clientToken,
      boolean global,
      boolean getCHKOnly,
      boolean dontCompress,
      int maxRetries,
      boolean earlyEncode,
      boolean canWriteClientCache,
      boolean forkOnCacheable,
      boolean localRequestOnly,
      int extraInsertsSingleBlock,
      int extraInsertsSplitfileHeader,
      boolean realTimeFlag,
      String compressorDescriptor,
      InsertContext.CompatibilityMode compatMode,
      boolean ignoreUSKDatehints,
      NodeClientCore core)
      throws MalformedURLException {
    super(
        uri,
        identifier,
        verbosity,
        handler,
        client,
        priorityClass,
        persistence,
        realTimeFlag,
        clientToken,
        global);
    warnIfUnsupportedCharset(charset);
    ctx = core.getClientContext().getDefaultPersistentInsertContext();
    ctx.setGetCHKOnly(getCHKOnly);
    ctx.setDontCompress(dontCompress);
    ctx.getEventProducer().addEventListener(this);
    ctx.setMaxInsertRetries(maxRetries);
    ctx.setCanWriteClientCache(canWriteClientCache);
    ctx.setCompressorDescriptor(compressorDescriptor);
    ctx.setForkOnCacheable(forkOnCacheable);
    ctx.setExtraInsertsSingleBlock(extraInsertsSingleBlock);
    ctx.setExtraInsertsSplitfileHeaderBlock(extraInsertsSplitfileHeader);
    ctx.setLocalRequestOnly(localRequestOnly);
    ctx.setCompatibilityMode(compatMode);
    ctx.setIgnoreUSKDatehints(ignoreUSKDatehints);
    ctx.setEarlyEncode(earlyEncode);
    publicURI = this.uri.deriveRequestURIFromInsertURI();
  }

  /**
   * Reacts to the owning socket disconnecting by cancelling connection-scoped requests while
   * leaving persistent ones untouched so they can resume later without extra chatter.
   *
   * <p>The method keeps side effects intentionally small. It does not throw nor block; instead it
   * simply triggers {@link #cancel(ClientContext)} for requests that were declared {@link
   * Persistence#CONNECTION}. Persistent and forever requests ignore the event because they expect
   * to be resumed through {@link network.crypta.client.async.ClientRequester} after
   * deserialization.
   *
   * @param context client context that supplies cancellation helpers and resource pools; the value
   *     may be reused across many requests and must not be {@code null}
   */
  @Override
  public void onLostConnection(ClientContext context) {
    if (persistence == Persistence.CONNECTION) cancel(context);
    // otherwise ignore
  }

  /**
   * Finalizes a successful insert by freezing timing statistics, cleaning up transient buckets, and
   * emitting the appropriate {@code PutSuccessful} message.
   *
   * <p>The method is synchronized to guard shared fields such as {@link #generatedURI} and {@link
   * #putFailedMessage}. It also informs the owning {@link PersistentRequestClient} when present so
   * that client-side caches update promptly. Connection-scoped requests additionally release any
   * staged data through {@link #freeData()} before the final message leaves.
   *
   * @param state inserter state referencing the splitfile scheduler; used only for logging or
   *     debugging
   */
  public void onSuccess(BaseClientPutter state) {
    synchronized (this) {
      // Including these helps with certain bugs...
      started = true; // Keep started flag set for resume compatibility.
      succeeded = true;
      finished = true;
      completionTime = System.currentTimeMillis();
      if (generatedURI == null)
        LOG.error("No generated URI in onSuccess() for {} from {}", this, state);
    }
    if (persistence == Persistence.CONNECTION) {
      freeData();
    }
    finish();
    trySendFinalMessage(null, null);
    if (client != null) client.notifySuccess(this);
  }

  /**
   * Records a fatal insert failure, captures the {@link InsertException}, and notifies clients
   * through a {@code PutFailed} message.
   *
   * <p>The method treats the first invocation as authoritative and ignores subsequent calls once
   * {@link #finished} becomes {@code true}. Connection-scoped requests relinquish buffered data,
   * persistent requests keep the failure payload so that reconnecting clients can inspect detailed
   * codes, and registered {@link PersistentRequestClient}s are notified immediately.
   *
   * @param e exception describing why the insert failed, including retry history and codes
   * @param state inserter that triggered the failure; used only for logging context
   */
  @Override
  public void onFailure(InsertException e, BaseClientPutter state) {
    if (finished) return;
    synchronized (this) {
      started = true; // Keep started flag set for resume compatibility.
      finished = true;
      completionTime = System.currentTimeMillis();
      putFailedMessage = new PutFailedMessage(e, identifier, global);
    }
    if (persistence == Persistence.CONNECTION) {
      freeData();
    }
    finish();
    trySendFinalMessage(null, null);
    if (client != null) client.notifyFailure(this);
  }

  /**
   * Accepts the newly derived final URI from the inserter and propagates it to listeners and caches
   * exactly once.
   *
   * <p>Additional invocations log discrepancies but keep the original URI to avoid confusing
   * clients. When a persistent request has an associated {@link RequestStatusCache}, the cache is
   * updated so that reconnecting dashboards immediately display the final URI even if the client is
   * offline at the time of generation.
   *
   * @param uri freshly minted request URI from the inserter; must not be {@code null}
   * @param state inserter providing the URI; used for diagnostics only
   */
  @Override
  public void onGeneratedURI(FreenetURI uri, BaseClientPutter state) {
    synchronized (this) {
      if (generatedURI != null) {
        if (!uri.equals(generatedURI))
          LOG.error(
              "onGeneratedURI({},{}) but already set generatedURI to {}", uri, state, generatedURI);
        else if (LOG.isDebugEnabled())
          LOG.debug("onGeneratedURI() twice with same value: {} -> {}", generatedURI, uri);
      } else {
        generatedURI = uri;
      }
    }
    trySendGeneratedURIMessage(null, null);
    if (client != null) {
      RequestStatusCache cache = client.getRequestStatusCache();
      if (cache != null) {
        cache.gotFinalURI(identifier, uri);
      }
    }
  }

  /**
   * Returns the final URI assigned to this insert once {@link #onGeneratedURI(FreenetURI,
   * BaseClientPutter)} has run. Callers should treat the value as immutable and thread-safe because
   * access is synchronized, and they should avoid caching {@code null} results since future calls
   * may return a valid URI after the inserter finishes. The method never throws and therefore fits
   * polling loops or status pages.
   *
   * @return generated URI or {@code null} when the insert has not produced one yet
   */
  public FreenetURI getGeneratedURI() {
    return generatedURI;
  }

  /**
   * Captures metadata generated instead of a URI and either forwards or frees the supplied bucket
   * depending on whether another metadata payload is already stored.
   *
   * <p>Only the first metadata bucket is retained so disconnecting clients cannot accidentally leak
   * resources. Duplicate deliveries are logged and freed immediately. Non-duplicate metadata is
   * queued for FCP delivery and persisted if the request survives restarts.
   *
   * @param metadata metadata bucket; ownership transfers to this method on success
   * @param state inserter reporting metadata generation; used for logging context only
   */
  @Override
  public void onGeneratedMetadata(Bucket metadata, BaseClientPutter state) {
    boolean delete = false;
    synchronized (this) {
      if (generatedURI != null)
        LOG.error("Got generated metadata but already have URI on {} from {}", this, state);
      if (generatedMetadata != null) {
        LOG.error("Already got generated metadata from {} on {}", state, this);
        delete = true;
      } else {
        generatedMetadata = metadata;
      }
    }
    if (delete) {
      metadata.free();
    } else {
      trySendGeneratedMetadataMessage(metadata, null, null);
    }
  }

  /**
   * Handles explicit removal from the scheduler by sending final notifications, freeing resources,
   * and purging cached progress snapshots so persistent storage shrinks.
   *
   * <p>If the job was still running, the method synthesizes a cancellation {@link InsertException}
   * so clients receive a deterministic failure code. It then informs either the original handler or
   * the persistent client queue, frees metadata buckets, and resets URIs and messages when the
   * persistence tier is {@link Persistence#FOREVER} to avoid replaying stale data on requeue.
   *
   * @param context client context through which cleanup helpers and factories can be reached
   */
  @Override
  public void requestWasRemoved(ClientContext context) {
    // if request is still running, send a PutFailed with code=cancelled
    if (!finished) {
      synchronized (this) {
        finished = true;
        InsertException cancelled = new InsertException(InsertExceptionMode.CANCELLED);
        putFailedMessage = new PutFailedMessage(cancelled, identifier, global);
      }
      trySendFinalMessage(null, null);
    }
    // notify client that request was removed
    FCPMessage msg = new PersistentRequestRemovedMessage(getIdentifier(), global);
    if (persistence == Persistence.CONNECTION) origHandler.send(msg);
    else client.queueClientRequestMessage(msg, 0);

    freeData();
    Bucket meta;
    synchronized (this) {
      meta = generatedMetadata;
      generatedMetadata = null;
      if (persistence == Persistence.FOREVER) {
        putFailedMessage = null;
        generatedURI = null;
        progressMessage = null;
      }
    }
    if (meta != null) {
      meta.free();
    }
    super.requestWasRemoved(context);
  }

  /**
   * Consumes asynchronous events emitted by {@link BaseClientPutter} and converts them into a
   * stable stream of FCP messages according to the active verbosity mask.
   *
   * <p>The method is careful to short-circuit quickly when the request has already finished. It
   * handles four event types—splitfile progress, compression start/end, and expected hashes—and
   * delegates the formatting of each to specialized helper methods that also update local caches.
   *
   * @param ce event describing a state change produced by the inserter
   * @param context context carrying handler references for connection-bound requests; may be {@code
   *     null} when the request is purely persistent
   */
  @Override
  public void receive(final ClientEvent ce, ClientContext context) {
    if (finished) return;
    if (LOG.isDebugEnabled()) LOG.debug("Receiving event {} on {}", ce, this);
    if (ce instanceof SplitfileProgressEvent event) {
      handleSplitfileProgress(event);
    } else if (ce instanceof StartedCompressionEvent event) {
      handleCompressionStarted(event);
    } else if (ce instanceof FinishedCompressionEvent event) {
      handleCompressionFinished(event);
    } else if (ce instanceof ExpectedHashesEvent event) {
      handleExpectedHashes(event);
    }
  }

  private void handleSplitfileProgress(SplitfileProgressEvent event) {
    if ((verbosity & VERBOSITY_SPLITFILE_PROGRESS) == VERBOSITY_SPLITFILE_PROGRESS) {
      SimpleProgressMessage progress = new SimpleProgressMessage(identifier, global, event);
      trySendProgressMessage(progress, VERBOSITY_SPLITFILE_PROGRESS, null);
    }
    if (client != null) {
      RequestStatusCache cache = client.getRequestStatusCache();
      if (cache != null) {
        cache.updateStatus(identifier, event);
      }
    }
  }

  private void handleCompressionStarted(StartedCompressionEvent event) {
    if ((verbosity & VERBOSITY_COMPRESSION_START_END) != VERBOSITY_COMPRESSION_START_END) {
      return;
    }
    StartedCompressionMessage msg = new StartedCompressionMessage(identifier, global, event.codec);
    trySendProgressMessage(msg, VERBOSITY_COMPRESSION_START_END, null);
    onStartCompressing();
  }

  private void handleCompressionFinished(FinishedCompressionEvent event) {
    if ((verbosity & VERBOSITY_COMPRESSION_START_END) != VERBOSITY_COMPRESSION_START_END) {
      return;
    }
    FinishedCompressionMessage msg = new FinishedCompressionMessage(identifier, global, event);
    trySendProgressMessage(msg, VERBOSITY_COMPRESSION_START_END, null);
    onStopCompressing();
  }

  private void handleExpectedHashes(ExpectedHashesEvent event) {
    if ((verbosity & VERBOSITY_EXPECTED_HASHES) != VERBOSITY_EXPECTED_HASHES) {
      return;
    }
    ExpectedHashes msg = new ExpectedHashes(event, identifier, global);
    trySendProgressMessage(msg, VERBOSITY_EXPECTED_HASHES, null);
  }

  /**
   * Invoked whenever the inserter finishes a compression phase so subclasses can flush UI state,
   * release temporary buffers, or update accounting that depends on compression ratios. The method
   * is called on the same thread that receives events and should therefore avoid blocking. Typical
   * implementations toggle a “compressing” flag or decrement a counter used by progress dialogs.
   */
  protected abstract void onStopCompressing();

  /**
   * Invoked immediately before compression begins, enabling subclasses to initialize indicators,
   * allocate scratch space, or log codec-specific activity before data flows through the pipeline.
   * Implementations should be idempotent because reconnecting clients may request restarts, and
   * they should keep work minimal to avoid delaying the inserter threads.
   */
  protected abstract void onStartCompressing();

  /**
   * Broadcasts that a put has become fetchable, meaning that at least one URI exists that other
   * peers can retrieve. This is primarily a UX hint for clients monitoring long-running jobs.
   *
   * <p>The method respects the {@link #VERBOSITY_PUT_FETCHABLE} flag, thereby suppressing chatter
   * when clients prefer minimal updates. It is safe to call even when the final URI has not been
   * persisted yet because the method reads the current value under synchronization.
   *
   * @param putter inserter announcing fetchability; it is not dereferenced here but kept for API
   *     symmetry with the callback interface
   */
  @Override
  public void onFetchable(BaseClientPutter putter) {
    if (finished) return;
    if ((verbosity & VERBOSITY_PUT_FETCHABLE) == VERBOSITY_PUT_FETCHABLE) {
      FreenetURI temp;
      synchronized (this) {
        temp = generatedURI;
      }
      PutFetchableMessage msg = new PutFetchableMessage(identifier, global, temp);
      trySendProgressMessage(msg, VERBOSITY_PUT_FETCHABLE, null);
    }
  }

  private void trySendFinalMessage(
      FCPConnectionOutputHandler handler, String listRequestIdentifier) {

    FCPMessage msg;
    synchronized (this) {
      if (succeeded) {
        msg =
            new PutSuccessfulMessage(identifier, global, generatedURI, startupTime, completionTime);
      } else {
        msg = putFailedMessage;
      }
    }

    if (msg == null) {
      LOG.warn("Trying to send null message on {}", this);
      return;
    }
    dispatchMessage(FCPMessage.withListRequestIdentifier(msg, listRequestIdentifier), handler, 0);
  }

  private void trySendGeneratedURIMessage(
      FCPConnectionOutputHandler handler, String listRequestIdentifier) {
    FCPMessage msg;
    synchronized (this) {
      msg = new URIGeneratedMessage(generatedURI, identifier, isGlobalQueue());
    }
    dispatchMessage(FCPMessage.withListRequestIdentifier(msg, listRequestIdentifier), handler, 0);
  }

  /**
   * @param metadata activated bucket containing metadata that should be forwarded; ownership
   *     belongs to this method once the call succeeds
   * @param handler optional handler to which the metadata message should be sent immediately;
   *     {@code null} uses the persistent queue
   * @param listRequestIdentifier correlation identifier used when replaying messages for list
   *     operations; may be {@code null}
   */
  private void trySendGeneratedMetadataMessage(
      Bucket metadata, FCPConnectionOutputHandler handler, String listRequestIdentifier) {
    FCPMessage msg =
        FCPMessage.withListRequestIdentifier(
            new GeneratedMetadataMessage(identifier, global, metadata), listRequestIdentifier);
    dispatchMessage(msg, handler, 0);
  }

  /**
   * @param msg progress or status message that should be delivered and optionally cached for
   *     reconnecting clients
   * @param verbosity queue priority used when sending via the persistent client request queue;
   *     callers typically pass the verbosity mask for the message type
   * @param handler connection-specific handler when the caller wants immediate delivery; pass
   *     {@code null} to route through the persistent client queue instead
   */
  private void trySendProgressMessage(
      final FCPMessage msg, final int verbosity, FCPConnectionOutputHandler handler) {
    synchronized (this) {
      if (handler == null && persistence != Persistence.CONNECTION) {
        progressMessage = msg;
      }
    }
    dispatchMessage(msg, handler, verbosity);
  }

  private boolean dispatchViaOriginalHandler(FCPConnectionOutputHandler handler, FCPMessage msg) {
    if (persistence == Persistence.CONNECTION && handler == null) {
      if (origHandler != null) {
        origHandler.send(msg);
      }
      return true;
    }
    return false;
  }

  private void dispatchMessage(FCPMessage msg, FCPConnectionOutputHandler handler, int verbosity) {
    if (dispatchViaOriginalHandler(handler, msg)) {
      return;
    }
    if (handler != null) {
      handler.handler.send(msg);
    } else {
      client.queueClientRequestMessage(msg, verbosity);
    }
  }

  /**
   * Supplies the identifying tag message that precedes any replayed progress when a persistent
   * client reconnects. Implementations should return inexpensive, side-effect-free objects because
   * the value is regenerated each time {@link #sendPendingMessages(FCPConnectionOutputHandler,
   * String, boolean, boolean)} runs, and they must embed enough metadata for clients to recognize
   * which request the subsequent payload refers to.
   *
   * @return tag message describing the specific request type and identifiers
   */
  protected abstract FCPMessage persistentTagMessage();

  /**
   * Replays pending progress, metadata, and completion messages to a handler that just subscribed
   * to this request, typically because the client reconnected or issued a listing command.
   *
   * <p>The method first emits the persistent tag so parsers can reestablish context, then delivers
   * stored URIs, metadata buckets, last progress snapshot, and optionally the final success or
   * failure message. Verbosity flags continue to apply, and null checks protect against partially
   * populated state when the request is mid-flight.
   *
   * @param handler destination handler; its {@link FCPConnectionOutputHandler#handler} field must
   *     not be {@code null}
   * @param listRequestIdentifier optional identifier supplied by list requests for correlation
   * @param includeData unused legacy flag preserved for signature compatibility
   * @param onlyData unused legacy flag preserved for signature compatibility
   */
  @Override
  public void sendPendingMessages(
      FCPConnectionOutputHandler handler,
      String listRequestIdentifier,
      boolean includeData,
      boolean onlyData) {
    FCPMessage msg =
        FCPMessage.withListRequestIdentifier(persistentTagMessage(), listRequestIdentifier);
    handler.handler.send(msg);

    boolean generated;
    boolean fin;
    Bucket meta;
    synchronized (this) {
      generated = generatedURI != null;
      msg = FCPMessage.withListRequestIdentifier(progressMessage, listRequestIdentifier);
      fin = finished;
      meta = generatedMetadata;
    }
    if (generated) trySendGeneratedURIMessage(handler, listRequestIdentifier);
    if (meta != null) trySendGeneratedMetadataMessage(meta, handler, listRequestIdentifier);
    if (msg != null) {
      trySendProgressMessage(msg, 0, handler);
    }
    if (fin) trySendFinalMessage(handler, listRequestIdentifier);
  }

  /**
   * Reports the fraction of required blocks that have successfully been inserted so far. The value
   * is derived from the last {@link SimpleProgressMessage} received and therefore lags real time by
   * at most one event. A negative value indicates that no progress message has ever been recorded,
   * which typically happens before encoding starts or immediately after a restart.
   *
   * @return progress fraction between {@code 0} and {@code 1}, or {@code -1} when unknown
   */
  @Override
  public synchronized double getSuccessFraction() {
    if (progressMessage != null) {
      if (progressMessage instanceof SimpleProgressMessage message) return message.getFraction();
      else return 0;
    } else return -1;
  }

  /**
   * Returns the total number of blocks implied by the most recent progress snapshot. The value is
   * useful for computing completion percentages or estimating remaining time. Because splitfiles
   * may expand dynamically, callers should be prepared for the reported number to increase up until
   * {@link #isTotalFinalized()} becomes {@code true}. When no snapshot has been received, the
   * method returns {@code -1} to signal “unknown”.
   *
   * @return non-negative block count or {@code -1} if unavailable
   */
  @Override
  public synchronized double getTotalBlocks() {
    if (progressMessage != null) {
      if (progressMessage instanceof SimpleProgressMessage message) return message.getTotalBlocks();
      else return 0;
    } else return -1;
  }

  /**
   * Returns the minimum number of fetched blocks needed to reconstruct the payload according to the
   * most recent progress update. This helps UI code communicate resilience to failures because it
   * represents the erasure-coded threshold that must be met. A return value of {@code -1} means
   * progress has not been reported yet or the job has just restarted.
   *
   * @return minimum required block count or {@code -1} when unknown
   */
  @Override
  public synchronized double getMinBlocks() {
    if (progressMessage != null) {
      if (progressMessage instanceof SimpleProgressMessage message) return message.getMinBlocks();
      else return 0;
    } else return -1;
  }

  /**
   * Returns how many blocks have failed but remain retryable according to the last progress
   * snapshot. Monitoring code can use the value to decide whether to adjust priorities or warn the
   * user about degrading network conditions. The statistic drops back toward zero once retries
   * succeed.
   *
   * @return non-negative retryable-failure count, or {@code -1} when progress is unavailable
   */
  @Override
  public synchronized double getFailedBlocks() {
    if (progressMessage != null) {
      if (progressMessage instanceof SimpleProgressMessage message)
        return message.getFailedBlocks();
      else return 0;
    } else return -1;
  }

  /**
   * Indicates how many blocks have failed irrecoverably, meaning retries are exhausted or a
   * permanent error occurred. The metric is derived from the last received progress message and is
   * therefore advisory rather than transactional. Operators can watch this number to decide whether
   * to abandon a request early when the count grows too fast.
   *
   * @return fatal failure count or {@code -1} when no progress snapshot exists
   */
  @Override
  public synchronized double getFatalyFailedBlocks() {
    if (progressMessage != null) {
      if (progressMessage instanceof SimpleProgressMessage message)
        return message.getFatalyFailedBlocks();
      else return 0;
    } else return -1;
  }

  /**
   * Returns the number of blocks that have been fetched (or inserted) successfully according to the
   * latest progress report. The value is monotonically non-decreasing for a given snapshot and
   * gives clients a sense of throughput over time. A return value of {@code -1} mirrors the “no
   * progress yet” condition used by the other metrics.
   *
   * @return fetched-block count or {@code -1} when the job has not reported progress
   */
  @Override
  public synchronized double getFetchedBlocks() {
    if (progressMessage != null) {
      if (progressMessage instanceof SimpleProgressMessage message)
        return message.getFetchedBlocks();
      else return 0;
    } else return -1;
  }

  /**
   * Reports whether the total block count has finalized, meaning the inserter no longer anticipates
   * discovering additional segments. UI code can use this to decide when to display absolute
   * percentages rather than “at least” semantics.
   *
   * @return {@code true} when the latest progress snapshot marked totals final, otherwise false
   */
  @Override
  public synchronized boolean isTotalFinalized() {
    if (progressMessage instanceof SimpleProgressMessage message) {
      return message.isTotalFinalized();
    }
    return false;
  }

  /**
   * Returns a human-readable description of the failure recorded in {@link #putFailedMessage},
   * optionally including the extended description. The method is synchronized to ensure the message
   * is not cleared mid-read when a persistent request resets itself, making it safe for repeated
   * polling by management tools.
   *
   * @param longDescription {@code true} to append the verbose description when present
   * @return textual description or {@code null} when the job has not failed
   */
  @Override
  public synchronized String getFailureReason(boolean longDescription) {
    if (putFailedMessage == null) return null;
    String s = putFailedMessage.shortCodeDescription;
    if (longDescription && putFailedMessage.extraDescription != null)
      s += ": " + putFailedMessage.extraDescription;
    return s;
  }

  /**
   * Exposes the entire {@link PutFailedMessage} object so that higher-level components can
   * serialize or inspect the fine-grained failure codes before freeing state. Callers must not
   * mutate the returned object and should treat {@code null} as meaning “no failure recorded”. The
   * reference remains valid until {@link #setVarsRestart()} runs.
   *
   * @return failure message object or {@code null} if the insert never failed
   */
  public PutFailedMessage getFailureMessage() {
    if (putFailedMessage == null) return null;
    return putFailedMessage;
  }

  /** {@inheritDoc} */
  @Override
  public boolean equals(Object obj) {
    return super.equals(obj);
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    return super.hashCode();
  }

  /**
   * Resets volatile fields so that a persistent request can be restarted cleanly without reusing
   * stale progress, failure state, or bookkeeping flags. This method does not alter persisted
   * metadata or tokens and is safe to call multiple times. Callers typically invoke it immediately
   * before enqueuing a restarted request to guarantee that subsequent callbacks behave as if the
   * job were freshly created.
   */
  public synchronized void setVarsRestart() {
    finished = false;
    this.putFailedMessage = null;
    this.progressMessage = null;
    started = false;
  }

  /**
   * Serializes persistent fields using default Java serialization so client detail blobs remain
   * compatible with historical versions.
   *
   * @param out destination stream supplied by the persistence layer; never {@code null}
   * @throws IOException when the underlying stream rejects the writing
   */
  @Serial
  private void writeObject(ObjectOutputStream out) throws IOException {
    out.defaultWriteObject();
  }

  /**
   * Restores persistent fields during deserialization. Subclasses are expected to rebuild transient
   * collaborators during {@link #innerResume(ClientContext)} rather than in this hook.
   *
   * @param in source stream containing a previously serialized form of the object
   * @throws IOException when reading fails
   * @throws ClassNotFoundException when serialized field types cannot be resolved
   */
  @Serial
  private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.defaultReadObject();
  }

  private static void warnIfUnsupportedCharset(String charset) {
    if (charset == null || charset.isBlank()) {
      return;
    }
    try {
      if (!Charset.isSupported(charset)) {
        LOG.warn("Unsupported charset '{}' requested for ClientPutBase", charset);
      }
    } catch (IllegalCharsetNameException e) {
      LOG.warn("Illegal charset '{}' requested for ClientPutBase", charset);
    }
  }
}
