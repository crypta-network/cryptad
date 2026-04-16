package network.crypta.clients.fcp;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamField;
import java.io.Serial;
import java.net.MalformedURLException;
import java.nio.charset.Charset;
import java.nio.charset.IllegalCharsetNameException;
import java.util.HashMap;
import java.util.Map;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.InsertException;
import network.crypta.client.async.persistence.PersistentRequestRuntimeContext;
import network.crypta.client.events.ClientEvent;
import network.crypta.client.events.ClientEventDispatchContext;
import network.crypta.client.events.ClientEventListener;
import network.crypta.client.events.ExpectedHashesEvent;
import network.crypta.client.events.FinishedCompressionEvent;
import network.crypta.client.events.SplitfileProgressEvent;
import network.crypta.client.events.StartedCompressionEvent;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Coordinates the lifecycle of FCP insert requests that persist across reconnections and restarts.
 *
 * <p>The class centralizes common state tracking for {@link ClientPut} and {@link ClientPutDir},
 * wiring FCP-facing identifiers, scheduling metadata, persistence constraints, and node callbacks
 * into a single state machine. Instances travel through connection-bound and forever-persistent
 * modes, reattaching to runtime contexts after deserialization, driving insert progress, and
 * translating internal events into client-visible FCP messages. It is designed to be thread-aware:
 * mutations happen under synchronization, while outbound messages are dispatched via handler
 * abstractions to avoid deadlocks.
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
    implements FcpInsertCallback, ClientEventListener {
  private static final Logger LOG = LoggerFactory.getLogger(ClientPutBase.class);
  private static final String LEGACY_INSERT_CONTEXT_TYPE = "network.crypta.client.InsertContext";
  private static final String FIELD_SUCCEEDED = "succeeded";
  private static final String FIELD_CTX = "ctx";
  private static final String FIELD_GENERATED_METADATA = "generatedMetadata";
  private static final String FIELD_GENERATED_URI = "generatedURI";
  private static final String FIELD_PUT_FAILED_MESSAGE = "putFailedMessage";
  private static final String FIELD_PUBLIC_URI = "publicURI";

  @Serial private static final long serialVersionUID = 1L;

  @SuppressWarnings("UnusedVariable")
  @Serial
  private static final ObjectStreamField[] serialPersistentFields =
      new ObjectStreamField[] {
        new ObjectStreamField(FIELD_SUCCEEDED, boolean.class),
        new ObjectStreamField(FIELD_CTX, requiredLegacyInsertContextClass()),
        new ObjectStreamField(FIELD_GENERATED_METADATA, Bucket.class),
        new ObjectStreamField(FIELD_GENERATED_URI, FreenetURI.class),
        new ObjectStreamField(FIELD_PUT_FAILED_MESSAGE, PutFailedMessage.class),
        new ObjectStreamField(FIELD_PUBLIC_URI, FreenetURI.class)
      };

  /**
   * Per-request detached insert-context handle seeded from the node defaults. It carries retry
   * rules, redundancy knobs, and compatibility flags and therefore must be explicitly cleaned up in
   * {@link #requestWasRemoved(PersistentRequestRuntimeContext)} to avoid leaking stale listeners.
   */
  FcpInsertContextHandle ctx;

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
   * #onGeneratedURI(FreenetURI, FcpInsertCallbackState)} runs, after which it never changes.
   * Subclasses and clients should treat it as immutable and safe for reuse across threads.
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
  protected FreenetURI publicURI;

  /** Metadata returned instead of URI */
  private Bucket generatedMetadata;

  /**
   * The name of the FCP field carrying the SHA-256 hash of source data when clients request that
   * value instead of a final URI.
   */
  public static final String FILE_HASH = "FileHash";

  // Legacy threshold callback removed.

  private static final Map<Integer, UploadFrom> uploadFromByCode = new HashMap<>();

  /**
   * Lists where the bytes for a put operation originate, which drives validation and bucket
   * ownership rules during persistence and resume scenarios. The value is serialized with
   * persistent requests, so future versions can continue applying consistent invariants.
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
     * insert-time validation is minimal, and no bucket ownership is required.
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
     * and stubs after a restart. The helper keeps a static map, so the conversion is O(1) even when
     * invoked frequently. Callers typically load the integer from the disk and feed it here before
     * reconstructing the bucket ownership policy.
     *
     * @param x integer code stored with persistent state or received via FCP, expected to be one of
     *     the constants defined in this enum
     * @return matching enum instance; never {@code null} for valid codes because results are cached
     * @throws IllegalArgumentException when the caller supplies an unknown code, signaling corrupt
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
   * state, derives a baseline-detached insert-context handle, subscribes to progress events, and
   * records every tunable requested by the remote peer. Subclasses can immediately begin staging
   * data once control returns because scheduling metadata, verbosity flags, and caches have all
   * been populated consistently.
   *
   * @param requestParams request metadata including URI, identifiers, and scheduling flags
   * @param charset optional declared source charset; unsupported values trigger warnings only
   * @param options insert tuning options covering retries, compression, and caching behavior
   * @param handler owning connection handler responsible for queuing outbound replies
   * @param runtimeSupport insert runtime support providing contexts and bucket factories
   * @param publicURI precomputed request URI corresponding to {@code requestParams.uri()}
   */
  ClientPutBase(
      ClientRequestParams requestParams,
      String charset,
      FcpInsertOptions options,
      FCPConnectionHandler handler,
      FcpInsertRuntimeSupport runtimeSupport,
      FreenetURI publicURI) {
    this(
        new ClientPutConstructorSupport.BaseInit(
            requestParams, charset, options, handler, null, runtimeSupport, publicURI));
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
   * @param runtimeSupport insert runtime support that owns placeholder-SSK normalization
   * @return original URI when already complete or a freshly derived insert URI with the filename
   *     applied; the result is never {@code null}
   */
  static FreenetURI checkEmptySSK(
      FreenetURI uri, String filename, FcpInsertRuntimeSupport runtimeSupport) {
    return runtimeSupport.normalizeInsertUri(uri, filename);
  }

  /**
   * Reconstructs a persistent insert owned by a {@link PersistentRequestClient} when resuming from
   * disk or migrating between schedulers.
   *
   * <p>The constructor receives a fully resolved persistent client handle and reuses the
   * persistence-aware detached insert-context handle provided by the insert runtime support seam.
   * It mirrors the connection-bound constructor but skips server-specific bookkeeping, allowing
   * REST API callers or resuming jobs to bypass socket handlers entirely while preserving the same
   * configuration surface.
   *
   * @param requestParams request metadata including URI, identifiers, and scheduling flags
   * @param charset optional charset hint that influences metadata generation when meaningful
   * @param options insert tuning options that should persist across restarts
   * @param handler connection handler for immediate responses during the resume handshake
   * @param client persistent request owner used to enqueue outbound messages after resumption
   * @param runtimeSupport insert runtime support used to get shared factories and contexts for
   *     resumed jobs
   * @param publicURI precomputed request URI corresponding to {@code requestParams.uri()}
   */
  ClientPutBase(
      ClientRequestParams requestParams,
      String charset,
      FcpInsertOptions options,
      FCPConnectionHandler handler,
      PersistentRequestClient client,
      FcpInsertRuntimeSupport runtimeSupport,
      FreenetURI publicURI) {
    this(
        new ClientPutConstructorSupport.BaseInit(
            requestParams, charset, options, handler, client, runtimeSupport, publicURI));
  }

  ClientPutBase(ClientPutConstructorSupport.BaseInit init) {
    super(
        init.persistentClient() == null
            ? prepareConstructorInit(init.requestParams(), init.handler())
            : prepareConstructorInit(
                init.requestParams(), init.handler(), init.persistentClient()));
    warnIfUnsupportedCharset(init.charset());
    FcpInsertOptions options = init.options();
    ctx = init.runtimeSupport().defaultPersistentInsertContextHandle();
    ctx.setGetCHKOnly(options.getCHKOnly());
    ctx.setDontCompress(options.dontCompress());
    ctx.addEventListener(this);
    ctx.setMaxInsertRetries(options.maxRetries());
    ctx.setCanWriteClientCache(options.canWriteClientCache());
    ctx.setCompressorDescriptor(options.compressorDescriptor());
    ctx.setForkOnCacheable(options.forkOnCacheable());
    ctx.setExtraInsertsSingleBlock(options.extraInsertsSingleBlock());
    ctx.setExtraInsertsSplitfileHeaderBlock(options.extraInsertsSplitfileHeaderBlock());
    ctx.setLocalRequestOnly(options.localRequestOnly());
    ctx.setCompatibilityMode(options.compatibilityMode());
    ctx.setIgnoreUSKDatehints(options.ignoreUSKDatehints());
    ctx.setEarlyEncode(options.earlyEncode());
    this.publicURI = init.publicUri();
  }

  /**
   * Derives the fetchable request URI corresponding to an insert URI.
   *
   * @param insertUri normalized insert URI
   * @return request URI used for status reporting and completion messages
   * @throws MalformedURLException if the insert URI cannot be converted
   */
  protected static FreenetURI derivePublicURI(FreenetURI insertUri) throws MalformedURLException {
    return insertUri.deriveRequestURIFromInsertURI();
  }

  /**
   * Reacts to the owning socket disconnecting by cancelling connection-scoped requests while
   * leaving persistent ones untouched so they can resume later without extra chatter.
   *
   * <p>The method keeps side effects intentionally small. It does not throw nor block; instead it
   * simply triggers {@link #cancel(PersistentRequestRuntimeContext)} for requests that were
   * declared {@link Persistence#CONNECTION}. Persistent and forever requests ignore the event
   * because they expect to be resumed through their detached requester handle after
   * deserialization.
   *
   * @param context detached runtime context that supplies cancellation helpers and resource pools;
   *     the value may be reused across many requests and must not be {@code null}
   */
  @Override
  public void onLostConnection(
      network.crypta.client.async.persistence.PersistentRequestRuntimeContext context) {
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
  @Override
  public void onSuccess(FcpInsertCallbackState state) {
    FreenetURI resolvedGeneratedUri = generatedUriOrFallback(state);
    synchronized (this) {
      // Including these helps with certain bugs...
      started = true; // Keep the started flag set for resume compatibility.
      succeeded = true;
      finished = true;
      completionTime = System.currentTimeMillis();
      if (resolvedGeneratedUri == null)
        LOG.error("No generated URI in onSuccess() for {} from {}", this, state);
    }
    if (persistence == Persistence.CONNECTION) {
      freeData();
    }
    finish();
    trySendFinalMessage(null, null);
    if (client != null) client.notifySuccess(this);
  }

  private FreenetURI generatedUriOrFallback(FcpInsertCallbackState state) {
    synchronized (this) {
      if (generatedURI != null) {
        return generatedURI;
      }
    }
    FreenetURI fallbackUri = state != null ? state.getURI() : null;
    if (fallbackUri == null) {
      return null;
    }
    synchronized (this) {
      if (generatedURI == null) {
        generatedURI = fallbackUri;
      }
      return generatedURI;
    }
  }

  /**
   * Records a fatal insert failure, captures the {@link InsertException}, and notifies clients
   * through a {@code PutFailed} message.
   *
   * <p>The method treats the first invocation as authoritative and ignores later calls once {@link
   * #finished} becomes {@code true}. Connection-scoped requests relinquish buffered data,
   * persistent requests keep the failure payload so that reconnecting clients can inspect detailed
   * codes, and registered {@link PersistentRequestClient}s are notified immediately.
   *
   * @param e exception describing why the insert failed, including retry history and codes
   * @param state inserter that triggered the failure; used only for logging context
   */
  @Override
  public void onFailure(InsertException e, FcpInsertCallbackState state) {
    if (finished) return;
    synchronized (this) {
      started = true; // Keep the started flag set for resume compatibility.
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
  public void onGeneratedURI(FreenetURI uri, FcpInsertCallbackState state) {
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
   * FcpInsertCallbackState)} has run. Callers should treat the value as immutable and thread-safe
   * because access is synchronized, and they should avoid caching {@code null} results since future
   * calls may return a valid URI after the inserter finishes. The method never throws and therefore
   * fits polling loops or status pages.
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
   * <p>Only the first metadata bucket is retained, so disconnecting clients cannot accidentally
   * leak resources. Duplicate deliveries are logged and freed immediately. Non-duplicate metadata
   * is queued for FCP delivery and persisted if the request survives restarts.
   *
   * @param metadata metadata bucket; ownership transfers to this method on success
   * @param state inserter reporting metadata generation; used for logging context only
   */
  @Override
  public void onGeneratedMetadata(Bucket metadata, FcpInsertCallbackState state) {
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
   * @param context detached runtime context through which cleanup helpers and factories can be
   *     reached
   */
  @Override
  public void requestWasRemoved(
      network.crypta.client.async.persistence.PersistentRequestRuntimeContext context) {
    if (ctx != null) {
      ctx.removeEventListener(this);
    }
    // if the request is still running, send a PutFailed with code=canceled
    if (!finished) {
      synchronized (this) {
        finished = true;
        InsertException cancelled = new InsertException(InsertExceptionMode.CANCELLED);
        putFailedMessage = new PutFailedMessage(cancelled, identifier, global);
      }
      trySendFinalMessage(null, null);
    }
    // notify client that the request was removed
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
   * Consumes asynchronous events emitted by the live insert runtime and converts them into a stable
   * stream of FCP messages according to the active verbosity mask.
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
  public void receive(final ClientEvent ce, ClientEventDispatchContext context) {
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
   * Invoked whenever the inserter finishes a compression phase, so subclasses can flush UI state,
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
   * @param state minimal bridge-owned state view announcing fetchability; it is not dereferenced
   *     here but kept for API symmetry with the callback interface
   */
  @Override
  public void onFetchable(FcpInsertCallbackState state) {
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
   * which request the later payload refers to.
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
   * Returns the minimum number of fetched blocks needed to reconstruct the payload, according to
   * the most recent progress update. This helps UI code communicate resilience to failures because
   * it represents the erasure-coded threshold that must be met. A return value of {@code -1} means
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
   * Returns the number of blocks that have been fetched (or inserted) successfully, according to
   * the latest progress report. The value is monotonically non-decreasing for a given snapshot and
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

  final synchronized FCPMessage getProgressMessageSnapshot() {
    return progressMessage;
  }

  /**
   * Exposes the entire {@link PutFailedMessage} object so that higher-level components can
   * serialize or inspect the fine-grained failure codes before freeing state. Callers must not
   * mutate the returned object and should treat {@code null} as meaning “no failure recorded”. The
   * reference remains valid until {@link #setVarsRestart()} runs.
   *
   * @return failure message object or {@code null} if the insert never failed
   */
  public synchronized PutFailedMessage getFailureMessage() {
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
   * before enqueuing a restarted request to guarantee that later callbacks behave as if the job
   * were freshly created.
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
    ObjectOutputStream.PutField fields = out.putFields();
    fields.put(FIELD_SUCCEEDED, succeeded);
    fields.put(FIELD_CTX, legacyInsertContextForSerialization());
    fields.put(FIELD_GENERATED_METADATA, generatedMetadata);
    fields.put(FIELD_GENERATED_URI, generatedURI);
    fields.put(FIELD_PUT_FAILED_MESSAGE, putFailedMessage);
    fields.put(FIELD_PUBLIC_URI, publicURI);
    out.writeFields();
  }

  /**
   * Restores persistent fields during deserialization. Subclasses are expected to rebuild transient
   * collaborators during {@link #innerResume(FcpRequestRuntimeContext)} rather than in this hook.
   *
   * @param in source stream containing a previously serialized form of the object
   * @throws IOException when reading fails
   * @throws ClassNotFoundException when serialized field types cannot be resolved
   */
  @Serial
  private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    ObjectInputStream.GetField fields = in.readFields();
    succeeded = fields.get(FIELD_SUCCEEDED, false);
    ctx =
        LegacyInsertExecutionBridgeLoader.load()
            .wrapLegacyInsertContext(fields.get(FIELD_CTX, null));
    generatedMetadata = (Bucket) fields.get(FIELD_GENERATED_METADATA, null);
    generatedURI = (FreenetURI) fields.get(FIELD_GENERATED_URI, null);
    putFailedMessage = (PutFailedMessage) fields.get(FIELD_PUT_FAILED_MESSAGE, null);
    publicURI = (FreenetURI) fields.get(FIELD_PUBLIC_URI, null);
  }

  private static Class<?> requiredLegacyInsertContextClass() {
    try {
      return Class.forName(LEGACY_INSERT_CONTEXT_TYPE);
    } catch (ClassNotFoundException e) {
      throw new ExceptionInInitializerError(e);
    }
  }

  private Object legacyInsertContextForSerialization() throws IOException {
    return LegacyInsertExecutionBridgeLoader.load().legacyInsertContextForSerialization(ctx);
  }

  private static void warnIfUnsupportedCharset(String charset) {
    if (charset == null || charset.isBlank()) {
      return;
    }
    try {
      if (!Charset.isSupported(charset)) {
        LOG.warn("Unsupported charset '{}' requested for ClientPutBase", charset);
      }
    } catch (IllegalCharsetNameException _) {
      LOG.warn("Illegal charset '{}' requested for ClientPutBase", charset);
    }
  }
}
