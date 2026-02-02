package network.crypta.clients.fcp;

import java.io.File;
import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serial;
import java.io.Serializable;
import network.crypta.client.ClientMetadata;
import network.crypta.client.InsertException;
import network.crypta.client.MetadataUnresolvedException;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientPutter;
import network.crypta.client.async.ClientPutterOptions;
import network.crypta.client.async.ClientPutterRequest;
import network.crypta.client.async.ClientRequester;
import network.crypta.client.async.InsertRequestParams;
import network.crypta.clients.fcp.RequestIdentifier.RequestType;
import network.crypta.keys.FreenetURI;
import network.crypta.node.NodeClientCore;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.ResumeFailedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Drives a single insert issued through the FCP interface, coordinating validation and scheduling
 * for a single payload or redirect.
 *
 * <p>The class mediates between user requests and the asynchronous node core: it validates disk
 * access, synthesizes redirect metadata, resolves MIME metadata, and constructs the underlying
 * {@link ClientPutter}. Instances encapsulate all mutable states needed to monitor progress,
 * respond to retries, and surface status updates across reconnections. Persistent requests are
 * serialized so the node can resume in-flight inserts after restart without reloading the client’s
 * original configuration.
 *
 * <p>Thread-safety follows the contract of {@link ClientPutBase}. Most state is mutated by worker
 * threads, while a handful of accessors synchronize on {@code this} to guard shared progress flags
 * used by UIs and status caches. Callers should treat the request as owning its buckets once
 * construction finishes and avoid mutating those buckets directly.
 *
 * <ul>
 *   <li>Prepares uploads originating from disk, memory buckets, or redirect metadata.
 *   <li>Captures per-request metadata so status polling exposes MIME type and filenames.
 *   <li>Publishes persistent tag messages whenever queue bookkeeping updates are required.
 * </ul>
 *
 * @see ClientPutBase
 * @see ClientRequester
 */
public class ClientPut extends ClientPutBase {
  /** Logger for lifecycle and diagnostic messages. */
  private static final Logger LOG = LoggerFactory.getLogger(ClientPut.class);

  /** Debugging template for persistent uploads to log bucket identity and source. */
  private static final String PERSISTENT_UPLOAD_LOG_TEMPLATE =
      "Prepared persistent upload data: data = {}, uploadFrom = {}";

  /** Debugging template for message-based uploads to log bucket identity and source. */
  private static final String MESSAGE_UPLOAD_LOG_TEMPLATE =
      "Prepared message upload data: data = {}, uploadFrom = {}";

  /** Serialization version for persistent request snapshots. */
  @Serial private static final long serialVersionUID = 1L;

  /**
   * Active {@link ClientPutter} driving the insert; nulled only after FOREVER persistence removal.
   */
  ClientPutter putter;

  /** Describes how payload bytes are obtained (direct, disk, redirect, or in-memory). */
  private final UploadFrom uploadFrom;

  /** Original filename if from disk, otherwise null. Purely for PersistentPut. */
  private final File origFilename;

  /** If uploadFrom==UPLOAD_FROM_REDIRECT, this is the target of the redirect */
  private final FreenetURI targetURI;

  /** Bucket storing user data or generated redirect metadata for the pending insert. */
  private RandomAccessBucket data;

  /** MIME and ancillary metadata persisted for status reporting and manifest/CHK generation. */
  private final ClientMetadata clientMetadata;

  /** We store the size of inserted data before freeing it */
  private long finishedSize;

  /** Filename if the file has one */
  private final String targetFilename;

  /** If true, we are inserting a binary blob: No metadata, no URI is generated. */
  private final boolean binaryBlob;

  /** Indicates whether compression is currently scheduled since the last restart. */
  private transient boolean compressing;

  /** Records if compression finished once so we do not resignal redundant progress. */
  private boolean compressed;

  // Legacy threshold callback removed.

  /**
   * Creates a persistent insert originating from a long-lived client or FProxy.
   *
   * <p>The constructor enforces disk-access policy, builds redirect metadata when needed, captures
   * MIME hints, and sets up {@link ClientPutter} with the retry and redundancy settings supplied by
   * the caller. It is intended for uploads that must survive restarts, so the node takes ownership
   * of persistence and retry state while the caller keeps the backing bucket readable for the
   * request’s lifetime. Compression settings are honored exactly as supplied, allowing clients to
   * trade throughput for deterministic behavior.
   *
   * @param request persistent request metadata including URI, identifier, and queue settings; must
   *     not be {@code null} and should reflect the intended persistence scope.
   * @param options insert tuning options such as retries, compression, and redundancy; must not be
   *     {@code null} and should be consistent with the request type.
   * @param upload upload payload metadata describing source and content hints; must not be {@code
   *     null} and should include a readable bucket if required.
   * @param core owning {@link NodeClientCore} providing policies, factories, and scheduler hooks;
   *     must not be {@code null}.
   * @throws IdentifierCollisionException when the chosen identifier already exists in persistence.
   * @throws NotAllowedException when the configured upload source violates server-side policy.
   * @throws MetadataUnresolvedException when redirect metadata cannot serialize into a bucket.
   * @throws IOException when filesystem or bucket reads fail during preparation.
   */
  public ClientPut(
      FcpInsertRequest request,
      FcpInsertOptions options,
      ClientPutUpload upload,
      NodeClientCore core)
      throws IdentifierCollisionException,
          NotAllowedException,
          MetadataUnresolvedException,
          IOException {
    ClientRequestParams requestParams =
        new ClientRequestParams(
            checkEmptySSK(request.uri(), upload.targetFilename(), core.getClientContext()),
            ensurePersistentIdentifierAvailable(request.client(), request.identifier()),
            request.verbosity(),
            request.priorityClass(),
            request.persistence(),
            options.realTimeFlag(),
            null,
            request.global());
    super(requestParams, request.charset(), options, null, request.client(), core);
    UploadFrom uploadFromType = upload.uploadFromType();
    File uploadOrigFilename = upload.origFilename();
    String contentType = upload.contentType();
    String uploadTargetFilename = upload.targetFilename();
    RandomAccessBucket tempData = upload.data();

    if (uploadFromType == UploadFrom.DISK) {
      ClientPutDiskUploadValidator.validatePersistentDiskUpload(core, uploadOrigFilename);
    }

    this.binaryBlob = upload.binaryBlob();
    if (this.binaryBlob) contentType = null;
    this.targetFilename = uploadTargetFilename;
    this.uploadFrom = uploadFromType;
    this.origFilename = uploadOrigFilename;
    // Now go through the fields one at a time
    String mimeType = contentType;
    this.clientToken = request.clientToken();
    ClientMetadata cm = new ClientMetadata(mimeType);
    if (LOG.isDebugEnabled()) LOG.debug(PERSISTENT_UPLOAD_LOG_TEMPLATE, tempData, uploadFrom);
    PreparedData preparedData =
        ClientPutPreparedDataFactory.prepareForPersistentUpload(
            uploadFrom, cm, tempData, upload.redirectTarget(), core, isPersistentForever());
    this.data = preparedData.bucket();
    this.clientMetadata = cm;
    this.targetURI = preparedData.targetUri();

    ClientPutterRequest putterRequest =
        new ClientPutterRequest(
            new InsertRequestParams(this, this.uri, ctx, priorityClass),
            data,
            cm,
            preparedData.isMetadata());
    ClientPutterOptions putterOptions =
        new ClientPutterOptions(
            this.uri.getDocName() == null ? uploadTargetFilename : null,
            this.binaryBlob,
            options.overrideSplitfileCryptoKey(),
            -1);
    putter = ClientPutPutterFactory.create(putterRequest, putterOptions);
  }

  /**
   * Reconstructs an insert from a live FCP connection by interpreting a {@link ClientPutMessage}.
   *
   * <p>This constructor is used for transient or connection-scoped inserts issued over the socket
   * protocol. It verifies disk upload permissions, optional salted hashes, and MIME hints supplied
   * by the client before crafting in-memory buckets or redirecting metadata. Because the handler
   * may multiplex many inserts, identifier validation is performed against the connection’s map to
   * avoid collisions that would otherwise corrupt status routing. All costly bucket conversions
   * happen before {@link ClientPutter} starts so any validation errors surface immediately to the
   * client.
   *
   * @param handler live FCP connection handler coordinating per-connection identifiers and DDA
   *     rights; must not be {@code null} and should represent the active socket.
   * @param message parsed {@link ClientPutMessage} containing payload descriptors and metadata;
   *     must not be {@code null} and should already have validated field syntax.
   * @param server owning server providing {@link NodeClientCore} accessors and capability checks;
   *     must not be {@code null}.
   * @throws IdentifierCollisionException if another request on the connection already uses the
   *     identifier.
   * @throws MessageInvalidException when client supplied fields (hashes, MIME, permissions) are
   *     invalid or violate protocol constraints.
   * @throws IOException when message-provided buckets cannot be read to compute salted hashes.
   */
  public ClientPut(FCPConnectionHandler handler, ClientPutMessage message, FCPServer server)
      throws IdentifierCollisionException, MessageInvalidException, IOException {
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
            checkEmptySSK(message.uri, message.targetFilename, server.getCore().getClientContext()),
            ensureConnectionIdentifierAvailable(handler, message),
            message.verbosity,
            message.priorityClass,
            message.persistence,
            options.realTimeFlag(),
            message.clientToken,
            message.global);
    super(requestParams, null, options, handler, server);
    binaryBlob = message.binaryBlob;

    DiskUploadContext diskContext =
        ClientPutDiskUploadValidator.validateDiskUpload(
            handler, message, message.identifier, message.global);

    this.targetFilename = message.targetFilename;
    this.uploadFrom = message.uploadFromType;
    this.origFilename = message.origFilename;

    String mimeType =
        ClientPutMimeResolver.resolve(
            message,
            this.origFilename,
            this.targetFilename,
            binaryBlob,
            message.identifier,
            message.global);

    clientToken = message.clientToken;
    ClientMetadata cm = new ClientMetadata(mimeType);
    PreparedData preparedData =
        ClientPutPreparedDataFactory.prepareForMessage(
            message, cm, server, isPersistentForever(), uploadFrom, identifier, global);
    this.data = preparedData.bucket();
    this.clientMetadata = cm;
    this.targetURI = preparedData.targetUri();

    ClientPutDiskUploadValidator.verifySaltedHash(diskContext, data, identifier, global);

    if (LOG.isDebugEnabled()) LOG.debug(MESSAGE_UPLOAD_LOG_TEMPLATE, data, uploadFrom);
    ClientPutterRequest putterRequest =
        new ClientPutterRequest(
            new InsertRequestParams(this, this.uri, ctx, priorityClass),
            data,
            cm,
            preparedData.isMetadata());
    ClientPutterOptions putterOptions =
        new ClientPutterOptions(
            this.uri.getDocName() == null ? targetFilename : null,
            binaryBlob,
            message.overrideSplitfileCryptoKey,
            message.metadataThreshold);
    putter = ClientPutPutterFactory.create(putterRequest, putterOptions);
  }

  /**
   * Ensures the request identifier is unused within a connection-scoped persistence map.
   *
   * @param handler connection handler tracking in-flight requests; must not be {@code null}.
   * @param message parsed put message containing the requested identifier; must not be {@code
   *     null}.
   * @return the validated identifier string when no collision exists.
   * @throws IdentifierCollisionException when the identifier already exists for the connection.
   */
  private static String ensureConnectionIdentifierAvailable(
      FCPConnectionHandler handler, ClientPutMessage message) throws IdentifierCollisionException {
    if (message.persistence != Persistence.CONNECTION) {
      return message.identifier;
    }
    if (handler.requestsByIdentifier.containsKey(message.identifier)) {
      throw new IdentifierCollisionException();
    }
    return message.identifier;
  }

  /**
   * Ensures the identifier is free within the persistent request client, if present.
   *
   * @param client persistent request client, or {@code null} when not applicable.
   * @param identifier identifier requested by the caller; must not be {@code null}.
   * @return the identifier when it is not already in use.
   * @throws IdentifierCollisionException when the identifier already exists in persistence.
   */
  private static String ensurePersistentIdentifierAvailable(
      PersistentRequestClient client, String identifier) throws IdentifierCollisionException {
    if (client != null && client.getRequest(identifier) != null) {
      throw new IdentifierCollisionException();
    }
    return identifier;
  }

  /**
   * Returns whether the request is already marked finished.
   *
   * @return {@code true} when the request has completed or failed.
   */
  private synchronized boolean isFinishedRequest() {
    return finished;
  }

  /**
   * Determines whether a persistent tag message should be queued now.
   *
   * @return {@code true} when persistence is enabled and the request is not finished.
   */
  private synchronized boolean shouldQueuePersistentTag() {
    return persistence != Persistence.CONNECTION && !finished;
  }

  /**
   * Serialization-only constructor used when restoring persisted requests via Java serialization.
   *
   * <p>No operational fields are initialized here because {@link ObjectInputStream} populates them
   * immediately afterward. The placeholder values merely satisfy the JVM’s requirement for an
   * accessible no-arg constructor so saved queue snapshots can be deserialized before relinking to
   * live {@link ClientPutter} instances.
   */
  protected ClientPut() {
    // For serialization.
    uploadFrom = null;
    origFilename = null;
    targetURI = null;
    clientMetadata = null;
    finishedSize = 0;
    targetFilename = null;
    binaryBlob = false;
  }

  /**
   * Custom serialization hook ensuring {@link RandomAccessBucket} implementations are serializable
   * before persisting the request.
   *
   * @param out Destination stream managed by Java serialization infrastructure.
   * @throws IOException If field serialization fails or the provided stream signals an error.
   */
  @Serial
  private void writeObject(ObjectOutputStream out) throws IOException {
    if (data != null && !(data instanceof Serializable)) {
      throw new NotSerializableException(data.getClass().getName());
    }
    out.defaultWriteObject();
  }

  /**
   * Completes custom deserialization by delegating to default field restoration after validation.
   *
   * @param in Source stream managed by Java serialization infrastructure.
   * @throws IOException If the serialized form is truncated or unreadable.
   * @throws ClassNotFoundException If referenced, classes in the stream cannot be resolved.
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

  /**
   * Starts the underlying {@link ClientPutter}, queuing compression and insert work for this
   * request.
   *
   * <p>The method is idempotent: if the request already finished or the putter previously started,
   * it refreshes the persistent tag and returns. Otherwise, it schedules the insert, updates
   * bookkeeping, and emits persistent-queue tags so external monitors observe the in-flight status.
   * Callers should invoke this once after construction or resume to reattach the UI state. Any
   * startup failures are routed through the standard failure handler so retry logic stays
   * consistent.
   *
   * @param context client execution context providing schedulers, bucket factories, and thread
   *     pools; must not be {@code null} and should be the active runtime context.
   */
  @Override
  public void start(ClientContext context) {
    if (LOG.isDebugEnabled()) LOG.debug("Starting {} : {}", this, identifier);
    if (isFinishedRequest()) {
      return;
    }
    try {
      putter.start(false, context);
      if (shouldQueuePersistentTag()) {
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
    } catch (InsertException e) {
      synchronized (this) {
        started = true;
      }
      onFailure(e, null);
    } catch (Exception t) {
      synchronized (this) {
        started = true;
      }
      onFailure(
          new InsertException(InsertException.InsertExceptionMode.INTERNAL_ERROR, t, null), null);
    }
  }

  @Override
  protected void freeData() {
    RandomAccessBucket d;
    synchronized (this) {
      d = data;
      data = null;
      if (d == null) return;
      finishedSize = d.size();
    }
    d.free();
  }

  @Override
  protected ClientRequester getClientRequest() {
    return putter;
  }

  @Override
  protected FCPMessage persistentTagMessage() {
    if (putter == null) LOG.warn("putter == null");
    ClientRequestParams requestParams =
        new ClientRequestParams(
            publicURI,
            identifier,
            verbosity,
            priorityClass,
            persistence,
            isRealTime(),
            clientToken,
            client.isGlobalQueue);
    PersistentPutRequestMetadata metadata =
        new PersistentPutRequestMetadata(
            uri,
            started,
            ctx.getMaxInsertRetries(),
            this.ctx.getCompatibilityMode(),
            this.ctx.isDontCompress(),
            this.ctx.getCompressorDescriptor(),
            putter != null ? putter.getSplitfileCryptoKey() : null);
    ClientPutUpload upload =
        new ClientPutUpload(
            uploadFrom,
            origFilename,
            clientMetadata.getMIMEType(),
            null,
            targetURI,
            targetFilename,
            binaryBlob);
    return new PersistentPut(requestParams, upload, metadata, getDataSize());
  }

  /**
   * Returns whether the low-level request is scheduled as real-time work.
   *
   * @return {@code true} when the underlying request uses the real-time flag.
   */
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
   * Reports whether the put operation permanently succeeded, meaning the final URI is committed.
   *
   * <p>The flag flips to {@code true} only after {@link ClientPutter} notifies completion and
   * remains {@code true} even if future retries occur, allowing UIs to treat the request as
   * immutable history. It is safe to poll frequently because the underlying field is synchronized
   * via {@link ClientPutBase} access patterns.
   *
   * @return {@code true} once the insert commits and the node has acknowledged durable storage.
   */
  @Override
  public boolean hasSucceeded() {
    return succeeded;
  }

  /**
   * Returns the final {@link FreenetURI} assigned to the uploaded data once it becomes available.
   *
   * <p>The URI is generated lazily after encoding finishes, so callers should expect {@code null}
   * until the insert either succeeds or yields enough information (such as a CHK) to finalize the
   * address. Consumers typically surface this value in status tables or completion callbacks and
   * should treat it as immutable once set.
   *
   * @return finalized URI when known, or {@code null} until the node produces one.
   */
  public FreenetURI getFinalURI() {
    return generatedURI;
  }

  /**
   * Indicates whether the payload bytes were supplied inline via the FCP connection.
   *
   * <p>This mirrors the original {@link UploadFrom} choice. Direct uploads are useful for clients
   * that already hold data in memory and do not require DDA permissions. Disk-based inserts return
   * {@code false} so the UI can display security-sensitive origin information.
   *
   * @return {@code true} if {@link UploadFrom#DIRECT} initiated the request; {@code false}
   *     otherwise.
   */
  public boolean isDirect() {
    return uploadFrom == UploadFrom.DIRECT;
  }

  /**
   * Compares this request with another object for identity equality.
   *
   * <p>This implementation preserves {@link Object#equals(Object)} semantics by delegating to the
   * base class. Requests are treated as identity objects, so two distinct instances are not equal
   * even if they carry the same identifier.
   *
   * @param obj object to compare against; may be {@code null}.
   * @return {@code true} only when {@code obj} is the same instance as this request.
   */
  @Override
  public boolean equals(Object obj) {
    return super.equals(obj);
  }

  /**
   * Returns the stable hash code assigned to this request instance.
   *
   * <p>The value is computed once and preserved across serialization by the base class, allowing
   * hashed collections to remain stable even when requests are persisted and resumed.
   *
   * @return stable hash code derived from {@link Object#hashCode()} at construction time.
   */
  @Override
  public int hashCode() {
    return super.hashCode();
  }

  /**
   * Reveals the original disk filename when the upload originated from the node’s filesystem.
   *
   * <p>The field stays {@code null} for direct or redirect uploads to avoid leaking irrelevant
   * information. When present, callers typically show it to the operator so they can match queued
   * requests with local files and confirm DDA permissions before allowing restarts.
   *
   * @return source filename for disk uploads, or {@code null} for non-disk sources.
   */
  public File getOrigFilename() {
    if (uploadFrom != UploadFrom.DISK) return null;
    return origFilename;
  }

  /**
   * Reports the size of the payload in bytes, falling back to the last known finished size.
   *
   * <p>The method enables status pages to compute completion ratios even after {@link
   * RandomAccessBucket} resources were freed to save memory. When {@code data} becomes {@code
   * null}, callers still receive the last committed length so the UI never regresses to zero.
   *
   * @return number of bytes scheduled for upload, or the last completed size snapshot.
   */
  public long getDataSize() {
    if (data == null) return finishedSize;
    else {
      return data.size();
    }
  }

  /**
   * Returns the MIME type recorded for this request, which may be inferred or explicitly set.
   *
   * <p>The metadata is used to populate {@link UploadFileRequestStatus} responses so GUI clients
   * can provide better UX. Binary blob inserts return {@code null} because they decline MIME
   * metadata.
   *
   * @return MIME string reported to clients, or {@code null} if intentionally absent.
   */
  public String getMIMEType() {
    return clientMetadata.getMIMEType();
  }

  /**
   * Exposes metadata for status assemblies without exposing it publicly.
   *
   * @return the {@link ClientMetadata} associated with this request.
   */
  ClientMetadata clientMetadataForStatus() {
    return clientMetadata;
  }

  /**
   * Checks whether the insert can be retried by re-running compression and routing logic.
   *
   * <p>The method enforces the lifecycle contract: only completed yet failed requests are eligible,
   * and {@link ClientPutter} must agree that cached state still exists. Operators typically call
   * this before surfacing a retry action in the UI. The check is read-only and does not mutate any
   * request state.
   *
   * @return {@code true} when the request finished unsuccessfully and the putter retained restart
   *     data.
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
    return putter.canRestart();
  }

  /**
   * Replays the insert after a failure, optionally skipping filter-data regeneration.
   *
   * <p>Before scheduling the new attempt, the method resets the local state, updates status caches,
   * and notifies observers that the request left the finished state. Failures during {@link
   * ClientPutter} startup are handed to {@link ClientPutBase#onFailure(InsertException,
   * network.crypta.client.async.BaseClientPutter)} so retry logic remains consistent with the
   * normal start path. The method returns immediately if the request is not eligible for restart.
   *
   * @param context execution context containing shared schedulers and crypto factories; must not be
   *     {@code null} and should be active.
   * @param disableFilterData whether client filtering data should be bypassed for this retry.
   * @return {@code true} when the restart was scheduled successfully; {@code false} otherwise.
   */
  @Override
  public boolean restart(ClientContext context, final boolean disableFilterData) {
    if (!canRestart()) return false;
    setVarsRestart();
    try {
      if (client != null) {
        RequestStatusCache cache = client.getRequestStatusCache();
        if (cache != null) {
          cache.updateStarted(identifier, false);
        }
      }
      if (putter.restart(context)) {
        synchronized (this) {
          generatedURI = null;
          started = true;
        }
      }
      if (client != null) {
        RequestStatusCache cache = client.getRequestStatusCache();
        if (cache != null) {
          cache.updateStarted(identifier, true);
        }
      }
      return true;
    } catch (InsertException e) {
      onFailure(e, null);
      return false;
    }
  }

  /**
   * Resets state fields before a restart and refreshes compression status observers.
   *
   * <p>The override extends {@link ClientPutBase#setVarsRestart()} by also pushing compression
   * indicators into the {@link RequestStatusCache} so user interfaces render accurate status after
   * a manual retry. The method is synchronized to keep compression flags consistent with other
   * state updates.
   */
  @Override
  public synchronized void setVarsRestart() {
    super.setVarsRestart();
    if (client != null) {
      RequestStatusCache cache = client.getRequestStatusCache();
      if (cache != null) {
        cache.updateCompressionStatus(identifier, isCompressing());
      }
    }
  }

  /**
   * Handles cleanup when the request leaves the queue completely.
   *
   * <p>FOREVER-persistent inserts null the {@link ClientPutter} reference so the object graph can
   * be garbage-collected while the serialized form remains on disk. Subclasses may extend this
   * point to release more resources. The provided context is the one supplied by the queue at
   * removal time.
   *
   * @param context context supplied by the queue notifying removal time hooks; must not be {@code
   *     null}.
   */
  @Override
  public void requestWasRemoved(ClientContext context) {
    if (persistence == Persistence.FOREVER) {
      putter = null;
    }
    super.requestWasRemoved(context);
  }

  /**
   * Lists the user-visible compression lifecycle so status polling can expose intuitive progress.
   *
   * <p>The values summarize scheduler queues, CPU-bound work, and downstream insertion so clients
   * quickly understand whether throughput bottlenecks stem from contention or routing. The enum is
   * used only for UI reporting and does not affect scheduling decisions.
   */
  public enum COMPRESS_STATE {
    /**
     * Waiting for a slot on the compression scheduler while previous inserts finish; users should
     * expect zero CPU usage, but the request remains queued for work.
     */
    WAITING,
    /**
     * Actively compressing the payload or metadata; byte throughput is CPU-bound, and restarts will
     * resume from the last fully written block rather than discarding work.
     */
    COMPRESSING,
    /**
     * Compression finished, and the request now streams blocks into the network or datastore,
     * meaning failures are likely due to routing rather than preprocessing.
     */
    WORKING
  }

  /**
   * Reports the current {@link COMPRESS_STATE}, describing whether the request is queued or active.
   *
   * <p>The method inspects runtime flags so it reflects state across restarts: if compression ran
   * to completion previously, the state returns {@link COMPRESS_STATE#WORKING} even when the
   * request is being resumed. When compression is disabled entirely, the method always reports
   * {@link COMPRESS_STATE#WORKING}.
   *
   * @return compression state describing scheduler waits, active compression, or working uploads.
   */
  public COMPRESS_STATE isCompressing() {
    if (ctx.isDontCompress()) return COMPRESS_STATE.WORKING;
    synchronized (this) {
      if (!compressed) return COMPRESS_STATE.WAITING; // An insert starts at compressing
      // The progress message persists... so we need to know whether we have
      // started compressing *SINCE RESTART*.
      if (compressing) return COMPRESS_STATE.COMPRESSING;
      return COMPRESS_STATE.WORKING;
    }
  }

  @Override
  protected void onStartCompressing() {
    synchronized (this) {
      if (compressed) return;
      compressing = true;
    }
    if (client != null) {
      RequestStatusCache cache = client.getRequestStatusCache();
      if (cache != null) {
        cache.updateCompressionStatus(identifier, COMPRESS_STATE.COMPRESSING);
      }
    }
  }

  @Override
  protected void onStopCompressing() {
    synchronized (this) {
      if (compressed) return; // Race condition possible
      compressing = false;
      compressed = true;
    }
    if (client != null) {
      RequestStatusCache cache = client.getRequestStatusCache();
      if (cache != null) {
        cache.updateCompressionStatus(identifier, COMPRESS_STATE.WORKING);
      }
    }
  }

  @Override
  RequestStatus getStatus() {
    return ClientPutStatusSnapshotBuilder.build(this);
  }

  /**
   * Reattaches transient resources (notably {@link RandomAccessBucket} instances) after the request
   * is brought back from persistent storage.
   *
   * <p>Delegates to each bucket, so they can reopen files, memory maps, or network handles. Failure
   * to resume throws {@link ResumeFailedException}, which bubbles to queue management for user
   * visibility.
   *
   * @param context Context whose factories the buckets may need while reopening streams.
   * @throws ResumeFailedException If any bucket cannot restore the backing store for reading.
   */
  @Override
  public void innerResume(ClientContext context) throws ResumeFailedException {
    if (data != null) data.onResume(context);
  }

  @Override
  RequestType getType() {
    return RequestType.PUT;
  }

  /**
   * Indicates whether every component has been resumed; {@code false} here signals that additional
   * resume steps remain before the request is runnable.
   *
   * <p>The base class polls this to decide when to dispatch work; ClientPut never reports full
   * completion here because completion is tracked elsewhere.
   *
   * @return {@code false} to keep the base class aware that completion is tracked separately.
   */
  @Override
  public boolean fullyResumed() {
    return false;
  }
}
