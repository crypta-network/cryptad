package network.crypta.clients.fcp;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serial;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Date;
import java.util.Objects;
import network.crypta.client.ClientMetadata;
import network.crypta.client.DefaultMIMETypes;
import network.crypta.client.InsertException;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.Metadata;
import network.crypta.client.Metadata.DocumentType;
import network.crypta.client.MetadataUnresolvedException;
import network.crypta.client.async.BinaryBlob;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientPutter;
import network.crypta.client.async.ClientPutterOptions;
import network.crypta.client.async.ClientPutterRequest;
import network.crypta.client.async.ClientRequester;
import network.crypta.clients.fcp.RequestIdentifier.RequestType;
import network.crypta.crypt.SHA256;
import network.crypta.keys.FreenetURI;
import network.crypta.node.NodeClientCore;
import network.crypta.support.Base64;
import network.crypta.support.IllegalBase64Exception;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.ResumeFailedException;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Drives a single insert issued through the FCP interface, wrapping validation, upload preparation,
 * and {@link ClientPutter} lifecycle management for one file or metadata object.
 *
 * <p>The class mediates between user requests and the asynchronous node core: it verifies disk
 * permissions, synthesizes redirect metadata, builds MIME-aware {@link ClientMetadata}, and feeds
 * bytes to the low-level {@link ClientRequester}. Instances are stateful and survive restarts when
 * configured for persistent queues, persisting identifiers, retry budgets, and compression status
 * to ensure idempotent progress reports.
 *
 * <p>Thread-safety follows the contract of {@link ClientPutBase}: the object is primarily accessed
 * from the asynchronous worker threads, yet several accessors are synchronized to guard progress
 * flags shared with client UI components. Completion and failure callbacks may arrive concurrently,
 * so callers should not mutate externally visible buckets once construction finishes.
 *
 * <ul>
 *   <li>Prepares uploads originating from disk, memory buckets, or redirect metadata.
 *   <li>Captures per-request metadata so status polling exposes MIME type and filenames.
 *   <li>Publishes persistent tag messages whenever the queue requires bookkeeping updates.
 * </ul>
 *
 * @see ClientPutBase
 * @see ClientRequester
 */
public class ClientPut extends ClientPutBase {
  private static final Logger LOG = LoggerFactory.getLogger(ClientPut.class);
  private static final String DATA_UPLOAD_LOG_TEMPLATE = "data = {}, uploadFrom = {}";

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
   * Creates a persistent insert originating from FProxy or another long-lived client, wiring the
   * request into {@link ClientPutBase}'s bookkeeping structures.
   *
   * <p>The constructor enforces disk-access policy, builds redirect metadata when needed, captures
   * MIME hints, and sets up {@link ClientPutter} with the correct retry and redundancy policies.
   * Use it whenever an external client wants the node to own persistence, resume points, and retry
   * state for an upload that might span restarts. Callers remain responsible for supplying buckets
   * that stay readable for the lifetime of the insert. Compression configuration is honored exactly
   * as supplied, so callers can trade throughput for determinism.
   *
   * @param request Persistent request metadata including URI, identifier, and queue settings.
   * @param options Insert tuning options such as retries, compression, and redundancy.
   * @param upload Upload payload metadata describing source and content hints.
   * @param core Owning {@link NodeClientCore} providing policies, factories, and scheduler hooks.
   * @throws IdentifierCollisionException Thrown when the chosen identifier already exists within
   *     the persistence scope.
   * @throws NotAllowedException Raised when a configured upload source violates server-side safety
   *     policies.
   * @throws MetadataUnresolvedException Bubble-up if redirect metadata cannot serialize into a
   *     bucket factory.
   * @throws IOException Propagated for filesystem or bucket reads when preparing payload streams.
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
      if (!core.allowUploadFrom(uploadOrigFilename)) throw new NotAllowedException();
      if (!(uploadOrigFilename.exists() && uploadOrigFilename.canRead()))
        throw new FileNotFoundException();
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
    boolean isMetadata = false;
    if (LOG.isDebugEnabled()) LOG.debug(DATA_UPLOAD_LOG_TEMPLATE, tempData, uploadFrom);
    if (uploadFrom == UploadFrom.REDIRECT) {
      this.targetURI = upload.redirectTarget();
      Metadata m = new Metadata(DocumentType.SIMPLE_REDIRECT, null, null, targetURI, cm);
      tempData = m.toBucket(core.getClientContext().getBucketFactory(isPersistentForever()));
      isMetadata = true;
    } else targetURI = null;

    this.data = tempData;
    this.clientMetadata = cm;

    putter =
        new ClientPutter(
            new ClientPutterRequest(this, data, this.uri, cm, ctx, priorityClass, isMetadata),
            new ClientPutterOptions(
                this.uri.getDocName() == null ? uploadTargetFilename : null,
                this.binaryBlob,
                options.overrideSplitfileCryptoKey(),
                -1));
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
   * @param handler Live FCP connection handler coordinating per-connection identifiers and DDA
   *     rights.
   * @param message Parsed {@link ClientPutMessage} containing payload descriptors, policy flags,
   *     and metadata.
   * @param server Owning server providing {@link NodeClientCore} accessors and capability checks.
   * @throws IdentifierCollisionException If another request on the connection already uses the
   *     identifier.
   * @throws MessageInvalidException Throw when client supplied fields (hashes, MIME, permissions)
   *     prove invalid.
   * @throws IOException If message-provided buckets cannot be read to compute salted hashes.
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
        validateDiskUpload(handler, message, message.identifier, message.global);

    this.targetFilename = message.targetFilename;
    this.uploadFrom = message.uploadFromType;
    this.origFilename = message.origFilename;

    String mimeType =
        resolveMimeType(
            message,
            this.origFilename,
            this.targetFilename,
            binaryBlob,
            message.identifier,
            message.global);

    clientToken = message.clientToken;
    ClientMetadata cm = new ClientMetadata(mimeType);
    PreparedData preparedData = prepareDataForUpload(message, cm, server, isPersistentForever());
    this.data = preparedData.bucket();
    this.clientMetadata = cm;
    this.targetURI = preparedData.targetUri();

    verifySaltedHash(diskContext, data, message.identifier, message.global);

    if (LOG.isDebugEnabled()) LOG.debug(DATA_UPLOAD_LOG_TEMPLATE, data, uploadFrom);
    putter =
        new ClientPutter(
            new ClientPutterRequest(
                this, data, this.uri, cm, ctx, priorityClass, preparedData.isMetadata()),
            new ClientPutterOptions(
                this.uri.getDocName() == null ? targetFilename : null,
                binaryBlob,
                message.overrideSplitfileCryptoKey,
                message.metadataThreshold));
  }

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

  private static String ensurePersistentIdentifierAvailable(
      PersistentRequestClient client, String identifier) throws IdentifierCollisionException {
    if (client != null && client.getRequest(identifier) != null) {
      throw new IdentifierCollisionException();
    }
    return identifier;
  }

  private synchronized boolean isFinishedRequest() {
    return finished;
  }

  private synchronized boolean shouldQueuePersistentTag() {
    return persistence != Persistence.CONNECTION && !finished;
  }

  private PreparedData prepareDataForUpload(
      ClientPutMessage message,
      ClientMetadata metadata,
      FCPServer server,
      boolean persistentForever)
      throws MessageInvalidException, IOException {
    RandomAccessBucket tempData = message.getRandomAccessBucket();
    if (LOG.isDebugEnabled()) LOG.debug(DATA_UPLOAD_LOG_TEMPLATE, tempData, uploadFrom);
    if (uploadFrom == UploadFrom.REDIRECT) {
      FreenetURI redirectTarget = message.redirectTarget;
      Metadata metadataDoc =
          new Metadata(DocumentType.SIMPLE_REDIRECT, null, null, redirectTarget, metadata);
      try {
        RandomAccessBucket redirectData =
            metadataDoc.toBucket(
                server.getCore().getClientContext().getBucketFactory(persistentForever));
        return new PreparedData(redirectData, true, redirectTarget);
      } catch (MetadataUnresolvedException e) {
        throw new MessageInvalidException(
            ProtocolErrorMessage.INTERNAL_ERROR,
            "Impossible: metadata unresolved: " + e,
            identifier,
            global);
      }
    }
    return new PreparedData(tempData, false, null);
  }

  private void verifySaltedHash(
      DiskUploadContext diskContext, RandomAccessBucket bucket, String identifier, boolean global)
      throws MessageInvalidException {
    if (!diskContext.hasSalt()) {
      return;
    }
    MessageDigest md = SHA256.getMessageDigest();
    md.update(diskContext.salt().getBytes(StandardCharsets.UTF_8));
    byte[] foundHash;
    try (InputStream is = bucket.getInputStream()) {
      SHA256.hash(is, md);
      foundHash = md.digest();
    } catch (IOException e) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.COULD_NOT_READ_FILE,
          "Unable to access file: " + e,
          identifier,
          global);
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "FileHash result : we found {} and were given {}.",
          Base64.encode(foundHash),
          Base64.encode(diskContext.saltedHash()));
    }
    if (!Arrays.equals(diskContext.saltedHash(), foundHash)) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.DIRECT_DISK_ACCESS_DENIED,
          "The hash doesn't match! (salt used : \"" + diskContext.salt() + "\")",
          identifier,
          global);
    }
  }

  private static DiskUploadContext validateDiskUpload(
      FCPConnectionHandler handler, ClientPutMessage message, String identifier, boolean global)
      throws MessageInvalidException {
    if (message.uploadFromType != UploadFrom.DISK) {
      return DiskUploadContext.empty();
    }
    if (!handler.getServer().getCore().allowUploadFrom(message.origFilename)) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.ACCESS_DENIED,
          "Not allowed to upload from " + message.origFilename,
          identifier,
          global);
    }
    if (message.fileHash != null) {
      String salt =
          handler.getConnectionIdentifierUUID().toString() + '-' + message.identifier + '-';
      byte[] saltedHash = decodeFileHash(message.fileHash, identifier, global);
      return new DiskUploadContext(salt, saltedHash);
    }
    if (!handler.ddaAccessController().allowDDAFrom(message.origFilename, false)) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.DIRECT_DISK_ACCESS_DENIED,
          "Not allowed to upload from "
              + message.origFilename
              + ". Have you done a testDDA previously ?",
          identifier,
          global);
    }
    return DiskUploadContext.empty();
  }

  private static byte[] decodeFileHash(String encoded, String identifier, boolean global)
      throws MessageInvalidException {
    try {
      return Base64.decodeStandard(encoded);
    } catch (IllegalBase64Exception _) {
      try {
        return Base64.decode(encoded);
      } catch (IllegalBase64Exception _) {
        throw new MessageInvalidException(
            ProtocolErrorMessage.INVALID_FIELD,
            "Can't base64 decode " + ClientPutBase.FILE_HASH,
            identifier,
            global);
      }
    }
  }

  private static String resolveMimeType(
      ClientPutMessage message,
      File origFilename,
      String targetFilename,
      boolean binaryBlob,
      String identifier,
      boolean global)
      throws MessageInvalidException {
    String mimeType = message.contentType;
    if (binaryBlob && mimeType != null && !mimeType.equals(BinaryBlob.MIME_TYPE)) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.INVALID_FIELD,
          "No MIME type allowed when inserting a binary blob",
          identifier,
          global);
    }
    if (mimeType == null && origFilename != null) {
      mimeType = DefaultMIMETypes.guessMIMEType(origFilename.getName(), true);
    }
    if (mimeType == null && targetFilename != null) {
      mimeType = DefaultMIMETypes.guessMIMEType(targetFilename, true);
    }
    if (mimeType != null && mimeType.isEmpty()) {
      mimeType = null;
    }
    if (mimeType != null && !DefaultMIMETypes.isPlausibleMIMEType(mimeType)) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.BAD_MIME_TYPE,
          "Bad MIME type in Metadata.ContentType",
          identifier,
          global);
    }
    return mimeType;
  }

  private record DiskUploadContext(String salt, byte[] saltedHash) {
    private static final DiskUploadContext EMPTY = new DiskUploadContext(null, null);

    static DiskUploadContext empty() {
      return EMPTY;
    }

    boolean hasSalt() {
      return salt != null;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (!(o instanceof DiskUploadContext(String otherSalt, byte[] otherHash))) return false;
      return Objects.equals(salt, otherSalt) && Arrays.equals(saltedHash, otherHash);
    }

    @Override
    public int hashCode() {
      int result = Objects.hash(salt);
      result = 31 * result + Arrays.hashCode(saltedHash);
      return result;
    }

    @Override
    public @NotNull String toString() {
      return "DiskUploadContext[salt="
          + salt
          + ", saltedHash="
          + (saltedHash == null ? "null" : Arrays.toString(saltedHash))
          + ']';
    }
  }

  private record PreparedData(RandomAccessBucket bucket, boolean metadata, FreenetURI targetUri) {
    boolean isMetadata() {
      return metadata;
    }
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
   * it simply refreshes the persistent tag. Otherwise, it schedules the insert, updates
   * bookkeeping, and emits persistent-queue tags if necessary so external monitors observe the
   * in-flight status. Callers should invoke this once after construction or resume to reattach the
   * UI state.
   *
   * @param context Client execution context providing schedulers, bucket factories, and thread
   *     pools.
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
      onFailure(new InsertException(InsertExceptionMode.INTERNAL_ERROR, t, null), null);
    }
  }

  @Override
  protected void freeData() {
    Bucket d;
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
    return new PersistentPut(
        identifier,
        publicURI,
        uri,
        verbosity,
        priorityClass,
        uploadFrom,
        targetURI,
        persistence,
        origFilename,
        clientMetadata.getMIMEType(),
        client.isGlobalQueue,
        getDataSize(),
        clientToken,
        started,
        ctx.getMaxInsertRetries(),
        targetFilename,
        binaryBlob,
        this.ctx.getCompatibilityMode(),
        this.ctx.isDontCompress(),
        this.ctx.getCompressorDescriptor(),
        isRealTime(),
        putter != null ? putter.getSplitfileCryptoKey() : null);
  }

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
   * Reports whether the put operation permanently succeeded, meaning the final URI is committed and
   * any waiting clients may fetch it.
   *
   * <p>The flag flips to {@code true} only after {@link ClientPutter} notifies completion and
   * remains {@code true} even if future retries occur, allowing UIs to treat the request as
   * immutable history. It is safe to poll frequently; the backing field is volatile through {@link
   * ClientPutBase} synchronization.
   *
   * @return True, once the insert commits and the node has acknowledged durable storage.
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
   * address. Consumers typically surface this in status tables or completion callbacks.
   *
   * @return Finalized URI when known; {@code null} until the node produces one.
   */
  public FreenetURI getFinalURI() {
    return generatedURI;
  }

  /**
   * Indicates whether the payload bytes were supplied inline via the FCP connection rather than
   * read from disk or synthesized from metadata.
   *
   * <p>This mirrors the original {@link UploadFrom} choice. Direct uploads are useful for clients
   * that already hold data in memory and do not require DDA permissions. Disk-based inserts return
   * {@code false} so the UI can display security-sensitive origin information.
   *
   * @return {@code true} if {@link UploadFrom#DIRECT} initiated the request; {@code false} else.
   */
  public boolean isDirect() {
    return uploadFrom == UploadFrom.DIRECT;
  }

  @Override
  public boolean equals(Object obj) {
    return super.equals(obj);
  }

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
   * @return Source filename for disk uploads; {@code null} in other cases.
   */
  public File getOrigFilename() {
    if (uploadFrom != UploadFrom.DISK) return null;
    return origFilename;
  }

  /**
   * Reports the size of the payload in bytes, falling back to the last known finished size if the
   * current bucket has already been released.
   *
   * <p>The method enables status pages to compute completion ratios even after {@link
   * RandomAccessBucket} resources were freed to save memory. When {@code data} becomes {@code
   * null}, callers still receive the last committed length so the UI never regresses to zero.
   *
   * @return Number of bytes scheduled for upload, or the last completed size snapshot.
   */
  public long getDataSize() {
    if (data == null) return finishedSize;
    else {
      return data.size();
    }
  }

  /**
   * Returns the MIME type recorded for this request, which may be inferred from filenames or
   * explicitly set by the client.
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
   * Checks whether the insert can be retried by re-running compression and routing logic.
   *
   * <p>The method enforces the lifecycle contract: only completed yet failed requests are eligible,
   * and {@link ClientPutter} must agree that cached state still exists. Operators typically call
   * this before surfacing a “Retry” action in the UI.
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
   * Replays the insert after a failure, optionally skipping filter-data regeneration when
   * configured.
   *
   * <p>Before scheduling the new attempt, the method resets the local state, updates status caches,
   * and notifies observers that the request left the finished state. Failures during {@link
   * ClientPutter} startup are handed to {@link ClientPutBase#onFailure(InsertException,
   * network.crypta.client.async.BaseClientPutter)} so retry logic remains consistent with the
   * normal start path.
   *
   * @param context Execution context containing shared schedulers and crypto factories.
   * @param disableFilterData Whether client filtering data should be bypassed for this retry.
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
   * a manual retry.
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
   * Handles cleanup when the request leaves the queue completely, freeing heavyweight helpers when
   * possible.
   *
   * <p>FOREVER-persistent inserts null the {@link ClientPutter} reference so the object graph can
   * be GC’d while the serialized form remains on disk. Subclasses may extend this point to release
   * more resources.
   *
   * @param context Context supplied by the queue notifying removal time hooks.
   */
  @Override
  public void requestWasRemoved(ClientContext context) {
    if (persistence == Persistence.FOREVER) {
      putter = null;
    }
    super.requestWasRemoved(context);
  }

  /**
   * Lists the user-visible compression lifecycle so status polling can expose intuitive progress
   * wording.
   *
   * <p>The values summarize scheduler queues, CPU-bound work, and downstream insertion so clients
   * quickly understand whether throughput bottlenecks stem from contention or routing.
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
   * Reports the current {@link COMPRESS_STATE}, allowing UI callers to describe whether the request
   * is queued, compressing, or already uploading.
   *
   * <p>The method inspects runtime flags so it reflects state across restarts: if compression ran
   * to completion previously, the state returns {@link COMPRESS_STATE#WORKING} even when the
   * request is being resumed.
   *
   * @return Compression state describing scheduler waits, active compression, or working uploads.
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
    FreenetURI finalURI = getFinalURI();
    InsertExceptionMode failureCode = null;
    String failureReasonShort = null;
    String failureReasonLong = null;
    if (putFailedMessage != null) {
      failureCode = putFailedMessage.failureMode;
      failureReasonShort = putFailedMessage.getShortFailedMessage();
      failureReasonLong = putFailedMessage.getLongFailedMessage();
    }
    String mimeType = null;
    if (persistence == Persistence.FOREVER) {
      mimeType = clientMetadata.getMIMEType();
    }
    File fnam = getOrigFilename();
    if (fnam != null) fnam = new File(fnam.getPath());

    int total = 0;
    int min = 0;
    int fetched = 0;
    int fatal = 0;
    int failed = 0;
    // See ClientRequester.getLatestSuccess() for why this defaults to the current time.
    Date latestSuccess = new Date();
    Date latestFailure = null;
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

    return new UploadFileRequestStatus(
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
        finalURI,
        uri,
        failureCode,
        failureReasonShort,
        failureReasonLong,
        getDataSize(),
        mimeType,
        fnam,
        isCompressing());
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
