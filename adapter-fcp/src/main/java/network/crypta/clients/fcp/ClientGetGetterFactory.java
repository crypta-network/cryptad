package network.crypta.clients.fcp;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.Serial;
import java.io.Serializable;
import java.util.HashSet;
import java.util.Objects;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchException;
import network.crypta.client.FetchResult;
import network.crypta.client.InsertContext;
import network.crypta.client.async.BinaryBlob;
import network.crypta.client.async.BinaryBlobWriter;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientGetCallback;
import network.crypta.client.async.ClientGetter;
import network.crypta.client.async.ClientGetterOptions;
import network.crypta.client.async.ClientGetterRequest;
import network.crypta.client.async.PersistentClientCallback;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.crypt.HashResult;
import network.crypta.keys.FreenetURI;
import network.crypta.node.RequestClient;
import network.crypta.runtime.spi.TransferAccessPort;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ArrayBucketFactory;
import network.crypta.support.io.FileBucket;
import network.crypta.support.io.NullBucket;
import network.crypta.support.io.ResumeFailedException;
import network.crypta.support.io.StorageFormatException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Creates {@link ClientGetter} instances for {@link ClientGet} requests, including Binary Blob
 * support.
 *
 * <p>This utility centralizes the wiring required to build a {@link ClientGetter} with the correct
 * callback adapter, bucket choices, and optional {@link BinaryBlobWriter} so the request class can
 * focus on persistence and lifecycle duties. Callers typically invoke it during request creation or
 * resume paths to get a fully configured fetcher while keeping Binary Blob concerns out of {@link
 * ClientGet} and under the Sonar coupling limit (rule {@code java:S6539}).
 *
 * <p>There is no mutable-shared state beyond a reusable {@link NullBucket} instance, so the class
 * is effectively stateless. Thread-safety is therefore determined by the collaborators passed in,
 * not by this factory. The method contracts favor explicit inputs (for example, whether to discard
 * data or enable Binary Blob recording) and will fail fast when required dependencies such as
 * {@link FcpFetchRuntimeSupport} are missing.
 *
 * <ul>
 *   <li>Wires request callbacks via an adapter that implements persistence interfaces.
 *   <li>Selects output buckets and Binary Blob writers based on caller intent.
 *   <li>Creates disk-backed buckets and hash envelopes for persistence helpers.
 * </ul>
 *
 * @see ClientGetter
 * @see ClientGet
 * @see BinaryBlobWriter
 */
final class ClientGetGetterFactory {
  private static final Logger LOG = LoggerFactory.getLogger(ClientGetGetterFactory.class);

  /**
   * Reusable {@link NullBucket} to discard output without allocating per call.
   *
   * <p>The instance holds no external resources and has no state changes, so it is safe to share
   * across factory invocations. It is returned where a caller asks to discard data or when Binary
   * Blob fetching should ignore the ordinary return bucket.
   */
  @SuppressWarnings("java:S2095")
  private static final Bucket NULL_BUCKET = new NullBucket();

  /** Prevents instantiation because this class is a static factory. */
  private ClientGetGetterFactory() {}

  /**
   * Returns the MIME type for Binary Blob responses.
   *
   * <p>This is a simple pass-through to {@link BinaryBlob#MIME_TYPE} so callers can label Binary
   * Blob fetch results consistently without referencing the Binary Blob class directly.
   *
   * @return the canonical Binary Blob MIME type string used by fetch responses.
   */
  static String binaryBlobMimeType() {
    return BinaryBlob.MIME_TYPE;
  }

  /**
   * Adapter that forwards fetch callbacks back to the owning {@link ClientGet}.
   *
   * <p>The adapter implements both {@link ClientGetCallback} and {@link PersistentClientCallback}
   * so persistent requests can resume and serialize details through a single delegate. The only
   * state retained is the request instance provided at construction time.
   */
  @SuppressWarnings("ClassCanBeRecord")
  private static final class CallbackAdapter
      implements ClientGetCallback, PersistentClientCallback, Serializable {
    /** Serialization identifier for the adapter; no evolving state is persisted. */
    @Serial private static final long serialVersionUID = 1L;

    /** Request to receive all callback signals from the fetcher. */
    private final ClientGet request;

    /**
     * Creates an adapter that forwards callbacks to the supplied request.
     *
     * @param request owning request that implements the callback logic; must not be {@code null}.
     */
    private CallbackAdapter(ClientGet request) {
      this.request = request;
    }

    @Override
    public void onSuccess(FetchResult result, ClientGetter state) {
      request.onSuccess(result, state);
    }

    @Override
    public void onFailure(FetchException e) {
      request.onFailure(e);
    }

    @Override
    public void onResume(ClientContext context) throws ResumeFailedException {
      request.onResume(context);
    }

    @Override
    public RequestClient getRequestClient() {
      return request.getRequestClient();
    }

    @Override
    public void getClientDetail(DataOutputStream dos, ChecksumChecker checker) throws IOException {
      request.getClientDetail(dos, checker);
    }
  }

  /**
   * Wraps a {@link DataOutputStream} with length-prefixing and checksum enforcement.
   *
   * <p>The returned stream writes a length-prefixed payload and appends a checksum on close, using
   * a temporary {@link ArrayBucketFactory} to buffer the data. Callers must close the returned
   * stream to flush the checksum. The underlying target stream is provided by the caller and may be
   * closed when the wrapper is closed.
   *
   * @param target output stream that receives the length-prefixed, checksummed payload.
   * @param checker checksum implementation to use for writing and verification.
   * @return a data output stream that emits a length prefix and checksum when closed.
   * @throws IOException if the checksum writer cannot be created or initialized.
   */
  static DataOutputStream checksummedWriter(DataOutputStream target, ChecksumChecker checker)
      throws IOException {
    return new DataOutputStream(checker.checksumWriterWithLength(target, new ArrayBucketFactory()));
  }

  /**
   * Applies allowed MIME types to a fetch context.
   *
   * <p>The method initializes the allowed MIME type set when configured in the request message.
   * Passing {@code null} leaves the fetch context unchanged.
   *
   * @param fetchContext fetch context to update with allowed MIME types.
   * @param allowedMimeTypes optional list of allowed MIME type strings.
   */
  static void applyAllowedMimeTypes(FetchContext fetchContext, String[] allowedMimeTypes) {
    if (allowedMimeTypes == null) {
      return;
    }
    fetchContext.setAllowedMIMETypes(new HashSet<>());
    for (String mime : allowedMimeTypes) {
      fetchContext.getAllowedMIMETypes().add(mime);
    }
  }

  /**
   * Builds a {@link RequestStatus} snapshot for a download request.
   *
   * <p>The helper mirrors the status construction from {@link ClientGet} while keeping additional
   * dependencies out of the request class.
   *
   * @param snapshot captured request state used to populate the status.
   * @return a populated {@link DownloadRequestStatus} instance.
   */
  @SuppressWarnings("resource")
  static RequestStatus buildStatus(ClientGetStatusSnapshot snapshot) {
    RequestStatusSnapshot statusSnapshot = snapshot.statusSnapshot();
    boolean finished = statusSnapshot.finished();
    boolean succeeded = statusSnapshot.success();
    GetFailedMessage failedMessage = snapshot.failedMessage();
    String foundDataMimeType = snapshot.foundDataMimeType();
    long foundDataLength = snapshot.foundDataLength();
    File destinationFile = snapshot.destinationFile();
    Bucket dataBucket = snapshot.dataBucket();
    FetchContext fetchContext = snapshot.fetchContext();
    InsertContext.CompatibilityMode[] compatModes = snapshot.compatModes();
    byte[] splitfileKey = snapshot.splitfileKey();
    FreenetURI uri = snapshot.uri();
    boolean dontCompress = snapshot.dontCompress();
    FetchExceptionMode failureCode = null;
    String failureReasonShort = null;
    String failureReasonLong = null;
    if (failedMessage != null) {
      failureCode = failedMessage.failureMode;
      failureReasonShort = failedMessage.getShortFailedMessage();
      failureReasonLong = failedMessage.getLongFailedMessage();
    }
    File target = destinationFile;
    if (target != null) target = new File(target.getPath());

    Bucket shadow = (finished && succeeded) ? dataBucket : null;
    if (shadow != null) {
      if (foundDataLength != shadow.size()) {
        LOG.error(
            "Size of downloaded data has changed: {} -> {} on {}",
            foundDataLength,
            shadow.size(),
            shadow);
        shadow = null;
      } else {
        shadow = shadow.createShadow();
      }
    }

    boolean filterData = fetchContext.getFilterData();
    boolean overriddenDataType =
        fetchContext.getOverrideMIME() != null || fetchContext.getCharset() != null;

    DownloadOutcomeInfo outcome =
        new DownloadOutcomeInfo(
            foundDataLength,
            foundDataMimeType,
            failureCode,
            failureReasonShort,
            failureReasonLong,
            shadow,
            filterData);
    DownloadRequestStatusDetails details =
        new DownloadRequestStatusDetails(
            outcome, target, compatModes, splitfileKey, uri, overriddenDataType, dontCompress);

    return new DownloadRequestStatus(statusSnapshot, details);
  }

  /**
   * Plans return handling for a global request.
   *
   * <p>The returned setup contains the return bucket, target file, and extension hint in that
   * order.
   *
   * @param identifier request identifier used for policy checks.
   * @param fetchContext fetch context for return planning.
   * @param returnType configured return type.
   * @param returnFilename target file for disk returns.
   * @param filterData whether to derive an extension hint when filtering.
   * @param transferAccess transfer policy used for policy checks.
   * @return setup containing {@link Bucket}, {@link File}, and extension {@link String}.
   * @throws NotAllowedException if the transfer policy rejects the requested target path.
   * @throws IOException if an existing target file cannot be removed or is unsafe to overwrite.
   */
  static ClientGetReturnPlanner.ReturnSetup planReturnForGlobal(
      String identifier,
      FetchContext fetchContext,
      ClientGet.ReturnType returnType,
      File returnFilename,
      boolean filterData,
      TransferAccessPort transferAccess)
      throws NotAllowedException, IOException {
    ClientGetReturnPlanner returnPlanner =
        new ClientGetReturnPlanner(identifier, true, fetchContext);
    return returnPlanner.forGlobalRequest(returnType, returnFilename, filterData, transferAccess);
  }

  /**
   * Plans return handling for a client message.
   *
   * <p>The returned setup contains the return bucket, target file, and extension hint in that
   * order.
   *
   * @param identifier request identifier used for policy checks.
   * @param global whether the request uses the global identifier namespace.
   * @param fetchContext fetch context for return planning.
   * @param message message containing return settings.
   * @param transferAccess transfer policy used for policy checks.
   * @param handler connection handler providing DDA validation.
   * @return setup containing {@link Bucket}, {@link File}, and extension {@link String}.
   * @throws MessageInvalidException if policy checks fail or the target file is unsafe to use.
   */
  static ClientGetReturnPlanner.ReturnSetup planReturnForMessage(
      String identifier,
      boolean global,
      FetchContext fetchContext,
      ClientGetMessage message,
      TransferAccessPort transferAccess,
      FCPConnectionHandler handler)
      throws MessageInvalidException {
    ClientGetReturnPlanner returnPlanner =
        new ClientGetReturnPlanner(identifier, global, fetchContext);
    return returnPlanner.forMessage(message, transferAccess, handler);
  }

  /**
   * Restores a {@link FetchContext} or defaults when recovery fails.
   *
   * @param dis input stream positioned at the fetch context data.
   * @param context client context providing default fetch settings.
   * @param checker checksum helper used to verify the serialized block.
   * @return restored {@link FetchContext} or the default when recovery fails.
   */
  static FetchContext readFetchContextOrDefault(
      DataInputStream dis, ClientContext context, ChecksumChecker checker) {
    return ClientGetPersistenceIO.readFetchContextOrDefault(dis, context, checker);
  }

  /**
   * Restores an initial metadata bucket for the request, if present.
   *
   * @param dis input stream positioned at the metadata bucket marker.
   * @param context client context owning persistent bucket services.
   * @param checker checksum helper used to verify the bucket metadata.
   * @return restored bucket or {@code null} when no metadata marker was set.
   * @throws IOException if the underlying stream cannot be read.
   * @throws StorageFormatException if metadata integrity checks fail.
   * @throws ResumeFailedException if bucket restoration fails.
   */
  static Bucket readInitialMetadata(
      DataInputStream dis, ClientContext context, ChecksumChecker checker)
      throws IOException, StorageFormatException, ResumeFailedException {
    return ClientGetPersistenceIO.readInitialMetadata(dis, context, checker);
  }

  /**
   * Restores a completed direct bucket from persistent storage.
   *
   * @param dis input stream positioned at the bucket payload.
   * @param context client context owning persistent bucket services.
   * @param checker checksum helper used to verify the bucket metadata.
   * @return restored bucket, or {@code null} when restoration failed.
   * @throws ResumeFailedException if bucket restoration fails.
   */
  static Bucket restoreCompletedDirectBucketOrNull(
      DataInputStream dis, ClientContext context, ChecksumChecker checker)
      throws ResumeFailedException {
    return ClientGetPersistenceIO.restoreCompletedDirectBucketOrNull(dis, context, checker);
  }

  /**
   * Restores the failure message for a finished request.
   *
   * @param dis input stream positioned at the failure message payload.
   * @param reqID request identifier used to populate the failure message.
   * @param foundDataLength recorded data length for the request.
   * @param foundDataMimeType recorded MIME type for the request.
   * @param context client context providing checksum helpers.
   * @param checker checksum helper used to verify the payload.
   * @return restored {@link GetFailedMessage} or {@code null} when recovery fails.
   */
  static GetFailedMessage restoreFailureMessageOrNull(
      DataInputStream dis,
      RequestIdentifier reqID,
      long foundDataLength,
      String foundDataMimeType,
      ClientContext context,
      ChecksumChecker checker) {
    return ClientGetPersistenceIO.restoreFailureMessageOrNull(
        dis, reqID, foundDataLength, foundDataMimeType, context, checker);
  }

  /**
   * Restores in-progress getter state along with transient progress fields.
   *
   * @param dis input stream positioned at the progress data block.
   * @param context client context used to resume the getter.
   * @param checker checksum helper used to validate the block.
   * @param inProgressGetter getter instance to resume.
   * @param request request instance for restoring transient fields.
   * @throws StorageFormatException if the serialized state is invalid.
   */
  static void restoreInProgressState(
      DataInputStream dis,
      ClientContext context,
      ChecksumChecker checker,
      ClientGetter inProgressGetter,
      ClientGet request)
      throws StorageFormatException {
    ClientGetPersistenceIO.restoreInProgressState(dis, context, checker, inProgressGetter, request);
  }

  /**
   * Creates a disk-backed bucket intended to receive the final download output.
   *
   * <p>The bucket is configured so the file must not pre-exist on first writing, helping prevent
   * accidental overwrites. The bucket is writable by default and does not register for
   * delete-on-exit or delete-on-free behavior.
   *
   * @param file destination file backing the bucket; may be relative or absolute.
   * @return a new writable {@link FileBucket} configured for return data.
   */
  static Bucket diskReturnBucket(File file) {
    return new FileBucket(file, false, true, false, false);
  }

  /**
   * Creates a disk-backed bucket for staging data with optional read-only behavior.
   *
   * <p>The bucket does not enforce create-only semantics, allowing it to map to an existing file
   * for resume scenarios. Callers control the read-only flag explicitly.
   *
   * @param file file backing the bucket; may point to existing or new storage.
   * @param readOnly whether the bucket should reject further writes immediately.
   * @return a {@link FileBucket} backed by {@code file} with the specified read-only setting.
   */
  static Bucket diskBucket(File file, boolean readOnly) {
    return new FileBucket(file, readOnly, false, false, false);
  }

  /**
   * Reads expected hashes from a stream and wraps them in an {@link ExpectedHashes} message.
   *
   * <p>An empty or missing hash list is represented as {@code null} to preserve historical wire
   * semantics. The caller supplies the identifier and global flag that are attached to the message
   * when hashes are present.
   *
   * @param dis input stream positioned at the hash bitmask and values.
   * @param identifier request identifier to attach to the message when hashes exist.
   * @param global whether the identifier uses the global namespace for the client.
   * @return a populated {@link ExpectedHashes} or {@code null} when no hashes are present.
   * @throws IOException if the underlying stream cannot be read.
   */
  static ExpectedHashes readExpectedHashes(DataInputStream dis, String identifier, boolean global)
      throws IOException {
    HashResult[] hashes = HashResult.readHashes(dis);
    if (hashes == null || hashes.length == 0) {
      return null;
    }
    return new ExpectedHashes(hashes, identifier, global);
  }

  /**
   * Writes expected hashes to the stream in the canonical hash encoding.
   *
   * <p>When {@code expectedHashes} is {@code null}, the method writes an empty hash set marker.
   * Otherwise, the hash list is written in the order defined by {@link HashResult#write}.
   *
   * @param dos output stream that receives the hash bitmask and values.
   * @param expectedHashes expected hash message to encode; may be {@code null}.
   * @throws IOException if the stream cannot be written to.
   */
  static void writeExpectedHashes(DataOutputStream dos, ExpectedHashes expectedHashes)
      throws IOException {
    HashResult.write(expectedHashes == null ? null : expectedHashes.hashes, dos);
  }

  /**
   * Builds the {@link ClientGetterRequest} used to start a {@link ClientGet} fetch.
   *
   * <p>The request wires a {@link CallbackAdapter} so persistence operations and result delivery
   * are delegated to the owning {@link ClientGet} instance.
   *
   * @param request owning request to receive callbacks and resume signals; must not be {@code
   *     null}.
   * @param uri target {@link FreenetURI} to fetch; must not be {@code null}.
   * @param fetchContext fetch configuration that defines size limits and filters; must not be
   *     {@code null}.
   * @param priorityClass scheduler priority class for the request.
   * @return a {@link ClientGetterRequest} configured for the provided request context.
   */
  static ClientGetterRequest createGetterRequest(
      ClientGet request, FreenetURI uri, FetchContext fetchContext, short priorityClass) {
    ClientGetCallback callback = new CallbackAdapter(request);
    return new ClientGetterRequest(callback, uri, fetchContext, priorityClass);
  }

  /**
   * Builds a {@link ClientGetter} for the supplied request settings.
   *
   * <p>This convenience wrapper keeps the request class free from option and flag types while still
   * delegating to {@link #createGetter} for the actual fetcher creation.
   *
   * @param request owning request that receives fetch callbacks.
   * @param returnBucket bucket holding returned data when not discarded.
   * @param fetchRuntimeSupport fetch runtime support used to allocate buckets when required.
   * @return a configured {@link ClientGetter} ready to run.
   * @throws IOException if bucket allocation fails.
   */
  static ClientGetter createGetterForRequest(
      ClientGet request, Bucket returnBucket, FcpFetchRuntimeSupport fetchRuntimeSupport)
      throws IOException {
    ClientGetterRequest getterRequest =
        createGetterRequest(
            request, request.getURI(), request.fetchContextForGetter(), request.getPriority());
    ClientGetterOptions options =
        new ClientGetterOptions(
            returnBucket,
            null,
            false,
            request.initialMetadataBucket(),
            request.extensionCheckForGetter());
    ClientGet.ReturnType returnType = request.returnTypeForGetter();
    ClientGetGetterFlags flags =
        new ClientGetGetterFlags(
            returnType == ClientGet.ReturnType.NONE,
            request.binaryBlobRequested(),
            request.persistence == ClientRequest.Persistence.FOREVER);
    return createGetter(getterRequest, options, flags, fetchRuntimeSupport);
  }

  /**
   * Creates a configured {@link ClientGetter} for a {@link ClientGet} request.
   *
   * <p>The factory chooses the correct return bucket strategy and optionally sets up a {@link
   * BinaryBlobWriter} when Binary Blob recording is requested. If Binary Blob recording is enabled
   * and the options do not specify a return bucket, the method uses {@code fetchRuntimeSupport} to
   * allocate a bucket sized to {@link FetchContext#getMaxOutputLength()}. When {@link
   * ClientGetGetterFlags#discardData()} is true and Binary Blob is disabled, the returned fetcher
   * writes into a shared {@link NullBucket} instead of the provided bucket.
   *
   * @param request request parameters including the callback, URI, and fetch context.
   * @param options return bucket, metadata, and extension options for the fetcher.
   * @param flags behavior flags for Binary Blob recording and discard handling.
   * @param fetchRuntimeSupport fetch runtime support used to allocate buckets when needed; required
   *     if Binary Blob recording is enabled and no return bucket is supplied.
   * @return a fully constructed {@link ClientGetter} ready to start.
   * @throws IOException if bucket allocation fails or underlying stream setup fails.
   * @throws NullPointerException if {@code fetchRuntimeSupport} is required but not provided.
   */
  static ClientGetter createGetter(
      ClientGetterRequest request,
      ClientGetterOptions options,
      ClientGetGetterFlags flags,
      FcpFetchRuntimeSupport fetchRuntimeSupport)
      throws IOException {
    Bucket returnBucket = options.returnBucket();
    Bucket initialMetadata = options.initialMetadata();
    String extensionCheck = options.forceCompatibleExtension();
    Bucket blobBucket = returnBucket;
    if (flags.binaryBlob()) {
      if (blobBucket == null) {
        Objects.requireNonNull(fetchRuntimeSupport, "fetchRuntimeSupport");
        blobBucket =
            fetchRuntimeSupport.allocateBinaryBlobBucket(
                request.ctx().getMaxOutputLength(), flags.persistenceForever());
      }
      return new ClientGetter(
          request,
          new ClientGetterOptions(
              NULL_BUCKET,
              new BinaryBlobWriter(blobBucket),
              false,
              initialMetadata,
              extensionCheck));
    }
    if (flags.discardData()) {
      returnBucket = NULL_BUCKET;
    }
    return new ClientGetter(
        request,
        new ClientGetterOptions(returnBucket, null, false, initialMetadata, extensionCheck));
  }
}
