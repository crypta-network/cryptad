package network.crypta.clients.fcp;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.Serial;
import java.io.Serializable;
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
import network.crypta.client.async.ClientGetterOptions;
import network.crypta.client.async.ClientGetterRequest;
import network.crypta.client.async.PersistentClientCallback;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.crypt.HashResult;
import network.crypta.keys.FreenetURI;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestClient;
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
 * resume paths to obtain a fully configured fetcher while keeping Binary Blob concerns out of
 * {@link ClientGet} and under the Sonar coupling limit (rule {@code java:S6539}).
 *
 * <p>There is no mutable-shared state beyond a reusable {@link NullBucket} instance, so the class
 * is effectively stateless. Thread-safety is therefore determined by the collaborators passed in,
 * not by this factory. The method contracts favor explicit inputs (for example, whether to discard
 * data or enable Binary Blob recording) and will fail fast when required dependencies such as
 * {@link NodeClientCore} are missing.
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
  private static final Logger LOG = LoggerFactory.getLogger(ClientGet.class);

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
   * @param identifier request identifier to report.
   * @param persistence persistence mode for the request.
   * @param started whether the request has started.
   * @param finished whether the request has finished.
   * @param succeeded whether the request has succeeded.
   * @param progressPending last recorded progress snapshot, if any.
   * @param failedMessage cached failure message, if any.
   * @param foundDataMimeType MIME type discovered for the data.
   * @param foundDataLength data length recorded for the request.
   * @param destinationFile destination file for disk requests.
   * @param dataBucket bucket containing result data.
   * @param fetchContext fetch context providing filter and MIME overrides.
   * @param priorityClass scheduler priority class.
   * @param compatModes compatibility modes observed for the request.
   * @param splitfileKey splitfile crypto key override, if any.
   * @param uri request URI to report.
   * @param dontCompress whether reinsertion should skip compression.
   * @return a populated {@link DownloadRequestStatus} instance.
   */
  static RequestStatus buildStatus(
      String identifier,
      Persistence persistence,
      boolean started,
      boolean finished,
      boolean succeeded,
      SimpleProgressMessage progressPending,
      GetFailedMessage failedMessage,
      String foundDataMimeType,
      long foundDataLength,
      File destinationFile,
      Bucket dataBucket,
      FetchContext fetchContext,
      short priorityClass,
      InsertContext.CompatibilityMode[] compatModes,
      byte[] splitfileKey,
      FreenetURI uri,
      boolean dontCompress) {
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
    if (failedMessage != null) {
      failureCode = failedMessage.failureMode;
      failureReasonShort = failedMessage.getShortFailedMessage();
      failureReasonLong = failedMessage.getLongFailedMessage();
    }
    String mimeType = foundDataMimeType;
    long dataSize = foundDataLength;
    File target = destinationFile;
    if (target != null) target = new File(target.getPath());

    Bucket shadow = (finished && succeeded) ? dataBucket : null;
    if (shadow != null) {
      if (dataSize != shadow.size()) {
        LOG.error(
            "Size of downloaded data has changed: {} -> {} on {}", dataSize, shadow.size(), shadow);
        shadow = null;
      } else {
        shadow = shadow.createShadow();
      }
    }

    boolean filterData = fetchContext.getFilterData();
    boolean overriddenDataType =
        fetchContext.getOverrideMIME() != null || fetchContext.getCharset() != null;

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
        compatModes,
        splitfileKey,
        uri,
        failureReasonShort,
        failureReasonLong,
        overriddenDataType,
        shadow,
        filterData,
        dontCompress);
  }

  /**
   * Plans return handling for a global request.
   *
   * <p>The returned array contains the return bucket, target file, and extension hint in that
   * order.
   *
   * @param identifier request identifier used for policy checks.
   * @param global whether the request uses the global identifier namespace.
   * @param fetchContext fetch context for return planning.
   * @param returnType configured return type.
   * @param returnFilename target file for disk returns.
   * @param filterData whether to derive an extension hint when filtering.
   * @param core node core used for policy checks.
   * @return array containing {@link Bucket}, {@link File}, and extension {@link String}.
   * @throws NotAllowedException if the node policy rejects the requested target path.
   * @throws IOException if an existing target file cannot be removed or is unsafe to overwrite.
   */
  static Object[] planReturnForGlobal(
      String identifier,
      boolean global,
      FetchContext fetchContext,
      ClientGet.ReturnType returnType,
      File returnFilename,
      boolean filterData,
      NodeClientCore core)
      throws NotAllowedException, IOException {
    ClientGetReturnPlanner returnPlanner =
        new ClientGetReturnPlanner(identifier, global, fetchContext);
    ClientGetReturnPlanner.ReturnSetup setup =
        returnPlanner.forGlobalRequest(returnType, returnFilename, filterData, core);
    return new Object[] {setup.bucket(), setup.targetFile(), setup.extension()};
  }

  /**
   * Plans return handling for a client message.
   *
   * <p>The returned array contains the return bucket, target file, and extension hint in that
   * order.
   *
   * @param identifier request identifier used for policy checks.
   * @param global whether the request uses the global identifier namespace.
   * @param fetchContext fetch context for return planning.
   * @param message message containing return settings.
   * @param core node core used for policy checks.
   * @param handler connection handler providing DDA validation.
   * @return array containing {@link Bucket}, {@link File}, and extension {@link String}.
   * @throws MessageInvalidException if policy checks fail or the target file is unsafe to use.
   */
  static Object[] planReturnForMessage(
      String identifier,
      boolean global,
      FetchContext fetchContext,
      ClientGetMessage message,
      NodeClientCore core,
      FCPConnectionHandler handler)
      throws MessageInvalidException {
    ClientGetReturnPlanner returnPlanner =
        new ClientGetReturnPlanner(identifier, global, fetchContext);
    ClientGetReturnPlanner.ReturnSetup setup = returnPlanner.forMessage(message, core, handler);
    return new Object[] {setup.bucket(), setup.targetFile(), setup.extension()};
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
   * Creates a disk-backed bucket intended to receive final download output.
   *
   * <p>The bucket is configured so the file must not pre-exist on first write, helping prevent
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
   * Creates a configured {@link ClientGetter} for a {@link ClientGet} request.
   *
   * <p>The factory wires a {@link CallbackAdapter}, chooses the correct return bucket strategy, and
   * optionally sets up a {@link BinaryBlobWriter} when Binary Blob recording is requested. If
   * {@code binaryBlob} is enabled and {@code returnBucket} is {@code null}, the method uses {@code
   * core} to allocate a bucket sized to {@link FetchContext#getMaxOutputLength()}. When {@code
   * discardData} is true and Binary Blob is disabled, the returned fetcher writes into a shared
   * {@link NullBucket} instead of the provided bucket.
   *
   * @param request owning request to receive callbacks and resume signals; must not be {@code
   *     null}.
   * @param uri target {@link FreenetURI} to fetch; must not be {@code null}.
   * @param fetchContext fetch configuration that defines size limits and filters; must not be
   *     {@code null}.
   * @param priorityClass scheduler priority class for the request.
   * @param returnBucket bucket for final data, or {@code null} to let the getter allocate one.
   * @param initialMetadata optional metadata bucket to seed the fetcher, may be {@code null}.
   * @param extensionCheck optional extension used by MIME filtering; may be {@code null}.
   * @param discardData whether to discard payload bytes entirely when Binary Blob is disabled.
   * @param binaryBlob whether to record a Binary Blob stream instead of regular output data.
   * @param persistenceForever whether the request is persisted across restarts for bucket choice.
   * @param core node core used to allocate buckets when needed; required if {@code binaryBlob} is
   *     true and {@code returnBucket} is {@code null}.
   * @return a fully constructed {@link ClientGetter} ready to start.
   * @throws IOException if bucket allocation fails or underlying stream setup fails.
   * @throws NullPointerException if {@code core} is required but not provided.
   */
  static ClientGetter createGetter(
      ClientGet request,
      FreenetURI uri,
      FetchContext fetchContext,
      short priorityClass,
      Bucket returnBucket,
      Bucket initialMetadata,
      String extensionCheck,
      boolean discardData,
      boolean binaryBlob,
      boolean persistenceForever,
      NodeClientCore core)
      throws IOException {
    ClientGetCallback callback = new CallbackAdapter(request);
    Bucket blobBucket = returnBucket;
    if (binaryBlob) {
      if (blobBucket == null) {
        Objects.requireNonNull(core, "core");
        blobBucket =
            core.getClientContext()
                .getBucketFactory(persistenceForever)
                .makeBucket(fetchContext.getMaxOutputLength());
      }
      return new ClientGetter(
          new ClientGetterRequest(callback, uri, fetchContext, priorityClass),
          new ClientGetterOptions(
              NULL_BUCKET,
              new BinaryBlobWriter(blobBucket),
              false,
              initialMetadata,
              extensionCheck));
    }
    if (discardData) {
      returnBucket = NULL_BUCKET;
    }
    return new ClientGetter(
        new ClientGetterRequest(callback, uri, fetchContext, priorityClass),
        new ClientGetterOptions(returnBucket, null, false, initialMetadata, extensionCheck));
  }
}
