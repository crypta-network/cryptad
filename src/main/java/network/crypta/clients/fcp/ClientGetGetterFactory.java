package network.crypta.clients.fcp;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.Serial;
import java.io.Serializable;
import java.util.Objects;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.FetchResult;
import network.crypta.client.async.BinaryBlob;
import network.crypta.client.async.BinaryBlobWriter;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientGetCallback;
import network.crypta.client.async.ClientGetter;
import network.crypta.client.async.PersistentClientCallback;
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
          callback,
          uri,
          fetchContext,
          priorityClass,
          NULL_BUCKET,
          new BinaryBlobWriter(blobBucket),
          false,
          initialMetadata,
          extensionCheck);
    }
    if (discardData) {
      returnBucket = NULL_BUCKET;
    }
    return new ClientGetter(
        callback,
        uri,
        fetchContext,
        priorityClass,
        returnBucket,
        null,
        false,
        initialMetadata,
        extensionCheck);
  }
}
