package network.crypta.clients.fcp;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import network.crypta.client.async.CompatibilityAnalyser;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ResumeFailedException;
import network.crypta.support.io.StorageFormatException;

/**
 * Serializes and restores persistent state for {@link ClientGet} requests.
 *
 * <p>The codec reads and writes the binary client-detail format used by persistent queues. It is
 * responsible for emitting a stable header, encoding request configuration, and capturing progress
 * hints so a request can resume after a restart. The format is order-sensitive and versioned; any
 * changes must preserve backward compatibility with on-disk data.
 *
 * <p>This class is stateless and thread-safe. Callers are responsible for synchronization when
 * reading or writing mutable request state; the codec does not manage locking beyond honoring the
 * locks used by its callers. It also avoids side effects beyond the supplied streams and requests
 * state updates.
 *
 * <ul>
 *   <li><strong>Serialization</strong>: writes headers, configuration, and transient progress.
 *   <li><strong>Restoration</strong>: validates headers and rebuilds request state from streams.
 *   <li><strong>Compatibility</strong>: preserves field order and version numbers.
 * </ul>
 *
 * @see ClientGet
 * @see ClientGetPersistenceIO
 */
final class ClientGetPersistenceCodec {
  /**
   * Magic number guarding the serialized client-detail section.
   *
   * <p>The value is written at the start of each serialized request and used to detect corruption
   * or mismatched stream positions. It must remain stable across versions to preserve backward
   * compatibility.
   */
  private static final long CLIENT_DETAIL_MAGIC = 0x67145b675d2e22f4L;

  /**
   * Version number for the client-detail format.
   *
   * <p>The codec uses this value to validate that the stream layout matches the expected schema.
   * Increment only when the field ordering or encoding changes and retains compatibility logic as
   * needed for older versions.
   */
  private static final int CLIENT_DETAIL_VERSION = 1;

  /** Prevents instantiation; this class exposes only static codec utilities. */
  private ClientGetPersistenceCodec() {}

  /**
   * Restores a {@link ClientGet} instance from the serialized client-detail stream.
   *
   * <p>The method delegates to the {@link ClientGet} persistence constructor, which validates the
   * header and reconstructs configuration, buckets, and transient progress. The returned request is
   * configured but not started; callers should register it with the appropriate queue before
   * resuming. The input stream must be positioned at the start of the client-detail block.
   *
   * @param dis input stream positioned at the serialized client-detail payload.
   * @param reqID identifier tuple describing the request owner and scope.
   * @param fetchRuntimeSupport fetch runtime support providing factories for restoration.
   * @param checker checksum helper verifying embedded bucket sections.
   * @return reconstructed {@link ClientGet} instance ready for registration.
   * @throws StorageFormatException when magic or version checks fail.
   * @throws IOException when stream I/O fails during restoration.
   * @throws ResumeFailedException when state cannot be safely resumed.
   */
  static ClientGet restartFrom(
      DataInputStream dis,
      RequestIdentifier reqID,
      FcpFetchRuntimeSupport fetchRuntimeSupport,
      network.crypta.client.async.ClientContext context,
      ChecksumChecker checker)
      throws StorageFormatException, IOException, ResumeFailedException {
    return new ClientGet(dis, reqID, fetchRuntimeSupport, context, checker);
  }

  /**
   * Writes the client-detail section for a {@link ClientGet} into the provided stream.
   *
   * <p>The method emits a magic header, version tag, request configuration, and any available
   * progress metadata. When the request is finished, it also serializes the final success bucket or
   * failure descriptor. The caller supplies the framing stream; this method does not close the
   * outer stream but does close any checksummed substreams it creates.
   *
   * @param request request whose state and configuration are serialized.
   * @param dos destination stream receiving the serialized client-detail payload.
   * @param checker checksum helper used to wrap embedded bucket segments.
   * @throws IOException when writing to the stream fails or a bucket cannot be stored.
   */
  static void writeClientDetail(ClientGet request, DataOutputStream dos, ChecksumChecker checker)
      throws IOException {
    dos.writeLong(CLIENT_DETAIL_MAGIC);
    dos.writeInt(CLIENT_DETAIL_VERSION);
    dos.writeUTF(request.getURI().toString());
    ClientGet.ReturnType returnType = request.returnTypeForGetter();
    dos.writeShort(returnType.code);
    if (returnType == ClientGet.ReturnType.DISK) {
      dos.writeUTF(request.targetFileForLifecycle().toString());
    }
    dos.writeBoolean(request.binaryBlobRequested());
    byte[] encodedFetchConfig = encodedFetchConfigForPersistence(request);
    try (DataOutputStream ctxStream = ClientGetGetterFactory.checksummedWriter(dos, checker)) {
      ctxStream.write(encodedFetchConfig);
    }
    String extensionCheck = request.extensionCheckForGetter();
    if (extensionCheck != null) {
      dos.writeBoolean(true);
      dos.writeUTF(extensionCheck);
    } else {
      dos.writeBoolean(false);
    }
    // Request-owned bucket; closing here would free it prematurely.
    @SuppressWarnings({"resource", "java:S2095"})
    Bucket initialMetadata = request.initialMetadataBucket();
    if (initialMetadata != null) {
      dos.writeBoolean(true);
      try (DataOutputStream metadataStream =
          ClientGetGetterFactory.checksummedWriter(dos, checker)) {
        initialMetadata.storeTo(metadataStream);
      }
    } else {
      dos.writeBoolean(false);
    }
    ClientGetState state = request.state();
    synchronized (request.persistenceLock()) {
      if (request.finished) {
        dos.writeBoolean(state.hasSucceeded());
        writeTransientProgressFields(request, dos);
        if (state.hasSucceeded()) {
          if (returnType == ClientGet.ReturnType.DIRECT) {
            try (DataOutputStream bucketStream =
                ClientGetGetterFactory.checksummedWriter(dos, checker)) {
              state.getReturnBucketDirect().storeTo(bucketStream);
            }
          }
        } else {
          try (DataOutputStream failureStream =
              ClientGetGetterFactory.checksummedWriter(dos, checker)) {
            state.getFailedMessage().writeTo(failureStream);
          }
        }
        return;
      }
    }
    try (DataOutputStream progressStream = ClientGetGetterFactory.checksummedWriter(dos, checker)) {
      if (request.execution().writeTrivialProgress(progressStream)) {
        synchronized (request.persistenceLock()) {
          writeTransientProgressFields(request, progressStream);
        }
      }
    }
  }

  /**
   * Reads core configuration and metadata needed to reconstruct a {@link ClientGet}.
   *
   * <p>This method validates the header, parses the return type, detached fetch configuration,
   * optional extension check, and initial metadata bucket. It does not restore progress or final
   * success/failure state; that work happens in {@link #restoreState(ClientGet, DataInputStream,
   * RequestIdentifier, FcpFetchRuntimeSupport, ChecksumChecker)}.
   *
   * @param dis input stream positioned at the client-detail payload.
   * @param fetchRuntimeSupport fetch runtime support providing bucket factories and event handlers.
   * @param checker checksum helper used to read embedded bucket data.
   * @return basic restore data bundle with configuration and metadata buckets.
   * @throws IOException when reading from the stream fails.
   * @throws StorageFormatException when headers or encoded values are invalid.
   * @throws ResumeFailedException when metadata buckets fail to resume.
   */
  static BasicRestoreData readBasicRestoreData(
      DataInputStream dis, FcpFetchRuntimeSupport fetchRuntimeSupport, ChecksumChecker checker)
      throws IOException, StorageFormatException, ResumeFailedException {
    validateClientDetailHeader(dis);
    FreenetURI uri = parseUri(dis.readUTF());
    ClientGet.ReturnType returnType = parseReturnType(dis.readShort());
    File targetFile = returnType == ClientGet.ReturnType.DISK ? new File(dis.readUTF()) : null;
    boolean binaryBlob = dis.readBoolean();
    ClientGetFetchConfig fetchConfig =
        ClientGetPersistenceIO.readFetchConfigOrDefault(dis, fetchRuntimeSupport, checker);
    String extensionCheck = dis.readBoolean() ? dis.readUTF() : null;
    Bucket initialMetadata =
        ClientGetPersistenceIO.readInitialMetadata(dis, fetchRuntimeSupport, checker);
    return new BasicRestoreData(
        uri, returnType, targetFile, binaryBlob, fetchConfig, extensionCheck, initialMetadata);
  }

  /**
   * Restores progress or terminal state for a {@link ClientGet} from the stream.
   *
   * <p>If the request is already marked as finished, this method reads the final success or failure
   * payload and updates the request state accordingly. Otherwise, it creates an execution suitable
   * for resuming and delegates to the lower-level progress restoration helpers. The returned
   * execution is owned by the caller and should be installed on the request.
   *
   * @param request request whose mutable state is updated from persistence.
   * @param dis input stream positioned at the progress or terminal section.
   * @param reqID identifier tuple describing the request owner and scope.
   * @param fetchRuntimeSupport fetch runtime support used to rehydrate buckets and caches.
   * @param checker checksum helper for embedded bucket segments.
   * @return restored execution handle, or {@code null} when already finished.
   * @throws IOException when stream I/O fails during restoration.
   * @throws StorageFormatException when encoded values are invalid.
   * @throws ResumeFailedException when the request must restart instead of resuming.
   */
  static ClientGetExecution restoreState(
      ClientGet request,
      DataInputStream dis,
      RequestIdentifier reqID,
      FcpFetchRuntimeSupport fetchRuntimeSupport,
      ChecksumChecker checker)
      throws IOException, StorageFormatException, ResumeFailedException {
    if (request.finished) {
      restoreFinishedState(request, dis, reqID, fetchRuntimeSupport, checker);
      return null;
    }
    ClientGetExecution inProgressExecution =
        request.makeExecutionForPersistence(fetchRuntimeSupport, request.makePersistenceBucket());
    ClientGetPersistenceIO.restoreInProgressState(
        dis, fetchRuntimeSupport, checker, inProgressExecution, request);
    return inProgressExecution;
  }

  /**
   * Validates the magic number and version header for a client-detail payload.
   *
   * <p>The method reads the header values from the stream and throws if they do not match the
   * expected constants. Callers should invoke this before parsing any following fields to ensure
   * the stream is positioned correctly and the format is compatible.
   *
   * @param dis input stream positioned at the start of the header.
   * @throws IOException when reading from the stream fails.
   * @throws StorageFormatException when the header does not match expected values.
   */
  private static void validateClientDetailHeader(DataInputStream dis)
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

  /**
   * Parses a serialized URI string into a {@link FreenetURI} instance.
   *
   * <p>Any parsing failure is converted into a {@link StorageFormatException} to keep persistence
   * error handling consistent across the codec.
   *
   * @param serializedUri URI string read from persistent storage.
   * @return parsed {@link FreenetURI} instance corresponding to the string.
   * @throws StorageFormatException when the string is not a valid Freenet URI.
   */
  private static FreenetURI parseUri(String serializedUri) throws StorageFormatException {
    try {
      return new FreenetURI(serializedUri);
    } catch (Exception _) {
      throw new StorageFormatException("Bad URI");
    }
  }

  /**
   * Parses a serialized return-type code into a {@link ClientGet.ReturnType} value.
   *
   * <p>Unknown codes indicate corruption or incompatible versions and are rejected with a storage
   * exception.
   *
   * @param code encoded return-type tag from the persistence stream.
   * @return matching {@link ClientGet.ReturnType} value.
   * @throws StorageFormatException when the code does not map to a known return type.
   */
  private static ClientGet.ReturnType parseReturnType(short code) throws StorageFormatException {
    try {
      return ClientGet.ReturnType.getByCode(code);
    } catch (IllegalArgumentException _) {
      throw new StorageFormatException("Bad return type " + code);
    }
  }

  private static byte[] encodedFetchConfigForPersistence(ClientGet request) throws IOException {
    FcpFetchRuntimeSupport fetchRuntimeSupport = runtimeFetchSupportForPersistence(request);
    if (fetchRuntimeSupport != null) {
      try (ByteArrayOutputStream buffer = new ByteArrayOutputStream();
          DataOutputStream encoded = new DataOutputStream(buffer)) {
        fetchRuntimeSupport.encodeFetchConfig(request.fetchConfig(), encoded);
        byte[] encodedFetchConfig = buffer.toByteArray();
        request.setPersistedFetchConfigEncoding(encodedFetchConfig);
        return encodedFetchConfig;
      }
    }
    byte[] cachedEncoding = request.persistedFetchConfigEncoding();
    if (cachedEncoding != null) {
      return cachedEncoding;
    }
    throw new IOException("No runtime fetch support or cached fetch configuration encoding");
  }

  private static FcpFetchRuntimeSupport runtimeFetchSupportForPersistence(ClientGet request) {
    FcpFetchRuntimeSupport runtimeFetchSupport = request.runtimeFetchSupport();
    if (runtimeFetchSupport != null) {
      return runtimeFetchSupport;
    }
    PersistentRequestClient client = request.client;
    if (client == null) {
      return null;
    }
    FCPConnectionHandler connection = client.getConnection();
    if (connection == null) {
      return null;
    }
    return connection.getServer().fetchRuntimeSupport();
  }

  /**
   * Restores the terminal success or failure state for a finished request.
   *
   * <p>The method reads the success flag and transient progress fields, then either restores the
   * direct-return bucket or a {@link GetFailedMessage} depending on the outcome. If expected data
   * is missing or inconsistent, it downgrades the request to a non-finished state so the caller can
   * restart rather than trust corrupt payloads.
   *
   * @param request request whose terminal state is being reconstructed.
   * @param dis input stream positioned at the finished-state payload.
   * @param reqID identifier tuple used for failure message decoding.
   * @param fetchRuntimeSupport fetch runtime support used to restore buckets and metadata.
   * @param checker checksum helper verifying embedded bucket sections.
   * @throws IOException when stream I/O fails while reading data.
   * @throws StorageFormatException when encoded, data is invalid or incompatible.
   * @throws ResumeFailedException when bucket restoration fails unrecoverably.
   */
  private static void restoreFinishedState(
      ClientGet request,
      DataInputStream dis,
      RequestIdentifier reqID,
      FcpFetchRuntimeSupport fetchRuntimeSupport,
      ChecksumChecker checker)
      throws IOException, StorageFormatException, ResumeFailedException {
    ClientGetState state = request.state();
    state.setSucceeded(dis.readBoolean());
    readTransientProgressFields(request, dis, reqID.identifier, reqID.globalQueue);
    if (state.hasSucceeded()) {
      if (request.returnTypeForGetter() == ClientGet.ReturnType.DIRECT) {
        Bucket restoredBucket =
            ClientGetPersistenceIO.restoreCompletedDirectBucketOrNull(
                dis, fetchRuntimeSupport, checker);
        if (restoredBucket != null) {
          state.setReturnBucketDirect(restoredBucket);
        } else {
          state.setReturnBucketDirect(null);
          state.setSucceeded(false);
          request.finished = false;
        }
      }
    } else {
      GetFailedMessage restoredMessage =
          ClientGetPersistenceIO.restoreFailureMessageOrNull(
              dis,
              reqID,
              state.getFoundDataLength(),
              state.getFoundDataMimeType(),
              fetchRuntimeSupport,
              checker);
      if (restoredMessage != null) {
        state.setFailedMessage(restoredMessage);
        request.started = true;
      } else {
        request.finished = false;
        state.setFailedMessage(null);
      }
    }
  }

  /**
   * Reads transient progress fields using the request's identifier and scope.
   *
   * <p>This overload is used when the identifier and global scope are already available on the
   * request instance. It updates length, MIME hints, compatibility metadata, and expected hashes
   * from the provided stream.
   *
   * @param request request whose progress fields are updated.
   * @param dis input stream positioned at the transient progress section.
   * @throws IOException when stream I/O fails while reading fields.
   * @throws StorageFormatException when encoded values are invalid.
   */
  static void readTransientProgressFields(ClientGet request, DataInputStream dis)
      throws IOException, StorageFormatException {
    readTransientProgressFields(request, dis, request.identifier, request.global);
  }

  /**
   * Reads transient progress fields with an explicit identifier and scope.
   *
   * <p>This overload is used when the identifier and global flag are supplied externally, such as
   * during restore operations that have not yet populated the request identity. It updates the
   * request's cached size, MIME, compatibility, and expected-hash data.
   *
   * @param request request whose progress fields are updated.
   * @param dis input stream positioned at the transient progress section.
   * @param identifier identifier used to decode expected hashes.
   * @param global true when the request is in the global queue scope.
   * @throws IOException when stream I/O fails while reading fields.
   * @throws StorageFormatException when encoded values are invalid.
   */
  static void readTransientProgressFields(
      ClientGet request, DataInputStream dis, String identifier, boolean global)
      throws IOException, StorageFormatException {
    ClientGetState state = request.state();
    state.setFoundDataLength(dis.readLong());
    if (dis.readBoolean()) state.setFoundDataMimeType(dis.readUTF());
    else state.setFoundDataMimeType(null);
    state.setCompatibilityAnalyser(new CompatibilityAnalyser(dis));
    state.setExpectedHashes(ClientGetGetterFactory.readExpectedHashes(dis, identifier, global));
  }

  /**
   * Writes transient progress fields for persistence.
   *
   * <p>The method writes the best-known length, MIME type, compatibility metadata, and expected
   * hashes so that resuming requests retain progress hints. Callers should synchronize on the
   * request lock before invoking this helper to ensure a consistent snapshot.
   *
   * @param request request providing progress fields to serialize.
   * @param dos output stream receiving the encoded fields.
   * @throws IOException when writing to the output stream fails.
   */
  private static void writeTransientProgressFields(ClientGet request, DataOutputStream dos)
      throws IOException {
    ClientGetState state = request.state();
    dos.writeLong(state.getFoundDataLength());
    if (state.getFoundDataMimeType() != null) {
      dos.writeBoolean(true);
      dos.writeUTF(state.getFoundDataMimeType());
    } else {
      dos.writeBoolean(false);
    }
    state.ensureCompatibilityMode();
    state.getCompatibilityAnalyser().writeTo(dos);
    ClientGetGetterFactory.writeExpectedHashes(dos, state.getExpectedHashes());
  }

  /**
   * Bundles the minimal configuration needed to reconstruct a {@link ClientGet}.
   *
   * <p>The container holds immutable values parsed from persistence, such as the target URI, return
   * type, output destination, and detached fetch configuration. It does not carry transient
   * progress or terminal success/failure state. Callers use these values to populate the request
   * before restoring progress and completion metadata.
   */
  static final class BasicRestoreData {
    /** The target URI parsed from the persistence stream. */
    private final FreenetURI uri;

    /** The return type describing how the payload should be delivered. */
    private final ClientGet.ReturnType returnType;

    /** The disk target file when disk delivery is configured, or {@code null} otherwise. */
    private final File targetFile;

    /** True when the request is configured for BinaryBlob output instead of raw buckets. */
    private final boolean binaryBlob;

    /**
     * Detached fetch configuration reconstructed from the persistence stream and ready for reuse.
     */
    private final ClientGetFetchConfig fetchConfig;

    /** Optional filename extension hint used to validate filtering output. */
    private final String extensionCheck;

    /** Optional initial metadata bucket associated with the original request. */
    private final Bucket initialMetadata;

    /**
     * Creates a new restore data bundle with immutable configuration values.
     *
     * @param uri target URI parsed from persistence; must be non-null.
     * @param returnType return type describing delivery semantics; must be non-null.
     * @param targetFile disk target when return type is disk; otherwise {@code null}.
     * @param binaryBlob true when BinaryBlob output is enabled for the request.
     * @param fetchConfig reconstructed detached fetch configuration for the request.
     * @param extensionCheck optional extension hint used for validation, or {@code null}.
     * @param initialMetadata optional metadata bucket, or {@code null} when absent.
     */
    private BasicRestoreData(
        FreenetURI uri,
        ClientGet.ReturnType returnType,
        File targetFile,
        boolean binaryBlob,
        ClientGetFetchConfig fetchConfig,
        String extensionCheck,
        Bucket initialMetadata) {
      this.uri = uri;
      this.returnType = returnType;
      this.targetFile = targetFile;
      this.binaryBlob = binaryBlob;
      this.fetchConfig = fetchConfig;
      this.extensionCheck = extensionCheck;
      this.initialMetadata = initialMetadata;
    }

    /**
     * Returns the URI that the restored request should fetch.
     *
     * @return target {@link FreenetURI} parsed from persistence data.
     */
    FreenetURI uri() {
      return uri;
    }

    /**
     * Returns the return type encoded in the persistence stream.
     *
     * @return configured {@link ClientGet.ReturnType} for delivery semantics.
     */
    ClientGet.ReturnType returnType() {
      return returnType;
    }

    /**
     * Returns the target file for disk delivery, if configured.
     *
     * @return disk target file, or {@code null} when not applicable.
     */
    File targetFile() {
      return targetFile;
    }

    /**
     * Indicates whether BinaryBlob output was requested.
     *
     * @return {@code true} when BinaryBlob output is enabled.
     */
    boolean binaryBlob() {
      return binaryBlob;
    }

    /**
     * Returns the detached fetch configuration reconstructed from persistence.
     *
     * @return detached fetch configuration ready to be used by the restored request.
     */
    ClientGetFetchConfig fetchConfig() {
      return fetchConfig;
    }

    /**
     * Returns the optional extension check hint stored in persistence.
     *
     * @return extension hint string, or {@code null} when absent.
     */
    String extensionCheck() {
      return extensionCheck;
    }

    /**
     * Returns the optional initial metadata bucket associated with the request.
     *
     * @return initial metadata bucket, or {@code null} when none was stored.
     */
    Bucket initialMetadata() {
      return initialMetadata;
    }
  }
}
