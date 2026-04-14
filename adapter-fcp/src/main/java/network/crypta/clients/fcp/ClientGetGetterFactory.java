package network.crypta.clients.fcp;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.util.Collections;
import java.util.HashSet;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.InsertContext;
import network.crypta.client.async.BinaryBlob;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.crypt.HashResult;
import network.crypta.keys.FreenetURI;
import network.crypta.runtime.spi.TransferAccessPort;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ArrayBucketFactory;
import network.crypta.support.io.FileBucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Houses detached GET helpers that remain adapter-owned after the runtime handoff.
 *
 * <p>The bridge now owns live fetch execution, but the adapter still owns stable helpers for
 * detached fetch configuration, return planning, bucket wrappers, and status projection.
 *
 * <p>The class is effectively stateless. Thread-safety is therefore determined by the collaborators
 * passed in, not by this factory. The method contracts favor explicit inputs and will fail fast
 * when required dependencies such as {@link FcpFetchRuntimeSupport} are missing.
 *
 * <ul>
 *   <li>Applies request-visible fetch configuration overrides.
 *   <li>Plans output buckets and disk-return behavior.
 *   <li>Creates disk-backed buckets and hash envelopes for persistence helpers.
 * </ul>
 */
final class ClientGetGetterFactory {
  private static final Logger LOG = LoggerFactory.getLogger(ClientGetGetterFactory.class);

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
   * Applies allowed MIME types to detached fetch configuration.
   *
   * <p>The method initializes the allowed MIME type set when configured in the request message.
   * Passing {@code null} leaves the configuration unchanged.
   *
   * @param fetchConfig detached fetch configuration to update with allowed MIME types.
   * @param allowedMimeTypes optional list of allowed MIME type strings.
   */
  static void applyAllowedMimeTypes(ClientGetFetchConfig fetchConfig, String[] allowedMimeTypes) {
    if (allowedMimeTypes == null) {
      return;
    }
    HashSet<String> updated = new HashSet<>();
    Collections.addAll(updated, allowedMimeTypes);
    fetchConfig.setAllowedMimeTypes(updated);
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
    ClientGetFetchConfig fetchConfig = snapshot.fetchConfig();
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

    boolean filterData = fetchConfig.getFilterData();
    boolean overriddenDataType =
        fetchConfig.getOverrideMime() != null || fetchConfig.getCharset() != null;

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
   * @param fetchConfig detached fetch configuration for return planning.
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
      ClientGetFetchConfig fetchConfig,
      ClientGet.ReturnType returnType,
      File returnFilename,
      boolean filterData,
      TransferAccessPort transferAccess)
      throws NotAllowedException, IOException {
    ClientGetReturnPlanner returnPlanner =
        new ClientGetReturnPlanner(identifier, true, fetchConfig);
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
   * @param fetchConfig detached fetch configuration for return planning.
   * @param message message containing return settings.
   * @param transferAccess transfer policy used for policy checks.
   * @param handler connection handler providing DDA validation.
   * @return setup containing {@link Bucket}, {@link File}, and extension {@link String}.
   * @throws MessageInvalidException if policy checks fail or the target file is unsafe to use.
   */
  static ClientGetReturnPlanner.ReturnSetup planReturnForMessage(
      String identifier,
      boolean global,
      ClientGetFetchConfig fetchConfig,
      ClientGetMessage message,
      TransferAccessPort transferAccess,
      FCPConnectionHandler handler)
      throws MessageInvalidException {
    ClientGetReturnPlanner returnPlanner =
        new ClientGetReturnPlanner(identifier, global, fetchConfig);
    return returnPlanner.forMessage(message, transferAccess, handler);
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
}
