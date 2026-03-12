package network.crypta.clients.fcp;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Objects;
import network.crypta.client.FetchContext;
import network.crypta.node.NodeClientCore;
import network.crypta.support.api.Bucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Builds disk and bucket return handling for {@link ClientGet} requests.
 *
 * <p>This helper isolates DDA checks, existing file handling, and extension validation so the core
 * request flow can focus on scheduling and status coordination. It is intentionally stateful to
 * carry the request identifier and {@link FetchContext} needed for error reporting and per-request
 * validation.
 *
 * <p>Typical usage is to construct one planner per request and call either {@link
 * #forGlobalRequest(ClientGet.ReturnType, File, boolean, NodeClientCore)} for global requests or
 * {@link #forMessage(ClientGetMessage, NodeClientCore, FCPConnectionHandler)} for FCP message
 * handling. The planner enforces policy checks (node download permissions and DDA access),
 * validates that disk targets are safe to use, and prepares a {@link Bucket} plus optional file
 * extension hint for filtered data. It does not perform I/O beyond basic file existence checks and
 * deletion of zero-length stale files.
 *
 * <p>The class is not thread-safe and is designed for single-request, single-threaded use. All
 * state is immutable after construction; methods derive a {@link ReturnSetup} based on inputs and
 * may throw exceptions to signal invalid requests or unsafe targets.
 *
 * <ul>
 *   <li>Validates node policy and DDA access for disk destinations.
 *   <li>Normalizes existing file handling to avoid overwriting data.
 *   <li>Derives extension hints when filtered output is requested.
 * </ul>
 */
final class ClientGetReturnPlanner {
  /** Logger for exceptional disk target situations that require operator visibility. */
  private static final Logger LOG = LoggerFactory.getLogger(ClientGetReturnPlanner.class);

  /** Identifier for the owning request, echoed in error responses and logs. */
  private final String identifier;

  /** Whether errors should be marked as global to the connection. */
  private final boolean global;

  /** Fetch settings supplying filter decisions for disk return setups. */
  private final FetchContext fetchContext;

  /**
   * Creates a planner for a single request using the supplied identifier and fetch settings.
   *
   * <p>The planner retains the identifier and global flag for subsequent error reporting and uses
   * the fetch context to decide whether to derive file extensions for filtered data. Instances are
   * lightweight and intended to be short-lived for the lifetime of a single {@link ClientGet}
   * request.
   *
   * @param identifier request identifier to associate with protocol errors; must be non-null.
   * @param global whether generated errors should be flagged as connection-global.
   * @param fetchContext fetch settings used for filter decisions; must be non-null.
   * @throws NullPointerException if {@code identifier} or {@code fetchContext} is null.
   */
  ClientGetReturnPlanner(String identifier, boolean global, FetchContext fetchContext) {
    this.identifier = Objects.requireNonNull(identifier, "identifier");
    this.global = global;
    this.fetchContext = Objects.requireNonNull(fetchContext, "fetchContext");
  }

  /**
   * Builds return handling for a global request with explicit disk parameters.
   *
   * <p>The method validates node policy for disk downloads, checks whether the target file is safe
   * to use, and prepares a disk-backed bucket when the return type is {@link
   * ClientGet.ReturnType#DISK}. For non-disk return types, the returned setup is empty with all
   * fields set to {@code null}. The caller is expected to pass a valid {@link NodeClientCore}
   * instance and, for disk requests, a concrete target file.
   *
   * @param type return strategy describing whether disk output is required.
   * @param returnFilename target file to write to when {@code type} is disk.
   * @param filterData whether to derive an extension hint for filtered output.
   * @param core node core that enforces download policy checks.
   * @return a prepared {@link ReturnSetup} describing bucket, target, and extension hint.
   * @throws NotAllowedException if the node policy rejects the requested target path.
   * @throws IOException if an existing target file cannot be removed or is unsafe to overwrite.
   * @throws NullPointerException if {@code returnFilename} is null when disk output is requested.
   */
  ReturnSetup forGlobalRequest(
      ClientGet.ReturnType type, File returnFilename, boolean filterData, NodeClientCore core)
      throws NotAllowedException, IOException {
    if (type == ClientGet.ReturnType.DISK) {
      File file = Objects.requireNonNull(returnFilename, "returnFilename");
      ensureDownloadAllowed(core, file);
      return createDiskReturnSetup(file, filterData);
    }
    return new ReturnSetup(null, null, null);
  }

  /**
   * Builds return handling from an already-parsed {@link ClientGetMessage}.
   *
   * <p>The method performs node policy checks and DDA validation before returning a disk setup for
   * {@link ClientGet.ReturnType#DISK} messages. Any invalid condition results in a {@link
   * MessageInvalidException} carrying an appropriate protocol error code and identifier. For
   * non-disk return types, the returned setup is empty with all fields set to {@code null}.
   *
   * @param message parsed request message containing return type and disk filename.
   * @param core node core used to validate download policy for disk targets.
   * @param handler connection handler providing DDA access control decisions.
   * @return a prepared {@link ReturnSetup} describing bucket, target, and extension hint.
   * @throws MessageInvalidException if policy checks fail or the target file is unsafe to use.
   * @throws NullPointerException if {@code message}, {@code core}, or {@code handler} is null.
   */
  ReturnSetup forMessage(
      ClientGetMessage message, NodeClientCore core, FCPConnectionHandler handler)
      throws MessageInvalidException {
    if (message.returnType == ClientGet.ReturnType.DISK) {
      return buildDiskSetupForMessage(message, core, handler);
    }
    return new ReturnSetup(null, null, null);
  }

  /**
   * Validates and prepares disk return handling for an FCP message.
   *
   * <p>This method enforces node download policy, DDA access permission, and target file safety
   * before constructing the {@link ReturnSetup}. It maps failures to {@link
   * MessageInvalidException} instances with protocol-appropriate error codes to allow callers to
   * respond to the remote peer deterministically.
   *
   * @param message parsed message providing the disk target and return settings.
   * @param core node core that enforces download policy for the target.
   * @param handler connection handler that provides DDA access validation.
   * @return prepared disk return setup with bucket, target file, and optional extension.
   * @throws MessageInvalidException if any policy or disk checks fail.
   */
  private ReturnSetup buildDiskSetupForMessage(
      ClientGetMessage message, NodeClientCore core, FCPConnectionHandler handler)
      throws MessageInvalidException {
    File diskFile = message.diskFile;
    if (!core.allowDownloadTo(diskFile)) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.ACCESS_DENIED,
          "Not allowed to download to " + diskFile,
          identifier,
          global);
    }
    if (!handler.ddaAccessController().allowDDAFrom(diskFile, true)) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.DIRECT_DISK_ACCESS_DENIED,
          "Not allowed to download to "
              + diskFile
              + ". You might need to do a "
              + TestDdaRequestMessage.NAME
              + " first.",
          identifier,
          global);
    }
    try {
      handleExistingTargetFile(diskFile);
    } catch (IOException e) {
      MessageInvalidException mie =
          new MessageInvalidException(
              ProtocolErrorMessage.INTERNAL_ERROR,
              "Target filename exists already: " + diskFile,
              identifier,
              global);
      mie.initCause(e);
      throw mie;
    }
    return createDiskReturnSetup(diskFile, fetchContext.getFilterData());
  }

  /**
   * Creates a disk-backed return setup for the supplied file target.
   *
   * <p>The returned setup contains a {@link Bucket} that writes to the target file and optionally
   * includes an extension hint when filtering is enabled. The method does not verify the file
   * itself; callers must ensure it is safe to use before invoking this helper.
   *
   * @param file disk target file to back the return bucket.
   * @param filterData whether to derive a file extension hint for filtered data.
   * @return a {@link ReturnSetup} holding the disk bucket, target file, and optional extension.
   */
  private ReturnSetup createDiskReturnSetup(File file, boolean filterData) {
    Bucket bucket = ClientGetGetterFactory.diskReturnBucket(file);
    return new ReturnSetup(bucket, file, filterData ? deriveExtension(file) : null);
  }

  /**
   * Derives an extension hint from the target filename.
   *
   * <p>The extension is the substring after the final {@code "."} in the filename. If the file has
   * no dot or ends with a dot, the method returns {@code null} to indicate no usable extension.
   *
   * @param file file whose name should be inspected for an extension.
   * @return the extension substring without the dot, or {@code null} if none is present.
   */
  private static String deriveExtension(File file) {
    String name = file.getName();
    int idx = name.lastIndexOf('.');
    if (idx == -1 || idx == name.length() - 1) {
      return null;
    }
    return name.substring(idx + 1);
  }

  /**
   * Verifies that the node allows disk downloads and that the target file is safe to use.
   *
   * <p>The method delegates policy validation to {@link NodeClientCore#allowDownloadTo(File)} and
   * then ensures the destination does not already exist, except for the special case where a
   * zero-length file is deleted as a stale placeholder. It does not create directories or touch the
   * filesystem beyond existence checks and optional deletion of a zero-length file.
   *
   * @param core node core used to verify download policy for the target path.
   * @param file destination file for disk output.
   * @throws NotAllowedException if the node policy rejects the target file location.
   * @throws IOException if the target file exists and cannot be safely removed.
   */
  private void ensureDownloadAllowed(NodeClientCore core, File file)
      throws NotAllowedException, IOException {
    if (!core.allowDownloadTo(file)) {
      throw new NotAllowedException();
    }
    handleExistingTargetFile(file);
  }

  /**
   * Ensures the target file does not already exist or is safely removed when empty.
   *
   * <p>If the file does not exist, the method returns immediately. If it exists and is zero length,
   * it is deleted and a warning is logged. If it still exists afterward, the method throws an
   * {@link IOException} to prevent accidental overwrites.
   *
   * @param file file path to inspect and potentially delete.
   * @throws IOException if the file exists after zero-length cleanup attempts.
   */
  private void handleExistingTargetFile(File file) throws IOException {
    if (!file.exists()) {
      return;
    }
    if (file.length() == 0) {
      Files.delete(file.toPath());
      LOG.error("Target file already exists but is zero length, deleting...");
    }
    if (file.exists()) {
      throw new IOException("Target filename exists already: " + file);
    }
  }

  /**
   * Captures prepared return handling information for the request.
   *
   * @param bucket bucket to stream or persist, or {@code null} when unused
   * @param targetFile disk destination when {@link ClientGet.ReturnType#DISK} is selected
   * @param extension optional extension hint for filtered payload validation
   */
  record ReturnSetup(Bucket bucket, File targetFile, String extension) {}
}
