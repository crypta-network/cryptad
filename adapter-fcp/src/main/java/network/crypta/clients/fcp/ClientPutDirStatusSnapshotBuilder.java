package network.crypta.clients.fcp;

import java.time.Instant;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.keys.FreenetURI;

/**
 * Builds immutable upload-directory status DTOs from the mutable state held by {@link
 * ClientPutDir}.
 *
 * <p>{@link ClientPutDir} tracks a mix of long-lived request flags, optional failure details, and
 * transient progress messages produced by the live insert engine. The FCP layer, by contrast, needs
 * a detached status object that can be handed to polling code, queue views, or reconnect replies
 * without exposing the mutable request internals themselves. This helper performs that translation
 * in one place so the request shell does not need to interleave lifecycle mutations with DTO
 * assembly logic.
 *
 * <p>The builder preserves the existing status defaults used by the request path. If there is no
 * current failure message, failure fields stay empty. If there is no live progress snapshot yet,
 * block counters stay at zero, and the latest-success timestamp falls back to the current instant
 * in the same way the pre-refactor code did. The result is a stable adapter-owned snapshot rather
 * than a live view over mutable request fields.
 *
 * <ul>
 *   <li>Extracts final URI and failure details from the current request state.
 *   <li>Copies live progress counters when a {@link SimpleProgressMessage} is available.
 *   <li>Returns detached status DTOs suitable for queue and replay surfaces.
 * </ul>
 */
final class ClientPutDirStatusSnapshotBuilder {
  /** Utility class; callers use the static snapshot helpers only. */
  private ClientPutDirStatusSnapshotBuilder() {}

  /**
   * Builds the full directory-upload status snapshot for one request.
   *
   * <p>The returned object contains both the generic request counters and the directory-specific
   * totals for file count and aggregate data size. Failure details are included only when the
   * request already holds a {@link PutFailedMessage}. Otherwise, the builder leaves those fields
   * empty and reports the request as an in-flight or successful upload, according to the enclosing
   * request flags.
   *
   * @param request live request whose current state should be copied into detached status DTOs
   * @return immutable directory-upload status assembled from the request's current state
   */
  static UploadDirRequestStatus build(ClientPutDir request) {
    FreenetURI finalURI = request.getFinalURI();
    InsertExceptionMode failureCode = null;
    String failureReasonShort = null;
    PutFailedMessage failureMessage = request.getFailureMessage();
    if (failureMessage != null) {
      failureCode = failureMessage.failureMode;
      failureReasonShort = failureMessage.getLongFailedMessage();
    }

    RequestStatusSnapshot statusSnapshot = buildStatusSnapshot(request);
    UploadRequestStatusDetails details =
        new UploadRequestStatusDetails(
            finalURI, request.uri, failureCode, failureReasonShort, null);
    return new UploadDirRequestStatus(
        statusSnapshot, details, request.getTotalDataSize(), request.getNumberOfFiles());
  }

  /**
   * Builds the generic request-status portion shared with other upload status DTOs.
   *
   * <p>The method reads the latest progress message snapshot when one exists and copies its block
   * counters and timestamps into a detached {@link RequestStatusSnapshot}. When no progress message
   * is available yet, the builder preserves the legacy defaults so callers still receive a usable
   * status object before the insert engine has reported any progress.
   *
   * @param request live request whose current progress state should be copied
   * @return detached generic request-status snapshot for the directory insert
   */
  private static RequestStatusSnapshot buildStatusSnapshot(ClientPutDir request) {
    int total = 0;
    int min = 0;
    int fetched = 0;
    int fatal = 0;
    int failed = 0;
    // See ClientRequester.getLatestSuccess() for why this defaults to the current time.
    Instant latestSuccess = Instant.now();
    Instant latestFailure = null;
    boolean totalFinalized = false;

    FCPMessage progressSnapshot = request.getProgressMessageSnapshot();
    if (progressSnapshot instanceof SimpleProgressMessage msg) {
      total = (int) msg.getTotalBlocks();
      min = (int) msg.getMinBlocks();
      fetched = (int) msg.getFetchedBlocks();
      latestSuccess = msg.getLatestSuccess();
      fatal = (int) msg.getFatalyFailedBlocks();
      failed = (int) msg.getFailedBlocks();
      latestFailure = msg.getLatestFailure();
      totalFinalized = msg.isTotalFinalized();
    }

    return new RequestStatusSnapshot(
        request.identifier,
        request.persistence,
        request.started,
        request.finished,
        request.succeeded,
        total,
        min,
        fetched,
        latestSuccess,
        fatal,
        failed,
        latestFailure,
        totalFinalized,
        request.priorityClass);
  }
}
