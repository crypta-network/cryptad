package network.crypta.clients.fcp;

import java.io.File;
import java.time.Instant;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.keys.FreenetURI;

/**
 * Builds upload status snapshots from a live {@link ClientPut} request.
 *
 * <p>This helper centralizes the logic for turning the mutable request state into immutable status
 * objects that can be cached, displayed, or serialized to clients. Callers typically invoke {@link
 * #build(ClientPut)} when a request needs to be exposed outside the core worker thread, for
 * example, when the request cache is refreshed or a client polls for progress. The method mirrors
 * the original in-request assembly logic, so failure details, progress metrics, and MIME visibility
 * stay consistent with historical behavior.
 *
 * <p>The builder does not mutate the request. It reads the current fields, captures counts and
 * timestamps, and returns a new {@link UploadFileRequestStatus} instance that safely encapsulates
 * the snapshot. Timestamps are captured as {@link Instant} values so callers can keep the result
 * without additional synchronization.
 *
 * <ul>
 *   <li>Preserves failure metadata reported by {@link PutFailedMessage} when available.
 *   <li>Uses the latest {@link SimpleProgressMessage} to fill progress counters if present.
 *   <li>Limits MIME exposure to forever-persistent requests, matching legacy UI behavior.
 * </ul>
 *
 * @see ClientPut
 * @see UploadFileRequestStatus
 * @see RequestStatusSnapshot
 */
final class ClientPutStatusSnapshotBuilder {
  /** Prevents instantiation; this class only provides static builders. */
  private ClientPutStatusSnapshotBuilder() {}

  /**
   * Builds a file-upload status snapshot from the current request state.
   *
   * <p>The snapshot captures the request identifier, persistence mode, progress counters, failure
   * metadata, and compression state in a single immutable {@link UploadFileRequestStatus}. It
   * preserves the same semantics as the original request-owned status assembly, including default
   * progress counts of zero when no {@link SimpleProgressMessage} has been observed yet. The method
   * is idempotent for a given request state and performs no I/O beyond reading the request fields.
   *
   * <p>Callers should pass a fully initialized {@link ClientPut} that has already set any metadata
   * fields used for reporting, such as {@link ClientPut#clientMetadataForStatus()} and the
   * compression flags. The returned status is safe to expose to other threads because the snapshot
   * captures defensive copies of mutable timestamps through {@link RequestStatusSnapshot}.
   *
   * @param request active {@link ClientPut} containing identifiers, progress data, and metadata;
   *     must not be {@code null} and should be fully initialized before snapshotting.
   * @return new {@link UploadFileRequestStatus} containing a consistent, immutable view of the
   *     request at the time of invocation, suitable for caching or UI display.
   */
  static UploadFileRequestStatus build(ClientPut request) {
    FreenetURI finalURI = request.getFinalURI();
    InsertExceptionMode failureCode = null;
    String failureReasonShort = null;
    String failureReasonLong = null;
    PutFailedMessage failureMessage = request.getFailureMessage();
    if (failureMessage != null) {
      failureCode = failureMessage.failureMode;
      failureReasonShort = failureMessage.getShortFailedMessage();
      failureReasonLong = failureMessage.getLongFailedMessage();
    }
    String mimeType = null;
    if (request.persistence == ClientRequest.Persistence.FOREVER) {
      mimeType = request.clientMetadataForStatus().getMIMEType();
    }
    File fnam = request.getOrigFilename();
    if (fnam != null) fnam = new File(fnam.getPath());

    RequestStatusSnapshot statusSnapshot = buildStatusSnapshot(request);
    UploadRequestStatusDetails details =
        new UploadRequestStatusDetails(
            finalURI, request.uri, failureCode, failureReasonShort, failureReasonLong);
    return new UploadFileRequestStatus(
        statusSnapshot, details, request.getDataSize(), mimeType, fnam, request.isCompressing());
  }

  /**
   * Builds the base {@link RequestStatusSnapshot} for the provided request.
   *
   * <p>The snapshot contains counters, timestamps, and scheduling flags shared across request
   * types. When no progress message has been recorded yet, the counts remain at zero and the latest
   * success time defaults to the current time to preserve historical behavior in downstream
   * consumers. This helper does not interpret or clamp values; it simply mirrors the request’s
   * latest known progress state.
   *
   * @param request active {@link ClientPut} holding progress counters and lifecycle flags; must not
   *     be {@code null} and should reflect the current worker state.
   * @return {@link RequestStatusSnapshot} populated with the request’s progress counters and
   *     timestamps, ready to be wrapped by higher-level status objects.
   */
  private static RequestStatusSnapshot buildStatusSnapshot(ClientPut request) {
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
