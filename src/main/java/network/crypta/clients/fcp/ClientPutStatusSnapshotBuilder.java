package network.crypta.clients.fcp;

import java.io.File;
import java.util.Date;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.keys.FreenetURI;

/**
 * Builds status snapshots for {@link ClientPut} without bloating the request class.
 *
 * <p>The builder mirrors the original in-request status assembly, preserving failure reporting,
 * progress metadata, and MIME visibility rules.
 */
final class ClientPutStatusSnapshotBuilder {
  private ClientPutStatusSnapshotBuilder() {}

  static UploadFileRequestStatus build(ClientPut request) {
    FreenetURI finalURI = request.getFinalURI();
    InsertExceptionMode failureCode = null;
    String failureReasonShort = null;
    String failureReasonLong = null;
    if (request.putFailedMessage != null) {
      failureCode = request.putFailedMessage.failureMode;
      failureReasonShort = request.putFailedMessage.getShortFailedMessage();
      failureReasonLong = request.putFailedMessage.getLongFailedMessage();
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

  private static RequestStatusSnapshot buildStatusSnapshot(ClientPut request) {
    int total = 0;
    int min = 0;
    int fetched = 0;
    int fatal = 0;
    int failed = 0;
    // See ClientRequester.getLatestSuccess() for why this defaults to the current time.
    Date latestSuccess = new Date();
    Date latestFailure = null;
    boolean totalFinalized = false;

    if (request.progressMessage instanceof SimpleProgressMessage msg) {
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
