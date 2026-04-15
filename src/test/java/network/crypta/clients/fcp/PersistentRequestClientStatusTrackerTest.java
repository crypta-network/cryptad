package network.crypta.clients.fcp;

import java.util.ArrayList;
import java.util.List;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchException;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.InsertException;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
class PersistentRequestClientStatusTrackerTest {

  @Test
  void register_whenDownloadAndUploadRequests_expectStatusesCopiedIntoCache() {
    PersistentRequestClientStatusTracker tracker = new PersistentRequestClientStatusTracker(true);
    ClientGet download = mock(ClientGet.class);
    ClientPutBase upload = mock(ClientPutBase.class);
    DownloadRequestStatus downloadStatus = newDownloadStatus("download-1");
    UploadFileRequestStatus uploadStatus = newUploadStatus("upload-1");
    when(download.getStatus()).thenReturn(downloadStatus);
    when(upload.getStatus()).thenReturn(uploadStatus);

    tracker.register(download);
    tracker.register(upload);

    List<RequestStatus> statuses = new ArrayList<>();
    tracker.addPersistentRequestStatus(statuses);

    assertEquals(2, statuses.size());
    assertTrue(
        statuses.stream()
            .anyMatch(
                status ->
                    status instanceof DownloadRequestStatus
                        && status.getIdentifier().equals("download-1")));
    assertTrue(
        statuses.stream()
            .anyMatch(
                status ->
                    status instanceof UploadFileRequestStatus
                        && status.getIdentifier().equals("upload-1")));
  }

  @Test
  void finishedClientRequest_whenDownloadCompletes_expectOutcomeReflectedInCache() {
    PersistentRequestClientStatusTracker tracker = new PersistentRequestClientStatusTracker(true);
    ClientGet download = mock(ClientGet.class);
    ClientGetState state = mock(ClientGetState.class);
    Bucket bucket = mock(Bucket.class);
    Bucket shadow = mock(Bucket.class);
    DownloadRequestStatus initialStatus = newDownloadStatus("download-2");
    GetFailedMessage failureMessage =
        new GetFailedMessage(
            new FetchException(FetchExceptionMode.ALL_DATA_NOT_FOUND, "details"),
            "download-2",
            false);

    when(download.getStatus()).thenReturn(initialStatus);
    when(download.state()).thenReturn(state);
    when(state.getFailedMessage()).thenReturn(failureMessage);
    when(download.getBucket()).thenReturn(bucket);
    when(bucket.createShadow()).thenReturn(shadow);
    when(download.getDataSize()).thenReturn(42L);
    when(download.getMIMEType()).thenReturn("text/plain");
    when(download.filterData()).thenReturn(true);
    when(download.getIdentifier()).thenReturn("download-2");
    when(download.hasSucceeded()).thenReturn(false);

    tracker.register(download);
    tracker.finishedClientRequest(download);

    List<RequestStatus> statuses = new ArrayList<>();
    tracker.addPersistentRequestStatus(statuses);
    DownloadRequestStatus cached =
        assertInstanceOf(DownloadRequestStatus.class, statuses.getFirst());

    assertEquals(42L, cached.getDataSize());
    assertEquals("text/plain", cached.getMIMEType());
    assertEquals(failureMessage.getShortFailedMessage(), cached.getFailureReason(false));
    assertEquals(failureMessage.getLongFailedMessage(), cached.getFailureReason(true));
    assertSame(shadow, cached.getDataShadow());
  }

  @Test
  void finishedClientRequest_whenUploadCompletes_expectOutcomeReflectedInCache() {
    PersistentRequestClientStatusTracker tracker = new PersistentRequestClientStatusTracker(true);
    ClientPutBase upload = mock(ClientPutBase.class);
    UploadFileRequestStatus initialStatus = newUploadStatus("upload-2");
    FreenetURI finalUri = mock(FreenetURI.class);
    PutFailedMessage failureMessage =
        new PutFailedMessage(
            new InsertException(InsertExceptionMode.INTERNAL_ERROR, "boom", finalUri),
            "upload-2",
            false);

    when(upload.getStatus()).thenReturn(initialStatus);
    when(upload.getFailureMessage()).thenReturn(failureMessage);
    when(upload.getGeneratedURI()).thenReturn(finalUri);
    when(upload.getIdentifier()).thenReturn("upload-2");
    when(upload.hasSucceeded()).thenReturn(false);

    tracker.register(upload);
    tracker.finishedClientRequest(upload);

    List<RequestStatus> statuses = new ArrayList<>();
    tracker.addPersistentRequestStatus(statuses);
    UploadFileRequestStatus cached =
        assertInstanceOf(UploadFileRequestStatus.class, statuses.getFirst());

    assertFalse(cached.hasSucceeded());
    assertSame(finalUri, cached.getFinalURI());
    assertEquals(failureMessage.getShortFailedMessage(), cached.getFailureReason(false));
    assertEquals(failureMessage.getLongFailedMessage(), cached.getFailureReason(true));
  }

  @Test
  void removeAndUpdateRequestStatusCache_whenInvoked_expectCachePrunedAndRebuilt() {
    PersistentRequestClientStatusTracker tracker = new PersistentRequestClientStatusTracker(true);
    ClientRequest downloadRequest = mock(ClientRequest.class);
    ClientRequest uploadRequest = mock(ClientRequest.class);
    DownloadRequestStatus downloadStatus = newDownloadStatus("download-3");
    UploadFileRequestStatus uploadStatus = newUploadStatus("upload-3");
    when(downloadRequest.getStatus()).thenReturn(downloadStatus);
    when(uploadRequest.getStatus()).thenReturn(uploadStatus);

    tracker.updateRequestStatusCache(List.of(downloadRequest, uploadRequest));
    tracker.removeByIdentifier("download-3");

    List<RequestStatus> statuses = new ArrayList<>();
    tracker.addPersistentRequestStatus(statuses);

    assertEquals(1, statuses.size());
    assertEquals("upload-3", statuses.getFirst().getIdentifier());

    tracker.clear();
    statuses.clear();
    tracker.addPersistentRequestStatus(statuses);

    assertTrue(statuses.isEmpty());
  }

  @Test
  void getCompletedRequest_whenMatchingCompletedDownloadPresent_expectMatchingGetterReturned() {
    PersistentRequestClientStatusTracker tracker = new PersistentRequestClientStatusTracker(false);
    ClientRequest nonDownload = mock(ClientRequest.class);
    ClientGet otherDownload = mock(ClientGet.class);
    ClientGet matchingDownload = mock(ClientGet.class);
    FreenetURI key = mock(FreenetURI.class);

    when(otherDownload.getURI()).thenReturn(mock(FreenetURI.class));
    when(matchingDownload.getURI()).thenReturn(key);

    ClientGet result =
        tracker.getCompletedRequest(List.of(nonDownload, otherDownload, matchingDownload), key);

    assertSame(matchingDownload, result);
  }

  private static DownloadRequestStatus newDownloadStatus(String identifier) {
    RequestStatusSnapshot statusSnapshot =
        new RequestStatusSnapshot(
            identifier,
            ClientRequest.Persistence.REBOOT,
            false,
            false,
            false,
            0,
            0,
            0,
            null,
            0,
            0,
            null,
            false,
            (short) 1);
    DownloadOutcomeInfo outcome =
        new DownloadOutcomeInfo(10, "text/plain", null, null, null, null, false);
    DownloadRequestStatusDetails details =
        new DownloadRequestStatusDetails(
            outcome, null, null, null, mock(FreenetURI.class), false, false);
    return new DownloadRequestStatus(statusSnapshot, details);
  }

  private static UploadFileRequestStatus newUploadStatus(String identifier) {
    RequestStatusSnapshot statusSnapshot =
        new RequestStatusSnapshot(
            identifier,
            ClientRequest.Persistence.REBOOT,
            false,
            false,
            false,
            0,
            0,
            0,
            null,
            0,
            0,
            null,
            false,
            (short) 1);
    UploadRequestStatusDetails details =
        new UploadRequestStatusDetails(null, mock(FreenetURI.class), null, null, null);
    return new UploadFileRequestStatus(
        statusSnapshot,
        details,
        25L,
        "application/octet-stream",
        null,
        ClientPut.COMPRESS_STATE.WAITING);
  }
}
