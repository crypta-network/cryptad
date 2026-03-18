package network.crypta.node.runtime;

import java.util.List;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.clients.fcp.DownloadRequestStatus;
import network.crypta.clients.fcp.FCPServer;
import network.crypta.clients.fcp.RequestStatus;
import network.crypta.clients.fcp.UploadFileRequestStatus;
import network.crypta.node.ClientEndpoints;
import network.crypta.node.NodeClientCore;
import network.crypta.runtime.spi.RequestQueueUnavailableException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class LegacyQueueMutationPortTest {

  @Mock private NodeClientCore core;
  @Mock private ClientEndpoints endpoints;
  @Mock private FCPServer fcp;

  private LegacyQueueMutationPort port;

  @BeforeEach
  void setUp() {
    when(core.getEndpoints()).thenReturn(endpoints);
    when(endpoints.getFCPServer()).thenReturn(fcp);
    port = new LegacyQueueMutationPort(core);
  }

  @Test
  void removeRequests_whenCalled_delegatesToFcpForEachIdentifier() throws Exception {
    port.removeRequests(List.of("download-1", "download-2"));

    verify(fcp).removeGlobalRequestBlocking("download-1");
    verify(fcp).removeGlobalRequestBlocking("download-2");
  }

  @Test
  void restartRequests_whenDisableFilterDataRequested_preservesFlag() throws Exception {
    port.restartRequests(List.of("download-1", "download-2"), true);

    verify(fcp).restartBlocking("download-1", true);
    verify(fcp).restartBlocking("download-2", true);
  }

  @Test
  void changePriority_whenCalled_delegatesToPriorityMutation() throws Exception {
    port.changePriority(List.of("download-1", "download-2"), (short) 4);

    verify(fcp).modifyGlobalRequestBlocking("download-1", null, (short) 4);
    verify(fcp).modifyGlobalRequestBlocking("download-2", null, (short) 4);
  }

  @Test
  void removeFinishedUploads_whenMixedStatusesPresent_removesOnlySucceededUploads()
      throws Exception {
    UploadFileRequestStatus succeededUpload =
        org.mockito.Mockito.mock(UploadFileRequestStatus.class);
    UploadFileRequestStatus failedUpload = org.mockito.Mockito.mock(UploadFileRequestStatus.class);
    DownloadRequestStatus download = org.mockito.Mockito.mock(DownloadRequestStatus.class);
    when(succeededUpload.hasSucceeded()).thenReturn(true);
    when(succeededUpload.getIdentifier()).thenReturn("upload-1");
    when(failedUpload.hasSucceeded()).thenReturn(false);
    when(fcp.getGlobalRequests())
        .thenReturn(new RequestStatus[] {succeededUpload, failedUpload, download});

    port.removeFinishedUploads();

    verify(fcp).removeGlobalRequestBlocking("upload-1");
  }

  @Test
  void removeFinishedDownloads_whenMixedStatusesPresent_removesOnlyPersistentFinalizedDownloads()
      throws Exception {
    DownloadRequestStatus matchingDownload = org.mockito.Mockito.mock(DownloadRequestStatus.class);
    DownloadRequestStatus tempDownload = org.mockito.Mockito.mock(DownloadRequestStatus.class);
    DownloadRequestStatus unfinishedDownload =
        org.mockito.Mockito.mock(DownloadRequestStatus.class);
    UploadFileRequestStatus upload = org.mockito.Mockito.mock(UploadFileRequestStatus.class);

    when(matchingDownload.isPersistent()).thenReturn(true);
    when(matchingDownload.hasSucceeded()).thenReturn(true);
    when(matchingDownload.isTotalFinalized()).thenReturn(true);
    when(matchingDownload.toTempSpace()).thenReturn(false);
    when(matchingDownload.getIdentifier()).thenReturn("download-1");

    when(tempDownload.isPersistent()).thenReturn(true);
    when(tempDownload.hasSucceeded()).thenReturn(true);
    when(tempDownload.isTotalFinalized()).thenReturn(true);
    when(tempDownload.toTempSpace()).thenReturn(true);

    when(unfinishedDownload.isPersistent()).thenReturn(true);
    when(unfinishedDownload.hasSucceeded()).thenReturn(false);

    when(fcp.getGlobalRequests())
        .thenReturn(
            new RequestStatus[] {matchingDownload, tempDownload, unfinishedDownload, upload});

    port.removeFinishedDownloads();

    verify(fcp).removeGlobalRequestBlocking("download-1");
  }

  @Test
  void removeRequests_whenPersistenceDisabled_translatesToRequestQueueUnavailableException()
      throws Exception {
    PersistenceDisabledException cause = new PersistenceDisabledException();
    when(fcp.removeGlobalRequestBlocking("download-1")).thenThrow(cause);

    RequestQueueUnavailableException thrown =
        assertThrows(
            RequestQueueUnavailableException.class,
            () -> port.removeRequests(List.of("download-1")));

    assertSame(cause, thrown.getCause());
  }

  @Test
  void lazyFcpLookup_whenPortConstructed_defersEndpointAccessUntilMethodCall() throws Exception {
    verifyNoInteractions(endpoints, fcp);

    port.changePriority(List.of("download-1"), (short) 3);

    verify(endpoints).getFCPServer();
    verify(fcp).modifyGlobalRequestBlocking("download-1", null, (short) 3);
  }
}
