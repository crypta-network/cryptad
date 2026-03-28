package network.crypta.runtime.admin;

import java.util.List;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.runtime.admin.queue.QueueAdminBackend;
import network.crypta.runtime.admin.queue.QueueDownloadStatusView;
import network.crypta.runtime.admin.queue.QueueRequestStatusView;
import network.crypta.runtime.admin.queue.QueueUploadDirStatusView;
import network.crypta.runtime.admin.queue.QueueUploadFileStatusView;
import network.crypta.runtime.spi.RequestQueueUnavailableException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class LegacyQueueMutationPortTest {

  @Mock private QueueAdminBackend queueBackend;

  private LegacyQueueMutationPort port;

  @BeforeEach
  void setUp() {
    port = new LegacyQueueMutationPort(queueBackend);
  }

  @Test
  void removeRequests_whenCalled_delegatesToBackendForEachIdentifier() throws Exception {
    port.removeRequests(List.of("download-1", "download-2"));

    verify(queueBackend).removeGlobalRequestBlocking("download-1");
    verify(queueBackend).removeGlobalRequestBlocking("download-2");
  }

  @Test
  void restartRequests_whenDisableFilterDataRequested_preservesFlag() throws Exception {
    port.restartRequests(List.of("download-1", "download-2"), true);

    verify(queueBackend).restartBlocking("download-1", true);
    verify(queueBackend).restartBlocking("download-2", true);
  }

  @Test
  void changePriority_whenCalled_delegatesToPriorityMutation() throws Exception {
    port.changePriority(List.of("download-1", "download-2"), (short) 4);

    verify(queueBackend).modifyGlobalRequestBlocking("download-1", null, (short) 4);
    verify(queueBackend).modifyGlobalRequestBlocking("download-2", null, (short) 4);
  }

  @Test
  void removeFinishedUploads_whenMixedStatusesPresent_removesOnlySucceededUploads()
      throws Exception {
    QueueUploadFileStatusView succeededUpload =
        org.mockito.Mockito.mock(QueueUploadFileStatusView.class);
    QueueUploadFileStatusView failedUpload =
        org.mockito.Mockito.mock(QueueUploadFileStatusView.class);
    QueueUploadDirStatusView succeededDirectoryUpload =
        org.mockito.Mockito.mock(QueueUploadDirStatusView.class);
    QueueDownloadStatusView download = org.mockito.Mockito.mock(QueueDownloadStatusView.class);
    when(succeededUpload.hasSucceeded()).thenReturn(true);
    when(succeededUpload.getIdentifier()).thenReturn("upload-1");
    when(failedUpload.hasSucceeded()).thenReturn(false);
    when(queueBackend.getGlobalRequests())
        .thenReturn(
            new QueueRequestStatusView[] {
              succeededUpload, failedUpload, succeededDirectoryUpload, download
            });

    port.removeFinishedUploads();

    verify(queueBackend).removeGlobalRequestBlocking("upload-1");
    verify(queueBackend, never()).removeGlobalRequestBlocking("upload-dir-1");
  }

  @Test
  void removeFinishedDownloads_whenMixedStatusesPresent_removesOnlyPersistentFinalizedDownloads()
      throws Exception {
    QueueDownloadStatusView matchingDownload =
        org.mockito.Mockito.mock(QueueDownloadStatusView.class);
    QueueDownloadStatusView tempDownload = org.mockito.Mockito.mock(QueueDownloadStatusView.class);
    QueueDownloadStatusView unfinishedDownload =
        org.mockito.Mockito.mock(QueueDownloadStatusView.class);
    QueueUploadFileStatusView upload = org.mockito.Mockito.mock(QueueUploadFileStatusView.class);

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

    when(queueBackend.getGlobalRequests())
        .thenReturn(
            new QueueRequestStatusView[] {
              matchingDownload, tempDownload, unfinishedDownload, upload
            });

    port.removeFinishedDownloads();

    verify(queueBackend).removeGlobalRequestBlocking("download-1");
  }

  @Test
  void removeRequests_whenPersistenceDisabled_translatesToRequestQueueUnavailableException()
      throws Exception {
    PersistenceDisabledException cause = new PersistenceDisabledException();
    RequestQueueUnavailableException queueUnavailable =
        new RequestQueueUnavailableException("Persistent request queue unavailable", cause);
    when(queueBackend.removeGlobalRequestBlocking("download-1")).thenThrow(queueUnavailable);

    RequestQueueUnavailableException thrown =
        assertThrows(
            RequestQueueUnavailableException.class,
            () -> port.removeRequests(List.of("download-1")));

    assertSame(cause, thrown.getCause());
  }

  @Test
  void lazyBackendUsage_whenPortConstructed_defersBackendAccessUntilMethodCall() throws Exception {
    verifyNoInteractions(queueBackend);

    port.changePriority(List.of("download-1"), (short) 3);

    verify(queueBackend).modifyGlobalRequestBlocking("download-1", null, (short) 3);
  }
}
