package network.crypta.clients.fcp.bridge;

import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.clients.fcp.DownloadRequestStatus;
import network.crypta.clients.fcp.FCPServer;
import network.crypta.clients.fcp.RequestStatus;
import network.crypta.clients.fcp.UploadDirRequestStatus;
import network.crypta.clients.fcp.UploadFileRequestStatus;
import network.crypta.node.NodeClientCore;
import network.crypta.runtime.admin.queue.QueueDownloadStatusView;
import network.crypta.runtime.admin.queue.QueueRequestStatusView;
import network.crypta.runtime.admin.queue.QueueUploadDirStatusView;
import network.crypta.runtime.admin.queue.QueueUploadFileStatusView;
import network.crypta.runtime.endpoints.ClientEndpoints;
import network.crypta.runtime.spi.RequestQueueUnavailableException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class FcpQueueAdminBackendTest {

  @Mock private NodeClientCore core;
  @Mock private ClientEndpoints endpoints;
  @Mock private FCPServer fcpServer;

  private FcpQueueAdminBackend backend;

  @BeforeEach
  void setUp() {
    when(core.getEndpoints()).thenReturn(endpoints);
    backend = new FcpQueueAdminBackend(core);
  }

  @Test
  void isEnabled_whenNoFcpServerPresent_returnsFalse() {
    when(endpoints.getFcpEndpoint()).thenReturn(null);

    assertFalse(backend.isEnabled());
  }

  @Test
  void isEnabled_whenEndpointsUnavailable_returnsFalse() {
    when(core.getEndpoints()).thenReturn(null);

    assertFalse(backend.isEnabled());
  }

  @Test
  void isEnabled_whenServerPresent_delegatesToEnabledFlag() {
    when(endpoints.getFcpEndpoint()).thenReturn(FcpEndpointHandles.wrap(fcpServer));
    when(fcpServer.isEnabled()).thenReturn(true).thenReturn(false);

    assertTrue(backend.isEnabled());
    assertFalse(backend.isEnabled());
  }

  @Test
  void getGlobalRequests_whenMixedStatusesPresent_adaptsExpectedViewSubtypes() throws Exception {
    DownloadRequestStatus download = org.mockito.Mockito.mock(DownloadRequestStatus.class);
    UploadFileRequestStatus uploadFile = org.mockito.Mockito.mock(UploadFileRequestStatus.class);
    UploadDirRequestStatus uploadDir = org.mockito.Mockito.mock(UploadDirRequestStatus.class);
    RequestStatus generic = org.mockito.Mockito.mock(RequestStatus.class);
    when(endpoints.getFcpEndpoint()).thenReturn(FcpEndpointHandles.wrap(fcpServer));
    when(fcpServer.getGlobalRequests())
        .thenReturn(new RequestStatus[] {download, uploadFile, uploadDir, generic});

    when(download.hasSucceeded()).thenReturn(true);
    when(download.isPersistent()).thenReturn(true);
    when(download.isTotalFinalized()).thenReturn(true);
    when(download.toTempSpace()).thenReturn(false);

    when(generic.getIdentifier()).thenReturn("generic-1");
    when(generic.hasSucceeded()).thenReturn(false);
    when(generic.isPersistent()).thenReturn(true);
    when(generic.isTotalFinalized()).thenReturn(false);

    QueueRequestStatusView[] views = backend.getGlobalRequests();

    QueueDownloadStatusView downloadView =
        assertInstanceOf(QueueDownloadStatusView.class, views[0]);
    assertTrue(downloadView.hasSucceeded());
    assertTrue(downloadView.isPersistent());
    assertTrue(downloadView.isTotalFinalized());
    assertFalse(downloadView.toTempSpace());

    assertInstanceOf(QueueUploadFileStatusView.class, views[1]);
    assertInstanceOf(QueueUploadDirStatusView.class, views[2]);

    QueueRequestStatusView genericView = views[3];
    assertFalse(genericView instanceof QueueDownloadStatusView);
    assertFalse(genericView instanceof QueueUploadFileStatusView);
    assertFalse(genericView instanceof QueueUploadDirStatusView);
    assertEquals("generic-1", genericView.getIdentifier());
    assertFalse(genericView.hasSucceeded());
    assertTrue(genericView.isPersistent());
    assertFalse(genericView.isTotalFinalized());
  }

  @Test
  void getGlobalRequests_whenServerUnavailable_throwsIllegalStateException() {
    when(endpoints.getFcpEndpoint()).thenReturn(null);

    IllegalStateException thrown =
        assertThrows(IllegalStateException.class, backend::getGlobalRequests);

    assertTrue(thrown.getMessage().contains("FCP server unavailable"));
  }

  @Test
  void getGlobalRequests_whenPersistenceDisabled_translatesToRequestQueueUnavailableException()
      throws Exception {
    PersistenceDisabledException cause = new PersistenceDisabledException();
    when(endpoints.getFcpEndpoint()).thenReturn(FcpEndpointHandles.wrap(fcpServer));
    when(fcpServer.getGlobalRequests()).thenThrow(cause);

    RequestQueueUnavailableException thrown =
        assertThrows(RequestQueueUnavailableException.class, backend::getGlobalRequests);

    assertSame(cause, thrown.getCause());
  }

  @Test
  void removeGlobalRequestBlocking_whenCalled_delegatesToServer() throws Exception {
    when(endpoints.getFcpEndpoint()).thenReturn(FcpEndpointHandles.wrap(fcpServer));
    when(fcpServer.removeGlobalRequestBlocking("request-1")).thenReturn(true);

    assertTrue(backend.removeGlobalRequestBlocking("request-1"));
    verify(fcpServer).removeGlobalRequestBlocking("request-1");
  }

  @Test
  void
      removeGlobalRequestBlocking_whenPersistenceDisabled_translatesToRequestQueueUnavailableException()
          throws Exception {
    PersistenceDisabledException cause = new PersistenceDisabledException();
    when(endpoints.getFcpEndpoint()).thenReturn(FcpEndpointHandles.wrap(fcpServer));
    when(fcpServer.removeGlobalRequestBlocking("request-1")).thenThrow(cause);

    RequestQueueUnavailableException thrown =
        assertThrows(
            RequestQueueUnavailableException.class,
            () -> backend.removeGlobalRequestBlocking("request-1"));

    assertSame(cause, thrown.getCause());
  }

  @Test
  void restartBlocking_whenCalled_delegatesToServer() throws Exception {
    when(endpoints.getFcpEndpoint()).thenReturn(FcpEndpointHandles.wrap(fcpServer));
    when(fcpServer.restartBlocking("request-1", true)).thenReturn(true);

    assertTrue(backend.restartBlocking("request-1", true));
    verify(fcpServer).restartBlocking("request-1", true);
  }

  @Test
  void restartBlocking_whenPersistenceDisabled_translatesToRequestQueueUnavailableException()
      throws Exception {
    PersistenceDisabledException cause = new PersistenceDisabledException();
    when(endpoints.getFcpEndpoint()).thenReturn(FcpEndpointHandles.wrap(fcpServer));
    when(fcpServer.restartBlocking("request-1", false)).thenThrow(cause);

    RequestQueueUnavailableException thrown =
        assertThrows(
            RequestQueueUnavailableException.class,
            () -> backend.restartBlocking("request-1", false));

    assertSame(cause, thrown.getCause());
  }

  @Test
  void modifyGlobalRequestBlocking_whenCalled_delegatesToServer() throws Exception {
    when(endpoints.getFcpEndpoint()).thenReturn(FcpEndpointHandles.wrap(fcpServer));
    when(fcpServer.modifyGlobalRequestBlocking("request-1", "new-token", (short) 3))
        .thenReturn(true);

    assertTrue(backend.modifyGlobalRequestBlocking("request-1", "new-token", (short) 3));
    verify(fcpServer).modifyGlobalRequestBlocking("request-1", "new-token", (short) 3);
  }

  @Test
  void
      modifyGlobalRequestBlocking_whenPersistenceDisabled_translatesToRequestQueueUnavailableException()
          throws Exception {
    PersistenceDisabledException cause = new PersistenceDisabledException();
    when(endpoints.getFcpEndpoint()).thenReturn(FcpEndpointHandles.wrap(fcpServer));
    when(fcpServer.modifyGlobalRequestBlocking("request-1", null, (short) 7)).thenThrow(cause);

    RequestQueueUnavailableException thrown =
        assertThrows(
            RequestQueueUnavailableException.class,
            () -> backend.modifyGlobalRequestBlocking("request-1", null, (short) 7));

    assertSame(cause, thrown.getCause());
  }
}
