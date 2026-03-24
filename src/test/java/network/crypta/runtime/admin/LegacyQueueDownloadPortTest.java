package network.crypta.runtime.admin;

import java.io.File;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.clients.fcp.FCPServer;
import network.crypta.clients.fcp.NotAllowedException;
import network.crypta.clients.fcp.PersistentGlobalRequestParams;
import network.crypta.node.NodeClientCore;
import network.crypta.runtime.endpoints.ClientEndpoints;
import network.crypta.runtime.spi.QueueDownloadRejectedException;
import network.crypta.runtime.spi.QueueDownloadRequest;
import network.crypta.runtime.spi.RequestQueueUnavailableException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class LegacyQueueDownloadPortTest {

  @Mock private NodeClientCore core;
  @Mock private ClientEndpoints endpoints;
  @Mock private FCPServer fcp;

  private LegacyQueueDownloadPort port;

  @BeforeEach
  void setUp() {
    port = new LegacyQueueDownloadPort(core);
  }

  @Test
  void isDiskDownloadDisabled_whenCoreReportsDisabled_returnsTrue() {
    when(core.isDownloadDisabled()).thenReturn(true);

    boolean disabled = port.isDiskDownloadDisabled();

    assertTrue(disabled);
    verify(core).isDownloadDisabled();
    verifyNoInteractions(endpoints, fcp);
  }

  @Test
  void isDiskDownloadDisabled_whenCoreReportsEnabled_returnsFalse() {
    when(core.isDownloadDisabled()).thenReturn(false);

    boolean disabled = port.isDiskDownloadDisabled();

    assertFalse(disabled);
    verify(core).isDownloadDisabled();
    verifyNoInteractions(endpoints, fcp);
  }

  @Test
  void enqueueDownload_whenCalled_resolvesFcpLazilyAndForwardsExpectedValues() throws Exception {
    when(core.getEndpoints()).thenReturn(endpoints);
    when(endpoints.getFCPServer()).thenReturn(fcp);
    QueueDownloadRequest request =
        new QueueDownloadRequest(
            "CHK@", true, "text/plain", "forever", "disk", new File("/tmp/downloads"));

    verifyNoInteractions(endpoints, fcp);

    port.enqueueDownload(request);

    ArgumentCaptor<PersistentGlobalRequestParams> paramsCaptor =
        ArgumentCaptor.forClass(PersistentGlobalRequestParams.class);
    verify(endpoints).getFCPServer();
    verify(fcp).makePersistentGlobalRequestBlocking(paramsCaptor.capture());
    PersistentGlobalRequestParams params = paramsCaptor.getValue();
    assertEquals("CHK@", params.fetchURI().toString());
    assertTrue(params.filterData());
    assertEquals("text/plain", params.expectedMimeType());
    assertEquals("forever", params.persistenceType());
    assertEquals("disk", params.returnType());
    assertFalse(params.realTimeFlag());
    assertSame(request.downloadsDir(), params.downloadsDir());
  }

  @Test
  void enqueueDownload_whenNotAllowed_translatesToQueueDownloadRejectedException()
      throws Exception {
    when(core.getEndpoints()).thenReturn(endpoints);
    when(endpoints.getFCPServer()).thenReturn(fcp);
    NotAllowedException cause = new NotAllowedException();
    doThrow(cause)
        .when(fcp)
        .makePersistentGlobalRequestBlocking(any(PersistentGlobalRequestParams.class));

    QueueDownloadRejectedException thrown =
        assertThrows(
            QueueDownloadRejectedException.class,
            () ->
                port.enqueueDownload(
                    new QueueDownloadRequest("CHK@", false, null, "forever", "disk", null)));

    assertSame(cause, thrown.getCause());
  }

  @Test
  void enqueueDownload_whenPersistenceDisabled_translatesToRequestQueueUnavailableException()
      throws Exception {
    when(core.getEndpoints()).thenReturn(endpoints);
    when(endpoints.getFCPServer()).thenReturn(fcp);
    PersistenceDisabledException cause = new PersistenceDisabledException();
    doThrow(cause)
        .when(fcp)
        .makePersistentGlobalRequestBlocking(any(PersistentGlobalRequestParams.class));

    RequestQueueUnavailableException thrown =
        assertThrows(
            RequestQueueUnavailableException.class,
            () ->
                port.enqueueDownload(
                    new QueueDownloadRequest("CHK@", false, null, "forever", "disk", null)));

    assertSame(cause, thrown.getCause());
  }
}
