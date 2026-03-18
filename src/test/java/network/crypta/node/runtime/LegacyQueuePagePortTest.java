package network.crypta.node.runtime;

import java.io.File;
import java.lang.reflect.Field;
import java.net.MalformedURLException;
import network.crypta.client.async.ClientRequestScheduler;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.clients.fcp.DownloadRequestStatus;
import network.crypta.clients.fcp.FCPServer;
import network.crypta.clients.fcp.RequestStatus;
import network.crypta.clients.fcp.UploadFileRequestStatus;
import network.crypta.clients.fcp.UploadRequestStatus;
import network.crypta.keys.FreenetURI;
import network.crypta.node.ClientEndpoints;
import network.crypta.node.DarknetPeerNode;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestStarterGroup;
import network.crypta.runtime.spi.QueuePageRequest;
import network.crypta.runtime.spi.QueuePageSnapshot;
import network.crypta.runtime.spi.RequestQueueUnavailableException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings("java:S100")
class LegacyQueuePagePortTest {

  @Mock private NodeClientCore core;
  @Mock private ClientEndpoints endpoints;
  @Mock private FCPServer fcp;

  @Mock(answer = Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock(answer = Answers.RETURNS_DEEP_STUBS)
  private RequestStarterGroup requestStarters;

  @Mock private ClientRequestScheduler chkFetchSchedulerBulk;
  @Mock private ClientRequestScheduler chkFetchSchedulerRT;

  private LegacyQueuePagePort port;

  @BeforeEach
  void setUp() throws Exception {
    when(core.getEndpoints()).thenReturn(endpoints);
    when(core.getNode()).thenReturn(node);
    when(core.getRequestStarters()).thenReturn(requestStarters);
    when(endpoints.getFCPServer()).thenReturn(fcp);
    when(node.network().darknetConnections()).thenReturn(new DarknetPeerNode[0]);
    setRequestStarterField("chkFetchSchedulerBulk", chkFetchSchedulerBulk);
    setRequestStarterField("chkFetchSchedulerRT", chkFetchSchedulerRT);
    port = new LegacyQueuePagePort(core);
  }

  @Test
  void renderPage_whenUploadQueueHasCompletedRequest_returnsDetachedHtmlSnapshot()
      throws Exception {
    UploadFileRequestStatus upload = org.mockito.Mockito.mock(UploadFileRequestStatus.class);
    when(upload.hasSucceeded()).thenReturn(true);
    when(upload.getIdentifier()).thenReturn("upload-1");
    when(upload.getPriority()).thenReturn((short) 2);
    when(upload.getOrigFilename()).thenReturn(new File("hello.txt"));
    when(upload.getPreferredFilenameSafe()).thenReturn("hello.txt");
    when(upload.getDataSize()).thenReturn(123L);
    when(upload.getFinalURI()).thenReturn(sampleUri());
    when(fcp.getGlobalRequests()).thenReturn(new RequestStatus[] {upload});

    QueuePageSnapshot snapshot = port.renderPage(new QueuePageRequest(true, false, null, false));

    assertTrue(snapshot.pageTitle().contains("Uploads"));
    assertTrue(snapshot.contentHtmlTemplate().contains("upload-1"));
    assertTrue(snapshot.contentHtmlTemplate().contains("hello.txt"));
    assertTrue(snapshot.contentHtmlTemplate().contains("<!--CRYPTA_QUEUE_FORM_PASSWORD-->"));
  }

  @Test
  void renderCountPage_whenDownloadsRequested_returnsCountHtml() {
    when(chkFetchSchedulerBulk.countPersistentWaitingKeys()).thenReturn(2L);
    when(chkFetchSchedulerRT.countPersistentWaitingKeys()).thenReturn(3L);
    when(chkFetchSchedulerBulk.countQueuedRequests()).thenReturn(4L);
    when(chkFetchSchedulerRT.countQueuedRequests()).thenReturn(5L);

    QueuePageSnapshot snapshot = port.renderCountPage(false);

    assertTrue(snapshot.contentHtmlTemplate().contains("Total awaiting CHKs: 5"));
    assertTrue(snapshot.contentHtmlTemplate().contains("Total queued CHK requests: 9"));
  }

  @Test
  void renderPage_whenRequestIsNull_throwsNullPointerException() {
    assertThrows(NullPointerException.class, () -> port.renderPage(null));
  }

  @Test
  void renderPage_whenFcpServerMissing_returnsEmptyDownloadsSnapshot() throws Exception {
    when(endpoints.getFCPServer()).thenReturn(null);
    when(core.getDownloadsDir()).thenReturn(new File("downloads"));
    when(core.allowDownloadTo(any(File.class))).thenReturn(true);

    QueuePageSnapshot snapshot = port.renderPage(new QueuePageRequest(false, false, null, false));

    assertTrue(snapshot.pageTitle().contains("Downloads"));
    assertTrue(snapshot.contentHtmlTemplate().contains("queue-empty"));
    assertTrue(snapshot.contentHtmlTemplate().contains("queueDownloadForm"));
    assertTrue(snapshot.contentHtmlTemplate().contains("<!--CRYPTA_ALERT_SUMMARY-->"));
    verifyNoInteractions(fcp);
  }

  @Test
  void renderKeyList_whenDownloadsRequested_returnsOnlyDownloadUris() throws Exception {
    DownloadRequestStatus download = org.mockito.Mockito.mock(DownloadRequestStatus.class);
    UploadRequestStatus upload = org.mockito.Mockito.mock(UploadRequestStatus.class);
    FreenetURI downloadUri = sampleUri();
    FreenetURI uploadUri = sampleUri();
    when(download.getURI()).thenReturn(downloadUri);
    when(upload.getURI()).thenReturn(uploadUri);
    when(fcp.getGlobalRequests()).thenReturn(new RequestStatus[] {download, upload});

    String keyList = port.renderKeyList(false);

    assertEquals(downloadUri + "\n", keyList);
  }

  @Test
  void renderKeyList_whenUploadsRequested_skipsNullUploadUris() throws Exception {
    DownloadRequestStatus download = org.mockito.Mockito.mock(DownloadRequestStatus.class);
    UploadRequestStatus uploadWithUri = org.mockito.Mockito.mock(UploadRequestStatus.class);
    UploadRequestStatus uploadWithoutUri = org.mockito.Mockito.mock(UploadRequestStatus.class);
    FreenetURI uploadUri = sampleUri();
    when(download.getURI()).thenReturn(sampleUri());
    when(uploadWithUri.getURI()).thenReturn(uploadUri);
    when(uploadWithoutUri.getURI()).thenReturn(null);
    when(fcp.getGlobalRequests())
        .thenReturn(new RequestStatus[] {download, uploadWithUri, uploadWithoutUri});

    String keyList = port.renderKeyList(true);

    assertEquals(uploadUri + "\n", keyList);
  }

  @Test
  void renderKeyList_whenFcpServerMissing_returnsEmptyString() throws Exception {
    when(endpoints.getFCPServer()).thenReturn(null);

    String keyList = port.renderKeyList(false);

    assertEquals("", keyList);
    verifyNoInteractions(fcp);
  }

  @Test
  void renderPage_whenPersistenceDisabled_translatesToRequestQueueUnavailableException()
      throws Exception {
    PersistenceDisabledException cause = new PersistenceDisabledException();
    when(fcp.getGlobalRequests()).thenThrow(cause);

    RequestQueueUnavailableException thrown =
        assertThrows(
            RequestQueueUnavailableException.class,
            () -> port.renderPage(new QueuePageRequest(false, false, null, false)));

    assertSame(cause, thrown.getCause());
  }

  @Test
  void lazyFcpLookup_whenPortConstructed_defersEndpointAccessUntilMethodCall() throws Exception {
    verifyNoInteractions(endpoints, fcp);
    when(fcp.getGlobalRequests()).thenReturn(new RequestStatus[0]);

    port.renderKeyList(false);

    verify(endpoints).getFCPServer();
    verify(fcp).getGlobalRequests();
  }

  private FreenetURI sampleUri() {
    try {
      return new FreenetURI(
          "CHK@DTCDUmnkKFlrJi9UlDDVqXlktsIXvAJ~ZTseyx5cAZs,PmA2rLgWZKVyMXxSn-ZihSskPYDTY19uhrMwqDV-~Sk,AAICAAI/index_d51.xml");
    } catch (MalformedURLException e) {
      throw new AssertionError(e);
    }
  }

  private void setRequestStarterField(String fieldName, Object value) throws Exception {
    Field field = RequestStarterGroup.class.getField(fieldName);
    field.setAccessible(true);
    field.set(requestStarters, value);
  }
}
