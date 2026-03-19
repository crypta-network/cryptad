package network.crypta.clients.http;

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.runtime.spi.DarknetConnectionsPort;
import network.crypta.runtime.spi.DarknetMessagingPort;
import network.crypta.runtime.spi.QueueCompletionPort;
import network.crypta.runtime.spi.QueueDownloadPort;
import network.crypta.runtime.spi.QueueInsertPort;
import network.crypta.runtime.spi.QueueMutationPort;
import network.crypta.runtime.spi.QueuePagePort;
import network.crypta.runtime.spi.QueuePageRequest;
import network.crypta.runtime.spi.QueuePageSnapshot;
import network.crypta.runtime.spi.QueuePersistenceStatusSnapshot;
import network.crypta.runtime.spi.QueueSupportPort;
import network.crypta.runtime.spi.RequestQueueUnavailableException;
import network.crypta.runtime.spi.TransferAccessPort;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class QueueToadletTest {

  private static final String TEST_FORM_PASSWORD = "queue-form-password";

  @Mock private HighLevelSimpleClient client;
  @Mock private QueuePagePort queuePagePort;
  @Mock private TransferAccessPort transferAccessPort;
  @Mock private QueueDownloadPort queueDownloadPort;
  @Mock private QueueInsertPort queueInsertPort;
  @Mock private QueueMutationPort queueMutationPort;
  @Mock private QueueSupportPort queueSupportPort;
  @Mock private QueueCompletionPort queueCompletionPort;
  @Mock private DarknetConnectionsPort darknetConnectionsPort;
  @Mock private DarknetMessagingPort darknetMessagingPort;
  @Mock private UserAlertManager alerts;
  @Mock private ToadletContext ctx;
  @Mock private HTTPRequest request;
  @Mock private ToadletContainer container;

  @TempDir Path tempDir;

  private PageMaker pageMaker;

  @BeforeEach
  void setUp() {
    pageMaker = stubPageMaker(new HTMLNode("div"));
    when(ctx.getPageMaker()).thenReturn(pageMaker);
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.getFormPassword()).thenReturn(TEST_FORM_PASSWORD);
    when(ctx.getAlertManager()).thenReturn(alerts);
    when(ctx.getContainer()).thenReturn(container);
    when(alerts.createSummary()).thenReturn(new HTMLNode("div", "id", "default-alert-summary"));
    when(container.publicGatewayMode()).thenReturn(false);
    doAnswer(invocation -> invocation.getArgument(0, HTMLNode.class).addChild("form"))
        .when(container)
        .addFormChild(any(HTMLNode.class), anyString(), anyString());
    when(queueSupportPort.isQueueBackendEnabled()).thenReturn(true);
    when(queueSupportPort.persistenceStatus())
        .thenReturn(
            new QueuePersistenceStatusSnapshot(
                false, false, tempDir.toFile(), tempDir.resolve("queue.db").toString()));
  }

  @Test
  void constructor_whenInstantiated_startsQueueCompletionTrackingForSelectedSide() {
    // Arrange
    QueueToadlet toadlet = createQueueToadlet(false);

    // Assert
    verify(queueCompletionPort).ensureTrackingStarted(false);
    assertEquals(QueueToadlet.PATH_DOWNLOADS, toadlet.path());
  }

  @Test
  void path_whenUploadsFlagTrue_returnsUploadsPath() {
    // Arrange
    QueueToadlet toadlet = createQueueToadlet(true);

    // Assert
    verify(queueCompletionPort).ensureTrackingStarted(true);
    assertEquals(QueueToadlet.PATH_UPLOADS, toadlet.path());
  }

  @Test
  void handleMethodGET_whenNormalQueueRequested_delegatesToQueuePagePortRenderPage()
      throws Exception {
    // Arrange
    QueueToadlet toadlet = createQueueToadlet(false);
    when(pageMaker.advancedMode(request, container)).thenReturn(true);
    when(request.getPath()).thenReturn(QueueToadlet.PATH_DOWNLOADS);
    when(request.isParameterSet("sortBy")).thenReturn(true);
    when(request.getParam("sortBy")).thenReturn("progress");
    when(request.isParameterSet("reversed")).thenReturn(true);
    when(queuePagePort.renderPage(any()))
        .thenReturn(new QueuePageSnapshot("Downloads", "<div id=\"queue-page\">queue</div>"));

    ByteArrayOutputStream body = captureBody(ctx);

    // Act
    toadlet.handleMethodGET(URI.create("http://localhost/downloads/"), request, ctx);

    // Assert
    ArgumentCaptor<QueuePageRequest> requestCaptor =
        ArgumentCaptor.forClass(QueuePageRequest.class);
    verify(queuePagePort).renderPage(requestCaptor.capture());
    QueuePageRequest queuePageRequest = requestCaptor.getValue();
    assertFalse(queuePageRequest.uploads());
    assertTrue(queuePageRequest.advancedMode());
    assertEquals("progress", queuePageRequest.sortBy());
    assertTrue(queuePageRequest.reversed());
    assertTrue(body.toString(StandardCharsets.UTF_8).contains("queue-page"));
  }

  @Test
  void handleMethodGET_whenCountPageRequested_delegatesToRenderCountPage() throws Exception {
    // Arrange
    QueueToadlet toadlet = createQueueToadlet(false);
    when(request.getPath()).thenReturn(QueueToadlet.PATH_DOWNLOADS + "countRequests.html");
    when(queuePagePort.renderCountPage(false))
        .thenReturn(new QueuePageSnapshot("Queue", "<div id=\"count-page\">count</div>"));

    ByteArrayOutputStream body = captureBody(ctx);

    // Act
    toadlet.handleMethodGET(
        URI.create("http://localhost/downloads/countRequests.html"), request, ctx);

    // Assert
    verify(queuePagePort).renderCountPage(false);
    verify(queuePagePort, never()).renderPage(any());
    verify(queuePagePort, never()).renderKeyList(anyBoolean());
    assertTrue(body.toString(StandardCharsets.UTF_8).contains("count-page"));
  }

  @Test
  void handleMethodGET_whenCountPageHasLeadingSlash_delegatesToRenderCountPage() throws Exception {
    // Arrange
    QueueToadlet toadlet = createQueueToadlet(false);
    when(request.getPath()).thenReturn(QueueToadlet.PATH_DOWNLOADS + "/countRequests.html");
    when(queuePagePort.renderCountPage(false))
        .thenReturn(new QueuePageSnapshot("Queue", "<div id=\"count-page\">count</div>"));

    // Act
    toadlet.handleMethodGET(
        URI.create("http://localhost/downloads//countRequests.html"), request, ctx);

    // Assert
    verify(queuePagePort).renderCountPage(false);
  }

  @Test
  void handleMethodGET_whenKeyListRequested_delegatesToRenderKeyList() throws Exception {
    // Arrange
    QueueToadlet toadlet = createQueueToadlet(true);
    when(request.getPath()).thenReturn(QueueToadlet.PATH_UPLOADS + "listKeys.txt");
    when(queuePagePort.renderKeyList(true)).thenReturn("CHK@key\n");

    ByteArrayOutputStream body = captureBody(ctx);

    // Act
    toadlet.handleMethodGET(URI.create("http://localhost/uploads/listKeys.txt"), request, ctx);

    // Assert
    verify(queuePagePort).renderKeyList(true);
    verify(queuePagePort, never()).renderPage(any());
    verify(queuePagePort, never()).renderCountPage(anyBoolean());
    assertEquals("CHK@key\n", body.toString(StandardCharsets.UTF_8));
  }

  @Test
  void handleMethodGET_whenSnapshotContainsPlaceholders_replacesRequestContextContent()
      throws Exception {
    // Arrange
    QueueToadlet toadlet = createQueueToadlet(false);
    UserAlertManager alertManager = mock(UserAlertManager.class);
    when(alertManager.createSummary()).thenReturn(new HTMLNode("div", "id", "alert-summary"));
    when(ctx.getAlertManager()).thenReturn(alertManager);
    when(request.getPath()).thenReturn(QueueToadlet.PATH_DOWNLOADS);
    when(request.isParameterSet("sortBy")).thenReturn(false);
    when(request.isParameterSet("reversed")).thenReturn(false);
    when(queuePagePort.renderPage(any()))
        .thenReturn(
            new QueuePageSnapshot(
                "Downloads",
                """
                <div id="detached-queue">queue</div>
                <!--CRYPTA_ALERT_SUMMARY-->
                <!--CRYPTA_QUEUE_FORM_PASSWORD-->
                """));

    ByteArrayOutputStream body = captureBody(ctx);

    // Act
    toadlet.handleMethodGET(URI.create("http://localhost/downloads/"), request, ctx);

    // Assert
    String html = body.toString(StandardCharsets.UTF_8);
    assertTrue(html.contains("detached-queue"));
    assertTrue(html.contains("alert-summary"));
    assertTrue(html.contains("formPassword"));
    assertTrue(html.contains(TEST_FORM_PASSWORD));
    assertFalse(html.contains("<!--CRYPTA_ALERT_SUMMARY-->"));
    assertFalse(html.contains("<!--CRYPTA_QUEUE_FORM_PASSWORD-->"));
  }

  @Test
  void handleMethodGET_whenQueueBackendDisabled_returnsBadRequestWithoutDelegating()
      throws Exception {
    // Arrange
    QueueToadlet toadlet = createQueueToadlet(false);
    when(queueSupportPort.isQueueBackendEnabled()).thenReturn(false);

    ByteArrayOutputStream body = captureBody(ctx);

    // Act
    toadlet.handleMethodGET(URI.create("http://localhost/downloads/"), request, ctx);

    // Assert
    String html = body.toString(StandardCharsets.UTF_8);
    assertTrue(html.contains("You need to enable the FCP server to access this page"));
    verify(queueSupportPort).isQueueBackendEnabled();
    verifyNoInteractions(queuePagePort);
  }

  @Test
  void handleMethodGET_whenPublicGatewayWithoutFullAccess_returnsUnauthorizedWithoutDelegating()
      throws Exception {
    // Arrange
    QueueToadlet toadlet = createQueueToadlet(false);
    when(container.publicGatewayMode()).thenReturn(true);
    when(ctx.isAllowedFullAccess()).thenReturn(false);

    ByteArrayOutputStream body = captureBody(ctx);

    // Act
    toadlet.handleMethodGET(URI.create("http://localhost/downloads/"), request, ctx);

    // Assert
    String html = body.toString(StandardCharsets.UTF_8);
    assertTrue(html.contains("You are not permitted access to this page."));
    verifyNoInteractions(queuePagePort);
  }

  @Test
  void handleMethodGET_whenQueuePagePortUnavailable_returnsPersistenceDisabledErrorPage()
      throws Exception {
    // Arrange
    QueueToadlet toadlet = createQueueToadlet(false);
    when(queueSupportPort.persistenceStatus())
        .thenReturn(
            new QueuePersistenceStatusSnapshot(
                false,
                false,
                tempDir.resolve("detached-persistent-temp").toFile(),
                tempDir.resolve("snapshot-only.db").toString()));
    when(request.getPath()).thenReturn(QueueToadlet.PATH_DOWNLOADS);
    when(request.isParameterSet("sortBy")).thenReturn(false);
    when(request.isParameterSet("reversed")).thenReturn(false);
    when(queuePagePort.renderPage(any()))
        .thenThrow(new RequestQueueUnavailableException("queue unavailable"));

    ByteArrayOutputStream body = captureBody(ctx);

    // Act
    toadlet.handleMethodGET(URI.create("http://localhost/downloads/"), request, ctx);

    // Assert
    String html = body.toString(StandardCharsets.UTF_8);
    assertTrue(html.contains("detached-persistent-temp"));
    assertTrue(html.contains("snapshot-only.db"));
    verify(queueSupportPort).persistenceStatus();
    verify(queuePagePort).renderPage(any());
  }

  @Test
  void handleMethodGET_whenQueueUnavailableAndAwaitingPassword_rendersPasswordPageWithoutPaths()
      throws Exception {
    // Arrange
    QueueToadlet toadlet = createQueueToadlet(false);
    when(queueSupportPort.persistenceStatus())
        .thenReturn(new QueuePersistenceStatusSnapshot(true, false, null, null));
    when(request.getPath()).thenReturn(QueueToadlet.PATH_DOWNLOADS);
    when(request.isParameterSet("sortBy")).thenReturn(false);
    when(request.isParameterSet("reversed")).thenReturn(false);
    when(queuePagePort.renderPage(any()))
        .thenThrow(new RequestQueueUnavailableException("queue unavailable"));

    ByteArrayOutputStream body = captureBody(ctx);

    // Act
    toadlet.handleMethodGET(URI.create("http://localhost/downloads/"), request, ctx);

    // Assert
    assertTrue(body.size() > 0);
    verify(ctx)
        .sendReplyHeaders(eq(500), eq("Internal Server Error"), any(), anyString(), anyLong());
    verify(container).addFormChild(any(HTMLNode.class), anyString(), anyString());
    verify(queueSupportPort).persistenceStatus();
  }

  private QueueToadlet createQueueToadlet(boolean uploads) {
    QueueToadlet toadlet =
        new QueueToadlet(
            client,
            uploads,
            new QueueToadletRuntimePorts(
                queuePagePort,
                transferAccessPort,
                queueDownloadPort,
                queueInsertPort,
                queueMutationPort,
                queueSupportPort,
                queueCompletionPort,
                darknetConnectionsPort,
                darknetMessagingPort));
    toadlet.container = container;
    return toadlet;
  }

  private PageMaker stubPageMaker(HTMLNode content) {
    HTMLNode root = new HTMLNode("html");
    HTMLNode head = root.addChild("head");
    root.addChild(content);
    PageNode page = new PageNode(root, head, content);

    PageMaker stub = mock(PageMaker.class);
    when(stub.getPageNode(anyString(), any(ToadletContext.class))).thenReturn(page);
    doAnswer(
            invocation -> {
              HTMLNode parent = invocation.getArgument(2);
              return parent.addChild("div");
            })
        .when(stub)
        .getInfobox(anyString(), anyString(), any(HTMLNode.class), any(), anyBoolean());
    return stub;
  }

  private ByteArrayOutputStream captureBody(ToadletContext context) throws Exception {
    ByteArrayOutputStream body = new ByteArrayOutputStream();
    doAnswer(_ -> null)
        .when(context)
        .sendReplyHeaders(anyInt(), anyString(), any(), anyString(), anyLong());
    doAnswer(
            invocation -> {
              byte[] data = invocation.getArgument(0);
              int offset = invocation.getArgument(1);
              int length = invocation.getArgument(2);
              body.write(data, offset, length);
              return null;
            })
        .when(context)
        .writeData(any(byte[].class), anyInt(), anyInt());
    return body;
  }
}
