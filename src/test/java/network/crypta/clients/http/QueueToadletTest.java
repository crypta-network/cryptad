package network.crypta.clients.http;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.net.MalformedURLException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Random;
import network.crypta.client.ArchiveManager;
import network.crypta.client.FetchContext;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.InsertContext;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientContextDefaults;
import network.crypta.client.async.ClientContextRafFactories;
import network.crypta.client.async.ClientContextRuntime;
import network.crypta.client.async.ClientContextServices;
import network.crypta.client.async.ClientContextStorageFactories;
import network.crypta.client.async.ClientLayerPersister;
import network.crypta.client.async.DatastoreChecker;
import network.crypta.client.async.HealingQueue;
import network.crypta.client.async.PersistentJob;
import network.crypta.client.async.USKManager;
import network.crypta.client.filter.LinkFilterExceptionProvider;
import network.crypta.clients.fcp.ClientGet;
import network.crypta.clients.fcp.ClientPut;
import network.crypta.clients.fcp.FCPServer;
import network.crypta.clients.fcp.PersistentRequestRoot;
import network.crypta.clients.fcp.RequestCompletionCallback;
import network.crypta.config.Config;
import network.crypta.crypt.MasterSecret;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.FreenetURI;
import network.crypta.node.ClientContextResources;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.ProgramDirectory;
import network.crypta.node.RequestStarterGroup;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.node.useralerts.UserEvent;
import network.crypta.runtime.spi.QueueDownloadPort;
import network.crypta.runtime.spi.QueueInsertPort;
import network.crypta.runtime.spi.QueueMutationPort;
import network.crypta.runtime.spi.QueuePagePort;
import network.crypta.runtime.spi.QueuePageRequest;
import network.crypta.runtime.spi.QueuePageSnapshot;
import network.crypta.runtime.spi.RequestQueueUnavailableException;
import network.crypta.runtime.spi.TransferAccessPort;
import network.crypta.support.HTMLNode;
import network.crypta.support.MemoryLimitedJobRunner;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.Ticker;
import network.crypta.support.api.HTTPRequest;
import network.crypta.support.api.LockableRandomAccessBufferFactory;
import network.crypta.support.compress.RealCompressor;
import network.crypta.support.io.FileRandomAccessBufferFactory;
import network.crypta.support.io.FilenameGenerator;
import network.crypta.support.io.PersistentFileTracker;
import network.crypta.support.io.PersistentTempBucketFactory;
import network.crypta.support.io.TempBucketFactory;
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
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class QueueToadletTest {

  private static final String TEST_FORM_PASSWORD = "queue-form-password";

  @Mock private HighLevelSimpleClient client;
  @Mock private FCPServer fcp;
  @Mock private QueuePagePort queuePagePort;
  @Mock private TransferAccessPort transferAccessPort;
  @Mock private QueueDownloadPort queueDownloadPort;
  @Mock private QueueInsertPort queueInsertPort;
  @Mock private QueueMutationPort queueMutationPort;
  @Mock private UserAlertManager alerts;
  @Mock private PriorityAwareExecutor executor;
  @Mock private ClientLayerPersister jobRunner;
  @Mock private ToadletContext ctx;
  @Mock private HTTPRequest request;
  @Mock private ToadletContainer container;

  @TempDir Path tempDir;

  private RequestCompletionCallback completionCallback;
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
    when(fcp.isEnabled()).thenReturn(true);
  }

  @Test
  void constructor_whenInstantiated_setsCompletionCallbackAndQueuesLoadJob() throws Exception {
    // Arrange
    QueueToadlet toadlet = createQueueToadlet(false);

    // Assert
    RequestCompletionCallback callback = getCompletionCallback();
    verify(fcp).setCompletionCallback(callback);
    verify(jobRunner, times(1)).queue(any(PersistentJob.class), anyInt());
    assertEquals(QueueToadlet.PATH_DOWNLOADS, toadlet.path());
  }

  @Test
  void path_whenUploadsFlagTrue_returnsUploadsPath() throws Exception {
    // Arrange
    QueueToadlet toadlet = createQueueToadlet(true);

    // Assert
    assertEquals(QueueToadlet.PATH_UPLOADS, toadlet.path());
  }

  @Test
  void notifySuccess_whenDownloadCompleted_recordsIdentifierAndRegistersAlert() throws Exception {
    // Arrange
    createQueueToadlet(false);
    clearInvocations(executor, alerts, jobRunner);

    ClientGet completedRequest = mock(ClientGet.class);
    when(completedRequest.getIdentifier()).thenReturn("download-1");
    when(completedRequest.hasFinished()).thenReturn(true);
    when(completedRequest.getURI()).thenReturn(sampleUri());
    when(completedRequest.getDataSize()).thenReturn(123L);

    // Act
    getCompletionCallback().notifySuccess(completedRequest);

    // Assert
    File completedList = tempDir.resolve("completed.list.downloads").toFile();
    assertTrue(completedList.exists());
    assertEquals("download-1\n", Files.readString(completedList.toPath()));

    ArgumentCaptor<UserEvent> alertCaptor = ArgumentCaptor.forClass(UserEvent.class);
    verify(alerts).register(alertCaptor.capture());
    assertTrue(alertCaptor.getValue().getClass().getSimpleName().contains("GetCompletedEvent"));
    verify(executor).execute(any(Runnable.class), anyString());
  }

  @Test
  void notifySuccess_whenDirectionMismatch_doesNothing() throws Exception {
    // Arrange
    createQueueToadlet(false);
    clearInvocations(executor, alerts);

    ClientPut uploadRequest = mock(ClientPut.class);

    // Act
    getCompletionCallback().notifySuccess(uploadRequest);

    // Assert
    File completedList = tempDir.resolve("completed.list.downloads").toFile();
    if (completedList.exists()) {
      assertEquals(0, Files.size(completedList.toPath()));
    }
    verifyNoInteractions(alerts);
    verify(executor, times(0)).execute(any(Runnable.class), anyString());
  }

  @Test
  void onRemove_whenEntryExists_removesAndPersistsEmptyList() throws Exception {
    // Arrange
    createQueueToadlet(false);
    clearInvocations(executor, alerts, jobRunner);

    ClientGet completedRequest = mock(ClientGet.class);
    when(completedRequest.getIdentifier()).thenReturn("download-2");
    when(completedRequest.hasFinished()).thenReturn(true);
    when(completedRequest.getURI()).thenReturn(sampleUri());
    when(completedRequest.getDataSize()).thenReturn(500L);

    getCompletionCallback().notifySuccess(completedRequest);
    clearInvocations(executor, alerts);

    // Act
    getCompletionCallback().onRemove(completedRequest);

    // Assert
    File completedList = tempDir.resolve("completed.list.downloads").toFile();
    assertTrue(completedList.exists());
    assertEquals(0, Files.readAllBytes(completedList.toPath()).length);

    Map<?, ?> completedGets = getCompletedGets();
    assertFalse(completedGets.containsKey("download-2"));
    verify(executor).execute(any(Runnable.class), anyString());
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
  void handleMethodGET_whenFcpDisabled_returnsBadRequestWithoutDelegating() throws Exception {
    // Arrange
    QueueToadlet toadlet = createQueueToadlet(false);
    when(fcp.isEnabled()).thenReturn(false);

    ByteArrayOutputStream body = captureBody(ctx);

    // Act
    toadlet.handleMethodGET(URI.create("http://localhost/downloads/"), request, ctx);

    // Assert
    String html = body.toString(StandardCharsets.UTF_8);
    assertTrue(html.contains("You need to enable the FCP server to access this page"));
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
    assertTrue(html.contains(tempDir.toString()));
    assertTrue(html.contains("queue.db"));
    verify(queuePagePort).renderPage(any());
  }

  private QueueToadlet createQueueToadlet(boolean uploads) throws Exception {
    ProgramDirectory userDir = new ProgramDirectory();
    userDir.move(tempDir.toString());

    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    when(node.userDir()).thenReturn(userDir);
    when(node.getUserDir()).thenReturn(userDir.dir());
    when(node.awaitingPassword()).thenReturn(false);
    when(node.isStopping()).thenReturn(false);
    when(node.getDatabasePath()).thenReturn(tempDir.resolve("queue.db").toString());

    RequestStarterGroup starters = mock(RequestStarterGroup.class);
    NodeClientCore core = mock(NodeClientCore.class);
    when(core.getNode()).thenReturn(node);
    when(core.getAlerts()).thenReturn(alerts);
    when(core.getPersistentTempDir()).thenReturn(tempDir.toFile());

    NodeNetworkSubsystem network = mock(NodeNetworkSubsystem.class);
    when(node.network()).thenReturn(network);
    when(network.executor()).thenReturn(executor);

    ClientContext context = createClientContext();
    context.init(starters, alerts);
    when(core.getClientContext()).thenReturn(context);

    when(fcp.getGlobalRequest(anyString())).thenReturn(null);
    doAnswer(
            invocation -> {
              completionCallback = invocation.getArgument(0);
              return null;
            })
        .when(fcp)
        .setCompletionCallback(any(RequestCompletionCallback.class));

    doAnswer(
            invocation -> {
              PersistentJob job = invocation.getArgument(0);
              job.run(null);
              return null;
            })
        .when(jobRunner)
        .queue(any(PersistentJob.class), anyInt());

    doAnswer(
            invocation -> {
              Runnable runnable = invocation.getArgument(0);
              runnable.run();
              return null;
            })
        .when(executor)
        .execute(any(Runnable.class), anyString());

    doAnswer(
            invocation -> {
              Runnable runnable = invocation.getArgument(0);
              runnable.run();
              return null;
            })
        .when(executor)
        .execute(any(Runnable.class));

    QueueToadlet toadlet =
        new QueueToadlet(
            core,
            fcp,
            client,
            uploads,
            new QueueToadletRuntimePorts(
                queuePagePort,
                transferAccessPort,
                queueDownloadPort,
                queueInsertPort,
                queueMutationPort));
    toadlet.container = container;
    return toadlet;
  }

  private ClientContext createClientContext() {
    ArchiveManager archiveManager = mock(ArchiveManager.class);
    PersistentTempBucketFactory ptbf = mock(PersistentTempBucketFactory.class);
    TempBucketFactory tbf = mock(TempBucketFactory.class);
    PersistentFileTracker tracker = mock(PersistentFileTracker.class);
    HealingQueue hq = mock(HealingQueue.class);
    USKManager uskManager = mock(USKManager.class);
    RandomSource strongRandom = mock(RandomSource.class);
    Ticker ticker = mock(Ticker.class);
    MemoryLimitedJobRunner memoryLimitedJobRunner = mock(MemoryLimitedJobRunner.class);
    FilenameGenerator fg = mock(FilenameGenerator.class);
    LockableRandomAccessBufferFactory rafFactory = mock(LockableRandomAccessBufferFactory.class);
    LockableRandomAccessBufferFactory persistentRAFFactory =
        mock(LockableRandomAccessBufferFactory.class);
    FileRandomAccessBufferFactory fileRAFTransient = mock(FileRandomAccessBufferFactory.class);
    FileRandomAccessBufferFactory fileRAFPersistent = mock(FileRandomAccessBufferFactory.class);
    RealCompressor rc = mock(RealCompressor.class);
    DatastoreChecker checker = mock(DatastoreChecker.class);
    PersistentRequestRoot persistentRoot = mock(PersistentRequestRoot.class);
    MasterSecret masterSecret = mock(MasterSecret.class);
    LinkFilterExceptionProvider linkFilterExceptionProvider =
        mock(LinkFilterExceptionProvider.class);
    FetchContext fetchContext = mock(FetchContext.class);
    InsertContext insertContext = mock(InsertContext.class);
    Config config = mock(Config.class);

    return new ClientContext(
        1L,
        new ClientContextRuntime(
            jobRunner,
            executor,
            memoryLimitedJobRunner,
            ticker,
            strongRandom,
            new Random(123),
            masterSecret),
        new ClientContextStorageFactories(
            ptbf, tbf, tracker, fg, fg, fileRAFTransient, fileRAFPersistent),
        new ClientContextRafFactories(rafFactory, persistentRAFFactory),
        new ClientContextServices(
            new ClientContextResources(archiveManager, hq),
            uskManager,
            rc,
            checker,
            persistentRoot,
            linkFilterExceptionProvider),
        new ClientContextDefaults(fetchContext, insertContext, config));
  }

  private FreenetURI sampleUri() {
    try {
      return new FreenetURI(
          "CHK@DTCDUmnkKFlrJi9UlDDVqXlktsIXvAJ~ZTseyx5cAZs,PmA2rLgWZKVyMXxSn-ZihSskPYDTY19uhrMwqDV-~Sk,AAICAAI/index_d51.xml");
    } catch (MalformedURLException e) {
      throw new IllegalStateException(e);
    }
  }

  @SuppressWarnings("unchecked")
  private Map<String, ?> getCompletedGets() throws NoSuchFieldException, IllegalAccessException {
    Object tracker = getCompletionTracker();
    var field = tracker.getClass().getDeclaredField("completedGets");
    field.setAccessible(true);
    return (Map<String, ?>) field.get(tracker);
  }

  private RequestCompletionCallback getCompletionCallback() {
    return (RequestCompletionCallback) getCompletionTracker();
  }

  private Object getCompletionTracker() {
    if (completionCallback == null) {
      throw new IllegalStateException("Completion callback was not captured.");
    }
    return completionCallback;
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
