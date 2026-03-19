package network.crypta.clients.http;

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
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
import network.crypta.clients.fcp.FCPServer;
import network.crypta.clients.fcp.PersistentRequestRoot;
import network.crypta.clients.fcp.RequestCompletionCallback;
import network.crypta.config.Config;
import network.crypta.crypt.MasterSecret;
import network.crypta.crypt.RandomSource;
import network.crypta.node.ClientContextResources;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.ProgramDirectory;
import network.crypta.node.RequestStarterGroup;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.runtime.spi.DarknetConnectionsPort;
import network.crypta.runtime.spi.DarknetMessagingPort;
import network.crypta.runtime.spi.QueueDownloadPort;
import network.crypta.runtime.spi.QueueInsertPort;
import network.crypta.runtime.spi.QueueMutationPort;
import network.crypta.runtime.spi.QueuePagePort;
import network.crypta.runtime.spi.QueuePersistenceStatusSnapshot;
import network.crypta.runtime.spi.QueueSupportPort;
import network.crypta.runtime.spi.RequestQueueUnavailableException;
import network.crypta.runtime.spi.TransferAccessPort;
import network.crypta.support.HTMLNode;
import network.crypta.support.MemoryLimitedJobRunner;
import network.crypta.support.MultiValueTable;
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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings("java:S100")
class QueueToadletPostMutationTest {

  @Mock private HighLevelSimpleClient client;
  @Mock private FCPServer fcp;
  @Mock private QueuePagePort queuePagePort;
  @Mock private TransferAccessPort transferAccessPort;
  @Mock private QueueDownloadPort queueDownloadPort;
  @Mock private QueueInsertPort queueInsertPort;
  @Mock private QueueMutationPort queueMutationPort;
  @Mock private QueueSupportPort queueSupportPort;
  @Mock private DarknetConnectionsPort darknetConnectionsPort;
  @Mock private DarknetMessagingPort darknetMessagingPort;
  @Mock private UserAlertManager alerts;
  @Mock private PriorityAwareExecutor executor;
  @Mock private ClientLayerPersister jobRunner;
  @Mock private ToadletContext ctx;
  @Mock private ToadletContainer container;

  @TempDir Path tempDir;
  private boolean originalNoConfirmPanic;

  @BeforeEach
  void setUp() {
    PageMaker pageMaker = stubPageMaker(new HTMLNode("div"));
    when(ctx.getPageMaker()).thenReturn(pageMaker);
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.getFormPassword()).thenReturn("queue-form-password");
    when(ctx.getAlertManager()).thenReturn(alerts);
    when(ctx.getContainer()).thenReturn(container);
    when(alerts.createSummary()).thenReturn(new HTMLNode("div", "id", "default-alert-summary"));
    when(container.publicGatewayMode()).thenReturn(false);
    when(queueSupportPort.isQueueBackendEnabled()).thenReturn(true);
    when(queueSupportPort.persistenceStatus())
        .thenReturn(
            new QueuePersistenceStatusSnapshot(
                false, false, tempDir.toFile(), tempDir.resolve("queue.db").toString()));
    originalNoConfirmPanic = SimpleToadletServer.noConfirmPanic;
  }

  @AfterEach
  void tearDown() {
    SimpleToadletServer.noConfirmPanic = originalNoConfirmPanic;
  }

  @Test
  void handleMethodPOST_whenRemoveRequestSelected_callsQueueMutationPort() throws Exception {
    QueueToadlet toadlet = createQueueToadlet(false);
    HTTPRequest request =
        createRequest(
            Map.of(
                "remove_request", "yes",
                "identifier-a", "download-1",
                "identifier-b", "download-2"));

    toadlet.handleMethodPOST(URI.create("http://localhost/downloads/"), request, ctx);

    String location = captureRedirectLocation(ctx);
    verify(queueMutationPort).removeRequests(java.util.List.of("download-1", "download-2"));
    assertEquals(QueueToadlet.PATH_DOWNLOADS, location);
  }

  @Test
  void handleMethodPOST_whenRestartRequestSelected_callsQueueMutationPortWithDisableFilterData()
      throws Exception {
    QueueToadlet toadlet = createQueueToadlet(false);
    HTTPRequest request =
        createRequest(
            Map.of(
                "restart_request", "yes",
                "disableFilterData", "on",
                "identifier-a", "download-1"));

    toadlet.handleMethodPOST(URI.create("http://localhost/downloads/"), request, ctx);

    captureRedirectLocation(ctx);
    verify(queueMutationPort).restartRequests(java.util.List.of("download-1"), true);
  }

  @Test
  void handleMethodPOST_whenChangePriorityTopSelected_callsQueueMutationPort() throws Exception {
    QueueToadlet toadlet = createQueueToadlet(false);
    HTTPRequest request =
        createRequest(
            Map.of(
                "change_priority_top", "yes",
                "priority_top", "4",
                "identifier-a", "download-1"));

    toadlet.handleMethodPOST(URI.create("http://localhost/downloads/"), request, ctx);

    captureRedirectLocation(ctx);
    verify(queueMutationPort).changePriority(java.util.List.of("download-1"), (short) 4);
  }

  @Test
  void handleMethodPOST_whenChangePriorityBottomSelected_callsQueueMutationPort() throws Exception {
    QueueToadlet toadlet = createQueueToadlet(false);
    HTTPRequest request =
        createRequest(
            Map.of(
                "change_priority_bottom", "yes",
                "priority_bottom", "2",
                "identifier-a", "download-1"));

    toadlet.handleMethodPOST(URI.create("http://localhost/downloads/"), request, ctx);

    captureRedirectLocation(ctx);
    verify(queueMutationPort).changePriority(java.util.List.of("download-1"), (short) 2);
  }

  @Test
  void handleMethodPOST_whenRemoveFinishedUploadsSelected_callsQueueMutationPort()
      throws Exception {
    QueueToadlet toadlet = createQueueToadlet(true);
    HTTPRequest request = createRequest(Map.of("remove_finished_uploads_request", "yes"));

    toadlet.handleMethodPOST(URI.create("http://localhost/uploads/"), request, ctx);

    captureRedirectLocation(ctx);
    verify(queueMutationPort).removeFinishedUploads();
  }

  @Test
  void handleMethodPOST_whenRemoveFinishedDownloadsSelected_callsQueueMutationPort()
      throws Exception {
    QueueToadlet toadlet = createQueueToadlet(false);
    HTTPRequest request = createRequest(Map.of("remove_finished_downloads_request", "yes"));

    toadlet.handleMethodPOST(URI.create("http://localhost/downloads/"), request, ctx);

    captureRedirectLocation(ctx);
    verify(queueMutationPort).removeFinishedDownloads();
  }

  @Test
  void handleMethodPOST_whenQueueMutationUnavailable_returnsPersistenceDisabledErrorPage()
      throws Exception {
    QueueToadlet toadlet = createQueueToadlet(false);
    Path detachedTempDir = tempDir.resolve("detached-persistent-temp");
    HTTPRequest request =
        createRequest(Map.of("remove_request", "yes", "identifier-a", "download-1"));
    when(queueSupportPort.persistenceStatus())
        .thenReturn(
            new QueuePersistenceStatusSnapshot(
                false,
                false,
                detachedTempDir.toFile(),
                tempDir.resolve("detached-queue.db").toString()));
    doThrow(new RequestQueueUnavailableException("queue unavailable"))
        .when(queueMutationPort)
        .removeRequests(java.util.List.of("download-1"));

    ByteArrayOutputStream body = captureBody(ctx);

    toadlet.handleMethodPOST(URI.create("http://localhost/downloads/"), request, ctx);

    String html = body.toString(StandardCharsets.UTF_8);
    assertTrue(html.contains(detachedTempDir.toString()));
    assertTrue(html.contains("detached-queue.db"));
    verify(queueSupportPort).persistenceStatus();
  }

  @Test
  void handleMethodPOST_whenPanicSelectedAndNoConfirmPanic_callsSupportPortAndRendersBeforeFinish()
      throws Exception {
    QueueToadlet toadlet = createQueueToadlet(false);
    SimpleToadletServer.noConfirmPanic = true;
    HTTPRequest request = createRequest(Map.of("panic", "yes"));
    ByteArrayOutputStream body = captureBody(ctx);

    toadlet.handleMethodPOST(URI.create("http://localhost/downloads/"), request, ctx);

    InOrder inOrder = org.mockito.Mockito.inOrder(queueSupportPort, ctx);
    inOrder.verify(queueSupportPort).beginPanic();
    inOrder.verify(ctx).sendReplyHeaders(eq(200), eq("OK"), any(), anyString(), anyLong());
    inOrder.verify(ctx).writeData(any(byte[].class), anyInt(), anyInt());
    inOrder.verify(queueSupportPort).finishPanic();
    assertTrue(body.size() > 0);
  }

  @Test
  void handleMethodPOST_whenConfirmPanicSelected_callsSupportPortAndRendersBeforeFinish()
      throws Exception {
    QueueToadlet toadlet = createQueueToadlet(false);
    SimpleToadletServer.noConfirmPanic = false;
    HTTPRequest request = createRequest(Map.of("confirmpanic", "yes"));
    ByteArrayOutputStream body = captureBody(ctx);

    toadlet.handleMethodPOST(URI.create("http://localhost/downloads/"), request, ctx);

    InOrder inOrder = org.mockito.Mockito.inOrder(queueSupportPort, ctx);
    inOrder.verify(queueSupportPort).beginPanic();
    inOrder.verify(ctx).sendReplyHeaders(eq(200), eq("OK"), any(), anyString(), anyLong());
    inOrder.verify(ctx).writeData(any(byte[].class), anyInt(), anyInt());
    inOrder.verify(queueSupportPort).finishPanic();
    assertTrue(body.size() > 0);
  }

  private QueueToadlet createQueueToadlet(boolean uploads) throws Exception {
    ProgramDirectory userDir = new ProgramDirectory();
    userDir.move(tempDir.toString());

    Node node = org.mockito.Mockito.mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    when(node.userDir()).thenReturn(userDir);
    when(node.getUserDir()).thenReturn(userDir.dir());
    when(node.awaitingPassword()).thenReturn(false);
    when(node.isStopping()).thenReturn(false);
    when(node.getDatabasePath()).thenReturn(tempDir.resolve("queue.db").toString());

    RequestStarterGroup starters = org.mockito.Mockito.mock(RequestStarterGroup.class);
    NodeClientCore core = org.mockito.Mockito.mock(NodeClientCore.class);
    when(core.getNode()).thenReturn(node);
    when(core.getAlerts()).thenReturn(alerts);
    when(core.getPersistentTempDir()).thenReturn(tempDir.toFile());

    NodeNetworkSubsystem network = org.mockito.Mockito.mock(NodeNetworkSubsystem.class);
    when(node.network()).thenReturn(network);
    when(network.executor()).thenReturn(executor);

    ClientContext context = createClientContext();
    context.init(starters, alerts);
    when(core.getClientContext()).thenReturn(context);

    when(fcp.getGlobalRequest(anyString())).thenReturn(null);
    doAnswer(_ -> null).when(fcp).setCompletionCallback(any(RequestCompletionCallback.class));

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
                queueMutationPort,
                queueSupportPort,
                darknetConnectionsPort,
                darknetMessagingPort));
    toadlet.container = container;
    return toadlet;
  }

  private ClientContext createClientContext() {
    ArchiveManager archiveManager = org.mockito.Mockito.mock(ArchiveManager.class);
    PersistentTempBucketFactory ptbf = org.mockito.Mockito.mock(PersistentTempBucketFactory.class);
    TempBucketFactory tbf = org.mockito.Mockito.mock(TempBucketFactory.class);
    PersistentFileTracker tracker = org.mockito.Mockito.mock(PersistentFileTracker.class);
    HealingQueue hq = org.mockito.Mockito.mock(HealingQueue.class);
    USKManager uskManager = org.mockito.Mockito.mock(USKManager.class);
    RandomSource strongRandom = org.mockito.Mockito.mock(RandomSource.class);
    Ticker ticker = org.mockito.Mockito.mock(Ticker.class);
    MemoryLimitedJobRunner memoryLimitedJobRunner =
        org.mockito.Mockito.mock(MemoryLimitedJobRunner.class);
    FilenameGenerator fg = org.mockito.Mockito.mock(FilenameGenerator.class);
    LockableRandomAccessBufferFactory rafFactory =
        org.mockito.Mockito.mock(LockableRandomAccessBufferFactory.class);
    LockableRandomAccessBufferFactory persistentRAFFactory =
        org.mockito.Mockito.mock(LockableRandomAccessBufferFactory.class);
    FileRandomAccessBufferFactory fileRAFTransient =
        org.mockito.Mockito.mock(FileRandomAccessBufferFactory.class);
    FileRandomAccessBufferFactory fileRAFPersistent =
        org.mockito.Mockito.mock(FileRandomAccessBufferFactory.class);
    RealCompressor rc = org.mockito.Mockito.mock(RealCompressor.class);
    DatastoreChecker checker = org.mockito.Mockito.mock(DatastoreChecker.class);
    PersistentRequestRoot persistentRoot = org.mockito.Mockito.mock(PersistentRequestRoot.class);
    MasterSecret masterSecret = org.mockito.Mockito.mock(MasterSecret.class);
    LinkFilterExceptionProvider linkFilterExceptionProvider =
        org.mockito.Mockito.mock(LinkFilterExceptionProvider.class);
    FetchContext fetchContext = org.mockito.Mockito.mock(FetchContext.class);
    InsertContext insertContext = org.mockito.Mockito.mock(InsertContext.class);
    Config config = org.mockito.Mockito.mock(Config.class);

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

  private HTTPRequest createRequest(Map<String, String> parts) {
    HTTPRequest request = org.mockito.Mockito.mock(HTTPRequest.class);
    when(request.getParts()).thenReturn(parts.keySet().stream().sorted().toArray(String[]::new));
    when(request.isPartSet(anyString()))
        .thenAnswer(invocation -> parts.containsKey(invocation.getArgument(0, String.class)));
    when(request.getPartAsStringFailsafe(anyString(), anyInt()))
        .thenAnswer(invocation -> parts.getOrDefault(invocation.getArgument(0, String.class), ""));
    return request;
  }

  @SuppressWarnings("unchecked")
  private String captureRedirectLocation(ToadletContext context) throws Exception {
    ArgumentCaptor<MultiValueTable<String, String>> headersCaptor =
        ArgumentCaptor.forClass(MultiValueTable.class);
    verify(context)
        .sendReplyHeaders(
            eq(301), eq("Moved Permanently"), headersCaptor.capture(), anyString(), anyLong());
    return headersCaptor.getValue().getFirst("Location");
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

  private PageMaker stubPageMaker(HTMLNode content) {
    HTMLNode root = new HTMLNode("html");
    HTMLNode head = root.addChild("head");
    root.addChild(content);
    PageNode page = new PageNode(root, head, content);

    PageMaker stub = org.mockito.Mockito.mock(PageMaker.class);
    doReturn(page).when(stub).getPageNode(anyString(), any(ToadletContext.class));
    doReturn(page)
        .when(stub)
        .getPageNode(anyString(), any(ToadletContext.class), any(PageMaker.RenderParameters.class));
    doAnswer(
            invocation -> {
              HTMLNode parent = invocation.getArgument(2);
              return parent.addChild("div");
            })
        .when(stub)
        .getInfobox(anyString(), anyString(), any(HTMLNode.class), any(), anyBoolean());
    return stub;
  }
}
