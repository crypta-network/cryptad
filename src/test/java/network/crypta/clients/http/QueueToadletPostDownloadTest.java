package network.crypta.clients.http;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
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
import network.crypta.runtime.spi.QueueDownloadPort;
import network.crypta.runtime.spi.QueueDownloadRejectedException;
import network.crypta.runtime.spi.QueueDownloadRequest;
import network.crypta.runtime.spi.QueueMutationPort;
import network.crypta.runtime.spi.QueuePagePort;
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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings("java:S100")
class QueueToadletPostDownloadTest {

  @Mock private HighLevelSimpleClient client;
  @Mock private FCPServer fcp;
  @Mock private QueuePagePort queuePagePort;
  @Mock private TransferAccessPort transferAccessPort;
  @Mock private QueueDownloadPort queueDownloadPort;
  @Mock private QueueMutationPort queueMutationPort;
  @Mock private UserAlertManager alerts;
  @Mock private PriorityAwareExecutor executor;
  @Mock private ClientLayerPersister jobRunner;
  @Mock private ToadletContext ctx;
  @Mock private ToadletContainer container;

  @TempDir Path tempDir;

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
    when(queueDownloadPort.isDiskDownloadDisabled()).thenReturn(false);
  }

  @Test
  void handleMethodPOST_whenSingleDownloadRequested_callsQueueDownloadPort() throws Exception {
    QueueToadlet toadlet = createQueueToadlet();
    Path downloadsDir = Files.createDirectories(tempDir.resolve("downloads"));
    String downloadPath = downloadsDir.toString();
    when(transferAccessPort.allowDownloadTo(any(File.class))).thenReturn(true);
    HTTPRequest request =
        createRequest(
            Map.of(
                "download", "yes",
                "key", "CHK@",
                "type", "text/plain",
                "persistence", "forever",
                "return-type", "disk",
                "path", downloadPath,
                "filterData", "on"));

    toadlet.handleMethodPOST(URI.create("http://localhost/downloads/"), request, ctx);

    assertEquals(QueueToadlet.PATH_DOWNLOADS, captureRedirectLocation(ctx));
    ArgumentCaptor<QueueDownloadRequest> requestCaptor =
        ArgumentCaptor.forClass(QueueDownloadRequest.class);
    verify(queueDownloadPort).enqueueDownload(requestCaptor.capture());
    QueueDownloadRequest queueRequest = requestCaptor.getValue();
    assertEquals("CHK@", queueRequest.fetchUri());
    assertTrue(queueRequest.filterData());
    assertEquals("text/plain", queueRequest.expectedMimeType());
    assertEquals("forever", queueRequest.persistenceType());
    assertEquals("disk", queueRequest.returnType());
    assertEquals(new File(downloadPath), queueRequest.downloadsDir());
  }

  @Test
  void handleMethodPOST_whenBulkDownloadsRequested_callsQueueDownloadPortOncePerValidKey()
      throws Exception {
    QueueToadlet toadlet = createQueueToadlet();
    Path downloadsDir = Files.createDirectories(tempDir.resolve("bulk-downloads"));
    String downloadPath = downloadsDir.toString();
    when(transferAccessPort.allowDownloadTo(any(File.class))).thenReturn(true);
    ByteArrayOutputStream body = captureBody(ctx);
    HTTPRequest request =
        createRequest(
            Map.of(
                "bulkDownloads", "CHK@\nnot-a-uri\n\nSSK@\n",
                "target", "disk",
                "path", downloadPath,
                "filterData", "on"));

    toadlet.handleMethodPOST(URI.create("http://localhost/downloads/"), request, ctx);

    ArgumentCaptor<QueueDownloadRequest> requestCaptor =
        ArgumentCaptor.forClass(QueueDownloadRequest.class);
    verify(queueDownloadPort, times(2)).enqueueDownload(requestCaptor.capture());
    List<QueueDownloadRequest> requests = requestCaptor.getAllValues();
    assertEquals("CHK@", requests.getFirst().fetchUri());
    assertEquals("SSK@", requests.get(1).fetchUri());
    assertEquals("disk", requests.getFirst().returnType());
    assertEquals(new File(downloadPath), requests.getFirst().downloadsDir());
    assertTrue(body.toString(StandardCharsets.UTF_8).contains("not-a-uri"));
  }

  @Test
  void handleMethodPOST_whenSingleDownloadRejected_returnsDiskConfigErrorPage() throws Exception {
    QueueToadlet toadlet = createQueueToadlet();
    Path downloadsDir = Files.createDirectories(tempDir.resolve("downloads"));
    when(transferAccessPort.allowDownloadTo(any(File.class))).thenReturn(true);
    doThrow(new QueueDownloadRejectedException("rejected"))
        .when(queueDownloadPort)
        .enqueueDownload(any(QueueDownloadRequest.class));

    toadlet.handleMethodPOST(
        URI.create("http://localhost/downloads/"),
        createRequest(
            Map.of(
                "download", "yes",
                "key", "CHK@",
                "persistence", "forever",
                "return-type", "disk",
                "path", downloadsDir.toString())),
        ctx);

    verify(queueDownloadPort).enqueueDownload(any(QueueDownloadRequest.class));
    verify(ctx).sendReplyHeaders(eq(400), eq("Bad request"), any(), anyString(), anyLong());
  }

  @Test
  void handleMethodPOST_whenBulkQueueUnavailable_rendersBulkFailureResultPage() throws Exception {
    QueueToadlet toadlet = createQueueToadlet();
    doThrow(new RequestQueueUnavailableException("queue unavailable"))
        .when(queueDownloadPort)
        .enqueueDownload(any(QueueDownloadRequest.class));
    ByteArrayOutputStream body = captureBody(ctx);

    toadlet.handleMethodPOST(
        URI.create("http://localhost/downloads/"),
        createRequest(Map.of("bulkDownloads", "CHK@\n", "target", "direct")),
        ctx);

    String html = body.toString(StandardCharsets.UTF_8);
    assertTrue(html.contains("CHK@"));
    assertFalse(html.contains("queue.db"));
    verify(ctx).sendReplyHeaders(eq(200), eq("OK"), any(), anyString(), anyLong());
  }

  @Test
  void handleMethodPOST_whenBulkQueueUnavailableAfterPartialSuccess_preservesAcceptedKeys()
      throws Exception {
    QueueToadlet toadlet = createQueueToadlet();
    doNothing()
        .doThrow(new RequestQueueUnavailableException("queue unavailable"))
        .when(queueDownloadPort)
        .enqueueDownload(any(QueueDownloadRequest.class));
    ByteArrayOutputStream body = captureBody(ctx);

    toadlet.handleMethodPOST(
        URI.create("http://localhost/downloads/"),
        createRequest(Map.of("bulkDownloads", "CHK@\nSSK@\n", "target", "direct")),
        ctx);

    String html = body.toString(StandardCharsets.UTF_8);
    assertTrue(html.contains("CHK@"));
    assertTrue(html.contains("SSK@"));
    assertFalse(html.contains("queue.db"));
    verify(queueDownloadPort, times(2)).enqueueDownload(any(QueueDownloadRequest.class));
    verify(ctx).sendReplyHeaders(eq(200), eq("OK"), any(), anyString(), anyLong());
  }

  @Test
  void handleMethodPOST_whenDownloadPathDisallowed_returnsDisallowedPageWithoutQueueDownloadCall()
      throws Exception {
    QueueToadlet toadlet = createQueueToadlet();
    String downloadPath = tempDir.resolve("blocked").toString();
    when(transferAccessPort.allowDownloadTo(any(File.class))).thenReturn(false);
    ByteArrayOutputStream body = captureBody(ctx);

    toadlet.handleMethodPOST(
        URI.create("http://localhost/downloads/"),
        createRequest(
            Map.of(
                "download", "yes",
                "key", "CHK@",
                "persistence", "forever",
                "return-type", "disk",
                "path", downloadPath)),
        ctx);

    String html = body.toString(StandardCharsets.UTF_8);
    assertTrue(html.contains(downloadPath));
    assertTrue(html.contains("disallowed"));
    verify(queueDownloadPort, never()).enqueueDownload(any(QueueDownloadRequest.class));
  }

  @Test
  void handleMethodPOST_whenDiskDownloadsDisabled_fallsBackToDirectReturnWithoutPathCheck()
      throws Exception {
    QueueToadlet toadlet = createQueueToadlet();
    when(queueDownloadPort.isDiskDownloadDisabled()).thenReturn(true);

    toadlet.handleMethodPOST(
        URI.create("http://localhost/downloads/"),
        createRequest(
            Map.of(
                "download", "yes",
                "key", "CHK@",
                "persistence", "forever",
                "return-type", "disk",
                "path", tempDir.resolve("downloads").toString())),
        ctx);

    ArgumentCaptor<QueueDownloadRequest> requestCaptor =
        ArgumentCaptor.forClass(QueueDownloadRequest.class);
    verify(queueDownloadPort).enqueueDownload(requestCaptor.capture());
    QueueDownloadRequest queueRequest = requestCaptor.getValue();
    assertEquals("direct", queueRequest.returnType());
    assertNull(queueRequest.downloadsDir());
    verify(transferAccessPort, never()).allowDownloadTo(any(File.class));
  }

  private QueueToadlet createQueueToadlet() throws Exception {
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
            false,
            new QueueToadletRuntimePorts(
                queuePagePort, transferAccessPort, queueDownloadPort, queueMutationPort));
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
}
