package network.crypta.clients.http;

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
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
import network.crypta.l10n.NodeL10n;
import network.crypta.node.ClientContextResources;
import network.crypta.node.DarknetPeerNode;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.ProgramDirectory;
import network.crypta.node.RequestStarterGroup;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.runtime.spi.DarknetConnectionPeerSnapshot;
import network.crypta.runtime.spi.DarknetConnectionsPort;
import network.crypta.runtime.spi.DarknetMessagingPort;
import network.crypta.runtime.spi.QueueDownloadPort;
import network.crypta.runtime.spi.QueueInsertPort;
import network.crypta.runtime.spi.QueueMutationPort;
import network.crypta.runtime.spi.QueuePagePort;
import network.crypta.runtime.spi.QueuePersistenceStatusSnapshot;
import network.crypta.runtime.spi.QueueSupportPort;
import network.crypta.runtime.spi.TransferAccessPort;
import network.crypta.runtime.spi.UnknownPeerException;
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
import org.junit.jupiter.api.BeforeAll;
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
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings("java:S100")
class QueueToadletRecommendTest {

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

  private Node node;

  @BeforeAll
  static void initL10n() {
    new NodeL10n();
  }

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
    when(ctx.addFormChild(any(HTMLNode.class), anyString(), anyString()))
        .thenAnswer(
            invocation -> {
              HTMLNode parent = invocation.getArgument(0);
              HTMLNode form = new HTMLNode("form");
              parent.addChild(form);
              return form;
            });
  }

  @Test
  void handleMethodPOST_whenRecommendFormRequested_rendersDetachedPeersAndLegacyCheckboxNames()
      throws Exception {
    QueueToadlet toadlet = createQueueToadlet();
    when(container.isFProxyJavascriptEnabled()).thenReturn(true);
    when(node.isFProxyJavascriptEnabled()).thenReturn(false);
    when(darknetConnectionsPort.listPeers()).thenReturn(List.of(alicePeer(), bobPeer()));
    ByteArrayOutputStream body = captureBody(ctx);

    toadlet.handleMethodPOST(
        URI.create("http://localhost/downloads/"),
        createRequest(
            Map.of("recommend_request", "yes", "identifier-a", "download-1", "key-a", "CHK@")),
        ctx);

    String html = body.toString(StandardCharsets.UTF_8);
    assertTrue(html.contains("Alice"));
    assertTrue(html.contains("Bob"));
    assertTrue(html.contains("node_42"));
    assertTrue(html.contains("node_99"));
    assertTrue(html.contains("recommend_uri"));
    assertTrue(html.contains("darknet_connections"));
    verify(darknetConnectionsPort).listPeers();
  }

  @Test
  void handleMethodPOST_whenRecommendFormRequestedAndJavascriptDisabled_omitsCheckAllScript()
      throws Exception {
    QueueToadlet toadlet = createQueueToadlet();
    when(container.isFProxyJavascriptEnabled()).thenReturn(false);
    when(node.isFProxyJavascriptEnabled()).thenReturn(true);
    when(darknetConnectionsPort.listPeers()).thenReturn(List.of(alicePeer()));
    ByteArrayOutputStream body = captureBody(ctx);

    toadlet.handleMethodPOST(
        URI.create("http://localhost/downloads/"),
        createRequest(
            Map.of("recommend_request", "yes", "identifier-a", "download-1", "key-a", "CHK@")),
        ctx);

    String html = body.toString(StandardCharsets.UTF_8);
    assertFalse(html.contains("/static/js/checkall.js"));
    assertFalse(html.contains("checkAll(this, 'darknet_connections')"));
  }

  @Test
  void handleMethodPOST_whenRecommendSubmitted_callsRuntimePortOnlyForSelectedPeers()
      throws Exception {
    QueueToadlet toadlet = createQueueToadlet();
    when(darknetConnectionsPort.listPeers()).thenReturn(List.of(alicePeer(), bobPeer()));

    toadlet.handleMethodPOST(
        URI.create("http://localhost/downloads/"),
        createRequest(
            Map.of(
                "recommend_uri", "yes",
                "description", "look at these",
                "key-0", "CHK@",
                "key-1", "SSK@",
                "node_42", "on")),
        ctx);

    verify(darknetMessagingPort)
        .recommendDownloads("peer-1", List.of("CHK@", "SSK@"), "look at these");
    verify(darknetMessagingPort, never()).recommendDownloads(eq("peer-2"), any(), anyString());
    assertEquals(QueueToadlet.PATH_DOWNLOADS, captureRedirectLocation(ctx));
  }

  @Test
  void handleMethodPOST_whenSelectedPeerDisappears_continuesBestEffortAndRedirects()
      throws Exception {
    QueueToadlet toadlet = createQueueToadlet();
    when(darknetConnectionsPort.listPeers()).thenReturn(List.of(alicePeer(), bobPeer()));
    doThrow(new UnknownPeerException("peer-1"))
        .when(darknetMessagingPort)
        .recommendDownloads("peer-1", List.of("CHK@"), "look at these");

    toadlet.handleMethodPOST(
        URI.create("http://localhost/downloads/"),
        createRequest(
            Map.of(
                "recommend_uri", "yes",
                "description", "look at these",
                "key-0", "CHK@",
                "node_42", "on",
                "node_99", "on")),
        ctx);

    verify(darknetMessagingPort).recommendDownloads("peer-1", List.of("CHK@"), "look at these");
    verify(darknetMessagingPort).recommendDownloads("peer-2", List.of("CHK@"), "look at these");
    assertEquals(QueueToadlet.PATH_DOWNLOADS, captureRedirectLocation(ctx));
  }

  @Test
  void handleMethodPOST_whenRecommendationUriIsMalformed_returnsInvalidUriErrorWithoutSend()
      throws Exception {
    QueueToadlet toadlet = createQueueToadlet();
    ByteArrayOutputStream body = captureBody(ctx);

    toadlet.handleMethodPOST(
        URI.create("http://localhost/downloads/"),
        createRequest(
            Map.of(
                "recommend_uri", "yes",
                "description", "broken",
                "key-0", "not-a-uri",
                "node_42", "on")),
        ctx);

    String html = body.toString(StandardCharsets.UTF_8);
    assertFalse(html.isBlank());
    verify(ctx).sendReplyHeaders(eq(400), eq("Bad request"), any(), anyString(), anyLong());
    verifyNoInteractions(darknetMessagingPort);
  }

  private QueueToadlet createQueueToadlet() throws Exception {
    ProgramDirectory userDir = new ProgramDirectory();
    userDir.move(tempDir.toString());

    node = org.mockito.Mockito.mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    when(node.userDir()).thenReturn(userDir);
    when(node.getUserDir()).thenReturn(userDir.dir());
    when(node.awaitingPassword()).thenReturn(false);
    when(node.isStopping()).thenReturn(false);
    when(node.getDatabasePath()).thenReturn(tempDir.resolve("queue.db").toString());
    when(node.isFProxyJavascriptEnabled()).thenReturn(false);

    RequestStarterGroup starters = org.mockito.Mockito.mock(RequestStarterGroup.class);
    NodeClientCore core = org.mockito.Mockito.mock(NodeClientCore.class);
    when(core.getNode()).thenReturn(node);
    when(core.getAlerts()).thenReturn(alerts);
    when(core.getPersistentTempDir()).thenReturn(tempDir.toFile());

    NodeNetworkSubsystem network = org.mockito.Mockito.mock(NodeNetworkSubsystem.class);
    when(node.network()).thenReturn(network);
    when(network.executor()).thenReturn(executor);
    when(network.darknetConnections()).thenReturn(new DarknetPeerNode[0]);

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

  private static DarknetConnectionPeerSnapshot alicePeer() {
    return new DarknetConnectionPeerSnapshot(42, "peer-1", "Alice", "", false);
  }

  private static DarknetConnectionPeerSnapshot bobPeer() {
    return new DarknetConnectionPeerSnapshot(99, "peer-2", "Bob", "", false);
  }
}
