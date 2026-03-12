package network.crypta.clients.http;

import java.io.ByteArrayOutputStream;
import java.net.InetAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.config.PersistentConfig;
import network.crypta.config.SubConfig;
import network.crypta.io.AddressTracker;
import network.crypta.io.InetAddressAddressTrackerItem;
import network.crypta.io.PeerAddressTrackerItem;
import network.crypta.io.comm.Peer;
import network.crypta.io.comm.UdpSocketHandler;
import network.crypta.node.Node;
import network.crypta.node.NodeIPDetector;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.support.HTMLNode;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ConnectivityToadletTest {

  @Mock HighLevelSimpleClient client;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  Node node;

  @Mock PersistentConfig config;
  @Mock ToadletContext ctx;
  @Mock HTTPRequest request;

  private ConnectivityToadlet toadlet;

  @BeforeEach
  void setUp() {
    toadlet = new ConnectivityToadlet(client, node);
  }

  @Test
  void path_whenCalled_returnsConnectivityPath() {
    assertEquals(ConnectivityToadlet.CONNECTIVITY_PATH, toadlet.path());
  }

  @Test
  void handleMethodGET_whenAdvancedDisabled_rendersPortSummaryAndAlertBox() throws Exception {
    HTMLNode content = new HTMLNode("div");
    PageMaker pageMaker = stubPageMaker(content);

    setConfigPorts(true, 8080, false, 0, false, 0);
    network.crypta.node.subsystem.NodeNetworkSubsystem network =
        org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeNetworkSubsystem.class);
    when(node.network()).thenReturn(network);
    when(network.fnpPort()).thenReturn(12345);
    when(network.opennetFnpPort()).thenReturn(33333);
    when(node.getConfig()).thenReturn(config);
    when(network.packetSocketHandlers()).thenReturn(new UdpSocketHandler[0]);

    NodeIPDetector ipDetector = mock(NodeIPDetector.class);
    when(network.ipDetector()).thenReturn(ipDetector);
    doAnswer(invocation -> ((HTMLNode) invocation.getArgument(0)).addChild("div", "ip"))
        .when(ipDetector)
        .addConnectionTypeBox(any(HTMLNode.class));

    UserAlertManager alertManager = mock(UserAlertManager.class);
    when(alertManager.createSummary()).thenReturn(new HTMLNode("div", "id", "alert"));
    when(ctx.getAlertManager()).thenReturn(alertManager);

    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.isAdvancedModeEnabled()).thenReturn(false);
    when(ctx.getPageMaker()).thenReturn(pageMaker);

    ByteArrayOutputStream body = captureBody(ctx);

    toadlet.handleMethodGET(URI.create("http://localhost/connectivity/"), request, ctx);

    String html = body.toString(StandardCharsets.UTF_8);

    assertTrue(html.contains("12345"), "Should list darknet FNP port");
    assertTrue(html.contains("33333"), "Should list opennet FNP port when configured");
    assertTrue(html.contains("8080"), "Should list enabled fproxy port");
    assertTrue(html.contains("alert"), "Should render alert summary for full access users");

    verify(ipDetector).addConnectionTypeBox(content);
    verify(ctx).sendReplyHeaders(anyInt(), anyString(), any(), anyString(), anyLong());
  }

  @Test
  void handleMethodGET_whenAdvancedEnabled_rendersPeerAndIpTables() throws Exception {
    HTMLNode content = new HTMLNode("div");
    PageMaker pageMaker = stubPageMaker(content);

    setConfigPorts(false, 9090, true, 9481, true, 2222);
    network.crypta.node.subsystem.NodeNetworkSubsystem network =
        org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeNetworkSubsystem.class);
    when(node.network()).thenReturn(network);
    when(network.fnpPort()).thenReturn(54321);
    when(network.opennetFnpPort()).thenReturn(0);
    when(node.getConfig()).thenReturn(config);

    PeerAddressTrackerItem peerItem =
        new PeerAddressTrackerItem(0, 0, new Peer("1.1.1.1:4242", false));
    peerItem.sentPacket(1_000L);
    peerItem.receivedPacket(AddressTracker.MAYBE_TUNNEL_LENGTH + 2_000L);

    InetAddressAddressTrackerItem ipItem =
        new InetAddressAddressTrackerItem(0, 0, InetAddress.getByName("2.2.2.2"));
    ipItem.sentPacket(2_000L);
    ipItem.receivedPacket(AddressTracker.MAYBE_TUNNEL_LENGTH + 4_000L);

    AddressTracker tracker = mock(AddressTracker.class);
    when(tracker.getPortForwardStatus())
        .thenReturn(AddressTracker.Status.DEFINITELY_PORT_FORWARDED);
    when(tracker.getLongestSendReceiveGap()).thenReturn(12_345L);
    when(tracker.getPeerAddressTrackerItems()).thenReturn(new PeerAddressTrackerItem[] {peerItem});
    when(tracker.getInetAddressTrackerItems())
        .thenReturn(new InetAddressAddressTrackerItem[] {ipItem});

    UdpSocketHandler handler = mock(UdpSocketHandler.class);
    when(handler.getTitle()).thenReturn("udp-9999");
    when(handler.getAddressTracker()).thenReturn(tracker);

    when(network.packetSocketHandlers()).thenReturn(new UdpSocketHandler[] {handler});

    NodeIPDetector ipDetector = mock(NodeIPDetector.class);
    when(network.ipDetector()).thenReturn(ipDetector);
    doAnswer(invocation -> ((HTMLNode) invocation.getArgument(0)).addChild("div", "ip"))
        .when(ipDetector)
        .addConnectionTypeBox(any(HTMLNode.class));

    UserAlertManager alertManager = mock(UserAlertManager.class);
    when(alertManager.createSummary()).thenReturn(new HTMLNode("div", "id", "alert"));
    when(ctx.getAlertManager()).thenReturn(alertManager);

    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.isAdvancedModeEnabled()).thenReturn(true);
    when(ctx.getPageMaker()).thenReturn(pageMaker);

    ByteArrayOutputStream body = captureBody(ctx);

    toadlet.handleMethodGET(URI.create("http://localhost/connectivity/"), request, ctx);

    String html = body.toString(StandardCharsets.UTF_8);

    assertTrue(html.contains("1.1.1.1:4242"), "Peer table should include peer address");
    assertTrue(html.contains("2.2.2.2"), "IP table should include raw IP");
    assertTrue(html.contains("udp-9999"), "Summary should list handler title");
  }

  private PageMaker stubPageMaker(HTMLNode content) {
    HTMLNode root = new HTMLNode("html");
    HTMLNode head = root.addChild("head");
    root.addChild(content);
    PageNode page = new PageNode(root, head, content);

    PageMaker pageMaker = mock(PageMaker.class);
    when(pageMaker.getPageNode(anyString(), any(ToadletContext.class))).thenReturn(page);
    lenient()
        .doAnswer(
            invocation -> {
              HTMLNode parent = invocation.getArgument(2);
              HTMLNode infobox = new HTMLNode("div", "class", "infobox");
              parent.addChild(infobox);
              return infobox.addChild("div", "class", "content");
            })
        .when(pageMaker)
        .getInfobox(anyString(), anyString(), any(HTMLNode.class), anyString(), anyBoolean());
    return pageMaker;
  }

  private void setConfigPorts(
      boolean fproxyEnabled,
      int fproxyPort,
      boolean fcpEnabled,
      int fcpPort,
      boolean tmciEnabled,
      int tmciPort) {
    when(config.get("fproxy")).thenReturn(mockSubConfig(fproxyEnabled, fproxyPort));
    when(config.get("fcp")).thenReturn(mockSubConfig(fcpEnabled, fcpPort));
    when(config.get("console")).thenReturn(mockSubConfig(tmciEnabled, tmciPort));
  }

  private SubConfig mockSubConfig(boolean enabled, int port) {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.put("enabled", enabled);
    fs.put("port", port);
    return mock(
        SubConfig.class,
        invocation -> {
          if ("exportFieldSet".equals(invocation.getMethod().getName())) {
            return fs;
          }
          return org.mockito.Answers.RETURNS_DEFAULTS.answer(invocation);
        });
  }

  private ByteArrayOutputStream captureBody(ToadletContext context) throws Exception {
    ByteArrayOutputStream body = new ByteArrayOutputStream();
    doAnswer(invocation -> null)
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
