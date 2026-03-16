package network.crypta.clients.http;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URI;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.Map;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.node.OpennetPeerNodeStatus;
import network.crypta.node.PeerNodeStatus;
import network.crypta.runtime.spi.ConfigPort;
import network.crypta.runtime.spi.ConnectionsPageKind;
import network.crypta.runtime.spi.ConnectionsPagePort;
import network.crypta.runtime.spi.ConnectionsPageRequest;
import network.crypta.runtime.spi.ConnectionsPageSnapshot;
import network.crypta.runtime.spi.ConnectionsSupportPort;
import network.crypta.runtime.spi.NodeFieldSet;
import network.crypta.runtime.spi.NodeInfoPort;
import network.crypta.runtime.spi.NodeReferenceSnapshot;
import network.crypta.runtime.spi.NodeReferenceView;
import network.crypta.runtime.spi.PeerPort;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class OpennetConnectionsToadletTest {
  private static final String VALID_DARKNET_REFERENCE =
      "identity=darknet-peer\nlastGoodVersion=1\nEnd\n";
  private static final String OWN_NODE_IDENTITY = "peer-1";
  private static final String OWN_NODE_LAST_GOOD_VERSION = "1";

  @Mock private HighLevelSimpleClient client;
  @Mock private ConnectionsPagePort connectionsPage;
  @Mock private ConnectionsSupportPort connectionsSupportPort;
  @Mock private PeerPort peerPort;
  @Mock private NodeInfoPort nodeInfoPort;
  @Mock private ConfigPort configPort;
  @Mock private ToadletContext ctx;
  @Mock private HTTPRequest request;

  private OpennetConnectionsToadlet toadlet;

  @BeforeEach
  void setUp() {
    ConnectionsToadletRuntimePorts runtimePorts =
        new ConnectionsToadletRuntimePorts(
            connectionsPage, peerPort, nodeInfoPort, configPort, connectionsSupportPort);
    toadlet = new OpennetConnectionsToadlet(client, runtimePorts);
  }

  @Test
  void constructor_withoutNodeOrNodeClientCoreDependency_acceptsRuntimePortsOnly() {
    ConnectionsToadletRuntimePorts runtimePorts =
        new ConnectionsToadletRuntimePorts(
            connectionsPage, peerPort, nodeInfoPort, configPort, connectionsSupportPort);

    assertDoesNotThrow(() -> new OpennetConnectionsToadlet(client, runtimePorts));
  }

  @Test
  void noderefView_returnsPublicOpennetReferenceView() {
    assertEquals(NodeReferenceView.OPENNET_PUBLIC, toadlet.noderefView());
  }

  @Test
  void isEnabled_whenQueried_usesConnectionsSupportPort() {
    when(connectionsSupportPort.isOpennetEnabled()).thenReturn(true).thenReturn(false);

    assertTrue(toadlet.isEnabled(null));
    assertFalse(toadlet.isEnabled(null));
    verify(connectionsSupportPort, times(2)).isOpennetEnabled();
  }

  @Test
  void shouldDrawNoderefBox_matchesAdvancedMode() {
    assertTrue(toadlet.shouldDrawNoderefBox(true));
    assertFalse(toadlet.shouldDrawNoderefBox(false));
  }

  @Test
  void peerActionsAndAcceptRefPosts_flagsAreConstant() {
    assertFalse(toadlet.showPeerActionsBox());
    assertTrue(toadlet.acceptRefPosts());
    assertEquals("/opennet/", toadlet.defaultRedirectLocation());
    assertTrue(toadlet.isOpennet());
    assertEquals("/strangers/", toadlet.path());
  }

  @Test
  void comparator_successTimeOrdersByLastSuccess() {
    Comparator<PeerNodeStatus> comparator = toadlet.comparator("successTime", false);
    OpennetConnectionsToadlet.OpennetComparator opennetComparator =
        (OpennetConnectionsToadlet.OpennetComparator) comparator;

    OpennetPeerNodeStatus newer = statusWithLastSuccess(2000L);
    OpennetPeerNodeStatus older = statusWithLastSuccess(1000L);

    int result = opennetComparator.customCompare(newer, older);

    assertEquals(-1, result, "Newer success should sort before older by default");
  }

  @Test
  void comparator_successTimeHonoursReversedFlag() {
    OpennetConnectionsToadlet.OpennetComparator comparator =
        (OpennetConnectionsToadlet.OpennetComparator) toadlet.comparator("successTime", true);

    OpennetPeerNodeStatus newer = statusWithLastSuccess(2000L);
    OpennetPeerNodeStatus older = statusWithLastSuccess(1000L);

    int result = comparator.customCompare(newer, older);

    assertEquals(1, result, "Reversed comparator should flip ordering");
  }

  @Test
  void handleMethodGET_whenCalled_usesConnectionsPagePortAndSkipsPeerActionsForm()
      throws Exception {
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    when(ctx.isAdvancedModeEnabled()).thenReturn(false);
    when(ctx.isAllowedFullAccess()).thenReturn(false);
    PageMaker pageMaker = stubPageMaker(new HTMLNode("div"));
    when(ctx.getPageMaker()).thenReturn(pageMaker);
    when(request.getParam("sortBy", null)).thenReturn("address");
    when(request.isParameterSet("reversed")).thenReturn(false);
    when(connectionsPage.render(any()))
        .thenReturn(
            new ConnectionsPageSnapshot(
                "strangers",
                1,
                false,
                "<div id=\"before\">before</div>",
                "<table id=\"peer-table\"></table>",
                "<div id=\"after\">after</div>"));

    ArgumentCaptor<ConnectionsPageRequest> requestCaptor =
        ArgumentCaptor.forClass(ConnectionsPageRequest.class);
    ByteArrayOutputStream body = captureBody(ctx);

    toadlet.handleMethodGET(
        URI.create("http://localhost/strangers/displaymessagetypes.html"), request, ctx);

    String html = body.toString(java.nio.charset.StandardCharsets.UTF_8);
    assertTrue(html.contains("before"));
    assertTrue(html.contains("peer-table"));
    assertTrue(html.contains("after"));
    verify(ctx, never()).addFormChild(any(HTMLNode.class), anyString(), anyString());
    verify(connectionsPage).render(requestCaptor.capture());
    ConnectionsPageRequest pageRequest = requestCaptor.getValue();
    assertEquals(ConnectionsPageKind.OPENNET, pageRequest.kind());
    assertFalse(pageRequest.advancedMode());
    assertTrue(pageRequest.drawMessageTypes());
    assertEquals("address", pageRequest.sortBy());
    assertFalse(pageRequest.reversed());
  }

  @Test
  void handleMethodGET_whenSnapshotHasNoPeers_doesNotRedirectLikeDarknet() throws Exception {
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    when(ctx.isAdvancedModeEnabled()).thenReturn(false);
    when(ctx.isAllowedFullAccess()).thenReturn(false);
    PageMaker pageMaker = stubPageMaker(new HTMLNode("div"));
    when(ctx.getPageMaker()).thenReturn(pageMaker);
    when(connectionsPage.render(any()))
        .thenReturn(
            new ConnectionsPageSnapshot(
                "strangers",
                0,
                false,
                "<div id=\"before\">before</div>",
                "<div id=\"no-peers\">none</div>",
                "<div id=\"after\">after</div>"));

    ByteArrayOutputStream body = captureBody(ctx);

    assertDoesNotThrow(
        () -> toadlet.handleMethodGET(URI.create("http://localhost/strangers/"), request, ctx));

    String html = body.toString(java.nio.charset.StandardCharsets.UTF_8);
    assertTrue(html.contains("no-peers"));
    verify(ctx, never()).addFormChild(any(HTMLNode.class), anyString(), anyString());
  }

  @Test
  void handleMethodGET_whenAdvancedModeEnabled_rendersOwnNoderefFromNodeInfoPort()
      throws Exception {
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    when(ctx.isAdvancedModeEnabled()).thenReturn(true);
    when(ctx.isAllowedFullAccess()).thenReturn(false);
    when(request.getParam("sortBy", null)).thenReturn(null);
    when(request.isParameterSet("reversed")).thenReturn(false);
    when(connectionsPage.render(any()))
        .thenReturn(
            new ConnectionsPageSnapshot(
                "strangers",
                1,
                false,
                "<div id=\"before\">before</div>",
                "<div>peer-table</div>",
                ""));
    when(nodeInfoPort.exportReference(NodeReferenceView.OPENNET_PUBLIC, false))
        .thenReturn(ownNodeReferenceSnapshot());
    PageMaker pageMaker = stubPageMaker(new HTMLNode("div"));
    when(ctx.getPageMaker()).thenReturn(pageMaker);
    stubFormChild(ctx);

    ByteArrayOutputStream body = captureBody(ctx);

    toadlet.handleMethodGET(URI.create("http://localhost/strangers/"), request, ctx);

    String html = body.toString(java.nio.charset.StandardCharsets.UTF_8);
    assertTrue(html.contains("identity=" + OWN_NODE_IDENTITY));
    assertTrue(html.contains("lastGoodVersion=" + OWN_NODE_LAST_GOOD_VERSION));
    verify(nodeInfoPort).exportReference(NodeReferenceView.OPENNET_PUBLIC, false);
  }

  @Test
  void addNewNode_whenDarknetReferenceSubmittedOnOpennetPage_rejectsWithoutCallingPeerPort()
      throws Exception {
    ConnectionsToadlet.PeerAdditionReturnCodes result = invokeAddNewNodeWithDarknetReference();

    assertEquals(ConnectionsToadlet.PeerAdditionReturnCodes.CANT_PARSE, result);
    verify(peerPort, never()).add(any(), any(), any());
  }

  private OpennetPeerNodeStatus statusWithLastSuccess(long timestamp) {
    OpennetPeerNodeStatus status = mock(OpennetPeerNodeStatus.class);
    setTimeLastSuccess(status, timestamp);
    return status;
  }

  private void setTimeLastSuccess(OpennetPeerNodeStatus status, long timestamp) {
    try {
      Field field = OpennetPeerNodeStatus.class.getField("timeLastSuccess");
      field.setAccessible(true);
      field.setLong(status, timestamp);
    } catch (ReflectiveOperationException e) {
      throw linkageError(e);
    }
  }

  private static LinkageError linkageError(ReflectiveOperationException e) {
    return new LinkageError("Unable to set timeLastSuccess on mock", e);
  }

  private ConnectionsToadlet.PeerAdditionReturnCodes invokeAddNewNodeWithDarknetReference()
      throws Exception {
    Method method =
        ConnectionsToadlet.class.getDeclaredMethod(
            "addNewNode",
            String.class,
            String.class,
            network.crypta.node.DarknetPeerNode.FRIEND_TRUST.class,
            network.crypta.node.DarknetPeerNode.FRIEND_VISIBILITY.class);
    method.setAccessible(true);
    return (ConnectionsToadlet.PeerAdditionReturnCodes)
        method.invoke(toadlet, VALID_DARKNET_REFERENCE, "", null, null);
  }

  private PageMaker stubPageMaker(HTMLNode content) {
    HTMLNode root = new HTMLNode("html");
    HTMLNode head = root.addChild("head");
    root.addChild(content);
    PageNode page = new PageNode(root, head, content);

    PageMaker pageMaker = mock(PageMaker.class);
    when(pageMaker.getPageNode(anyString(), any(ToadletContext.class))).thenReturn(page);
    return pageMaker;
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

  private void stubFormChild(ToadletContext context) {
    doAnswer(
            invocation -> {
              HTMLNode parentNode = invocation.getArgument(0);
              String target = invocation.getArgument(1);
              String id = invocation.getArgument(2);
              return parentNode
                  .addChild("div")
                  .addChild(
                      "form",
                      new String[] {"action", "method", "enctype", "id", "accept-charset"},
                      new String[] {target, "post", "multipart/form-data", id, "utf-8"});
            })
        .when(context)
        .addFormChild(any(HTMLNode.class), anyString(), anyString());
  }

  private static NodeReferenceSnapshot ownNodeReferenceSnapshot() {
    return new NodeReferenceSnapshot(new NodeFieldSet(ownNodeReferenceValues(), Map.of()));
  }

  private static Map<String, String> ownNodeReferenceValues() {
    LinkedHashMap<String, String> values = new LinkedHashMap<>();
    values.put("identity", OWN_NODE_IDENTITY);
    values.put("lastGoodVersion", OWN_NODE_LAST_GOOD_VERSION);
    return values;
  }
}
