package network.crypta.clients.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.util.HashMap;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.DarknetPeerNode;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.support.HTMLNode;
import network.crypta.support.MultiValueTable;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class N2NTMToadletTest {

  @Mock private Node node;
  @Mock private NodeClientCore core;
  @Mock private HighLevelSimpleClient client;
  @Mock private HTTPRequest request;
  @Mock private ToadletContext ctx;

  private N2NTMToadlet toadlet;

  @BeforeAll
  static void initL10n() {
    // Ensure localization bundle is initialised once for predictable strings.
    new NodeL10n();
  }

  @BeforeEach
  void setUp() {
    toadlet = new N2NTMToadlet(node, core, client, "/friends/");
  }

  @Test
  void path_returnsConfiguredEndpoint() {
    assertEquals("/send_n2ntm/", toadlet.path());
  }

  @Test
  void getBrowser_returnsLocalFileToadlet() {
    assertInstanceOf(LocalFileN2NMToadlet.class, toadlet.getBrowser());
  }

  @Test
  void handleMethodGET_whenAccessDenied_abortsEarly() throws Exception {
    when(ctx.checkFullAccess(toadlet)).thenReturn(false);

    toadlet.handleMethodGET(new URI("http://localhost/send_n2ntm/"), request, ctx);

    verify(ctx).checkFullAccess(toadlet);
    verifyNoMoreInteractions(ctx);
  }

  @Test
  void handleMethodGET_whenNoParam_redirectsToFriends() throws Exception {
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    when(request.isParameterSet("peernode_hashcode")).thenReturn(false);

    toadlet.handleMethodGET(new URI("http://localhost/send_n2ntm/"), request, ctx);

    @SuppressWarnings("unchecked")
    ArgumentCaptor<MultiValueTable<String, String>> headersCaptor =
        ArgumentCaptor.forClass(
            (Class<MultiValueTable<String, String>>) (Class<?>) MultiValueTable.class);
    verify(ctx).sendReplyHeaders(eq(302), eq("Found"), headersCaptor.capture(), eq(null), eq(0L));
    assertEquals("/friends/", headersCaptor.getValue().getFirst("Location"));
  }

  @Test
  void handleMethodGET_whenPeerMissing_showsErrorBox() throws Exception {
    when(ctx.checkFullAccess(any(Toadlet.class))).thenReturn(true);
    when(request.isParameterSet("peernode_hashcode")).thenReturn(true);
    DarknetPeerNode peer = mock(DarknetPeerNode.class);
    int peerHash = peer.hashCode();
    String missingHash = String.valueOf(peerHash + 1);
    when(request.getParam("peernode_hashcode")).thenReturn(missingHash);
    when(node.getDarknetConnections()).thenReturn(new DarknetPeerNode[] {peer});

    PageMaker pageMaker = mock(PageMaker.class);
    PageNode page = createPageNode();
    doReturn(page).when(pageMaker).getPageNode(anyString(), any(ToadletContext.class));
    when(ctx.getPageMaker()).thenReturn(pageMaker);
    AtomicReference<String> html = new AtomicReference<>("");
    N2NTMToadlet spyToadlet = spy(toadlet);
    doAnswer(
            invocation -> {
              html.set(invocation.getArgument(3));
              return null;
            })
        .when(spyToadlet)
        .writeHTMLReply(eq(ctx), eq(200), eq("OK"), anyString());

    spyToadlet.handleMethodGET(
        new URI("http://localhost/send_n2ntm/?peernode_hashcode=1234"), request, ctx);

    String generated = html.get();
    assertTrue(generated.contains("infobox-error"));
    assertTrue(generated.contains(missingHash));
  }

  @Test
  void handleMethodGET_whenPeerFound_rendersSendForm() throws Exception {
    when(ctx.checkFullAccess(any(Toadlet.class))).thenReturn(true);
    when(request.isParameterSet("peernode_hashcode")).thenReturn(true);
    DarknetPeerNode peer = mock(DarknetPeerNode.class);
    int peerHash = peer.hashCode();
    when(request.getParam("peernode_hashcode")).thenReturn(String.valueOf(peerHash));
    when(peer.getName()).thenReturn("Alice");
    when(node.getDarknetConnections()).thenReturn(new DarknetPeerNode[] {peer});

    PageMaker pageMaker = mock(PageMaker.class);
    PageNode page = createPageNode();
    doReturn(page).when(pageMaker).getPageNode(anyString(), any(ToadletContext.class));
    when(ctx.getPageMaker()).thenReturn(pageMaker);
    when(ctx.isAdvancedModeEnabled()).thenReturn(true);
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.addFormChild(any(HTMLNode.class), eq("/send_n2ntm/"), eq("sendN2NTMForm")))
        .thenAnswer(
            invocation -> {
              HTMLNode parent = invocation.getArgument(0);
              HTMLNode form = new HTMLNode("form");
              parent.addChild(form);
              return form;
            });

    AtomicReference<String> html = new AtomicReference<>("");
    N2NTMToadlet spyToadlet = spy(toadlet);
    doAnswer(
            invocation -> {
              html.set(invocation.getArgument(3));
              return null;
            })
        .when(spyToadlet)
        .writeHTMLReply(eq(ctx), eq(200), eq("OK"), anyString());

    spyToadlet.handleMethodGET(
        new URI("http://localhost/send_n2ntm/?peernode_hashcode=42"), request, ctx);

    String generated = html.get();
    assertTrue(generated.contains("Alice"));
    assertTrue(generated.contains("node_" + peerHash));
    assertTrue(generated.contains("n2ntmtext"));
  }

  @Test
  void handleMethodPOST_whenMessageTooLong_returnsBadRequest() throws Exception {
    when(ctx.checkFullAccess(any(Toadlet.class))).thenReturn(true);
    when(request.isPartSet(anyString())).thenReturn(false);
    when(request.isPartSet("send")).thenReturn(true);

    String oversizedMessage = "x".repeat(130 * 1024 + 1);
    when(request.getPartAsStringFailsafe("message", 1024 * 1024)).thenReturn(oversizedMessage);

    N2NTMToadlet spyToadlet = spy(toadlet);
    AtomicReference<Integer> status = new AtomicReference<>(0);
    doAnswer(
            invocation -> {
              status.set(invocation.getArgument(1));
              return null;
            })
        .when(spyToadlet)
        .writeTextReply(eq(ctx), anyInt(), anyString(), anyString());

    spyToadlet.handleMethodPOST(new URI("http://localhost/send_n2ntm/"), request, ctx);

    assertEquals(400, status.get());
    verify(spyToadlet, times(1)).writeTextReply(eq(ctx), eq(400), eq("Bad request"), anyString());
  }

  @Test
  void addUnsentMessageTextInfo_appendsMessage() {
    HTMLNode root = new HTMLNode("div");
    String message = "Pending message body";

    N2NTMToadlet.addUnsentMessageTextInfo(root, message);

    String html = root.generate();
    assertTrue(html.contains(message));
    assertTrue(html.contains("<p>"));
  }

  @Test
  void createN2NTMSendForm_whenAdvanced_addsFileControls() {
    HTMLNode contentNode = new HTMLNode("div");
    HashMap<String, String> peers = new HashMap<>();
    peers.put("7", "Bob");

    when(ctx.addFormChild(any(HTMLNode.class), eq("/send_n2ntm/"), eq("sendN2NTMForm")))
        .thenAnswer(
            invocation -> {
              HTMLNode parent = invocation.getArgument(0);
              HTMLNode form = new HTMLNode("form");
              parent.addChild(form);
              return form;
            });
    when(ctx.isAllowedFullAccess()).thenReturn(true);

    N2NTMToadlet.createN2NTMSendForm(true, contentNode, ctx, peers);

    String html = contentNode.generate();
    assertTrue(html.contains("Bob"));
    assertTrue(html.contains("node_7"));
    assertTrue(html.contains("n2nm-upload"));
    assertTrue(html.contains("n2ntmtext"));
  }

  private PageNode createPageNode() {
    HTMLNode outer = new HTMLNode("div");
    HTMLNode content = outer.addChild("div");
    HTMLNode head = new HTMLNode("head");
    return new PageNode(outer, head, content);
  }
}
