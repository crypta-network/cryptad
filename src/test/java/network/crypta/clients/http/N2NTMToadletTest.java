package network.crypta.clients.http;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.l10n.NodeL10n;
import network.crypta.runtime.spi.DarknetConnectionPeerSnapshot;
import network.crypta.runtime.spi.DarknetConnectionsPort;
import network.crypta.runtime.spi.DarknetMessageSendStatus;
import network.crypta.runtime.spi.DarknetMessagingPort;
import network.crypta.runtime.spi.DarknetUploadedFile;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.runtime.spi.UnknownPeerException;
import network.crypta.support.HTMLNode;
import network.crypta.support.MultiValueTable;
import network.crypta.support.SimpleReadOnlyArrayBucket;
import network.crypta.support.api.HTTPRequest;
import network.crypta.support.api.HTTPUploadedFile;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class N2NTMToadletTest {

  @Mock private RuntimePorts runtimePorts;
  @Mock private DarknetConnectionsPort darknetConnectionsPort;
  @Mock private DarknetMessagingPort darknetMessagingPort;
  @Mock private LocalFileN2NMToadlet browser;
  @Mock private HighLevelSimpleClient client;
  @Mock private HTTPRequest request;
  @Mock private ToadletContext ctx;

  private N2NTMToadlet toadlet;

  @BeforeAll
  static void initL10n() {
    new NodeL10n();
  }

  @BeforeEach
  void setUp() {
    org.mockito.Mockito.lenient()
        .when(runtimePorts.darknetConnections())
        .thenReturn(darknetConnectionsPort);
    org.mockito.Mockito.lenient()
        .when(runtimePorts.darknetMessaging())
        .thenReturn(darknetMessagingPort);
    toadlet = new N2NTMToadlet(runtimePorts, browser, client);
  }

  @Test
  void path_returnsConfiguredEndpoint() {
    assertEquals("/send_n2ntm/", toadlet.path());
  }

  @Test
  void getBrowser_returnsInjectedBrowser() {
    assertSame(browser, toadlet.getBrowser());
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
    when(request.getParam("peernode_hashcode")).thenReturn("99");
    when(darknetConnectionsPort.listPeers()).thenReturn(List.of(alicePeerSnapshot()));

    PageMaker pageMaker = pageMaker();
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
        new URI("http://localhost/send_n2ntm/?peernode_hashcode=99"), request, ctx);

    String generated = html.get();
    assertTrue(generated.contains("infobox-error"));
    assertTrue(generated.contains("99"));
  }

  @Test
  void handleMethodGET_whenPeerFound_rendersSendFormFromDetachedSnapshot() throws Exception {
    when(ctx.checkFullAccess(any(Toadlet.class))).thenReturn(true);
    when(request.isParameterSet("peernode_hashcode")).thenReturn(true);
    when(request.getParam("peernode_hashcode")).thenReturn("42");
    when(darknetConnectionsPort.listPeers()).thenReturn(List.of(alicePeerSnapshot()));

    PageMaker pageMaker = pageMaker();
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
    assertTrue(generated.contains("node_42"));
    assertTrue(generated.contains("n2ntmtext"));
  }

  @Test
  void handleMethodPOST_whenMessageTooLong_returnsBadRequest() throws Exception {
    when(ctx.checkFullAccess(any(Toadlet.class))).thenReturn(true);
    doReturn(false).when(request).isPartSet(anyString());
    doReturn(true).when(request).isPartSet("send");
    when(request.getPartAsStringFailsafe("message", 1024 * 1024))
        .thenReturn("x".repeat(130 * 1024 + 1));

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
  void handleMethodPOST_whenSelectedPeerPresent_sendsTextThroughMessagingPort() throws Exception {
    when(ctx.checkFullAccess(any(Toadlet.class))).thenReturn(true);
    doReturn(false).when(request).isPartSet(anyString());
    doReturn(true).when(request).isPartSet("send");
    when(request.getPartAsStringFailsafe("message", 1024 * 1024)).thenReturn("hello");
    when(darknetConnectionsPort.listPeers()).thenReturn(List.of(alicePeerSnapshot()));
    doReturn(true).when(request).isPartSet("node_42");
    when(darknetMessagingPort.sendComposedMessage("peer-1", "hello", null, null, "hello"))
        .thenReturn(DarknetMessageSendStatus.SENT);

    PageMaker pageMaker = pageMaker();
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

    spyToadlet.handleMethodPOST(new URI("http://localhost/send_n2ntm/"), request, ctx);

    verify(darknetMessagingPort).sendComposedMessage("peer-1", "hello", null, null, "hello");
    assertTrue(html.get().contains("Alice"));
    assertTrue(html.get().contains("n2ntm-send-sent"));
  }

  @Test
  void handleMethodPOST_whenLocalFileSelected_sendsFileOfferThroughMessagingPort(
      @TempDir Path tempDir) throws Exception {
    Path filePath = Files.writeString(tempDir.resolve("offer.txt"), "payload");
    when(ctx.checkFullAccess(any(Toadlet.class))).thenReturn(true);
    doReturn(false).when(request).isPartSet(anyString());
    doReturn(true).when(request).isPartSet(LocalFileBrowserToadlet.SELECT_FILE);
    when(request.getPartAsStringFailsafe("message", 1024 * 1024)).thenReturn("hello");
    when(request.getPartAsStringFailsafe("filename", 1024)).thenReturn(filePath.toString());
    when(darknetConnectionsPort.listPeers()).thenReturn(List.of(alicePeerSnapshot()));
    doReturn(true).when(request).isPartSet("node_42");
    when(darknetMessagingPort.sendComposedMessage(
            "peer-1", "hello", filePath.toFile(), null, "hello"))
        .thenReturn(DarknetMessageSendStatus.SENT);

    PageMaker pageMaker = pageMaker();
    when(ctx.getPageMaker()).thenReturn(pageMaker);
    N2NTMToadlet spyToadlet = spy(toadlet);
    doAnswer(_ -> null).when(spyToadlet).writeHTMLReply(eq(ctx), eq(200), eq("OK"), anyString());

    spyToadlet.handleMethodPOST(new URI("http://localhost/send_n2ntm/"), request, ctx);

    verify(darknetMessagingPort)
        .sendComposedMessage("peer-1", "hello", filePath.toFile(), null, "hello");
  }

  @Test
  void handleMethodPOST_whenUploadSelected_streamsUploadThroughMessagingPort() throws Exception {
    byte[] bytes = "payload".getBytes(StandardCharsets.UTF_8);
    HTTPUploadedFile uploadedFile = org.mockito.Mockito.mock(HTTPUploadedFile.class);
    when(ctx.checkFullAccess(any(Toadlet.class))).thenReturn(true);
    doReturn(false).when(request).isPartSet(anyString());
    doReturn(true).when(request).isPartSet("n2nm-upload");
    when(request.getPartAsStringFailsafe("message", 1024 * 1024)).thenReturn("hello");
    when(request.getUploadedFile("n2nm-upload")).thenReturn(uploadedFile);
    when(uploadedFile.getFilename()).thenReturn("upload.txt");
    when(uploadedFile.getContentType()).thenReturn("text/plain");
    when(uploadedFile.getData()).thenReturn(new SimpleReadOnlyArrayBucket(bytes));
    when(darknetConnectionsPort.listPeers()).thenReturn(List.of(alicePeerSnapshot()));
    doReturn(true).when(request).isPartSet("node_42");

    doAnswer(
            invocation -> {
              DarknetUploadedFile upload = invocation.getArgument(3);
              assertEquals("upload.txt", upload.filename());
              assertEquals("text/plain", upload.contentType());
              assertEquals(bytes.length, upload.size());
              try (var inputStream = upload.openStream()) {
                assertArrayEquals(bytes, inputStream.readAllBytes());
              }
              return DarknetMessageSendStatus.SENT;
            })
        .when(darknetMessagingPort)
        .sendComposedMessage(
            eq("peer-1"), eq("hello"), eq(null), any(DarknetUploadedFile.class), eq("hello"));

    PageMaker pageMaker = pageMaker();
    when(ctx.getPageMaker()).thenReturn(pageMaker);
    N2NTMToadlet spyToadlet = spy(toadlet);
    doAnswer(_ -> null).when(spyToadlet).writeHTMLReply(eq(ctx), eq(200), eq("OK"), anyString());

    spyToadlet.handleMethodPOST(new URI("http://localhost/send_n2ntm/"), request, ctx);

    verify(darknetMessagingPort)
        .sendComposedMessage(
            eq("peer-1"), eq("hello"), eq(null), any(DarknetUploadedFile.class), eq("hello"));
  }

  @Test
  void handleMethodPOST_whenUploadResolutionFails_writesFailureAndStops() throws Exception {
    when(ctx.checkFullAccess(any(Toadlet.class))).thenReturn(true);
    doReturn(false).when(request).isPartSet(anyString());
    doReturn(true).when(request).isPartSet("n2nm-upload");
    when(request.getPartAsStringFailsafe("message", 1024 * 1024)).thenReturn("hello");
    when(darknetConnectionsPort.listPeers()).thenReturn(List.of(alicePeerSnapshot()));
    doReturn(true).when(request).isPartSet("node_42");
    doAnswer(
            _ -> {
              throw new IOException("boom");
            })
        .when(request)
        .getUploadedFile("n2nm-upload");

    PageMaker pageMaker = pageMaker();
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

    spyToadlet.handleMethodPOST(new URI("http://localhost/send_n2ntm/"), request, ctx);

    verify(spyToadlet, times(1)).writeHTMLReply(eq(ctx), eq(200), eq("OK"), anyString());
    verifyNoInteractions(darknetMessagingPort);
    assertTrue(html.get().contains("hello"));
  }

  @Test
  void handleMethodPOST_whenPeerCannotBeResolved_rendersQueuedStatusRow() throws Exception {
    when(ctx.checkFullAccess(any(Toadlet.class))).thenReturn(true);
    doReturn(false).when(request).isPartSet(anyString());
    doReturn(true).when(request).isPartSet("send");
    when(request.getPartAsStringFailsafe("message", 1024 * 1024)).thenReturn("hello");
    when(darknetConnectionsPort.listPeers()).thenReturn(List.of(alicePeerSnapshot()));
    doReturn(true).when(request).isPartSet("node_42");
    when(darknetMessagingPort.sendComposedMessage("peer-1", "hello", null, null, "hello"))
        .thenThrow(new UnknownPeerException("peer-1"));

    PageMaker pageMaker = pageMaker();
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

    spyToadlet.handleMethodPOST(new URI("http://localhost/send_n2ntm/"), request, ctx);

    assertTrue(html.get().contains("Alice"));
    assertTrue(html.get().contains("n2ntm-send-queued"));
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
    Map<String, String> peers = new LinkedHashMap<>();
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

  private PageMaker pageMaker() {
    PageMaker pageMaker = org.mockito.Mockito.mock(PageMaker.class);
    doReturn(createPageNode()).when(pageMaker).getPageNode(anyString(), any(ToadletContext.class));
    return pageMaker;
  }

  private static DarknetConnectionPeerSnapshot alicePeerSnapshot() {
    return new DarknetConnectionPeerSnapshot(42, "peer-1", "Alice", "", false);
  }

  private PageNode createPageNode() {
    HTMLNode outer = new HTMLNode("div");
    HTMLNode content = outer.addChild("div");
    HTMLNode head = new HTMLNode("head");
    return new PageNode(outer, head, content);
  }
}
