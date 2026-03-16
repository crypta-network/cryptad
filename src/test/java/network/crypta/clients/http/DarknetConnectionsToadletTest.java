package network.crypta.clients.http;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Method;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.node.DarknetPeerNode.FRIEND_TRUST;
import network.crypta.node.DarknetPeerNode.FRIEND_VISIBILITY;
import network.crypta.node.DarknetPeerNode;
import network.crypta.node.DarknetPeerNodeStatus;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.ProgramDirectory;
import network.crypta.runtime.spi.ConfigPort;
import network.crypta.runtime.spi.ConnectionsPageKind;
import network.crypta.runtime.spi.ConnectionsPagePort;
import network.crypta.runtime.spi.ConnectionsPageRequest;
import network.crypta.runtime.spi.ConnectionsPageSnapshot;
import network.crypta.runtime.spi.NodeFieldSet;
import network.crypta.runtime.spi.NodeInfoPort;
import network.crypta.runtime.spi.NodeReferenceSnapshot;
import network.crypta.runtime.spi.NodeReferenceView;
import network.crypta.runtime.spi.PeerAddFailureReason;
import network.crypta.runtime.spi.PeerAddRejectedException;
import network.crypta.runtime.spi.PeerFieldSet;
import network.crypta.runtime.spi.PeerPort;
import network.crypta.runtime.spi.PeerSnapshot;
import network.crypta.runtime.spi.PeerTrust;
import network.crypta.runtime.spi.PeerVisibility;
import network.crypta.support.HTMLNode;
import network.crypta.support.MultiValueTable;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class DarknetConnectionsToadletTest {
  private static final String TEST_FORM_PASSWORD = "test-form-password";
  private static final String VALID_PEER_REFERENCE =
      "identity=peer-identity\nlastGoodVersion=1\nEnd\n";
  private static final String VALID_OPENNET_REFERENCE =
      "opennet=true\nidentity=peer-identity\nlastGoodVersion=1\nEnd\n";
  private static final String OWN_NODE_NAME = "Alice";
  private static final String OWN_NODE_IDENTITY = "peer-identity";
  private static final String OWN_NODE_LAST_GOOD_VERSION = "1";
  private static final String OWN_NODE_PHYSICAL_UDP = "127.0.0.1:1234";

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private NodeClientCore core;
  @Mock private HighLevelSimpleClient client;
  @Mock private ConnectionsPagePort connectionsPage;
  @Mock private PeerPort peerPort;
  @Mock private NodeInfoPort nodeInfoPort;
  @Mock private ConfigPort configPort;
  @Mock private ToadletContext ctx;
  @Mock private HTTPRequest request;
  @TempDir Path tempDir;

  private DarknetConnectionsToadlet toadlet;

  @BeforeEach
  void setUp() {
    toadlet =
        new DarknetConnectionsToadlet(
            node, core, client, connectionsPage, peerPort, nodeInfoPort, configPort);
    Mockito.lenient().when(request.isPartSet(anyString())).thenReturn(false);
  }

  @Test
  void handleMethodGET_whenUsingDisplayMessageTypes_buildsDarknetRequestAndRedirectsOnZeroPeers()
      throws Exception {
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    when(ctx.isAdvancedModeEnabled()).thenReturn(true);
    when(request.getParam("sortBy", null)).thenReturn("name");
    when(request.isParameterSet("reversed")).thenReturn(true);
    when(connectionsPage.render(any()))
        .thenReturn(new ConnectionsPageSnapshot("friends", 0, true, "", "", ""));

    ArgumentCaptor<ConnectionsPageRequest> requestCaptor =
        ArgumentCaptor.forClass(ConnectionsPageRequest.class);

    RedirectException redirect =
        assertThrows(
            RedirectException.class,
            () ->
                toadlet.handleMethodGET(
                    URI.create("http://localhost/friends/displaymessagetypes.html"), request, ctx));

    assertEquals(URI.create("/addfriend/"), redirect.getTarget());
    verify(connectionsPage).render(requestCaptor.capture());
    ConnectionsPageRequest pageRequest = requestCaptor.getValue();
    assertEquals(ConnectionsPageKind.DARKNET, pageRequest.kind());
    assertTrue(pageRequest.advancedMode());
    assertTrue(pageRequest.drawMessageTypes());
    assertEquals("name", pageRequest.sortBy());
    assertTrue(pageRequest.reversed());
  }

  @Test
  void handleMethodGET_whenPeerActionsEnabled_wrapsPeerTableInPeersForm() throws Exception {
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    when(ctx.isAdvancedModeEnabled()).thenReturn(false);
    when(ctx.isAllowedFullAccess()).thenReturn(false);
    PageMaker pageMaker = stubPageMaker(new HTMLNode("div"));
    when(ctx.getPageMaker()).thenReturn(pageMaker);
    when(connectionsPage.render(any()))
        .thenReturn(
            new ConnectionsPageSnapshot(
                "friends",
                1,
                true,
                "<div id=\"before\">before</div>",
                "<table id=\"peer-table\"></table><div id=\"actions\">actions</div>",
                "<div id=\"after\">after</div>"));
    stubFormChild(ctx);

    ByteArrayOutputStream body = captureBody(ctx);

    toadlet.handleMethodGET(URI.create("http://localhost/friends/"), request, ctx);

    String html = body.toString(StandardCharsets.UTF_8);
    assertTrue(html.contains("before"));
    assertTrue(html.contains("peer-table"));
    assertTrue(html.contains("id=\"peersForm\""));
    assertTrue(html.contains("formPassword"));
    assertTrue(html.contains(TEST_FORM_PASSWORD));
    assertTrue(html.contains("actions"));
    assertTrue(html.contains("after"));
    verify(ctx).addFormChild(any(HTMLNode.class), eq("."), eq("peersForm"));
  }

  @Test
  void comparator_nameSort_respectsCaseInsensitiveAndReversed() {
    DarknetConnectionsToadlet.DarknetComparator comparator =
        (DarknetConnectionsToadlet.DarknetComparator) toadlet.comparator("name", false);
    DarknetPeerNodeStatus alice = mock(DarknetPeerNodeStatus.class);
    DarknetPeerNodeStatus bob = mock(DarknetPeerNodeStatus.class);
    when(alice.getName()).thenReturn("alice");
    when(bob.getName()).thenReturn("Bob");

    int result = comparator.compare(alice, bob);
    assertTrue(result < 0, "alice should sort before Bob ignoring case");

    DarknetConnectionsToadlet.DarknetComparator reversed =
        (DarknetConnectionsToadlet.DarknetComparator) toadlet.comparator("name", true);
    int reversedResult = reversed.compare(alice, bob);
    assertTrue(reversedResult > 0, "reversed comparator should invert ordering");
  }

  @Test
  void comparator_visibility_whenOurVisibilityEqual_usesTheirVisibilityAsTieBreaker() {
    DarknetConnectionsToadlet.DarknetComparator comparator =
        (DarknetConnectionsToadlet.DarknetComparator) toadlet.comparator("visibility", false);

    DarknetPeerNodeStatus first = mock(DarknetPeerNodeStatus.class);
    DarknetPeerNodeStatus second = mock(DarknetPeerNodeStatus.class);
    when(first.getOurVisibility()).thenReturn(FRIEND_VISIBILITY.YES);
    when(second.getOurVisibility()).thenReturn(FRIEND_VISIBILITY.YES);
    when(first.getTheirVisibility()).thenReturn(FRIEND_VISIBILITY.NAME_ONLY);
    when(second.getTheirVisibility()).thenReturn(FRIEND_VISIBILITY.NO);

    int result = comparator.customCompare(first, second);

    assertTrue(result < 0, "NAME_ONLY should sort before NO when our visibility matches");
  }

  @Test
  void handleAltPost_updateNotes_updatesChangedNotesAndRedirects() throws Exception {
    DarknetPeerNode peer = mock(DarknetPeerNode.class);
    when(peer.getPrivateDarknetCommentNote()).thenReturn("old");
    network.crypta.node.subsystem.NodeNetworkSubsystem network =
        org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeNetworkSubsystem.class);
    when(node.network()).thenReturn(network);
    when(network.darknetConnections()).thenReturn(new DarknetPeerNode[] {peer});

    int peerHash = peer.hashCode();
    when(request.isPartSet("doAction")).thenReturn(true);
    when(request.getPartAsStringFailsafe("action", 25)).thenReturn("update_notes");
    when(request.isPartSet("peerPrivateNote_" + peerHash)).thenReturn(true);
    when(request.getPartAsStringFailsafe("peerPrivateNote_" + peerHash, 250)).thenReturn("new");

    doNothing().when(ctx).sendReplyHeaders(eq(302), eq("Found"), any(), isNull(), eq(0L));

    toadlet.handleAltPost(new URI("http://localhost/friends/"), request, ctx, false);

    verify(peer).setPrivateDarknetCommentNote("new");
    assertRedirectIssued();
  }

  @Test
  void handleAltPost_enableAction_enablesSelectedPeersAndRedirects() throws Exception {
    DarknetPeerNode peer = mock(DarknetPeerNode.class);
    network.crypta.node.subsystem.NodeNetworkSubsystem network =
        org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeNetworkSubsystem.class);
    when(node.network()).thenReturn(network);
    when(network.darknetConnections()).thenReturn(new DarknetPeerNode[] {peer});

    int peerHash = peer.hashCode();
    when(request.isPartSet("doAction")).thenReturn(true);
    when(request.getPartAsStringFailsafe("action", 25)).thenReturn("enable");
    when(request.isPartSet("node_" + peerHash)).thenReturn(true);

    doNothing().when(ctx).sendReplyHeaders(eq(302), eq("Found"), any(), isNull(), eq(0L));

    toadlet.handleAltPost(new URI("http://localhost/friends/"), request, ctx, false);

    verify(peer).enablePeer();
    assertRedirectIssued();
  }

  @Test
  void handleAltPost_removeWithForce_removesPeerAndRedirects() throws Exception {
    DarknetPeerNode peer = mock(DarknetPeerNode.class);
    when(peer.timeLastConnectionCompleted()).thenReturn(System.currentTimeMillis());
    when(peer.getPeerNodeStatus()).thenReturn(0);
    network.crypta.node.subsystem.NodeNetworkSubsystem network =
        org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeNetworkSubsystem.class);
    when(node.network()).thenReturn(network);
    when(network.darknetConnections()).thenReturn(new DarknetPeerNode[] {peer});

    int peerHash = peer.hashCode();
    when(request.isPartSet("remove")).thenReturn(true);
    when(request.isPartSet("node_" + peerHash)).thenReturn(true);
    when(request.isPartSet("forceit")).thenReturn(true);

    doNothing().when(ctx).sendReplyHeaders(eq(302), eq("Found"), any(), isNull(), eq(0L));

    toadlet.handleAltPost(new URI("http://localhost/friends/"), request, ctx, false);

    verify(network).removePeerConnection(peer);
    assertRedirectIssued();
  }

  @Test
  void addNewNode_whenPeerPortAcceptsDarknetRef_addsPeerAndWritesPrivateNote() throws Exception {
    when(peerPort.add(any(), any(), any())).thenReturn(peerSnapshot("peer-added"));

    ConnectionsToadlet.PeerAdditionReturnCodes result =
        invokeAddNewNode("private-note", FRIEND_TRUST.HIGH, FRIEND_VISIBILITY.NAME_ONLY);

    assertEquals(ConnectionsToadlet.PeerAdditionReturnCodes.OK, result);

    ArgumentCaptor<PeerFieldSet> fieldSetCaptor = ArgumentCaptor.forClass(PeerFieldSet.class);
    ArgumentCaptor<PeerTrust> trustCaptor = ArgumentCaptor.forClass(PeerTrust.class);
    ArgumentCaptor<PeerVisibility> visibilityCaptor = ArgumentCaptor.forClass(PeerVisibility.class);
    verify(peerPort)
        .add(fieldSetCaptor.capture(), trustCaptor.capture(), visibilityCaptor.capture());
    verify(peerPort).writePrivateDarknetComment("peer-added", "private-note");

    assertEquals("peer-identity", fieldSetCaptor.getValue().directValues().get("identity"));
    assertEquals("1", fieldSetCaptor.getValue().directValues().get("lastGoodVersion"));
    assertEquals(PeerTrust.HIGH, trustCaptor.getValue());
    assertEquals(PeerVisibility.NAME_ONLY, visibilityCaptor.getValue());
  }

  @Test
  void addNewNode_whenPeerPortRejects_mapsLegacyFailureReasons() throws Exception {
    assertAddRejectedMaps(
        PeerAddFailureReason.REF_PARSE_ERROR,
        ConnectionsToadlet.PeerAdditionReturnCodes.CANT_PARSE);
    assertAddRejectedMaps(
        PeerAddFailureReason.REF_SIGNATURE_INVALID,
        ConnectionsToadlet.PeerAdditionReturnCodes.INVALID_SIGNATURE);
    assertAddRejectedMaps(
        PeerAddFailureReason.CANNOT_PEER_WITH_SELF,
        ConnectionsToadlet.PeerAdditionReturnCodes.TRY_TO_ADD_SELF);
    assertAddRejectedMaps(
        PeerAddFailureReason.DUPLICATE_PEER_REF,
        ConnectionsToadlet.PeerAdditionReturnCodes.ALREADY_IN_REFERENCE);
    assertAddRejectedMaps(
        PeerAddFailureReason.OPENNET_DISABLED,
        ConnectionsToadlet.PeerAdditionReturnCodes.INTERNAL_ERROR);
  }

  @Test
  void addNewNode_whenOpennetReferenceSubmittedOnDarknetPage_rejectsWithoutCallingPeerPort()
      throws Exception {
    ConnectionsToadlet.PeerAdditionReturnCodes result =
        invokeAddNewNode(
            VALID_OPENNET_REFERENCE,
            "private-note",
            FRIEND_TRUST.HIGH,
            FRIEND_VISIBILITY.NAME_ONLY);

    assertEquals(ConnectionsToadlet.PeerAdditionReturnCodes.CANT_PARSE, result);
    verify(peerPort, Mockito.never()).add(any(), any(), any());
    verify(peerPort, Mockito.never()).writePrivateDarknetComment(anyString(), anyString());
  }

  @Test
  void handleMethodPOST_whenUsingPeersOfferFiles_appliesDismissedOverrideAndAddsPeer()
      throws Exception {
    Path peersOffersDir = Files.createDirectories(tempDir.resolve("peers-offers"));
    Files.writeString(
        peersOffersDir.resolve("offer.fref"),
        "identity=offer-peer\nlastGoodVersion=1\nEnd\n",
        StandardCharsets.UTF_8);

    ProgramDirectory runDir = new ProgramDirectory();
    runDir.move(tempDir.toString());
    when(core.getNode()).thenReturn(node);
    when(node.runDir()).thenReturn(runDir);
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    when(request.isPartSet("add")).thenReturn(true);
    when(request.getPartAsStringFailsafe("url", 200)).thenReturn("");
    when(request.getPartAsStringFailsafe("ref", Integer.MAX_VALUE)).thenReturn("");
    when(request.getPartAsStringFailsafe("reffile", Integer.MAX_VALUE)).thenReturn("");
    when(request.getPartAsStringFailsafe("peerPrivateNote", 250)).thenReturn("");
    when(request.getPartAsStringFailsafe("peers-offers-files", 5)).thenReturn("true");
    when(request.getPartAsStringFailsafe("trust", 10)).thenReturn(FRIEND_TRUST.NORMAL.name());
    when(request.getPartAsStringFailsafe("visibility", 10)).thenReturn(FRIEND_VISIBILITY.NO.name());
    when(peerPort.add(any(), any(), any())).thenReturn(peerSnapshot("offer-peer"));
    PageMaker pageMaker = stubPageMaker(new HTMLNode("div"));
    when(ctx.getPageMaker()).thenReturn(pageMaker);
    captureBody(ctx);

    toadlet.handleMethodPOST(URI.create("http://localhost/friends/"), request, ctx);

    verify(configPort).applyOverrides(Map.of("node.peersOffersDismissed", "true"));
    ArgumentCaptor<PeerFieldSet> fieldSetCaptor = ArgumentCaptor.forClass(PeerFieldSet.class);
    verify(peerPort).add(fieldSetCaptor.capture(), eq(PeerTrust.NORMAL), eq(PeerVisibility.NO));
    assertEquals("offer-peer", fieldSetCaptor.getValue().directValues().get("identity"));
    assertEquals("1", fieldSetCaptor.getValue().directValues().get("lastGoodVersion"));
  }

  @Test
  void handleMethodGET_whenDownloadingOwnReference_usesNodeInfoPort() throws Exception {
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    when(nodeInfoPort.exportReference(NodeReferenceView.DARKNET_PUBLIC, false))
        .thenReturn(ownNodeReferenceSnapshot());

    ByteArrayOutputStream body = captureBody(ctx);

    toadlet.handleMethodGET(URI.create("http://localhost/friends/myref.fref"), request, ctx);

    @SuppressWarnings("unchecked")
    ArgumentCaptor<MultiValueTable<String, String>> headersCaptor =
        ArgumentCaptor.forClass(MultiValueTable.class);
    verify(nodeInfoPort).exportReference(NodeReferenceView.DARKNET_PUBLIC, false);
    verify(ctx)
        .sendReplyHeaders(
            eq(200),
            eq("OK"),
            headersCaptor.capture(),
            eq("application/x-freenet-reference"),
            anyLong());
    assertEquals(
        "attachment; filename=myref.fref",
        headersCaptor.getValue().getFirst("Content-Disposition"));
    assertEquals(
        ownNodeReferenceFieldSet().toOrderedStringWithBase64(),
        body.toString(StandardCharsets.UTF_8));
  }

  @Test
  void tryHandlePeerNoderef_withValidFriendHash_sendsAttachmentResponse() throws Exception {
    SimpleFieldSet fieldSet = new SimpleFieldSet(false);
    fieldSet.putSingle("key", "value");

    DarknetPeerNode peer = mock(DarknetPeerNode.class);
    when(peer.getName()).thenReturn("Friend");
    when(peer.getFullNoderef()).thenReturn(fieldSet);
    network.crypta.node.subsystem.NodeNetworkSubsystem network =
        org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeNetworkSubsystem.class);
    when(node.network()).thenReturn(network);
    when(network.darknetConnections()).thenReturn(new DarknetPeerNode[] {peer});

    int peerHash = peer.hashCode();
    URI uri = URI.create("http://localhost/friends/friend-" + peerHash + ".fref");

    doNothing()
        .when(ctx)
        .sendReplyHeaders(
            eq(200), eq("OK"), any(), eq("application/x-freenet-reference"), anyLong());
    doNothing().when(ctx).writeData(any(byte[].class), eq(0), anyInt());

    boolean handled = invokeTryHandlePeerNoderef(uri);

    assertTrue(handled);
    @SuppressWarnings("unchecked")
    ArgumentCaptor<MultiValueTable<String, String>> headersCaptor =
        ArgumentCaptor.forClass(MultiValueTable.class);
    ArgumentCaptor<byte[]> bodyCaptor = ArgumentCaptor.forClass(byte[].class);

    int expectedLength = fieldSet.toString().getBytes(StandardCharsets.UTF_8).length;
    verify(ctx)
        .sendReplyHeaders(
            eq(200),
            eq("OK"),
            headersCaptor.capture(),
            eq("application/x-freenet-reference"),
            eq((long) expectedLength));
    verify(ctx).writeData(bodyCaptor.capture(), eq(0), eq(expectedLength));

    String headerValue = headersCaptor.getValue().getFirst("Content-Disposition");
    assertEquals("attachment; filename=Friend.fref", headerValue);
    assertEquals(fieldSet.toString(), new String(bodyCaptor.getValue(), StandardCharsets.UTF_8));
  }

  @Test
  void tryHandlePeerNoderef_withInvalidHash_returnsFalse() throws Exception {
    URI uri = URI.create("http://localhost/friends/friend-abc.fref");

    boolean handled = invokeTryHandlePeerNoderef(uri);

    assertFalse(handled);
    verifyNoInteractions(ctx);
  }

  private boolean invokeTryHandlePeerNoderef(URI uri) throws Exception {
    Method method =
        DarknetConnectionsToadlet.class.getDeclaredMethod(
            "tryHandlePeerNoderef", URI.class, HTTPRequest.class, ToadletContext.class);
    method.setAccessible(true);
    return (boolean) method.invoke(toadlet, uri, request, ctx);
  }

  private ConnectionsToadlet.PeerAdditionReturnCodes invokeAddNewNode(
      String nodeReference, String privateComment, FRIEND_TRUST trust, FRIEND_VISIBILITY visibility)
      throws Exception {
    Method method =
        ConnectionsToadlet.class.getDeclaredMethod(
            "addNewNode", String.class, String.class, FRIEND_TRUST.class, FRIEND_VISIBILITY.class);
    method.setAccessible(true);
    return (ConnectionsToadlet.PeerAdditionReturnCodes)
        method.invoke(toadlet, nodeReference, privateComment, trust, visibility);
  }

  private ConnectionsToadlet.PeerAdditionReturnCodes invokeAddNewNode(
      String privateComment, FRIEND_TRUST trust, FRIEND_VISIBILITY visibility) throws Exception {
    return invokeAddNewNode(VALID_PEER_REFERENCE, privateComment, trust, visibility);
  }

  private void assertAddRejectedMaps(
      PeerAddFailureReason reason, ConnectionsToadlet.PeerAdditionReturnCodes expected)
      throws Exception {
    Mockito.reset(peerPort);
    when(peerPort.add(any(), any(), any())).thenThrow(new PeerAddRejectedException(reason, "bad"));

    ConnectionsToadlet.PeerAdditionReturnCodes result =
        invokeAddNewNode("", FRIEND_TRUST.NORMAL, FRIEND_VISIBILITY.NO);

    assertEquals(expected, result);
  }

  private void assertRedirectIssued() throws Exception {
    @SuppressWarnings("unchecked")
    ArgumentCaptor<MultiValueTable<String, String>> headersCaptor =
        ArgumentCaptor.forClass(MultiValueTable.class);
    verify(ctx).sendReplyHeaders(eq(302), eq("Found"), headersCaptor.capture(), isNull(), eq(0L));
    assertEquals("/friends/", headersCaptor.getValue().getFirst("Location"));
  }

  private PageMaker stubPageMaker(HTMLNode content) {
    HTMLNode root = new HTMLNode("html");
    HTMLNode head = root.addChild("head");
    root.addChild(content);
    PageNode page = new PageNode(root, head, content);

    PageMaker pageMaker = mock(PageMaker.class);
    when(pageMaker.getPageNode(anyString(), any(ToadletContext.class))).thenReturn(page);
    Mockito.lenient()
        .when(
            pageMaker.getInfobox(
                anyString(), anyString(), any(HTMLNode.class), anyString(), anyBoolean()))
        .thenAnswer(_ -> new HTMLNode("div"));
    return pageMaker;
  }

  private void stubFormChild(ToadletContext context) {
    doAnswer(
            invocation -> {
              HTMLNode parentNode = invocation.getArgument(0);
              String target = invocation.getArgument(1);
              String id = invocation.getArgument(2);
              HTMLNode formNode =
                  parentNode
                      .addChild("div")
                      .addChild(
                          "form",
                          new String[] {"action", "method", "enctype", "id", "accept-charset"},
                          new String[] {target, "post", "multipart/form-data", id, "utf-8"});
              formNode.addChild(
                  "input",
                  new String[] {"type", "name", "value"},
                  new String[] {"hidden", "formPassword", TEST_FORM_PASSWORD});
              return formNode;
            })
        .when(context)
        .addFormChild(any(HTMLNode.class), anyString(), anyString());
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

  private static PeerSnapshot peerSnapshot(String identity) {
    return new PeerSnapshot(new PeerFieldSet(Map.of("identity", identity), Map.of()));
  }

  private static NodeReferenceSnapshot ownNodeReferenceSnapshot() {
    return new NodeReferenceSnapshot(new NodeFieldSet(ownNodeReferenceValues(), Map.of()));
  }

  private static Map<String, String> ownNodeReferenceValues() {
    LinkedHashMap<String, String> values = new LinkedHashMap<>();
    values.put("myName", OWN_NODE_NAME);
    values.put("identity", OWN_NODE_IDENTITY);
    values.put("lastGoodVersion", OWN_NODE_LAST_GOOD_VERSION);
    values.put("physical.udp", OWN_NODE_PHYSICAL_UDP);
    return values;
  }

  private static SimpleFieldSet ownNodeReferenceFieldSet() {
    SimpleFieldSet fieldSet = new SimpleFieldSet(true);
    fieldSet.putSingle("myName", OWN_NODE_NAME);
    fieldSet.putSingle("identity", OWN_NODE_IDENTITY);
    fieldSet.putSingle("lastGoodVersion", OWN_NODE_LAST_GOOD_VERSION);
    fieldSet.putSingle("physical.udp", OWN_NODE_PHYSICAL_UDP);
    return fieldSet;
  }
}
