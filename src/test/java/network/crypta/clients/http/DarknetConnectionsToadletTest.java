package network.crypta.clients.http;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import network.crypta.platform.webshell.routes.WebShellPaths;
import network.crypta.runtime.spi.ConfigPort;
import network.crypta.runtime.spi.ConnectionsPageKind;
import network.crypta.runtime.spi.ConnectionsPagePort;
import network.crypta.runtime.spi.ConnectionsPageRequest;
import network.crypta.runtime.spi.ConnectionsPageSnapshot;
import network.crypta.runtime.spi.ConnectionsSupportPort;
import network.crypta.runtime.spi.DarknetConnectionPeerSnapshot;
import network.crypta.runtime.spi.DarknetConnectionsPort;
import network.crypta.runtime.spi.DarknetPeerSettingsUpdate;
import network.crypta.runtime.spi.LifecyclePort;
import network.crypta.runtime.spi.NodeFieldSet;
import network.crypta.runtime.spi.NodeInfoPort;
import network.crypta.runtime.spi.NodeReferenceSnapshot;
import network.crypta.runtime.spi.NodeReferenceView;
import network.crypta.runtime.spi.PeerFieldSet;
import network.crypta.runtime.spi.PeerPort;
import network.crypta.runtime.spi.PeerSnapshot;
import network.crypta.runtime.spi.PeerTrust;
import network.crypta.runtime.spi.PeerVisibility;
import network.crypta.support.HTMLNode;
import network.crypta.support.MultiValueTable;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.SizeUtil;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.ArgumentMatchers.nullable;
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
  private static final String OWN_NODE_NAME = "Alice";
  private static final String OWN_NODE_IDENTITY = "peer-identity";
  private static final String OWN_NODE_LAST_GOOD_VERSION = "1";
  private static final String OWN_NODE_PHYSICAL_UDP = "127.0.0.1:1234";
  private static final String TEST_NODE_IDENTIFIER = "peer-1";

  @Mock private ConnectionsPagePort connectionsPage;
  @Mock private ConnectionsSupportPort connectionsSupportPort;
  @Mock private DarknetConnectionsPort darknetConnectionsPort;
  @Mock private LifecyclePort lifecyclePort;
  @Mock private PeerPort peerPort;
  @Mock private NodeInfoPort nodeInfoPort;
  @Mock private ConfigPort configPort;
  @Mock private ToadletContext ctx;
  @Mock private ToadletContainer container;
  @Mock private HTTPRequest request;

  private DarknetConnectionsToadlet toadlet;

  @BeforeEach
  void setUp() {
    ConnectionsToadletRuntimePorts runtimePorts =
        new ConnectionsToadletRuntimePorts(
            connectionsPage,
            peerPort,
            nodeInfoPort,
            configPort,
            connectionsSupportPort,
            lifecyclePort);
    toadlet = new DarknetConnectionsToadlet(runtimePorts, darknetConnectionsPort);
    Mockito.lenient().when(request.isPartSet(anyString())).thenReturn(false);
    Mockito.lenient().when(ctx.getContainer()).thenReturn(container);
  }

  @Test
  void constructor_withoutNodeClientCoreDependency_acceptsRuntimePortsOnly() {
    ConnectionsToadletRuntimePorts runtimePorts =
        new ConnectionsToadletRuntimePorts(
            connectionsPage,
            peerPort,
            nodeInfoPort,
            configPort,
            connectionsSupportPort,
            lifecyclePort);

    assertDoesNotThrow(() -> new DarknetConnectionsToadlet(runtimePorts, darknetConnectionsPort));
  }

  @Test
  void connectionsToadletRuntimePorts_whenLifecyclePortNull_throwsNullPointerException() {
    assertThrows(
        NullPointerException.class,
        () ->
            new ConnectionsToadletRuntimePorts(
                connectionsPage, peerPort, nodeInfoPort, configPort, connectionsSupportPort, null));
  }

  @Test
  void handleMethodGET_whenUsingDisplayMessageTypesAndZeroPeers_writesShellPeerRedirect()
      throws Exception {
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    when(container.isFProxyJavascriptEnabled()).thenReturn(true);
    when(ctx.isAdvancedModeEnabled()).thenReturn(true);
    when(request.getParam("sortBy", null)).thenReturn("name");
    when(request.isParameterSet("reversed")).thenReturn(true);
    when(connectionsPage.render(any()))
        .thenReturn(new ConnectionsPageSnapshot("friends", 0, true, "", "", ""));

    ArgumentCaptor<ConnectionsPageRequest> requestCaptor =
        ArgumentCaptor.forClass(ConnectionsPageRequest.class);

    toadlet.handleMethodGET(
        URI.create("http://localhost/friends/displaymessagetypes.html"), request, ctx);

    assertTemporaryRedirect(WebShellPaths.SHELL_ROOT + "#peers");
    verify(connectionsPage).render(requestCaptor.capture());
    ConnectionsPageRequest pageRequest = requestCaptor.getValue();
    assertEquals(ConnectionsPageKind.DARKNET, pageRequest.kind());
    assertTrue(pageRequest.advancedMode());
    assertTrue(pageRequest.drawMessageTypes());
    assertEquals("name", pageRequest.sortBy());
    assertTrue(pageRequest.reversed());
  }

  @Test
  void handleMethodGET_whenJavascriptDisabledAndZeroPeers_writesLegacyAddFriendRedirect()
      throws Exception {
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    when(container.isFProxyJavascriptEnabled()).thenReturn(false);
    when(ctx.isAdvancedModeEnabled()).thenReturn(true);
    when(request.getParam("sortBy", null)).thenReturn(null);
    when(request.isParameterSet("reversed")).thenReturn(false);
    when(connectionsPage.render(any()))
        .thenReturn(new ConnectionsPageSnapshot("friends", 0, true, "", "", ""));

    toadlet.handleMethodGET(URI.create("http://localhost/friends/"), request, ctx);

    assertTemporaryRedirect(DarknetAddRefToadlet.PATH);
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
  void drawAddPeerBox_whenRenderedInDarknet_ordersTrustAndVisibilityOptionsAndSetsDefaults() {
    HTMLNode contentNode = new HTMLNode("div");
    stubFormChild(ctx);

    ConnectionsToadlet.drawAddPeerBox(contentNode, ctx, false, "/friends/");

    List<HTMLNode> trustInputs = findInputsByName(contentNode, "trust");
    assertEquals(List.of("HIGH", "NORMAL", "LOW"), valuesOf(trustInputs));
    assertEquals("checked", trustInputs.get(1).getAttribute("checked"));

    List<HTMLNode> visibilityInputs = findInputsByName(contentNode, "visibility");
    assertEquals(List.of("YES", "NAME_ONLY", "NO"), valuesOf(visibilityInputs));
    assertEquals("checked", visibilityInputs.getFirst().getAttribute("checked"));
  }

  @Test
  void handleAltPost_updateNotes_updatesChangedNotesAndRedirects() throws Exception {
    int selectionToken = 101;
    when(darknetConnectionsPort.listPeers())
        .thenReturn(List.of(darknetPeerSnapshot(selectionToken, "Alice", "old")));
    when(request.isPartSet("doAction")).thenReturn(true);
    when(request.getPartAsStringFailsafe("action", 25)).thenReturn("update_notes");
    when(request.isPartSet("peerPrivateNote_" + selectionToken)).thenReturn(true);
    when(request.getPartAsStringFailsafe("peerPrivateNote_" + selectionToken, 250))
        .thenReturn("new");

    doNothing().when(ctx).sendReplyHeaders(eq(302), eq("Found"), any(), isNull(), eq(0L));

    toadlet.handleAltPost(new URI("http://localhost/friends/"), request, ctx, false);

    verify(peerPort).writePrivateDarknetCommentByIdentity(TEST_NODE_IDENTIFIER, "new");
    assertRedirectIssued();
  }

  @Test
  void handleAltPost_enableAction_updatesSelectedPeersThroughPeerPortAndRedirects()
      throws Exception {
    int selectionToken = 101;
    when(darknetConnectionsPort.listPeers())
        .thenReturn(List.of(darknetPeerSnapshot(selectionToken, "Alice", "")));
    when(request.isPartSet("doAction")).thenReturn(true);
    when(request.getPartAsStringFailsafe("action", 25)).thenReturn("enable");
    when(request.isPartSet("node_" + selectionToken)).thenReturn(true);

    doNothing().when(ctx).sendReplyHeaders(eq(302), eq("Found"), any(), isNull(), eq(0L));

    toadlet.handleAltPost(new URI("http://localhost/friends/"), request, ctx, false);

    ArgumentCaptor<DarknetPeerSettingsUpdate> updateCaptor =
        ArgumentCaptor.forClass(DarknetPeerSettingsUpdate.class);
    verify(peerPort).updateDarknetPeerByIdentity(eq(TEST_NODE_IDENTIFIER), updateCaptor.capture());
    assertEquals(Boolean.FALSE, updateCaptor.getValue().disabled());
    assertNull(updateCaptor.getValue().routingEnabled());
    assertRedirectIssued();
  }

  @Test
  void handleAltPost_changeTrust_updatesSelectedPeersThroughPeerPortAndRedirects()
      throws Exception {
    int selectionToken = 101;
    when(darknetConnectionsPort.listPeers())
        .thenReturn(List.of(darknetPeerSnapshot(selectionToken, "Alice", "")));
    when(request.isPartSet("changeTrust")).thenReturn(true);
    when(request.isPartSet("doChangeTrust")).thenReturn(true);
    when(request.isPartSet("node_" + selectionToken)).thenReturn(true);
    when(request.getPartAsStringFailsafe("changeTrust", 10)).thenReturn(PeerTrust.HIGH.name());

    doNothing().when(ctx).sendReplyHeaders(eq(302), eq("Found"), any(), isNull(), eq(0L));

    toadlet.handleAltPost(new URI("http://localhost/friends/"), request, ctx, false);

    ArgumentCaptor<DarknetPeerSettingsUpdate> updateCaptor =
        ArgumentCaptor.forClass(DarknetPeerSettingsUpdate.class);
    verify(peerPort).updateDarknetPeerByIdentity(eq(TEST_NODE_IDENTIFIER), updateCaptor.capture());
    assertEquals(PeerTrust.HIGH, updateCaptor.getValue().trust());
    assertRedirectIssued();
  }

  @Test
  void handleAltPost_changeVisibility_updatesSelectedPeersThroughPeerPortAndRedirects()
      throws Exception {
    int selectionToken = 101;
    when(darknetConnectionsPort.listPeers())
        .thenReturn(List.of(darknetPeerSnapshot(selectionToken, "Alice", "")));
    when(request.isPartSet("changeVisibility")).thenReturn(true);
    when(request.isPartSet("doChangeVisibility")).thenReturn(true);
    when(request.isPartSet("node_" + selectionToken)).thenReturn(true);
    when(request.getPartAsStringFailsafe("changeVisibility", 10))
        .thenReturn(PeerVisibility.NAME_ONLY.name());

    doNothing().when(ctx).sendReplyHeaders(eq(302), eq("Found"), any(), isNull(), eq(0L));

    toadlet.handleAltPost(new URI("http://localhost/friends/"), request, ctx, false);

    ArgumentCaptor<DarknetPeerSettingsUpdate> updateCaptor =
        ArgumentCaptor.forClass(DarknetPeerSettingsUpdate.class);
    verify(peerPort).updateDarknetPeerByIdentity(eq(TEST_NODE_IDENTIFIER), updateCaptor.capture());
    assertEquals(PeerVisibility.NAME_ONLY, updateCaptor.getValue().visibility());
    assertRedirectIssued();
  }

  @Test
  void handleAltPost_removeWithForce_removesPeerAndRedirects() throws Exception {
    int peerHash = 101;
    when(darknetConnectionsPort.listPeers())
        .thenReturn(List.of(darknetPeerSnapshot(peerHash, "Alice", "")));
    when(request.isPartSet("remove")).thenReturn(true);
    when(request.isPartSet("node_" + peerHash)).thenReturn(true);
    when(request.isPartSet("forceit")).thenReturn(true);

    doNothing().when(ctx).sendReplyHeaders(eq(302), eq("Found"), any(), isNull(), eq(0L));

    toadlet.handleAltPost(new URI("http://localhost/friends/"), request, ctx, false);

    verify(peerPort).removeByIdentity(TEST_NODE_IDENTIFIER);
    assertRedirectIssued();
  }

  @Test
  void handleAltPost_removeWithoutForceForNonRemovablePeer_rendersConfirmationAndDoesNotRemove()
      throws Exception {
    int selectionToken = 101;
    when(darknetConnectionsPort.listPeers())
        .thenReturn(List.of(darknetPeerSnapshot(selectionToken, "Alice", "")));
    when(request.isPartSet("remove")).thenReturn(true);
    when(request.isPartSet("node_" + selectionToken)).thenReturn(true);
    PageMaker pageMaker = stubPageMaker(new HTMLNode("div"));
    when(ctx.getPageMaker()).thenReturn(pageMaker);
    stubFormChild(ctx);

    ByteArrayOutputStream body = captureBody(ctx);

    toadlet.handleAltPost(new URI("http://localhost/friends/"), request, ctx, false);

    String html = body.toString(StandardCharsets.UTF_8);
    assertTrue(html.contains("Alice"));
    assertTrue(html.contains("name=\"node_" + selectionToken + '"'));
    verify(peerPort, Mockito.never()).removeByIdentity(anyString());
  }

  @Test
  void handleAltPost_acceptTransfer_usesDarknetConnectionsPortAndRedirects() throws Exception {
    int selectionToken = 101;
    when(darknetConnectionsPort.listPeers())
        .thenReturn(List.of(darknetPeerSnapshot(selectionToken, "Alice", "")));
    when(request.isPartSet("acceptTransfer")).thenReturn(true);
    when(request.isPartSet("node_" + selectionToken)).thenReturn(true);
    when(request.getPartAsStringFailsafe("id", 32)).thenReturn("77");

    doNothing().when(ctx).sendReplyHeaders(eq(302), eq("Found"), any(), isNull(), eq(0L));

    toadlet.handleAltPost(new URI("http://localhost/friends/"), request, ctx, false);

    verify(darknetConnectionsPort).acceptTransfer(TEST_NODE_IDENTIFIER, 77L);
    assertRedirectIssued();
  }

  @Test
  void handleAltPost_rejectTransfer_usesDarknetConnectionsPortAndRedirects() throws Exception {
    int selectionToken = 101;
    when(darknetConnectionsPort.listPeers())
        .thenReturn(List.of(darknetPeerSnapshot(selectionToken, "Alice", "")));
    when(request.isPartSet("rejectTransfer")).thenReturn(true);
    when(request.isPartSet("node_" + selectionToken)).thenReturn(true);
    when(request.getPartAsStringFailsafe("id", 32)).thenReturn("88");

    doNothing().when(ctx).sendReplyHeaders(eq(302), eq("Found"), any(), isNull(), eq(0L));

    toadlet.handleAltPost(new URI("http://localhost/friends/"), request, ctx, false);

    verify(darknetConnectionsPort).rejectTransfer(TEST_NODE_IDENTIFIER, 88L);
    assertRedirectIssued();
  }

  @Test
  void handleAltPost_sendMessageToPeers_buildsComposeFormFromDetachedSnapshots() throws Exception {
    int aliceToken = 101;
    int bobToken = 202;
    long memoryLimitBytes = 64L * 1024 * 1024;
    when(darknetConnectionsPort.listPeers())
        .thenReturn(
            List.of(
                darknetPeerSnapshot(aliceToken, "Alice", ""),
                darknetPeerSnapshot(bobToken, "Bob", "")));
    when(lifecyclePort.memoryLimitBytes()).thenReturn(memoryLimitBytes);
    when(request.isPartSet("doSendMessageToPeers")).thenReturn(true);
    when(request.isPartSet("node_" + aliceToken)).thenReturn(true);
    when(request.isPartSet("node_" + bobToken)).thenReturn(true);
    when(ctx.isAdvancedModeEnabled()).thenReturn(true);
    PageMaker pageMaker = stubPageMaker(new HTMLNode("div"));
    when(ctx.getPageMaker()).thenReturn(pageMaker);
    stubFormChild(ctx);

    ByteArrayOutputStream body = captureBody(ctx);

    toadlet.handleAltPost(new URI("http://localhost/friends/"), request, ctx, false);

    String html = body.toString(StandardCharsets.UTF_8);
    String normalizedHtml =
        html.replace("&nbsp;", " ").replace("&#160;", " ").replace('\u00A0', ' ');
    assertTrue(html.contains("Alice"));
    assertTrue(html.contains("Bob"));
    assertTrue(html.contains("name=\"node_" + aliceToken + '"'));
    assertTrue(html.contains("name=\"node_" + bobToken + '"'));
    assertTrue(
        normalizedHtml.contains(SizeUtil.formatSize(N2NTMToadlet.maxSize(memoryLimitBytes))));
    verify(lifecyclePort).memoryLimitBytes();
  }

  @Test
  void handleMethodPOST_whenUsingPeersOfferFiles_appliesDismissedOverrideAndAddsPeer()
      throws Exception {
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    when(request.isPartSet("add")).thenReturn(true);
    when(request.getPartAsStringFailsafe("url", 200)).thenReturn("");
    when(request.getPartAsStringFailsafe("ref", Integer.MAX_VALUE)).thenReturn("");
    when(request.getPartAsStringFailsafe("reffile", Integer.MAX_VALUE)).thenReturn("");
    when(request.getPartAsStringFailsafe("peerPrivateNote", 250)).thenReturn("");
    when(request.getPartAsStringFailsafe("peers-offers-files", 5)).thenReturn("true");
    when(request.getPartAsStringFailsafe("trust", 10)).thenReturn(PeerTrust.NORMAL.name());
    when(request.getPartAsStringFailsafe("visibility", 10)).thenReturn(PeerVisibility.NO.name());
    when(connectionsSupportPort.readPeerOfferReferencesText())
        .thenReturn("identity=offer-peer\nlastGoodVersion=1\nEnd\n");
    when(peerPort.add(any(), any(), any())).thenReturn(peerSnapshot("offer-peer"));
    PageMaker pageMaker = stubPageMaker(new HTMLNode("div"));
    when(ctx.getPageMaker()).thenReturn(pageMaker);
    captureBody(ctx);

    toadlet.handleMethodPOST(URI.create("http://localhost/friends/"), request, ctx);

    verify(connectionsSupportPort).readPeerOfferReferencesText();
    verify(configPort).applyOverrides(Map.of("node.peersOffersDismissed", "true"));
    ArgumentCaptor<PeerFieldSet> fieldSetCaptor = ArgumentCaptor.forClass(PeerFieldSet.class);
    verify(peerPort).add(fieldSetCaptor.capture(), eq(PeerTrust.NORMAL), eq(PeerVisibility.NO));
    assertEquals("offer-peer", fieldSetCaptor.getValue().directValues().get("identity"));
    assertEquals("1", fieldSetCaptor.getValue().directValues().get("lastGoodVersion"));
  }

  @Test
  void handleMethodPOST_whenAddPeerFormUsesUrl_delegatesReferenceLoadingThroughSupportPort()
      throws Exception {
    String locationText = "https://example.invalid/noderef";
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    when(request.isPartSet("add")).thenReturn(true);
    when(request.getPartAsStringFailsafe("url", 200)).thenReturn(locationText);
    when(request.getPartAsStringFailsafe("ref", Integer.MAX_VALUE)).thenReturn("");
    when(request.getPartAsStringFailsafe("reffile", Integer.MAX_VALUE)).thenReturn("");
    when(request.getPartAsStringFailsafe("peerPrivateNote", 250)).thenReturn("");
    when(request.getPartAsStringFailsafe("peers-offers-files", 5)).thenReturn("false");
    when(request.getPartAsStringFailsafe("trust", 10)).thenReturn(PeerTrust.NORMAL.name());
    when(request.getPartAsStringFailsafe("visibility", 10)).thenReturn(PeerVisibility.NO.name());
    when(connectionsSupportPort.readPeerReferenceText(locationText))
        .thenReturn(new StringBuilder(VALID_PEER_REFERENCE));
    when(peerPort.add(any(), any(), any())).thenReturn(peerSnapshot("peer-added"));
    when(container.isFProxyJavascriptEnabled()).thenReturn(true);
    PageMaker pageMaker = stubPageMaker(new HTMLNode("div"));
    when(ctx.getPageMaker()).thenReturn(pageMaker);
    ByteArrayOutputStream body = captureBody(ctx);

    toadlet.handleMethodPOST(URI.create("http://localhost/friends/"), request, ctx);

    verify(connectionsSupportPort).readPeerReferenceText(locationText);
    ArgumentCaptor<PeerFieldSet> fieldSetCaptor = ArgumentCaptor.forClass(PeerFieldSet.class);
    verify(peerPort).add(fieldSetCaptor.capture(), eq(PeerTrust.NORMAL), eq(PeerVisibility.NO));
    assertEquals("peer-identity", fieldSetCaptor.getValue().directValues().get("identity"));
    assertEquals("1", fieldSetCaptor.getValue().directValues().get("lastGoodVersion"));
    String html = body.toString(StandardCharsets.UTF_8);
    assertTrue(html.contains(WebShellPaths.SHELL_ROOT + "#peers"));
    assertFalse(html.contains("/addfriend/"));
  }

  @Test
  void handleMethodPOST_whenUrlReferenceLoadingFails_rendersErrorPageAndSkipsPeerAdd()
      throws Exception {
    String locationText = "https://example.invalid/noderef";
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    when(request.isPartSet("add")).thenReturn(true);
    when(request.getPartAsStringFailsafe("url", 200)).thenReturn(locationText);
    when(request.getPartAsStringFailsafe("ref", Integer.MAX_VALUE)).thenReturn("");
    when(request.getPartAsStringFailsafe("reffile", Integer.MAX_VALUE)).thenReturn("");
    when(request.getPartAsStringFailsafe("peerPrivateNote", 250)).thenReturn("");
    when(request.getPartAsStringFailsafe("peers-offers-files", 5)).thenReturn("false");
    when(request.getPartAsStringFailsafe("trust", 10)).thenReturn(PeerTrust.NORMAL.name());
    when(request.getPartAsStringFailsafe("visibility", 10)).thenReturn(PeerVisibility.NO.name());
    when(connectionsSupportPort.readPeerReferenceText(locationText))
        .thenThrow(new IOException("boom"));
    when(container.isFProxyJavascriptEnabled()).thenReturn(true);
    PageMaker pageMaker = stubPageMaker(new HTMLNode("div"));
    when(ctx.getPageMaker()).thenReturn(pageMaker);
    ByteArrayOutputStream body = captureBody(ctx);

    toadlet.handleMethodPOST(URI.create("http://localhost/friends/"), request, ctx);

    verify(connectionsSupportPort).readPeerReferenceText(locationText);
    verifyNoInteractions(peerPort);
    String html = body.toString(StandardCharsets.UTF_8);
    assertTrue(html.contains(locationText));
    assertTrue(html.contains(WebShellPaths.SHELL_ROOT + "#peers"));
    assertFalse(html.contains("/addfriend/"));
  }

  @Test
  void handleMethodPOST_whenAddPeerFormContainsDarknetReference_addsPeerAndWritesPrivateNote()
      throws Exception {
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    when(request.isPartSet("add")).thenReturn(true);
    when(request.getPartAsStringFailsafe("url", 200)).thenReturn("");
    when(request.getPartAsStringFailsafe("ref", Integer.MAX_VALUE)).thenReturn("");
    when(request.getPartAsStringFailsafe("reffile", Integer.MAX_VALUE))
        .thenReturn(VALID_PEER_REFERENCE);
    when(request.getPartAsStringFailsafe("peerPrivateNote", 250)).thenReturn("private-note");
    when(request.getPartAsStringFailsafe("peers-offers-files", 5)).thenReturn("false");
    when(request.getPartAsStringFailsafe("trust", 10)).thenReturn(PeerTrust.HIGH.name());
    when(request.getPartAsStringFailsafe("visibility", 10))
        .thenReturn(PeerVisibility.NAME_ONLY.name());
    when(peerPort.add(any(), any(), any())).thenReturn(peerSnapshot("peer-added"));
    PageMaker pageMaker = stubPageMaker(new HTMLNode("div"));
    when(ctx.getPageMaker()).thenReturn(pageMaker);
    ByteArrayOutputStream body = captureBody(ctx);

    toadlet.handleMethodPOST(URI.create("http://localhost/friends/"), request, ctx);

    ArgumentCaptor<PeerFieldSet> fieldSetCaptor = ArgumentCaptor.forClass(PeerFieldSet.class);
    verify(peerPort)
        .add(fieldSetCaptor.capture(), eq(PeerTrust.HIGH), eq(PeerVisibility.NAME_ONLY));
    verify(peerPort).writePrivateDarknetComment("peer-added", "private-note");
    assertEquals("peer-identity", fieldSetCaptor.getValue().directValues().get("identity"));
    assertEquals("1", fieldSetCaptor.getValue().directValues().get("lastGoodVersion"));
    String html = body.toString(StandardCharsets.UTF_8);
    assertTrue(html.contains(DarknetAddRefToadlet.PATH));
    assertFalse(html.contains(WebShellPaths.SHELL_ROOT + "#peers"));
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
    int peerHash = 1234;
    when(darknetConnectionsPort.listPeers())
        .thenReturn(List.of(darknetPeerSnapshot(peerHash, "Friend", "")));
    when(darknetConnectionsPort.exportPeerReference(peerHash))
        .thenReturn(Optional.of(peerNodeReferenceSnapshot()));
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

    int expectedLength =
        peerNodeReferenceFieldSet().toString().getBytes(StandardCharsets.UTF_8).length;
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
    assertEquals(
        peerNodeReferenceFieldSet().toString(),
        new String(bodyCaptor.getValue(), StandardCharsets.UTF_8));
    verify(darknetConnectionsPort).exportPeerReference(peerHash);
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

  private void assertRedirectIssued() throws Exception {
    @SuppressWarnings("unchecked")
    ArgumentCaptor<MultiValueTable<String, String>> headersCaptor =
        ArgumentCaptor.forClass(MultiValueTable.class);
    verify(ctx).sendReplyHeaders(eq(302), eq("Found"), headersCaptor.capture(), isNull(), eq(0L));
    assertEquals("/friends/", headersCaptor.getValue().getFirst("Location"));
  }

  private void assertTemporaryRedirect(String expectedLocation) throws Exception {
    @SuppressWarnings("unchecked")
    ArgumentCaptor<MultiValueTable<String, String>> headersCaptor =
        ArgumentCaptor.forClass(MultiValueTable.class);
    verify(ctx)
        .sendReplyHeaders(
            eq(302),
            eq("Found"),
            headersCaptor.capture(),
            eq("text/html; charset=UTF-8"),
            anyLong());
    assertEquals(expectedLocation, headersCaptor.getValue().getFirst("Location"));
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
                anyString(),
                anyString(),
                any(HTMLNode.class),
                nullable(String.class),
                anyBoolean()))
        .thenAnswer(
            invocation -> {
              HTMLNode parentNode = invocation.getArgument(2);
              return parentNode.addChild("div");
            });
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

  private static DarknetConnectionPeerSnapshot darknetPeerSnapshot(
      int selectionToken, String displayName, String privateNoteText) {
    return new DarknetConnectionPeerSnapshot(
        selectionToken, TEST_NODE_IDENTIFIER, displayName, privateNoteText, false);
  }

  private static NodeReferenceSnapshot ownNodeReferenceSnapshot() {
    return new NodeReferenceSnapshot(new NodeFieldSet(ownNodeReferenceValues(), Map.of()));
  }

  private static NodeReferenceSnapshot peerNodeReferenceSnapshot() {
    return new NodeReferenceSnapshot(new NodeFieldSet(Map.of("key", "value"), Map.of()));
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

  private static SimpleFieldSet peerNodeReferenceFieldSet() {
    SimpleFieldSet fieldSet = new SimpleFieldSet(true);
    fieldSet.putSingle("key", "value");
    return fieldSet;
  }

  private static List<HTMLNode> findInputsByName(HTMLNode root, String name) {
    List<HTMLNode> inputs = new ArrayList<>();
    collectInputsByName(root, name, inputs);
    return inputs;
  }

  private static void collectInputsByName(HTMLNode node, String name, List<HTMLNode> inputs) {
    if ("input".equals(node.getName()) && name.equals(node.getAttribute("name"))) {
      inputs.add(node);
    }
    for (HTMLNode child : node.getChildren()) {
      collectInputsByName(child, name, inputs);
    }
  }

  private static List<String> valuesOf(List<HTMLNode> inputs) {
    List<String> values = new ArrayList<>(inputs.size());
    for (HTMLNode input : inputs) {
      values.add(input.getAttribute("value"));
    }
    return values;
  }
}
