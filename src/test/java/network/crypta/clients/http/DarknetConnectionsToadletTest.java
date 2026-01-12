package network.crypta.clients.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.lang.reflect.Method;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.node.DarknetPeerNode;
import network.crypta.node.DarknetPeerNode.FRIEND_VISIBILITY;
import network.crypta.node.DarknetPeerNodeStatus;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.support.HTMLNode;
import network.crypta.support.MultiValueTable;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class DarknetConnectionsToadletTest {

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private NodeClientCore core;
  @Mock private HighLevelSimpleClient client;
  @Mock private ToadletContext ctx;
  @Mock private HTTPRequest request;

  private DarknetConnectionsToadlet toadlet;

  @BeforeEach
  void setUp() {
    toadlet = new DarknetConnectionsToadlet(node, core, client);
    Mockito.lenient().when(request.isPartSet(anyString())).thenReturn(false);
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
  void drawPrivateNoteColumn_whenJavascriptEnabled_includesChangeHandler() {
    HTMLNode row = new HTMLNode("tr");
    DarknetPeerNodeStatus status = mock(DarknetPeerNodeStatus.class);
    when(status.getPrivateDarknetCommentNote()).thenReturn("note");
    int statusHash = status.hashCode();

    toadlet.drawPrivateNoteColumn(row, status, true);

    String rendered = row.generate();
    assertTrue(rendered.contains("peerPrivateNote_" + statusHash));
    assertTrue(rendered.contains("onChange=\"peerNoteChange();\""));
  }

  @Test
  void drawPrivateNoteColumn_whenJavascriptDisabled_omitsChangeHandler() {
    HTMLNode row = new HTMLNode("tr");
    DarknetPeerNodeStatus status = mock(DarknetPeerNodeStatus.class);
    when(status.getPrivateDarknetCommentNote()).thenReturn("note");
    int statusHash = status.hashCode();

    toadlet.drawPrivateNoteColumn(row, status, false);

    String rendered = row.generate();
    assertTrue(rendered.contains("peerPrivateNote_" + statusHash));
    assertFalse(rendered.contains("onChange=\"peerNoteChange();\""));
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

  private void assertRedirectIssued() throws Exception {
    @SuppressWarnings("unchecked")
    ArgumentCaptor<MultiValueTable<String, String>> headersCaptor =
        ArgumentCaptor.forClass(MultiValueTable.class);
    verify(ctx).sendReplyHeaders(eq(302), eq("Found"), headersCaptor.capture(), isNull(), eq(0L));
    assertEquals("/friends/", headersCaptor.getValue().getFirst("Location"));
  }
}
