package network.crypta.clients.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.URI;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.node.DarknetPeerNode;
import network.crypta.node.DarknetPeerNode.FRIEND_VISIBILITY;
import network.crypta.node.DarknetPeerNodeStatus;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.NodeStats;
import network.crypta.node.PeerManager;
import network.crypta.support.HTMLNode;
import network.crypta.support.MultiValueTable;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings("java:S100")
class DarknetConnectionsToadletTest {

  @Mock private Node node;
  @Mock private NodeClientCore core;
  @Mock private HighLevelSimpleClient client;
  @Mock private NodeStats stats;
  @Mock private PeerManager peerManager;

  private DarknetConnectionsToadlet toadlet;

  @BeforeEach
  void setUp() {
    when(node.getNodeStats()).thenReturn(stats);
    when(node.getPeers()).thenReturn(peerManager);
    toadlet = new DarknetConnectionsToadlet(node, core, client);
  }

  @Test
  void comparator_sortByName_expectCaseInsensitiveOrdering() {
    DarknetConnectionsToadlet.DarknetComparator comparator =
        (DarknetConnectionsToadlet.DarknetComparator) toadlet.comparator("name", false);

    DarknetPeerNodeStatus first = mock(DarknetPeerNodeStatus.class);
    DarknetPeerNodeStatus second = mock(DarknetPeerNodeStatus.class);
    when(first.getName()).thenReturn("alice");
    when(second.getName()).thenReturn("Bob");

    int result = comparator.compare(first, second);

    assertEquals(-1, result);
  }

  @Test
  void comparator_sortByVisibility_usesSecondaryVisibilityWhenNeeded() {
    DarknetConnectionsToadlet.DarknetComparator comparator =
        (DarknetConnectionsToadlet.DarknetComparator) toadlet.comparator("visibility", false);

    DarknetPeerNodeStatus first = mock(DarknetPeerNodeStatus.class);
    DarknetPeerNodeStatus second = mock(DarknetPeerNodeStatus.class);
    when(first.getOurVisibility()).thenReturn(FRIEND_VISIBILITY.NO);
    when(second.getOurVisibility()).thenReturn(FRIEND_VISIBILITY.NO);
    when(first.getTheirVisibility()).thenReturn(FRIEND_VISIBILITY.NO);
    when(second.getTheirVisibility()).thenReturn(FRIEND_VISIBILITY.YES);

    int result = comparator.compare(first, second);

    assertEquals(1, result);
  }

  @Test
  void drawPrivateNoteColumn_whenJavascriptEnabled_setsOnChangeHandler() {
    DarknetPeerNodeStatus status = mock(DarknetPeerNodeStatus.class);
    when(status.getPrivateDarknetCommentNote()).thenReturn("note");

    HTMLNode row = new HTMLNode("tr");

    toadlet.drawPrivateNoteColumn(row, status, true);

    HTMLNode cell = row.getChildren().getFirst();
    HTMLNode input = cell.getChildren().getFirst();

    assertEquals("td", cell.getName());
    assertEquals("peer-private-darknet-comment-note", cell.getAttribute("class"));
    assertEquals("input", input.getName());
    assertEquals("peerNoteChange();", input.getAttribute("onChange"));
  }

  @Test
  void drawPrivateNoteColumn_whenJavascriptDisabled_skipsOnChangeHandler() {
    DarknetPeerNodeStatus status = mock(DarknetPeerNodeStatus.class);
    when(status.getPrivateDarknetCommentNote()).thenReturn("note");

    HTMLNode row = new HTMLNode("tr");

    toadlet.drawPrivateNoteColumn(row, status, false);

    HTMLNode input = row.getChildren().getFirst().getChildren().getFirst();

    assertNull(input.getAttribute("onChange"));
  }

  @Test
  void handleAltPost_updateNotes_updatesChangedNotesAndRedirects() throws Exception {
    DarknetPeerNode peerToChange = mock(DarknetPeerNode.class);
    when(peerToChange.getPrivateDarknetCommentNote()).thenReturn("old-note");

    DarknetPeerNode peerUnchanged = mock(DarknetPeerNode.class);
    when(peerUnchanged.getPrivateDarknetCommentNote()).thenReturn("keep");

    int peerToChangeHash = peerToChange.hashCode();
    int peerUnchangedHash = peerUnchanged.hashCode();

    when(node.getDarknetConnections())
        .thenReturn(new DarknetPeerNode[] {peerToChange, peerUnchanged});

    HTTPRequest request = mock(HTTPRequest.class);
    lenient().when(request.isPartSet(anyString())).thenReturn(false);
    when(request.isPartSet("doAction")).thenReturn(true);
    when(request.getPartAsStringFailsafe("action", 25)).thenReturn("update_notes");
    when(request.isPartSet("peerPrivateNote_" + peerToChangeHash)).thenReturn(true);
    when(request.getPartAsStringFailsafe("peerPrivateNote_" + peerToChangeHash, 250))
        .thenReturn("new-note");
    when(request.isPartSet("peerPrivateNote_" + peerUnchangedHash)).thenReturn(true);
    when(request.getPartAsStringFailsafe("peerPrivateNote_" + peerUnchangedHash, 250))
        .thenReturn("keep");

    ToadletContext ctx = mock(ToadletContext.class);
    doNothing().when(ctx).sendReplyHeaders(anyInt(), anyString(), any(), anyString(), anyLong());
    doNothing()
        .when(ctx)
        .sendReplyHeaders(anyInt(), anyString(), any(), anyString(), anyLong(), anyBoolean());

    toadlet.handleAltPost(new URI("http://localhost/friends/"), request, ctx, false);

    verify(peerToChange).setPrivateDarknetCommentNote("new-note");
    verify(node).getDarknetConnections();

    @SuppressWarnings("unchecked")
    ArgumentCaptor<MultiValueTable<String, String>> headers =
        ArgumentCaptor.forClass(
            (Class<MultiValueTable<String, String>>) (Class<?>) MultiValueTable.class);
    verify(ctx).sendReplyHeaders(eq(302), eq("Found"), headers.capture(), isNull(), eq(0L));
    assertEquals("/friends/", headers.getValue().getAllAsList("Location").getFirst());
  }

  @Test
  void handleAltPost_removePeers_removesWhenOldEnough() throws Exception {
    DarknetPeerNode peer = mock(DarknetPeerNode.class);
    when(peer.timeLastConnectionCompleted()).thenReturn(0L);
    when(peer.getPeerNodeStatus()).thenReturn(PeerManager.PEER_NODE_STATUS_NEVER_CONNECTED);

    int peerHash = peer.hashCode();

    when(node.getDarknetConnections()).thenReturn(new DarknetPeerNode[] {peer});

    HTTPRequest request = mock(HTTPRequest.class);
    lenient().when(request.isPartSet(anyString())).thenReturn(false);
    when(request.isPartSet("doAction")).thenReturn(true);
    when(request.getPartAsStringFailsafe("action", 25)).thenReturn("remove");
    when(request.isPartSet("node_" + peerHash)).thenReturn(true);

    ToadletContext ctx = mock(ToadletContext.class);
    doNothing().when(ctx).sendReplyHeaders(anyInt(), anyString(), any(), anyString(), anyLong());
    doNothing()
        .when(ctx)
        .sendReplyHeaders(anyInt(), anyString(), any(), anyString(), anyLong(), anyBoolean());

    toadlet.handleAltPost(new URI("http://localhost/friends/"), request, ctx, false);

    verify(node).removePeerConnection(peer);

    @SuppressWarnings("unchecked")
    ArgumentCaptor<MultiValueTable<String, String>> headers =
        ArgumentCaptor.forClass(
            (Class<MultiValueTable<String, String>>) (Class<?>) MultiValueTable.class);
    verify(ctx).sendReplyHeaders(eq(302), eq("Found"), headers.capture(), isNull(), eq(0L));
    assertEquals("/friends/", headers.getValue().getAllAsList("Location").getFirst());
  }

  @Test
  void handleMethodGET_frefPath_sendsNoderefDownload() throws Exception {
    SimpleFieldSet noderef = new SimpleFieldSet(true);

    DarknetPeerNode peer = mock(DarknetPeerNode.class);
    when(peer.getName()).thenReturn("Friend");
    when(peer.getFullNoderef()).thenReturn(noderef);
    int peerHash = peer.hashCode();
    when(node.getDarknetConnections()).thenReturn(new DarknetPeerNode[] {peer});

    ToadletContext ctx = mock(ToadletContext.class);
    doNothing().when(ctx).sendReplyHeaders(anyInt(), anyString(), any(), anyString(), anyLong());
    doNothing()
        .when(ctx)
        .sendReplyHeaders(anyInt(), anyString(), any(), anyString(), anyLong(), anyBoolean());

    ArgumentCaptor<byte[]> body = ArgumentCaptor.forClass(byte[].class);
    doNothing().when(ctx).writeData(body.capture(), anyInt(), anyInt());

    HTTPRequest request = mock(HTTPRequest.class);

    URI uri = new URI("http://localhost/friends/friend-" + peerHash + ".fref");

    toadlet.handleMethodGET(uri, request, ctx);

    verify(ctx)
        .sendReplyHeaders(
            anyInt(),
            anyString(),
            any(),
            org.mockito.ArgumentMatchers.eq("application/x-freenet-reference"),
            anyLong(),
            anyBoolean());
    verify(ctx).writeData(any(byte[].class), anyInt(), anyInt());
  }
}
