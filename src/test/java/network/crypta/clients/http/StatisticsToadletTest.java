package network.crypta.clients.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.URI;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.NodeStats;
import network.crypta.node.OpennetManager;
import network.crypta.node.PeerManager;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class StatisticsToadletTest {

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private NodeClientCore core;
  @Mock private HighLevelSimpleClient client;
  @Mock private NodeStats nodeStats;
  @Mock private PeerManager peerManager;

  private StatisticsToadlet toadlet;

  @BeforeEach
  void setUp() {
    network.crypta.node.subsystem.NodeNetworkSubsystem network =
        org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeNetworkSubsystem.class);
    when(node.network()).thenReturn(network);
    when(network.stats()).thenReturn(nodeStats);
    when(network.peers()).thenReturn(peerManager);
    toadlet = new StatisticsToadlet(node, core, client) {};
  }

  @Test
  void path_returnsStatsPath() {
    assertEquals("/stats/", toadlet.path());
  }

  @Test
  void handleMethodGET_whenAccessDenied_returnsWithoutFurtherInteraction()
      throws IOException, ToadletContextClosedException, RedirectException {
    HTTPRequest request = mock(HTTPRequest.class);
    ToadletContext ctx = mock(ToadletContext.class);

    when(ctx.checkFullAccess(toadlet)).thenReturn(false);

    toadlet.handleMethodGET(URI.create("/stats/"), request, ctx);

    verify(ctx).checkFullAccess(toadlet);
    verifyNoMoreInteractions(ctx);
  }

  @Test
  void drawPeerStatsBox_whenCountsZero_doesNotRenderStatusEntries() {
    HTMLNode infobox = new HTMLNode("div");
    Node nodeWithoutOpennet = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    network.crypta.node.subsystem.NodeNetworkSubsystem networkWithoutOpennet =
        org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeNetworkSubsystem.class);
    when(nodeWithoutOpennet.network()).thenReturn(networkWithoutOpennet);
    when(networkWithoutOpennet.opennet()).thenReturn(null);

    StatisticsToadlet.drawPeerStatsBox(
        infobox,
        false,
        0, // connected
        0, // routingBackedOff
        0, // tooNew
        0, // tooOld
        0, // disconnected
        0, // neverConnected
        0, // disabled
        0, // bursting
        0, // listening
        0, // listenOnly
        0, // seedServers
        0, // seedClients
        0, // routingDisabled
        0, // clockProblem
        0, // connError
        0, // disconnecting
        0, // noLoadStats
        nodeWithoutOpennet);

    String rendered = infobox.generate();

    assertTrue(rendered.contains("<ul>"));
    assertFalse(rendered.contains("peer_connected"));
    assertFalse(rendered.contains("peer_backed_off"));
  }

  @Test
  void drawPeerStatsBox_whenCountsPresent_rendersEntriesAndOpennetTotals() {
    HTMLNode infobox = new HTMLNode("div");
    Node nodeWithOpennet = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    OpennetManager opennet = mock(OpennetManager.class);
    when(opennet.getNumberOfConnectedPeersToAimIncludingDarknet()).thenReturn(7);
    when(opennet.getNumberOfConnectedPeersToAim()).thenReturn(3);
    network.crypta.node.subsystem.NodeNetworkSubsystem networkWithOpennet =
        org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeNetworkSubsystem.class);
    when(nodeWithOpennet.network()).thenReturn(networkWithOpennet);
    when(networkWithOpennet.opennet()).thenReturn(opennet);

    StatisticsToadlet.drawPeerStatsBox(
        infobox,
        true,
        2, // connected
        1, // routingBackedOff
        1, // tooNew
        0, // tooOld
        0, // disconnected
        0, // neverConnected
        0, // disabled
        0, // bursting
        0, // listening
        0, // listenOnly
        0, // seedServers
        1, // seedClients
        0, // routingDisabled
        0, // clockProblem
        0, // connError
        0, // disconnecting
        0, // noLoadStats
        nodeWithOpennet);

    String rendered = infobox.generate();

    assertTrue(rendered.contains("peer_connected"));
    assertTrue(rendered.contains("peer_backed_off"));
    assertTrue(rendered.contains("peer_too_new"));
    assertTrue(rendered.contains("peer_listening"));
    assertTrue(rendered.contains("7"));
    assertTrue(rendered.contains("3"));
  }
}
