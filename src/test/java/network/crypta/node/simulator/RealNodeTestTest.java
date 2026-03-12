package network.crypta.node.simulator;

import network.crypta.crypt.RandomSource;
import network.crypta.io.comm.Peer;
import network.crypta.node.FSParseException;
import network.crypta.node.Location;
import network.crypta.node.Node;
import network.crypta.node.NodeStats;
import network.crypta.node.PeerManager;
import network.crypta.node.PeerNode;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class RealNodeTestTest {

  @Test
  void makeKleinbergNetwork_whenIdealLocationsTrue_setsEvenlySpacedLocations() {
    // Arrange
    Node[] nodes =
        new Node[] {
          mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS),
          mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS),
          mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS)
        };
    NodeNetworkSubsystem[] networks =
        new NodeNetworkSubsystem[] {
          mock(NodeNetworkSubsystem.class),
          mock(NodeNetworkSubsystem.class),
          mock(NodeNetworkSubsystem.class)
        };
    double[] locations = new double[nodes.length];
    for (int i = 0; i < nodes.length; i++) {
      final int index = i;
      when(nodes[i].network()).thenReturn(networks[i]);
      doAnswer(
              invocation -> {
                locations[index] = invocation.getArgument(0);
                return null;
              })
          .when(networks[i])
          .setLocation(org.mockito.ArgumentMatchers.anyDouble());
      when(networks[i].location()).thenAnswer(invocation -> locations[index]);
    }
    RandomSource random = mock(RandomSource.class);

    // Act
    RealNodeTest.makeKleinbergNetwork(nodes, true, 0, false, random);

    // Assert
    assertEquals(0.0, locations[0], 1e-9);
    assertEquals(1.0 / 3.0, locations[1], 1e-9);
    assertEquals(2.0 / 3.0, locations[2], 1e-9);
  }

  @Test
  void makeKleinbergNetwork_whenForceNeighbourConnectionsTrue_connectsNeighborsBidirectionally()
      throws Exception {
    // Arrange
    Node[] nodes =
        new Node[] {
          mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS),
          mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS),
          mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS),
          mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS)
        };
    NodeNetworkSubsystem[] networks =
        new NodeNetworkSubsystem[] {
          mock(NodeNetworkSubsystem.class),
          mock(NodeNetworkSubsystem.class),
          mock(NodeNetworkSubsystem.class),
          mock(NodeNetworkSubsystem.class)
        };
    for (int i = 0; i < nodes.length; i++) {
      when(nodes[i].network()).thenReturn(networks[i]);
    }
    RandomSource random = mock(RandomSource.class);

    // Act
    RealNodeTest.makeKleinbergNetwork(nodes, false, 0, true, random);

    // Assert
    for (int i = 0; i < nodes.length; i++) {
      int next = (i + 1) % nodes.length;
      verify(networks[i]).connect(nodes[next], RealNodeTest.trust, RealNodeTest.visibility);
      verify(networks[next]).connect(nodes[i], RealNodeTest.trust, RealNodeTest.visibility);
    }
  }

  @Test
  void makeKleinbergNetwork_whenRandomAlwaysAccepts_connectsBothDirectionsForTwoNodes()
      throws Exception {
    // Arrange
    Node[] nodes =
        new Node[] {
          mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS),
          mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS)
        };
    NodeNetworkSubsystem[] networks =
        new NodeNetworkSubsystem[] {
          mock(NodeNetworkSubsystem.class), mock(NodeNetworkSubsystem.class)
        };
    double[] locations = new double[nodes.length];
    for (int i = 0; i < nodes.length; i++) {
      final int index = i;
      when(nodes[i].network()).thenReturn(networks[i]);
      doAnswer(
              invocation -> {
                locations[index] = invocation.getArgument(0);
                return null;
              })
          .when(networks[i])
          .setLocation(org.mockito.ArgumentMatchers.anyDouble());
      when(networks[i].location()).thenAnswer(invocation -> locations[index]);
    }
    RandomSource random = mock(RandomSource.class);
    when(random.nextFloat()).thenReturn(0.0f);

    // Act
    RealNodeTest.makeKleinbergNetwork(nodes, true, 2, false, random);

    // Assert
    verify(networks[0], times(2)).connect(nodes[1], RealNodeTest.trust, RealNodeTest.visibility);
    verify(networks[1], times(2)).connect(nodes[0], RealNodeTest.trust, RealNodeTest.visibility);
  }

  @Test
  void connect_whenFirstConnectThrows_doesNotPropagateAndSkipsSecond() throws Exception {
    // Arrange
    Node a = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    Node b = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    NodeNetworkSubsystem netA = mock(NodeNetworkSubsystem.class);
    NodeNetworkSubsystem netB = mock(NodeNetworkSubsystem.class);
    when(a.network()).thenReturn(netA);
    when(b.network()).thenReturn(netB);
    doThrow(new FSParseException("boom"))
        .when(netA)
        .connect(b, RealNodeTest.trust, RealNodeTest.visibility);

    // Act + Assert
    assertDoesNotThrow(() -> RealNodeTest.connect(a, b));
    verify(netA).connect(b, RealNodeTest.trust, RealNodeTest.visibility);
    verify(netB, never()).connect(a, RealNodeTest.trust, RealNodeTest.visibility);
  }

  @Test
  void distance_whenLocationsValid_returnsLocationDistance() {
    // Arrange
    Node a = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    Node b = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    when(a.network().location()).thenReturn(0.1);
    when(b.network().location()).thenReturn(0.9);

    // Act
    double distance = RealNodeTest.distance(a, b);

    // Assert
    assertEquals(0.2, distance, 1e-9);
  }

  @Test
  void distance_whenLocationInvalid_throwsIllegalArgumentException() {
    // Arrange
    Node a = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    Node b = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    when(a.network().location()).thenReturn(Location.LOCATION_INVALID);
    when(b.network().location()).thenReturn(0.5);

    // Act + Assert
    assertThrows(IllegalArgumentException.class, () -> RealNodeTest.distance(a, b));
  }

  @Test
  void getPortNumber_whenPeerNodeOrPeerNull_returnsNullString() {
    // Arrange
    PeerNode peerNode = mock(PeerNode.class);
    when(peerNode.getPeer()).thenReturn(null);

    // Act + Assert
    assertEquals("null", RealNodeTest.getPortNumber((PeerNode) null));
    assertEquals("null", RealNodeTest.getPortNumber(peerNode));
  }

  @Test
  void getPortNumber_whenPeerPresent_returnsPort() {
    // Arrange
    PeerNode peerNode = mock(PeerNode.class);
    Peer peer = mock(Peer.class);
    when(peer.getPort()).thenReturn(12345);
    when(peerNode.getPeer()).thenReturn(peer);

    // Act
    String port = RealNodeTest.getPortNumber(peerNode);

    // Assert
    assertEquals("12345", port);
  }

  @Test
  void getPortNumber_whenNodeNull_returnsNullString() {
    // Act + Assert
    assertEquals("null", RealNodeTest.getPortNumber((Node) null));
  }

  @Test
  void getPortNumber_whenNodePresent_returnsPort() {
    // Arrange
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    when(node.network().darknetPortNumber()).thenReturn(4242);

    // Act
    String port = RealNodeTest.getPortNumber(node);

    // Assert
    assertEquals("4242", port);
  }

  @Test
  void waitForAllConnected_whenAllConditionsMet_returnsWithoutDelay() {
    // Arrange
    Node nodeA = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    Node nodeB = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    PeerManager peersA = mock(PeerManager.class);
    PeerManager peersB = mock(PeerManager.class);
    NodeStats statsA = mock(NodeStats.class);
    NodeStats statsB = mock(NodeStats.class);

    when(nodeA.network().peers()).thenReturn(peersA);
    when(nodeB.network().peers()).thenReturn(peersB);
    when(nodeA.network().stats()).thenReturn(statsA);
    when(nodeB.network().stats()).thenReturn(statsB);

    when(peersA.countConnectedDarknetPeers()).thenReturn(2);
    when(peersA.countAlmostConnectedDarknetPeers()).thenReturn(2);
    when(peersA.countValidPeers()).thenReturn(2);
    when(peersA.countBackedOffPeers(false)).thenReturn(0);
    when(peersA.countCompatibleDarknetPeers()).thenReturn(2);

    when(peersB.countConnectedDarknetPeers()).thenReturn(1);
    when(peersB.countAlmostConnectedDarknetPeers()).thenReturn(1);
    when(peersB.countValidPeers()).thenReturn(1);
    when(peersB.countBackedOffPeers(false)).thenReturn(0);
    when(peersB.countCompatibleDarknetPeers()).thenReturn(1);

    when(statsA.getNodeAveragePingTime()).thenReturn(100.0);
    when(statsB.getNodeAveragePingTime()).thenReturn(100.0);

    // Act + Assert
    assertDoesNotThrow(() -> RealNodeTest.waitForAllConnected(new Node[] {nodeA, nodeB}));
    verify(peersA).countConnectedDarknetPeers();
    verify(peersB).countConnectedDarknetPeers();
  }
}
