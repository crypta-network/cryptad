package network.crypta.node.simulator;

import java.util.Random;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.crypt.EntropySource;
import network.crypta.crypt.RandomSource;
import network.crypta.node.LocationManager;
import network.crypta.node.Node;
import network.crypta.node.NodeStats;
import network.crypta.node.PeerManager;
import network.crypta.node.PeerNode;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.runtime.bootstrap.NodeBootstrap;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyDouble;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class RealNodePitchBlackMitigationTestTest {

  @Test
  void attackSpecificNode_whenRandomZero_setsLocationAtMean() {
    Random random = mock(Random.class);
    when(random.nextDouble()).thenReturn(0.0);

    AtomicReference<Double> location = new AtomicReference<>(0.0);
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    NodeBootstrap bootstrap = mock(NodeBootstrap.class);
    NodeNetworkSubsystem network = mock(NodeNetworkSubsystem.class);
    when(node.bootstrap()).thenReturn(bootstrap);
    when(bootstrap.fastWeakRandom()).thenReturn(random);
    when(node.network()).thenReturn(network);
    when(network.location()).thenAnswer(invocation -> location.get());
    doAnswer(
            invocation -> {
              location.set(invocation.getArgument(0));
              return null;
            })
        .when(network)
        .setLocation(anyDouble());

    RealNodePitchBlackMitigationTest.attackSpecificNode(0.5, 0.1, node, 7);

    verify(network).setLocation(0.5);
  }

  @Test
  void attackSpecificNode_whenRandomNonZero_offsetsByJitter() {
    Random random = mock(Random.class);
    when(random.nextDouble()).thenReturn(0.25);

    AtomicReference<Double> location = new AtomicReference<>(0.0);
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    NodeBootstrap bootstrap = mock(NodeBootstrap.class);
    NodeNetworkSubsystem network = mock(NodeNetworkSubsystem.class);
    when(node.bootstrap()).thenReturn(bootstrap);
    when(bootstrap.fastWeakRandom()).thenReturn(random);
    when(node.network()).thenReturn(network);
    when(network.location()).thenAnswer(invocation -> location.get());
    doAnswer(
            invocation -> {
              location.set(invocation.getArgument(0));
              return null;
            })
        .when(network)
        .setLocation(anyDouble());

    RealNodePitchBlackMitigationTest.attackSpecificNode(0.4, 0.2, node, 3);

    ArgumentCaptor<Double> locationCaptor = ArgumentCaptor.forClass(Double.class);
    verify(network).setLocation(locationCaptor.capture());
    assertEquals(0.45, locationCaptor.getValue(), 1e-9);
  }

  @Test
  void attackSpecificNode_whenNodeNull_throwsNullPointerException() {
    //noinspection DataFlowIssue
    assertThrows(
        NullPointerException.class,
        () -> RealNodePitchBlackMitigationTest.attackSpecificNode(0.5, 0.1, null, 1));
  }

  @Test
  void waitForPingAverage_whenAccuracyReached_returnsNormally() {
    Node nodeA = createConnectedNode(0.1, 1111);
    Node nodeB = createConnectedNode(0.9, 2222);
    Node[] nodes = new Node[] {nodeA, nodeB};

    RandomSource random = new AlternatingRandomSource();

    assertDoesNotThrow(
        () -> RealNodePitchBlackMitigationTest.waitForPingAverage(0.5, nodes, random, 43, 0));
  }

  private static Node createConnectedNode(double location, int port) {
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    NodeNetworkSubsystem network = mock(NodeNetworkSubsystem.class);
    PeerManager peers = mock(PeerManager.class);
    NodeStats stats = mock(NodeStats.class);
    LocationManager locationManager = mock(LocationManager.class);

    when(node.network()).thenReturn(network);
    when(network.peers()).thenReturn(peers);
    when(peers.countConnectedDarknetPeers()).thenReturn(0);
    when(peers.countAlmostConnectedDarknetPeers()).thenReturn(0);
    when(peers.countValidPeers()).thenReturn(0);
    when(peers.countBackedOffPeers(false)).thenReturn(0);
    when(peers.countCompatibleDarknetPeers()).thenReturn(0);

    when(network.stats()).thenReturn(stats);
    when(stats.getNodeAveragePingTime()).thenReturn(0.0);

    when(network.peerNodes()).thenReturn(new PeerNode[0]);
    when(network.location()).thenReturn(location);

    when(network.locationManager()).thenReturn(locationManager);
    when(locationManager.getSendSwapInterval()).thenReturn(0L);
    when(locationManager.getAverageSwapTime()).thenReturn(0);

    when(network.darknetPortNumber()).thenReturn(port);
    when(network.darknetPubKeyHash()).thenReturn(new byte[0]);
    when(network.routedPing(anyDouble(), any(byte[].class))).thenReturn(1);

    return node;
  }

  private static final class AlternatingRandomSource extends RandomSource {
    private int pairIndex;
    private boolean secondInPair;

    @Override
    public int nextInt(int bound) {
      if (bound <= 1) {
        return 0;
      }
      int start = pairIndex % bound;
      int value = secondInPair ? (start + 1) % bound : start;
      if (secondInPair) {
        pairIndex++;
      }
      secondInPair = !secondInPair;
      return value;
    }

    @Override
    public int acceptEntropy(EntropySource source, long data, int entropyGuess) {
      return 0;
    }

    @Override
    public int acceptTimerEntropy(EntropySource timer) {
      return 0;
    }

    @Override
    public int acceptTimerEntropy(EntropySource fnpTimingSource, double bias) {
      return 0;
    }

    @Override
    public int acceptEntropyBytes(
        EntropySource myPacketDataSource, byte[] buf, int offset, int length, double bias) {
      return 0;
    }

    @Override
    public void close() {
      // No resources to release in test-only deterministic source.
    }
  }
}
