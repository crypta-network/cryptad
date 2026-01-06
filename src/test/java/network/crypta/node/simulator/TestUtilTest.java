package network.crypta.node.simulator;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import network.crypta.node.Node;
import network.crypta.node.OpennetManager;
import network.crypta.node.PeerManager;
import network.crypta.node.SeedPeerQueries;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class TestUtilTest {
  @Test
  void waitForNodes_whenOpennetConnectionsReachTarget_expectTrueAndStopsEarly()
      throws InterruptedException {
    // Arrange
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    OpennetManager opennet = mock(OpennetManager.class);
    PeerManager peers = mock(PeerManager.class);
    SeedPeerQueries seedPeers = mock(SeedPeerQueries.class);
    when(node.network().opennet()).thenReturn(opennet);
    when(opennet.getAnnouncementThreshold()).thenReturn(3);
    when(node.network().peers()).thenReturn(peers);
    when(peers.seedPeers()).thenReturn(seedPeers);
    when(peers.countSeednodes()).thenReturn(1);
    when(seedPeers.getConnectedSeedServerPeersVector(null)).thenReturn(List.of());
    when(peers.countValidPeers()).thenReturn(2);
    when(peers.countConnectedOpennetPeers()).thenReturn(3);

    // Act
    boolean result = TestUtil.waitForNodes(node);

    // Assert
    assertTrue(result);
    verify(peers).countConnectedOpennetPeers();
    verify(peers).countSeednodes();
    verify(peers).countValidPeers();
    verify(seedPeers).getConnectedSeedServerPeersVector(null);
  }

  @Test
  void waitForNodes_whenSleepInterrupted_expectInterruptedException() {
    // Arrange
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    OpennetManager opennet = mock(OpennetManager.class);
    when(node.network().opennet()).thenReturn(opennet);
    when(opennet.getAnnouncementThreshold()).thenReturn(1);

    Thread.currentThread().interrupt();
    try {
      // Act + Assert
      assertThrows(InterruptedException.class, () -> TestUtil.waitForNodes(node));
    } finally {
      assertFalse(Thread.interrupted());
    }
  }
}
