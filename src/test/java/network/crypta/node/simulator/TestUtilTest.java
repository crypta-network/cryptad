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
    Node node = mock(Node.class);
    OpennetManager opennet = mock(OpennetManager.class);
    PeerManager peers = mock(PeerManager.class);
    when(node.getOpennet()).thenReturn(opennet);
    when(opennet.getAnnouncementThreshold()).thenReturn(3);
    when(node.getPeers()).thenReturn(peers);
    when(peers.countSeednodes()).thenReturn(1);
    when(peers.getConnectedSeedServerPeersVector(null)).thenReturn(List.of());
    when(peers.countValidPeers()).thenReturn(2);
    when(peers.countConnectedOpennetPeers()).thenReturn(3);

    // Act
    boolean result = TestUtil.waitForNodes(node);

    // Assert
    assertTrue(result);
    verify(peers).countConnectedOpennetPeers();
    verify(peers).countSeednodes();
    verify(peers).countValidPeers();
    verify(peers).getConnectedSeedServerPeersVector(null);
  }

  @Test
  void waitForNodes_whenSleepInterrupted_expectInterruptedException() {
    // Arrange
    Node node = mock(Node.class);
    OpennetManager opennet = mock(OpennetManager.class);
    when(node.getOpennet()).thenReturn(opennet);
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
