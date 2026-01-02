package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Hashtable;
import network.crypta.support.math.RunningAverage;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class OpennetPeerNodeStatusTest {

  private static OpennetPeerNode mockMinimalOpennetPeerNode(long timeLastSuccessValue) {
    OpennetPeerNode node = mock(OpennetPeerNode.class);

    // Keep address path in PeerNodeStatus constructor on the null branch.
    when(node.getPeer()).thenReturn(null);

    PeerTransport transport = mock(PeerTransport.class);
    when(transport.getThrottle()).thenReturn(null);
    when(node.transport()).thenReturn(transport);

    // Backoff percent access requires non-null RunningAverage instances.
    RunningAverage rt = mock(RunningAverage.class);
    when(rt.currentValue()).thenReturn(0.0);
    RunningAverage bulk = mock(RunningAverage.class);
    when(bulk.currentValue()).thenReturn(0.0);
    when(node.getBackedOffPercentRT()).thenReturn(rt);
    when(node.getBackedOffPercentBulk()).thenReturn(bulk);

    // Specific to OpennetPeerNodeStatus.
    when(node.timeLastSuccess()).thenReturn(timeLastSuccessValue);
    return node;
  }

  @Test
  @DisplayName("constructor_whenOpennetPeer_setsTimeLastSuccessFromNode")
  void constructor_whenOpennetPeer_setsTimeLastSuccessFromNode() {
    // Arrange
    long expected = 123_456_789L;
    OpennetPeerNode node = mockMinimalOpennetPeerNode(expected);

    // Act
    OpennetPeerNodeStatus status = new OpennetPeerNodeStatus(node, true);

    // Assert
    assertEquals(expected, status.timeLastSuccess);
  }

  @Test
  @DisplayName("constructor_whenPeerIsNotOpennet_throwsClassCastException")
  void constructor_whenPeerIsNotOpennet_throwsClassCastException() {
    // Arrange: minimal PeerNode stub so super(...) path succeeds
    PeerNode base = mock(PeerNode.class);
    when(base.getPeer()).thenReturn(null);
    PeerTransport transport = mock(PeerTransport.class);
    when(transport.getThrottle()).thenReturn(null);
    when(base.transport()).thenReturn(transport);

    RunningAverage rt = mock(RunningAverage.class);
    when(rt.currentValue()).thenReturn(0.0);
    RunningAverage bulk = mock(RunningAverage.class);
    when(bulk.currentValue()).thenReturn(0.0);
    // getBackedOffPercent* are package-private; the test lives in the same package
    doReturn(rt).when(base).getBackedOffPercentRT();
    doReturn(bulk).when(base).getBackedOffPercentBulk();

    // Act + Assert
    assertThrows(ClassCastException.class, () -> new OpennetPeerNodeStatus(base, true));
  }

  @Test
  @DisplayName("constructor_whenNoHeavyTrue_heavyMapsAreNull")
  void constructor_whenNoHeavyTrue_heavyMapsAreNull() {
    // Arrange
    OpennetPeerNode node = mockMinimalOpennetPeerNode(0L);

    // Act
    OpennetPeerNodeStatus status = new OpennetPeerNodeStatus(node, true);

    // Assert
    assertNull(status.getLocalMessagesReceived());
    assertNull(status.getLocalMessagesSent());
  }

  @Test
  @DisplayName("constructor_whenNoHeavyFalse_heavyMapsArePopulated")
  void constructor_whenNoHeavyFalse_heavyMapsArePopulated() {
    // Arrange
    OpennetPeerNode node = mockMinimalOpennetPeerNode(42L);
    Hashtable<String, Long> received = new Hashtable<>();
    received.put("Hello", 3L);
    Hashtable<String, Long> sent = new Hashtable<>();
    sent.put("World", 4L);
    when(node.getLocalNodeReceivedMessagesFromStatistic()).thenReturn(received);
    when(node.getLocalNodeSentMessagesToStatistic()).thenReturn(sent);

    // Act
    OpennetPeerNodeStatus status = new OpennetPeerNodeStatus(node, false);

    // Assert
    assertEquals(received, status.getLocalMessagesReceived());
    assertEquals(sent, status.getLocalMessagesSent());
  }
}
