package network.crypta.node;

import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

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

    when(node.getBackedOffPercentRT()).thenReturn(0.0);
    when(node.getBackedOffPercentBulk()).thenReturn(0.0);

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
    Map<String, Long> received = new HashMap<>();
    received.put("Hello", 3L);
    Map<String, Long> sent = new HashMap<>();
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
