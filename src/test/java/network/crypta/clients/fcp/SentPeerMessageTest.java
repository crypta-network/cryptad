package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verifyNoInteractions;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class SentPeerMessageTest {

  @Mock private FCPConnectionHandler handler;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Test
  void getFieldSet_withValues_containsIdentifierAndNodeStatus() {
    // Arrange
    SentPeerMessage message = new SentPeerMessage("peer-123", 7);

    // Act
    SimpleFieldSet fieldSet = message.getFieldSet();

    // Assert
    assertEquals("peer-123", fieldSet.get("Identifier"));
    assertEquals("7", fieldSet.get("NodeStatus"));
  }

  @Test
  void getFieldSet_withNullIdentifier_omitsIdentifierButRetainsNodeStatus() {
    // Arrange
    SentPeerMessage message = new SentPeerMessage(null, -1);

    // Act
    SimpleFieldSet fieldSet = message.getFieldSet();

    // Assert
    assertNull(fieldSet.get("Identifier"));
    assertEquals("-1", fieldSet.get("NodeStatus"));
  }

  @Test
  void getName_whenCalled_returnsSentPeer() {
    // Arrange
    SentPeerMessage message = new SentPeerMessage("id", 0);

    // Act & Assert
    assertEquals(SentPeerMessage.NAME, message.getName());
  }

  @Test
  void run_whenInvoked_throwsMessageInvalidExceptionWithDetails() {
    // Arrange
    SentPeerMessage message = new SentPeerMessage("peer-id", 1);

    // Act
    MessageInvalidException thrown =
        assertThrows(MessageInvalidException.class, () -> message.run(handler));

    // Assert
    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, thrown.protocolCode);
    assertEquals("peer-id", thrown.ident);
    assertEquals(
        message.getName() + " goes from server to client not the other way around",
        thrown.getMessage());
    assertFalse(thrown.global);
    verifyNoInteractions(handler, node);
  }
}
