package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class UnknownNodeIdentifierMessageTest {

  @Mock private FCPConnectionHandler handler;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Test
  void getFieldSet_whenIdentifierPresent_containsBothFields() {
    UnknownNodeIdentifierMessage message =
        new UnknownNodeIdentifierMessage("node-123", "request-456");

    SimpleFieldSet result = message.getFieldSet();

    assertEquals("node-123", result.get("NodeIdentifier"));
    assertEquals("request-456", result.get("Identifier"));
  }

  @Test
  void getFieldSet_whenIdentifierMissing_excludesIdentifierField() {
    UnknownNodeIdentifierMessage message = new UnknownNodeIdentifierMessage("node-abc", null);

    SimpleFieldSet result = message.getFieldSet();

    assertEquals("node-abc", result.get("NodeIdentifier"));
    assertNull(result.get("Identifier"));
  }

  @Test
  void getName_always_returnsConstantName() {
    UnknownNodeIdentifierMessage message = new UnknownNodeIdentifierMessage("id", "ident");

    assertEquals("UnknownNodeIdentifier", message.getName());
  }

  @Test
  void run_alwaysThrowsMessageInvalidException() {
    UnknownNodeIdentifierMessage message = new UnknownNodeIdentifierMessage("node-id", "ident");

    MessageInvalidException thrown =
        assertThrows(MessageInvalidException.class, () -> message.run(handler));

    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, thrown.protocolCode);
    assertEquals(
        "UnknownNodeIdentifier goes from server to client not the other way around",
        thrown.getMessage());
    assertEquals("node-id", thrown.ident);
    assertFalse(thrown.global);
    Mockito.verifyNoInteractions(handler, node);
  }
}
