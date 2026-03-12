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

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class EndListPeerNotesMessageTest {

  private static final String NODE_IDENTIFIER = "node-123";
  private static final String IDENTIFIER = "req-456";

  @Mock private FCPConnectionHandler handler;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Test
  void getFieldSet_whenIdentifierProvided_expectBothKeys() {
    EndListPeerNotesMessage message = new EndListPeerNotesMessage(NODE_IDENTIFIER, IDENTIFIER);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertEquals(NODE_IDENTIFIER, fieldSet.get("NodeIdentifier"));
    assertEquals(IDENTIFIER, fieldSet.get("Identifier"));
  }

  @Test
  void getFieldSet_whenIdentifierNull_expectOnlyNodeIdentifier() {
    EndListPeerNotesMessage message = new EndListPeerNotesMessage(NODE_IDENTIFIER, null);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertEquals(NODE_IDENTIFIER, fieldSet.get("NodeIdentifier"));
    assertNull(fieldSet.get("Identifier"));
  }

  @Test
  void getName_whenCalled_expectConstantName() {
    EndListPeerNotesMessage message = new EndListPeerNotesMessage(NODE_IDENTIFIER, IDENTIFIER);

    String name = message.getName();

    assertEquals("EndListPeerNotes", name);
  }

  @Test
  void run_whenInvoked_expectMessageInvalidException() {
    EndListPeerNotesMessage message = new EndListPeerNotesMessage(NODE_IDENTIFIER, IDENTIFIER);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> message.run(handler, node));

    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, exception.protocolCode);
    assertEquals(
        "EndListPeerNotes goes from server to client not the other way around",
        exception.getMessage());
    assertNull(exception.ident);
    assertFalse(exception.global);
  }
}
