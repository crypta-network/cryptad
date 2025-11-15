package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verifyNoInteractions;

import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class EndListPersistentRequestsMessageTest {

  private static final String IDENTIFIER = "identifier-123";

  @Mock private FCPConnectionHandler handler;
  @Mock private Node node;

  @Test
  void getFieldSet_whenIdentifierProvided_includesIdentifier() {
    EndListPersistentRequestsMessage message = new EndListPersistentRequestsMessage(IDENTIFIER);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertEquals(IDENTIFIER, fieldSet.get("Identifier"));
  }

  @Test
  void getFieldSet_whenIdentifierNull_omitsIdentifier() {
    EndListPersistentRequestsMessage message = new EndListPersistentRequestsMessage(null);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertNull(fieldSet.get("Identifier"));
  }

  @Test
  void getName_whenCalled_returnsEndListPersistentRequestsLiteral() {
    EndListPersistentRequestsMessage message = new EndListPersistentRequestsMessage(IDENTIFIER);

    assertEquals("EndListPersistentRequests", message.getName());
  }

  @Test
  void run_whenInvoked_throwsMessageInvalidException() {
    EndListPersistentRequestsMessage message = new EndListPersistentRequestsMessage(IDENTIFIER);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> message.run(handler, node));

    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, exception.protocolCode);
    assertEquals(
        "EndListPersistentRequests goes from server to client not the other way around",
        exception.getMessage());
    assertNull(exception.ident);
    assertFalse(exception.global);
    verifyNoInteractions(handler, node);
  }
}
