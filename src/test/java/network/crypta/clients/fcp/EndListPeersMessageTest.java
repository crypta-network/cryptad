package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class EndListPeersMessageTest {

  private static final String IDENTIFIER = "identifier-123";

  @Test
  void getFieldSet_whenIdentifierProvided_includesIdentifier() {
    EndListPeersMessage message = new EndListPeersMessage(IDENTIFIER);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertEquals(IDENTIFIER, fieldSet.get("Identifier"));
  }

  @Test
  void getFieldSet_whenIdentifierNull_omitsIdentifier() {
    EndListPeersMessage message = new EndListPeersMessage(null);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertNull(fieldSet.get("Identifier"));
  }

  @Test
  void getName_whenCalled_returnsEndListPeersLiteral() {
    EndListPeersMessage message = new EndListPeersMessage(IDENTIFIER);

    assertEquals("EndListPeers", message.getName());
  }

  @Test
  void run_whenInvoked_throwsMessageInvalidException() {
    EndListPeersMessage message = new EndListPeersMessage(IDENTIFIER);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> message.run(null, null));

    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, exception.protocolCode);
    assertEquals(
        "EndListPeers goes from server to client not the other way around", exception.getMessage());
    assertNull(exception.ident);
    assertFalse(exception.global);
  }
}
