package network.crypta.clients.fcp;

import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class PeerRemovedTest {

  @Test
  void getFieldSet_whenIdentifierPresent_containsAllFields() {
    PeerRemoved message = new PeerRemoved("identity-123", "node-abc", "request-42");

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertNotNull(fieldSet);
    assertEquals("identity-123", fieldSet.get("Identity"));
    assertEquals("node-abc", fieldSet.get("NodeIdentifier"));
    assertEquals("request-42", fieldSet.get("Identifier"));
  }

  @Test
  void getFieldSet_whenIdentifierNull_excludesIdentifierField() {
    PeerRemoved message = new PeerRemoved("identity-123", "node-abc", null);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertNotNull(fieldSet);
    assertEquals("identity-123", fieldSet.get("Identity"));
    assertEquals("node-abc", fieldSet.get("NodeIdentifier"));
    assertNull(fieldSet.get("Identifier"));
  }

  @Test
  void getName_whenInvoked_returnsPeerRemoved() {
    PeerRemoved message = new PeerRemoved("identity", "node", "id");

    String name = message.getName();

    assertEquals("PeerRemoved", name);
  }

  @Test
  void run_whenCalled_throwsMessageInvalidExceptionWithDetails() {
    PeerRemoved message = new PeerRemoved("identity-123", "node-abc", "request-42");

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> message.run(null));

    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, exception.protocolCode);
    assertEquals(
        "PeerRemoved goes from server to client not the other way around", exception.getMessage());
    assertEquals("request-42", exception.ident);
    assertFalse(exception.global);
  }
}
