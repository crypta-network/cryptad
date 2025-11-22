package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class PersistentRequestRemovedMessageTest {

  @Mock private FCPConnectionHandler handler;
  @Mock private Node node;

  @ParameterizedTest
  @CsvSource({"req-123,true", "another-id,false"})
  void getFieldSet_whenCreated_containsIdentifierAndGlobal(String identifier, boolean global) {
    PersistentRequestRemovedMessage message =
        new PersistentRequestRemovedMessage(identifier, global);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertNotNull(fieldSet);
    assertEquals(identifier, fieldSet.get("Identifier"));
    assertEquals(Boolean.toString(global), fieldSet.get("Global"));
    assertNotSame(fieldSet, message.getFieldSet());
  }

  @Test
  void getName_whenCalled_returnsPersistentRequestRemoved() {
    PersistentRequestRemovedMessage message = new PersistentRequestRemovedMessage("id", true);

    String name = message.getName();

    assertEquals("PersistentRequestRemoved", name);
  }

  @ParameterizedTest
  @CsvSource({"req-123,true", "req-456,false"})
  void run_whenInvoked_throwsMessageInvalidExceptionWithContext(String identifier, boolean global) {
    PersistentRequestRemovedMessage message =
        new PersistentRequestRemovedMessage(identifier, global);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> message.run(handler, node));

    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, exception.protocolCode);
    assertEquals(
        "PersistentRequestRemoved goes from server to client not the other way around",
        exception.getMessage());
    assertEquals(identifier, exception.ident);
    assertEquals(global, exception.global);
  }
}
