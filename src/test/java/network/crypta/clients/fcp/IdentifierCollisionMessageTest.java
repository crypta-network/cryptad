package network.crypta.clients.fcp;

import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class IdentifierCollisionMessageTest {

  @Mock private FCPConnectionHandler handler;

  @Test
  void getFieldSet_whenIdentifierAndGlobalProvided_expectFieldsSet() {
    IdentifierCollisionMessage message = new IdentifierCollisionMessage("dup-id", true);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertNotNull(fieldSet);
    assertEquals("dup-id", fieldSet.get("Identifier"));
    assertEquals("true", fieldSet.get("Global"));
  }

  @Test
  void getFieldSet_whenIdentifierNull_expectIdentifierAbsentButGlobalPresent() {
    IdentifierCollisionMessage message = new IdentifierCollisionMessage(null, false);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertNotNull(fieldSet);
    assertNull(fieldSet.get("Identifier"));
    assertEquals("false", fieldSet.get("Global"));
  }

  @Test
  void getName_always_returnsIdentifierCollision() {
    IdentifierCollisionMessage message = new IdentifierCollisionMessage("any", true);

    assertEquals("IdentifierCollision", message.getName());
  }

  @ParameterizedTest
  @CsvSource({"true,collision-one", "false,collision-two"})
  void run_whenInvoked_expectMessageInvalidExceptionWithDetails(boolean global, String ident) {
    IdentifierCollisionMessage message = new IdentifierCollisionMessage(ident, global);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> message.run(handler));

    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, exception.protocolCode);
    assertEquals(
        "IdentifierCollision goes from server to client not the other way around",
        exception.getMessage());
    assertEquals(ident, exception.ident);
    assertEquals(global, exception.global);
  }
}
