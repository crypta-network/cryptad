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
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class PersistentRequestModifiedMessageTest {

  private static final String IDENTIFIER = "req-123";
  private static final String CLIENT_TOKEN = "token-abc";

  @Mock private FCPConnectionHandler connectionHandler;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Test
  void getFieldSet_withPriorityOnly_setsIdentifierGlobalAndPriority() {
    short priorityClass = 5;
    PersistentRequestModifiedMessage message =
        new PersistentRequestModifiedMessage(IDENTIFIER, true, priorityClass);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertEquals(IDENTIFIER, fieldSet.get("Identifier"));
    assertTrue(fieldSet.getBoolean("Global", false));
    assertEquals(String.valueOf(priorityClass), fieldSet.get("PriorityClass"));
    assertNull(fieldSet.get("ClientToken"));
  }

  @Test
  void getFieldSet_withClientTokenOnly_setsIdentifierGlobalAndToken() {
    PersistentRequestModifiedMessage message =
        new PersistentRequestModifiedMessage(IDENTIFIER, false, CLIENT_TOKEN);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertEquals(IDENTIFIER, fieldSet.get("Identifier"));
    assertFalse(fieldSet.getBoolean("Global", true));
    assertNull(fieldSet.get("PriorityClass"));
    assertEquals(CLIENT_TOKEN, fieldSet.get("ClientToken"));
  }

  @Test
  void getFieldSet_withPriorityAndToken_setsAllAvailableFields() {
    short priorityClass = 1;
    PersistentRequestModifiedMessage message =
        new PersistentRequestModifiedMessage(IDENTIFIER, true, priorityClass, CLIENT_TOKEN);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertEquals(IDENTIFIER, fieldSet.get("Identifier"));
    assertTrue(fieldSet.getBoolean("Global", false));
    assertEquals(String.valueOf(priorityClass), fieldSet.get("PriorityClass"));
    assertEquals(CLIENT_TOKEN, fieldSet.get("ClientToken"));
  }

  @Test
  void getName_returnsExpectedConstant() {
    PersistentRequestModifiedMessage message =
        new PersistentRequestModifiedMessage(IDENTIFIER, true, (short) 0);

    assertEquals("PersistentRequestModified", message.getName());
  }

  @Test
  void run_whenInvoked_throwsMessageInvalidExceptionWithContext() {
    PersistentRequestModifiedMessage message =
        new PersistentRequestModifiedMessage(IDENTIFIER, true, (short) 2);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> message.run(connectionHandler, node));

    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, exception.protocolCode);
    assertEquals(IDENTIFIER, exception.ident);
    assertTrue(exception.global);
    assertEquals(
        "PersistentRequestModified goes from server to client not the other way around",
        exception.getMessage());
  }
}
