package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class CloseConnectionDuplicateClientNameMessageTest {

  @Mock private FCPConnectionHandler handler;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Test
  void getFieldSet_whenInvoked_returnsEmptyFieldSet() {
    CloseConnectionDuplicateClientNameMessage message =
        new CloseConnectionDuplicateClientNameMessage();

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertNotNull(fieldSet);
    assertTrue(fieldSet.isEmpty());
    assertNotSame(fieldSet, message.getFieldSet());
  }

  @Test
  void getName_whenCalled_returnsCommandName() {
    CloseConnectionDuplicateClientNameMessage message =
        new CloseConnectionDuplicateClientNameMessage();

    String name = message.getName();

    assertEquals("CloseConnectionDuplicateClientName", name);
  }

  @Test
  void run_whenCalled_throwsMessageInvalidException() {
    CloseConnectionDuplicateClientNameMessage message =
        new CloseConnectionDuplicateClientNameMessage();

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> message.run(handler, node));

    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, exception.protocolCode);
    assertEquals(
        "CloseConnectionDuplicateClientName goes from server to client not the other way around",
        exception.getMessage());
    assertNull(exception.ident);
    assertFalse(exception.global);
  }
}
