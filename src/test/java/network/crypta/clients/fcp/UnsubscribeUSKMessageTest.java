package network.crypta.clients.fcp;

import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class UnsubscribeUSKMessageTest {

  @Mock private FCPConnectionHandler handler;

  @Test
  void constructor_whenIdentifierMissing_throwsMessageInvalidException() {
    // Arrange
    SimpleFieldSet fieldSet = new SimpleFieldSet(true);

    // Act
    MessageInvalidException thrown =
        assertThrows(MessageInvalidException.class, () -> new UnsubscribeUSKMessage(fieldSet));

    // Assert
    assertEquals(ProtocolErrorMessage.MISSING_FIELD, thrown.protocolCode);
    assertEquals("No Identifier!", thrown.getMessage());
    assertNull(thrown.ident);
  }

  @Test
  void getName_whenInvoked_returnsConstantName() throws MessageInvalidException {
    // Arrange
    SimpleFieldSet fieldSet = new SimpleFieldSet(true);
    fieldSet.putSingle("Identifier", "id-123");
    UnsubscribeUSKMessage message = new UnsubscribeUSKMessage(fieldSet);

    // Act & Assert
    assertEquals(UnsubscribeUSKMessage.NAME, message.getName());
  }

  @Test
  void getFieldSet_whenCalled_throwsUnsupportedOperationException() throws MessageInvalidException {
    // Arrange
    SimpleFieldSet fieldSet = new SimpleFieldSet(true);
    fieldSet.putSingle("Identifier", "id-123");
    UnsubscribeUSKMessage message = new UnsubscribeUSKMessage(fieldSet);

    // Act & Assert
    assertThrows(UnsupportedOperationException.class, message::getFieldSet);
  }

  @Test
  void run_whenInvoked_callsHandlerWithIdentifier() throws Exception {
    // Arrange
    SimpleFieldSet fieldSet = new SimpleFieldSet(true);
    fieldSet.putSingle("Identifier", "abc");
    UnsubscribeUSKMessage message = new UnsubscribeUSKMessage(fieldSet);

    // Act
    message.run(handler);

    // Assert
    verify(handler).unsubscribeUSK("abc");
  }

  @Test
  void run_whenHandlerThrows_propagatesMessageInvalidException() throws Exception {
    // Arrange
    SimpleFieldSet fieldSet = new SimpleFieldSet(true);
    fieldSet.putSingle("Identifier", "abc");
    UnsubscribeUSKMessage message = new UnsubscribeUSKMessage(fieldSet);
    MessageInvalidException failure =
        new MessageInvalidException(
            ProtocolErrorMessage.NO_SUCH_IDENTIFIER, "missing", "abc", false);
    doThrow(failure).when(handler).unsubscribeUSK("abc");

    // Act & Assert
    MessageInvalidException thrown =
        assertThrows(MessageInvalidException.class, () -> message.run(handler));
    assertEquals(failure, thrown);
  }
}
