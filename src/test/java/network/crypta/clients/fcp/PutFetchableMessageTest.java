package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class PutFetchableMessageTest {

  private static final String IDENTIFIER = "test-id";

  @Mock private FCPConnectionHandler handler;
  @Mock private Node node;

  @Test
  void getFieldSet_whenUriProvided_expectIdentifierGlobalAndUriFields() {
    // Arrange
    FreenetURI uri = new FreenetURI("KSK", "keyword");
    PutFetchableMessage message = new PutFetchableMessage(IDENTIFIER, true, uri);

    // Act
    SimpleFieldSet result = message.getFieldSet();

    // Assert
    assertEquals(IDENTIFIER, result.get("Identifier"));
    assertEquals("true", result.get("Global"));
    assertEquals(uri.toString(false, false), result.get("URI"));
    assertEquals("PutFetchable", message.getName());
  }

  @Test
  void getFieldSet_whenUriIsNull_expectUriFieldAbsent() {
    // Arrange
    PutFetchableMessage message = new PutFetchableMessage(IDENTIFIER, false, null);

    // Act
    SimpleFieldSet result = message.getFieldSet();

    // Assert
    assertEquals(IDENTIFIER, result.get("Identifier"));
    assertEquals("false", result.get("Global"));
    assertNull(result.get("URI"));
  }

  @Test
  void run_whenInvoked_expectMessageInvalidExceptionWithContext() {
    // Arrange
    PutFetchableMessage message = new PutFetchableMessage(IDENTIFIER, true, null);

    // Act
    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> message.run(handler, node));

    // Assert
    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, exception.protocolCode);
    assertEquals(IDENTIFIER, exception.ident);
    assertTrue(exception.global);
    assertEquals(
        "PutFetchable goes from server to client not the other way around", exception.getMessage());
  }
}
