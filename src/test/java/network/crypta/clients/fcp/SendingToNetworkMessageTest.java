package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verifyNoInteractions;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class SendingToNetworkMessageTest {

  @Mock FCPConnectionHandler handler;

  @Mock Node node;

  @ParameterizedTest(name = "global={0}")
  @CsvSource({"true", "false"})
  void getFieldSet_whenCreated_expectIdentifierAndGlobalValues(boolean global) {
    // Arrange
    String identifier = "request-123";
    SendingToNetworkMessage message = new SendingToNetworkMessage(identifier, global);

    // Act
    SimpleFieldSet result = message.getFieldSet();

    // Assert
    assertAll(
        () -> assertEquals(identifier, result.get("Identifier")),
        () -> assertEquals(global, result.getBoolean("Global", !global)));
  }

  @Test
  void getName_whenCalled_expectConstantName() {
    SendingToNetworkMessage message = new SendingToNetworkMessage("id", true);

    assertEquals(SendingToNetworkMessage.NAME, message.getName());
  }

  @Test
  void run_whenInvoked_expectNoInteractions() {
    SendingToNetworkMessage message = new SendingToNetworkMessage("id", false);

    assertDoesNotThrow(() -> message.run(handler, node));

    verifyNoInteractions(handler, node);
  }
}
