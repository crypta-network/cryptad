package network.crypta.clients.fcp;

import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class SubscribedUSKSendingToNetworkMessageTest {

  @Test
  void getFieldSet_whenIdentifierProvided_containsIdentifierField() {
    // Arrange
    SubscribedUSKSendingToNetworkMessage message =
        new SubscribedUSKSendingToNetworkMessage("abc123");

    // Act
    SimpleFieldSet fieldSet = message.getFieldSet();

    // Assert
    assertNotNull(fieldSet);
    assertEquals("abc123", fieldSet.get("Identifier"));
  }

  @Test
  void getFieldSet_whenIdentifierNull_skipsIdentifierEntry() {
    // Arrange
    SubscribedUSKSendingToNetworkMessage message = new SubscribedUSKSendingToNetworkMessage(null);

    // Act
    SimpleFieldSet fieldSet = message.getFieldSet();

    // Assert
    assertNotNull(fieldSet);
    assertNull(fieldSet.get("Identifier"));
  }

  @Test
  void getFieldSet_whenCalledMultipleTimes_returnsNewInstances() {
    // Arrange
    SubscribedUSKSendingToNetworkMessage message = new SubscribedUSKSendingToNetworkMessage("id");

    // Act
    SimpleFieldSet first = message.getFieldSet();
    SimpleFieldSet second = message.getFieldSet();

    // Assert
    assertNotSame(first, second);
    assertEquals("id", first.get("Identifier"));
    assertEquals("id", second.get("Identifier"));
  }

  @Test
  void getName_alwaysReturnsFixedMessageName() {
    // Arrange
    SubscribedUSKSendingToNetworkMessage message = new SubscribedUSKSendingToNetworkMessage("id");

    // Act & Assert
    assertEquals("SubscribedUSKSendingToNetwork", message.getName());
  }

  @Test
  void run_whenInvoked_throwsUnsupportedOperationException() {
    // Arrange
    SubscribedUSKSendingToNetworkMessage message = new SubscribedUSKSendingToNetworkMessage("id");

    // Act & Assert
    assertThrows(UnsupportedOperationException.class, () -> message.run(null));
  }
}
