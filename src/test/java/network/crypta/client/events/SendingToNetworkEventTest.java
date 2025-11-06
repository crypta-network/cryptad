package network.crypta.client.events;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class SendingToNetworkEventTest {

  @Test
  void api_whenQueried_expectStableCodeAndDescription() {
    // Arrange
    SendingToNetworkEvent event = new SendingToNetworkEvent();

    // Act & Assert
    assertInstanceOf(ClientEvent.class, event, "Event must implement ClientEvent");
    assertEquals(
        SendingToNetworkEvent.CODE, event.getCode(), "getCode should return CODE constant");
    assertEquals(0x0A, event.getCode(), "CODE must be the expected numeric value");
    assertNotNull(event.getDescription(), "Description must be non-null");
    assertEquals("Sending to network", event.getDescription(), "Description text must match");
  }
}
