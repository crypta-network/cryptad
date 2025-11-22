package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class PluginRemovedMessageTest {

  @Mock private FCPConnectionHandler handler;

  @Mock private Node node;

  @Test
  void getFieldSet_whenIdentifierAndPluginProvided_containsBothFields() {
    PluginRemovedMessage message = new PluginRemovedMessage("ExamplePlugin", "req-123");

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertNotNull(fieldSet);
    assertEquals("req-123", fieldSet.get("Identifier"));
    assertEquals("ExamplePlugin", fieldSet.get("PluginName"));
    assertEquals("Identifier=req-123\nPluginName=ExamplePlugin\nEnd\n", fieldSet.toOrderedString());
  }

  @Test
  void getFieldSet_whenPluginNameIsNull_skipsPluginNameField() {
    PluginRemovedMessage message = new PluginRemovedMessage(null, "identifier-only");

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertEquals("identifier-only", fieldSet.get("Identifier"));
    assertNull(fieldSet.get("PluginName"));
    assertEquals("Identifier=identifier-only\nEnd\n", fieldSet.toOrderedString());
  }

  @Test
  void getFieldSet_whenIdentifierIsNull_skipsIdentifierField() {
    PluginRemovedMessage message = new PluginRemovedMessage("PluginOnly", null);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertNull(fieldSet.get("Identifier"));
    assertEquals("PluginOnly", fieldSet.get("PluginName"));
    assertEquals("PluginName=PluginOnly\nEnd\n", fieldSet.toOrderedString());
  }

  @Test
  void getName_always_returnsPluginRemoved() {
    PluginRemovedMessage message = new PluginRemovedMessage("any", "id");

    assertEquals("PluginRemoved", message.getName());
  }

  @Test
  void run_whenInvoked_throwsMessageInvalidExceptionWithExpectedDetails() {
    PluginRemovedMessage message = new PluginRemovedMessage("plug", "id");

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> message.run(handler, node));

    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, exception.protocolCode);
    assertEquals(
        "PluginRemoved goes from server to client not the other way around",
        exception.getMessage());
    assertNull(exception.ident);
    assertFalse(exception.global);
  }
}
