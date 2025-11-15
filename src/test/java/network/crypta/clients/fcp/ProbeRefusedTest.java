package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class ProbeRefusedTest {

  @Mock private FCPConnectionHandler handler;
  @Mock private Node node;

  @Test
  void constructor_whenIdentifierProvided_expectIdentifierStored() {
    ProbeRefused message = new ProbeRefused("req-123");

    SimpleFieldSet fields = message.getFieldSet();

    assertEquals("req-123", fields.get(FCPMessage.IDENTIFIER));
  }

  @Test
  void constructor_whenIdentifierMissing_expectIdentifierOmitted() {
    ProbeRefused message = new ProbeRefused(null);

    assertNull(message.getFieldSet().get(FCPMessage.IDENTIFIER));
  }

  @Test
  void getName_whenInvoked_expectProtocolConstant() {
    ProbeRefused message = new ProbeRefused("any");

    assertEquals("ProbeRefused", message.getName());
  }

  @Test
  void run_whenCalled_expectMessageInvalidException() {
    ProbeRefused message = new ProbeRefused("req-789");

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> message.run(handler, node));

    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, exception.protocolCode);
    assertEquals(
        "ProbeRefused is a reply from the node; the client should not send it.",
        exception.getMessage());
    assertNull(exception.ident);
    assertFalse(exception.global);
  }
}
