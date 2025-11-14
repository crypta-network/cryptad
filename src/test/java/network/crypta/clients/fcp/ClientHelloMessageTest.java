package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.UUID;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ClientHelloMessageTest {

  @Mock private FCPConnectionHandler handler;

  @Mock private Node node;

  @Test
  void constructor_whenNameMissing_expectException() {
    SimpleFieldSet fieldSet = fieldSet(null, "0.7.0");

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> new ClientHelloMessage(fieldSet));

    assertEquals(ProtocolErrorMessage.MISSING_FIELD, exception.protocolCode);
    assertEquals("ClientHello must contain a Name field", exception.getMessage());
  }

  @Test
  void constructor_whenExpectedVersionMissing_expectException() {
    SimpleFieldSet fieldSet = fieldSet("deterministic-client", null);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> new ClientHelloMessage(fieldSet));

    assertEquals(ProtocolErrorMessage.MISSING_FIELD, exception.protocolCode);
    assertEquals("ClientHello must contain a ExpectedVersion field", exception.getMessage());
  }

  @Test
  void getFieldSet_whenCalled_containsProvidedValues() throws MessageInvalidException {
    ClientHelloMessage message = new ClientHelloMessage(fieldSet("deterministic-client", "0.7.0"));

    SimpleFieldSet result = message.getFieldSet();

    assertEquals("deterministic-client", result.get("Name"));
    assertEquals("0.7.0", result.get("ExpectedVersion"));
  }

  @Test
  void getName_whenCalled_returnsClientHelloConstant() throws MessageInvalidException {
    ClientHelloMessage message = new ClientHelloMessage(fieldSet("deterministic-client", "0.7.0"));

    assertEquals(ClientHelloMessage.NAME, message.getName());
  }

  @Test
  void run_whenInvoked_sendsNodeHelloAndRegistersClient() throws MessageInvalidException {
    ClientHelloMessage message = new ClientHelloMessage(fieldSet("deterministic-client", "0.7.0"));
    UUID identifier = UUID.fromString("123e4567-e89b-12d3-a456-426614174000");
    when(handler.getConnectionIdentifierUUID()).thenReturn(identifier);

    message.run(handler, node);

    ArgumentCaptor<FCPMessage> captor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(handler).send(captor.capture());
    FCPMessage sentMessage = captor.getValue();
    assertInstanceOf(NodeHelloMessage.class, sentMessage);
    assertEquals(identifier.toString(), sentMessage.getFieldSet().get("ConnectionIdentifier"));
    verify(handler).setClientName("deterministic-client");
  }

  private static SimpleFieldSet fieldSet(String name, String expectedVersion) {
    SimpleFieldSet fieldSet = new SimpleFieldSet(true);
    if (name != null) {
      fieldSet.putSingle("Name", name);
    }
    if (expectedVersion != null) {
      fieldSet.putSingle("ExpectedVersion", expectedVersion);
    }
    return fieldSet;
  }
}
