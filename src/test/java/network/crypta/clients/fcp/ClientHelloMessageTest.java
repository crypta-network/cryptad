package network.crypta.clients.fcp;

import java.util.UUID;
import network.crypta.node.Node;
import network.crypta.runtime.spi.NodeGreetingSnapshot;
import network.crypta.runtime.spi.NodeInfoPort;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ClientHelloMessageTest {

  @Mock private FCPConnectionHandler handler;

  @Mock private Node node;

  @Mock private FCPServer server;

  @Mock private RuntimePorts runtimePorts;

  @Mock private NodeInfoPort nodeInfoPort;

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
  void run_whenInvoked_fetchesGreetingSendsNodeHelloAndRegistersClient()
      throws MessageInvalidException {
    ClientHelloMessage message = new ClientHelloMessage(fieldSet("deterministic-client", "0.7.0"));
    UUID identifier = UUID.fromString("123e4567-e89b-12d3-a456-426614174000");
    NodeGreetingSnapshot greeting =
        new NodeGreetingSnapshot(
            "Cryptad", "v-string", 123, "rev-xyz", true, "descriptor", "ENGLISH");
    when(handler.getServer()).thenReturn(server);
    when(server.runtime()).thenReturn(runtimePorts);
    when(runtimePorts.nodeInfo()).thenReturn(nodeInfoPort);
    when(nodeInfoPort.greeting()).thenReturn(greeting);
    when(handler.getConnectionIdentifierUUID()).thenReturn(identifier);

    message.run(handler);

    ArgumentCaptor<FCPMessage> captor = ArgumentCaptor.forClass(FCPMessage.class);
    InOrder order = inOrder(nodeInfoPort, handler);
    order.verify(nodeInfoPort).greeting();
    order.verify(handler).send(captor.capture());
    order.verify(handler).setClientName("deterministic-client");
    FCPMessage sentMessage = captor.getValue();
    assertInstanceOf(NodeHelloMessage.class, sentMessage);
    SimpleFieldSet greetingFieldSet = sentMessage.getFieldSet();
    assertEquals(identifier.toString(), greetingFieldSet.get("ConnectionIdentifier"));
    assertEquals("Cryptad", greetingFieldSet.get("Node"));
    assertEquals("v-string", greetingFieldSet.get("Version"));
    verifyNoInteractions(node);
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
