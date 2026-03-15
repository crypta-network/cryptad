package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.runtime.spi.NodeGreetingSnapshot;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class NodeHelloMessageTest {

  @Test
  void getFieldSet_whenCalled_populatesExpectedFields() {
    NodeGreetingSnapshot greeting =
        new NodeGreetingSnapshot(
            "Cryptad", "v-string", 123, "rev-xyz", true, "descriptor", "ENGLISH");
    NodeHelloMessage message = new NodeHelloMessage(greeting, "connection-1");

    SimpleFieldSet sfs = message.getFieldSet();

    assertAll(
        () -> assertEquals("2.0", sfs.get("FCPVersion")),
        () -> assertEquals("Cryptad", sfs.get("Node")),
        () -> assertEquals("v-string", sfs.get("Version")),
        () -> assertEquals("123", sfs.get("Build")),
        () -> assertEquals("rev-xyz", sfs.get("Revision")),
        () -> assertEquals("true", sfs.get("Testnet")),
        () -> assertEquals("descriptor", sfs.get("CompressionCodecs")),
        () -> assertEquals("connection-1", sfs.get("ConnectionIdentifier")),
        () -> assertEquals("ENGLISH", sfs.get("NodeLanguage")),
        () -> assertEquals(9, sfs.directKeys().size()));
  }

  @Test
  void getName_whenCalled_returnsNodeHello() {
    NodeHelloMessage message =
        new NodeHelloMessage(
            new NodeGreetingSnapshot("Cryptad", "v", 1, "rev", false, "descriptor", "ENGLISH"),
            "id");

    assertEquals(NodeHelloMessage.NAME, message.getName());
  }

  @Test
  void run_whenInvoked_throwsMessageInvalidException() {
    NodeHelloMessage message =
        new NodeHelloMessage(
            new NodeGreetingSnapshot("Cryptad", "v", 1, "rev", false, "descriptor", "ENGLISH"),
            "id");

    MessageInvalidException exception =
        assertThrows(
            MessageInvalidException.class,
            () ->
                message.run(
                    org.mockito.Mockito.mock(FCPConnectionHandler.class),
                    org.mockito.Mockito.mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS)));

    assertAll(
        () -> assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, exception.protocolCode),
        () ->
            assertEquals(
                "NodeHello goes from server to client not the other way around",
                exception.getMessage()),
        () -> assertNull(exception.ident),
        () -> assertFalse(exception.global));
  }
}
