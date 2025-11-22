package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import network.crypta.l10n.BaseL10n;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.Node;
import network.crypta.node.Version;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.compress.Compressor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class NodeHelloMessageTest {

  @Test
  void getFieldSet_whenCalled_populatesExpectedFields() {
    try (MockedStatic<Version> version = Mockito.mockStatic(Version.class);
        MockedStatic<Node> node = Mockito.mockStatic(Node.class);
        MockedStatic<NodeL10n> nodeL10n = Mockito.mockStatic(NodeL10n.class);
        MockedStatic<Compressor.COMPRESSOR_TYPE> compressor =
            Mockito.mockStatic(Compressor.COMPRESSOR_TYPE.class)) {

      version.when(Version::getVersionString).thenReturn("v-string");
      version.when(Version::currentBuildNumber).thenReturn(123);
      version.when(Version::gitRevision).thenReturn("rev-xyz");
      //noinspection ResultOfMethodCallIgnored
      node.when(Node::isTestnetEnabled).thenReturn(true);
      compressor
          .when(Compressor.COMPRESSOR_TYPE::getHelloCompressorDescriptor)
          .thenReturn("descriptor");

      BaseL10n base = Mockito.mock(BaseL10n.class);
      Mockito.when(base.getSelectedLanguage()).thenReturn(BaseL10n.LANGUAGE.ENGLISH);
      nodeL10n.when(NodeL10n::getBase).thenReturn(base);

      NodeHelloMessage message = new NodeHelloMessage("connection-1");

      SimpleFieldSet sfs = message.getFieldSet();

      assertAll(
          () -> assertEquals("2.0", sfs.get("FCPVersion")),
          () -> assertEquals("Cryptad", sfs.get("Node")),
          () -> assertEquals("v-string", sfs.get("Version")),
          () -> assertEquals("123", sfs.get("Build")),
          () -> assertEquals("rev-xyz", sfs.get("Revision")),
          () -> assertTrue(Node.isTestnetEnabled()),
          () -> assertEquals("true", sfs.get("Testnet")),
          () -> assertEquals("descriptor", sfs.get("CompressionCodecs")),
          () -> assertEquals("connection-1", sfs.get("ConnectionIdentifier")),
          () -> assertEquals(BaseL10n.LANGUAGE.ENGLISH.toString(), sfs.get("NodeLanguage")),
          () -> assertEquals(9, sfs.directKeys().size()));
    }
  }

  @Test
  void getName_whenCalled_returnsNodeHello() {
    NodeHelloMessage message = new NodeHelloMessage("id");

    assertEquals(NodeHelloMessage.NAME, message.getName());
  }

  @Test
  void run_whenInvoked_throwsMessageInvalidException() {
    NodeHelloMessage message = new NodeHelloMessage("id");

    MessageInvalidException exception =
        assertThrows(
            MessageInvalidException.class,
            () -> message.run(Mockito.mock(FCPConnectionHandler.class), Mockito.mock(Node.class)));

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
