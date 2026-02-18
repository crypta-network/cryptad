package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class StartedCompressionMessageTest {

  @Mock FCPConnectionHandler handler;
  @Mock Node node;

  @Test
  void getFieldSet_whenGzipGlobalTrue_setsIdentifierCodecAndGlobalFlag() {
    StartedCompressionMessage message =
        new StartedCompressionMessage("req-123", true, COMPRESSOR_TYPE.GZIP);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertEquals("req-123", fieldSet.get("Identifier"));
    assertEquals("GZIP", fieldSet.get("Codec"));
    assertEquals("true", fieldSet.get("Global"));
  }

  @Test
  void getFieldSet_whenBzip2GlobalFalse_setsCodecNameAndFalseFlag() {
    StartedCompressionMessage message =
        new StartedCompressionMessage("another-id", false, COMPRESSOR_TYPE.BZIP2);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertEquals("another-id", fieldSet.get("Identifier"));
    assertEquals("BZIP2", fieldSet.get("Codec"));
    assertEquals("false", fieldSet.get("Global"));
  }

  @Test
  void getName_always_returnsStartedCompression() {
    StartedCompressionMessage message =
        new StartedCompressionMessage("id", false, COMPRESSOR_TYPE.LZMA_NEW);

    assertEquals("StartedCompression", message.getName());
  }

  @Test
  void run_whenInvoked_throwsMessageInvalidExceptionWithDetails() {
    StartedCompressionMessage message =
        new StartedCompressionMessage("identifier", true, COMPRESSOR_TYPE.LZMA);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> message.run(handler, node));

    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, exception.protocolCode);
    assertEquals(
        "StartedCompression goes from server to client not the other way around",
        exception.getMessage());
    assertEquals("identifier", exception.ident);
    assertTrue(exception.global);
  }
}
