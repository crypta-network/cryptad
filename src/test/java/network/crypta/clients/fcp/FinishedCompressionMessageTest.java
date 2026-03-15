package network.crypta.clients.fcp;

import network.crypta.client.events.FinishedCompressionEvent;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class FinishedCompressionMessageTest {

  @Mock FCPConnectionHandler handler;
  @Mock Node node;

  @Test
  void getFieldSet_whenCodecPresent_populatesAllFieldsWithCodecName() {
    FinishedCompressionEvent event = new FinishedCompressionEvent(0, 1024L, 256L);
    FinishedCompressionMessage message = new FinishedCompressionMessage("req-1", false, event);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertEquals("req-1", fieldSet.get("Identifier"));
    assertEquals("0", fieldSet.get("Codec"));
    assertEquals("GZIP", fieldSet.get("Codec.Name"));
    assertEquals("1024", fieldSet.get("OriginalSize"));
    assertEquals("256", fieldSet.get("CompressedSize"));
    assertEquals("false", fieldSet.get("Global"));
  }

  @Test
  void getFieldSet_whenCodecIsNone_setsNoneNameAndSizes() {
    FinishedCompressionEvent event = new FinishedCompressionEvent(-1, 10L, 10L);
    FinishedCompressionMessage message = new FinishedCompressionMessage("req-2", true, event);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertEquals("req-2", fieldSet.get("Identifier"));
    assertEquals("-1", fieldSet.get("Codec"));
    assertEquals("NONE", fieldSet.get("Codec.Name"));
    assertEquals("10", fieldSet.get("OriginalSize"));
    assertEquals("10", fieldSet.get("CompressedSize"));
    assertEquals("true", fieldSet.get("Global"));
  }

  @Test
  void getName_always_returnsFinishedCompression() {
    FinishedCompressionMessage message =
        new FinishedCompressionMessage("id-name", false, new FinishedCompressionEvent(-1, 1L, 1L));

    assertEquals("FinishedCompression", message.getName());
  }

  @Test
  void run_whenCalled_throwsMessageInvalidExceptionWithDetails() {
    FinishedCompressionMessage message =
        new FinishedCompressionMessage(
            "identifier", true, new FinishedCompressionEvent(-1, 5L, 5L));

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> message.run(handler));

    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, exception.protocolCode);
    assertEquals(
        "FinishedCompression goes from server to client not the other way around",
        exception.getMessage());
    assertEquals("identifier", exception.ident);
    assertTrue(exception.global);
  }
}
