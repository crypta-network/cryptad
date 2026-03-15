package network.crypta.clients.fcp;

import network.crypta.client.FetchResult;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
class DataFoundMessageTest {

  @Test
  void getFieldSet_whenConstructedFromFetchResult_populatesMetadata() {
    FetchResult fetchResult = mock(FetchResult.class);
    when(fetchResult.getMimeType()).thenReturn("text/plain");
    when(fetchResult.size()).thenReturn(512L);

    DataFoundMessage message = new DataFoundMessage(fetchResult, "req-123", true, 10L, 20L);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertEquals("req-123", fieldSet.get("Identifier"));
    assertTrue(fieldSet.getBoolean("Global", false));
    assertEquals("text/plain", fieldSet.get("Metadata.ContentType"));
    assertEquals(512L, fieldSet.getLong("DataLength", -1));
    assertEquals(10L, fieldSet.getLong("StartupTime", -1));
    assertEquals(20L, fieldSet.getLong("CompletionTime", -1));
    assertEquals("DataFound", message.getName());
  }

  @Test
  void getFieldSet_whenConstructedFromExplicitValues_usesProvidedData() {
    DataFoundMessage message =
        new DataFoundMessage(2048L, "application/json", "req-456", false, 5L, 30L);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertEquals("req-456", fieldSet.get("Identifier"));
    assertFalse(fieldSet.getBoolean("Global", true));
    assertEquals("application/json", fieldSet.get("Metadata.ContentType"));
    assertEquals(2048L, fieldSet.getLong("DataLength", -1));
    assertEquals(5L, fieldSet.getLong("StartupTime", -1));
    assertEquals(30L, fieldSet.getLong("CompletionTime", -1));
  }

  @Test
  void run_whenInvokedFromClient_throwsMessageInvalidException() {
    DataFoundMessage message =
        new DataFoundMessage(1L, "application/octet-stream", "req-789", false, 0L, 1L);

    MessageInvalidException exception =
        assertThrows(
            MessageInvalidException.class, () -> message.run(mock(FCPConnectionHandler.class)));

    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, exception.protocolCode);
    assertEquals(
        "DataFound goes from server to client not the other way around", exception.getMessage());
    assertEquals("req-789", exception.ident);
    assertFalse(exception.global);
  }
}
