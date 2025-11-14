package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.Bucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class AllDataMessageTest {

  private static final String IDENTIFIER = "test-identifier";
  private static final long STARTUP_TIME = 1234L;
  private static final long COMPLETION_TIME = 5678L;
  private static final String MIME_TYPE = "text/plain";

  @Mock private Bucket bucket;

  @Test
  void dataLength_whenConstructed_matchesBucketSize() {
    when(bucket.size()).thenReturn(2048L);

    AllDataMessage message =
        new AllDataMessage(bucket, IDENTIFIER, true, STARTUP_TIME, COMPLETION_TIME, MIME_TYPE);

    assertEquals(2048L, message.dataLength());
  }

  @Test
  void getFieldSet_whenMimeTypeProvided_includesMetadata() {
    when(bucket.size()).thenReturn(1024L);
    AllDataMessage message =
        new AllDataMessage(bucket, IDENTIFIER, true, STARTUP_TIME, COMPLETION_TIME, MIME_TYPE);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertNotNull(fieldSet);
    assertEquals(1024L, fieldSet.getLong("DataLength", -1));
    assertEquals(IDENTIFIER, fieldSet.get("Identifier"));
    assertTrue(fieldSet.getBoolean("Global", false));
    assertEquals(STARTUP_TIME, fieldSet.getLong("StartupTime", -1));
    assertEquals(COMPLETION_TIME, fieldSet.getLong("CompletionTime", -1));
    assertEquals(MIME_TYPE, fieldSet.get("Metadata.ContentType"));
  }

  @Test
  void getFieldSet_whenMimeTypeMissing_omitsMetadata() {
    when(bucket.size()).thenReturn(512L);
    AllDataMessage message =
        new AllDataMessage(bucket, IDENTIFIER, false, STARTUP_TIME, COMPLETION_TIME, null);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertNull(fieldSet.get("Metadata.ContentType"));
  }

  @Test
  void run_whenCalledFromClient_throwsMessageInvalidException() {
    when(bucket.size()).thenReturn(256L);
    AllDataMessage message =
        new AllDataMessage(bucket, IDENTIFIER, true, STARTUP_TIME, COMPLETION_TIME, MIME_TYPE);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> message.run(null, null));

    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, exception.protocolCode);
    assertEquals(IDENTIFIER, exception.ident);
    assertTrue(exception.global);
    assertEquals(
        "AllData goes from server to client not the other way around", exception.getMessage());
  }

  @Test
  void getIdentifier_whenCalled_returnsConstructorValue() {
    when(bucket.size()).thenReturn(128L);
    AllDataMessage message =
        new AllDataMessage(bucket, IDENTIFIER, true, STARTUP_TIME, COMPLETION_TIME, MIME_TYPE);

    assertEquals(IDENTIFIER, message.getIdentifier());
  }

  @Test
  void isGlobal_whenCalled_returnsConstructorFlag() {
    when(bucket.size()).thenReturn(64L);
    AllDataMessage message =
        new AllDataMessage(bucket, IDENTIFIER, false, STARTUP_TIME, COMPLETION_TIME, MIME_TYPE);

    assertFalse(message.isGlobal());
  }

  @Test
  void getName_whenCalled_returnsAllDataLiteral() {
    when(bucket.size()).thenReturn(32L);
    AllDataMessage message =
        new AllDataMessage(bucket, IDENTIFIER, true, STARTUP_TIME, COMPLETION_TIME, MIME_TYPE);

    assertEquals("AllData", message.getName());
  }
}
