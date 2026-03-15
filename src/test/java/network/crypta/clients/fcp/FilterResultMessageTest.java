package network.crypta.clients.fcp;

import network.crypta.support.SimpleFieldSet;
import network.crypta.support.SimpleReadOnlyArrayBucket;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class FilterResultMessageTest {

  @Test
  void constructor_whenSafeContentType_populatesBucketAndLength() {
    SimpleReadOnlyArrayBucket bucket = new SimpleReadOnlyArrayBucket(new byte[] {1, 2, 3});

    FilterResultMessage message =
        new FilterResultMessage("req-1", "UTF-8", "text/plain", false, bucket);

    assertEquals("req-1", message.getIdentifier());
    assertEquals(bucket.size(), message.dataLength());
    assertSame(bucket, message.bucket);
    assertFalse(message.isGlobal());
  }

  @Test
  void constructor_whenUnsafeContentType_setsNegativeLengthAndLeavesBucketNull() {
    SimpleReadOnlyArrayBucket bucket = new SimpleReadOnlyArrayBucket(new byte[] {10, 11});

    FilterResultMessage message =
        new FilterResultMessage("req-2", "UTF-16", "application/json", true, bucket);

    assertEquals(-1, message.dataLength());
    assertNull(message.bucket);
  }

  @Test
  void getFieldSet_whenSafeContentType_containsMetadata() {
    FilterResultMessage message =
        new FilterResultMessage(
            "req-3",
            "ISO-8859-1",
            "text/html",
            false,
            new SimpleReadOnlyArrayBucket(new byte[] {5, 6, 7, 8}));

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertEquals("req-3", fieldSet.get("Identifier"));
    assertEquals("ISO-8859-1", fieldSet.get("Charset"));
    assertEquals("text/html", fieldSet.get("MimeType"));
    assertFalse(fieldSet.getBoolean("UnsafeContentType", true));
    assertEquals(4, fieldSet.getLong("DataLength", -42));
  }

  @Test
  void getFieldSet_whenUnsafeContentType_reportsFlagAndNegativeLength() {
    FilterResultMessage message =
        new FilterResultMessage(
            "req-4",
            "UTF-8",
            "application/octet-stream",
            true,
            new SimpleReadOnlyArrayBucket(new byte[] {9, 9, 9}));

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertTrue(fieldSet.getBoolean("UnsafeContentType", false));
    assertEquals(-1, fieldSet.getLong("DataLength", 0));
  }

  @Test
  void getName_whenCalled_returnsFilterResult() {
    FilterResultMessage message =
        new FilterResultMessage(
            "req-5", "UTF-8", "text/plain", false, new SimpleReadOnlyArrayBucket(new byte[] {1}));

    assertEquals(FilterResultMessage.NAME, message.getName());
  }

  @Test
  void run_whenInvoked_throwsInvalidMessageException() {
    FilterResultMessage message =
        new FilterResultMessage(
            "req-6",
            "UTF-8",
            "text/plain",
            false,
            new SimpleReadOnlyArrayBucket(new byte[] {1, 2}));

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> message.run(null));

    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, exception.protocolCode);
    assertEquals(
        FilterResultMessage.NAME + " goes from server to client not the other way around",
        exception.getMessage());
    assertNull(exception.ident);
    assertFalse(exception.global);
  }
}
