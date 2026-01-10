package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ArrayBucket;
import network.crypta.support.io.NullBucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class TextFeedMessageTest {

  @Test
  void getFieldSet_whenMessageTextProvided_expectMessageTextBucketContributesToLengths() {
    // Arrange
    String header = "Test header";
    String shortText = "Short summary";
    String text = "Body text with UTF-8 ☃ and newlines\nsecond line";
    short priorityClass = 5;
    long updatedTime = 1_694_000_000L;
    String sourceNodeName = "PeerNode-A";
    long composed = 100L;
    long sent = 200L;
    long received = 300L;
    String messageText = "Additional message text";

    N2NFeedMessageParams params =
        new N2NFeedMessageParams(
            header,
            shortText,
            text,
            priorityClass,
            updatedTime,
            sourceNodeName,
            composed,
            sent,
            received);
    TextFeedMessage message = new TextFeedMessage(params, messageText);

    // Act
    SimpleFieldSet fieldSet = message.getFieldSet();

    int textBytes = text.getBytes(StandardCharsets.UTF_8).length;
    int messageTextBytes = messageText.getBytes(StandardCharsets.UTF_8).length;
    long expectedTotalBytes = (long) textBytes + messageTextBytes;

    // Assert: base feed fields
    assertEquals(header, fieldSet.get("Header"));
    assertEquals(shortText, fieldSet.get("ShortText"));
    assertEquals(priorityClass, fieldSet.getShort("PriorityClass", (short) -1));
    assertEquals(updatedTime, fieldSet.getLong("UpdatedTime", -1L));

    // Assert: node-to-node metadata
    assertEquals(sourceNodeName, fieldSet.get("SourceNodeName"));
    assertEquals(composed, fieldSet.getLong("TimeComposed", -1L));
    assertEquals(sent, fieldSet.getLong("TimeSent", -1L));
    assertEquals(received, fieldSet.getLong("TimeReceived", -1L));

    // Assert: bucket lengths and aggregated DataLength
    assertEquals(textBytes, fieldSet.getLong("TextLength", -1L));
    assertEquals(messageTextBytes, fieldSet.getLong("MessageTextLength", -1L));
    assertEquals(expectedTotalBytes, fieldSet.getLong("DataLength", -1L));
    assertEquals(expectedTotalBytes, message.dataLength());

    // Assert: implementation detail – non-null message text uses ArrayBucket
    Bucket messageBucket = getBuckets(message).get("MessageText");
    assertEquals(ArrayBucket.class, messageBucket.getClass());
  }

  @Test
  void getFieldSet_whenTimestampsUnknown_expectTimeFieldsOmitted() {
    // Arrange
    String header = "Header";
    String shortText = "Short";
    String text = "Body";
    short priorityClass = 1;
    long updatedTime = 42L;
    String sourceNodeName = "UnknownNode";
    String messageText = "Message payload";

    N2NFeedMessageParams params =
        new N2NFeedMessageParams(
            header, shortText, text, priorityClass, updatedTime, sourceNodeName, -1L, -1L, -1L);
    TextFeedMessage message = new TextFeedMessage(params, messageText);

    // Act
    SimpleFieldSet fieldSet = message.getFieldSet();

    // Assert
    assertEquals(sourceNodeName, fieldSet.get("SourceNodeName"));
    assertNull(fieldSet.get("TimeComposed"));
    assertNull(fieldSet.get("TimeSent"));
    assertNull(fieldSet.get("TimeReceived"));

    int messageTextBytes = messageText.getBytes(StandardCharsets.UTF_8).length;
    assertEquals(messageTextBytes, fieldSet.getLong("MessageTextLength", -1L));
  }

  @Test
  void getFieldSet_whenMessageTextNull_expectZeroLengthNullBucketAndBodyOnlyDataLength() {
    // Arrange
    String text = "Body only";
    short priorityClass = 3;
    long updatedTime = 1234L;

    N2NFeedMessageParams params =
        new N2NFeedMessageParams(
            "Header", "Short", text, priorityClass, updatedTime, "SomeNode", 10L, 20L, 30L);
    TextFeedMessage message = new TextFeedMessage(params, null);

    // Act
    SimpleFieldSet fieldSet = message.getFieldSet();

    int textBytes = text.getBytes(StandardCharsets.UTF_8).length;

    // Assert: the MessageText bucket exists but contributes zero bytes
    assertEquals(textBytes, fieldSet.getLong("TextLength", -1L));
    assertEquals(0L, fieldSet.getLong("MessageTextLength", -1L));
    assertEquals(textBytes, fieldSet.getLong("DataLength", -1L));
    assertEquals(textBytes, message.dataLength());

    Bucket messageBucket = getBuckets(message).get("MessageText");
    assertEquals(NullBucket.class, messageBucket.getClass());
  }

  @Test
  void getName_whenCalled_expectTextFeedConstantReturned() {
    // Arrange
    N2NFeedMessageParams params =
        new N2NFeedMessageParams("Header", "Short", "Body", (short) 1, 0L, "Node", -1L, -1L, -1L);
    TextFeedMessage message = new TextFeedMessage(params, "message");

    // Act & Assert
    assertEquals(TextFeedMessage.NAME, message.getName());
  }

  private Map<String, Bucket> getBuckets(TextFeedMessage message) {
    try {
      Field bucketsField = MultipleDataCarryingMessage.class.getDeclaredField("buckets");
      bucketsField.setAccessible(true);
      @SuppressWarnings("unchecked")
      Map<String, Bucket> buckets = (Map<String, Bucket>) bucketsField.get(message);
      return buckets;
    } catch (ReflectiveOperationException e) {
      throw new AssertionError("Failed to access buckets for TextFeedMessage", e);
    }
  }
}
