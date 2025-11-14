package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import network.crypta.keys.FreenetURI;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ArrayBucket;
import network.crypta.support.io.NullBucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100") // Test method naming: method_whenCondition_expectOutcome
@ExtendWith(MockitoExtension.class)
class URIFeedMessageTest {

  @Mock private FreenetURI uriMock;

  @Test
  void constructor_whenDescriptionNonNull_expectArrayBucketWithUtf8Bytes() throws IOException {
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
    String description = "Description with UTF-8 ✓";

    URIFeedMessage message =
        new URIFeedMessage(
            header,
            shortText,
            text,
            priorityClass,
            updatedTime,
            sourceNodeName,
            composed,
            sent,
            received,
            uriMock,
            description);

    int textBytes = text.getBytes(StandardCharsets.UTF_8).length;
    int descriptionBytes = description.getBytes(StandardCharsets.UTF_8).length;
    long expectedTotalBytes = (long) textBytes + descriptionBytes;

    // Act
    Map<String, Bucket> buckets = getBuckets(message);
    Bucket textBucket = buckets.get("Text");
    Bucket descriptionBucket = buckets.get("Description");

    // Assert: text bucket from FeedMessage
    assertEquals(ArrayBucket.class, textBucket.getClass());
    assertEquals(textBytes, textBucket.size());

    // Assert: description bucket populated with UTF-8 bytes
    assertEquals(ArrayBucket.class, descriptionBucket.getClass());
    assertEquals(descriptionBytes, descriptionBucket.size());
    assertEquals(expectedTotalBytes, message.dataLength());

    // Verify bucket contents decode back to the original description
    try (InputStream in = descriptionBucket.getInputStream()) {
      byte[] buffer = in.readAllBytes();
      String decoded = new String(buffer, StandardCharsets.UTF_8);
      assertEquals(description, decoded);
    }
  }

  @Test
  void constructor_whenDescriptionNull_expectNullBucketWithZeroLength() {
    // Arrange
    String text = "Body only";
    short priorityClass = 3;
    long updatedTime = 1234L;

    URIFeedMessage message =
        new URIFeedMessage(
            "Header",
            "Short",
            text,
            priorityClass,
            updatedTime,
            "SomeNode",
            10L,
            20L,
            30L,
            uriMock,
            null);

    int textBytes = text.getBytes(StandardCharsets.UTF_8).length;

    // Act
    Map<String, Bucket> buckets = getBuckets(message);
    Bucket textBucket = buckets.get("Text");
    Bucket descriptionBucket = buckets.get("Description");

    // Assert: text bucket still populated from FeedMessage
    assertEquals(ArrayBucket.class, textBucket.getClass());
    assertEquals(textBytes, textBucket.size());

    // Assert: null description leads to a NullBucket with zero size
    assertEquals(NullBucket.class, descriptionBucket.getClass());
    assertEquals(0L, descriptionBucket.size());

    // Overall DataLength should reflect only the text bucket
    assertEquals(textBytes, message.dataLength());
  }

  @Test
  void constructor_whenDescriptionEmpty_expectArrayBucketWithZeroLength() {
    // Arrange
    String text = "Body";
    String description = "";
    short priorityClass = 2;
    long updatedTime = 99L;

    URIFeedMessage message =
        new URIFeedMessage(
            "Header",
            "Short",
            text,
            priorityClass,
            updatedTime,
            "Node",
            1L,
            2L,
            3L,
            uriMock,
            description);

    int textBytes = text.getBytes(StandardCharsets.UTF_8).length;

    // Act
    Map<String, Bucket> buckets = getBuckets(message);
    Bucket textBucket = buckets.get("Text");
    Bucket descriptionBucket = buckets.get("Description");

    // Assert
    assertEquals(ArrayBucket.class, descriptionBucket.getClass());
    assertEquals(0L, descriptionBucket.size());
    assertEquals(ArrayBucket.class, textBucket.getClass());
    assertEquals(textBytes, textBucket.size());
    assertEquals(textBytes, message.dataLength());
  }

  @Test
  void getFieldSet_whenStandardValuesProvided_expectBaseFieldsAndUriPresent() {
    // Arrange
    String header = "URI Feed Header";
    String shortText = "Short URI summary";
    String text = "Body text";
    short priorityClass = 7;
    long updatedTime = 1_700_000_000L;
    String sourceNodeName = "OriginNode";
    long composed = 1234L;
    long sent = 5678L;
    long received = 9012L;
    String description = "Descriptive text";

    String uriString = "KSK@some-doc";
    org.mockito.Mockito.when(uriMock.toString()).thenReturn(uriString);

    URIFeedMessage message =
        new URIFeedMessage(
            header,
            shortText,
            text,
            priorityClass,
            updatedTime,
            sourceNodeName,
            composed,
            sent,
            received,
            uriMock,
            description);

    // Act
    SimpleFieldSet fieldSet = message.getFieldSet();

    int textBytes = text.getBytes(StandardCharsets.UTF_8).length;
    int descriptionBytes = description.getBytes(StandardCharsets.UTF_8).length;
    long expectedTotalBytes = (long) textBytes + descriptionBytes;

    // Assert: base feed metadata
    assertEquals(header, fieldSet.get("Header"));
    assertEquals(shortText, fieldSet.get("ShortText"));
    assertEquals(priorityClass, fieldSet.getShort("PriorityClass", (short) -1));
    assertEquals(updatedTime, fieldSet.getLong("UpdatedTime", -1L));

    // Assert: node-to-node metadata
    assertEquals(sourceNodeName, fieldSet.get("SourceNodeName"));
    assertEquals(composed, fieldSet.getLong("TimeComposed", -1L));
    assertEquals(sent, fieldSet.getLong("TimeSent", -1L));
    assertEquals(received, fieldSet.getLong("TimeReceived", -1L));

    // Assert: URI is included
    assertEquals(uriString, fieldSet.get("URI"));

    // Assert: bucket lengths and aggregated DataLength
    assertEquals(textBytes, fieldSet.getLong("TextLength", -1L));
    assertEquals(descriptionBytes, fieldSet.getLong("DescriptionLength", -1L));
    assertEquals(expectedTotalBytes, fieldSet.getLong("DataLength", -1L));
    assertEquals(expectedTotalBytes, message.dataLength());
  }

  @Test
  void getFieldSet_whenTimestampsUnknown_expectTimeFieldsOmittedButUriPresent() {
    // Arrange
    String text = "Body";
    String description = "Desc";
    short priorityClass = 4;
    long updatedTime = 42L;
    String sourceNodeName = "UnknownNode";
    String uriString = "KSK@editionless";

    org.mockito.Mockito.when(uriMock.toString()).thenReturn(uriString);

    URIFeedMessage message =
        new URIFeedMessage(
            "Header",
            "Short",
            text,
            priorityClass,
            updatedTime,
            sourceNodeName,
            -1L,
            -1L,
            -1L,
            uriMock,
            description);

    // Act
    SimpleFieldSet fieldSet = message.getFieldSet();

    // Assert: source node name is present but time fields are omitted
    assertEquals(sourceNodeName, fieldSet.get("SourceNodeName"));
    assertNull(fieldSet.get("TimeComposed"));
    assertNull(fieldSet.get("TimeSent"));
    assertNull(fieldSet.get("TimeReceived"));

    // URI remains present regardless of timestamps
    assertEquals(uriString, fieldSet.get("URI"));
  }

  @Test
  void getName_whenCalled_expectUriFeedConstantReturned() {
    // Arrange
    URIFeedMessage message =
        new URIFeedMessage(
            "Header",
            "Short",
            "Text",
            (short) 1,
            0L,
            "Node",
            -1L,
            -1L,
            -1L,
            uriMock,
            "Description");

    // Act & Assert
    assertEquals(URIFeedMessage.NAME, message.getName());
    assertEquals("URIFeed", message.getName());
  }

  private static Map<String, Bucket> getBuckets(MultipleDataCarryingMessage message) {
    try {
      java.lang.reflect.Field bucketsField =
          MultipleDataCarryingMessage.class.getDeclaredField("buckets");
      bucketsField.setAccessible(true);
      @SuppressWarnings("unchecked")
      Map<String, Bucket> buckets = (Map<String, Bucket>) bucketsField.get(message);
      return buckets;
    } catch (ReflectiveOperationException e) {
      throw new AssertionError("Failed to access buckets for URIFeedMessage", e);
    }
  }
}
