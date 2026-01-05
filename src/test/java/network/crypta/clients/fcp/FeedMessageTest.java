package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class FeedMessageTest {

  @Test
  void getFieldSet_whenConstructedWithStandardParameters_expectHeaderShortTextAndLengthFields() {
    // Arrange
    String header = "Test header";
    String shortText = "Short summary";
    String text = "Body text with UTF-8 ☃ and newlines\nsecond line";
    short priorityClass = 5;
    long updatedTime = 1_694_000_000L;

    FeedMessage message = new FeedMessage(header, shortText, text, priorityClass, updatedTime);

    // Act
    SimpleFieldSet fieldSet = message.getFieldSet();

    // Assert
    assertEquals(header, fieldSet.get("Header"));
    assertEquals(shortText, fieldSet.get("ShortText"));
    assertEquals(priorityClass, fieldSet.getShort("PriorityClass", (short) -1));
    assertEquals(updatedTime, fieldSet.getLong("UpdatedTime", -1L));

    int expectedBytes = text.getBytes(StandardCharsets.UTF_8).length;
    assertEquals(expectedBytes, fieldSet.getLong("TextLength", -1L));
    assertEquals(expectedBytes, fieldSet.getLong("DataLength", -1L));
  }

  @Test
  void getFieldSet_whenHeaderAndShortTextAreNull_expectFieldsOmitted() {
    // Arrange
    String text = "Only body text";
    short priorityClass = 1;
    long updatedTime = 42L;

    FeedMessage message = new FeedMessage(null, null, text, priorityClass, updatedTime);

    // Act
    SimpleFieldSet fieldSet = message.getFieldSet();

    // Assert
    assertNull(fieldSet.get("Header"));
    assertNull(fieldSet.get("ShortText"));

    int expectedBytes = text.getBytes(StandardCharsets.UTF_8).length;
    assertEquals(expectedBytes, fieldSet.getLong("TextLength", -1L));
    assertEquals(expectedBytes, fieldSet.getLong("DataLength", -1L));
  }

  @Test
  void dataLength_whenTextContainsMultiByteCharacters_expectUtf8ByteLengthUsed() {
    // Arrange
    String text = "ASCII and üñîçødê ☃";
    FeedMessage message = new FeedMessage("header", "short", text, (short) 3, 100L);

    long expectedBytes = text.getBytes(StandardCharsets.UTF_8).length;

    // Act
    long dataLength = message.dataLength();
    SimpleFieldSet fieldSet = message.getFieldSet();

    // Assert
    assertEquals(expectedBytes, dataLength);
    assertEquals(expectedBytes, fieldSet.getLong("DataLength", -1L));
  }

  @Test
  void run_whenInvoked_expectMessageInvalidExceptionWithInvalidMessageCode() {
    // Arrange
    FeedMessage message = new FeedMessage("header", "short", "text", (short) 2, 123_456_789L);
    Node node = org.mockito.Mockito.mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);

    // Act
    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> message.run(null, node));

    // Assert
    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, exception.protocolCode);
    assertEquals(
        "Feed goes from server to client not the other way around", exception.getMessage());
    assertNull(exception.ident);
    assertFalse(exception.global);
  }

  @Test
  void getName_whenCalled_expectFeedConstantReturned() {
    // Arrange
    FeedMessage message = new FeedMessage("header", "short", "text", (short) 1, 987_654_321L);

    // Act & Assert
    assertEquals(FeedMessage.NAME, message.getName());
  }

  @Test
  void getEndString_whenCalled_expectDataMarkerReturned() {
    // Arrange
    FeedMessage message = new FeedMessage("header", "short", "text", (short) 1, 0L);

    // Act & Assert
    assertEquals("Data", message.getEndString());
  }
}
