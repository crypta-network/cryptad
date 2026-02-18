package network.crypta.client.events;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

@SuppressWarnings("java:S100")
class ExpectedMIMEEventTest {

  @Test
  void constructor_andAccessors_whenNormalType_expectValues() {
    // Arrange
    String mime = "text/html";

    // Act
    ExpectedMIMEEvent event = new ExpectedMIMEEvent(mime);

    // Assert
    assertEquals(mime, event.expectedMIMEType, "Field should reflect constructor argument");
    assertEquals(0x0B, event.getCode(), "Event code should match constant");
    assertEquals(
        "Expected MIME type: text/html",
        event.getDescription(),
        "Description should prefix with label");
  }

  @Test
  void getDescription_whenNullType_expectNullLiteralInDescription() {
    // Arrange & Act
    ExpectedMIMEEvent event = new ExpectedMIMEEvent(null);

    // Assert
    assertNull(event.expectedMIMEType, "Field should be null when constructed with null");
    assertEquals(0x0B, event.getCode(), "Event code remains constant for all instances");
    String description = event.getDescription();
    assertNotNull(description, "Description must be non-null even if MIME type is null");
    assertEquals(
        "Expected MIME type: null",
        description,
        "String concatenation should render null as literal 'null'");
  }

  @Test
  void getDescription_whenEmptyType_expectTrailingSpaceOnly() {
    // Arrange
    String mime = "";

    // Act
    ExpectedMIMEEvent event = new ExpectedMIMEEvent(mime);

    // Assert
    assertEquals("", event.expectedMIMEType, "Field should allow empty strings");
    assertEquals(
        "Expected MIME type: ",
        event.getDescription(),
        "Description should handle empty MIME without extra punctuation");
  }

  @ParameterizedTest
  @CsvSource({
    "application/json; charset=UTF-8",
    "image/png",
    "application/octet-stream",
    "text/plain; charset=US-ASCII"
  })
  void getDescription_whenVariousTypes_expectFormattedPrefix(String mime) {
    // Arrange & Act
    ExpectedMIMEEvent event = new ExpectedMIMEEvent(mime);

    // Assert
    assertEquals(mime, event.expectedMIMEType, "Field preserves exact MIME value");
    assertEquals(
        "Expected MIME type: " + mime,
        event.getDescription(),
        "Description must include exact MIME value with standard prefix");
  }
}
