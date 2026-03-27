package network.crypta.support.http;

import java.text.ParseException;
import java.time.Instant;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class HttpDateParserTest {

  @Test
  void parseHTTPDate_whenValidRfc1123Date_expectParsedInstant() throws Exception {
    // Arrange
    String httpDate = "Thu, 01 Jan 1970 00:00:00 GMT";

    // Act
    Instant parsed = HttpDateParser.parseHTTPDate(httpDate).toInstant();

    // Assert
    assertEquals(Instant.EPOCH, parsed);
  }

  @Test
  void parseHTTPDate_whenInvalidDate_expectParseException() {
    // Arrange
    String httpDate = "not a date";

    // Act / Assert
    assertThrows(ParseException.class, () -> HttpDateParser.parseHTTPDate(httpDate));
  }
}
