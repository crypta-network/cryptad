package network.crypta.support;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100") // Allow underscore style for test method names
class URLDecoderTest {

  @Test
  @DisplayName("decode: empty string returns empty string")
  void decode_whenEmptyString_returnsEmpty() throws URLEncodedFormatException {
    // Arrange
    String input = "";

    // Act
    String result = URLDecoder.decode(input, false);

    // Assert
    assertEquals("", result);
  }

  @Test
  void decode_whenNoPercents_returnsOriginal() throws URLEncodedFormatException {
    // Arrange
    String input = "Hello_äöü"; // keep '+' unhandled by design; non-ASCII stays intact

    // Act
    String result = URLDecoder.decode(input, false);

    // Assert
    assertEquals(input, result);
  }

  @Test
  void decode_whenPlusSign_present_keptLiteral() throws URLEncodedFormatException {
    // Arrange
    String input = "a+b+c"; // not application/x-www-form-urlencoded

    // Act
    String result = URLDecoder.decode(input, false);

    // Assert
    assertEquals("a+b+c", result);
  }

  @ParameterizedTest(name = "{index} -> decode('{0}') = '{1}'")
  @CsvSource({
    "%41,A",
    "Hello%20World,Hello World",
    "%2F,/",
    "%7B%7D,{}",
    "path%2Fto%2Ffile,path/to/file",
    // lowercase hex should work
    "%2f,/",
    // UTF-8 multibyte sequences
    "%C3%A9,é",
    "%E2%82%AC,€"
  })
  void decode_whenValidEscapes_decodesUtf8(String input, String expected)
      throws URLEncodedFormatException {
    // Act
    String result = URLDecoder.decode(input, false);

    // Assert
    assertEquals(expected, result);
  }

  @Test
  void decode_whenSingleByte0x7F_decodesControlChar() throws URLEncodedFormatException {
    // Arrange
    String input = "%7F";
    String expected = new String(new byte[] {(byte) 0x7F}, StandardCharsets.UTF_8);

    // Act
    String result = URLDecoder.decode(input, false);

    // Assert
    assertEquals(expected, result);
  }

  @Test
  void decode_whenEncodedNullByte_throwsFormatException() {
    // Arrange
    String input = "%00";

    // Act + Assert
    URLEncodedFormatException ex =
        assertThrows(URLEncodedFormatException.class, () -> URLDecoder.decode(input, false));
    assertEquals("Can't encode 00", ex.getMessage());
  }

  @Test
  void decode_whenInvalidHex_tolerantFalse_throws() {
    // Arrange
    String input = "%G1";

    // Act + Assert
    URLEncodedFormatException ex =
        assertThrows(URLEncodedFormatException.class, () -> URLDecoder.decode(input, false));
    // Message includes the offending two characters and the full input
    // e.g., "Not a two character hex % escape: G1 in %G1"
    // Keep assertion stable by checking significant fragment
    String msg = ex.getMessage();
    // Use exact prefix to ensure we hit the intended branch
    // (avoid brittle full-string matches across potential future tweaks)
    Assertions.assertTrue(
        msg != null && msg.startsWith("Not a two character hex % escape: G1 in "));
  }

  @Test
  void decode_whenInvalidHex_tolerantTrueBeforeAnyValid_passesThrough() throws Exception {
    // Arrange
    String input = "%GG%41";

    // Act
    String result = URLDecoder.decode(input, true);

    // Assert: first bogus kept literally, then %41 -> 'A'
    assertEquals("%GGA", result);
  }

  @Test
  void decode_whenInvalidHex_afterValidEvenWithTolerant_throws() {
    // Arrange
    String input = "%41%GG"; // first decode sets hasDecodedSomething=true

    // Act + Assert
    assertThrows(URLEncodedFormatException.class, () -> URLDecoder.decode(input, true));
  }

  @ParameterizedTest
  @CsvSource({"abc%", "abc%A"})
  void decode_whenIncompleteEscape_throwsOriginalInputAsMessage(String input) {
    // Act + Assert
    URLEncodedFormatException ex =
        assertThrows(URLEncodedFormatException.class, () -> URLDecoder.decode(input, false));
    assertEquals(input, ex.getMessage());
  }

  @Test
  void decode_whenOnlyBogusAndTolerantTrue_passesThroughAll() throws Exception {
    // Arrange
    String input = "%GG%HH%II";

    // Act
    String result = URLDecoder.decode(input, true);

    // Assert: stays unchanged because no successful decode ever occurred
    assertEquals(input, result);
  }
}
