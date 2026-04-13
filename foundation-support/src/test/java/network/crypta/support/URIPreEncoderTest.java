package network.crypta.support;

import java.net.URI;
import java.net.URISyntaxException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for {@link URIPreEncoder}.
 *
 * <p>Covers: happy-path encoding, preservation of allowed characters, multibyte UTF-8, anchors,
 * already-encoded sequences, zero-padding, null handling, and URI construction success/error paths.
 */
@SuppressWarnings({"java:S100", "java:S5778"})
class URIPreEncoderTest {

  private static final String ALL_CHARS = new String(allCharacters());
  private static final String PRINTABLE_ASCII = " !@#$%^&()+=[]{}:;\\\"',<>.?~`";
  private static final String STRESSED_UTF_CHARS = "ÉâûĔĭņşÊãüĕĮŇŠ漢字";

  @Test
  void encode_whenMixedAsciiAndUtf8_expectOnlyAllowedChars() {
    // Arrange
    String toEncode = PRINTABLE_ASCII + STRESSED_UTF_CHARS;

    // Act
    String encoded = URIPreEncoder.encode(toEncode);

    // Assert
    assertTrue(containsOnlyValidChars(encoded));

    // Act/Assert again with a very wide range of characters
    String encodedAll = URIPreEncoder.encode(ALL_CHARS);
    assertTrue(containsOnlyValidChars(encodedAll));
  }

  @ParameterizedTest
  @CsvSource({
    // spaces and simple ASCII
    "http://example.com/a b, http://example.com/a%20b",
    // unicode é (C3 A9)
    "http://example.com/café, http://example.com/caf%c3%a9",
    // CJK example: 漢 (E6 BC A2)
    "http://example.com/漢, http://example.com/%e6%bc%a2",
    // plus should NOT be converted to space; remains '+'
    "http://example.com/a+b c, http://example.com/a+b%20c",
    // anchor preserved, its contents encoded
    "http://example.com/page#sec tion, http://example.com/page#sec%20tion"
  })
  void encode_whenVariousInputs_expectExpectedPercentEncoding(String input, String expected) {
    // Act
    String actual = URIPreEncoder.encode(input);

    // Assert
    assertEquals(expected, actual);
  }

  @Test
  void encode_whenContainsNewline_expectPercentEncodedZeroPadded() {
    // Arrange
    String input = "http://example.com/line\nfeed";
    String expected = "http://example.com/line%0afeed";

    // Act
    String actual = URIPreEncoder.encode(input);

    // Assert
    assertEquals(expected, actual);
  }

  @Test
  void encode_whenContainsAlreadyEncodedSequence_expectNotDoubleEncoded() {
    // Arrange
    String input = "http://example.com/a%20b";

    // Act
    String actual = URIPreEncoder.encode(input);

    // Assert
    assertEquals(input, actual);
  }

  @Test
  void encode_whenNull_expectNullPointerException() {
    assertThrows(NullPointerException.class, () -> URIPreEncoder.encode(null));
  }

  @Test
  void encodeURI_whenSpacesAndUnicodePresent_expectValidURI() throws URISyntaxException {
    // Arrange
    String input = "http://example.com/café au lait?q=汉 字#frag ment";
    String expected =
        "http://example.com/caf%c3%a9%20au%20lait?q=%e6%b1%89%20%e5%ad%97#frag%20ment";

    // Act
    URI uri = URIPreEncoder.encodeURI(input);

    // Assert
    assertEquals(expected, uri.toString());
  }

  @Test
  void encodeURI_whenInvalidPercentSequence_expectURISyntaxException() {
    // Arrange: invalid percent-escape in the path
    String input = "http://example.com/a%2Zb";

    // Act + Assert
    assertThrows(URISyntaxException.class, () -> URIPreEncoder.encodeURI(input));
  }

  @Test
  void encodeURI_whenNull_expectNullPointerException() {
    assertThrows(NullPointerException.class, () -> URIPreEncoder.encodeURI(null));
  }

  private static char[] allCharacters() {
    char[] chars = new char[Character.MAX_VALUE - Character.MIN_VALUE + 1];
    for (int i = 0; i <= Character.MAX_VALUE - Character.MIN_VALUE; ++i) {
      int characterValue = Character.MIN_VALUE + i;
      if (characterValue >= Character.MIN_LOW_SURROGATE
          && characterValue <= Character.MAX_LOW_SURROGATE) {
        chars[i] = ' ';
      } else if (characterValue >= Character.MIN_HIGH_SURROGATE
          && characterValue <= Character.MAX_HIGH_SURROGATE) {
        chars[i] = ' ';
      } else {
        chars[i] = (char) characterValue;
      }
    }
    return chars;
  }

  private static boolean containsOnlyValidChars(String s) {
    for (int i = 0; i < s.length(); i++) {
      if (URIPreEncoder.ALLOWED_CHARS.indexOf(s.charAt(i)) < 0) {
        return false;
      }
    }
    return true;
  }
}
