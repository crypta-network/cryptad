package network.crypta.support;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Unit tests for {@link URLEncoder}. */
@SuppressWarnings("java:S100") // test naming uses method_whenCondition_expectOutcome
class URLEncoderTest {

  @Test
  void getSafeURLCharacters_containsExpected_withoutSpace() {
    String safe = URLEncoder.getSafeURLCharacters();
    assertTrue(safe.indexOf('/') >= 0);
    assertTrue(safe.indexOf('_') >= 0);
    assertTrue(safe.indexOf('-') >= 0);
    assertTrue(safe.indexOf('.') >= 0);
    assertTrue(safe.indexOf('A') >= 0 && safe.indexOf('z') >= 0);
    assertTrue(safe.indexOf('0') >= 0 && safe.indexOf('9') >= 0);
    assertTrue(safe.indexOf(' ') < 0); // spaces must not be safe by default
  }

  @Test
  void encode_whenAsciiFalse_allowsUnicodeAndEncodesSpaces() {
    String input = "café 123"; // contains non-ASCII 'é' and a space
    String encoded = URLEncoder.encode(input, false);
    assertEquals("café%20123", encoded);
  }

  @Test
  void encode_whenAsciiTrue_encodesNonAsciiAndUnsafePunctuation() {
    String input = "café ~!@\n"; // é, space, tilde, !, @, newline
    String encoded = URLEncoder.encode(input, true);
    // é -> c3 a9, space -> 20, ~ -> 7e, ! -> 21, @ -> 40, \n -> 0a (zero-padded)
    assertEquals("caf%c3%a9%20%7e%21%40%0a", encoded);
  }

  @Test
  void encode_withForce_encodesEvenSafeAndUnicode() {
    String input = "A/é";
    String force = "A/é"; // force all three characters
    String encoded = URLEncoder.encode(input, force, false);
    assertEquals("%41%2f%c3%a9", encoded);
  }

  @Test
  void encode_withExtraSafeChars_allowsAdditionalCharactersToPassThrough() {
    String input = "@?* ";
    String extraSafe = "@?* ";
    String encoded = URLEncoder.encode(input, null, true, extraSafe);
    assertEquals(input, encoded);
  }

  @Test
  void encode_withExtraSafeChars_andForce_overridesExtraSafe() {
    String input = "a* b"; // '*' and space are extra-safe; only '*' is forced
    String extraSafe = "* ";
    String force = "*";
    String encoded = URLEncoder.encode(input, force, true, extraSafe);
    assertEquals("a%2a b", encoded);
  }

  @Test
  void encode_overloadConsistency_encodeBooleanEqualsEncodeWithNullForce() {
    String s = "abcXYZ";
    assertEquals(URLEncoder.encode(s, true), URLEncoder.encode(s, null, true));
    assertEquals(URLEncoder.encode(s, false), URLEncoder.encode(s, null, false));
  }

  @Test
  void encode_emptyString_returnsEmptyString() {
    assertEquals("", URLEncoder.encode("", true));
    assertEquals("", URLEncoder.encode("", false));
  }

  @Test
  void encode_nullInputs_throwNullPointerException() {
    assertThrows(NullPointerException.class, () -> URLEncoder.encode(null, true));
    assertThrows(NullPointerException.class, () -> URLEncoder.encode(null, null, true));
  }

  @Test
  void encode_whenAsciiFalse_preservesNonBmpEmoji() {
    String input = "hi\uD83D\uDE00"; // "hi😀" (U+1F600)
    String encoded = URLEncoder.encode(input, false);
    assertEquals(input, encoded);
  }
}
