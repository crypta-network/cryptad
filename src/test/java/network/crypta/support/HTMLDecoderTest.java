package network.crypta.support;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.stream.Stream;
import network.crypta.test.UTFUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Tests for {@link HTMLDecoder} covering named, numeric-decimal, numeric-hex entities, whitespace
 * handling, and compaction. Focuses on deterministic, comprehensive coverage of the public API.
 */
@SuppressWarnings("java:S100") // Allow method names with underscores for readability
class HTMLDecoderTest {

  private static void ignoreString(String ignored) {}

  // -------- decode(String) --------

  @Test
  @SuppressWarnings("DataFlowIssue")
  void decode_whenNull_throwsNullPointerException() {
    assertThrows(NullPointerException.class, () -> ignoreString(HTMLDecoder.decode(null)));
  }

  @ParameterizedTest
  @CsvSource({"&lt;,<", "&gt;,>", "&amp;,&", "&copy;,©", "&euro;,€"})
  void decode_whenNamedEntity_expectMappedCharacter(String encoded, String expected) {
    assertEquals(expected, HTMLDecoder.decode(encoded));
  }

  @ParameterizedTest
  @MethodSource("decimalEntityProvider")
  void decode_whenNumericDecimal_expectCharacter(String encoded, String expected) {
    assertEquals(expected, HTMLDecoder.decode(encoded));
  }

  static Stream<Arguments> decimalEntityProvider() {
    return Stream.of(
        Arguments.of("&#229;", "å"),
        Arguments.of("&#1048;", "И"),
        Arguments.of("&#39;", "'"),
        Arguments.of("&#65535;", "\uFFFF"));
  }

  @ParameterizedTest
  @CsvSource({
    "&#x6C34;,水", // CJK: U+6C34
    "&#X6C34;,水", // uppercase X supported
    "&#x00A9;,©", // copyright
    "&#xa9;,©" // lowercase hex
  })
  void decode_whenNumericHex_expectCharacter(String encoded, String expected) {
    assertEquals(expected, HTMLDecoder.decode(encoded));
  }

  @Test
  void decode_whenControlCharacterNumeric_expectInsertedChar() {
    String decoded = HTMLDecoder.decode("&#0;");
    assertEquals(1, decoded.length());
    assertEquals(0, decoded.charAt(0));
  }

  @ParameterizedTest
  @MethodSource("invalidEntityProvider")
  void decode_whenInvalidOrIncomplete_expectUnchanged(String input) {
    assertEquals(input, HTMLDecoder.decode(input));
  }

  static Stream<String> invalidEntityProvider() {
    return Stream.of(
        "&Phi", // missing semicolon
        "&Ph;", // unknown entity
        "&1234;", // no leading '#'
        "Phi;", // no leading '&'
        "", // empty
        "&#229", // decimal without semicolon
        "&#x6C34", // hex without semicolon
        "&#xGG;", // non-hex digits
        "&apos;", // not in decode map
        "abc&", // dangling ampersand
        "&#65536;", // out-of-range decimal
        "&#x10000;", // out-of-range hex
        "&#x6C34XYZ;" // junk after valid hex digits before semicolon
        );
  }

  @Test
  void decode_whenMixedValidAndInvalid_expectOnlyValidDecoded() {
    String input = "test &lt;tag&#62; &unknown; &#xZZ; end";
    String expected = "test <tag> &unknown; &#xZZ; end";
    assertEquals(expected, HTMLDecoder.decode(input));
  }

  @Test
  void decode_allSupportedNamedEntities_viaUTFUtilData() {
    String[][] entities = UTFUtil.htmlEntitiesUtf();
    for (String[] pair : entities) {
      String decoded = HTMLDecoder.decode(pair[1]);
      assertEquals(pair[0], decoded, () -> "Failed for entity: " + pair[1]);
    }
  }

  @Test
  void decode_appendedEntities_viaUTFUtilData() {
    String[][] entities = UTFUtil.htmlEntitiesUtf();
    StringBuilder encoded = new StringBuilder();
    StringBuilder expected = new StringBuilder();
    for (String[] pair : entities) {
      expected.append(pair[0]);
      encoded.append(pair[1]);
    }
    assertEquals(expected.toString(), HTMLDecoder.decode(encoded.toString()));
  }

  // -------- compact(String) --------

  @Test
  @SuppressWarnings("DataFlowIssue")
  void compact_whenNull_throwsNullPointerException() {
    assertThrows(NullPointerException.class, () -> ignoreString(HTMLDecoder.compact(null)));
  }

  @Test
  void compact_whenRepeatedSingleType_expectSingleSpace() {
    String ws = "\t\t\t";
    assertEquals(" ", HTMLDecoder.compact(ws));
  }

  @Test
  void compact_whenMixedWhitespace_expectSingleSpacesBetweenWords() {
    String mixed = "a" + " " + "\t" + "\n" + "\r" + "\u200b" + "\u000c" + "b";
    assertEquals("a b", HTMLDecoder.compact(mixed));
  }

  @Test
  void compact_whenLeadingAndTrailingWhitespace_expectSingleSpacesAtEdges() {
    String s = "\t\t  abc\n\r\u200b\u000c";
    assertEquals(" abc ", HTMLDecoder.compact(" " + s + " "));
  }

  @Test
  void compact_whenNoWhitespace_expectUnchanged() {
    assertEquals("abcXYZ", HTMLDecoder.compact("abcXYZ"));
  }

  @Test
  void compact_whenNonBreakingSpace_notTreatedAsWhitespace() {
    String nbsp = "a\u00A0\u00A0b"; // NBSP is not considered whitespace by HTMLDecoder
    assertEquals(nbsp, HTMLDecoder.compact(nbsp));
  }

  // -------- isWhitespace(char) --------

  @Test
  void isWhitespace_whenAllDeclaredTypes_expectTrue() {
    assertTrue(HTMLDecoder.isWhitespace(' '));
    assertTrue(HTMLDecoder.isWhitespace('\r'));
    assertTrue(HTMLDecoder.isWhitespace('\n'));
    assertTrue(HTMLDecoder.isWhitespace('\t'));
    assertTrue(HTMLDecoder.isWhitespace('\u000c'));
    assertTrue(HTMLDecoder.isWhitespace('\u200b'));
  }

  @Test
  void isWhitespace_whenCommonNonWhitespace_expectFalse() {
    assertFalse(HTMLDecoder.isWhitespace('A'));
    assertFalse(HTMLDecoder.isWhitespace('0'));
    assertFalse(HTMLDecoder.isWhitespace('\u00A0')); // NBSP
  }
}
