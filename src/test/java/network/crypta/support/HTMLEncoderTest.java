package network.crypta.support;

import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class HTMLEncoderTest {

  // -------- encode(String) --------

  @Test
  void encode_whenLettersAndDigits_expectUnchanged() {
    // Arrange
    String input = "AbcXYZ0123456789";
    // Act
    String encoded = HTMLEncoder.encode(input);
    // Assert
    assertEquals(input, encoded);
  }

  @ParameterizedTest
  @MethodSource("specialEntityProvider")
  void encode_whenSpecials_expectEntities(String ch, String expectedEntity) {
    // Arrange & Act
    String encoded = HTMLEncoder.encode(ch);
    // Assert
    assertEquals(expectedEntity, encoded);
  }

  @Test
  void encode_whenMixedContent_expectEncodedOnlyForNonAlnumSpecials() {
    // Arrange
    String input = "Abc©<>&'\"Z9";
    // Act
    String encoded = HTMLEncoder.encode(input);
    // Assert
    assertEquals("Abc&copy;&lt;&gt;&amp;&#39;&quot;Z9", encoded);
  }

  @Test
  void encode_whenCommaAndSpace_expectUnchanged() {
    // Arrange
    String input = ", .";
    // Act
    String encoded = HTMLEncoder.encode(input);
    // Assert
    assertEquals(input, encoded);
  }

  @Test
  void encode_whenGreekLetter_expectUnchanged() {
    // Arrange
    String alpha = "α"; // Greek small alpha: not encoded by HTMLEncoder (letter)
    // Act
    String encoded = HTMLEncoder.encode(alpha);
    // Assert
    assertEquals(alpha, encoded);
  }

  @Test
  void encode_whenNullChar_expectUnchanged() {
    // Arrange
    String input = "\u0000";
    // Act / Assert
    assertEquals(input, HTMLEncoder.encode(input));
  }

  static Stream<Arguments> specialEntityProvider() {
    return Stream.of(
        Arguments.of("<", "&lt;"),
        Arguments.of(">", "&gt;"),
        Arguments.of("&", "&amp;"),
        Arguments.of("'", "&#39;"),
        Arguments.of("\"", "&quot;"),
        Arguments.of("©", "&copy;"),
        Arguments.of("€", "&euro;"));
  }

  @Test
  void encode_allMapEntries_roundTripToExpectedEntities() {
    // Arrange / Act / Assert
    for (Map.Entry<Character, String> e : HTMLEntities.encodeMap.entrySet()) {
      char ch = e.getKey();
      String expected = "&" + e.getValue() + ";";

      // HTMLEncoder deliberately leaves letters/digits unchanged; skip those here
      if (Character.isLetterOrDigit(ch) || ch == 0) continue;

      String encoded = HTMLEncoder.encode(String.valueOf(ch));
      assertEquals(expected, encoded, () -> "Failed for char U+" + Integer.toHexString(ch));
    }
  }

  // -------- encodeToBuffer(String, StringBuilder) --------

  @Test
  void encodeToBuffer_whenAppending_expectBuilderContainsPrefixPlusEncoded() {
    // Arrange
    StringBuilder sb = new StringBuilder("prefix:");
    String input = "<a>&";
    // Act
    HTMLEncoder.encodeToBuffer(input, sb);
    // Assert
    assertEquals("prefix:&lt;a&gt;&amp;", sb.toString());
  }

  @Test
  void encodeToBuffer_whenNullInput_throwsNullPointerException() {
    // Arrange
    StringBuilder sb = new StringBuilder();
    // Act / Assert (ensure the lambda performs a single potentially throwing call)
    assertThrows(NullPointerException.class, () -> HTMLEncoder.encodeToBuffer(null, sb));
    // Also verify the builder remains untouched (consume to satisfy static analysis)
    assertEquals(0, sb.length());
  }

  @Test
  void encodeToBuffer_whenNullBuilder_throwsNullPointerException() {
    // Arrange
    String input = "<>";
    // Act / Assert
    assertThrows(NullPointerException.class, () -> HTMLEncoder.encodeToBuffer(input, null));
  }

  // -------- encodeXML(String) --------

  @Test
  void encodeXML_whenAttributeAndTextSpecials_expectNumericEntities() {
    // Arrange
    String input = "<a attr=\"x&y\" data='z'>text</a>";
    // Act
    String out = HTMLEncoder.encodeXML(input);
    // Assert
    assertEquals("&#60;a attr=&#34;x&#38;y&#34; data=&#39;z&#39;&#62;text&#60;/a&#62;", out);
  }

  @Test
  void encodeXML_whenCdataEndSequence_expectAngleBracketEncoded() {
    // Arrange
    String input = "]]>"; // literal CDATA end marker
    // Act
    String out = HTMLEncoder.encodeXML(input);
    // Assert
    assertEquals("]]&#62;", out);
  }

  @Test
  void encodeXML_whenEmpty_expectEmpty() {
    assertEquals("", HTMLEncoder.encodeXML(""));
  }

  @Test
  void encodeXML_whenNull_throwsNullPointerException() {
    assertThrows(NullPointerException.class, () -> HTMLEncoder.encodeXML(null));
  }
}
