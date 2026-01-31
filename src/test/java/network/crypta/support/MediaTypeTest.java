package network.crypta.support;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.MalformedURLException;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/** Tests for {@link MediaType}. */
@SuppressWarnings("java:S100") // Allow method names like method_whenCondition_expectOutcome
class MediaTypeTest {

  private static final String MIME_TEXT_HTML = "text/html";
  private static final String PARAM_CHARSET = "charset";
  private static final String CHARSET_UTF8 = "utf-8";
  private static final String CHARSET_UTF8_UPPER = "UTF-8";
  private static final String MIME_TEXT_HTML_CHARSET_UTF8 =
      MIME_TEXT_HTML + "; " + PARAM_CHARSET + "=" + CHARSET_UTF8;

  @Test
  @DisplayName("parse constructor: simple type/subtype without parameters")
  void constructor_whenSimpleType_expectParsedCorrectly() throws Exception {
    // Arrange & Act
    MediaType mt = new MediaType(MIME_TEXT_HTML);

    // Assert
    assertEquals("text", mt.getType());
    assertEquals("html", mt.getSubtype());
    assertEquals(MIME_TEXT_HTML, mt.getPlainType());
    assertEquals(MIME_TEXT_HTML, mt.toString());
    assertNull(mt.getParameter(PARAM_CHARSET));
  }

  @Test
  @DisplayName("parse constructor: parameters with whitespace and quotes are normalized")
  void constructor_whenParamsWithWhitespaceAndQuotes_expectNormalized() throws Exception {
    // Arrange
    String input =
        MIME_TEXT_HTML
            + "; "
            + PARAM_CHARSET
            + "="
            + CHARSET_UTF8
            + "; foo=\"bar baz\" ; QuUx = \" spaced \"";

    // Act
    MediaType mt = new MediaType(input);

    // Assert
    assertEquals(CHARSET_UTF8, mt.getParameter(PARAM_CHARSET));
    assertEquals("bar baz", mt.getParameter("foo"));
    assertEquals("spaced", mt.getParameter("quux"));
    assertEquals(
        MIME_TEXT_HTML
            + "; "
            + PARAM_CHARSET
            + "=\""
            + CHARSET_UTF8
            + "\"; foo=\"bar baz\"; quux=\"spaced\"",
        mt.toString());
  }

  @Test
  @DisplayName("parse constructor: trailing semicolon after params is ignored")
  void constructor_whenTrailingSemicolon_expectParsedCorrectly() throws Exception {
    // Arrange
    String input = MIME_TEXT_HTML + "; " + PARAM_CHARSET + "=" + CHARSET_UTF8 + ";";

    // Act
    MediaType mt = new MediaType(input);

    // Assert
    assertEquals(CHARSET_UTF8, mt.getParameter(PARAM_CHARSET));
    assertEquals(
        MIME_TEXT_HTML + "; " + PARAM_CHARSET + "=\"" + CHARSET_UTF8 + "\"", mt.toString());
  }

  @Test
  @SuppressWarnings("ConstantValue")
  @DisplayName("parse constructor: null input throws NPE with message")
  void constructor_whenNull_expectNullPointerException() {
    // Arrange
    String input = null;

    // Act + Assert
    NullPointerException ex = assertThrows(NullPointerException.class, () -> new MediaType(input));
    assertEquals("contentType must not be null", ex.getMessage());
  }

  @Test
  @DisplayName("parse constructor: missing slash throws MalformedURLException")
  void constructor_whenNoSlash_expectMalformedURLException() {
    // Arrange
    String input = "texthtml";

    // Act + Assert
    MalformedURLException ex =
        assertThrows(MalformedURLException.class, () -> new MediaType(input));
    assertEquals("Doesn't look like a MIME type", ex.getMessage());
  }

  @Test
  @DisplayName("parse constructor: parameter without equals throws MalformedURLException")
  void constructor_whenParamWithoutEquals_expectMalformedURLException() {
    // Arrange
    // This matches DefaultMIMETypes' legacy compatibility pattern and reaches the equals-check.
    String input = "application/mercurial-bundle;123";

    // Act + Assert
    MalformedURLException ex =
        assertThrows(MalformedURLException.class, () -> new MediaType(input));
    // Message includes the illegal parameter string that lacked '='
    assertEquals("Illegal parameter: “123”", ex.getMessage());
  }

  @Test
  @DisplayName("varargs constructor: even number of parameters accepted and ordered")
  void varargsConstructor_whenEvenParamCount_expectAccepted() {
    // Arrange + Act
    MediaType mt = new MediaType("text", "html", PARAM_CHARSET, CHARSET_UTF8, "q", "1");

    // Assert
    assertEquals("text", mt.getType());
    assertEquals("html", mt.getSubtype());
    assertEquals(CHARSET_UTF8, mt.getParameter(PARAM_CHARSET));
    assertEquals(
        MIME_TEXT_HTML + "; " + PARAM_CHARSET + "=\"" + CHARSET_UTF8 + "\"; q=\"1\"",
        mt.toString());
  }

  @Test
  @DisplayName("varargs constructor: odd number of parameters throws IAE")
  void varargsConstructor_whenOddParamCount_expectIllegalArgumentException() {
    // Arrange + Act + Assert
    assertThrows(
        IllegalArgumentException.class,
        () -> new MediaType("text", "html", PARAM_CHARSET, CHARSET_UTF8, "lonelyKey"));
  }

  @Test
  @DisplayName(
      "map constructor: copies parameters and preserves insertion order while skipping null")
  void mapConstructor_whenGivenMap_expectCopiedAndOrderedAndSkipsNull() {
    // Arrange
    LinkedHashMap<String, String> params = new LinkedHashMap<>();
    params.put("q", "0.8");
    params.put("foo", null); // should be skipped in toString()
    params.put(PARAM_CHARSET, CHARSET_UTF8);

    // Act
    MediaType mt = new MediaType("text", "html", params);

    // Mutate the original map to verify defensive copy
    params.put("another", "x");

    // Assert
    assertEquals("0.8", mt.getParameter("q"));
    assertEquals(CHARSET_UTF8, mt.getParameter(PARAM_CHARSET));
    assertNull(mt.getParameter("foo"));
    assertEquals(
        MIME_TEXT_HTML + "; q=\"0.8\"; " + PARAM_CHARSET + "=\"" + CHARSET_UTF8 + "\"",
        mt.toString());
  }

  @Test
  @DisplayName("getParameters returns a copy not backed by internal map")
  void getParameters_whenMutated_expectOriginalUnaffected() throws Exception {
    // Arrange
    MediaType mt = new MediaType(MIME_TEXT_HTML_CHARSET_UTF8 + "; q=0.9");

    // Act
    Map<String, String> copy = mt.getParameters();
    copy.put("newparam", "value");

    // Assert
    assertNull(mt.getParameter("newparam"));
    assertEquals(
        MIME_TEXT_HTML + "; " + PARAM_CHARSET + "=\"" + CHARSET_UTF8 + "\"; q=\"0.9\"",
        mt.toString());
  }

  @Test
  @DisplayName("setType returns new instance with updated type and preserves others")
  void setType_whenCalled_expectNewWithChangedType() throws Exception {
    // Arrange
    MediaType original = new MediaType(MIME_TEXT_HTML_CHARSET_UTF8);

    // Act
    MediaType changed = original.setType("application");

    // Assert
    assertNotSame(original, changed);
    assertEquals("text", original.getType());
    assertEquals("application", changed.getType());
    assertEquals("html", changed.getSubtype());
    assertEquals(CHARSET_UTF8, changed.getParameter(PARAM_CHARSET));
  }

  @Test
  @DisplayName("setSubtype returns new instance with updated subtype and preserves others")
  void setSubtype_whenCalled_expectNewWithChangedSubtype() throws Exception {
    // Arrange
    MediaType original = new MediaType(MIME_TEXT_HTML_CHARSET_UTF8);

    // Act
    MediaType changed = original.setSubtype("plain");

    // Assert
    assertNotSame(original, changed);
    assertEquals("html", original.getSubtype());
    assertEquals("plain", changed.getSubtype());
    assertEquals("text", changed.getType());
    assertEquals(CHARSET_UTF8, changed.getParameter(PARAM_CHARSET));
  }

  @Test
  @DisplayName(
      "setParameter with non-null value updates or adds parameter (normalized to lowercase)")
  void setParameter_whenNonNull_expectUpdatedAndNormalized() throws Exception {
    // Arrange
    MediaType original = new MediaType(MIME_TEXT_HTML_CHARSET_UTF8);

    // Act
    MediaType changed = original.setParameter("Charset", "latin-1");

    // Assert
    assertNotSame(original, changed);
    assertEquals(CHARSET_UTF8, original.getParameter(PARAM_CHARSET));
    assertEquals("latin-1", changed.getParameter(PARAM_CHARSET));
    assertEquals(MIME_TEXT_HTML + "; " + PARAM_CHARSET + "=\"latin-1\"", changed.toString());
  }

  @Test
  @DisplayName("setParameter with null value removes parameter")
  void setParameter_whenNull_expectRemoval() throws Exception {
    // Arrange
    MediaType original =
        new MediaType(MIME_TEXT_HTML + "; q=0.5; " + PARAM_CHARSET + "=" + CHARSET_UTF8);

    // Act
    MediaType changed = original.setParameter("q", null);

    // Assert
    assertNotSame(original, changed);
    assertNull(changed.getParameter("q"));
    assertEquals(
        MIME_TEXT_HTML + "; " + PARAM_CHARSET + "=\"" + CHARSET_UTF8 + "\"", changed.toString());
  }

  @Test
  @DisplayName("removeParameter for missing key returns same instance; for existing returns new")
  void removeParameter_whenMissingOrPresent_expectSameOrNew() throws Exception {
    // Arrange
    MediaType withoutParams = new MediaType(MIME_TEXT_HTML);
    MediaType withCharset = new MediaType(MIME_TEXT_HTML_CHARSET_UTF8);

    // Act
    MediaType same = withoutParams.removeParameter(PARAM_CHARSET);
    MediaType removed = withCharset.removeParameter("Charset"); // case-insensitive by normalization

    // Assert
    assertSame(withoutParams, same);
    assertNotSame(withCharset, removed);
    assertEquals(MIME_TEXT_HTML, removed.toString());
  }

  @ParameterizedTest
  @CsvSource({
    "invalid, UTF-8", // invalid MIME → default
    MIME_TEXT_HTML + ", UTF-8" // valid MIME without charset → default
  })
  @DisplayName("getCharsetRobustOrUTF returns UTF-8 when charset is missing or input invalid")
  void getCharsetRobustOrUTF_whenMissingOrInvalid_expectUTF8(String input, String expected) {
    // Arrange + Act
    String result = MediaType.getCharsetRobustOrUTF(input);

    // Assert
    assertEquals(expected, result);
  }

  @Test
  @DisplayName("getCharsetRobustOrUTF returns UTF-8 for null input")
  void getCharsetRobustOrUTF_whenNull_expectUTF8() {
    // Arrange + Act
    String result = MediaType.getCharsetRobustOrUTF(null);

    // Assert
    assertEquals(CHARSET_UTF8_UPPER, result);
  }

  @Test
  @DisplayName("getCharsetRobust returns charset value when present (any case in input)")
  void getCharsetRobust_whenValidWithCharset_expectValue() {
    // Arrange
    String input = "Text/Html; Charset=\"" + CHARSET_UTF8_UPPER + "\"";

    // Act
    String charset = MediaType.getCharsetRobust(input);

    // Assert
    assertEquals(CHARSET_UTF8_UPPER, charset);
  }
}
