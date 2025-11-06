package network.crypta.client.filter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class CSSReadFilterTest {

  @Mock private FilterCallback callback;

  @Test
  void getCharset_whenAsciiAtCharsetDirective_returnsDetected() throws IOException {
    // Arrange
    String css = "@charset \"UTF-8\";\nbody{color:red}";
    byte[] bytes = css.getBytes(StandardCharsets.US_ASCII);
    CSSReadFilter filter = new CSSReadFilter();

    // Act
    String detected = filter.getCharset(bytes, bytes.length, "ISO-8859-1");

    // Assert
    assertEquals("UTF-8", detected);
  }

  @Test
  void getCharset_whenUnknownReaderCharset_throwsUnknownCharsetException() {
    // Arrange
    String css = "body{color:red}";
    byte[] bytes = css.getBytes(StandardCharsets.UTF_8);
    CSSReadFilter filter = new CSSReadFilter();

    // Act + Assert
    assertThrows(
        UnknownCharsetException.class,
        () -> filter.getCharset(bytes, bytes.length, "x-unknown-charset-1234"));
  }

  @Test
  void getCharset_whenNoDirective_returnsNull() throws IOException {
    // Arrange
    String css = "h1{color:#fff}";
    byte[] bytes = css.getBytes(StandardCharsets.UTF_8);
    CSSReadFilter filter = new CSSReadFilter();

    // Act
    String detected = filter.getCharset(bytes, bytes.length, "UTF-8");

    // Assert
    assertNull(detected);
  }

  @Test
  void getCharset_whenUnsupportedDeclaredCharset_throwsUnsupportedCharsetInFilterException() {
    // Arrange: declare a clearly unsupported charset token
    String css = "@charset \"X-FAKE-CHARSET-9999\";\nh2{color:blue}";
    byte[] bytes = css.getBytes(StandardCharsets.US_ASCII);
    CSSReadFilter filter = new CSSReadFilter();

    // Act + Assert
    assertThrows(
        UnsupportedCharsetInFilterException.class,
        () -> filter.getCharset(bytes, bytes.length, "UTF-8"));
  }

  @Test
  void getCharsetBufferSize_returns64() {
    assertEquals(64, new CSSReadFilter().getCharsetBufferSize());
  }

  @Test
  void getCharsetByBOM_whenAsciiPrefix_returnsUtf8AndMustHave() throws IOException {
    // Arrange: ASCII bytes for '@charset "'
    byte[] prefix = "@charset \"".getBytes(StandardCharsets.US_ASCII);
    CSSReadFilter filter = new CSSReadFilter();

    // Act
    CharsetExtractor.BOMDetection bom = filter.getCharsetByBOM(prefix, prefix.length);

    // Assert
    assertNotNull(bom);
    assertEquals("UTF-8", bom.charset);
    assertTrue(bom.mustHaveCharset);
  }

  @Test
  void getCharsetByBOM_whenUtf16bePrefix_returnsUtf16beAndMustHave() throws IOException {
    // Arrange: UTF-16BE bytes for '@charset "'
    byte[] prefix = "@charset \"".getBytes(StandardCharsets.UTF_16BE);
    CSSReadFilter filter = new CSSReadFilter();

    // Act
    CharsetExtractor.BOMDetection bom = filter.getCharsetByBOM(prefix, prefix.length);

    // Assert
    assertNotNull(bom);
    assertEquals("UTF-16BE", bom.charset);
    assertTrue(bom.mustHaveCharset);
  }

  @Test
  void getCharsetByBOM_whenUnsupportedUtf32_2143_throwsUnsupportedCharsetInFilterException() {
    // Arrange: exact byte sequence used by the implementation for UTF-32-2143 '@charset "'
    byte[] utf32Variant2143 =
        CSSReadFilter.parse(
            "00 00 40 00 00 00 63 00 00 00 68 00 00 00 61 00 00 00 72 00 00 00 73 00 00 00 65 00 00"
                + " 00 74 00 00 00 20 00 00 00 22 00");
    CSSReadFilter filter = new CSSReadFilter();

    // Act + Assert
    assertThrows(
        UnsupportedCharsetInFilterException.class,
        () -> filter.getCharsetByBOM(utf32Variant2143, utf32Variant2143.length));
  }

  @Test
  void filterMediaList_whenMixedTokens_returnsOnlyAllowedMedia() {
    // Arrange
    String input = "screen and (color), print and (min-width:900px), nonsense, TV, tv-4k";

    // Act
    String filtered = CSSReadFilter.filterMediaList(input);

    // Assert: only lowercase known media survive; order preserved, de-duplicated by logic
    assertEquals("screen, print, tv", filtered);
  }

  @Test
  void filterMediaList_whenNoValidTokens_returnsNull() {
    // Arrange
    String input = "unknown, invalid, SCREEN";

    // Act
    String filtered = CSSReadFilter.filterMediaList(input);

    // Assert
    assertNull(filtered);
  }

  @Test
  void readFilter_whenImportAndMedia_writesSanitizedImportAndCallsCallback() throws Exception {
    // Arrange
    String css =
        "@import url(\"http://example.org/a.css\") screen and (color), print;\nbody{color:#111;}";
    when(callback.processURI("http://example.org/a.css", "text/css"))
        .thenReturn("http://example.org/a.css?sanitized=true");

    ByteArrayInputStream in = new ByteArrayInputStream(css.getBytes(StandardCharsets.UTF_8));
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    CSSReadFilter filter = new CSSReadFilter();

    // Act
    filter.readFilter(in, out, "UTF-8", null, null, callback);
    String result = out.toString(StandardCharsets.UTF_8);

    // Assert: callback invoked and output contains sanitized URI with maybecharset and media list
    verify(callback, times(1)).processURI("http://example.org/a.css", "text/css");
    assertTrue(
        result.contains(
            "@import url(\"http://example.org/a.css?sanitized=true&maybecharset=UTF-8\")"),
        () -> "output=\n" + result);
    assertTrue(result.contains("screen"));
    assertTrue(result.contains("print"));
  }

  // No helpers
}
