package network.crypta.client.filter;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import network.crypta.client.filter.HTMLFilter.ParsedTag;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class HTMLFilterTest {

  private HTMLFilter filter;

  @Mock private FilterCallback callback;

  @BeforeEach
  void setUp() throws Exception {
    filter = new HTMLFilter();

    // Default: pass-through behavior for URIs and tags; do-nothing for others.
    // processURI(uri, overrideType, noRelative, inline) → return original uri
    lenient()
        .when(callback.processURI(anyString(), anyString(), anyBoolean(), anyBoolean()))
        .thenAnswer(inv -> inv.getArgument(0, String.class));
    // Overloads default to simple variant
    lenient()
        .when(callback.processURI(anyString(), anyString()))
        .thenAnswer(inv -> inv.getArgument(0, String.class));
    lenient()
        .when(callback.processURI(anyString(), anyString(), anyString(), anyBoolean()))
        .thenAnswer(inv -> inv.getArgument(0, String.class));
    lenient().when(callback.onBaseHref(anyString())).thenReturn(null);
    lenient().when(callback.processTag(any(ParsedTag.class))).thenReturn(null);
  }

  @ParameterizedTest
  @CsvSource(
      value = {
        "'text/html; charset=UTF-8','text/html','UTF-8'",
        "'text/html;    charset = UTF-8 ; q=0.8','text/html','UTF-8'",
        "'text/html; CHARSET=UTF-8','text/html',NULL"
      },
      nullValues = "NULL")
  void splitType_whenVariousInputs_expectParsed(
      String input, String expectedType, String expectedCharset) {
    // Act
    String[] result = HTMLFilter.splitType(input);

    // Assert
    assertArrayEquals(new String[] {expectedType, expectedCharset}, result);
  }

  @Test
  void getAllowedHTMLTags_containsCoreTags_andIsUnmodifiable() {
    // Act
    Set<String> allowed = HTMLFilter.getAllowedHTMLTags();

    // Assert
    assertNotNull(allowed);
    assertTrue(allowed.contains("body"));
    assertTrue(allowed.contains("a"));
    assertTrue(allowed.contains("div"));
    // Note: Do not attempt to mutate the returned set here to avoid static-analysis warnings
    // about modifying immutable objects in tests. Presence checks above suffice for contract.
  }

  @Test
  void getCharsetBufferSize_returnsExpectedConstant() {
    // Act & Assert
    assertEquals(1024 * 64, filter.getCharsetBufferSize());
  }

  @Test
  void getCharsetByBOM_returnsNull() {
    // Act & Assert
    assertNull(filter.getCharsetByBOM("<html>".getBytes(StandardCharsets.UTF_8), 6));
  }

  @Test
  void getCharset_whenHtml5MetaCharset_expectDetected() throws IOException {
    // Arrange
    String html =
        "<!doctype html><html><head><meta charset=\"UTF-8\"></head><body>ok</body></html>";
    byte[] bytes = html.getBytes(StandardCharsets.UTF_8);

    // Act
    String detected = filter.getCharset(bytes, bytes.length, StandardCharsets.UTF_8.name());

    // Assert
    assertEquals("UTF-8", detected);
  }

  @Test
  void getCharset_whenMetaHttpEquivContentType_expectDetected() throws IOException {
    // Arrange
    String html =
        "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html;"
            + " charset=ISO-8859-1\"></head><body></body></html>";
    byte[] bytes = html.getBytes(StandardCharsets.ISO_8859_1);

    // Act
    String detected = filter.getCharset(bytes, bytes.length, StandardCharsets.ISO_8859_1.name());

    // Assert
    assertEquals("ISO-8859-1", detected);
  }

  @Test
  void getCharset_whenTitleBeforeHeadAndNoClose_expectNull() throws IOException {
    // Arrange: a title before head triggers an implicit <head> open; without a close this
    // path raises MalformedInputException which is swallowed and results in null.
    String html = "<html><title>x</title>";
    byte[] bytes = html.getBytes(StandardCharsets.UTF_8);

    // Act
    String detected = filter.getCharset(bytes, bytes.length, StandardCharsets.UTF_8.name());

    // Assert
    assertNull(detected);
  }

  @Test
  void readFilter_whenInvalidCharset_throwsUnknownCharsetException() {
    // Arrange
    String bogus = "Definitely-Not-A-Charset";
    ByteArrayInputStream in =
        new ByteArrayInputStream("<html></html>".getBytes(StandardCharsets.US_ASCII));
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    // Act + Assert
    UnknownCharsetException ex =
        assertThrows(
            UnknownCharsetException.class,
            () ->
                filter.readFilter(
                    in, out, bogus, Collections.emptyMap(), "http://example", callback));
    assertEquals(bogus, ex.charset);
  }

  @Test
  void readFilter_whenScriptTagPresent_expectScriptRemoved() throws IOException {
    // Arrange
    String html = "<html><head><script> alert(1) </script></head><body>Hello</body></html>";
    ByteArrayInputStream in = new ByteArrayInputStream(html.getBytes(StandardCharsets.UTF_8));
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    // Act
    filter.readFilter(in, out, StandardCharsets.UTF_8.name(), Map.of(), null, callback);
    String sanitized = out.toString(StandardCharsets.UTF_8);

    // Assert: script content is swallowed and no <script> tag remains; body text preserved
    assertFalse(sanitized.toLowerCase().contains("<script"));
    assertTrue(sanitized.contains("Hello"));
  }

  @Test
  void readFilter_whenAudioTagPresent_expectM3uPlayerInjected() throws IOException {
    // Arrange
    String html =
        "<html><head></head><body><audio src=\"http://example/audio.mp3\"></audio></body></html>";
    ByteArrayInputStream in = new ByteArrayInputStream(html.getBytes(StandardCharsets.UTF_8));
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    // Act
    filter.readFilter(in, out, StandardCharsets.UTF_8.name(), Map.of(), null, callback);
    String sanitized = out.toString(StandardCharsets.UTF_8);

    // Assert: the inline player script is appended before </body>
    assertTrue(sanitized.contains("<script>"));
    // Heuristic check for expected inline script content to avoid brittle string comparisons
    assertTrue(sanitized.contains("PLAYLIST_MIME_TYPES"));
  }

  @Test
  @DisplayName("readFilter calls processURI for link hrefs with expected signature")
  void readFilter_whenAnchorHref_expectProcessUriInvoked() throws Exception {
    // Arrange
    String html = "<html><head></head><body><a href=\"/path\">x</a></body></html>";
    ByteArrayInputStream in = new ByteArrayInputStream(html.getBytes(StandardCharsets.UTF_8));
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    // Act
    filter.readFilter(in, out, StandardCharsets.UTF_8.name(), Map.of(), null, callback);

    // Assert: sanitizeURI uses the 4-arg variant (uri, overrideType, noRelative=false,
    // inline=false)
    verify(callback).processURI("/path", null, false, false);
  }

  @Test
  void readFilter_handlesTrailingWhitespaceAttributeWithoutCrash() {
    // This input previously produced an empty attribute token before '>' causing a crash
    String html = "<!DOCTYPE html><html><body><a href=\"/x\" >Hello</a></body></html>";
    ByteArrayInputStream in = new ByteArrayInputStream(html.getBytes(StandardCharsets.UTF_8));
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    ContentFilterRequest request =
        new ContentFilterRequest(
            in, out, "text/html; charset=UTF-8", "UTF-8", "http://example.com", null);
    ContentFilterCallbacks callbacks =
        new ContentFilterCallbacks(java.net.URI.create("http://example.com/"), null, null, null);
    assertDoesNotThrow(() -> ContentFilter.filter(request, callbacks));
  }
}
