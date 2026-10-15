package network.crypta.client.filter;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;
import network.crypta.support.http.ExternalLinkSupport;
import network.crypta.support.io.ArrayBucket;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class M3UFilterTest {
  private static final String[][] TEST_PLAYLISTS = {
    {"./m3u/safe.m3u", "./m3u/safe_madesafe.m3u"},
    {"./m3u/unsafe.m3u", "./m3u/unsafe_madesafe.m3u"}
  };

  private static final String SCHEME_HOST_PORT = "http://localhost:8888";
  private static final String BASE_KEY =
      "USK@0I8gctpUE32CM0iQhXaYpCMvtPPGfT4pjXm01oid5Zc,3dAcn4fX2LyxO6uCnWFTx-2HKZ89uruurcKwLSCxbZ4,AQACAAE/FakeM3UHostingFreesite/23/";
  private static final String BASE_URI = '/' + BASE_KEY;
  private static final long MAX_LENGTH_NO_PROGRESS = (200L * 1024 * 1024 * 11) / 10;

  @Test
  void readFilter_whenUsingResourcePlaylists_matchesGoldenFiles() {
    M3UFilter filter = new M3UFilter();

    for (String[] playlist : TEST_PLAYLISTS) {
      String original = playlist[0];
      String expected = playlist[1];

      assertDoesNotThrow(
          () -> {
            try (ArrayBucket source = ResourceFileUtil.resourceToBucket(original);
                ArrayBucket processed = new ArrayBucket();
                ArrayBucket expectedBucket = ResourceFileUtil.resourceToBucket(expected)) {
              filter.readFilter(
                  source.getInputStream(),
                  processed.getOutputStream(),
                  StandardCharsets.UTF_8.name(),
                  Map.of(),
                  SCHEME_HOST_PORT,
                  new GenericReadFilterCallback(
                      new ContentFilterCallbacks(new URI(BASE_URI), null, null, null)));

              String result = normalizeEol(processed.toString());
              assertEquals(
                  bucketToString(expectedBucket),
                  result,
                  original
                      + " should be filtered as "
                      + expected
                      + " but was filtered as\n"
                      + result);
            }
          },
          () -> "Filtering " + original + " failed");
    }
  }

  @Test
  void readFilter_whenPlaylistHasComments_skipsCommentLinesAndAppendsMaxSize() throws Exception {
    FilterCallback callback = mock(FilterCallback.class);
    when(callback.processURI("song.mp3", "audio/mpeg", SCHEME_HOST_PORT, true))
        .thenReturn("http://filtered/song.mp3");

    String result = runFilter("#EXTM3U\r\nsong.mp3\r\n", callback);

    assertEquals("http://filtered/song.mp3?max-size=" + MAX_LENGTH_NO_PROGRESS + "\n", result);
    verify(callback, times(1)).processURI("song.mp3", "audio/mpeg", SCHEME_HOST_PORT, true);
  }

  @Test
  void readFilter_whenSanitizedUriContainsQuery_appendsMaxSizeWithAmpersand() throws Exception {
    FilterCallback callback = mock(FilterCallback.class);
    when(callback.processURI("track.ogg?foo=1", "application/ogg", SCHEME_HOST_PORT, true))
        .thenReturn("http://filtered/track.ogg?foo=1");

    String result = runFilter("track.ogg?foo=1\n", callback);

    assertEquals(
        "http://filtered/track.ogg?foo=1&max-size=" + MAX_LENGTH_NO_PROGRESS + "\n", result);
    verify(callback).processURI("track.ogg?foo=1", "application/ogg", SCHEME_HOST_PORT, true);
  }

  @Test
  void readFilter_whenSanitizedUriIsExternalLink_doesNotAppendMaxSize() throws Exception {
    FilterCallback callback = mock(FilterCallback.class);
    when(callback.processURI("song.mp3", "audio/mpeg", SCHEME_HOST_PORT, true))
        .thenReturn(ExternalLinkSupport.EXTERNAL_LINK_PATH + "?target=example");

    String result = runFilter("song.mp3\n", callback);

    assertEquals(ExternalLinkSupport.EXTERNAL_LINK_PATH + "?target=example\n", result);
  }

  @Test
  void readFilter_whenSanitizedUriContainsMagicEscape_doesNotAppendMaxSize() throws Exception {
    FilterCallback callback = mock(FilterCallback.class);
    when(callback.processURI("second.mp3", "audio/mpeg", SCHEME_HOST_PORT, true))
        .thenReturn(
            "http://filtered/" + ExternalLinkSupport.MAGIC_HTTP_ESCAPE_STRING + "/second.mp3");

    String result = runFilter("second.mp3\n", callback);

    assertEquals(
        "http://filtered/" + ExternalLinkSupport.MAGIC_HTTP_ESCAPE_STRING + "/second.mp3\n",
        result);
  }

  @Test
  void readFilter_whenCallbackThrowsCommentException_writesPlaceholder() throws Exception {
    FilterCallback callback = mock(FilterCallback.class);
    when(callback.processURI("broken.flac", "audio/flac", SCHEME_HOST_PORT, true))
        .thenThrow(new CommentException("bad"));

    String result = runFilter("broken.flac\n", callback);

    assertEquals(M3UFilter.BAD_URI_REPLACEMENT + "\n", result);
  }

  @Test
  void readFilter_whenCallbackReturnsNull_writesPlaceholder() throws Exception {
    FilterCallback callback = mock(FilterCallback.class);
    when(callback.processURI("missing.wav", "audio/vnd.wave", SCHEME_HOST_PORT, true))
        .thenReturn(null);

    String result = runFilter("missing.wav\n", callback);

    assertEquals(M3UFilter.BAD_URI_REPLACEMENT + "\n", result);
  }

  @Test
  void readFilter_whenBulkReadReturnsZero_doesNotInventAnInputByte() throws Exception {
    FilterCallback callback = mock(FilterCallback.class);
    when(callback.processURI("song.mp3", "audio/mpeg", SCHEME_HOST_PORT, true))
        .thenReturn("http://filtered/song.mp3");
    InputStream input =
        new InputStream() {
          private final ByteArrayInputStream delegate =
              new ByteArrayInputStream("song.mp3\r\n".getBytes(StandardCharsets.UTF_8));
          private boolean firstBulkRead = true;

          @Override
          public int read() {
            return delegate.read();
          }

          @Override
          public int read(byte @NotNull [] bytes, int offset, int length) {
            if (firstBulkRead && length > 0) {
              firstBulkRead = false;
              return 0;
            }
            return delegate.read(bytes, offset, length);
          }
        };

    String result = runFilter(input, callback);

    assertEquals("http://filtered/song.mp3?max-size=" + MAX_LENGTH_NO_PROGRESS + "\n", result);
    verify(callback).processURI("song.mp3", "audio/mpeg", SCHEME_HOST_PORT, true);
  }

  @Test
  void readFilter_whenPlaylistEndsWithoutNewline_preservesUnterminatedLine() throws Exception {
    FilterCallback callback = mock(FilterCallback.class);
    when(callback.processURI("song.mp3", "audio/mpeg", SCHEME_HOST_PORT, true))
        .thenReturn("http://filtered/song.mp3");

    String result = runFilter("song.mp3", callback);

    assertEquals("http://filtered/song.mp3?max-size=" + MAX_LENGTH_NO_PROGRESS, result);
  }

  @Test
  void readFilter_whenByteIsUnsignedFf_decodesInputRatherThanTreatingItAsEof() throws Exception {
    FilterCallback callback = mock(FilterCallback.class);
    when(callback.processURI("\uFFFD.mp3", "audio/mpeg", SCHEME_HOST_PORT, true))
        .thenReturn("http://filtered/song.mp3");
    InputStream input =
        new ByteArrayInputStream(new byte[] {(byte) 0xff, '.', 'm', 'p', '3', '\n'});

    String result = runFilter(input, callback);

    assertEquals("http://filtered/song.mp3?max-size=" + MAX_LENGTH_NO_PROGRESS + "\n", result);
    verify(callback).processURI("\uFFFD.mp3", "audio/mpeg", SCHEME_HOST_PORT, true);
  }

  @Test
  void readFilter_whenLineIsAtMaximumByteLength_filtersTheCompleteLine() throws Exception {
    String uri = "x".repeat(M3UFilter.MAX_URI_LENGTH - ".mp3".length()) + ".mp3";
    FilterCallback callback = mock(FilterCallback.class);
    when(callback.processURI(uri, "audio/mpeg", SCHEME_HOST_PORT, true))
        .thenReturn("http://filtered/song.mp3");

    String result = runFilter(uri + "\r\n", callback);

    assertEquals("http://filtered/song.mp3?max-size=" + MAX_LENGTH_NO_PROGRESS + "\n", result);
    verify(callback).processURI(uri, "audio/mpeg", SCHEME_HOST_PORT, true);
  }

  @Test
  void readFilter_whenLineExceedsMaximumByteLength_discardsRemainderBeforeNextLine()
      throws Exception {
    FilterCallback callback = mock(FilterCallback.class);
    when(callback.processURI("song.mp3", "audio/mpeg", SCHEME_HOST_PORT, true))
        .thenReturn("http://filtered/song.mp3");
    String playlist = "x".repeat(M3UFilter.MAX_URI_LENGTH + 32) + "\r\nsong.mp3\r\n";

    String result = runFilter(playlist, callback);

    assertEquals("http://filtered/song.mp3?max-size=" + MAX_LENGTH_NO_PROGRESS + "\n", result);
    verify(callback).processURI("song.mp3", "audio/mpeg", SCHEME_HOST_PORT, true);
  }

  @Test
  void readFilter_whenInputIsEmpty_returnsEmptyOutputWithoutCallingCallback() throws Exception {
    FilterCallback callback = mock(FilterCallback.class);

    String result = runFilter("", callback);

    assertEquals("", result);
    verifyNoInteractions(callback);
  }

  private static String runFilter(String playlist, FilterCallback callback) throws IOException {
    return runFilter(new ByteArrayInputStream(playlist.getBytes(StandardCharsets.UTF_8)), callback);
  }

  private static String runFilter(InputStream input, FilterCallback callback) throws IOException {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    new M3UFilter()
        .readFilter(
            input,
            output,
            StandardCharsets.UTF_8.name(),
            Collections.emptyMap(),
            SCHEME_HOST_PORT,
            callback);
    return output.toString(StandardCharsets.UTF_8);
  }

  private static String bucketToString(ArrayBucket bucket) throws IOException {
    return normalizeEol(new String(bucket.toByteArray(), StandardCharsets.UTF_8));
  }

  private static String normalizeEol(String s) {
    return s.replace("\r\n", "\n");
  }
}
