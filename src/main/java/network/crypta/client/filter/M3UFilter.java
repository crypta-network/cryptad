package network.crypta.client.filter;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import network.crypta.clients.http.ExternalLinkToadlet;

/**
 * Content filter for M3U playlists.
 *
 * <p>This filter reads M3U/M3U8-like plaintext playlists line-by-line, removes comment and empty
 * lines, rejects excessively long entries, and rewrites each remaining entry through the {@link
 * ContentDataFilter} pipeline to ensure it is safe to fetch via the node. The goal is to prevent a
 * playlist from causing unsafe requests while keeping typical relative or absolute media URLs
 * functional. Historically this filter has been conservative: it favors dropping ambiguous or
 * malformed lines over passing them through unchanged. As a result, some real-world playlists may
 * require normalization upstream before they are accepted here.
 *
 * <p>Usage is straightforward: the filter accepts an input stream containing the playlist and
 * writes a sanitized version to the output stream. Callers should expect that comment lines (those
 * starting with {@code #}) are omitted entirely and that any item exceeding the internal maximum
 * byte length is replaced by a marker entry. Each surviving URI is handed to the callback for
 * validation and optional rewriting; failures are replaced with a stable placeholder so the overall
 * structure of the playlist remains readable to clients.
 *
 * <p>Extended M3U directives appear as comments and are therefore preserved only when carried in a
 * URI line; dedicated directive/comment lines are intentionally removed. The canonical extended
 * header is {@code #EXTM3U}. A typical entry line that accompanies metadata looks like {@code
 * #EXTINF:233,Title 1} followed by a path, for example {@code Somewhere\\title1.mp3}. In prose the
 * rule is often described as: {@code #EXTINF:&lt;length in seconds&gt;,&lt;title&gt;} followed by
 * {@code &lt;path&gt;}.
 *
 * <ul>
 *   <li>Comments beginning with {@code #} are dropped.
 *   <li>Overly long items (in UTF-8 bytes) are dropped or replaced.
 *   <li>Each URI is resolved through the filtering callback and may be rewritten.
 * </ul>
 *
 * @see ContentDataFilter
 */
public class M3UFilter implements ContentDataFilter {

  static final byte[] CHAR_NEWLINE = {(byte) '\n'};
  static final int MAX_URI_LENGTH = 16384;
  static final String BAD_URI_REPLACEMENT = "#bad-uri-removed";

  // pass-through for most files accessed via a playlist, likely through an external
  // palyer. See FProxyToadlet.MAX_LENGTH_NO_PROGRESS for the default. This value must
  // be synchronized with the test data!

  // Future: Add parsing of ext-comments to allow for gapless playback.

  /**
   * Reads a plaintext M3U playlist from {@code input}, filters and validates each entry, and writes
   * the sanitized result to {@code output}.
   *
   * <p>The method removes blank lines and comment lines (those starting with {@code #}) and
   * discards items whose UTF-8 encoded length exceeds an internal limit. For each remaining line
   * the URI is handed to the supplied callback to determine the appropriate sub-mime-type and to
   * rewrite the request into a safe, node-internal form. When rewriting fails or yields a null
   * result, a stable placeholder entry is emitted instead so that clients can continue parsing the
   * playlist. If the original line was terminated with a newline, the same termination is preserved
   * in the output.
   *
   * <p>Callers are responsible for providing streams with the desired lifecycle. This method does
   * not change the character set of the incoming data; it interprets bytes as UTF-8 only when
   * computing length limits and when emitting rewritten items. The behavior is idempotent with
   * respect to comments and overlong entries: repeated passes drop the same lines.
   *
   * @param input the source stream containing the playlist text; must be positioned at the start of
   *     the content and remain readable until end-of-stream; never {@code null}.
   * @param output the destination stream to receive the filtered playlist; data is written as UTF-8
   *     bytes and flushed; never {@code null}.
   * @param charset the declared character set of the source content; accepted but not used for
   *     parsing because validation operates on raw bytes and UTF-8 encoding for size checks; may be
   *     {@code null}.
   * @param otherParams additional, implementation-specific parameters supplied by the caller;
   *     values are not interpreted by this filter; may be empty but not {@code null}.
   * @param schemeHostAndPort the scheme/authority of the currently served request, for example
   *     {@code http://localhost:8888}; forwarded to the callback to assist in URI rewriting; must
   *     be non-null when rewriting requires absolute context.
   * @param cb the filtering callback invoked for each URI to determine a safe representation and
   *     appropriate mime type; must not be {@code null} and should be resilient to invalid input.
   * @throws IOException if an I/O error occurs while reading from {@code input} or writing to
   *     {@code output}; callers should assume partial output may have been produced.
   */
  @Override
  public void readFilter(
      InputStream input,
      OutputStream output,
      String charset,
      Map<String, String> otherParams,
      String schemeHostAndPort,
      FilterCallback cb)
      throws IOException {
    DataInputStream dis = new DataInputStream(input);
    DataOutputStream dos = new DataOutputStream(output);

    Line line;
    while ((line = readNextLine(dis)) != null) {
      if (line.text.isEmpty() || isCommentLine(line.text) || exceedsMaxLength(line.text)) {
        // Drop empty, comment, or overly long lines entirely (including newline)
        continue;
      }

      String filtered = filterUri(line.text, schemeHostAndPort, cb);

      try {
        dos.write(filtered.getBytes(StandardCharsets.UTF_8));
      } catch (Exception e) {
        dos.write(BAD_URI_REPLACEMENT.getBytes(StandardCharsets.UTF_8));
      }

      if (line.terminated) {
        dos.write(CHAR_NEWLINE);
      }
    }

    dos.flush();
    dos.close();
    output.flush();
  }

  private static boolean isCommentLine(String s) {
    return !s.isEmpty() && s.charAt(0) == '#';
  }

  private static boolean exceedsMaxLength(String s) {
    return s.getBytes(StandardCharsets.UTF_8).length > MAX_URI_LENGTH;
  }

  private static String filterUri(String uri, String schemeHostAndPort, FilterCallback cb) {
    String filtered;
    try {
      String subMimetype = ContentFilter.mimeTypeForSrc(uri);
      filtered = cb.processURI(uri, subMimetype, schemeHostAndPort, true);

      if (filtered != null
          && !filtered.contains(ExternalLinkToadlet.PATH)
          && !filtered.contains(ExternalLinkToadlet.magicHTTPEscapeString)) {
        filtered += (filtered.contains("?") ? "&" : "?");
        long maxLengthNoProgress = (200L * 1024 * 1024 * 11) / 10;
        filtered += "max-size=" + maxLengthNoProgress;
      }
    } catch (Exception e) {
      filtered = BAD_URI_REPLACEMENT;
    }

    if (filtered == null) {
      filtered = BAD_URI_REPLACEMENT;
    }
    return filtered;
  }

  private record Line(String text, boolean terminated) {}

  private static Line readNextLine(DataInputStream dis) throws IOException {
    byte[] one = new byte[1];
    boolean sawAny = false;
    boolean terminated = false;
    // Using a byte buffer to avoid incorrect char length accounting
    byte[] buf = new byte[MAX_URI_LENGTH + 1];
    int idx = 0;

    while (dis.read(one) != -1) {
      sawAny = true;
      byte b = one[0];
      if (b == '\n') {
        terminated = true;
        break;
      }
      if (b != '\r' && idx < buf.length) {
        buf[idx++] = b;
      }
    }

    if (!sawAny) {
      return null;
    }
    String text = new String(buf, 0, idx, StandardCharsets.UTF_8);
    return new Line(text, terminated);
  }
}
