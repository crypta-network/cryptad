package network.crypta.client.filter;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.util.Map;
import network.crypta.support.HexUtil;
import network.crypta.support.io.NullWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Filters and sanitizes Cascading Style Sheets (CSS) while extracting charset information.
 *
 * <p>This reader-side filter parses a CSS stream, normalizes or discards constructs that are not
 * allowed by the project’s safety policy, and writes a sanitized representation to a supplied
 * output. It also implements {@link CharsetExtractor} to detect the character encoding used by a
 * stylesheet based on a small prefix, explicit {@code @charset} declarations, and type-specific
 * rules. The implementation is streaming-oriented: callers may pass network or piped streams, and
 * the filter avoids unbounded buffering. When an invalid or unsafe construct is encountered, the
 * filter fails fast using {@link DataFilterException}-derived types so callers can present clear
 * error messages.
 *
 * <p>Typical usage is to let the higher-level content filter route {@code text/css} to this class
 * with an optional, best-effort charset hint and a {@link FilterCallback}. The callback can be
 * {@code null}; CSS filtering primarily relies on tokenization and strict, positive validation
 * rather than pluggable policy decisions. Instances are stateless and reusable across requests; no
 * shared mutable state is kept between invocations. This class does not perform network I/O by
 * itself; it only consumes the provided streams.
 *
 * <ul>
 *   <li>Responsibility: sanitize CSS and determine the effective charset.
 *   <li>Behavior: streaming parse; rejects unsafe or malformed input with informative exceptions.
 *   <li>Thread-safety: stateless; safe to reuse instances across threads.
 * </ul>
 *
 * @see CSSParser
 * @see ContentFilter
 */
public class CSSReadFilter implements ContentDataFilter, CharsetExtractor {
  private static final Logger LOG = LoggerFactory.getLogger(CSSReadFilter.class);

  // no static initialization required

  /**
   * Creates a new CSS read filter instance.
   *
   * <p>Instances of this class are stateless and thread-safe for concurrent use. Callers may reuse
   * a single instance across multiple filtering operations or construct new ones as needed; both
   * patterns are equivalent in behavior and performance.
   */
  public CSSReadFilter() {
    /* Intentionally empty: this filter is stateless and requires no
     * constructor initialization. */
  }

  /**
   * Parses and sanitizes a CSS stream, emitting a safe representation to {@code output}.
   *
   * <p>The filter validates the structure of the stylesheet, removes or normalizes unsafe
   * constructs, and writes the resulting CSS to the provided {@link OutputStream}. The method is
   * designed to operate on streaming inputs and must not rely on {@code available()} to detect end
   * of stream. When the provided {@code charset} is unsupported, an {@link UnknownCharsetException}
   * is thrown. Structural or policy violations are reported as {@link DataFilterException}
   * subtypes.
   *
   * <p>Callers typically route {@code text/css} responses through this method with a best-effort
   * charset hint and an optional {@link FilterCallback}. The callback may be {@code null}; CSS
   * filtering relies primarily on tokenizer-driven validation rather than pluggable rules.
   *
   * @param input the byte stream containing the original stylesheet; may be network- or pipe-backed
   *     and should be consumed in a streaming fashion without assuming the total size in advance.
   * @param output the destination for sanitized CSS bytes; implementations flush the writer when
   *     the method completes to make downstream processing predictable.
   * @param charset the declared or inferred name of the character set to use for decoding; may be
   *     {@code null} or empty when not known and will be validated before parsing begins.
   * @param otherParams additional parameters associated with the media type; this implementation
   *     ignores them and tolerates an empty or {@code null} map.
   * @param schemeHostAndPort the externally visible base URI (scheme, host, port) for absolute
   *     reference validation; may be {@code null} as it is not required by the CSS filter.
   * @param cb optional callback for policy decisions; may be {@code null}, in which case default
   *     behavior applies for all constructs.
   * @throws IOException if an I/O error occurs while reading from {@code input} or writing to
   *     {@code output}; validation failures are also communicated as {@code IOException} subtypes.
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
    if (LOG.isTraceEnabled()) LOG.trace("running {}with charset{}", this, charset);
    Reader r;
    Writer w = null;
    try {
      try {
        InputStreamReader isr = new InputStreamReader(input, charset);
        OutputStreamWriter osw = new OutputStreamWriter(output, charset);
        r = new BufferedReader(isr, 32768);
        w = new BufferedWriter(osw, 32768);

      } catch (UnsupportedEncodingException _) {
        throw UnknownCharsetException.create(charset);
      }
      CSSParser parser = new CSSParser(r, w, cb, charset, false, false);
      parser.parse();
    } finally {
      if (w != null) {
        w.flush();
      }
    }
  }

  /**
   * Determines the most appropriate charset for a CSS document using a small prefix.
   *
   * <p>The method examines up to {@code length} bytes from {@code input} and evaluates CSS-specific
   * cues such as an {@code @charset} rule near the start of the file. When a valid charset is
   * detected, its canonical name is returned; otherwise {@code null} is returned to signal that a
   * decision cannot be made from the provided bytes. The supplied {@code charset} hint is used as a
   * starting point for decoding the prefix when necessary.
   *
   * @param input byte buffer containing the beginning of the stylesheet; the array is not modified
   *     by this method.
   * @param length number of valid bytes in {@code input} that should be considered; must be
   *     non-negative and should not exceed {@code input.length}.
   * @param charset optional hint previously parsed from metadata or headers; may be {@code null}
   *     when no hint is available or applicable.
   * @return the canonical charset name when a valid in-band declaration is found, or {@code null}
   *     when the current prefix is insufficient to decide.
   * @throws IOException if decoding of the prefix fails due to an unknown or unsupported charset or
   *     if a malformed declaration prevents further inspection.
   */
  @Override
  public String getCharset(byte[] input, int length, String charset) throws IOException {
    if (LOG.isTraceEnabled())
      LOG.trace("Fetching charset for CSS with initial charset {}", charset);
    if (input.length > getCharsetBufferSize() && LOG.isDebugEnabled()) {
      LOG.debug(
          "More data than was strictly needed was passed to the charset extractor for extraction");
    }
    try (InputStream strm = new ByteArrayInputStream(input, 0, length);
        NullWriter w = new NullWriter()) {
      InputStreamReader isr;
      try {
        isr = new InputStreamReader(strm, charset);
      } catch (UnsupportedEncodingException _) {
        throw UnknownCharsetException.create(charset);
      }
      try (BufferedReader r = new BufferedReader(isr, 32768)) {
        CSSParser parser = new CSSParser(r, w, new NullFilterCallback(), null, true, false);
        parser.parse();
        return parser.detectedCharset();
      }
    }
  }

  // CSS 2.1 section 4.4.
  // In all cases these will be confirmed by calling getCharset().
  // We do not use all of the BOMs suggested.
  // Also, we do not use true BOMs.

  // We do check for ascii, even though it's the first one to check for anyway, because of the "as
  // specified" rule: if it starts with @charset in ascii, it MUST have a valid charset, or we
  // ignore the whole sheet, as per the spec.
  static final byte[] ascii = parse("40 63 68 61 72 73 65 74 20 22");
  static final byte[] utf16be =
      parse("00 40 00 63 00 68 00 61 00 72 00 73 00 65 00 74 00 20 00 22");
  static final byte[] utf16le =
      parse("40 00 63 00 68 00 61 00 72 00 73 00 65 00 74 00 20 00 22 00");
  static final byte[] utf32_le =
      parse(
          "40 00 00 00 63 00 00 00 68 00 00 00 61 00 00 00 72 00 00 00 73 00 00 00 65 00 00 00 74"
              + " 00 00 00 20 00 00 00 22 00 00 00");
  static final byte[] utf32_be =
      parse(
          "00 00 00 40 00 00 00 63 00 00 00 68 00 00 00 61 00 00 00 72 00 00 00 73 00 00 00 65 00"
              + " 00 00 74 00 00 00 20 00 00 00 22");
  static final byte[] ebcdic = parse("7C 83 88 81 99 A2 85 A3 40 7F");
  static final byte[] ibm1026 = parse("AE 83 88 81 99 A2 85 A3 40 FC");

  // Not supported.
  static final byte[] utf32_2143 =
      parse(
          "00 00 40 00 00 00 63 00 00 00 68 00 00 00 61 00 00 00 72 00 00 00 73 00 00 00 65 00 00"
              + " 00 74 00 00 00 20 00 00 00 22 00");
  static final byte[] utf32_3412 =
      parse(
          "00 40 00 00 00 63 00 00 00 68 00 00 00 61 00 00 00 72 00 00 00 73 00 00 00 65 00 00 00"
              + " 74 00 00 00 20 00 00 00 22 00 00");
  static final byte[] gsm = parse("00 63 68 61 72 73 65 74 20 22");

  // Maximum prefix length is computable from the patterns above, but not needed here.

  static byte[] parse(String s) {
    s = s.replace(" ", "");
    return HexUtil.hexToBytes(s);
  }

  /**
   * Performs a type-aware BOM-style pre-scan and returns the detected family, if any.
   *
   * <p>This method recognizes CSS-specific encodings by matching the leading bytes of {@code
   * @charset} against multiple Unicode encodings (for example, UTF‑8, UTF‑16BE/LE, UTF‑32BE/LE) and
   * a small set of EBCDIC/IBM code pages. Unsupported but recognizable patterns result in an {@link
   * UnsupportedCharsetInFilterException} to prevent ambiguous decoding. When no match is found,
   * {@code null} is returned so callers may proceed to content-based detection.
   * <p>
   * @param input byte buffer that starts with the first bytes of the stylesheet.
   * @param length number of bytes from {@code input} to consider for detection; must be
   *     non-negative.
   * @return a {@link BOMDetection} describing the detected family and whether an explicit charset
   *     declaration is required, or {@code null} when no decisive signature is present.
   * @throws IOException if an unsupported but recognized signature is found or if detection cannot
   *     proceed due to malformed leading bytes.
   */
  @Override
  public BOMDetection getCharsetByBOM(byte[] input, int length) throws IOException {
    if (ContentFilter.startsWith(input, ascii, length)) return new BOMDetection("UTF-8", true);
    if (ContentFilter.startsWith(input, utf16be, length)) return new BOMDetection("UTF-16BE", true);
    if (ContentFilter.startsWith(input, utf16le, length)) return new BOMDetection("UTF-16LE", true);
    if (ContentFilter.startsWith(input, utf32_be, length))
      return new BOMDetection("UTF-32BE", true);
    if (ContentFilter.startsWith(input, utf32_le, length))
      return new BOMDetection("UTF-32LE", true);
    if (ContentFilter.startsWith(input, ebcdic, length)) return new BOMDetection("IBM01140", true);
    if (ContentFilter.startsWith(input, ibm1026, length)) return new BOMDetection("IBM1026", true);

    // Unsupported BOMs

    if (ContentFilter.startsWith(input, utf32_2143, length))
      throw new UnsupportedCharsetInFilterException("UTF-32-2143");
    if (ContentFilter.startsWith(input, utf32_3412, length))
      throw new UnsupportedCharsetInFilterException("UTF-32-3412");
    if (ContentFilter.startsWith(input, gsm, length))
      throw new UnsupportedCharsetInFilterException("GSM 03.38");
    return null;
  }

  /**
   * Returns a sanitized, comma-separated list of CSS media types extracted from {@code media}.
   *
   * <p>The input is split on commas, each token is trimmed, and only the leading ASCII lowercase
   * letters are considered for validation. Recognized media types (for example, {@code screen} or
   * {@code print}) are preserved and joined using {@code ", "}. Unrecognized tokens are discarded
   * silently. If none of the tokens are valid media types, the method returns {@code null} rather
   * than an empty string.
   *
   * <pre>{@code
   * // Example: keeps only known media identifiers
   * // Input: "screen, projection, unknown, print"
   * // Output: "screen, projection, print"
   * String out = CSSReadFilter.filterMediaList("screen, projection, unknown, print");
   * }</pre>
   *
   * @param media raw {@code media} attribute or query list supplied by content; may contain
   *     arbitrary whitespace and punctuation; must not be {@code null}.
   * @return a normalized list containing only allowed media identifiers, or {@code null} when no
   *     valid entries are present after filtering.
   */
  public static String filterMediaList(String media) {
    String[] split = FilterUtils.splitOnChar(media, ',');
    boolean first = true;
    StringBuilder sb = new StringBuilder();
    for (String m : split) {
      m = m.trim();
      int i = allowedPrefixLength(m);
      m = m.substring(0, i);
      if (FilterUtils.isMedia(m)) {
        if (!first) sb.append(", ");
        sb.append(m);
        first = false;
      }
    }
    if (!sb.isEmpty()) return sb.toString();
    else return null;
  }

  private static int allowedPrefixLength(String m) {
    int i;
    for (i = 0; i < m.length(); i++) {
      char c = m.charAt(i);
      if (c < 'a' || c > 'z') {
        break;
      }
    }
    return i;
  }

  /**
   * Reports the recommended number of bytes to read from the start of a CSS resource for charset
   * detection.
   *
   * <p>Callers should attempt to provide at least this many bytes to {@link
   * #getCharsetByBOM(byte[], int)} or {@link #getCharset(byte[], int, String)} to maximize the
   * chances of accurate detection without incurring unnecessary I/O.
   *
   * @return the minimum suggested prefix length, in bytes, for reliable CSS charset detection.
   */
  @Override
  public int getCharsetBufferSize() {
    return 64; // Reasonable number of bytes to read in
  }
}
