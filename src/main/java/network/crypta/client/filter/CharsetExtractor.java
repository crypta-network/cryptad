package network.crypta.client.filter;

import java.io.IOException;

/**
 * Extracts character set information from textual content for a specific text-based MIME type.
 *
 * <p>This interface defines a small, focused API used by higher-level parsers and filters to
 * determine the character encoding of an incoming byte stream. Implementations typically combine a
 * lightweight byte-order-mark (BOM) pre-scan with in-band declarations (for example, directives
 * embedded near the start of the content) and any out-of-band hints supplied by the caller. The
 * contract intentionally avoids I/O; callers provide the already-read prefix of the resource.
 *
 * <p>Typical usage follows this pattern:
 *
 * <ol>
 *   <li>Read at least {@link #getCharsetBufferSize()} bytes from the start of the resource.
 *   <li>Call {@link #getCharsetByBOM(byte[], int)} to detect obvious BOM-style encodings and to
 *       learn whether a declared charset is mandatory for the content to be considered valid.
 *   <li>If needed, call {@link #getCharset(byte[], int, String)} to inspect in-band declarations or
 *       type-specific cues, optionally passing a previously parsed hint.
 * </ol>
 *
 * <p>Thread-safety: this is a pure inspection API. Implementations are commonly stateless and thus
 * safe to share across threads, but the interface does not require any particular concurrency
 * guarantees. Inputs are treated as read-only and must not be modified by implementations.
 */
public interface CharsetExtractor {

  /**
   * Determine the most appropriate charset name for the provided byte prefix.
   *
   * <p>The implementation should examine up to {@code length} bytes from {@code input} and may
   * combine signals from the pre-scan phase, in-band declarations, and the optional {@code
   * parseCharset} hint. The method is deterministic with respect to the supplied bytes and does not
   * perform additional I/O.
   *
   * <pre>{@code
   * // Example: determine charset from an already-read buffer
   * String charset = extractor.getCharset(buffer, bytesRead, null);
   * }</pre>
   *
   * @param input the byte buffer containing the beginning of the resource; the array is not
   *     modified and may be larger than {@code length}.
   * @param length the number of valid bytes in {@code input} to inspect; must be {@code >= 0} and
   *     should not exceed the buffer length.
   * @param parseCharset an optional, previously parsed charset token or external hint; may be
   *     {@code null} or empty when no hint is available.
   * @return the canonical charset name (for example, {@code "UTF-8"}) when a decision can be made,
   *     or {@code null} when the available bytes and hints are insufficient to decide.
   * @throws IOException if the implementation encounters malformed declarations or decoding steps
   *     that cannot proceed with the supplied data.
   */
  String getCharset(byte[] input, int length, String parseCharset) throws IOException;

  /**
   * Inspect the initial bytes for BOM-style signatures and return a pre-scan result.
   *
   * <p>This method performs a fast, type-aware check of the first few bytes to detect an obvious
   * byte-order mark (or similar, format-specific preamble). It should not attempt deep parsing; if
   * no decisive signal is present, callers can proceed to {@link #getCharset(byte[], int, String)}
   * with candidate families derived from this result.
   *
   * <pre>{@code
   * CharsetExtractor.BOMDetection bom = extractor.getCharsetByBOM(buffer, bytesRead);
   * if (bom.mustHaveCharset) {
   *   // downstream logic may enforce that a charset is declared
   * }
   * }</pre>
   *
   * @param input the byte buffer containing the beginning of the resource; only the first {@code
   *     length} bytes are considered.
   * @param length the number of bytes available in {@code input} for inspection; must be {@code >=
   *     0} and should reflect the actual number read.
   * @return a {@link BOMDetection} describing the detected charset family and whether a declared
   *     charset is required for the content to be considered valid.
   * @throws IOException if the pre-scan logic cannot proceed due to malformed leading bytes or
   *     other format errors in the provided prefix.
   */
  BOMDetection getCharsetByBOM(byte[] input, int length) throws IOException;

  /**
   * Report the minimum number of bytes callers should provide for reliable detection.
   *
   * <p>Callers are expected to read at least this many bytes before invoking {@link
   * #getCharsetByBOM(byte[], int)} or {@link #getCharset(byte[], int, String)}. Supplying a larger
   * prefix is allowed and may increase accuracy, but the value returned here indicates the
   * implementation's baseline requirement.
   *
   * @return a positive integer representing the recommended byte budget for the initial detection
   *     pass, expressed in bytes counted from the start of the resource.
   */
  int getCharsetBufferSize();

  /**
   * Result of the BOM pre-scan performed by {@link #getCharsetByBOM(byte[], int)}.
   *
   * <p>This simple value class communicates two pieces of information to the caller: the best
   * available guess for the charset family based solely on leading bytes, and whether the content
   * is considered valid only when a charset is explicitly declared downstream. The latter is useful
   * for enforcing specification rules that require an explicit {@code @charset}-style declaration.
   *
   * @see #getCharsetByBOM(byte[], int)
   * @see #getCharset(byte[], int, String)
   */
  class BOMDetection {
    /** The guessed charset family derived from the first few characters. */
    final String charset;

    /**
     * If this is true, getCharset() must return a charset, if it does not, we ignore the whole
     * stylesheet. See CSS 2.1 section 4.4, at the end, "as specified" rule.
     */
    final boolean mustHaveCharset;

    BOMDetection(String charset, boolean mustHaveCharset) {
      this.charset = charset;
      this.mustHaveCharset = mustHaveCharset;
    }
  }
}
