package network.crypta.support;

import java.io.Serial;

/**
 * Exception indicating malformed {@code application/x-www-form-urlencoded} input during decoding.
 *
 * <p>This checked exception is used by URL‑decoder utilities to signal that an input string does
 * not conform to the {@code application/x-www-form-urlencoded} format (often used in HTML forms and
 * query strings). Typical causes include malformed percent escapes (e.g., stray {@code '%'} or
 * non‑hex digits), premature end of input after {@code '%'}, or otherwise invalid sequences.
 *
 * <p>Usage: Catch this exception when decoding user‑provided strings that are expected to be in the
 * form‑URL‑encoded format and handle it as an input‑validation error. The instance is immutable
 * after construction.
 *
 * <p>Thread-safety: instances are thread‑safe after construction.
 *
 * @see java.net.URLDecoder
 * @see java.net.URLEncoder
 */
public class URLEncodedFormatException extends Exception {
  // Stable serialization identifier for compatibility across versions.
  @Serial private static final long serialVersionUID = -1;

  /**
   * Creates a new instance with no detail message.
   *
   * <p>Intended for use when the caller does not have additional error context.
   */
  @SuppressWarnings("unused")
  URLEncodedFormatException() {}

  /**
   * Creates a new instance with the specified detail message.
   *
   * @param s human‑readable explanation of the formatting problem; may be {@code null}
   */
  URLEncodedFormatException(String s) {
    super(s);
  }
}
