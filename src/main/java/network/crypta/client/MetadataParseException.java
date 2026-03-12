package network.crypta.client;

import java.io.Serial;

/**
 * Exception indicating that client metadata could not be parsed.
 *
 * <p>This checked exception is raised by client-side parsing code when an input that is expected to
 * represent metadata is malformed, incomplete, or otherwise violates the format understood by the
 * caller. It intentionally conveys a semantic parsing failure rather than transport or I/O errors.
 * Typical usage is to throw this exception from a parser or decoder and allow higher layers to
 * decide whether to surface a user-facing message, log diagnostics, or retry with a different
 * source.
 *
 * <p>The instance is immutable and safe to share between threads once constructed. The message
 * supplied at construction time should be concise and suitable for logs; callers may include
 * contextual details such as an identifier, schema version, or a short excerpt of the offending
 * input as appropriate. This type does not track a cause in its current form; if you need to attach
 * a root cause, consider wrapping that exception when you create the message.
 *
 * <ul>
 *   <li>Represents a parsing/validation failure of metadata content.
 *   <li>Intended for client-side code paths, not network transport issues.
 *   <li>Does not record an offset/location; callers should include such context in the message.
 * </ul>
 *
 * @see java.text.ParseException
 */
public class MetadataParseException extends Exception {

  @Serial private static final long serialVersionUID = 4910650977022715220L;

  /**
   * Creates a new exception describing why parsing failed.
   *
   * <p>Use a clear, actionable message that helps operators or calling code understand the nature
   * of the problem (e.g., unknown field, invalid value range, or truncated input). The message is
   * preserved verbatim for logs and error propagation. This constructor does not accept a cause; if
   * a lower-level exception exists, include its salient details in the message text.
   *
   * <pre>{@code
   * // Example: surface a metadata decoding error
   * if (!isValid(meta)) {
   *   throw new MetadataParseException("Unsupported metadata version: " + meta.getVersion());
   * }
   * }</pre>
   *
   * @param string human-readable description of the parsing failure; must be non-null and should
   *     explain what was invalid or unexpected in the input so callers can act on it.
   */
  public MetadataParseException(String string) {
    super(string);
  }
}
