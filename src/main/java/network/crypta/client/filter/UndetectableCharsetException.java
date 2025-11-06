package network.crypta.client.filter;

import java.io.Serial;
import network.crypta.l10n.NodeL10n;

/**
 * Signals that a character set declaration could not be determined reliably.
 *
 * <p>This exception is raised by client-side filtering when input advertises a specific character
 * encoding (for example, a stylesheet using an {@code @charset} declaration or a byte-order mark),
 * but the declaration is syntactically invalid, incomplete, or otherwise undecidable. In such
 * cases, decoding the payload would be error-prone and may result in unsafe rendering or
 * interpretation. The exception carries the raw token that purported to name the charset so that
 * callers can surface a clear, localized diagnostic to end users or logs.
 *
 * <p>The instance is immutable and thread-safe after construction. Typical usage is to throw it
 * from parsing or normalization routines and allow higher layers to translate it into a localized
 * message via {@link #getMessage()} or title helpers. No automatic recovery is attempted; callers
 * should either reject the content or retry using a safe default if policy allows.
 *
 * <ul>
 *   <li>Includes the raw {@code charset} token as observed.
 *   <li>Produces localized messages via {@link NodeL10n} keys scoped to this type.
 *   <li>Does not attempt to guess or coerce an encoding.
 * </ul>
 *
 * @see UnsafeContentTypeException
 * @see NodeL10n
 */
public class UndetectableCharsetException extends UnsafeContentTypeException {

  @Serial private static final long serialVersionUID = -7663468693283975543L;

  /**
   * The raw charset token captured from the input context.
   *
   * <p>This value reflects what was presented in the source (for example, within an
   * {@code @charset} directive) and is preserved verbatim. It may be suitable only for display in
   * diagnostics, not for direct use in decoders.
   */
  final String charset;

  /**
   * Creates a new exception indicating that the charset could not be determined.
   *
   * <p>The provided string is stored unmodified and is used in localized messages and titles.
   * Callers should ensure any sensitive content is avoided or sanitized before passing it here if
   * user-visible rendering is expected.
   *
   * @param string the raw charset token observed in the input; may be any non-null string and is
   *     preserved verbatim for diagnostics and localization keys.
   */
  public UndetectableCharsetException(String string) {
    charset = string;
  }

  /**
   * Returns a localized explanation suitable for logs or user-visible error text.
   *
   * <p>The message is obtained from {@link NodeL10n} using a key scoped to this exception type and
   * does not include markup.
   *
   * @return a human-readable, localized description explaining that the charset could not be
   *     detected from the provided declaration.
   */
  @Override
  public String getMessage() {
    return l10n("explanation");
  }

  /**
   * Returns a localized HTML-encoded title that includes the raw charset token.
   *
   * <p>The returned string is intended for safe embedding in HTML contexts where escaping is
   * applied by the localization layer.
   *
   * @return a localized, HTML-encoded short title incorporating the observed charset token.
   */
  @Override
  public String getHTMLEncodedTitle() {
    return l10n("title", "charset", charset);
  }

  /**
   * Returns a localized plain-text title that includes the raw charset token.
   *
   * <p>This variant does not apply HTML encoding and is suitable for console logs or other
   * plain-text environments.
   *
   * @return a localized, plain-text short title incorporating the observed charset token.
   */
  @Override
  public String getRawTitle() {
    return l10n("title", "charset", charset);
  }

  /**
   * Looks up a localized string for this exception's resource bundle scope.
   *
   * <p>Keys are resolved using the base {@link NodeL10n} instance with the {@code
   * "UndetectableCharsetException."} prefix.
   *
   * @param message the unprefixed message key to resolve within this exception's namespace; must be
   *     non-null and should correspond to a defined resource.
   * @return the resolved, localized string; callers should not assume a specific language or
   *     encoding and should treat the result as read-only.
   */
  public String l10n(String message) {
    return NodeL10n.getBase().getString("UndetectableCharsetException." + message);
  }

  /**
   * Looks up a localized format string and substitutes a single named parameter.
   *
   * <p>Keys are resolved within this exception's namespace. The provided {@code key} and {@code
   * value} are passed to the localization layer for named placeholder substitution.
   *
   * @param message the unprefixed message key to resolve; must be non-null and reference an entry
   *     that accepts a single named parameter.
   * @param key the name of the placeholder parameter in the message pattern; use a stable, known
   *     key expected by the resource.
   * @param value the string value to substitute for the named parameter; preserved verbatim and may
   *     be displayed to end users depending on the context.
   * @return the resolved, localized string with the provided parameter substituted; the result is
   *     intended for display and should be treated as immutable.
   */
  public String l10n(String message, String key, String value) {
    return NodeL10n.getBase().getString("UndetectableCharsetException." + message, key, value);
  }
}
