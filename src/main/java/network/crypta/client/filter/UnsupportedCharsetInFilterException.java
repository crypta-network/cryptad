package network.crypta.client.filter;

import java.io.Serial;
import network.crypta.l10n.NodeL10n;

/**
 * Signals that a character set declared or inferred during client-side filtering is not supported
 * by the running node. This exception is raised from filter components that need to interpret
 * textual payloads (for example, HTML or CSS filters) when the provided charset token cannot be
 * recognized or is considered unsafe for decoding.
 *
 * <p>The primary purpose of this type is to carry the original charset token (as a simple {@code
 * String}) and to provide localized, human-readable messages and titles suitable for surfacing in
 * user interfaces. Instances are lightweight and immutable; once created, the stored charset value
 * does not change. Consumers typically construct and throw this exception at the point where
 * decoding would otherwise occur and then allow higher-level code to translate it into an error
 * response.
 *
 * <p>Concurrency: this class is thread-safe to the extent that it is immutable. The captured
 * charset token is retained as provided by the caller; no normalization is applied. The
 * localization helpers delegate to {@link NodeL10n} at call time, which may depend on the process
 * localization configuration.
 *
 * <ul>
 *   <li>Responsibility: report unsupported or disallowed charset identifiers detected by filters.
 *   <li>Behavior: exposes localized {@linkplain #getMessage() message} and title strings.
 *   <li>State: immutable after construction; contains the original charset token.
 * </ul>
 *
 * @see UnsafeContentTypeException
 * @see NodeL10n
 */
public class UnsupportedCharsetInFilterException extends UnsafeContentTypeException {

  @Serial private static final long serialVersionUID = 3775454822229213420L;

  /**
   * The charset token that triggered the failure. The value is captured verbatim from the
   * originating context and may not be normalized; callers should treat it as display text only.
   */
  final String charset;

  /**
   * Creates an exception associated with a specific, unsupported charset token.
   *
   * <p>The provided value is stored without validation or transformation and may appear in
   * localized titles. Passing {@code null} is permitted; in that case, the title generation will
   * include a literal {@code null} representation as determined by the localization layer.
   *
   * <pre>{@code
   * // Example: raise an error when a page declares an unknown encoding
   * throw new UnsupportedCharsetInFilterException(declaredCharset);
   * }</pre>
   *
   * @param string the charset identifier encountered by the filter, such as {@code "UTF-8"} or a
   *     raw token as found in content metadata; may be {@code null} when unavailable.
   */
  public UnsupportedCharsetInFilterException(String string) {
    charset = string;
  }

  /**
   * Returns a localized, human-readable explanation describing why the charset is unsupported. The
   * message is suitable for logs or UI error summaries and is independent of the title.
   *
   * @return a localized explanation string; never {@code null}, though content depends on installed
   *     locales and resource bundles.
   */
  @Override
  public String getMessage() {
    return l10n("explanation");
  }

  /**
   * Returns a localized title intended for HTML presentation contexts. The title includes the
   * unsupported charset token and is returned as plain text; callers remain responsible for any
   * additional context-specific escaping.
   *
   * @return a localized title string that references the offending charset token; never {@code
   *     null}.
   */
  @Override
  public String getHTMLEncodedTitle() {
    return l10n("title", "charset", charset);
  }

  /**
   * Returns a localized title as plain, unencoded text. Unlike {@link #getHTMLEncodedTitle()}, no
   * assumptions are made about the output being inserted into HTML; it can be used for logs or
   * plain-text interfaces.
   *
   * @return a localized title string that references the offending charset token; never {@code
   *     null}.
   */
  @Override
  public String getRawTitle() {
    return l10n("title", "charset", charset);
  }

  /**
   * Looks up a localized message by suffix key within this exception's resource bundle namespace.
   * This is a convenience for building user-facing strings tied to this error type.
   *
   * @param message the suffix portion of the resource key, appended to the {@code
   *     UnsupportedCharsetInFilterException.} prefix; must match a defined bundle entry.
   * @return the resolved localized string for the provided key; never {@code null} when the bundle
   *     contains a matching entry.
   */
  public String l10n(String message) {
    return NodeL10n.getBase().getString("UnsupportedCharsetInFilterException." + message);
  }

  /**
   * Looks up a localized, parameterized message under this exception's namespace and substitutes a
   * single named argument. The substitution semantics are defined by {@link NodeL10n}.
   *
   * @param message the suffix portion of the resource key, appended to the {@code
   *     UnsupportedCharsetInFilterException.} prefix, identifying a parameterized string.
   * @param key the placeholder name expected by the resource entry (for example, {@code "charset"}
   *     to reference the unsupported token); must not be {@code null}.
   * @param value the placeholder value to inject for the given {@code key}; may be {@code null}
   *     when the original token is unavailable.
   * @return the resolved and formatted localized string; never {@code null} when the bundle
   *     contains a matching entry.
   */
  public String l10n(String message, String key, String value) {
    return NodeL10n.getBase()
        .getString("UnsupportedCharsetInFilterException." + message, key, value);
  }
}
