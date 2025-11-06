package network.crypta.client.filter;

import java.io.Serial;
import network.crypta.l10n.NodeL10n;

/**
 * Signals that a requested character set name is unknown or unsupported in the current execution
 * environment while filtering or parsing client-provided content. Instances of this exception are
 * created with localized, user-facing messages that explain the problem and can be surfaced by
 * higher-level code (for example, HTTP responses or UI alerts).
 *
 * <p>This type is typically thrown by content data filters when they attempt to construct
 * character-oriented readers or writers for a specific charset and the runtime cannot provide a
 * corresponding codec. The {@link #charset} field preserves the name that was originally requested,
 * allowing callers to include it in diagnostics or logs. Values are not normalized; the original
 * input is retained to avoid losing context.
 *
 * <p>Exception instances are immutable and therefore safe to share across threads if needed;
 * however, in normal usage they are created and immediately thrown in the same thread where the
 * failure occurs. No automatic recovery is performed by this class. Callers should select and retry
 * with an alternative charset when appropriate or propagate the exception to abort processing.
 *
 * <ul>
 *   <li>Purpose: report charset lookup or initialization failures encountered in filters.
 *   <li>Payload: preserves the requested charset name via {@link #charset}.
 *   <li>Localization: message text is sourced from the node localization bundle.
 * </ul>
 */
public class UnknownCharsetException extends DataFilterException {
  @Serial private static final long serialVersionUID = 1L;

  /**
   * The character set name that was requested when the failure occurred.
   *
   * <p>The value is preserved exactly as supplied by the caller to facilitate accurate diagnostics
   * and end-user feedback. It may be {@code null} or an empty string if the originating code did
   * not provide a name, although callers should normally pass a non-empty value that reflects the
   * attempted configuration.
   */
  public final String charset;

  private UnknownCharsetException(String warning, String warning2, String string, String charset) {
    super(warning, warning2, string);
    this.charset = charset;
  }

  /**
   * Creates a new {@code UnknownCharsetException} for the provided character set name.
   *
   * <p>This factory assembles a localized, user-facing explanation and a concise warning title that
   * higher layers can present to users. It does not attempt to validate or normalize the supplied
   * value; the name is stored as-is in {@link #charset}. Typical call sites invoke this method from
   * a catch block that handles charset initialization errors while setting up readers or writers
   * for content filtering.
   *
   * @param charset the character set name that failed to initialize; may be {@code null} or empty
   *     when no explicit name was available from the source context, but callers should prefer a
   *     non-empty, descriptive value that reflects the attempted encoding.
   * @return a new exception instance carrying localized messages and preserving the original
   *     charset name for diagnostics and user feedback.
   */
  public static UnknownCharsetException create(String charset) {
    String explTitle = l10nDF("unknownCharsetTitle");
    String expl = l10nDF("unknownCharset");

    String warning =
        NodeL10n.getBase()
            .getString("ContentDataFilter.warningUnknownCharsetTitle", "charset", charset);
    return new UnknownCharsetException(warning, warning, explTitle + " " + expl, charset);
  }

  private static String l10nDF(String key) {
    // All the strings here are generic
    return NodeL10n.getBase().getString("ContentDataFilter." + key);
  }
}
