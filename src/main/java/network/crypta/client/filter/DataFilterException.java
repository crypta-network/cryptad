package network.crypta.client.filter;

import java.io.Serial;
import network.crypta.client.FetchException;

/**
 * Signals that client-supplied or fetched data failed validation by a content filter and therefore
 * cannot be delivered safely. Instances of this exception carry a human-readable title (both raw
 * and HTML-encoded forms) and an explanatory message intended for presentation in error pages or
 * logs.
 *
 * <p>This type is raised by filters that parse and vet user-visible content (for example media
 * containers or markup) when a structural rule is violated, a known-dangerous construct is found,
 * or the stream cannot be sanitized to a level acceptable for safe distribution. Callers typically
 * catch {@link DataFilterException} near request boundaries and translate it into a {@link
 * FetchException} using {@link #recreateFetchException(FetchException, String)} or {@link
 * #createFetchException(String, long)} so that higher layers can render a clear error to the
 * client.
 *
 * <p>Objects of this class are immutable and thread-safe after construction; the title and
 * explanatory text never change. Equality is not overridden; the instance primarily acts as a
 * descriptive failure carrier. The class focuses on conveying displayable error details rather than
 * low-level parsing positions or byte offsets, which are filter-specific concerns.
 *
 * <ul>
 *   <li>Responsibilities: carry display-safe titles and explanations for filter failures.
 *   <li>Typical usage: throw from filter code paths; convert to {@link FetchException} at
 *       boundaries.
 *   <li>Thread-safety: immutable fields; safe to share across threads.
 * </ul>
 */
public class DataFilterException extends UnsafeContentTypeException {
  @Serial private static final long serialVersionUID = -1;

  /**
   * Raw, unescaped title suitable for plain-text logs or console output. The value may contain
   * characters that are unsafe for direct HTML rendering and must be escaped before being embedded
   * in markup. It is stable for the lifetime of the exception and never {@code null}.
   */
  final String rawTitle;

  /**
   * HTML-encoded title which is safe to insert into an HTML page without additional escaping. The
   * encoded form mirrors {@link #rawTitle} but is pre-escaped for convenience in UI layers that
   * render error pages.
   */
  final String encodedTitle;

  /**
   * Human-readable explanation describing why filtering failed. This is returned from {@link
   * #getMessage()} and is appropriate for inclusion in error pages or logs. The text does not
   * include markup and should be treated as plain text unless explicitly encoded by callers.
   */
  final String explanation;

  @SuppressWarnings("unused")
  DataFilterException(String explanation) {
    rawTitle = encodedTitle = this.explanation = explanation;
  }

  DataFilterException(String raw, String encoded, String explanation) {
    this.rawTitle = raw;
    this.encodedTitle = encoded;
    this.explanation = explanation;
  }

  /**
   * Returns the explanatory text associated with this failure.
   *
   * <p>The message is intended for human consumption, describing the primary reason the content
   * could not be filtered safely. It is plain text and may be displayed directly in logs or UI
   * components that expect unformatted strings.
   *
   * @return a plain-text explanation of the filtering failure; never {@code null} and stable for
   *     the life of the instance
   */
  @Override
  public String getMessage() {
    return explanation;
  }

  /**
   * Returns a title that is already safely encoded for HTML contexts.
   *
   * <p>Callers rendering an error page may include this value directly in markup without applying
   * additional escaping. For non-HTML contexts prefer {@link #getRawTitle()}.
   *
   * @return an HTML-escaped error title suitable for insertion into markup without further
   *     processing
   */
  @Override
  public String getHTMLEncodedTitle() {
    return encodedTitle;
  }

  /**
   * Returns the raw, unescaped title for this error.
   *
   * <p>This value is appropriate for logs or plain-text channels. When rendering to HTML, callers
   * must escape it or instead use {@link #getHTMLEncodedTitle()}.
   *
   * @return a plain-text title describing the failure; may contain characters unsafe for direct
   *     HTML insertion
   */
  @Override
  public String getRawTitle() {
    return rawTitle;
  }

  /**
   * Returns the raw title as the string representation of this exception.
   *
   * <p>This mirrors the behavior of {@link #getRawTitle()} to keep log output concise and focused
   * on the human-readable summary of the filtering error.
   *
   * @return the raw, unescaped title for logging and diagnostics
   */
  @Override
  public String toString() {
    return rawTitle;
  }

  /**
   * Recreates a {@link FetchException} using details from an existing one while preserving the
   * current filter failure as the cause.
   *
   * <p>Use this when translating a filtering error that occurred during an existing fetch flow. The
   * returned exception carries the previous expected size and uses this instance as the underlying
   * reason so that upstream logic can render appropriate client-facing messages.
   *
   * @param e the original {@link FetchException} whose expected size is reused; must not be {@code
   *     null} and should represent the in-flight fetch being translated
   * @param mime the MIME type associated with the failing content; pass a best-known value or
   *     {@code null} when unknown
   * @return a new {@link FetchException} that wraps this {@code DataFilterException} and retains
   *     the expected size from the prior exception for accurate reporting
   */
  @Override
  public FetchException recreateFetchException(FetchException e, String mime) {
    return new FetchException(e.expectedSize, this, mime);
  }

  /**
   * Creates a new {@link FetchException} that represents this filtering failure for a given content
   * type and expected size.
   *
   * <p>Use this at API boundaries when a filter rejects input, and you need to propagate a
   * standardized fetch-layer error. The returned instance identifies this exception as the cause so
   * higher layers can present consistent messages.
   *
   * @param mime the associated MIME type for the rejected data; may be {@code null} when not
   *     available or when type detection failed
   * @param expectedSize the anticipated size in bytes of the content at the time of failure; use a
   *     negative value only when no estimate is available
   * @return a {@link FetchException} wrapping this instance with the provided metadata so callers
   *     can display a uniform error to clients
   */
  @Override
  public FetchException createFetchException(String mime, long expectedSize) {
    return new FetchException(expectedSize, this, mime);
  }
}
