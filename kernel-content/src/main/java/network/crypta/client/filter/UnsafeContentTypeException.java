package network.crypta.client.filter;

import java.io.IOException;
import java.io.Serial;
import java.util.List;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchException;

/**
 * Signals that a client-side content filter determined that returned data cannot be considered safe
 * to render or process as-is. Typical reasons include an unknown MIME type, a known-but- hazardous
 * type, or content that cannot be filtered to a safe representation.
 *
 * <p>This abstract base class defines the contract used by higher layers to present meaningful
 * information to end users and calling code. Subclasses supply an HTML-encoded title ({@link
 * #getHTMLEncodedTitle()}), a raw (unescaped) title ({@link #getRawTitle()}), a human-readable
 * message ({@link #getMessage()}), and optional detail lines ({@link #details()}). The exception
 * also maps to a {@code FetchException} error mode so callers can preserve failure semantics across
 * API boundaries via {@link #recreateFetchException(FetchException, String)} and {@link
 * #createFetchException(String, long)}.
 *
 * <p>Instances are immutable with respect to their externally observable state and are expected to
 * be thread-safe for read-only use after construction. Callers should not attempt to mutate the
 * returned strings. Typical call patterns are:
 *
 * <ul>
 *   <li>Catch this exception when filtering content fetched from the network.
 *   <li>Display the HTML-encoded title and message in a UI error view.
 *   <li>Convert to a {@code FetchException} to propagate failure information to APIs that expect
 *       fetch-level errors.
 * </ul>
 *
 * @see FetchException
 */
public abstract class UnsafeContentTypeException extends IOException {
  @Serial private static final long serialVersionUID = 1L;

  /**
   * Creates a new exception with no detail message. Subclasses typically call this constructor from
   * their own constructors to signal that content failed validation and that the filter could not
   * safely process it further.
   */
  protected UnsafeContentTypeException() {
    super();
  }

  /**
   * Returns the human-readable contents of an error page describing why the content is considered
   * unsafe. Implementations should ensure the returned text is suitable for display and does not
   * leak sensitive information beyond what is necessary to explain the failure.
   *
   * @return descriptive text intended for display to users; never {@code null}
   */
  @Override
  public abstract String getMessage();

  /**
   * Provides additional detail lines that may help the caller render a richer error view or log
   * diagnostic information. Subclasses may return {@code null} when no extra details are available.
   *
   * @return an ordered list of detail strings, or {@code null} when not applicable
   */
  @SuppressWarnings("java:S1168")
  public List<String> details() {
    return null;
  }

  /**
   * Returns a short, HTML-encoded title suitable for embedding in an HTML context (for example, a
   * dialog or page header). Implementations must escape special characters, so the returned value
   * is safe to include in HTML without additional encoding.
   *
   * @return an HTML-encoded title safe for direct inclusion in markup
   */
  public abstract String getHTMLEncodedTitle();

  /**
   * Returns the raw title string of the error without HTML escaping. This value may contain
   * characters that require encoding before being inserted into HTML and should therefore be used
   * only in plain-text contexts or after appropriate escaping.
   *
   * @return an unescaped, plain-text title; callers must escape before using in HTML
   */
  public abstract String getRawTitle();

  /**
   * {@inheritDoc}
   *
   * <p>For convenience, this implementation returns the same value as {@link #getRawTitle()} to
   * make log output concise and consistent.
   *
   * @return a concise string representation, typically the raw title
   */
  @Override
  public String toString() {
    return getRawTitle();
  }

  /**
   * Returns the {@code FetchException} error mode that represents this validation failure. The
   * default maps to {@code CONTENT_VALIDATION_FAILED}. Subclasses may override to select a more
   * specific mode while preserving stable behavior for callers that translate this exception to a
   * {@code FetchException}.
   *
   * @return the fetch error mode to use when constructing a {@code FetchException}
   */
  public FetchExceptionMode getFetchErrorCode() {
    return FetchExceptionMode.CONTENT_VALIDATION_FAILED;
  }

  /**
   * Recreates a {@code FetchException} from an existing one, preserving the expected size while
   * updating the error mode and MIME type to reflect this specific validation failure.
   *
   * @param e the original fetch exception; its {@code expectedSize} will be propagated; must not be
   *     {@code null}
   * @param mime the MIME type associated with the failed content, such as {@code text/html} or
   *     {@code application/octet-stream}; may be {@code null} if unknown
   * @return a new {@code FetchException} that captures this validation failure and context
   */
  public FetchException recreateFetchException(FetchException e, String mime) {
    return new FetchException(getFetchErrorCode(), e.getExpectedSize(), this, mime);
  }

  /**
   * Creates a new {@code FetchException} representing this validation failure with the supplied
   * MIME type and expected content size.
   *
   * @param mime the MIME type inferred or declared for the content; may be {@code null} when
   *     unknown
   * @param expectedSize the expected size of the content in bytes, or {@code -1} when not known
   * @return a freshly constructed {@code FetchException} suitable for propagation to callers
   */
  public FetchException createFetchException(String mime, long expectedSize) {
    return new FetchException(getFetchErrorCode(), expectedSize, this, mime);
  }
}
