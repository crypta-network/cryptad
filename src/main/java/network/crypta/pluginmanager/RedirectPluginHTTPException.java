package network.crypta.pluginmanager;

import java.io.Serial;

/**
 * Signals that an HTTP-facing plugin request should be answered with a redirect.
 *
 * <p>This exception is a small, purpose-built specialization of {@link PluginHTTPException} that
 * carries a redirect target alongside the usual error message. It is typically thrown from plugin
 * request handling code when the correct response is not an HTML/body payload but rather an HTTP
 * redirect to a different path or resource. The HTTP layer interprets the exception as a redirect
 * response and uses {@link #code()} and {@link #newLocation} to construct the status line and the
 * associated redirect metadata.
 *
 * <p>Instances are immutable and contain only simple value state. They are safe to share across
 * threads after construction, assuming the surrounding exception handling logic is thread-safe.
 *
 * <ul>
 *   <li><b>Status code:</b> always {@code 302} ("Found") via {@link #code()}.
 *   <li><b>Redirect target:</b> exposed as {@link #newLocation} for response construction.
 *   <li><b>Message:</b> provided to the superclass for inclusion in an HTTP reply.
 * </ul>
 *
 * @author Florent Daigni&egrave;re &lt;nextgens@freenetproject.org&gt;
 * @see PluginHTTPException
 */
public class RedirectPluginHTTPException extends PluginHTTPException {
  @Serial private static final long serialVersionUID = -1;

  /**
   * Redirect target associated with this exception.
   *
   * <p>This value is treated as an opaque string by this class and is intended to be consumed by
   * the HTTP response layer as the redirect destination. Callers should provide a stable, fully
   * formed value appropriate for the surrounding HTTP context (for example, a path or URI), and
   * typically avoid {@code null} or empty strings.
   */
  public final String newLocation;

  /**
   * Returns the HTTP status code for this exception instance.
   *
   * <p>This implementation always returns {@code 302} ("Found"). The value is used by the HTTP
   * handling layer to format the response status line; it does not perform any validation of {@link
   * #newLocation}.
   *
   * @return the HTTP status code for the redirect response, always {@code 302}.
   */
  @Override
  public short code() {
    return 302; // Found
  }

  /**
   * Creates a new redirect exception.
   *
   * <p>Constructs an immutable exception instance that instructs the HTTP plugin bridge to respond
   * with a redirect rather than a normal plugin response body. The {@code message} is forwarded to
   * the {@link PluginHTTPException} base class, while {@code newLocation} is stored unchanged for
   * later use when constructing the redirect response.
   *
   * <p>This constructor performs no normalization of the provided values; callers are expected to
   * provide a location string appropriate for the intended HTTP client and environment.
   *
   * @param message message to include in the HTTP reply body, when applicable.
   * @param newLocation redirect destination string to expose via {@link #newLocation}.
   */
  public RedirectPluginHTTPException(String message, String newLocation) {
    super(message, null);
    this.newLocation = newLocation;
  }
}
