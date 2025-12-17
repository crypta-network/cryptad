package network.crypta.pluginmanager;

import java.io.Serial;

/**
 * Exception type representing an HTTP 404 (Not Found) response raised by a plugin.
 *
 * <p>This class is a specialized {@link PluginHTTPException} intended for situations where the
 * requested resource does not exist or cannot be located using the information in the request. It
 * carries the same structured information as the base type (a human-readable {@code message} and an
 * optional {@code location} hint) but fixes the HTTP status code to {@code 404} via {@link #code()}
 * so the HTTP layer can render a standard "not found" response.
 *
 * <p>Instances are immutable after construction and therefore safe to share between threads. As
 * with {@link PluginHTTPException}, callers should treat the supplied message and location as
 * display-oriented data that may be surfaced over HTTP and should avoid embedding sensitive values.
 *
 * <ul>
 *   <li><b>Status</b>: always {@code 404} (Not Found).
 *   <li><b>Use case</b>: missing resources rather than malformed requests.
 * </ul>
 *
 * @author Florent Daigni&egrave;re &lt;nextgens@freenetproject.org&gt;
 */
public class NotFoundPluginHTTPException extends PluginHTTPException {
  @Serial private static final long serialVersionUID = -1;

  /**
   * Returns the HTTP status code associated with this exception instance.
   *
   * <p>This override returns {@code 404} (Not Found) to indicate that the request cannot be
   * satisfied because the addressed resource is missing. The base class continues to carry the
   * human-readable message and optional location hint, which can be used when rendering an
   * HTTP-facing error response.
   *
   * @return the HTTP status code {@code 404} (Not Found).
   */
  @Override
  public short code() {
    return 404; // Not Found
  }

  /**
   * Creates a new exception instance representing an HTTP 404 (Not Found) error.
   *
   * <p>This constructor stores the provided values as-is and delegates to {@link
   * PluginHTTPException#PluginHTTPException(String, String)}. Neither parameter is validated or
   * normalized; both may be {@code null}. Callers that render the exception should tolerate missing
   * values and should keep the provided data safe for display in HTTP-facing output.
   *
   * <pre>{@code
   * throw new NotFoundPluginHTTPException("Resource not found", "/some/path");
   * }</pre>
   *
   * @param errorMessage human-readable description suitable for surfacing in an HTTP response.
   * @param location opaque hint identifying what could not be found, as understood by the caller.
   */
  public NotFoundPluginHTTPException(String errorMessage, String location) {
    super(errorMessage, location);
  }
}
