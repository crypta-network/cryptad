package network.crypta.pluginmanager;

import java.io.Serial;

/**
 * Exception type representing an HTTP 403 (Forbidden) response raised by a plugin.
 *
 * <p>This class is a specialized {@link PluginHTTPException} for access-control failures where the
 * caller is not permitted to perform the requested operation. It carries the same structured
 * information as the base type (a human-readable {@code message} and an optional {@code location}
 * hint) but fixes the HTTP status code to {@code 403} via {@link #code()}.
 *
 * <p>Instances are immutable after construction and therefore safe to share between threads. As
 * with {@link PluginHTTPException}, callers should treat the supplied message and location as
 * display-oriented data that may be surfaced over HTTP and should avoid embedding sensitive values.
 *
 * <ul>
 *   <li><b>Status</b>: always {@code 403} (Forbidden).
 *   <li><b>Use case</b>: authorization failures rather than malformed requests.
 * </ul>
 *
 * @author Florent Daigni&egrave;re &lt;nextgens@freenetproject.org&gt;
 */
public class AccessDeniedPluginHTTPException extends PluginHTTPException {
  @Serial private static final long serialVersionUID = -1;

  /**
   * Returns the HTTP status code associated with this exception instance.
   *
   * <p>This override returns {@code 403} (Forbidden) to indicate that the request is understood but
   * not allowed in the current authorization context. The base class continues to carry the
   * human-readable message and optional location hint, which can be used when rendering an
   * HTTP-facing error response.
   *
   * @return the HTTP status code {@code 403} (Forbidden).
   */
  @Override
  public short code() {
    return 403; // Access Denied
  }

  /**
   * Creates a new exception instance representing an HTTP 403 (Forbidden) error.
   *
   * <p>This constructor stores the provided values as-is and delegates to {@link
   * PluginHTTPException#PluginHTTPException(String, String)}. Neither parameter is validated or
   * normalized; both may be {@code null}. Callers that render the exception should tolerate missing
   * values and should keep the provided data safe for display in HTTP-facing output.
   *
   * <pre>{@code
   * throw new AccessDeniedPluginHTTPException("Not authorized to access this resource", "/path");
   * }</pre>
   *
   * @param errorMessage human-readable description suitable for surfacing in an HTTP response.
   * @param location opaque hint identifying where the access check failed, as understood by caller.
   */
  public AccessDeniedPluginHTTPException(String errorMessage, String location) {
    super(errorMessage, location);
  }
}
