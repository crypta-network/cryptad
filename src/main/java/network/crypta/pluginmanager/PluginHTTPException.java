package network.crypta.pluginmanager;

import java.io.Serial;

/**
 * Exception type used to represent an HTTP-facing failure raised by a plugin.
 *
 * <p>This exception is intended to be thrown from code paths that are preparing an HTTP response
 * and need a structured way to communicate an HTTP status code together with a human-readable
 * message and (optionally) a caller-supplied location hint. The default implementation returns
 * {@code 400} (Bad Request) via {@link #code()}, but subclasses may override {@link #code()} to map
 * the same exception shape to a different HTTP status without changing how the message and location
 * are carried.
 *
 * <p>Instances are immutable after construction and are therefore safe to share between threads.
 * Callers should treat {@link #message} and {@link #location} as display-oriented data and avoid
 * embedding sensitive values, since the typical use is to surface them in a user interface or over
 * an HTTP API.
 *
 * <ul>
 *   <li><b>Message</b>: a short description of what went wrong (caller-provided).
 *   <li><b>Location</b>: an opaque hint identifying where the error applies (caller-provided).
 *   <li><b>Status</b>: returned by {@link #code()} and used when forming the HTTP response.
 * </ul>
 *
 * @author Florent Daigni&egrave;re &lt;nextgens@freenetproject.org&gt;
 */
public class PluginHTTPException extends Exception {
  @Serial private static final long serialVersionUID = -1;

  /**
   * Human-readable description of the failure, intended for display in HTTP-facing output.
   *
   * <p>This value is stored exactly as provided to the constructor and is immutable thereafter. It
   * may be {@code null} if the caller passes {@code null}; callers that render it should handle the
   * absence of a message gracefully.
   */
  public final String message;

  /**
   * Opaque location hint associated with this error, such as a field, path, or other identifier.
   *
   * <p>This value is stored exactly as provided to the constructor and is immutable thereafter. It
   * may be {@code null} if no location information is available or if the caller passes {@code
   * null}.
   */
  public final String location;

  /**
   * Returns the HTTP status code associated with this exception instance.
   *
   * <p>The base implementation returns {@code 400} (Bad Request), which is appropriate for
   * request-validation failures and other client-originated errors. Subclasses may override this
   * method to return a more specific status code while continuing to use the same {@link #message}
   * and {@link #location} fields for response construction.
   *
   * @return an HTTP status code to use when forming the corresponding HTTP response.
   */
  public short code() {
    return 400; // Bad Request
  }

  /**
   * Creates a new exception instance with the given display message and location hint.
   *
   * <p>This constructor performs no validation or normalization of its inputs; it stores them as-is
   * so that the caller controls the exact text and identifier to expose. Both parameters are
   * permitted to be {@code null}; code that renders the exception should treat missing values as
   * "unknown" rather than failing.
   *
   * <pre>{@code
   * throw new PluginHTTPException("Missing required parameter", "someParameter");
   * }</pre>
   *
   * @param errorMessage human-readable description suitable for surfacing in an HTTP response.
   * @param location opaque hint identifying where the error applies, as understood by the caller.
   */
  public PluginHTTPException(String errorMessage, String location) {
    this.message = errorMessage;
    this.location = location;
  }
}
