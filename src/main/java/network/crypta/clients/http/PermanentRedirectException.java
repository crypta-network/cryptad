package network.crypta.clients.http;

import java.io.Serial;
import java.net.URI;

/**
 * Exception indicating that a request should be retried with a permanent redirect target.
 *
 * <p>This exception is raised by HTTP toadlets that want the calling infrastructure to perform a
 * 301-style reroute while preserving the current method and payload. It carries the destination
 * {@link URI} so callers can update internal dispatch logic without relying on HTTP response
 * bodies. Instances are immutable after construction to ensure that the redirect target observed by
 * error handlers cannot drift during propagation across threads or call boundaries.
 *
 * <p>Typical usage is to throw this exception from handler code when a resource has moved
 * permanently, allowing higher-level routing layers to decide how to inform the client. It may also
 * be instantiated with a {@code null} target when the caller wishes to signal a redirect condition
 * but determine the final location later in the pipeline. Because it extends {@link Exception}, it
 * participates in checked exception handling and should be documented on method signatures where it
 * can surface.
 *
 * <ul>
 *   <li>Responsibility: carry a stable target URI for permanent redirects.
 *   <li>Mutability: all fields are final; instances are thread-safe once constructed.
 *   <li>Error semantics: indicates a recoverable control-flow redirect rather than a failure.
 * </ul>
 */
public class PermanentRedirectException extends Exception {

  @Serial private static final long serialVersionUID = -166786248237623796L;

  /**
   * Target location for the permanent redirect, or {@code null} when the destination is determined
   * lazily. The reference is immutable after construction and may be shared safely across threads
   * by callers that need to inspect or log redirect decisions.
   */
  final URI newuri;

  /**
   * Creates an instance without an immediate redirect target, allowing callers to attach or resolve
   * the destination later in their control flow while still signaling a permanent redirect
   * condition. This is useful for serialization frameworks or guard code that needs to rethrow the
   * exception before the final location is known.
   */
  @SuppressWarnings("unused")
  public PermanentRedirectException() {
    this(null);
  }

  /**
   * Creates an exception that carries the URI to which the current request should be permanently
   * redirected. The supplied value may be {@code null} when the redirect location is optional, but
   * callers typically provide an absolute {@link URI} so the transport layer can instruct clients
   * precisely where to retry the request without mutating the HTTP method.
   *
   * @param newuri absolute or context-resolved {@link URI} designating the permanent redirect
   *     target; may be {@code null} when the destination is deferred to later processing
   */
  public PermanentRedirectException(URI newuri) {
    this.newuri = newuri;
  }
}
