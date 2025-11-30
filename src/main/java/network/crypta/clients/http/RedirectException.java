package network.crypta.clients.http;

import java.io.Serial;
import java.net.URI;
import java.net.URISyntaxException;

/**
 * Signals to the HTTP toadlet container that a request should be retried against a different target
 * URI while preserving the caller's original HTTP method and request body.
 *
 * <p>This exception is thrown by handlers that want the framework to perform an internal redirect
 * without rewriting the verb to {@code GET}. It is useful when a form submission or streaming POST
 * must be routed to a newer path or another handler instance, and the handler prefers the container
 * to repeat the request instead of issuing a client-visible 3xx response. Instances are immutable
 * and therefore safe to share between threads if needed, although they are normally constructed and
 * consumed on a single request-processing thread.
 *
 * <p>Typical usage flows are:
 *
 * <ul>
 *   <li>Validate the incoming request and compute a replacement URI for the same request method.
 *   <li>Throw this exception with the new {@link URI}; the container catches it and re-dispatches
 *       internally.
 *   <li>Allow the downstream toadlet to decide whether to stream, buffer, or discard the original
 *       entity body.
 * </ul>
 *
 * @author Matthew Toseland &lt;toad@amphibian.dyndns.org&gt; (0xE43DA450)
 * @author xor &lt;xor@freenetproject.org&gt;
 */
public class RedirectException extends Exception {
  @Serial private static final long serialVersionUID = -1;

  /**
   * Immutable target URI supplied by the throwing handler; never rewritten by the container and not
   * normalized beyond {@link URI} construction.
   */
  final URI newuri;

  /**
   * Creates a redirect instruction from a textual URI representation, preserving the caller's HTTP
   * method so POST/PUT requests remain intact during the retry.
   *
   * <p>The provided string is parsed immediately; invalid syntax results in a checked exception to
   * encourage callers to validate inputs before dispatch. Callers commonly build the URI from
   * request context (path segments, query parameters) and should avoid passing user-controlled
   * values without validation to prevent open redirects.
   *
   * @param newURI fully qualified or context-relative URI string indicating the retry destination;
   *     must be valid per {@link URI#URI(String)} and should not be {@code null}
   * @throws URISyntaxException if the supplied text cannot be converted into a legal {@link URI}
   */
  public RedirectException(String newURI) throws URISyntaxException {
    this.newuri = new URI(newURI);
  }

  /**
   * Creates a redirect instruction from a pre-parsed {@link URI}, retaining the original HTTP verb
   * and entity when the container reissues the request.
   *
   * <p>This overload is preferred when the target has already been validated or assembled via URI
   * builders elsewhere in the codebase. The reference is stored as-is; callers should supply an
   * immutable {@link URI} instance and ensure it accurately represents the desired destination to
   * avoid surprising downstream routing.
   *
   * @param newURI resolved and validated target URI to use when the container retries the request;
   *     must not be {@code null}
   */
  public RedirectException(URI newURI) {
    this.newuri = newURI;
  }

  /**
   * Returns the destination URI that the container should use when reissuing the intercepted
   * request with the original HTTP method and body.
   *
   * <p>The returned reference is the same instance provided at construction time; callers must not
   * mutate it if they rely on immutability for thread-safety. Typical handlers extract this value
   * to perform logging or to compare against policy lists before accepting the internal redirect.
   *
   * @return immutable {@link URI} that represents the retry target; never {@code null}
   */
  public URI getTarget() {
    return newuri;
  }
}
