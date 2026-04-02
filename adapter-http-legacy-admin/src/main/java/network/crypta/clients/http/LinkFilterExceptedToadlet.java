package network.crypta.clients.http;

import java.net.URI;

/**
 * Declares that a {@link Toadlet} can decide whether incoming links targeting it should bypass the
 * content/link filtering pipeline.
 *
 * <p>The interface is used by HTTP serving components such as {@link SimpleToadletServer} to route
 * filtering decisions back to the addressed toadlet. Implementations typically evaluate whether a
 * link points to administrative resources, trusted local assets, or other URIs that must be served
 * verbatim. Callers query this contract before applying any filter so that exempt links can proceed
 * unchanged while all other traffic remains subject to the standard sanitization steps. Because the
 * decision may depend on per-request context, implementations should document any assumptions about
 * session state or caller identity and ensure that evaluations are quick and side effect free.
 *
 * <p>Thread-safety is determined by the concrete toadlet; many implementations are stateless and
 * therefore safe to use concurrently, but consumers should not assume caching or idempotency beyond
 * the scope of a single request.
 *
 * <ul>
 *   <li>Responsibility: declare if specific links are exempt from filtering.
 *   <li>Typical use: called once per candidate link before filter processing.
 *   <li>Scope: decision only; no filtering or I/O should occur here.
 * </ul>
 *
 * @author <a href="mailto:bombe@pterodactylus.net">David ‘Bombe’ Roden</a>
 * @see network.crypta.client.filter.LinkFilterExceptionProvider
 * @see SimpleToadletServer
 */
public interface LinkFilterExceptedToadlet {

  /**
   * Evaluates whether the supplied link should be served without passing through the filter.
   *
   * <p>Callers invoke this method immediately before running link or content filters so that exempt
   * destinations can be forwarded unchanged. The input is expected to be the exact target of the
   * current request; implementations may consider request context or static policy, but should not
   * mutate shared state or perform expensive I/O while deciding. Repeated calls with the same link
   * during a single request are expected to return consistent results unless the enclosing toadlet
   * documents otherwise.
   *
   * @param link the absolute or server-relative {@link URI} being evaluated for a filtering
   *     exception; must be non-{@code null} and represent the request target
   * @return {@code true} when this toadlet requires the link to bypass filtering; {@code false}
   *     when the normal filtering pipeline should continue to process the link
   */
  boolean isLinkExcepted(URI link);
}
