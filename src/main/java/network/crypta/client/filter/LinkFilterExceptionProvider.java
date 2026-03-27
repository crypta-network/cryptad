package network.crypta.client.filter;

import java.net.URI;

/**
 * Supplies link filter exception decisions to components that perform content filtering.
 *
 * <p>This interface abstracts the policy that decides whether a particular {@link URI} should be
 * exempt from the link/content filtering pipeline. Client code that needs to evaluate links before
 * serving or fetching content can depend on this contract without tying itself to a specific HTTP
 * server or request handling implementation. A typical call pattern is that a request handler
 * inspects a candidate link and queries this provider to determine if the link must bypass
 * filtering; the handler then either forwards unmodified or applies the filter accordingly.
 *
 * <p>Thread-safety and mutability characteristics depend on the concrete implementation. Callers
 * should treat providers as read‑only decision services. Implementations may consult configuration
 * or per-request context, but consumers should not assume caching or idempotency beyond the single
 * invocation.
 *
 * <ul>
 *   <li>Responsibility: Answer whether a specific link is excluded from filtering.
 *   <li>Scope: Only makes the exception decision; does not perform filtering.
 *   <li>Usage: Query per link as part of request handling or preflight checks.
 * </ul>
 *
 * @author <a href="mailto:bombe@pterodactylus.net">David ‘Bombe’ Roden</a>
 */
public interface LinkFilterExceptionProvider {

  /**
   * Determines whether the supplied link is exempt from content filtering.
   *
   * <p>The decision typically reflects policy exposed by the target handler or server‑level
   * configuration. Callers should invoke this method for each candidate link they intend to process
   * and act on the result immediately; the outcome is not guaranteed to be stable across requests
   * if the policy is dynamic. Implementations are expected to be side‑effect-free and execute
   * quickly; however, consult documentation of the concrete provider for any additional performance
   * considerations.
   *
   * <p>Idempotency: Repeated calls with the same input during a single evaluation phase are
   * expected to return the same boolean answer.
   *
   * @param link the absolute or server‑relative {@link URI} to check against the exception policy;
   *     must not be {@code null}; callers should reject opaque or malformed URIs upstream before
   *     invoking this method
   * @return {@code true} when filtering must be bypassed for this link and the request may proceed
   *     unfiltered; {@code false} when the standard filtering pipeline should process the link
   */
  boolean isLinkExcepted(URI link);
}
