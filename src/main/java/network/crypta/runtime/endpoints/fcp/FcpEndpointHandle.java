package network.crypta.runtime.endpoints.fcp;

import network.crypta.client.async.DownloadCache;

/**
 * Runtime-owned handle for the active FCP endpoint and its download-cache behavior.
 *
 * <p>The runtime-endpoints package depends on this narrow handle rather than directly on the
 * concrete {@code network.crypta.clients.fcp.FCPServer}. Bridge code in this package can still
 * unwrap the legacy server when it needs protocol-specific operations. Higher-level runtime wiring
 * uses the seam only for endpoint lifecycle and cache registration.
 *
 * <p>Typical usage is straightforward: endpoint bootstrap creates one handle, registers it as the
 * {@link DownloadCache}, and later asks it to load persistent requests and maybe start listening.
 * The interface intentionally stays small, so queue behavior, persistence ownership, and
 * protocol-specific administration can remain in the FCP bridge package. Implementations should
 * preserve the wrapped endpoint's existing lifecycle semantics rather than adding retries, caching
 * layers, or alternative startup policy.
 */
public interface FcpEndpointHandle extends DownloadCache {

  /**
   * Loads persistent request state for the wrapped endpoint.
   *
   * <p>Callers typically invoke this during startup once persistence is known to be healthy, so
   * durable FCP requests are available before serving queue and status queries. Implementations are
   * expected to preserve the endpoint's existing loading rules, including how duplicates,
   * checkpointed requests, and database-reset scenarios are handled. The method does not imply that
   * the endpoint will also start listening for new client connections.
   */
  void load();

  /**
   * Starts the wrapped endpoint when configuration allows.
   *
   * <p>Implementations preserve the underlying endpoint's idempotent start behavior and do not
   * promise that a listener will bind when the endpoint is disabled by configuration. Callers may
   * invoke this after dependency wiring is complete and after any required request loading has
   * already happened. The method should not broaden startup policy beyond what the concrete
   * endpoint already does today.
   */
  void maybeStart();
}
