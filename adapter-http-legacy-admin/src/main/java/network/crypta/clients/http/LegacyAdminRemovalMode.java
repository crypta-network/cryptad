package network.crypta.clients.http;

/**
 * Execution policy for a mapped legacy admin surface.
 *
 * <p>This policy is deliberately separate from {@link LegacyAdminRetirementState}. Retirement state
 * records product ownership, while removal mode records what the legacy HTTP adapter should do with
 * direct requests today. That separation lets later waves leave some {@link
 * LegacyAdminRetirementState#PRIMARY_REPLACED} routes renderable while removing a smaller proven
 * subset by default.
 *
 * <p>The values are stable metadata, not request-specific decisions. {@link
 * LegacyAdminRetirementRegistry} assigns one mode to each known surface, and {@link
 * LegacyAdminRemovalPolicy} interprets that mode together with the HTTP method, canonical path, and
 * replacement availability. Diagnostics and release-certification evidence expose the enum name so
 * operators can distinguish product status from current dispatch behavior without inspecting route
 * handlers.
 *
 * <ul>
 *   <li>rendering modes keep old toadlets reachable;
 *   <li>replacement modes stop default rendering for canonical page paths;
 *   <li>retained, pending, and infrastructure modes document why a route stays outside removal.
 * </ul>
 */
public enum LegacyAdminRemovalMode {
  /**
   * Let the registered legacy toadlet render the route.
   *
   * <p>Primary-replaced surfaces in this mode can still render a non-blocking notice that points
   * operators to the Web Shell or app replacement. The mode is appropriate when direct fallback
   * behavior is still intentionally supported.
   */
  RENDER_LEGACY,

  /**
   * Return a replacement redirect for safe read requests and block mutating requests.
   *
   * <p>The removal policy uses this mode for canonical page routes whose replacements are safe to
   * open as normal browser destinations. In wave 1 this usually means a {@code 303 See Other}
   * response to Web Shell, Queue Manager, or Publisher when that destination is available.
   */
  REDIRECT_TO_REPLACEMENT,

  /**
   * Return a gone-with-replacement page for safe read requests and block mutating requests.
   *
   * <p>This mode is available for future routes where a direct redirect would be misleading or
   * unsafe, but the old canonical page should still stop rendering by default. The response body
   * must stay small and contain only the replacement link and explanatory text.
   */
  GONE_WITH_REPLACEMENT,

  /**
   * Keep the route as retained long-term functionality.
   *
   * <p>Retained routes are not removal candidates in the current plan. Browse-owned FProxy routes
   * and browse-adjacent tools use this classification when their legacy behavior remains the
   * intended local interface.
   */
  RETAINED,

  /**
   * Keep the route reachable because replacement work is not complete or not proven.
   *
   * <p>Pending routes can have a planned replacement, but the adapter must continue rendering the
   * legacy handler until startup gates, operator workflows, or compatibility edge cases are proven
   * safe for a later wave.
   */
  PENDING,

  /**
   * Treat the route as support infrastructure rather than a user-facing page.
   *
   * <p>Infrastructure routes can support retained, pending, or replacement pages without being
   * standalone removal targets. The policy does not redirect these entries unless a future wave
   * promotes a specific canonical route into an explicit removal mode.
   */
  INFRASTRUCTURE
}
