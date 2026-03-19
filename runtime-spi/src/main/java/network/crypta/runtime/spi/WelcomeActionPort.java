package network.crypta.runtime.spi;

/**
 * Exposes the remaining welcome-page maintenance actions that still need daemon-backed behavior.
 *
 * <p>This SPI exists so the welcome-page HTTP layer can stop reaching into live-daemon objects
 * directly while still preserving the legacy POST/action paths that operators already use. Typical
 * callers read form fields, validate access at the HTTP boundary, and then delegate the daemon-side
 * effect through this port. The implementation keeps the existing update arming, delayed
 * shutdown/restart scheduling, and upgrade-connection-speed behavior in the daemon root module.
 *
 * <p>This is intentionally not a general maintenance or lifecycle API. It stays narrow,
 * page-shaped, and biased toward preserving existing welcome-page semantics rather than introducing
 * a reusable admin surface. Redirect handling, confirmation pages, wrapper integration, and other
 * HTTP concerns remain outside this contract.
 *
 * @see RuntimePorts#welcomeAction()
 */
public interface WelcomeActionPort {
  /**
   * Arms the existing node-update flow from the welcome page.
   *
   * <p>Callers invoke this after the HTTP layer has validated the request and completed whatever
   * confirmation-page rendering or redirect handling is required. Implementations preserve the
   * daemon-side behavior that the legacy welcome page previously reached through direct {@code
   * Node}-level access.
   */
  void armNodeUpdate();

  /**
   * Queues the legacy welcome-page shutdown action.
   *
   * <p>Implementations preserve the existing delayed scheduling semantics used by the welcome page
   * so the HTTP redirect can be sent before the live daemon begins shutting down. The call is
   * intentionally page-scoped: it represents only the welcome-page shutdown flow, not a general
   * node-administration primitive.
   */
  void queueShutdownFromWelcome();

  /**
   * Queues the legacy welcome-page restart action.
   *
   * <p>Implementations preserve the existing delayed scheduling semantics used by the welcome page
   * so the HTTP redirect can be sent before the live daemon begins restarting. As with shutdown,
   * this remains deliberately narrow and models the existing welcome-page action rather than a
   * broader restart API.
   */
  void queueRestartFromWelcome();

  /**
   * Applies the legacy upgrade-connection-speed submission from the welcome page.
   *
   * <p>The supplied values are the raw request parts read by the HTTP layer. Implementations own
   * the legacy validation rules, config writes, alert lookup, and success or error updates on the
   * existing upgrade alert. They also preserve the historical behavior around restart-required
   * configuration changes, so the HTTP layer does not need to know about daemon-side config
   * details.
   *
   * @param inputBandwidthLimit raw download-limit text read from the welcome-page form submission
   * @param outputBandwidthLimit raw upload-limit text read from the welcome-page form submission
   */
  void applyUpgradeConnectionSpeed(String inputBandwidthLimit, String outputBandwidthLimit);
}
