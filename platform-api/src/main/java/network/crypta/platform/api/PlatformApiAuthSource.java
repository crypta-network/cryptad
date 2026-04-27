package network.crypta.platform.api;

/**
 * Transport-side mechanism that established a Platform API principal.
 *
 * <p>The source is recorded separately from the principal type so tests and diagnostics can
 * distinguish legacy local host access from launch-token based app access without carrying raw
 * credentials through the transport-neutral API layer.
 *
 * <p>This enum describes how trust was established, not which authorization policy applies. The
 * policy still follows the principal type: host/operator requests keep the existing local
 * management behavior, while app principals are checked against manifest-declared capabilities.
 * Keeping the source explicit helps bridges and tests verify that raw bearer tokens were consumed
 * before a request reached the router.
 */
public enum PlatformApiAuthSource {
  /**
   * Legacy local host/operator access accepted by the HTTP bridge.
   *
   * <p>This value represents the current trusted local management model. It does not imply a named
   * human user or role because host/operator RBAC is outside the app-permission enforcement phase.
   */
  HOST_LOCAL,

  /**
   * Opaque AppHost launch token verified by the transport bridge.
   *
   * <p>Requests with this source must carry only a token-free app principal after authentication.
   * The raw token remains in the transport layer and must not appear in router state, audit events,
   * JSON responses, or Web Shell bootstrap data.
   */
  APP_TOKEN,

  /**
   * No authenticated identity was established.
   *
   * <p>This value is available for tests and failure paths that need to model authentication before
   * the bridge can construct a usable principal. Normal routed requests should use either
   * host-local or app-token sources.
   */
  UNAUTHENTICATED
}
