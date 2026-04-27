package network.crypta.platform.api;

/**
 * Identity category used for Platform API authorization decisions.
 *
 * <p>The current Platform API distinguishes trusted local host/operator requests from
 * app-originated process requests. Host/operator authorization remains the legacy local-management
 * model, while app principals are capability checked against manifest-declared permissions.
 *
 * <p>The type is intentionally independent of the transport source. A bridge can record how a
 * principal was established with {@link PlatformApiAuthSource}, while the router uses this enum to
 * choose the authorization path. That separation keeps the model ready for future transport sources
 * without changing the current app-principal default-deny rule.
 */
public enum PlatformApiPrincipalType {
  /**
   * Trusted local operator request accepted by the host-facing transport bridge.
   *
   * <p>This category keeps existing local Web Shell and management flows working. It does not carry
   * app permissions and is not audited as app-originated traffic by the app audit log.
   */
  HOST_OPERATOR,

  /**
   * Request authenticated as a running app process.
   *
   * <p>App principals are authorized against the immutable manifest permissions attached to the
   * principal. They are denied by default when a route is not mapped or the required capability is
   * absent.
   */
  APP
}
