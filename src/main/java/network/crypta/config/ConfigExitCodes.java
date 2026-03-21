package network.crypta.config;

/**
 * Defines process exit codes that originate in configuration and wrapper handling.
 *
 * <p>This class gives low-level configuration code a stable place to reference shared numeric exit
 * statuses without depending on broader startup exception types. Keep constants here when the same
 * exit status must be reused by wrapper editing, config persistence, or other early-boot paths that
 * may run before the full node stack is available.
 *
 * <p>The values are process-level contracts rather than user-facing settings. Callers should treat
 * them as stable identifiers that may be surfaced by launch scripts, service managers, or wrapper
 * tooling when startup fails before the daemon becomes operational.
 *
 * @see network.crypta.node.NodeInitException
 */
public final class ConfigExitCodes {
  /**
   * Exit status used when generated or edited {@code wrapper.conf} is invalid and startup cannot
   * safely continue with that file in place.
   */
  public static final int BROKE_WRAPPER_CONF = 28;

  private ConfigExitCodes() {}
}
