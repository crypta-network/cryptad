package network.crypta.clients.http;

import java.util.Objects;
import network.crypta.runtime.spi.ConfigPort;
import network.crypta.runtime.spi.SecurityLevelsPort;

/**
 * Shared runtime-port bundle used by the legacy security-levels toadlet.
 *
 * <p>The `/seclevels/` page still owns its HTTP branching and HTML generation, but its remaining
 * live daemon touches are now limited to detached runtime collaborators for security-level state
 * and config persistence. Grouping those two ports keeps the constructor narrow without threading
 * the full runtime aggregate into the HTTP layer.
 *
 * @param securityLevelsPort detached security-levels runtime used for threat-level reads, warning
 *     rendering, and master-password mutations
 * @param configPort detached config runtime used to persist the page's existing configuration
 *     writes
 */
record SecurityLevelsToadletRuntimePorts(
    SecurityLevelsPort securityLevelsPort, ConfigPort configPort) {
  /**
   * Creates a runtime-port bundle for the legacy security-levels page.
   *
   * @param securityLevelsPort detached security-levels runtime required by the toadlet
   * @param configPort detached config runtime used after successful mutations
   * @throws NullPointerException if either runtime port reference is {@code null}
   */
  SecurityLevelsToadletRuntimePorts {
    Objects.requireNonNull(securityLevelsPort);
    Objects.requireNonNull(configPort);
  }
}
