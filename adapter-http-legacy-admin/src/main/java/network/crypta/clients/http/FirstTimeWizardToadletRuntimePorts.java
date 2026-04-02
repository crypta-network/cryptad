package network.crypta.clients.http;

import java.util.Objects;
import network.crypta.runtime.spi.FirstTimeWizardPort;

/**
 * Shared runtime-port bundle used by the legacy first-time wizard toadlet.
 *
 * <p>The legacy multipage wizard still owns its HTTP routing, redirects, and most config writes,
 * but its remaining live daemon interactions now route through the existing first-time-wizard SPI.
 * Grouping that collaborator keeps the toadlet constructor narrow without threading the full
 * runtime aggregate through the HTTP layer.
 *
 * @param firstTimeWizardPort detached wizard runtime used by the legacy multipage wizard
 */
record FirstTimeWizardToadletRuntimePorts(FirstTimeWizardPort firstTimeWizardPort) {
  /**
   * Creates the legacy wizard's HTTP-local runtime bundle.
   *
   * <p>The compact constructor enforces the invariant that every collaborator needed by the legacy
   * multipage wizard is present up front. That keeps later request handling code simple: the
   * toadlet and step helpers can dereference the record components without repeating null checks or
   * partially constructing fallback behavior.
   *
   * @throws NullPointerException if any supplied runtime collaborator is {@code null}
   */
  FirstTimeWizardToadletRuntimePorts {
    Objects.requireNonNull(firstTimeWizardPort);
  }
}
