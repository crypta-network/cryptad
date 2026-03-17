package network.crypta.clients.http;

import java.util.Objects;
import java.util.function.LongSupplier;
import java.util.function.Supplier;
import network.crypta.clients.http.wizardsteps.BandwidthLimit;
import network.crypta.runtime.spi.FirstTimeWizardPort;

/**
 * Shared runtime-port bundle used by the legacy first-time wizard toadlet.
 *
 * <p>The legacy multipage wizard still owns its HTTP routing, redirects, and most config writes,
 * but the bandwidth/datastore slice now reads detached runtime state through the existing
 * first-time-wizard SPI. It also needs the legacy datastore dropdown cap, which still comes from
 * the live store-directory heuristic rather than the shared JavaScript wizard snapshot. Grouping
 * those collaborators keeps the toadlet constructor narrow without threading the full runtime
 * aggregate through the HTTP layer.
 *
 * @param firstTimeWizardPort detached wizard runtime used by the bandwidth and datastore steps
 * @param legacyDatastoreMaxStorageLimitBytes store-dir-aware cap supplier used by the legacy
 *     datastore dropdown to preserve its historical thresholds
 * @param legacyCurrentBandwidthLimits supplier for the legacy rate-page “current settings” row,
 *     backed by the live network subsystem instead of config-derived defaults
 */
record FirstTimeWizardToadletRuntimePorts(
    FirstTimeWizardPort firstTimeWizardPort,
    LongSupplier legacyDatastoreMaxStorageLimitBytes,
    Supplier<BandwidthLimit> legacyCurrentBandwidthLimits) {
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
    Objects.requireNonNull(legacyDatastoreMaxStorageLimitBytes);
    Objects.requireNonNull(legacyCurrentBandwidthLimits);
  }
}
