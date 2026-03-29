package network.crypta.runtime.admin;

import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.runtime.admin.geoip.GeoIpCountryLookup;
import network.crypta.runtime.endpoints.fcp.FcpQueuePorts;
import network.crypta.runtime.endpoints.http.geoip.HttpGeoIpCountryLookups;

/**
 * Creates the legacy admin and page-oriented runtime SPI adapters as one package-owned bundle.
 *
 * <p>This factory keeps the construction details for the transitional admin cluster inside {@code
 * network.crypta.runtime.admin}. The surrounding runtime-core wiring only needs to know that there
 * is one coherent group of page, queue, statistics, and welcome adapters that depend on the live
 * daemon {@link Node} and {@link NodeClientCore}. That keeps the move mechanical in this PR while
 * making the ownership boundary explicit for later extraction work.
 *
 * <p>The factory is intentionally small. It does not cache adapters, interpret the daemon state, or
 * add policy on top of the existing constructors. Each call creates a fresh immutable {@link
 * AdminRuntimePortsBundle} whose members preserve the legacy adapter behavior and lifecycle
 * expectations.
 */
public final class AdminRuntimePortsFactory {
  private AdminRuntimePortsFactory() {}

  /**
   * Creates the admin/page runtime-port bundle backed by the current daemon node and client core.
   *
   * <p>Callers normally invoke this once while assembling {@link
   * network.crypta.runtime.core.LegacyRuntimePorts}. The returned bundle contains the exact legacy
   * adapter set that was moved out of {@code network.crypta.runtime.core}, with queue-oriented
   * adapters bound to {@code core} and page or node-state adapters bound to {@code node}. The
   * method performs no validation beyond the constructors it delegates to.
   *
   * @param node live daemon node used by node-backed admin adapters and page state lookups
   * @param core live client core used by queue, wizard, and persistence-oriented adapters
   * @return immutable bundle containing the moved admin and page-oriented runtime adapters
   */
  public static AdminRuntimePortsBundle create(Node node, NodeClientCore core) {
    FcpQueuePorts.Bundle queuePorts = FcpQueuePorts.create(core);
    GeoIpCountryLookup geoIpCountryLookup = HttpGeoIpCountryLookups.forNode(node);
    return new AdminRuntimePortsBundle(
        new LegacyConnectionsPagePort(node, geoIpCountryLookup),
        new LegacyConnectionsSupportPort(node),
        new LegacyDarknetConnectionsPort(node),
        new LegacyDarknetMessagingPort(node),
        new LegacyDiagnosticPort(node, core, queuePorts.adminBackend()),
        new LegacyPageChromePort(node),
        queuePorts.completionPort(),
        new LegacyQueuePagePort(core, queuePorts.pageBackend()),
        queuePorts.downloadPort(),
        queuePorts.insertPort(),
        new LegacyQueueMutationPort(queuePorts.adminBackend()),
        new LegacyQueueSupportPort(core, queuePorts.adminBackend()),
        new LegacyStatisticsPort(node, core),
        new LegacyFirstTimeWizardPort(node, core),
        new LegacyToadletSymlinkPort(node, core),
        new LegacyWelcomePagePort(node),
        new LegacyWelcomeActionPort(node));
  }
}
