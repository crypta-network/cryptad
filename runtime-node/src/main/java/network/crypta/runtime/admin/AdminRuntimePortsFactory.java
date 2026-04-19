package network.crypta.runtime.admin;

import java.util.Objects;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestStarter;
import network.crypta.runtime.alerts.UserAlertManager;
import network.crypta.support.http.HttpFetchSizeLimits;

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
   * adapters bound to {@code core}, page or node-state adapters bound to {@code node}, and
   * bridge-owned construction supplied by the runtime composition root. The method performs no
   * validation beyond the constructors it delegates to.
   *
   * @param node live daemon node used by node-backed admin adapters and page state lookups
   * @param core live client core used by queue, wizard, and persistence-oriented adapters
   * @param bridgeInputs runtime-owned bridge seams and ports constructed by the composition root
   * @return immutable bundle containing the moved admin and page-oriented runtime adapters
   */
  public static AdminRuntimePortsBundle create(
      Node node, NodeClientCore core, AdminRuntimeBridgeInputs bridgeInputs) {
    long maxLengthNoProgress = HttpFetchSizeLimits.getMaxLengthNoProgress();
    HighLevelSimpleClient peerReferenceClient =
        core.makeClient(RequestStarter.INTERACTIVE_PRIORITY_CLASS, true, true);
    peerReferenceClient.setMaxLength(maxLengthNoProgress);
    peerReferenceClient.setMaxIntermediateLength(maxLengthNoProgress);
    UserAlertManager alertManager = Objects.requireNonNull(core.getAlerts(), "alerts");
    LegacyAlertPort alertPort = new LegacyAlertPort(alertManager);
    return new AdminRuntimePortsBundle(
        new LegacyConnectionsPagePort(node, bridgeInputs.geoIpCountryLookup()),
        new LegacyConnectionsSupportPort(node, peerReferenceClient),
        new LegacyDarknetConnectionsPort(node),
        new LegacyDarknetMessagingPort(node),
        alertPort,
        alertPort,
        new LegacyDiagnosticPort(node, core, bridgeInputs.queueAdminBackend()),
        new LegacyPageChromePort(node),
        bridgeInputs.queueCompletionPort(),
        new LegacyQueuePagePort(core, bridgeInputs.queuePageBackend()),
        bridgeInputs.queueDownloadPort(),
        bridgeInputs.queueInsertPort(),
        new LegacyQueueMutationPort(bridgeInputs.queueAdminBackend()),
        new LegacyQueueSupportPort(core, bridgeInputs.queueAdminBackend()),
        new LegacyStatisticsPort(node, core),
        new LegacyFirstTimeWizardPort(node, core),
        new LegacyToadletSymlinkPort(node, core),
        new LegacyWelcomePagePort(node),
        new LegacyWelcomeActionPort(node));
  }
}
