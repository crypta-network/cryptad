package network.crypta.node.runtime;

import java.util.Objects;
import network.crypta.node.DarknetPeerNode;
import network.crypta.node.Node;
import network.crypta.node.OpennetManager;
import network.crypta.node.SecurityLevels;
import network.crypta.runtime.spi.PageChromePort;
import network.crypta.runtime.spi.PageChromeSnapshot;
import network.crypta.runtime.spi.SecurityNetworkThreatLevel;
import network.crypta.runtime.spi.SecurityPhysicalThreatLevel;

/**
 * Adapts the shared page-chrome SPI to the legacy daemon runtime.
 *
 * <p>This adapter keeps the remaining status-bar reads inside the daemon root module, where the
 * legacy {@link Node}, peer roster, opennet manager, and security-level services still live. The
 * HTTP layer can then render the existing shared admin shell from one detached snapshot without
 * traversing live daemon internals directly.
 *
 * <p>The adapter is intentionally conservative. It mirrors the current page chrome only: detached
 * threat-level enums, connected peer counts, enabled-darknet totals, and the opennet target count
 * used by the existing progress bar.
 */
final class LegacyPageChromePort implements PageChromePort {
  /** Live daemon node that remains the source of truth for legacy page-chrome reads. */
  private final Node node;

  /**
   * Creates a legacy adapter backed by the live daemon node.
   *
   * @param node live daemon node that remains the source of truth for shared page-chrome state
   */
  LegacyPageChromePort(Node node) {
    this.node = Objects.requireNonNull(node, "node");
  }

  /** {@inheritDoc} */
  @Override
  public PageChromeSnapshot snapshot() {
    OpennetManager opennet = node.network().opennet();
    return new PageChromeSnapshot(
        mapNetworkThreatLevel(node.services().securityLevels().getNetworkThreatLevel()),
        mapPhysicalThreatLevel(node.services().securityLevels().getPhysicalThreatLevel()),
        node.network().peers().countConnectedPeers(),
        node.network().peers().countConnectedDarknetPeers(),
        node.network().peers().countConnectedOpennetPeers(),
        countEnabledDarknetPeers(),
        opennet != null,
        opennet == null ? 0 : opennet.getNumberOfConnectedPeersToAimIncludingDarknet());
  }

  /**
   * Counts enabled darknet peers for the legacy status-bar target calculation.
   *
   * <p>The legacy shell ignores {@code null} entries and disabled peers when computing the
   * denominator shown for darknet-only operation. This preserves the existing rendering behavior
   * while keeping the roster walk inside the daemon module.
   *
   * @return number of enabled darknet peers currently present in the live roster
   */
  private int countEnabledDarknetPeers() {
    int enabledDarknetPeers = 0;
    for (DarknetPeerNode peer : node.network().peers().roster().getDarknetPeers()) {
      if (peer != null && !peer.isDisabled()) {
        enabledDarknetPeers++;
      }
    }
    return enabledDarknetPeers;
  }

  /**
   * Maps the legacy daemon network threat enum to the detached runtime-spi enum.
   *
   * @param networkThreatLevel live daemon network threat level to translate
   * @return detached enum value with the same semantic posture and name
   */
  private static SecurityNetworkThreatLevel mapNetworkThreatLevel(
      SecurityLevels.NETWORK_THREAT_LEVEL networkThreatLevel) {
    return switch (networkThreatLevel) {
      case LOW -> SecurityNetworkThreatLevel.LOW;
      case NORMAL -> SecurityNetworkThreatLevel.NORMAL;
      case HIGH -> SecurityNetworkThreatLevel.HIGH;
      case MAXIMUM -> SecurityNetworkThreatLevel.MAXIMUM;
    };
  }

  /**
   * Maps the legacy daemon physical threat enum to the detached runtime-spi enum.
   *
   * @param physicalThreatLevel live daemon physical threat level to translate
   * @return detached enum value with the same semantic posture and name
   */
  private static SecurityPhysicalThreatLevel mapPhysicalThreatLevel(
      SecurityLevels.PHYSICAL_THREAT_LEVEL physicalThreatLevel) {
    return switch (physicalThreatLevel) {
      case LOW -> SecurityPhysicalThreatLevel.LOW;
      case NORMAL -> SecurityPhysicalThreatLevel.NORMAL;
      case HIGH -> SecurityPhysicalThreatLevel.HIGH;
      case MAXIMUM -> SecurityPhysicalThreatLevel.MAXIMUM;
    };
  }
}
