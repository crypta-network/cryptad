package network.crypta.clients.http;

import java.util.Objects;
import network.crypta.runtime.spi.ConfigPort;
import network.crypta.runtime.spi.ConnectionsPagePort;
import network.crypta.runtime.spi.NodeInfoPort;
import network.crypta.runtime.spi.PeerPort;

/**
 * Shared runtime-port bundle used by HTTP connections toadlets.
 *
 * <p>Darknet and opennet connections pages both require the same detached runtime services for page
 * rendering, peer updates, noderef export, and config lookups. Grouping these collaborators keeps
 * constructor signatures small while preserving the existing split between generic connections-page
 * behavior and network-specific extensions.
 *
 * <p>This record is package-private because it is only a wiring convenience for the HTTP layer. It
 * does not define a new cross-module abstraction, and it deliberately avoids pulling darknet-only
 * helpers into the shared base toadlet constructor. Instances are immutable after construction and
 * can be shared safely across long-lived toadlet instances because they contain only stable runtime
 * service references.
 *
 * @param connectionsPage read-only page-rendering port for detached peer snapshots.
 * @param peerPort peer-management port used for additions and updates.
 * @param nodeInfoPort node-info port used for local noderef export.
 * @param configPort config port used for connections-page settings.
 */
record ConnectionsToadletRuntimePorts(
    ConnectionsPagePort connectionsPage,
    PeerPort peerPort,
    NodeInfoPort nodeInfoPort,
    ConfigPort configPort) {
  /**
   * Creates one shared runtime-port bundle for connections toadlets.
   *
   * <p>All components are required because the base connections-page flow can exercise any of them
   * during rendering, noderef export, add-peer handling, or follow-up configuration reads.
   *
   * @throws NullPointerException if any required runtime port reference is {@code null}
   */
  ConnectionsToadletRuntimePorts {
    Objects.requireNonNull(connectionsPage);
    Objects.requireNonNull(peerPort);
    Objects.requireNonNull(nodeInfoPort);
    Objects.requireNonNull(configPort);
  }
}
