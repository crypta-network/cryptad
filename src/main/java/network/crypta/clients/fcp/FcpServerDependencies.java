package network.crypta.clients.fcp;

import network.crypta.node.NodeClientCore;
import network.crypta.runtime.spi.RuntimePorts;

/**
 * Core node services required to construct an {@link FCPServer}.
 *
 * @param core node client core exposing persistence, download directories, and cache factories.
 * @param runtimePorts runtime SPI bridge for infrastructure code that avoids daemon internals.
 * @param persistentRoot persistence root used to access global clients and caches.
 */
public record FcpServerDependencies(
    NodeClientCore core, RuntimePorts runtimePorts, PersistentRequestRoot persistentRoot) {}
