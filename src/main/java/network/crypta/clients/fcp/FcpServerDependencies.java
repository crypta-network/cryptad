package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.runtime.spi.RuntimePorts;

/**
 * Core node services required to construct an {@link FCPServer}.
 *
 * @param node owning {@link Node} providing executors and lifecycle hooks.
 * @param core node client core exposing persistence, download directories, and cache factories.
 * @param runtimePorts runtime SPI bridge for infrastructure code that avoids daemon internals.
 * @param persistentRoot persistence root used to access global clients and caches.
 */
public record FcpServerDependencies(
    Node node,
    NodeClientCore core,
    RuntimePorts runtimePorts,
    PersistentRequestRoot persistentRoot) {}
