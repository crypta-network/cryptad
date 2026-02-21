package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;

/**
 * Core node services required to construct an {@link FCPServer}.
 *
 * @param node owning {@link Node} providing executors and lifecycle hooks.
 * @param core node client core exposing persistence, download directories, and cache factories.
 * @param persistentRoot persistence root used to access global clients and caches.
 */
public record FcpServerDependencies(
    Node node, NodeClientCore core, PersistentRequestRoot persistentRoot) {}
