package network.crypta.clients.fcp;

import java.io.IOException;
import java.util.UUID;
import network.crypta.clients.fcp.FCPPluginConnection.SendDirection;
import network.crypta.node.Node;
import network.crypta.pluginmanager.FredPluginFCPMessageHandler.ClientSideFCPMessageHandler;
import network.crypta.pluginmanager.PluginNotFoundException;

/**
 * Coordinates plugin-oriented FCP connections for both networked and in-process callers.
 *
 * <p>This helper owns a {@link FCPPluginConnectionTracker} and exposes factory methods that bridge
 * plugin endpoints with FCP message handlers. It supports two modes: networked FCP connections that
 * are backed by TCP sockets and intra-node connections that remain in process. Callers typically
 * construct the helper alongside {@link FCPServer} startup and invoke {@link
 * #startTrackerIfEnabled()} once, then create connections as plugins request them.
 *
 * <p>The tracker stores weak references to connection instances, so callers must hold a strong
 * reference to keep a connection alive. This class is not responsible for plugin lifecycles; it
 * simply wires the node’s plugin manager and executor into the connection factory methods.
 *
 * <ul>
 *   <li>Starts the plugin connection tracker when plugins are enabled.
 *   <li>Creates networked and intra-node plugin connections with proper direction adapters.
 *   <li>Resolves existing connections by identifier for server-to-client messaging.
 * </ul>
 *
 * @see FCPServer
 * @see FCPPluginConnectionTracker
 * @see FCPPluginConnectionImpl
 */
final class FcpServerPluginConnections {
  /** Node providing executors and plugin management services. */
  private final Node node;

  /** Tracker storing weak references to active plugin connections. */
  private final FCPPluginConnectionTracker pluginConnectionTracker;

  /**
   * Creates a plugin-connection helper for the given node.
   *
   * <p>The constructor instantiates a new tracker but does not start it; callers should invoke
   * {@link #startTrackerIfEnabled()} after plugin services are initialized.
   *
   * @param node node supplying executors and plugin manager access; must not be {@code null}.
   */
  FcpServerPluginConnections(Node node) {
    this.node = node;
    this.pluginConnectionTracker = new FCPPluginConnectionTracker();
  }

  /**
   * Starts the underlying tracker when the plugin manager is enabled.
   *
   * <p>When plugins are disabled, the method does nothing. It is safe to call repeatedly; the
   * tracker will ignore redundant starts.
   */
  void startTrackerIfEnabled() {
    if (node.services().pluginManager().isEnabled()) {
      pluginConnectionTracker.start();
    }
  }

  /**
   * Creates a network-backed plugin connection for an external FCP client.
   *
   * <p>The returned connection is registered with the tracker and must be held by the caller to
   * keep it alive. It is configured so messages flow to the server-side plugin identified by {@code
   * serverPluginName}.
   *
   * @param serverPluginName plugin name that will receive server-side messages.
   * @param messageHandler network connection handler responsible for I/O.
   * @return connection instance registered with the tracker and backed by the network handler.
   * @throws PluginNotFoundException when the target plugin cannot be resolved or instantiated.
   */
  FCPPluginConnectionImpl createFCPPluginConnectionForNetworkedFCP(
      String serverPluginName, FCPConnectionHandler messageHandler) throws PluginNotFoundException {
    return FCPPluginConnectionImpl.constructForNetworkedFCP(
        pluginConnectionTracker,
        node.network().executor(),
        node.services().pluginManager(),
        serverPluginName,
        messageHandler);
  }

  /**
   * Creates an in-process plugin connection for intra-node messaging.
   *
   * <p>The returned connection is adapted, so the default send direction is toward the server-side
   * plugin, matching the expectations of a client-side plugin. Callers must keep a strong reference
   * to prevent the tracker from discarding the connection.
   *
   * @param serverPluginName plugin name that will receive server-side messages.
   * @param messageHandler client-side message handler that processes responses.
   * @return adapter configured to send it toward the server-side plugin by default.
   * @throws PluginNotFoundException when the target plugin cannot be resolved or instantiated.
   */
  FCPPluginConnection createFCPPluginConnectionForIntraNodeFCP(
      String serverPluginName, ClientSideFCPMessageHandler messageHandler)
      throws PluginNotFoundException {
    FCPPluginConnectionImpl connection =
        FCPPluginConnectionImpl.constructForIntraNodeFCP(
            pluginConnectionTracker,
            node.network().executor(),
            node.services().pluginManager(),
            serverPluginName,
            messageHandler);
    return connection.getDefaultSendDirectionAdapter(SendDirection.TO_SERVER);
  }

  /**
   * Resolves an existing plugin connection and adapts it for server-to-client messaging.
   *
   * @param connectionID identifier returned when the connection was created.
   * @return connection adapter configured to send toward the client side by default.
   * @throws IOException when the connection cannot be resolved or is inaccessible.
   */
  FCPPluginConnection getPluginConnectionByID(UUID connectionID) throws IOException {
    return pluginConnectionTracker
        .getConnection(connectionID)
        .getDefaultSendDirectionAdapter(SendDirection.TO_CLIENT);
  }
}
