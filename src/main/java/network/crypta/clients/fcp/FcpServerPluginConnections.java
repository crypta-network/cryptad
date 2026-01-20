package network.crypta.clients.fcp;

import java.io.IOException;
import java.util.UUID;
import network.crypta.clients.fcp.FCPPluginConnection.SendDirection;
import network.crypta.node.Node;
import network.crypta.pluginmanager.FredPluginFCPMessageHandler.ClientSideFCPMessageHandler;
import network.crypta.pluginmanager.PluginNotFoundException;

final class FcpServerPluginConnections {
  private final Node node;
  private final FCPPluginConnectionTracker pluginConnectionTracker;

  FcpServerPluginConnections(Node node) {
    this.node = node;
    this.pluginConnectionTracker = new FCPPluginConnectionTracker();
  }

  void startTrackerIfEnabled() {
    if (node.services().pluginManager().isEnabled()) {
      pluginConnectionTracker.start();
    }
  }

  FCPPluginConnectionImpl createFCPPluginConnectionForNetworkedFCP(
      String serverPluginName, FCPConnectionHandler messageHandler) throws PluginNotFoundException {
    return FCPPluginConnectionImpl.constructForNetworkedFCP(
        pluginConnectionTracker,
        node.network().executor(),
        node.services().pluginManager(),
        serverPluginName,
        messageHandler);
  }

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

  FCPPluginConnection getPluginConnectionByID(UUID connectionID) throws IOException {
    return pluginConnectionTracker
        .getConnection(connectionID)
        .getDefaultSendDirectionAdapter(SendDirection.TO_CLIENT);
  }
}
