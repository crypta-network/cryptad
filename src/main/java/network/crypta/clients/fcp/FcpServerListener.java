package network.crypta.clients.fcp;

import java.net.Socket;
import network.crypta.io.NetworkInterface;
import network.crypta.io.SSLNetworkInterface;
import network.crypta.node.Node;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.tanukisoftware.wrapper.WrapperManager;

final class FcpServerListener implements Runnable {
  private static final Logger LOG = LoggerFactory.getLogger(FcpServerListener.class);

  private static boolean ssl = false;

  private final FCPServer server;
  private final Node node;
  private final int port;
  private final boolean enabled;
  private final String allowedHosts;
  private String bindTo;
  private NetworkInterface networkInterface;

  FcpServerListener(FCPServer server, Node node, FcpServerConfig config) {
    this.server = server;
    this.node = node;
    this.port = config.port();
    this.enabled = config.enabled();
    this.allowedHosts = config.allowedHosts();
    this.bindTo = config.bindTo();
  }

  static boolean isSslEnabled() {
    return ssl;
  }

  static void setSslEnabled(boolean enabled) {
    ssl = enabled;
  }

  @SuppressWarnings("SameParameterValue")
  String[] setBindTo(String value, boolean update) {
    return networkInterface.setBindTo(value, update);
  }

  void updateBindTo(String value) {
    this.bindTo = value;
  }

  String getAllowedHosts() {
    NetworkInterface netIface = networkInterface;
    return netIface == null ? NetworkInterface.DEFAULT_BIND_TO : netIface.getAllowedHosts();
  }

  void setAllowedHosts(String value) {
    networkInterface.setAllowedHosts(value);
  }

  private void maybeGetNetworkInterface() {
    if (this.networkInterface != null) return;

    NetworkInterface tempNetworkInterface;
    if (ssl) {
      tempNetworkInterface =
          SSLNetworkInterface.create(port, bindTo, allowedHosts, node.network().executor(), true);
    } else {
      tempNetworkInterface =
          NetworkInterface.create(port, bindTo, allowedHosts, node.network().executor(), true);
    }

    this.networkInterface = tempNetworkInterface;
  }

  void maybeStart() {
    if (this.enabled) {
      maybeGetNetworkInterface();

      LOG.info("Starting FCP server on {}:{}.", bindTo, port);

      if (this.networkInterface != null) {
        Thread t = new Thread(server, "FCP server");
        t.setDaemon(true);
        t.start();
      }
    } else {
      LOG.info("Not starting FCP server as it's disabled");
      this.networkInterface = null;
    }
  }

  @Override
  public void run() {
    while (true) {
      try {
        networkInterface.waitBound();
        realRun();
      } catch (Exception e) {
        LOG.error("Caught {}", e, e);
      }
      if (WrapperManager.hasShutdownHookBeenTriggered()) return;
    }
  }

  private void realRun() {
    if (!node.isHasStarted()) return;
    Socket s = networkInterface.accept();
    FCPConnectionHandler ch = new FCPConnectionHandler(s, server);
    ch.start();
  }
}
