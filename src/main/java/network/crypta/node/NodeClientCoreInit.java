package network.crypta.node;

import network.crypta.clients.http.SimpleToadletServer;
import network.crypta.config.Config;
import network.crypta.config.SubConfig;

/** Bundles configuration inputs required to initialize {@link NodeClientCore}. */
public final class NodeClientCoreInit {
  private final Config config;
  private final SubConfig nodeConfig;
  private final SubConfig installConfig;
  private final SimpleToadletServer toadlets;

  public NodeClientCoreInit(
      Config config, SubConfig nodeConfig, SubConfig installConfig, SimpleToadletServer toadlets) {
    this.config = config;
    this.nodeConfig = nodeConfig;
    this.installConfig = installConfig;
    this.toadlets = toadlets;
  }

  public Config getConfig() {
    return config;
  }

  public SubConfig getNodeConfig() {
    return nodeConfig;
  }

  public SubConfig getInstallConfig() {
    return installConfig;
  }

  public SimpleToadletServer getToadlets() {
    return toadlets;
  }
}
