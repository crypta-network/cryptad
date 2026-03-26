package network.crypta.runtime.endpoints.http;

import java.io.File;
import java.util.Objects;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.clients.http.FProxyFetchTracker;
import network.crypta.clients.http.FProxyRuntimeSupport;
import network.crypta.clients.http.FProxyToadlet;
import network.crypta.clients.http.HttpShellFProxyBootstrap;
import network.crypta.clients.http.HttpShellRuntimeSupport;
import network.crypta.clients.http.SimpleToadletServer;
import network.crypta.clients.http.bookmark.BookmarkManager;
import network.crypta.config.Config;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestClientBuilder;
import network.crypta.node.RequestStarter;
import network.crypta.node.SecurityLevels.NETWORK_THREAT_LEVEL;
import network.crypta.node.SecurityLevels.PHYSICAL_THREAT_LEVEL;
import network.crypta.runtime.alerts.UserAlertManager;
import network.crypta.runtime.endpoints.http.bookmark.CoreBookmarkRuntimeSupport;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.support.Ticker;

/**
 * Adapts {@link NodeClientCore} to the narrow runtime surface used by {@link SimpleToadletServer}.
 *
 * <p>This record keeps the remaining HTTP-shell coupling under runtime-owned HTTP endpoint
 * bootstrap code instead of letting the server reach directly into the daemon core. Callers
 * normally create one instance during a server bootstrap and then treat it as an immutable
 * delegate. The adapter is intentionally HTTP-local rather than a reusable platform API: it still
 * exposes alerts, config storage, upload permission checks, and FProxy bootstrap work because those
 * behaviors remain part of the HTTP shell in the current architecture.
 *
 * @param core daemon core that backs delegated shell services and FProxy bootstrap wiring
 */
public record CoreHttpShellRuntimeSupport(NodeClientCore core) implements HttpShellRuntimeSupport {
  /**
   * Creates a core-backed HTTP runtime adapter.
   *
   * <p>The supplied daemon core must stay valid for the lifetime of the surrounding HTTP shell.
   * This adapter retains the reference and delegates every runtime operation to it.
   *
   * @param core daemon core that supplies the shell-level runtime services
   * @throws NullPointerException if {@code core} is {@code null}
   */
  public CoreHttpShellRuntimeSupport(NodeClientCore core) {
    this.core = Objects.requireNonNull(core);
  }

  @Override
  public RuntimePorts runtimePorts() {
    return core.getRuntimePorts();
  }

  @Override
  public Config config() {
    return core.getNode().getConfig();
  }

  @Override
  public Ticker ticker() {
    return core.getNode().network().ticker();
  }

  @Override
  public UserAlertManager userAlerts() {
    return core.getAlerts();
  }

  @Override
  public String formPassword() {
    return core.getFormPassword();
  }

  @Override
  public boolean allowUploadFrom(File filename) {
    return core.allowUploadFrom(filename);
  }

  @Override
  public void storeConfig() {
    config().store();
  }

  @Override
  public boolean canRedirectToWizard() {
    return true;
  }

  @Override
  public void addNetworkThreatLevelListener(ThreatLevelListener<NetworkThreatLevel> listener) {
    Objects.requireNonNull(listener);
    core.getNode()
        .services()
        .securityLevels()
        .addNetworkThreatLevelListener(
            (oldLevel, newLevel) ->
                listener.onChange(
                    mapNetworkThreatLevel(oldLevel), mapNetworkThreatLevel(newLevel)));
  }

  @Override
  public void addPhysicalThreatLevelListener(ThreatLevelListener<PhysicalThreatLevel> listener) {
    Objects.requireNonNull(listener);
    core.getNode()
        .services()
        .securityLevels()
        .addPhysicalThreatLevelListener(
            (oldLevel, newLevel) ->
                listener.onChange(
                    mapPhysicalThreatLevel(oldLevel), mapPhysicalThreatLevel(newLevel)));
  }

  @Override
  public HttpShellFProxyBootstrap createFProxyBootstrap(boolean publicGatewayMode) {
    BookmarkManager bookmarkManager =
        new BookmarkManager(
            new CoreBookmarkRuntimeSupport(core), core.getAlerts(), publicGatewayMode);
    HighLevelSimpleClient client =
        core.makeClient(RequestStarter.INTERACTIVE_PRIORITY_CLASS, true, true);
    FProxyFetchTracker fetchTracker =
        new FProxyFetchTracker(
            core.getClientContext(),
            client.getFetchContext(),
            new RequestClientBuilder().realTime().build());
    FProxyRuntimeSupport fproxyRuntimeSupport = new CoreFProxyRuntimeSupport(core);
    HttpShellFProxyBootstrap bootstrap =
        HttpShellFProxyBootstrap.create(
            bookmarkManager, client, fproxyRuntimeSupport, fetchTracker);
    FProxyToadlet fproxy = bootstrap.fproxy();
    core.getEndpoints().setFProxy(fproxy);
    return bootstrap;
  }

  /**
   * Maps daemon network threat levels into the detached enum used by the HTTP shell.
   *
   * @param threatLevel daemon threat level reported by node security listeners
   * @return matching HTTP-local threat level value for shell callbacks
   */
  private static NetworkThreatLevel mapNetworkThreatLevel(NETWORK_THREAT_LEVEL threatLevel) {
    return switch (threatLevel) {
      case LOW -> NetworkThreatLevel.LOW;
      case NORMAL -> NetworkThreatLevel.NORMAL;
      case HIGH -> NetworkThreatLevel.HIGH;
      case MAXIMUM -> NetworkThreatLevel.MAXIMUM;
    };
  }

  /**
   * Maps daemon physical threat levels into the detached enum used by the HTTP shell.
   *
   * @param threatLevel daemon threat level reported by node security listeners
   * @return matching HTTP-local threat level value for shell callbacks
   */
  private static PhysicalThreatLevel mapPhysicalThreatLevel(PHYSICAL_THREAT_LEVEL threatLevel) {
    return switch (threatLevel) {
      case LOW -> PhysicalThreatLevel.LOW;
      case NORMAL -> PhysicalThreatLevel.NORMAL;
      case HIGH -> PhysicalThreatLevel.HIGH;
      case MAXIMUM -> PhysicalThreatLevel.MAXIMUM;
    };
  }
}
