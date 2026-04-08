package network.crypta.clients.http.bridge;

import java.io.File;
import java.io.IOException;
import java.util.Objects;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.clients.http.FProxyFetchTracker;
import network.crypta.clients.http.FProxyRuntimeSupport;
import network.crypta.clients.http.HttpShellFProxyBootstrap;
import network.crypta.clients.http.HttpShellRuntimeSupport;
import network.crypta.clients.http.SimpleToadletServer;
import network.crypta.clients.http.bookmark.BookmarkManager;
import network.crypta.clients.http.bridge.bookmark.CoreBookmarkRuntimeSupport;
import network.crypta.config.Config;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestClientBuilder;
import network.crypta.node.RequestStarter;
import network.crypta.node.SecurityLevels.NETWORK_THREAT_LEVEL;
import network.crypta.node.SecurityLevels.PHYSICAL_THREAT_LEVEL;
import network.crypta.node.SemiOrderedShutdownHook;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.AppHostLayout;
import network.crypta.platform.apphost.RunningAppSnapshot;
import network.crypta.platform.apphost.runtime.LocalProcessAppHost;
import network.crypta.runtime.alerts.UserAlertManager;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.support.Ticker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Adapts {@link NodeClientCore} to the narrow runtime surface used by {@link SimpleToadletServer}.
 *
 * <p>This record keeps the remaining HTTP-shell coupling inside the adapter-owned HTTP bridge layer
 * instead of letting the server reach directly into the daemon core. Callers normally create one
 * instance during a server bootstrap and then treat it as an immutable delegate. The adapter is
 * intentionally HTTP-local rather than a reusable platform API: it still exposes alerts, config
 * storage, upload permission checks, AppHost access, and FProxy bootstrap work because those
 * behaviors remain part of the HTTP shell in the current architecture.
 *
 * @param core daemon core that backs delegated shell services and FProxy bootstrap wiring
 * @param appHost shared AppHost instance used by the platform control plane
 */
public record CoreHttpShellRuntimeSupport(NodeClientCore core, AppHost appHost)
    implements network.crypta.runtime.http.HttpShellRuntimeSupport, HttpShellRuntimeSupport {
  private static final Logger LOG = LoggerFactory.getLogger(CoreHttpShellRuntimeSupport.class);

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
    this(core, createManagedAppHost(Objects.requireNonNull(core, "core")));
  }

  /**
   * Creates a core-backed HTTP runtime adapter with an explicit AppHost.
   *
   * @param core daemon core that supplies the shell-level runtime services
   * @param appHost shared AppHost instance used by the platform control plane
   * @throws NullPointerException if {@code core} or {@code appHost} is {@code null}
   */
  public CoreHttpShellRuntimeSupport(NodeClientCore core, AppHost appHost) {
    this.core = Objects.requireNonNull(core, "core");
    this.appHost = Objects.requireNonNull(appHost, "appHost");
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
  public AppHost appHost() {
    return appHost;
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
    return HttpShellFProxyBootstrap.create(
        bookmarkManager, client, appHost, fproxyRuntimeSupport, fetchTracker);
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

  /**
   * Creates the shared AppHost instance and registers its shutdown cleanup.
   *
   * @param core daemon core that exposes the current node and temp-directory layout
   * @return managed AppHost instance rooted in the current node layout
   */
  private static AppHost createManagedAppHost(NodeClientCore core) {
    AppHost appHost = createAppHost(core);
    SemiOrderedShutdownHook.get().addEarlyJob(createAppHostShutdownJob(appHost));
    return appHost;
  }

  /**
   * Creates the single AppHost instance shared by the current HTTP bridge.
   *
   * <p>The host is rooted in the live node/core directories that the current daemon instance has
   * already selected. That keeps app installs, cache data, and run files attached to this node
   * rather than a fresh global directory lookup that could ignore per-instance overrides.
   *
   * @param core daemon core that exposes the current node and temp-directory layout
   * @return long-lived AppHost instance rooted in the current node layout
   */
  private static AppHost createAppHost(NodeClientCore core) {
    return new LocalProcessAppHost(
        new AppHostLayout(
            core.getNode().nodeDir().dir().toPath(),
            core.getPersistentTempDir().toPath(),
            core.getNode().runDir().dir().toPath()));
  }

  /**
   * Creates the shutdown job that stops any AppHost-managed child processes on node exit.
   *
   * <p>The shared AppHost is otherwise only reachable through the HTTP runtime support. Registering
   * this early shutdown job keeps app processes from surviving node shutdown and leaving stale run
   * state behind for the next boot.
   *
   * @param appHost shared AppHost instance used by the platform control plane
   * @return unstarted shutdown thread suitable for {@link SemiOrderedShutdownHook}
   */
  static Thread createAppHostShutdownJob(AppHost appHost) {
    Objects.requireNonNull(appHost, "appHost");
    return new Thread(() -> stopRunningAppsOnShutdown(appHost), "Shutdown AppHost");
  }

  private static void stopRunningAppsOnShutdown(AppHost appHost) {
    for (RunningAppSnapshot runningApp : appHost.listRunning()) {
      stopRunningAppOnShutdown(appHost, runningApp);
    }
  }

  private static void stopRunningAppOnShutdown(AppHost appHost, RunningAppSnapshot runningApp) {
    try {
      appHost.stop(runningApp.appId());
    } catch (IOException e) {
      LOG.warn("Failed to stop app during shutdown: {}", runningApp.appId(), e);
    } catch (RuntimeException e) {
      LOG.warn("Unexpected app shutdown failure: {}", runningApp.appId(), e);
    }
  }
}
