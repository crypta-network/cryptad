package network.crypta.clients.http.bridge;

import java.io.File;
import java.util.Objects;
import network.crypta.client.async.ClientContext;
import network.crypta.clients.http.FProxyRuntimeSupport;
import network.crypta.clients.http.FProxyToadlet;
import network.crypta.config.SubConfig;
import network.crypta.node.NodeClientCore;
import network.crypta.node.SecurityLevels.NETWORK_THREAT_LEVEL;
import network.crypta.node.SecurityLevels.PHYSICAL_THREAT_LEVEL;

/**
 * Core-backed implementation of {@link FProxyRuntimeSupport}.
 *
 * <p>This adapter is the adapter-owned HTTP bridge between {@link FProxyToadlet} and {@link
 * NodeClientCore}. It translates the broad daemon API into the small set of values and callbacks
 * that FProxy currently consumes, including threat-level state, download policy, and the node
 * executor used for background follow-up work. The adapter stays package-private because it is an
 * internal wiring detail of HTTP bridge assembly, not a reusable cross-module contract.
 *
 * <p>The record is immutable after construction and delegates every call directly to the wrapped
 * core. It does not cache mutable security state or configuration snapshots, so callers continue to
 * observe the current daemon settings each time they consult the adapter.
 */
record CoreFProxyRuntimeSupport(NodeClientCore core) implements FProxyRuntimeSupport {

  /**
   * Creates an adapter over the supplied node core.
   *
   * <p>The constructor rejects {@code null} eagerly because all later methods delegate directly to
   * the wrapped core and would otherwise fail at unrelated call sites. Callers typically create one
   * instance during HTTP bootstrap and pass it into the long-lived {@link FProxyToadlet}.
   *
   * @param core live daemon core that provides FProxy runtime services.
   */
  CoreFProxyRuntimeSupport(NodeClientCore core) {
    this.core = Objects.requireNonNull(core);
  }

  /** {@inheritDoc} */
  @Override
  public ClientContext clientContext() {
    return core.getClientContext();
  }

  /** {@inheritDoc} */
  @Override
  public PhysicalThreatLevel physicalThreatLevel() {
    return mapPhysicalThreatLevel(
        core.getNode().services().securityLevels().getPhysicalThreatLevel());
  }

  /** {@inheritDoc} */
  @Override
  public NetworkThreatLevel networkThreatLevel() {
    return mapNetworkThreatLevel(
        core.getNode().services().securityLevels().getNetworkThreatLevel());
  }

  /** {@inheritDoc} */
  @Override
  public boolean isDownloadDisabled() {
    return core.isDownloadDisabled();
  }

  /** {@inheritDoc} */
  @Override
  public File downloadsDir() {
    return core.getDownloadsDir();
  }

  /** {@inheritDoc} */
  @Override
  public boolean allowDownloadTo(File file) {
    return core.allowDownloadTo(file);
  }

  /** {@inheritDoc} */
  @Override
  public File[] allowedDownloadDirs() {
    return core.getAllowedDownloadDirs();
  }

  /** {@inheritDoc} */
  @Override
  public void executeBackground(Runnable task) {
    core.getNode().network().executor().execute(task);
  }

  /** {@inheritDoc} */
  @Override
  public SubConfig fproxyConfig() {
    return core.getNode().getConfig().get("fproxy");
  }

  /**
   * Maps the node's physical-threat enum into the local HTTP-facing enum.
   *
   * <p>This translation keeps {@link FProxyToadlet} independent of node security types while
   * preserving the one-to-one meaning of each threat level.
   *
   * @param threatLevel physical-threat value reported by the node security subsystem.
   * @return the equivalent local threat-level value used by HTTP code.
   */
  private static FProxyRuntimeSupport.PhysicalThreatLevel mapPhysicalThreatLevel(
      PHYSICAL_THREAT_LEVEL threatLevel) {
    return switch (threatLevel) {
      case LOW -> FProxyRuntimeSupport.PhysicalThreatLevel.LOW;
      case NORMAL -> FProxyRuntimeSupport.PhysicalThreatLevel.NORMAL;
      case HIGH -> FProxyRuntimeSupport.PhysicalThreatLevel.HIGH;
      case MAXIMUM -> FProxyRuntimeSupport.PhysicalThreatLevel.MAXIMUM;
    };
  }

  /**
   * Maps the node's network-threat enum into the local HTTP-facing enum.
   *
   * <p>This translation mirrors {@link #mapPhysicalThreatLevel(PHYSICAL_THREAT_LEVEL)} and keeps
   * the package-local runtime seam free of node security API types.
   *
   * @param threatLevel network-threat value reported by the node security subsystem.
   * @return the equivalent local threat-level value used by HTTP code.
   */
  private static FProxyRuntimeSupport.NetworkThreatLevel mapNetworkThreatLevel(
      NETWORK_THREAT_LEVEL threatLevel) {
    return switch (threatLevel) {
      case LOW -> FProxyRuntimeSupport.NetworkThreatLevel.LOW;
      case NORMAL -> FProxyRuntimeSupport.NetworkThreatLevel.NORMAL;
      case HIGH -> FProxyRuntimeSupport.NetworkThreatLevel.HIGH;
      case MAXIMUM -> FProxyRuntimeSupport.NetworkThreatLevel.MAXIMUM;
    };
  }
}
