package network.crypta.runtime.bootstrap;

import network.crypta.clients.fcp.bridge.FcpPersistentRequestServices;
import network.crypta.clients.fcp.bridge.FcpQueuePorts;
import network.crypta.clients.http.bridge.CoreHttpShellRuntimeSupport;
import network.crypta.clients.http.bridge.HttpShellContainers;
import network.crypta.clients.http.bridge.geoip.HttpGeoIpCountryLookups;
import network.crypta.clients.http.bridge.security.CorePasswordFormPageRenderer;
import network.crypta.runtime.admin.AdminRuntimeBridgeInputs;

/**
 * Bootstrap-owned default production bindings for runtime bridge factories.
 *
 * <p>This helper is the composition-root entry point for the legacy daemon wiring. It selects the
 * current adapter-backed implementations for admin bridge inputs, FCP persistent-request services,
 * HTTP shell support, HTTP shell containers, and the shared password prompt renderer, then returns
 * them as a {@link NodeRuntimeBridgeFactories} holder. Higher-level runtime code should depend on
 * the holder and seam types, while this helper remains the only bootstrap-owned place that knows
 * which concrete production bridges to assemble by default. Keeping that policy here makes the
 * runtime holder easier to reuse in tests and alternate bootstraps because callers can inject an
 * already-selected seam set without inheriting production-only adapter choices. The helper also
 * stays deliberately narrow: it centralizes the selection of lightweight factories and renderers,
 * but it does not cache bridge instances or trigger endpoint startup as a side effect of assembly.
 */
public final class DefaultNodeRuntimeBridgeFactories {
  private DefaultNodeRuntimeBridgeFactories() {}

  /**
   * Returns the default production bridge-factory bundle backed by the current core adapters.
   *
   * <p>The returned holder preserves the existing startup wiring without eagerly starting endpoint
   * services. Admin bridge inputs are assembled lazily from the supplied node and client core, FCP
   * persistent-request services are created on demand, and HTTP shell support/container seams keep
   * their current adapter pairings.
   *
   * @return bridge-factory holder that preserves the current production bootstrap wiring
   */
  public static NodeRuntimeBridgeFactories coreBacked() {
    return new NodeRuntimeBridgeFactories(
        (node, core) -> {
          FcpQueuePorts.Bundle queuePorts = FcpQueuePorts.create(core);
          return new AdminRuntimeBridgeInputs(
              queuePorts.adminBackend(),
              queuePorts.pageBackend(),
              queuePorts.completionPort(),
              queuePorts.downloadPort(),
              queuePorts.insertPort(),
              HttpGeoIpCountryLookups.forNode(node));
        },
        FcpPersistentRequestServices::new,
        CoreHttpShellRuntimeSupport::new,
        HttpShellContainers::create,
        new CorePasswordFormPageRenderer());
  }
}
