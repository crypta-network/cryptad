package network.crypta.runtime.endpoints.admin;

import network.crypta.runtime.admin.AdminRuntimeBridgeInputs;
import network.crypta.runtime.admin.AdminRuntimeBridgeInputsFactory;
import network.crypta.runtime.endpoints.fcp.FcpQueuePorts;
import network.crypta.runtime.endpoints.http.geoip.HttpGeoIpCountryLookups;

/**
 * Endpoint-owned factory entry points for admin bridge inputs.
 *
 * <p>This package keeps the concrete bridge construction local to the endpoint layer while exposing
 * only the runtime-owned factory seam upstream. The class acts as the endpoint-layer composition
 * helper for the legacy admin runtime adapters that still depend on concrete queue and GeoIP bridge
 * implementations. Callers above this package see only {@link
 * network.crypta.runtime.admin.AdminRuntimeBridgeInputsFactory}, while this helper preserves the
 * current bridge choices, constructor arguments, and startup ordering behind that seam.
 */
public final class AdminRuntimeBridgeInputsFactories {
  private AdminRuntimeBridgeInputsFactories() {}

  /**
   * Returns the default admin bridge-input factory backed by the current endpoint bridge classes.
   *
   * <p>The returned factory recreates the same queue and GeoIP bridge assembly that the client core
   * previously performed inline. It delegates queue adapter construction to {@link FcpQueuePorts}
   * and resolves the HTTP GeoIP lookup from the supplied node at factory invocation time. The
   * method adds no caching or policy of its own, so callers retain the existing behavior for queue
   * access, GeoIP rendering, and startup sequencing.
   *
   * @return factory that assembles admin bridge inputs from the existing endpoint-backed bridge
   *     implementations
   */
  public static AdminRuntimeBridgeInputsFactory coreBacked() {
    return (node, core) -> {
      FcpQueuePorts.Bundle queuePorts = FcpQueuePorts.create(core);
      return new AdminRuntimeBridgeInputs(
          queuePorts.adminBackend(),
          queuePorts.pageBackend(),
          queuePorts.completionPort(),
          queuePorts.downloadPort(),
          queuePorts.insertPort(),
          HttpGeoIpCountryLookups.forNode(node));
    };
  }
}
