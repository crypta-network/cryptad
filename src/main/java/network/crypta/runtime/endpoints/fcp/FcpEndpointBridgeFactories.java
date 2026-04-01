package network.crypta.runtime.endpoints.fcp;

import network.crypta.runtime.fcp.PersistentRequestEndpointServicesFactory;

/**
 * Endpoint-owned default production bindings for runtime-owned FCP persistence seams.
 *
 * <p>This helper keeps the composition-root knowledge about the current FCP bridge implementation
 * inside the endpoint-owned package. Bootstrap code can call these factories once, select the
 * historical endpoint-backed binding, and then thread only the runtime-owned seam upstream through
 * {@code NodeRuntimeBridgeFactories}, {@code Node}, and {@code NodeClientCore}. That preserves the
 * existing bootstrap order and persistent-request behavior without forcing higher-level runtime
 * packages to import {@link FcpPersistentRequestServices} directly.
 *
 * <p>The class intentionally exposes only narrow static binding methods. It does not cache bridge
 * instances, own endpoint lifecycle, or start FCP services by itself. Those responsibilities stay
 * with the runtime bootstrap and client-persistence layers that consume the returned seam factory.
 */
public final class FcpEndpointBridgeFactories {
  private FcpEndpointBridgeFactories() {}

  /**
   * Returns the default production factory for the FCP persistent-request bundle.
   *
   * <p>The returned factory preserves the existing production wiring by creating {@link
   * FcpPersistentRequestServices} instances on demand. Callers typically pass the factory into
   * runtime bootstrap structures and invoke it later from {@code NodeClientPersistence} so the
   * persistence adapters, persistent-request snapshot, and eventual FCP endpoint handle all share
   * one bundle instance for that node startup path. The factory itself remains side-effect free
   * until invoked.
   *
   * @return factory that creates the current endpoint-backed persistent-request bundle for one
   *     client-persistence construction path
   */
  public static PersistentRequestEndpointServicesFactory
      coreBackedPersistentRequestServicesFactory() {
    return FcpPersistentRequestServices::new;
  }
}
