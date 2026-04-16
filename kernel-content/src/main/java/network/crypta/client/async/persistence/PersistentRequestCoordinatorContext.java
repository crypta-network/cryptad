package network.crypta.client.async.persistence;

/**
 * Narrow runtime-context seam that exposes the persistent-request coordinator.
 *
 * <p>Persistent request implementations sometimes need more than the bare {@link
 * PersistentRequestRuntimeContext} marker during restart and resume. In particular, they may need
 * to recover the owning persistent client or re-register themselves with the persistent-request
 * coordinator. This interface exposes just that coordinator dependency without forcing higher
 * layers to depend on a larger live runtime type.
 *
 * <p>Concrete runtimes may implement this directly on their live execution context, or they may
 * wrap another runtime token and forward the coordinator call. Callers should treat the returned
 * coordinator as a persistence-only collaborator rather than as a general runtime service locator.
 * The seam exists specifically so restart and replay code can recover persistent ownership without
 * reintroducing compile-time coupling to larger runtime types such as the daemon's full client
 * context.
 */
public interface PersistentRequestCoordinatorContext extends PersistentRequestRuntimeContext {

  /**
   * Returns the persistent-request coordinator for the current runtime.
   *
   * <p>Callers use the coordinator to recover persistent request clients, re-register durable
   * requests after deserialization, and keep queue ownership consistent across restarts. The
   * returned coordinator should be treated as stable for the lifetime of the surrounding runtime
   * context, but not as a general-purpose access path to unrelated node services.
   *
   * @return persistence coordinator used to recover clients and resume durable requests
   */
  PersistentRequestCoordinator persistentRequestCoordinator();
}
