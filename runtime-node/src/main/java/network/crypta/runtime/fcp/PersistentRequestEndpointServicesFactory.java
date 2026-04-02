package network.crypta.runtime.fcp;

/**
 * Creates runtime-owned FCP persistent-request service bundles.
 *
 * <p>Bootstrap code selects one factory at composition-root time and threads it into node/client
 * core construction. Higher-level runtime code can then request the persistent-request bundle it
 * needs without naming endpoint-owned concrete bridge classes directly. The factory itself is
 * intentionally narrow: it chooses an implementation but does not define caching or lifecycle
 * policy beyond creating the bundle instance. In the current startup flow, the factory is usually
 * invoked once while building {@code NodeClientPersistence}. The returned bundle is then reused for
 * client-layer persistence wiring and later FCP endpoint bootstrap so those stages share the same
 * durable request state.
 */
@FunctionalInterface
public interface PersistentRequestEndpointServicesFactory {

  /**
   * Creates one persistent-request service bundle.
   *
   * <p>Callers typically invoke this once during {@code NodeClientPersistence} construction so the
   * client-layer persistence adapters and later FCP endpoint bootstrap share the same underlying
   * durable request state. Implementations may return a fresh bundle per invocation or delegate to
   * another provider, but they should not expose endpoint-owned concrete types through this method
   * signature.
   *
   * @return runtime-owned persistent-request service bundle aligned to one client-persistence
   *     construction path
   */
  PersistentRequestEndpointServices create();
}
