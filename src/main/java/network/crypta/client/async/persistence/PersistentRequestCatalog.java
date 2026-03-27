package network.crypta.client.async.persistence;

/**
 * Provides access to the currently registered durable requests.
 *
 * <p>The catalog is the read-only view that {@code ClientLayerPersister} needs from the runtime at
 * checkpoint and restart time. It exposes a stable snapshot of requests that should be written to
 * disk and a duplicate-detection query that lets startup skip requests already reconstructed by an
 * earlier load step.
 *
 * <p>Implementations are typically thin adapters over endpoint-specific registries. They should
 * avoid side effects, return a point-in-time snapshot rather than a live view, and preserve the
 * runtime's existing notion of request identity so restart semantics remain unchanged.
 */
public interface PersistentRequestCatalog {

  /**
   * Returns a snapshot of the current persistent requests.
   *
   * <p>The returned array should represent the requests that are eligible for durable checkpointing
   * at the time of the call. Callers may iterate it immediately and should not assume that later
   * runtime changes, such as newly queued requests or completions, will be reflected in the same
   * array instance.
   *
   * @return array containing the currently checkpointable persistent requests; never {@code null}
   */
  PersistentRequestHandle[] getPersistentRequests();

  /**
   * Returns whether a request with the given identifier is already registered.
   *
   * <p>This method supports duplicate detection during startup replay. Implementations should use
   * the same queue and identifier semantics that the runtime uses for live request lookups so the
   * client layer does not accidentally restart a request that is already attached to the node.
   *
   * @param identifier stable persistent-request identifier describing the request being checked
   * @return {@code true} when a matching durable request is already present in the runtime
   */
  boolean hasRequest(PersistentRequestIdentifier identifier);
}
