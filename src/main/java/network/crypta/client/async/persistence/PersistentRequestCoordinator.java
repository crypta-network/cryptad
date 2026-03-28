package network.crypta.client.async.persistence;

/**
 * Coordinates the client-layer handoff between durable request handles and runtime-owned owners.
 *
 * <p>This interface is the narrow seam that lets {@code network.crypta.client.async} create or
 * recover persistent requests without importing protocol-specific owner registries. Startup wiring
 * provides an implementation from the active runtime package. The client layer then uses that
 * implementation only to resolve an opaque owner handle for a new persistent request or to reattach
 * a reloaded request to the owner that should resume it.
 *
 * <p>The contract stays intentionally small. It does not expose request catalogs, queue mutation
 * primitives, or transport callbacks. Those details remain in the runtime implementation so the
 * client package can preserve existing checkpoint and restart behavior while avoiding a direct
 * dependency on endpoint-specific types.
 *
 * @see PersistentRequestClientHandle
 * @see PersistentRequestHandle
 */
public interface PersistentRequestCoordinator {

  /**
   * Returns an opaque owner handle for a persistent request, creating the owner if needed.
   *
   * <p>Callers use this when they need the runtime-owned client or queue that should back a newly
   * created durable request. Implementations may reuse an existing owner, create one lazily, or
   * normalize the supplied identity to a canonical runtime object. When {@code global} is {@code
   * true}, implementations may ignore {@code clientName} and resolve the shared global owner
   * instead.
   *
   * @param global whether the request belongs to the runtime's global persistent queue rather than
   *     a named client-specific owner
   * @param clientName durable client name used for non-global ownership lookup; ignored or
   *     implementation-defined when {@code global} is {@code true}
   * @return opaque handle for the runtime-owned client or queue that should own the request
   */
  PersistentRequestClientHandle getOrCreateClientHandle(boolean global, String clientName);

  /**
   * Reattaches a reloaded persistent request to its runtime-owned owner and returns that owner.
   *
   * <p>This method is used during restart and recovery flows after the durable request object has
   * been reconstructed from serialized state or compact recovery data. Implementations should bind
   * the request to the correct owner, restore whatever owner-side bookkeeping is required for later
   * callbacks, and return the same opaque handle shape used for newly created requests.
   *
   * @param request durable request handle that has been reconstructed and is ready to be attached
   *     to runtime-owned ownership state
   * @param global whether the request should resume under the runtime's global persistent queue
   * @param clientName durable client name used for non-global owner lookup during resume
   * @return opaque handle for the runtime-owned owner that now backs the resumed request
   * @throws IllegalArgumentException if the supplied request handle is incompatible with the
   *     implementation performing the resuming
   */
  PersistentRequestClientHandle resumePersistentRequest(
      PersistentRequestHandle request, boolean global, String clientName);
}
