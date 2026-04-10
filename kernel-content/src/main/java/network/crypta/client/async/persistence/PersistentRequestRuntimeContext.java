package network.crypta.client.async.persistence;

/**
 * Narrow runtime-context seam used by durable request recovery hooks.
 *
 * <p>This marker interface keeps the client-owned persistence contracts compile-neutral while they
 * still need to talk to runtime-owned request implementations during resume, restart, cancellation,
 * and shutdown. The seam is intentionally tiny: it exists only to prevent the persistence package
 * from depending directly on {@code ClientContext} while preserving the current recovery behavior
 * and adapter boundaries.
 *
 * <p>Concrete runtime code may implement this interface with richer context objects such as {@code
 * ClientContext}, then narrow back to that concrete type at the adapter boundary when a request
 * implementation genuinely needs the full runtime API. Higher layers should treat this type as a
 * callback token for persistence flows, not as a general-purpose runtime abstraction.
 */
public interface PersistentRequestRuntimeContext {}
