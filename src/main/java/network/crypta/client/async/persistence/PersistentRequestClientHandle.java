package network.crypta.client.async.persistence;

/**
 * Opaque reference to the runtime-owned owner that backs a durable client request.
 *
 * <p>The client layer uses this marker interface to remember which runtime-owned client, queue, or
 * session currently owns a persistent request. The handle deliberately exposes no behavioral API.
 * That keeps {@code network.crypta.client.async} independent of endpoint-specific owner types while
 * still allowing startup wiring to return a stable token that can be passed back through the
 * persistence seam. Implementations are free to represent the handle with an existing runtime
 * object, a lightweight wrapper, or another identity-bearing type, as long as callers can treat it
 * as opaque and implementation-specific.
 *
 * <p>Handles are typically obtained from {@link PersistentRequestCoordinator} when a request is
 * first created or when a saved request is reattached during node startup. Callers should not
 * serialize, inspect, or downcast a handle outside the runtime package that created it.
 *
 * @see PersistentRequestCoordinator
 */
public interface PersistentRequestClientHandle {}
