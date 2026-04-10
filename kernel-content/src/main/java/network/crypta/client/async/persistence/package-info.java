/**
 * Client-owned persistence contracts for durable async request recovery.
 *
 * <p>This package defines the narrow seam that {@code network.crypta.client.async} uses to
 * checkpoint, deduplicate, and recover durable requests without depending directly on a concrete
 * endpoint implementation such as FCP. The types here are owned by the client layer because the
 * persistence coordinator needs stable concepts that survive protocol refactors: an opaque client
 * handle, a request handle, a byte-compatible identifier, a catalog for live requests, a compact
 * recovery codec, and a tiny runtime-context seam for resume callbacks.
 *
 * <p>The seam is intentionally small. It preserves the existing identifier layout and restart
 * behavior so runtime-owned adapters can continue to bridge legacy request types without widening
 * {@code runtime-spi}. In practice, startup wiring provides adapter implementations, the client
 * layer performs save and load orchestration locally, and endpoint packages remain responsible only
 * for listing requests and reconstructing protocol-specific state. The primary bridge types are
 * {@link network.crypta.client.async.persistence.PersistentRequestHandle}, {@link
 * network.crypta.client.async.persistence.PersistentRequestClientHandle}, {@link
 * network.crypta.client.async.persistence.PersistentRequestCoordinator}, and {@link
 * network.crypta.client.async.persistence.PersistentRequestRuntimeContext}.
 */
package network.crypta.client.async.persistence;
