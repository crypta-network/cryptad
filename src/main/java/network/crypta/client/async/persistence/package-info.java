/**
 * Client-owned persistence contracts for durable async request recovery.
 *
 * <p>This package defines the narrow seam that {@code network.crypta.client.async} uses to
 * checkpoint, deduplicate, and recover durable requests without depending directly on a concrete
 * endpoint implementation such as FCP. The types here are owned by the client layer because the
 * persistence coordinator needs stable concepts that survive protocol refactors: a request handle,
 * a byte-compatible identifier, a catalog for live requests, and a codec for compact recovery
 * records.
 *
 * <p>The seam is intentionally small. It preserves the existing identifier layout and restart
 * behavior so runtime-owned adapters can continue to bridge legacy request types without widening
 * {@code runtime-spi}. In practice, startup wiring provides an adapter implementation, the client
 * layer performs save and load orchestration locally, and endpoint packages remain responsible only
 * for listing requests and reconstructing protocol-specific state.
 */
package network.crypta.client.async.persistence;
