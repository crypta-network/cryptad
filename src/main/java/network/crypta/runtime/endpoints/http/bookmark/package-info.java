/**
 * Runtime-owned HTTP bookmark bootstrap glue.
 *
 * <p>This package adapts daemon- and runtime-backed services to the narrow bookmark runtime seam
 * owned by {@code network.crypta.clients.http.bookmark}. The types here keep the remaining {@code
 * NodeClientCore}-backed bookmark bootstrap wiring under runtime ownership while preserving
 * existing bookmark behavior and without widening {@code runtime-spi}.
 */
package network.crypta.runtime.endpoints.http.bookmark;
