/**
 * Runtime-owned HTTP endpoint bootstrap glue.
 *
 * <p>This package adapts daemon- and runtime-backed services to the narrow runtime-support seams
 * owned by {@code network.crypta.clients.http}. The types here keep remaining {@code
 * NodeClientCore}-backed HTTP bootstrap wiring under runtime ownership while preserving current
 * shell and FProxy behavior and without widening {@code runtime-spi}.
 */
package network.crypta.runtime.endpoints.http;
