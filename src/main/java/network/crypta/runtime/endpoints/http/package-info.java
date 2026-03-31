/**
 * Endpoint-owned HTTP bridge implementations and default production bindings.
 *
 * <p>This package adapts daemon- and runtime-backed services to the narrow runtime-support seams
 * owned by {@code network.crypta.clients.http}. It contains the concrete HTTP shell bridge
 * implementations plus the endpoint-owned helper methods that expose the default production
 * bindings used by bootstrap. Higher-level runtime and bootstrap code should depend on the neutral
 * seam types in {@code network.crypta.runtime.http}, not on the bridge implementation classes in
 * this package.
 */
package network.crypta.runtime.endpoints.http;
