/**
 * Endpoint-owned default production bindings for HTTP bridge implementations.
 *
 * <p>This package keeps the bootstrap-facing helper methods that expose the default production
 * bindings used by runtime/bootstrap code. The concrete HTTP bridge implementations now live under
 * {@code network.crypta.clients.http.bridge}. Higher-level runtime and bootstrap code should depend
 * on the neutral seam types in {@code network.crypta.runtime.http}, not on the bridge
 * implementation classes themselves.
 */
package network.crypta.runtime.endpoints.http;
