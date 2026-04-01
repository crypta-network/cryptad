/**
 * Runtime-owned FCP seam bindings and endpoint handle surface.
 *
 * <p>This package now contains only the narrow runtime-owned FCP endpoint seam, plus the default
 * production binding entry point that selects the adapter-owned bridge implementations in {@code
 * network.crypta.clients.fcp.bridge}. Higher-level runtime/bootstrap code should depend on {@link
 * network.crypta.runtime.endpoints.fcp.FcpEndpointHandle} and the factory methods on {@link
 * network.crypta.runtime.endpoints.fcp.FcpEndpointBridgeFactories}, not on the concrete bridge
 * classes themselves.
 */
package network.crypta.runtime.endpoints.fcp;
