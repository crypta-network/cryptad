/**
 * Endpoint-owned FCP bridge implementations and default bindings.
 *
 * <p>This package adapts daemon- and runtime-backed services to the narrow runtime-support seams
 * defined in {@code network.crypta.clients.fcp} and {@code network.crypta.runtime.fcp}. The types
 * here keep the concrete FCP server, persistent-request root, and default production bindings owned
 * by bridge-local wrappers such as {@code FcpEndpointHandle}, {@code FcpPersistentRequestServices},
 * and {@code FcpEndpointBridgeFactories}, preserving the current protocol behavior without widening
 * {@code runtime-spi}.
 */
package network.crypta.runtime.endpoints.fcp;
