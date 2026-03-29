/**
 * Runtime-owned FCP endpoint bootstrap glue.
 *
 * <p>This package adapts daemon- and runtime-backed services to the narrow runtime-support seams
 * defined in {@code network.crypta.clients.fcp}. The types here keep the concrete FCP server and
 * persistent-request root owned by bridge-local wrappers such as {@code FcpEndpointHandle} and
 * {@code FcpPersistentRequestServices}, preserving the current protocol behavior without widening
 * {@code runtime-spi}.
 */
package network.crypta.runtime.endpoints.fcp;
