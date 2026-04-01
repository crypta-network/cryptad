/**
 * Runtime-owned FCP endpoint handle surface.
 *
 * <p>This package now contains only the narrow runtime-owned {@link
 * network.crypta.runtime.endpoints.fcp.FcpEndpointHandle} seam. Bootstrap-owned code selects the
 * adapter-backed persistent-request services elsewhere, and the concrete FCP bridge classes remain
 * in {@code network.crypta.clients.fcp.bridge}. Higher-level runtime code should therefore depend
 * on this endpoint-handle seam rather than on concrete FCP server types.
 */
package network.crypta.runtime.endpoints.fcp;
