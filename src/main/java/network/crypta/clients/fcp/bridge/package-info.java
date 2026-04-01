/**
 * Adapter-owned concrete bridge implementations for the legacy FCP endpoint.
 *
 * <p>This package contains the production classes that translate between the legacy FCP adapter and
 * the narrower runtime-owned seams in {@code network.crypta.runtime.fcp}, {@code
 * network.crypta.runtime.admin}, and {@code network.crypta.runtime.endpoints.fcp}. It is the home
 * for concrete daemon-facing wiring that still depends on the full FCP server, persistent-request
 * root, queue pages and admin operations, user-alert feed integration, and endpoint-handle
 * wrapping. Higher-level runtime packages should depend on the runtime-owned interfaces, not on the
 * concrete bridge classes collected here.
 *
 * <p>Typical bootstrap still begins at {@code
 * network.crypta.runtime.endpoints.fcp.FcpEndpointBridgeFactories}, which selects the default
 * production binding and then hands only seam types upstream. This package keeps the concrete
 * adapter behavior behind that boundary, so the current FCP startup sequence, persistent-request
 * recovery path, queue semantics, and alert delivery behavior remain unchanged while ownership is
 * made explicit for later extraction work.
 *
 * <ul>
 *   <li>Owns the concrete persistent-request bundle and recovery adapters for FCP-backed state.
 *   <li>Owns queue, admin, and alert-feed adapters that still require direct FCP knowledge.
 *   <li>Owns wrappers that convert between concrete {@code FCPServer} instances and runtime-owned
 *       endpoint handles.
 * </ul>
 */
package network.crypta.clients.fcp.bridge;
