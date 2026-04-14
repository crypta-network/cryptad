/**
 * Runtime-binding concrete bridge implementations for the legacy FCP endpoint.
 *
 * <p>This package contains the production classes that translate between the protocol-side FCP leaf
 * in {@code network.crypta.clients.fcp} and the narrower runtime-owned seams in {@code
 * network.crypta.runtime.fcp}, {@code network.crypta.runtime.admin}, and {@code
 * network.crypta.runtime.endpoints.fcp}. It is the home for concrete daemon-facing wiring that
 * still depends on the full FCP server, persistent-request root, queue pages and admin operations,
 * user-alert feed integration, and endpoint-handle wrapping. Higher-level runtime packages should
 * depend on the runtime-owned interfaces, not on the concrete bridge classes collected here.
 *
 * <p>Typical bootstrap now begins in {@code
 * network.crypta.runtime.bootstrap.DefaultNodeRuntimeBridgeFactories}, which selects the default
 * production binding and then hands only seam types upstream. This package keeps the concrete
 * runtime-binding behavior behind that boundary, so the current FCP startup sequence,
 * persistent-request recovery path, queue semantics, and alert delivery behavior remain unchanged
 * while ownership is made explicit for later extraction work. It also owns the concrete mapping
 * between adapter-owned FCP peer/probe seam types and the live node peer/probe runtime classes,
 * plus the bridge-side translation between adapter-owned detached insert compatibility types and
 * the live {@code InsertContext}/{@code CompatibilityAnalyser} implementations. The AddPeer
 * noderef-loading bridge still requires live client and runtime loader access.
 *
 * <ul>
 *   <li>Owns the concrete persistent-request bundle and recovery adapters for FCP-backed state.
 *   <li>Owns queue, admin, and alert-feed adapters that still require direct FCP knowledge.
 *   <li>Owns the compatibility and insert-context translation helpers that keep detached FCP values
 *       and live runtime state in sync.
 *   <li>Owns wrappers that convert between concrete {@code FCPServer} instances and runtime-owned
 *       endpoint handles.
 * </ul>
 */
package network.crypta.clients.fcp.bridge;
