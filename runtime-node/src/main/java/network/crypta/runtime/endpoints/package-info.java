/**
 * Client endpoint wiring and TMCI bootstrap support for the runtime boundary.
 *
 * <p>This package groups the legacy endpoint bootstrap cluster that wires the live FCP, HTTP, and
 * text-mode client interfaces from daemon-backed services. The classes remain part of the daemon
 * runtime and keep their existing collaboration patterns, including package-private TMCI access,
 * but they now sit under a neutral runtime-oriented package instead of {@code network.crypta.node}.
 *
 * <p>The package also owns {@link network.crypta.runtime.endpoints.ClientContextInitParams}, the
 * immutable bootstrap bundle used to assemble client context dependencies during node startup.
 *
 * <p>The intent is ownership clarification only. These types still depend on daemon-local services
 * such as {@code Node}, {@code NodeClientCore}, queue persistence, and HTTP bootstrap helpers, but
 * the FCP-specific concrete types now live behind the bridge leaf in {@code
 * network.crypta.clients.fcp.bridge}, while default production binding selection is rooted in
 * {@code network.crypta.runtime.bootstrap}. The runtime-endpoint types intentionally preserve the
 * current behavior and lifecycle semantics while depending only on the seam-owned FCP endpoint
 * handle and persistent-request service abstractions.
 */
package network.crypta.runtime.endpoints;
