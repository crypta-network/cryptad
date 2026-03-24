/**
 * Client endpoint wiring and TMCI bootstrap support for the runtime boundary.
 *
 * <p>This package groups the legacy endpoint bootstrap cluster that still wires the live FCP, HTTP,
 * and text-mode client interfaces from daemon-backed services. The classes remain in the root
 * project and keep their existing collaboration patterns, including package-private TMCI access,
 * but they now sit under a neutral runtime-oriented package instead of {@code network.crypta.node}.
 *
 * <p>The intent is ownership clarification only. These types still depend on daemon-local services
 * such as {@code Node}, {@code NodeClientCore}, queue persistence, and HTTP/FCP bootstrap helpers,
 * and they intentionally preserve the current runtime behavior and lifecycle semantics.
 */
package network.crypta.runtime.endpoints;
