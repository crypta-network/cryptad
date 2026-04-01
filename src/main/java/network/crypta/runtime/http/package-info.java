/**
 * Runtime-owned HTTP seam types and reusable runtime-facing helpers.
 *
 * <p>This package contains the neutral HTTP seam interfaces that higher-level runtime and bootstrap
 * code should depend on when they need to create, wire, or lifecycle-manage the node's HTTP shell.
 * It also owns small runtime-facing helper types, such as canonical HTTP path constants, that other
 * non-HTTP runtime code may reference without depending on endpoint-owned bridge implementations.
 *
 * <p>Concrete bridge implementations now live under {@code network.crypta.clients.http.bridge},
 * while the default production binding entry points remain in {@code
 * network.crypta.runtime.endpoints.http}. Callers that need the historical daemon wiring should
 * choose those bindings at bootstrap time. They should then pass only the seam interfaces and
 * runtime-owned helpers from this package into higher-level runtime components such as node
 * construction, service startup, and detached status rendering.
 */
package network.crypta.runtime.http;
