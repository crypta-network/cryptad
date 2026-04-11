/**
 * Runtime-owned HTTP seam types and reusable runtime-facing helpers.
 *
 * <p>This package contains the neutral HTTP seam interfaces that higher-level runtime and bootstrap
 * code should depend on when they need to create, wire, or lifecycle-manage the node's HTTP shell.
 * It also owns small runtime-facing helper types that remain node-specific; shared canonical HTTP
 * path constants now live in {@code network.crypta.runtime.http} and {@code
 * network.crypta.runtime.updater} under {@code :runtime-spi} so detached adapters can use them
 * without depending on node-owned helper classes.
 *
 * <p>Concrete bridge implementations now live under {@code network.crypta.clients.http.bridge}. The
 * default production binding selection now lives in {@code
 * network.crypta.runtime.bootstrap.DefaultNodeRuntimeBridgeFactories}. Callers that need the
 * historical daemon wiring should choose those bindings at bootstrap time. They should then pass
 * only the seam interfaces and runtime-owned helpers from this package into higher-level runtime
 * components such as node construction, service startup, and detached status rendering.
 */
package network.crypta.runtime.http;
