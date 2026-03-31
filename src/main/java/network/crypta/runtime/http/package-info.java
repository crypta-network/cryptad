/**
 * Runtime-owned HTTP shell seam types.
 *
 * <p>This package contains the neutral HTTP shell seam interfaces that higher-level runtime and
 * bootstrap code should depend on when they need to create, wire, or lifecycle-manage the node's
 * HTTP shell. The types here define the runtime-facing contracts only. They deliberately avoid any
 * dependency on endpoint-owned bridge implementations so that composition-root code can select
 * bindings without pushing endpoint ownership concerns back into the runtime-owned seam package.
 *
 * <p>Concrete bridge implementations and the default production bindings remain in {@code
 * network.crypta.runtime.endpoints.http}. Callers that need the historical daemon wiring should
 * choose those bindings at bootstrap time, then pass only the seam interfaces from this package
 * into higher-level runtime components such as node construction and service startup.
 */
package network.crypta.runtime.http;
