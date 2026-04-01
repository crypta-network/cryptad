/**
 * Runtime-owned FCP seam types used by higher-level bootstrap and persistence code.
 *
 * <p>This package contains the neutral interfaces that runtime and node code should depend on when
 * they need the FCP persistent-request bundle during startup. The types here describe the small
 * surface that runtime-owned code uses to configure client-layer persistence, inspect the current
 * persistent-request snapshot, and ask the endpoint layer to create an FCP handle later in startup.
 *
 * <p>Concrete bridge implementations and the default production bindings remain in {@code
 * network.crypta.runtime.endpoints.fcp}. Bootstrap code selects those bindings once, threads only
 * these seam types through node construction, and keeps the endpoint-owned request root and server
 * bootstrap details behind that boundary. That split preserves the current startup order while
 * making the composition-root choice explicit.
 */
package network.crypta.runtime.fcp;
