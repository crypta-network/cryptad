/**
 * Detached runtime service contracts exposed to adapters and platform modules.
 *
 * <p>Types in this package are public-safe projections of runtime state and actions. They let
 * consumers such as the Platform API and legacy HTTP adapter depend on narrow contracts rather than
 * updater internals. In particular, {@link network.crypta.runtime.spi.CoreSupportLifecycleSnapshot}
 * represents the locally verified Stable 1.0 support status without exposing raw lifecycle
 * descriptors, update URIs, secrets, local paths, or mutable runtime objects. Unknown and stale
 * states remain explicit, and {@link network.crypta.runtime.spi.CoreSupportLifecycleStatus} keeps
 * the public lifecycle vocabulary closed.
 *
 * <p>Implementations remain responsible for authentication, persistence, and policy enforcement.
 * Adapters must treat these records as read-only data and must not infer update-key revocation or
 * destructive runtime actions from build lifecycle status.
 */
package network.crypta.runtime.spi;
