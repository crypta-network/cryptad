/**
 * Defines the client-owned alert seam used by asynchronous client code.
 *
 * <p>This package exists for one narrow purpose: let code under {@code network.crypta.client.async}
 * emit operator-facing alerts without importing runtime-owned alert classes directly. The package
 * provides a marker interface for alert values and a sink interface for posting them. That keeps
 * the dependency direction clean while preserving the existing runtime alert pipeline.
 *
 * <p>The seam is intentionally small. It does not define rendering, formatting, persistence, or
 * transport behavior. Runtime code remains responsible for those concerns, typically through a
 * small adapter that validates the neutral client-layer alert and forwards it into the concrete
 * {@code UserAlertManager} infrastructure.
 */
package network.crypta.client.async.alerts;
