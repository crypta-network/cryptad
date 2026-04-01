/**
 * Runtime-owned alert feed seam.
 *
 * <p>This package holds the immutable event and subscriber types that let {@code
 * network.crypta.runtime.alerts} publish user-alert feed updates without depending on any specific
 * endpoint protocol. The types here intentionally describe runtime concepts only: alert text,
 * bookmark or URI payloads, node-to-node provenance metadata, and the minimal subscriber callback
 * used by {@code UserAlertManager}.
 *
 * <p>Protocol-specific encoding stays outside this package. That split lets the runtime own alert
 * semantics and tests while endpoint packages, such as the FCP bridge, remain responsible for wire
 * names, bucket layouts, and transport lifecycle.
 */
package network.crypta.runtime.alerts.feed;
