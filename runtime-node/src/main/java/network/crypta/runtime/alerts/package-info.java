/**
 * Transitional runtime/operator-facing alerts cluster.
 *
 * <p>This package groups the legacy user-alert types while they are being re-homed under a neutral
 * runtime package. The classes still collaborate with daemon-local state and remain responsible for
 * the same alert rendering, sorting, and subscription behavior as before.
 *
 * <p>The ownership change is intentionally behavioral no-op only: existing daemon-local
 * integrations, alert lifecycles, and operator-facing semantics are preserved.
 */
package network.crypta.runtime.alerts;
