/**
 * Transitional runtime/operator-facing alerts cluster.
 *
 * <p>This package now spans the extracted {@code :runtime-alerts} leaf and the remaining
 * daemon-bound {@code :runtime-node} classes. Leaf-safe alert model, feed types, and the detached
 * consumer-facing {@code UserAlertSurface} live in {@code :runtime-alerts}; the concrete {@code
 * UserAlertManager}, node-backed producers, and other daemon-coupled alert implementations remain
 * adjacent to the runtime services that still own their state.
 *
 * <p>The ownership split is intentionally behavioral no-op only. Existing alert rendering, sorting,
 * subscription, and operator-facing semantics stay unchanged while later boundary work continues to
 * reduce direct daemon coupling.
 */
package network.crypta.runtime.alerts;
