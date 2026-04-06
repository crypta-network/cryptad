/**
 * Transport-neutral out-of-process AppHost core for locally installed applications.
 *
 * <p>This package defines the public model and lifecycle contracts for AppHost v1. It owns the
 * transport-neutral interface, immutable installed and running snapshots, the stable filesystem
 * layout model, and the checked exception surface that callers use to reason about installation,
 * discovery, launch, and shutdown behavior.
 *
 * <p>The package sits below transport adapters, launcher UI code, and higher-level management
 * shells. That separation lets future API layers reuse the same manifest, path, and snapshot model
 * whether the caller is a local administrative shell, a UI layer, or a transport endpoint.
 */
package network.crypta.platform.apphost;
