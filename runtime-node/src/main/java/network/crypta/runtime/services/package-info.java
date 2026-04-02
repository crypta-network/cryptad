/**
 * Runtime-owned service coordination for daemon startup and long-lived node services.
 *
 * <p>This package groups the service-level orchestrators that wire the running node to operator
 * services such as the web interface lifecycle, diagnostics, updater setup, and alert helpers. The
 * coordinating logic lives here because it belongs to the daemon runtime and has to respect the
 * node startup sequence, not because it defines an endpoint adapter contract.
 *
 * <p>Keeping these classes separate from the endpoint adapters clarifies the current boundary:
 * adapters render or transport requests, while this package manages service creation, attachment,
 * and lifecycle coordination within {@code runtime-node}.
 */
package network.crypta.runtime.services;
