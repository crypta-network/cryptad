/**
 * App-management Platform API handlers.
 *
 * <p>This package owns the minimal AppHost control surface for Platform API v1. It translates
 * detached AppHost snapshots and lifecycle actions into stable JSON shapes for app listing,
 * description, installation, start, stop, and uninstall flows.
 *
 * <p>The package is intentionally transport-neutral. It validates already-decoded request inputs,
 * projects AppHost data onto operator-facing response maps, and leaves authentication and
 * byte-level HTTP handling to the legacy bridge layer. That split lets the existing {@code
 * /api/v1/apps/...} routes expose local AppHost control operations without pushing filesystem,
 * process, or serialization concerns back into the router or toadlet adapters.
 *
 * <p>AppHost v1 remains deliberately narrow here: install operations come from a local staged
 * directory, lifecycle commands stay local/admin-only, and summary payloads expose only stable
 * inventory and running-state fields needed by the Platform API contract.
 */
package network.crypta.platform.api.apps;
