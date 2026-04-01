/**
 * Adapter-owned concrete bridge implementations for the HTTP shell.
 *
 * <p>This package contains the production adapters that connect the legacy HTTP shell to the
 * runtime-owned seams in {@code network.crypta.runtime.http}. The classes here know about the
 * concrete HTTP host, the daemon-backed services that drive it, and the remaining bootstrap details
 * that are still specific to the legacy web UI. They exist so runtime packages can stay focused on
 * narrow contracts instead of taking direct dependencies on {@code clients.http} implementation
 * types.
 *
 * <p>In practical terms, this package owns the default bridge objects that wire {@code
 * SimpleToadletServer}, FProxy support, and shell startup helpers to the daemon core. Production
 * binding selection still starts in {@code network.crypta.runtime.endpoints.http}, but that
 * runtime-owned package should treat these classes as adapter implementations, not as part of the
 * long-lived runtime seam. Keeping the concrete bridge here preserves current behavior while making
 * ownership explicit for later extraction work.
 */
package network.crypta.clients.http.bridge;
