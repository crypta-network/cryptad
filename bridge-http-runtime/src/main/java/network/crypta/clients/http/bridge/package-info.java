/**
 * Concrete runtime-binding bridge implementations for the legacy HTTP shell.
 *
 * <p>This package now lives in the extracted {@code :bridge-http-runtime} leaf. It contains the
 * production adapters that connect the remaining legacy HTTP shell in {@code
 * :adapter-http-legacy-admin} to the runtime-owned seams in {@code network.crypta.runtime.http}.
 * The classes here know about the concrete HTTP host, the daemon-backed services that drive it, and
 * the bootstrap details that are still specific to the legacy web UI. Keeping that knowledge in a
 * separate bridge leaf makes ownership explicit without changing package names or HTTP behavior.
 *
 * <p>In practical terms, this package owns the default bridge objects that wire {@code
 * SimpleToadletServer}, FProxy support, and shell startup helpers to the daemon core. Production
 * binding selection remains in {@code
 * network.crypta.runtime.bootstrap.DefaultNodeRuntimeBridgeFactories}, while runtime-owned packages
 * continue to treat these classes as adapter implementations rather than as part of the long-lived
 * runtime seam. This leaf also installs the admin-owned HTTP route registrar implementation into
 * the shared shell. The remaining browse/FProxy shell stays boundary-frozen in {@code
 * :adapter-http-legacy-admin}, and {@code network.crypta.clients.http.updater} also remains in that
 * adapter leaf in this PR.
 */
package network.crypta.clients.http.bridge;
