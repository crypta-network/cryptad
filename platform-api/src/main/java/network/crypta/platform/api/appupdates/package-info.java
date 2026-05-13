/**
 * App update lifecycle coordination for Platform API host/operator routes.
 *
 * <p>This package sits above signed catalog verification and AppHost bundle replacement. It keeps
 * candidate detection, background scheduler metadata, policy, pending staging, apply history, and
 * rollback summaries out of the transport router while reusing the existing catalog and AppHost
 * primitives.
 *
 * <p>The package is intentionally conservative. The default policy is manual, catalog checks only
 * record candidates, and scheduler-triggered checks follow the same policy gates as manual checks.
 * Automatic apply is limited to eligible reviewed updates for apps that are already stopped. Staged
 * update summaries contain safe identifiers, versions, digest metadata, compatibility summaries,
 * review state, and permission deltas. They do not expose staging directories, rollback
 * directories, app tokens, browser-session tokens, signing keys, request bodies, or private catalog
 * URIs.
 *
 * <p>Rollback support in this package is bundle-scoped. It asks AppHost to restore the previous
 * verified installed bundle while preserving mutable app data and cache. Platform API handlers
 * expose this state as JSON-compatible maps for Web Shell and automation clients, but AppHost and
 * the signed catalog manager remain responsible for filesystem safety and artifact verification.
 *
 * @see network.crypta.platform.api.appupdates.AppUpdateService
 * @see network.crypta.platform.api.appupdates.AppUpdatesApiHandler
 * @see network.crypta.platform.appcatalog.AppCatalogManager
 * @see network.crypta.platform.apphost.AppHost
 */
package network.crypta.platform.api.appupdates;
