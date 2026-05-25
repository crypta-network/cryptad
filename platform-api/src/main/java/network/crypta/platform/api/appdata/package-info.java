/**
 * Bounded app-scoped durable data records for browser/static apps.
 *
 * <p>This package implements the generic local app-data layer exposed through Platform API v1
 * contract v9. It is app-scoped and quota-bounded; it is not a generic filesystem, database, or
 * secret vault. Secret and identity material belongs in AppVault.
 *
 * <p>The package is split into three responsibilities. {@link
 * network.crypta.platform.api.appdata.AppDataService} owns app-facing policy: identifier
 * normalization, schema metadata, import/export validation, manifest-aware quota checks, and
 * sanitized Platform API errors. {@link network.crypta.platform.api.appdata.AppDataStore}
 * implementations own persistence mechanics. The model records define the stable metadata and value
 * shapes returned through the API and browser SDK.
 *
 * <p>Data is scoped by the authenticated app principal. Request parameters never select a target
 * app id, and logical namespaces or keys are not host filesystem paths. File-backed storage hashes
 * record keys before they become directory names and keeps host roots, staging paths, tokens,
 * private insert URIs, and raw secret material out of responses.
 *
 * <p>The durable store is intended for bounded app-owned user state such as drafts, read markers,
 * UI preferences, feed source metadata, and short publish summaries. It deliberately does not
 * provide arbitrary file access, a query engine, secret storage, or the future durable Trust Graph
 * backend.
 */
package network.crypta.platform.api.appdata;
