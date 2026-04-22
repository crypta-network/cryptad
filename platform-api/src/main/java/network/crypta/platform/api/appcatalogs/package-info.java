/**
 * Platform API handlers for signed app catalog source and catalog-app operations.
 *
 * <p>The package adapts the transport-neutral catalog manager to JSON-compatible response maps and
 * delegates final app installation or update to AppHost. Existing local staged-directory app routes
 * remain owned by {@code network.crypta.platform.api.apps}.
 *
 * <p>Routes in this package are the HTTP/API control surface for PR-195. They expose configured
 * catalog sources, catalog app metadata, and catalog-backed install/update commands, but they do
 * not fetch artifacts directly or manage app processes. The lower catalog module performs source
 * fetch, signature verification, artifact digest checks, and safe ZIP staging. AppHost still owns
 * the final install tree, update semantics, and running-process checks.
 *
 * <p>Error mapping is part of the package contract. Catalog-specific failures keep stable codes
 * such as {@code invalid_catalog_signature}, {@code artifact_digest_mismatch}, and {@code
 * invalid_app_bundle}; AppHost lifecycle conflicts continue to use the same app API codes as local
 * staged-directory operations.
 */
package network.crypta.platform.api.appcatalogs;
