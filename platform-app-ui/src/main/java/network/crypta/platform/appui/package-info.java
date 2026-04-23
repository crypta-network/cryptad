/**
 * Static browser UI routing and file-resolution helpers for installed AppHost bundles.
 *
 * <p>This package keeps app-owned UI path parsing, public URL construction, content-type mapping,
 * and installed-bundle asset confinement outside the legacy HTTP adapter. HTTP bridges should stay
 * thin: authorize the request, ask these helpers for the app-owned asset, and stream the resolved
 * file with the returned metadata.
 *
 * <p>The package is intentionally transport-neutral. It depends on AppHost snapshots and manifest
 * metadata, but it does not know about toadlets, servlet APIs, or any particular response writer.
 * That boundary lets future adapters reuse the same rules for {@code /apps/{appId}/}: decode raw
 * route segments safely, keep static assets under the immutable installed bundle root, reject
 * traversal and symbolic-link escapes, and publish launch URLs that preserve browser-relative asset
 * resolution for nested static entries.
 *
 * <p>This layer does not enforce app permissions, execute app code, or serve mutable app data and
 * cache directories. It only describes and resolves app-owned static UI files that were installed
 * as part of the signed bundle.
 */
package network.crypta.platform.appui;
