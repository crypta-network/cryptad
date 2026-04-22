/**
 * Signed app catalog parsing, fetching, artifact verification, and staging support.
 *
 * <p>This package is the distribution layer above local signed app bundles and below AppHost
 * process orchestration. It verifies catalog sidecars, downloads or reads bundle artifacts, checks
 * catalog-declared artifact size and SHA-256 metadata, safely extracts ZIP artifacts into
 * host-owned staging directories, and then reuses {@code platform-appdist} bundle verification
 * before callers install or update through AppHost. The package does not launch apps or own runtime
 * lifecycle state.
 *
 * <p>The trust order is fixed:
 *
 * <ol>
 *   <li>Verify {@code cryptad-app-catalog.signature} over the exact catalog properties bytes.
 *   <li>Validate catalog metadata, source/artifact URI policy, artifact size, and artifact digest.
 *   <li>Extract the ZIP into scratch space and verify the extracted signed app bundle.
 * </ol>
 *
 * <p>All network and filesystem work uses JDK APIs only. JSON, HTTP, ZIP, crypto, and catalog
 * parsing remain dependency-free in this leaf so it can serve as a narrow distribution primitive
 * for Platform API and Web Shell integration without introducing runtime process orchestration
 * here.
 */
package network.crypta.platform.appcatalog;
