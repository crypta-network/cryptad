/**
 * Deterministic local app-bundle digest and signature primitives.
 *
 * <p>This package owns the signed-distribution sidecars for locally staged Crypta application
 * bundles. It defines the deterministic {@code cryptad-app.digests} format, the corresponding
 * {@code cryptad-app.signature} format, the deterministic bundle ZIP packager, the JDK-only SHA-256
 * and Ed25519 helpers that write and verify those sidecars, and the immutable trust model used by
 * higher layers.
 *
 * <p>The implementation intentionally stays below AppHost, HTTP adapters, shell code, and runtime
 * process orchestration. It works only with local bundle directories, regular files, and explicit
 * trusted public keys so higher layers can enforce signing without coupling distribution metadata
 * to transport or runtime concerns. The package also contains the shared manifest parser used by
 * signing tools and AppHost adapters so signed-bundle validation and runtime installation interpret
 * {@code cryptad-app.properties} the same way.
 *
 * <p>This is not a remote app-store implementation. It does not fetch catalogs, resolve download
 * URLs, serve app assets, or manage production private keys. Those responsibilities belong to
 * higher-level distribution or release tooling built on top of these local, deterministic
 * primitives.
 */
package network.crypta.platform.appdist;
