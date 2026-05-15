/**
 * Loopback-only local development server for staged static Crypta app bundles.
 *
 * <p>The package is owned by {@code platform-devtools}. It serves scaffolded static assets and a
 * deterministic mock Platform API for offline developer testing. The server provides the same
 * bootstrap and browser-session shape used by the browser SDK, but all data is local fixture data
 * or built-in safe mock content. It is useful for template development, app lint/test smoke checks,
 * and documentation examples that need a same-origin Platform API without a running daemon.
 *
 * <p>This package is not an AppHost replacement and does not install, update, sandbox, review, or
 * publish apps. Static asset resolution stays within the staged bundle, rejects reserved sidecars
 * and private-material names, and refuses symlink escapes. The default host policy binds to
 * loopback; non-loopback listeners are an explicit developer opt-in and should be used only on
 * trusted networks.
 */
package network.crypta.platform.devtools.devserver;
