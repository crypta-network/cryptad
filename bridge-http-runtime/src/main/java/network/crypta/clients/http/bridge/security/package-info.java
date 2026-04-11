/**
 * Concrete security-page rendering bridges for the legacy HTTP shell.
 *
 * <p>This package now lives in {@code :bridge-http-runtime}. It contains the renderer
 * implementations that adapt runtime-owned security page seams to the legacy HTTP admin UI. The
 * bridge code here preserves the existing password-prompt form structure, submit targets, and
 * legacy page-builder calls that the current administrative flows still expect. That includes the
 * shared password form used during first-time setup and during later security-level changes that
 * require the node's master password.
 *
 * <p>The runtime-owned seam under {@code network.crypta.runtime.http.security} remains the contract
 * that bootstrap and runtime code should depend on. This package owns only the default adapter
 * implementations that translate that neutral prompt state into the legacy HTTP renderer behavior.
 * Keeping the concrete renderer in the separate bridge leaf preserves the current HTML output while
 * making the ownership boundary explicit.
 */
package network.crypta.clients.http.bridge.security;
