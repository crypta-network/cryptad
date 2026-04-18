/**
 * Core-update Platform API handlers.
 *
 * <p>This package owns the deliberately small updater control-plane surface introduced for Platform
 * API v1. The code here lets transport-neutral callers ask whether the daemon exposes the core
 * updater and whether a shell-native manual download is currently actionable, then trigger the same
 * download path that the legacy updater page already uses.
 *
 * <p>The package does not replace the full legacy updater experience. Platform-specific installer
 * launching, package-store handoff, progress-oriented UI details, and recovery guidance still live
 * on the legacy HTTP side. The classes here therefore focus on stable JSON contracts and detached
 * runtime seams that make the shell more operational without broadening the updater API beyond the
 * current Phase 3 scope.
 */
package network.crypta.platform.api.updates;
