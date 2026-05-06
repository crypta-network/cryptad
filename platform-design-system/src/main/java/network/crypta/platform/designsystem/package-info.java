/**
 * Canonical static assets and copy helpers for Crypta app-owned browser UI.
 *
 * <p>The design-system module is intentionally leaf-sized. It publishes local CSS and optional
 * progressive-enhancement JavaScript that app bundles vendor under {@code static/crypta-ui/}, plus
 * Java helpers for deterministic asset metadata and safe bundle staging.
 *
 * <p>The package does not define a component framework or a runtime dependency for app authors.
 * Instead it gives platform tooling a stable source for the small asset set used by scaffolded
 * apps, first-party app staging, UI lint, and release-certification evidence. Assets remain
 * bundle-local so static app UI works under both the same-origin fallback route and isolated
 * loopback app origins without allowing remote style or script dependencies.
 */
package network.crypta.platform.designsystem;
