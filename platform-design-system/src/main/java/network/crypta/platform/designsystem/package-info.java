/**
 * Canonical static assets and copy helpers for Crypta app-owned browser UI.
 *
 * <p>The design-system module is intentionally leaf-sized. It publishes local CSS and optional
 * progressive-enhancement JavaScript that app bundles vendor under {@code static/crypta-ui/}, plus
 * Java helpers for deterministic asset metadata and safe bundle staging. The package is shared by
 * first-party app staging tasks and standalone developer tooling, so asset names and bundle paths
 * should remain stable unless the app UI lint and distribution documentation are updated together.
 *
 * <p>The package does not define a component framework or a runtime dependency for app authors.
 * Instead it gives platform tooling a stable source for the small asset set used by scaffolded
 * apps, first-party app staging, UI lint, and release-certification evidence. Assets remain
 * bundle-local so static app UI works under both the same-origin fallback route and isolated
 * loopback app origins without allowing remote style or script dependencies. The Java API also
 * centralizes SHA-256 and MIME metadata, which keeps lint reports and release evidence aligned with
 * the exact bytes shipped in the platform build.
 *
 * @see network.crypta.platform.designsystem.DesignSystemAssets
 * @see network.crypta.platform.designsystem.DesignSystemAsset
 */
package network.crypta.platform.designsystem;
