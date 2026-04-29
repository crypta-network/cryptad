/**
 * Developer-facing command-line tooling for app bundle scaffolding, validation, packaging, and
 * catalog authoring.
 *
 * <p>This leaf module wires reusable app distribution, catalog, SDK, and capability-registry
 * helpers into a local CLI. The package owns command-line UX, template rendering, key-material
 * option handling, and developer-specific lint presentation. Bundle format rules stay in {@code
 * platform-appdist}; catalog serialization, signing, and verification stay in {@code
 * platform-appcatalog}.
 *
 * <p>The package intentionally stays out of daemon/runtime code paths. It should not depend on
 * app-host, runtime-node, HTTP adapter, or FCP adapter modules, and it should avoid introducing
 * install-time behavior that belongs in the platform catalog installer.
 */
package network.crypta.platform.devtools;
