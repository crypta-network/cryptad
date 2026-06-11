# Plugin system status

Last updated: 2026-06-10

This document defines Cryptad's production RC status for the legacy in-process plugin system.

## Production RC policy

The old in-process plugin runtime is removed and frozen. Cryptad must not reintroduce the legacy
plugin manager, old plugin ABI, plugin toadlets, or old FCP plugin execution paths as part of the
production RC app-platform transition.

The detailed freeze boundary is maintained in
[legacy-plugin-freeze-policy.md](legacy-plugin-freeze-policy.md). Migration guidance is maintained
in [legacy-plugin-migration-guide.md](legacy-plugin-migration-guide.md).

## Removed and frozen surfaces

The following legacy surfaces are not implementation commitments:

| Surface | Production RC status |
| --- | --- |
| `network.crypta.pluginmanager` and in-core plugin lifecycle APIs | Removed and frozen. Do not add new in-core plugin APIs. |
| Legacy plugin ABI classes such as `PluginManager`, `PluginRespirator`, and `PluginTalker` | Removed. Do not add compatibility shims. |
| Plugin toadlets and legacy plugin admin pages | Removed. Replacement UI belongs in app-owned UI or Web Shell surfaces. |
| Old FCP plugin commands such as `FCPPluginMessage`, `GetPluginInfo`, `LoadPlugin`, `ReloadPlugin`, and `RemovePlugin` | Must continue to fail deterministically through the unsupported-command handler. They must not dispatch to plugin execution. |
| Core update behavior | Package-based through `CoreUpdater`; not plugin-based. |
| Historical plugin documentation under `docs/legacy/**` | Historical archive only. It does not define current runtime behavior or compatibility commitments. |

## Forward path

Plugin-like functionality should move to out-of-process app/platform mechanisms:

- Signed app bundles and signed catalogs for distribution.
- Platform API routes for bounded node interaction.
- App-owned isolated UI plus the browser SDK for local user workflows.
- AppVault for app-owned identity, secret material, and bounded signing operations.
- Durable app data for app-owned mutable state.
- Content subscriptions for bounded follow/poll workflows.
- Trust Graph Local RC for local advisory trust scoring, exposed to other apps through
  operator-approved app-service grants.
- App-service discovery, grant bundles, and active grants for mediated local app-to-app service
  calls.

These mechanisms keep authority explicit. Apps declare capabilities, catalogs and bundles verify
distribution artifacts, and operators approve local app-service grants before one app can call
another app's advertised service.

## Non-goals

The production RC policy does not restore:

- Old plugin ABI compatibility.
- Old FCP plugin command compatibility.
- WebOfTrust plugin compatibility.
- Freetalk, Sone, or Freemail compatibility.
- Encrypted mail transport.
- A daemon-core social or mail store.
- A generic localhost RPC bridge.
- New FNP, FCP, or peer wire-protocol behavior.

## Certification

Release certification should include `legacy-plugin.freeze-policy` evidence. The evidence should
prove that the freeze policy is documented, that legacy FCP plugin command names still fail
deterministically, and that no in-core plugin runtime/API surface has been reintroduced.
