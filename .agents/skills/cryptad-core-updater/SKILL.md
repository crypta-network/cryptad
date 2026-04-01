---
name: cryptad-core-updater
description: "Understand and modify the package-based CoreUpdater update system: /core-update/ endpoints, descriptor format, UI wiring, and platform behaviors."
compatibility: opencode
metadata:
  area: updater
  domain: cryptad
---

## When to use
Use this skill when working on:
- Core update discovery/download/install flows
- `NodeUpdateManager` and updater wiring
- `/core-update/` HTTP endpoint and UI surfacing
- Platform-specific installer behaviors (Linux/macOS/Windows/Flatpak/Snap)

## CoreUpdater migration (conceptual overview)
- Core package-based updates replace self-updating of `cryptad.jar`.
- The updater:
  - Fetches `info/<N>` JSON from the existing update USK.
  - Treats `CoreInfo.version` as the release gate: it must be a base-10 integer string and be
    greater than `Version.currentBuildNumber()` for update availability.
  - Selects an OS/arch-specific installer (deb/rpm/dmg/exe/flatpak/snap).
  - Downloads to `nodeDir/updates/core/<version>/`.
- Plugin updates remain unchanged.

## System wiring changes
- Legacy core jar updater was removed.
- `NodeUpdateManager` now coordinates:
  - `CoreUpdater` for core packages
  - `PluginJarUpdater` for plugins
- The legacy HTTP updater UI now crosses the runtime boundary through
  `RuntimePorts#coreUpdateAction()` and `network.crypta.runtime.spi.CoreUpdateActionPort`,
  implemented in the root daemon by `network.crypta.runtime.core.LegacyCoreUpdateActionPort`.
- Core updater state surfaces through CorePackage-named APIs:
  - `hasNewCorePackage()`, `newCorePackageVersion()`, `newCorePackageVersionLabel()`
  - `fetchingNewCorePackage()`, `fetchingNewCorePackageVersion()`
- JAR Update-over-Mandatory for core payload transfer is disabled; legacy jar UOM paths remain
  gated/no-ops while revocation/dependency signaling is still active.

## Versioning and discovery details
- Discovery still follows USK editions (`info/<N>`) and keeps startup subscribe seeding logic from
  persisted fetched editions.
- Release gating and user-facing version labels come from descriptor `version`:
  - strict integer parse only
  - missing/non-integer/overflow => do not advertise update available
- Changelog link resolution still uses edition/build-based URIs when CHK links are absent.

## Endpoint and UI
- HTTP endpoint: `/core-update/`
- Actions: `download`, `install`, `openStore`
- UI: alerts panel shows progress percent when available.
  - Failures surface clear retry guidance (non-fatal errors relabel to “Retry”).
- Request parsing, redirects, `AppEnv` checks, and OS-specific installer or store-launching now
  live in the HTTP adapter layer at `network.crypta.clients.http.updater.CoreActionToadlet`.
- Daemon-backed availability checks, UI-triggered download start, and downloaded-installer
  containment validation now live behind `CoreUpdateActionPort`.

## Runtime-boundary classes to inspect
- HTTP/action layer: `network.crypta.clients.http.updater.CoreActionToadlet`
- Updater coordinator/state: `network.crypta.runtime.updater.NodeUpdateManager`
- Core package downloader: `network.crypta.runtime.updater.CoreUpdater`
- SPI contract: `network.crypta.runtime.spi.CoreUpdateActionPort`
- Root adapter: `network.crypta.runtime.core.LegacyCoreUpdateActionPort`
- Aggregate runtime entry point: `network.crypta.runtime.spi.RuntimePorts`

## Platform specifics (selected behaviors)
- Linux:
  - Prefers GUI handoff (`gio`/`xdg-open`) or PackageKit.
  - In Flatpak, uses the portal / `flatpak-spawn` to bridge to host tools.
  - `.snap` files are never GUI-opened; installs use `snap install --dangerous`.
- macOS:
  - Adds Gatekeeper guidance for unsigned builds.
- Windows:
  - Adds SmartScreen guidance and SHA-256 verification tips.

## Environment detection (important)
- `AppEnv` is the single source of truth for OS/arch/sandbox/service detection.
- Do not add new `os.name`/`os.arch` checks; use `AppEnv` APIs.

## Descriptor format and integrity
- JSON includes:
  - `version` (required integer string for release gating)
  - `packages` keyed by `<arch>.<ext>`
  - optional `changelog_chk` / `fullchangelog_chk`
- CHK integrity covers content.
- Any historical `sha256` fields in descriptors are ignored.

## UOM compatibility note
- Code identifiers have been renamed to Core/CorePackage terminology.
- UOM wire compatibility keeps legacy field/type strings where required:
  - field payload names such as `"mainJarKey"`, `"mainJarVersion"`, `"mainJarFileLength"`
  - message type strings `"CryptadUOMRequestMainJar"` / `"CryptadUOMSendingMainJar"`
