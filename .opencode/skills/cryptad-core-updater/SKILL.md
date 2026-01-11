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
  - Selects an OS/arch-specific installer (deb/rpm/dmg/exe/flatpak/snap).
  - Downloads to `nodeDir/updates/core/<version>/`.
- Plugin updates remain unchanged.

## System wiring changes
- `MainJarUpdater` was removed.
- `NodeUpdateManager` now coordinates:
  - `CoreUpdater` for core packages
  - `PluginJarUpdater` for plugins
- JAR Update-over-Mandatory is disabled:
  - `supportsJarUOM()` returns false
  - Legacy jar UOM paths are gated/no-ops.

## Endpoint and UI
- HTTP endpoint: `/core-update/`
- Actions: `download`, `install`, `openStore`
- UI: alerts panel shows progress percent when available.
  - Failures surface clear retry guidance (non-fatal errors relabel to “Retry”).

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
  - `version`
  - `packages` keyed by `<arch>.<ext>`
  - optional `changelog_chk` / `fullchangelog_chk`
- CHK integrity covers content.
- Any historical `sha256` fields in descriptors are ignored.
