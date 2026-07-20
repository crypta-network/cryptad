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
- The legacy plugin runtime has been removed. This skill only covers core package update flows.
- The updater:
  - Fetches `info/<N>` JSON from the existing update USK.
  - Treats `CoreInfo.version` as the release gate: it must be a base-10 integer string and be
    greater than `Version.currentBuildNumber()` for update availability.
  - Selects an OS/arch-specific installer (deb/rpm/dmg/exe/flatpak/snap).
  - Downloads to `nodeDir/updates/core/<version>/`.

## System wiring changes
- Legacy core jar updater was removed.
- `NodeUpdateManager` now coordinates core-package discovery, download, and install signaling.
- The legacy HTTP updater UI now crosses the runtime boundary through
  `RuntimePorts#coreUpdateAction()` and `network.crypta.runtime.spi.CoreUpdateActionPort`,
  implemented by the daemon-backed runtime adapter
  `network.crypta.runtime.core.LegacyCoreUpdateActionPort` in `:runtime-node`.
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
- `NodeUpdater` intentionally delays retries for `FetchExceptionMode.RECENTLY_FAILED` instead of
  rescheduling immediately while the key is still in the recently-failed table. Preserve that
  throttle unless replacing it with an explicit, tested retry policy.
- Request parsing, redirects, `AppEnv` checks, and OS-specific installer or store-launching now
  live in the HTTP adapter layer at `network.crypta.clients.http.updater.CoreActionToadlet`,
  currently packaged in `:adapter-http-legacy-admin`.
- Daemon-backed availability checks, UI-triggered download start, and downloaded-installer
  containment validation now live behind `CoreUpdateActionPort`.

## Runtime-boundary classes to inspect
- HTTP/action layer (`:adapter-http-legacy-admin`): `network.crypta.clients.http.updater.CoreActionToadlet`
- Updater coordinator/state (`:runtime-node`): `network.crypta.runtime.updater.NodeUpdateManager`
- Core package downloader (`:runtime-node`): `network.crypta.runtime.updater.CoreUpdater`
- SPI contract: `network.crypta.runtime.spi.CoreUpdateActionPort`
- Daemon-backed adapter (`:runtime-node`): `network.crypta.runtime.core.LegacyCoreUpdateActionPort`
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

## Stable 1.0 maintenance descriptor publication

For a Stable 1.0 maintenance or security-hotfix candidate, `stable-maintenance` generates
deterministic `core-info.json` bytes bound to the exact frozen packages. Require the canonical
integer `version`, public release page, sorted supported `<arch>.<ext>` package keys, public CHK or
store URLs, and authenticated package sizes. Every required candidate package must appear exactly
once; do not add a misleading local SHA-256 field, placeholder, private insert URI, or local path.

Include the descriptor digest in checksums, provenance, authorization, and the publication plan.
The update USK private insert URI/key is a protected secret supplied only at the publication
boundary. After insertion, fetch through the public request URI, compare exact descriptor bytes and
referenced package identities, and record a separate updater publication receipt. Conflict or an
unavailable public observation is not idempotent success and must not be overwritten.
The protected workflow loads the reviewed provider named by
`CRYPTAD_STABLE_MAINTENANCE_PUBLICATION_BACKEND` and exposes
`CRYPTAD_CORE_UPDATE_PUBLICATION_INPUT` only to the CoreUpdater target operation. Never reuse the
catalog or maintenance-state protected input for update insertion, and never serialize the private
input into the descriptor, plan, receipt, logs, or uploaded artifacts.

Use `AppEnv` for platform/package-key mapping and follow
`docs/stable-1.0-maintenance-release-and-hotfix-path.md`.
