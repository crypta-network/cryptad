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
- Stable 1.0 `support-lifecycle` discovery, persistence, trust invalidation, and local status
  exposure
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
- Stable 1.0 support state crosses the runtime boundary as the immutable
  `CoreSupportLifecycleSnapshot` returned by `CoreUpdateActionPort#supportLifecycleSnapshot()`.
  Platform API and Web Shell must not reach updater internals directly.
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
- Platform API separates app-readable update readiness from operator support state:
  - `GET /api/v1/updates/core` reports only updater availability and download readiness.
  - `GET /api/v1/updates/support-lifecycle` is host/operator-only and returns the redacted
    last-known-good lifecycle projection.
  - Web Shell fetches those routes independently; never add lifecycle state back to the
    app-readable core response.
- UI: alerts panel shows progress percent when available.
  - Failures surface clear retry guidance (non-fatal errors relabel to “Retry”).
- `NodeUpdater` intentionally delays retries for `FetchExceptionMode.RECENTLY_FAILED` instead of
  rescheduling immediately while the key is still in the recently-failed table. Preserve that
  throttle unless replacing it with an explicit, tested retry policy.
- Request parsing, redirects, `AppEnv` checks, and OS-specific installer or store-launching now
  live in the HTTP adapter layer at `network.crypta.clients.http.updater.CoreActionToadlet`,
  currently packaged in `:adapter-http-legacy-admin`.
- Daemon-backed availability checks, UI-triggered download start, downloaded-installer containment
  validation, and exact current store-target validation now live behind `CoreUpdateActionPort`.

## Runtime-boundary classes to inspect
- HTTP/action layer (`:adapter-http-legacy-admin`): `network.crypta.clients.http.updater.CoreActionToadlet`
- Updater coordinator/state (`:runtime-node`): `network.crypta.runtime.updater.NodeUpdateManager`
- Core package downloader (`:runtime-node`): `network.crypta.runtime.updater.CoreUpdater`
- Lifecycle subscriber/model/parser/store (`:runtime-node`):
  `CoreSupportLifecycleUpdater`, `CoreSupportLifecycleState`, `CoreSupportLifecycleParser`,
  `CoreSupportLifecycleStore`, `CoreSupportLifecycleDescriptor`, and
  `CoreSupportLifecycleEntry`
- SPI contract: `network.crypta.runtime.spi.CoreUpdateActionPort`
- SPI lifecycle values: `network.crypta.runtime.spi.CoreSupportLifecycleSnapshot` and
  `CoreSupportLifecycleStatus`
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
Bind the plan and receipt to the exact public fetch URI and USK edition, not only to the descriptor
and package-map digests. The published descriptor's CHK/store references must use canonical public
destinations whose resolved addresses are global. A receipt for a different URI, edition, package
target, or fetched byte sequence cannot activate a successor baseline.
The protected workflow loads the reviewed provider named by
`CRYPTAD_STABLE_MAINTENANCE_PUBLICATION_BACKEND` and exposes
`CRYPTAD_CORE_UPDATE_PUBLICATION_INPUT` only to the CoreUpdater target operation. Never reuse the
catalog or maintenance-state protected input for update insertion, and never serialize the private
input into the descriptor, plan, receipt, logs, or uploaded artifacts.
The provider's public deployment-service verification receives the authenticated CoreUpdater plan
and descriptor inside its closed `verificationInputs` set. It must construct a complete updater
receipt from those exact records; it must not rely on an undocumented service-side copy. The
protected adapter independently validates `verificationStatus`, public fetch URI, edition,
descriptor bytes, and every referenced package before accepting that receipt.

Use `AppEnv` for platform/package-key mapping and follow
`docs/stable-1.0-maintenance-release-and-hotfix-path.md`.

## Stable 1.0 support lifecycle descriptor

Build support state is mutable and must not be added to or changed in an already published
`core-info.json`. The runtime obtains the separate `support-lifecycle` document under the same
trusted public update-key identity, validates its closed schema and release identities, and retains
the last-known-good exact bytes plus edition and digest on disk. Reject a wrong key scope/docname,
unknown schema or status, edition rollback, previous-digest mismatch, release-identity mutation,
multiple current builds, or a current build that is not the authenticated release-chain tip.

Keep the read-only lifecycle subscriber active when `node.updater.enabled=false`; that setting
disables package fetching and installation, not local support/security status discovery. A genuine
update-key blow still stops lifecycle fetching because the lifecycle document shares that public
trust key. Persist accepted bytes at
`nodeDir/updates/core/support-lifecycle-last-known-good.json`, seed the subscription from the
accepted edition after restart, and fetch digest-linked successor editions sequentially. Fetch,
validation, or persistence failure retains the prior descriptor. Persistence retry must remain
bounded/backed off, and stale callbacks or temporary blobs from a replaced URI/subscription must
not regress accepted state or leak files.
Persist the bounded public-safe
`support-lifecycle-last-known-good.json.revocation-activations` sibling before replacing the
descriptor. It records when each terminal revocation first became enforceable, so a
future-effective successor preserves predecessor revocations across restart without activating a
new revocation early. If this derived state is absent or invalid, fail closed from each authenticated
revoked entry's own effective time rather than suspending a potentially prior terminal revocation.
Clear this derived state with the descriptor after update-key compromise.

Local-only package-updater failure must leave both lifecycle polling and revocation-key polling
active; only authenticated update-key compromise invalidates documents under that key. Package
payload downloads remain serialized, but completion of an older CHK fetch must retry a newer
automatic selection that was advertised while the older fetch was active.

Lifecycle persistence is crash-durable and platform-aware. Force completed temporary bytes before
publishing them; synchronize the parent-directory entry where supported and use the Windows native
write-through move instead of opening a Windows directory as a file channel. Resolve and pin the
`ProgramDirectory`-accepted node root before deriving lifecycle paths; allow that configured root
to use a symlink while rejecting symlinks in controlled descendants and descriptor/marker leaves.
Do not treat an accepted symlinked node-directory path as compromise evidence when no marker exists.

An authenticated update-key compromise invalidates cached lifecycle authority and package-update
authority across restart. Maintain the fixed-content sibling marker and independent node-level
fallback marker, treat an existing malformed/symbolic/unreadable marker as fail-closed compromise
evidence, retry failed marker persistence with bounded backoff, restore the critical operator alert
on restart, and block both package and lifecycle subscribers. Local-only updater failure must not
create that durable compromise latch or permanently stop lifecycle polling.

Expose only the detached, public-safe lifecycle snapshot through `CoreUpdateActionPort`. Unknown or
stale state must remain explicit; never infer support from update availability or the running build
number. Build `revoked` is a lifecycle-policy decision and must not call, alias, or otherwise trigger
the update-key blow/revocation path. End-of-support and build revocation surface actionable local
warnings without deleting data, shutting down the node, disabling FProxy browse, or inventing a
forced-update path.

Recheck effective build revocation at every package-action boundary. A later accepted descriptor
whose activation time is ahead of the local clock must not suspend an already-effective terminal
revocation preserved in its entry chain. Publish descriptor metadata, integer build identity,
detected environment, selected package key, and package specification as one immutable atomic
snapshot. Every download, installer, store-handoff, retry, and UI reader must use one snapshot
instance and reject it if a newer snapshot replaced it before the action boundary. Downloaded
installer launch and Linux `openStore` submission both cross `CoreUpdateActionPort`; never return a
detached installer path after authorization. Run the bounded installer-launch callback while the
manager identity, updater selection, and lifecycle-state authorization remain held, then release
those locks before rendering the HTTP response. Store submissions must exactly match the daemon's
current selected kind, derived id, and public URL before the HTTP adapter may open or install them.

The lifecycle descriptor's public schema, protected publication, and operator behavior are defined
in `docs/stable-1.0-support-lifecycle-and-deprecation-governance.md`. Use deterministic local
fixtures for fetch, rollback, persistence, stale-state, and release-identity tests; do not require
live DNS or update-key publication.
