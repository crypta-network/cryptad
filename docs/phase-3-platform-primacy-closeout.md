# Phase 3 Platform Primacy Closeout

This document records the Phase 3 Platform Primacy state after PR-194: what landed, which modules
owned the platform surfaces at closeout, which release gates must pass, and which work stayed
deferred at that snapshot. Later Phase 4 app-platform work has since added signed app catalogs and
app-owned static UI routes; those current contracts live in [app-catalogs.md](app-catalogs.md) and
[app-owned-ui.md](app-owned-ui.md).

## Status

Phase 3 is complete as of PR-194, assuming the release gates below pass.

PR-194 is a documentation and release-readiness closeout. It does not remove legacy HTTP or FCP,
change AppHost runtime semantics, change signed-app cryptography, or change wire, routing, key, or
persistent formats.

## Goals

Phase 3 made the platform path the primary local operator and first-party app path:

- Shell-native control plane through Platform API v1 and Web Shell v1.
- First-party AppHost apps for queue management and publishing workflows.
- Signed local app distribution for staged first-party app bundles.
- Hyphanet/Freenet compatibility coverage through the packaged-node interop gate.

Legacy HTTP and FCP remain available. They are compatibility, bridge, debug, and fallback surfaces,
not removed components.

## PR map

| PR | Area | Result |
| --- | --- | --- |
| PR-184 | Browse detach | Cleaned up the tail of the legacy browse detachment work and kept browse/FProxy concerns owned by the legacy browse adapter. |
| PR-185 | Platform API mutation plumbing | Added the mutation plumbing needed for shell-native control-plane actions instead of read-only snapshots only. |
| PR-186 | Queue control plane | Made queue snapshots, direct downloads, request mutations, cleanup, and queue key export reachable through Platform API and Web Shell surfaces. |
| PR-187 | Peer control plane | Added Platform API and Web Shell peer roster, add, settings, note, and removal flows on top of detached runtime peer ports. |
| PR-188 | Config, update, and wizard control plane | Brought config overrides/persistence, core-update download triggering, and first-time wizard submission into the platform path. |
| PR-189 | Alerts and diagnostics surface | Added Platform API and Web Shell alert listing/dismissal plus diagnostics snapshots and text export. |
| PR-190 | First-party app toolchain and Queue Manager app | Added first-party app staging/tooling and the Queue Manager app bundle that deep-links into the shell queue surface. |
| PR-191 | Publisher first-party app | Added the Publisher app bundle and shell-native local file/directory insert workflow. |
| PR-192 | Signed local app distribution | Added deterministic digest sidecars, Ed25519 signatures, Gradle signing/verification tasks, and AppHost trusted-key checks for local staged bundles. |
| PR-193 | Hyphanet interop gate | Added the packaged-node Hyphanet interop smoke harness and CI gate under `tools/interop/`. |
| PR-194 | Closeout and release readiness | Documents the completed Phase 3 state, release gates, Platform API/Web Shell surface, and Phase 4 candidates. |

## Current platform architecture

The Phase 3 platform path is split across focused modules:

- `:runtime-spi` owns the detached runtime ports and DTOs used by the platform layer. It is the
  JDK-only boundary between shell/API code and daemon-backed runtime implementations.
- `:platform-api` owns the transport-neutral Platform API v1 router, JSON response/error helpers,
  and endpoint handlers for node, connectivity, queue, peers, config, security levels, updates,
  wizard, alerts, diagnostics, and apps.
- `:platform-web-shell` owns the browser-facing Web Shell v1 page contract, bootstrap model, route
  constants, and static browser assets. The current shell is mounted at `/app/node/`.
- `:platform-apphost` owns the transport-neutral local AppHost core: manifest parsing, installed
  app layout, process lifecycle, running-state snapshots, and launch-token plumbing.
- `:platform-appdist` owns the local app distribution tooling used to digest, sign, and verify
  staged bundles.
- `apps/queue-manager` owns the Queue Manager first-party app bundle. Its `app.ui.entry` points to
  `/app/node/#queue`.
- `apps/publisher` owns the Publisher first-party app bundle. Its `app.ui.entry` points to
  `/app/node/#publisher`.
- `:adapter-fcp` owns the detached FCP protocol adapter surface. It remains a compatibility and
  automation protocol, separate from Platform API.
- `:bridge-fcp-runtime` owns the concrete runtime bindings for FCP.
- `:adapter-http-legacy-admin` owns the shared legacy HTTP admin shell, admin toadlets, the
  `/api/v1/` Platform API bridge, and the `/app/node/` Web Shell bridge.
- `:adapter-http-legacy-browse` owns concrete legacy browse/FProxy routes and helpers.
- `:bridge-http-runtime` owns concrete runtime bindings for legacy HTTP.
- `tools/interop` owns the packaged-node Hyphanet interop smoke harness and checked-in baseline
  defaults.

The main production composition still starts from root-owned bootstrap code. The Phase 3 change is
that routine local operator workflows now have a first-party platform path through Platform API and
Web Shell, while the legacy adapters continue to host transport, auth, compatibility, and fallback
behavior.

## First-party apps and signed local distribution

First-party app bundles are staged by their app modules and by root convenience tasks:

- `./gradlew :apps:queue-manager:stageApp`
- `./gradlew :apps:publisher:stageApp`
- `./gradlew stageFirstPartyApps`

Signing and verification are separate release gates:

- `./gradlew signFirstPartyApps`
- `./gradlew verifyFirstPartyApps`

Signing inputs, trusted-key inputs, sidecar formats, and local install/update examples are
documented in [app-distribution.md](app-distribution.md). The staged bundles are local bundles.
At the PR-194 snapshot, remote catalogs, remote bundle downloads, app-owned static UI serving, and
browser-side uploads were still future work. Current catalog and app-owned static UI behavior is
documented in [app-catalogs.md](app-catalogs.md) and [app-owned-ui.md](app-owned-ui.md).

## Platform API and Web Shell

Platform API v1 is mounted at `/api/v1/` through the legacy HTTP admin bridge. The API is currently
a local/internal control plane, not a declared stable remote public API.

Web Shell v1 is mounted at `/app/node/` through the legacy HTTP admin bridge. It uses the Platform
API for shell-native node management and still exposes legacy deep links for flows that remain
fallback or debug surfaces.

The current family-level surface is documented in
[platform-api-surface.md](platform-api-surface.md).

## Hyphanet interop gate

PR-193 added the interop harness. It is present and should be treated as an existing release gate,
not recreated:

- `tools/interop/README.md`
- `tools/interop/hyphanet-baseline.env`
- `tools/interop/run-hyphanet-interop-smoke.sh`
- `tools/interop/interop_smoke.py`

CI runs the gate through the `interop-smoke` job in `.github/workflows/ci.yml` after building a
runnable Cryptad distribution. Local usage and diagnostics are documented in
[tools/interop/README.md](../tools/interop/README.md).

## Release gates

Treat these gates as blockers before promoting a Phase 3 release:

1. Run the normal Gradle build/test gate for the release branch.
2. Stage first-party apps.
3. Sign first-party apps with the intended release or staging signing inputs.
4. Verify first-party apps with the matching trusted public key inputs.
5. Run the Hyphanet interop smoke gate locally or verify the CI `interop-smoke` job passed.
6. Preserve `build/interop-smoke/` diagnostics when the interop smoke fails.

The release runbook records the same gates in
[cryptad-release-workflow-and-runbook.md](cryptad-release-workflow-and-runbook.md).

## Deferred to Phase 4

Phase 4 candidates were plans, not PR-194 implementation scope. Current status:

- Remote signed app catalogs and verified artifact staging have landed; background update
  scheduling remains future work.
- App-owned static UI routes have landed for installed static bundles; stronger isolation remains
  future work.
- Broader first-party app catalog remains future work.
- Better app permission enforcement and audit surfaces remain future work.
- Legacy admin and browse retirement plan.
- Longer USK and persistent-request interop soak tests.
- Multi-OS interop matrix.
- Opennet interop gate.
- Performance and regression gates.
