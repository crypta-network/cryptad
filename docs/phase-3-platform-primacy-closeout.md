# Phase 3 Platform Primacy Closeout

This document records the Phase 3 Platform Primacy state after PR-194: what landed, which modules
owned the platform surfaces at closeout, which release gates must pass, and which work stayed
deferred at that snapshot. Later app-platform work has since added signed app catalogs,
app-owned static UI routes, and release-certification evidence aggregation. Current contracts live
in [app-catalogs.md](app-catalogs.md), [app-owned-ui.md](app-owned-ui.md), and
[release-certification.md](release-certification.md).

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
  wizard, alerts, diagnostics, apps, app updates, app catalogs, and app-vault routes.
- `:platform-web-shell` owns the browser-facing Web Shell v1 page contract, bootstrap model, route
  constants, and static browser assets. The current shell is mounted at `/app/node/`.
- `:platform-apphost` owns the transport-neutral local AppHost core: manifest parsing, installed
  app layout, process lifecycle, running-state snapshots, launch-token plumbing, sandbox status
  reporting, data/cache quota checks, and bounded process-log handling.
- `:platform-app-ui` owns app-owned static UI route helpers and short-lived browser sessions for
  static app Platform API calls.
- `:platform-appvault` owns local app secret and identity vault records, grant metadata,
  wrapping-key lookup, and audit/redaction value types used by app/vault Platform API workflows.
- `:platform-sdk-js` owns the browser SDK resource staged into first-party static UI bundles.
- `:platform-appdist` owns the local app distribution tooling used to digest, sign, package, and
  verify staged bundles.
- `:platform-appcatalog` owns signed catalog parsing, catalog writing, Crypta catalog source
  fetching, artifact digest checks, safe ZIP extraction, and verified AppHost staging.
- `:platform-devtools` owns the standalone `crypta-app` developer CLI for external staged-bundle
  and catalog-authoring workflows.
- `apps/queue-manager` owns the Queue Manager first-party app bundle. Current staged bundles
  declare `app.ui.mode=static` and open through an isolated app origin when available, with
  `/apps/queue-manager/static/` retained as the compatibility fallback.
- `apps/publisher` owns the Publisher first-party app bundle. Current staged bundles declare
  `app.ui.mode=static` and open through an isolated app origin when available, with
  `/apps/publisher/static/` retained as the compatibility fallback.
- `apps/site-publisher` owns the Site Publisher first-party content reference app bundle. Current
  staged bundles declare `app.ui.mode=static` and open through an isolated app origin when
  available, with `/apps/site-publisher/static/` retained as the compatibility fallback.
- `apps/profile-publisher` owns the Profile Publisher first-party identity-profile reference app
  bundle. Current staged bundles declare `app.ui.mode=static`, create app-owned identities through
  app-vault, use the profile-document route for identity-bound profile publishing, and queue the
  generated profile document through the app-document insert route.
- `apps/feed-reader` owns the Feed Reader first-party content-fetch reference app bundle. Current
  staged bundles declare `app.ui.mode=static`, fetch bounded Crypta feed documents through
  `content.fetch`, publish generated feed snapshots through the app-document insert route, and keep
  USK follow behavior scoped to the open browser tab.
- `apps/trust-graph` owns the Trust Graph Local RC first-party local trust-service reference app
  bundle. Current staged bundles declare `app.ui.mode=static`, use `trust.read` and `trust.write`
  for local RC state, fetch bounded Crypta trust statement documents through `content.fetch`,
  and publish generated trust statements through the app-document insert route.
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
- `./gradlew :apps:site-publisher:stageApp`
- `./gradlew :apps:profile-publisher:stageApp`
- `./gradlew :apps:feed-reader:stageApp`
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

CI runs the Tier 1 gate through the `interop-smoke` job in `.github/workflows/ci.yml` after building
a runnable Cryptad distribution. Tier 1 is Linux-only and covers darknet peer exchange, FCP
content cross-fetches, Cryptad restart/refetch, and persistent request listings before and after
restart. Tier 2 runs through the scheduled/manual `interop-extended` job, with a multi-OS
`interop-self-test` matrix for parser, summary, and redaction behavior on platforms where the
pinned Linux Hyphanet baseline cannot run. Tier 2 covers long-lived `SubscribeUSK`, persistent
request replay across Cryptad restart, and optional opennet launch plumbing with skipped
path-validation status. Local usage,
diagnostics, artifact layout, and summary fields are documented in
[tools/interop/README.md](../tools/interop/README.md).

## Release gates

Treat these gates as blockers before promoting a release that ships the platform surface:

1. Run the normal Gradle build/test gate for the release branch.
2. Stage first-party apps.
3. Sign first-party apps with the intended release or staging signing inputs.
4. Verify first-party apps with the matching trusted public key inputs.
5. Smoke signed app catalogs when catalog sources ship.
6. Smoke the `crypta-app` CLI when `:platform-devtools` changes.
7. Smoke app-owned static UI routes when static UI apps ship.
8. Run the Linux Hyphanet interop Tier 1 smoke gate locally or verify the CI `interop-smoke` job
   passed.
9. Run or verify the Tier 2 extended interop job when the release changes FCP, peer handling,
   persistence, restart behavior, USK/SSK request handling, packaging layout, or node startup.
10. Run or verify the packaged-node performance smoke when release readiness or
   performance-sensitive changes require it.
11. Generate `build/release-certification/release-certification-report.md` and
   `build/release-certification/release-certification-summary.json` after the source gates have
   produced their summaries. The report aggregates interop, performance, app-platform, catalog,
   app-owned UI, legacy-admin retirement, and CI evidence for the release candidate.
12. Preserve `build/interop-smoke/` or `build/interop-extended/` diagnostics when an interop run
   fails or when Tier 2 evidence is part of the release record. Shared diagnostics must exclude
   `artifacts/private-insert-uris.json`.

The release runbook records the same gates in
[cryptad-release-workflow-and-runbook.md](cryptad-release-workflow-and-runbook.md).

## Deferred to Phase 4

Phase 4 candidates were plans, not PR-194 implementation scope. Current status:

- Remote signed app catalogs, verified artifact staging, app-update candidate detection, scheduler
  refresh/checks, staged apply, and bundle rollback have landed. Silent third-party auto-update is
  not the default; manual remains the default policy, and policy-driven staging or apply requires
  explicit operator selection.
- App-owned static UI routes have landed for installed static bundles, and Phase 6 now provides
  isolated per-app loopback browser origins with `/apps/{appId}/` retained as compatibility
  fallback.
- Standalone developer tooling has landed through the `crypta-app` CLI for scaffolding,
  validation, signing, packaging, verification, and catalog authoring.
- The first content-oriented reference app has landed as Site Publisher, the first
  identity-profile reference app has landed as Profile Publisher, the first feed/content-fetch
  reference app has landed as Feed Reader, and the first local trust-service RC reference app has
  landed as Trust Graph Local RC. Later app-platform phases added Social Inbox RC, durable app
  data, content subscriptions, and app-service grants; see
  [app-platform-developer-portal.md](app-platform-developer-portal.md) for the current first-party
  app map.
- App permission enforcement and app-origin audit landed after this Phase 3 closeout; see
  [app-permissions-and-audit.md](app-permissions-and-audit.md).
- Legacy admin and browse retirement plan.
- Portable full-node Hyphanet baseline artifacts for macOS and Windows.
- Lightweight performance and regression smoke coverage now lives under
  [tools/perf](../tools/perf/README.md); broader benchmark depth remains future work.
