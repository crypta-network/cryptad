---
name: cryptad-platform-apps
description: "Work on Cryptad's app platform: Platform API v1, AppHost runtime, signed app bundles/catalogs, app-owned static UI, the browser SDK, app permissions/audit, and legacy admin retirement routing."
---

# Cryptad platform apps

Use this skill before touching app-platform code, docs, or tests.

## Read first

Load only the docs needed for the change:

- Platform API and shell surface: `docs/platform-api-surface.md`
- Signed bundles and first-party app tasks: `docs/app-distribution.md`
- Signed catalogs: `docs/app-catalogs.md`
- App-owned static UI routes and bootstrap JSON: `docs/app-owned-ui.md`
- Browser SDK behavior: `docs/platform-sdk-js.md`
- AppHost runtime/log/token boundary: `docs/apphost-runtime-hardening.md`
- App-token permission matrix and audit model: `docs/app-permissions-and-audit.md`
- Legacy admin replacement map and usage counters: `docs/legacy-retirement-plan.md`

## Ownership map

- `:platform-api` owns the transport-neutral Platform API v1 router, route families, app-token
  authorization decisions, capabilities, and bounded app audit log.
- `:platform-apphost` owns installed app layout, manifest parsing, app process lifecycle,
  per-launch `CRYPTAD_APP_TOKEN`, runtime status, process-log capture/redaction, and restart
  attempts.
- `:platform-app-ui` owns static route/path/content-type/header helpers for `/apps/{appId}/`.
- `:platform-sdk-js` owns `crypta-platform.js`, the dependency-free browser helper staged into
  first-party static app bundles.
- `:platform-appdist` owns local signed bundle digests, signatures, trusted-key verification, and
  first-party signing/verification tooling.
- `:platform-appcatalog` owns signed catalog parsing, source/artifact verification, safe ZIP
  extraction, and verified staging into AppHost install/update flows.
- `:platform-web-shell` owns `/app/node/` browser shell assets and bootstrap.
- `:adapter-http-legacy-admin` hosts the current `/api/v1/`, `/app/node/`, and `/apps/{appId}/`
  HTTP bridges plus legacy admin retirement notices and diagnostics counters.
- `:apps:queue-manager` and `:apps:publisher` stage first-party static UI bundles.

## Guardrails

- Never expose `CRYPTAD_APP_TOKEN` through browser bootstrap JSON, Web Shell bootstrap, app
  summaries, runtime/log/audit API responses, diagnostics, `toString()`, or error text.
- Browser static UI is same-origin with the local admin UI. It is not a sandbox, an app session, or
  app-token authority. Server-side Platform API permission checks remain authoritative.
- App-originated Platform API requests must authenticate with a live launch token and pass the
  central capability matrix. Deny app principals by default.
- Audit entries are bounded and process-local. Do not add query strings, request bodies, form
  passwords, tokens, absolute filesystem paths, or large payloads.
- Static UI routes must serve only immutable installed-bundle files. Reject traversal, encoded path
  separators, symlink/reparse escapes, reserved sidecars, and host-dependent MIME inference.
- Signed catalogs and bundles must verify before install/update. Unsigned live-node installs require
  the explicit development-only escape hatch.
- Legacy admin retirement changes must update both the code map
  (`LegacyAdminRetirementRegistry`) and `docs/legacy-retirement-plan.md`.

## Validation

Use `$cryptad-build-test` for Gradle rules and timeouts. Common focused checks:

```bash
./gradlew :platform-api:test
./gradlew :platform-apphost:test
./gradlew :platform-app-ui:test
./gradlew :platform-appdist:test
./gradlew :platform-appcatalog:test
./gradlew :platform-sdk-js:test
./gradlew :platform-web-shell:test
./gradlew :adapter-http-legacy-admin:test
./gradlew :apps:queue-manager:test
./gradlew :apps:publisher:test
./gradlew stageFirstPartyApps
```

When changing route contracts or bridge wiring, also run the relevant root router/toadlet tests
with `./gradlew :test --tests *PlatformApiRouterTest --tests *PlatformApiToadletTest`.
