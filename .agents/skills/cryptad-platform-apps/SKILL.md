---
name: cryptad-platform-apps
description: "Work on Cryptad's app platform: Platform API v1, AppHost runtime, signed app bundles/catalogs, app-owned static UI, browser sessions, the browser SDK, developer CLI, app permissions/audit, and legacy admin retirement routing."
---

# Cryptad platform apps

Use this skill before touching app-platform code, docs, or tests.

## Read first

Load only the docs needed for the change:

- Platform API and shell surface: `docs/platform-api-surface.md`
- Signed bundles and first-party app tasks: `docs/app-distribution.md`
- Standalone app developer CLI: `docs/app-dev-cli.md`
- Signed catalogs: `docs/app-catalogs.md`
- App-owned static UI routes and bootstrap JSON: `docs/app-owned-ui.md`
- Browser SDK behavior: `docs/platform-sdk-js.md`
- AppHost runtime/log/token boundary: `docs/apphost-runtime-hardening.md`
- App-token permission matrix and audit model: `docs/app-permissions-and-audit.md`
- Legacy admin replacement map and usage counters: `docs/legacy-retirement-plan.md`
- App-platform release evidence: `docs/release-certification.md`

## Ownership map

- `:platform-api` owns the transport-neutral Platform API v1 router, route families, app-token
  authorization decisions, browser-session authorization decisions, capabilities, and bounded app
  audit log.
- `:platform-apphost` owns installed app layout, manifest parsing, app process lifecycle,
  per-launch `CRYPTAD_APP_TOKEN`, runtime status, process-log capture/redaction, and restart
  attempts, plus sandbox policy/status reporting and positive data/cache quota enforcement.
- `:platform-app-ui` owns static route/path/content-type/header helpers for `/apps/{appId}/` and
  short-lived browser session issuance/verification for static app Platform API calls.
- `:platform-sdk-js` owns `crypta-platform.js`, the dependency-free browser helper staged into
  first-party static app bundles.
- `:platform-appdist` owns local signed bundle digests, signatures, trusted-key verification,
  deterministic bundle packaging, manifest sandbox/quota fields, and first-party
  signing/verification tooling.
- `:platform-appcatalog` owns signed catalog parsing, catalog writing, catalog source/artifact
  verification, `crypta:` catalog-source URI handling, safe ZIP extraction, and verified staging
  into AppHost install/update flows.
- `:platform-devtools` owns the standalone `crypta-app` CLI for scaffolding, validating, signing,
  packaging, verifying, and catalog-authoring developer-owned staged bundles.
- `:platform-web-shell` owns `/app/node/` browser shell assets and bootstrap.
- `:adapter-http-legacy-admin` hosts the current `/api/v1/`, `/app/node/`, and `/apps/{appId}/`
  HTTP bridges plus legacy admin retirement notices and diagnostics counters.
- `:apps:queue-manager` and `:apps:publisher` stage first-party static UI bundles.

## Guardrails

- Never expose `CRYPTAD_APP_TOKEN` through browser bootstrap JSON, Web Shell bootstrap, app
  summaries, runtime/log/audit API responses, diagnostics, `toString()`, or error text.
- Browser static UI is same-origin with the local admin UI. It is not a sandbox or app-token
  authority. Server-side Platform API permission checks remain authoritative.
- Static app browser session tokens are local browser credentials for installed static UI calls.
  They are not AppHost launch tokens, must not expose `CRYPTAD_APP_TOKEN`, and should stay out of
  persistent browser storage.
- App-originated Platform API requests must authenticate with a live launch token and pass the
  central capability matrix. Deny app principals by default.
- Audit entries are bounded and process-local. Do not add query strings, request bodies, form
  passwords, tokens, absolute filesystem paths, or large payloads.
- Static UI routes must serve only immutable installed-bundle files. Reject traversal, encoded path
  separators, symlink/reparse escapes, reserved sidecars, and host-dependent MIME inference.
- Signed catalogs and bundles must verify before install/update. Unsigned live-node installs require
  the explicit development-only escape hatch.
- `crypta:` catalog sources still require signed catalog verification. They do not make catalog
  artifacts trusted, and catalog entry bundle artifacts remain limited to the schemes documented in
  `docs/app-catalogs.md`.
- Positive AppHost data/cache quotas must block launch or restart when usage is over limit or an
  enforced area cannot be measured completely. Quotas and current sandbox providers are operational
  controls, not hard OS isolation.
- Legacy admin retirement changes must update both the code map
  (`LegacyAdminRetirementRegistry`) and `docs/legacy-retirement-plan.md`.
- Release-certification evidence must not expose private signing keys, app process tokens,
  browser-session tokens, form passwords, raw request bodies, private insert URIs, non-localhost
  endpoint metadata, or unsanitized local paths. Optional live AppHost smoke reads the form password
  from `CRYPTAD_CERT_FORM_PASSWORD`; do not pass it as a command-line argument.

## Release certification smoke

- `tools/release-certification/app_platform_smoke.py` is the app-platform evidence collector for
  release certification. It validates first-party staged bundles, static UI/SDK coherence,
  `crypta-app init/validate/pack`, signed bundle evidence, signed catalog evidence,
  legacy-admin retirement state, and optional localhost-only live AppHost lifecycle evidence.
- `pr` mode must stay fast and offline-safe. It must not require a live node, signing keys, Hyphanet
  downloads, or production credentials.
- `release-candidate` mode treats missing required signed bundle/catalog/app-platform evidence as
  failing unless a release-manager waiver is recorded by the aggregator.
- Keep app smoke self-tests Python-only and deterministic. Use fixtures or fake CLI helpers instead
  of network or Java dependencies for regression coverage where possible.

## Validation

Use `$cryptad-build-test` for Gradle rules and timeouts. Common focused checks:

```bash
./gradlew :platform-api:test
./gradlew :platform-apphost:test
./gradlew :platform-app-ui:test
./gradlew :platform-appdist:test
./gradlew :platform-appcatalog:test
./gradlew :platform-devtools:test
./gradlew :platform-sdk-js:test
./gradlew :platform-web-shell:test
./gradlew :adapter-http-legacy-admin:test
./gradlew :apps:queue-manager:test
./gradlew :apps:publisher:test
./gradlew stageFirstPartyApps
python3 tools/release-certification/app_platform_smoke.py --self-test
```

When changing route contracts or bridge wiring, also run the relevant root router/toadlet tests
with `./gradlew :test --tests *PlatformApiRouterTest --tests *PlatformApiToadletTest`.

When changing `crypta-app` command wiring or distribution behavior, also run
`./gradlew :platform-devtools:installDist` and smoke the generated
`platform-devtools/build/install/crypta-app/bin/crypta-app --help` launcher.

When changing signed bundle/catalog, static UI, SDK, AppHost lifecycle, or legacy-admin retirement
evidence behavior, also run:

```bash
python3 tools/release-certification/app_platform_smoke.py --self-test
tools/release-certification/run-release-certification.sh --mode pr --skip-gradle --skip-git-metadata
```
