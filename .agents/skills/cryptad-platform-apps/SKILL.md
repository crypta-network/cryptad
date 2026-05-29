---
name: cryptad-platform-apps
description: "Work on Cryptad's app platform: Platform API v1/contract, AppHost runtime/rollback, signed app bundles/catalogs, trusted app-review receipts, Trust Graph Preview, app-update lifecycle, durable app data, content subscriptions, local app-service grants, app-owned static UI, browser sessions, the browser SDK, the app UI design system/linter, developer CLI, app permissions/audit, sandbox providers, beta docs evidence, and legacy admin retirement routing."
---

# Cryptad platform apps

Use this skill before touching app-platform code, docs, or tests.

## Read first

Load only the docs needed for the change:

- App ecosystem beta entry point: `docs/app-platform-developer-portal.md`
- Offline beta tutorials: `docs/app-platform-beta-tutorials.md`
- Beta limitations and safety boundaries: `docs/app-platform-beta-known-limitations.md`
- Beta program, submission, feedback, and closeout runbook: `docs/app-platform-beta-program.md`
- Platform API and shell surface: `docs/platform-api-surface.md`
- Platform API compatibility contract: `docs/platform-api-contract.md`
- Signed bundles and first-party app tasks: `docs/app-distribution.md`
- Standalone app developer CLI: `docs/app-dev-cli.md`
- Signed catalogs: `docs/app-catalogs.md`
- App update lifecycle and rollback: `docs/app-update-lifecycle.md`
- Durable app data: `docs/app-data-store.md`
- Local app-service discovery and grants: `docs/app-service-discovery-and-grants.md`
- App-owned static UI routes and bootstrap JSON: `docs/app-owned-ui.md`
- App UI design-system assets and offline UI lint: `docs/app-ui-design-system.md`
- Browser SDK behavior: `docs/platform-sdk-js.md`
- Feed Reader and content-fetch reference app: `docs/feed-reader-reference-app.md`
- Social Inbox Preview reference app: `docs/social-inbox-reference-app.md`
- Trust Graph Preview reference app and local trust-service API: `docs/trust-graph-preview.md`
- App secret and identity vault: `docs/app-secret-and-identity-vault.md`
- AppHost runtime/log/token boundary: `docs/apphost-runtime-hardening.md`
- App-token permission matrix and audit model: `docs/app-permissions-and-audit.md`
- Legacy admin replacement map and usage counters: `docs/legacy-retirement-plan.md`
- App-platform release evidence: `docs/release-certification.md`

## Ownership map

- `:platform-api` owns the transport-neutral Platform API v1 router, route families,
  deterministic compatibility contract, app-token authorization decisions, browser-session
  authorization decisions, capabilities, app-vault route handlers, generated app-document queue
  staging, bounded content fetch routing, durable content subscriptions, durable app data,
  local Trust Graph Preview route handlers, local app-service discovery/grants and adapters,
  bounded app audit logs, and the local app-update lifecycle service plus scheduler above
  AppHost/catalog/vault/app-data/content/trust/runtime primitives.
- `:platform-apphost` owns installed app layout, manifest parsing, app process lifecycle,
  per-launch `CRYPTAD_APP_TOKEN`, runtime status, process-log capture/redaction, and restart
  attempts, durable previous-bundle rollback records, plus sandbox policy/status reporting,
  Linux bubblewrap provider selection, and positive data/cache quota enforcement.
- `:platform-app-ui` owns static route/path/content-type/header helpers for `/apps/{appId}/` and
  isolated per-app loopback origin metadata, launch-proof bootstrap, and short-lived browser
  session issuance/verification for static app Platform API calls.
- `:platform-sdk-js` owns `crypta-platform.js`, the dependency-free browser helper staged into
  first-party static app bundles, including queue/content/feed/vault/trust/app-data/app-service
  helpers.
- `:platform-design-system` owns canonical local app UI CSS/JS assets and safe asset metadata/copy
  helpers used by scaffolds, first-party staging, UI lint, and release evidence.
- `:platform-appvault` owns app secret and identity vault storage records, metadata/grant value
  types, local wrapping-key provider, bounded profile/trust statement signing helpers,
  audit/redaction helpers, and deterministic vault tests.
- `:platform-appdist` owns local signed bundle digests, signatures, trusted-key verification,
  deterministic bundle packaging, manifest sandbox/quota fields, and first-party
  signing/verification tooling.
- `:platform-appcatalog` owns signed catalog parsing, catalog writing, catalog source/artifact
  verification, `crypta:` catalog-source URI handling, safe ZIP extraction, and verified staging
  into AppHost install/update flows, plus optional review/API compatibility metadata, independent
  app-review receipts, trusted reviewer-key loading, review policy modes, and review trust
  decisions used by app update review, reviewer-key lifecycle parsing, local review transparency
  logging, governance snapshots, and review-history API support.
- `:platform-trustgraph` owns the Trust Graph Preview statement model, strict JSON parser,
  canonical payload and signature helpers, process-local anchor/store abstractions, and
  deterministic direct-anchor scoring. It is a local preview library, not a peer protocol or full
  Web of Trust implementation.
- `:platform-devtools` owns the standalone `crypta-app` CLI for scaffolding, validating, signing,
  packaging, verifying, catalog-authoring, API contract snapshotting, compatibility verification,
  mock dev serving, offline app tests, developer key generation, and dry-run publication planning
  or explicit live USK publication for developer-owned staged bundles, including `crypta-app ui
  lint` and review receipt sign/verify helpers.
- `:platform-web-shell` owns `/app/node/` browser shell assets, bootstrap, app/catalog/update/review
  operator views, and app-service grant approval/revocation UI.
- `:adapter-http-legacy-admin` hosts the current `/api/v1/`, `/app/node/`, `/apps/{appId}/`
  compatibility bridge, isolated app-UI loopback origin server, Platform API form-password guard,
  and legacy admin retirement notices and diagnostics counters.
- `:apps:queue-manager` stages the first-party queue-control static UI bundle.
- `:apps:publisher` stages the legacy-publisher replacement static UI bundle.
- `:apps:site-publisher` stages the first-party content reference static UI bundle.
- `:apps:profile-publisher` stages the first-party identity-profile reference static UI bundle.
- `:apps:social-inbox` stages the first-party social/mail migration preview static UI bundle.
- `:apps:feed-reader` stages the first-party feed reader/subscription reference static UI bundle.
- `:apps:trust-graph` stages the first-party Trust Graph Preview reference static UI bundle and
  advertises the local `trust.score` app-service provider.

## Guardrails

- Never expose `CRYPTAD_APP_TOKEN` through browser bootstrap JSON, Web Shell bootstrap, app
  summaries, runtime/log/audit API responses, diagnostics, `toString()`, or error text.
- Browser static UI prefers isolated per-app loopback origins, with `/apps/{appId}/` retained as a
  same-origin compatibility fallback. Browser origin isolation is not a process sandbox or
  app-token authority; server-side Platform API permission checks remain authoritative.
- Static app browser session tokens are local browser credentials for installed static UI calls.
  They are not AppHost launch tokens, must not expose `CRYPTAD_APP_TOKEN`, and should stay out of
  persistent browser storage.
- App-originated Platform API requests must authenticate with a live app process token or app
  browser session and pass the central capability matrix. Deny app principals by default.
- App-facing `POST /api/v1/content/fetch` is bounded foreground content retrieval only. It must
  require `content.fetch`, cap bytes and timeouts, allow only Crypta/Freenet content-key forms, and
  reject `file:`, arbitrary HTTP(S), loopback/LAN URLs, and absolute local paths before calling the
  runtime fetch port.
- Durable content subscriptions are bounded USK follow metadata plus scheduled refresh requests.
  They must not become a crawler, arbitrary HTTP client, queue-HTML parser, raw content archive, or
  source of private insert URIs.
- Durable app data is app-owned state only. It must remain scoped to the authenticated caller app,
  enforce bounded namespaces/keys/values/imports, and keep raw values, request bodies, store roots,
  app data directories, private insert URIs, tokens, and local paths out of public JSON, audit,
  docs, and release evidence.
- App-generated document insert routes accept generated document bytes, not local source paths.
  Keep raw generated documents, raw feed/profile/trust bodies, private insert URIs, raw
  signatures, and request bodies out of audit entries, logs, and release evidence.
- Trust Graph Preview is local preview scoring and bounded statement import/sign/publish support.
  Do not claim full Web of Trust compatibility, old plugin compatibility, global moderation,
  background crawling, daemon-core identity sharing, or protocol/network behavior changes. Trust
  evidence must stay bounded and redacted; do not record raw trust documents from real users.
- App-service discovery and grants are local Platform API mediation only. Do not add generic RPC,
  arbitrary localhost proxying, bearer tokens apps can pass around, remote discovery, daemon-core
  plugin ABIs, cross-app app-data access, or provider run/cache/store path exposure. Invocation must
  check the authenticated app principal, declared capabilities, current provider descriptor, active
  grant, scope, and context at call time.
- Social Inbox Preview is a migration spike for social/mail-like workflows. Do not present it as
  encrypted mail transport, Freetalk/Sone/Freemail compatibility, full WoT, or a daemon-core message
  protocol.
- Audit entries are bounded and process-local. Do not add query strings, request bodies, form
  passwords, tokens, absolute filesystem paths, or large payloads.
- Static UI routes must serve only immutable installed-bundle files. Reject traversal, encoded path
  separators, symlink/reparse escapes, reserved sidecars, and host-dependent MIME inference.
- Static app UI design-system assets must stay local to the bundle. Do not add CDN dependencies or
  remote CSS/JS allowances; use `crypta-app ui lint` for offline CSP, SDK/bootstrap, accessibility,
  permission-disclosure, and design-system checks.
- Signed catalogs and bundles must verify before install/update. Unsigned live-node installs require
  the explicit development-only escape hatch.
- Trusted app-review receipts are independent reviewer evidence. Do not treat publisher advisory
  `review.status`, app signing keys, or catalog signing keys as reviewer trust.
- Reviewer governance is local trusted-key configuration plus a local tamper-evident transparency
  log. Do not present catalog-listed reviewer keys as automatically trusted, and do not describe
  the local transparency log as a global public log.
- `crypta:` catalog sources still require signed catalog verification. They do not make catalog
  artifacts trusted, and catalog entry bundle artifacts remain limited to the schemes documented in
  `docs/app-catalogs.md`.
- App-update lifecycle state must stay path-free and token-free. Do not expose catalog scratch
  directories, staged bundle paths, rollback directories, launch tokens, browser sessions, form
  passwords, private signing keys, or private insert URIs through API responses, Web Shell text,
  logs, audit entries, or certification output.
- The default app-update policy is `manual`. Do not introduce silent third-party auto-update; policy
  `stage` may stage eligible verified candidates, and `apply_when_stopped` may apply only when the
  app is already stopped and all review/compatibility gates pass.
- App-update routes under `/api/v1/apps/{appId}/updates` are mutating local-management routes when
  they check, stage, apply, rollback, or update policy. Browser/host requests must pass the
  form-password guard. App principals need the published app/catalog capabilities; do not let
  `apps.manage` alone trigger catalog refresh or artifact staging.
- Rollback restores only the immutable installed bundle. It must preserve AppHost-managed
  data/cache/run ownership boundaries and must not claim to roll back mutable app data.
- Positive AppHost data/cache quotas must block launch or restart when usage is over limit or an
  enforced area cannot be measured completely. Quotas and current sandbox providers are operational
  controls, not hard OS isolation.
- Bubblewrap sandbox status is public only as provider/support-level metadata. Do not expose the
  configured `bwrap` executable path, generated wrapper command line, bind mount source paths, app
  tokens, or host private configuration.
- Legacy admin retirement changes must update both the code map
  (`LegacyAdminRetirementRegistry`) and `docs/legacy-retirement-plan.md`.
- Release-certification evidence must not expose private signing keys, app process tokens,
  browser-session tokens, form passwords, raw request bodies, raw feed bodies, raw trust documents,
  private insert URIs, non-localhost endpoint metadata, or unsanitized local paths. Optional live
  AppHost smoke reads the form password from `CRYPTAD_CERT_FORM_PASSWORD`; do not pass it as a
  command-line argument.

## Release certification smoke

- `tools/release-certification/app_platform_smoke.py` is the app-platform evidence collector for
  release certification. It validates first-party staged bundles, static UI/SDK coherence,
  design-system adoption, strict UI lint JSON evidence, `crypta-app init/validate/pack/dev/test`,
  Platform API contract snapshots, app-vault capability evidence, generated document insert
  evidence, bounded content-fetch/subscription evidence, durable app-data evidence, signed bundle
  evidence, signed catalog/live USK publication evidence, first-party beta catalog metadata, trusted
  app-review receipt evidence, sandbox-provider evidence, app-update lifecycle/scheduler/rollback
  evidence, Site Publisher/Profile Publisher/Social Inbox/Feed Reader/Trust Graph Preview
  reference-app evidence, app-service registry/grant/redaction evidence, app-review governance and
  local transparency-log evidence, legacy-admin retirement state, and optional localhost-only live
  AppHost lifecycle evidence.
- `tools/release-certification/app_platform_docs_check.py` is the deterministic docs evidence
  collector for the app ecosystem beta portal, tutorials, beta program, issue templates, internal
  Markdown links, and docs redaction checks.
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
./gradlew :platform-trustgraph:test
./gradlew :platform-design-system:test
./gradlew :platform-appvault:test
./gradlew :platform-devtools:test
./gradlew :platform-sdk-js:test
./gradlew :platform-web-shell:test
./gradlew :adapter-http-legacy-admin:test
./gradlew :apps:queue-manager:test
./gradlew :apps:publisher:test
./gradlew :apps:site-publisher:test
./gradlew :apps:profile-publisher:test
./gradlew :apps:social-inbox:test
./gradlew :apps:feed-reader:test
./gradlew :apps:trust-graph:test
./gradlew stageFirstPartyApps
python3 tools/release-certification/app_platform_docs_check.py --self-test
python3 tools/release-certification/app_platform_smoke.py --self-test
```

When changing route contracts or bridge wiring, also run the relevant root router/toadlet tests
with `./gradlew :test --tests *PlatformApiRouterTest --tests *PlatformApiToadletTest`.

When changing `crypta-app` command wiring or distribution behavior, also run
`./gradlew :platform-devtools:installDist` and smoke the generated
`platform-devtools/build/install/crypta-app/bin/crypta-app --help` launcher.

When changing signed bundle/catalog, live USK publication, app-review receipts, static UI,
design-system assets, UI lint, SDK, Platform API contract, AppHost lifecycle, app-vault
capabilities, generated document inserts, content fetch/subscriptions, durable app data,
app-service grants/adapters, Trust Graph Preview, Social Inbox Preview, app-update
lifecycle/scheduler/rollback, sandbox-provider evidence, reference content/profile/social/feed/trust
apps, app platform beta docs evidence, or legacy-admin retirement evidence behavior, also run:

```bash
python3 tools/release-certification/app_platform_docs_check.py --self-test
python3 tools/release-certification/app_platform_smoke.py --self-test
tools/release-certification/run-release-certification.sh --mode pr --skip-gradle --skip-git-metadata
```
