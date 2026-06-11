---
name: cryptad-platform-apps
description: "Work on Cryptad's app platform: Platform API v1/contract, AppHost runtime/rollback, signed app bundles/catalogs, trusted app-review receipts, Trust Graph Local RC, app-update lifecycle, durable app data, app-data backup/restore, content subscriptions, local app-service discovery/dependencies/grant bundles, app-owned static UI, browser sessions, the browser SDK, the app UI design system/linter, developer CLI, app permissions/audit, sandbox providers, operator beta dashboard/support evidence, live-network beta certification evidence, legacy plugin freeze, and legacy admin retirement routing."
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
- App upgrade data migrations: `docs/app-upgrade-data-migrations.md`
- Durable app data: `docs/app-data-store.md`
- App-data backup/restore portability: `docs/app-data-backup-restore-portability.md`
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
- Legacy plugin freeze policy: `docs/legacy-plugin-freeze-policy.md`
- Operator beta dashboard and redacted support bundle: `docs/operator-beta-dashboard.md`
- App-platform release evidence: `docs/release-certification.md`

## Ownership map

- `:platform-api` owns the transport-neutral Platform API v1 router, route families,
  deterministic compatibility contract, app-token authorization decisions, browser-session
  authorization decisions, capabilities, app-vault route handlers, generated app-document queue
  staging, bounded content fetch routing, durable content subscriptions, durable app data,
  app-data backup/restore planning and commit routes, internal update snapshots, local Trust Graph
  Local RC route handlers, local app-service discovery/dependency/grant-bundle routes and adapters,
  bounded app audit logs, and the local app-update lifecycle service plus scheduler above
  AppHost/catalog/vault/app-data/content/trust/runtime primitives, plus the host/operator-only
  beta dashboard, subscription recovery wrappers, and redacted support-bundle assembly.
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
  deterministic bundle packaging, manifest sandbox/quota/app-data schema migration fields, and
  first-party signing/verification tooling.
- `:platform-appcatalog` owns signed catalog parsing, catalog writing, catalog source/artifact
  verification, `crypta:` catalog-source URI handling, safe ZIP extraction, and verified staging
  into AppHost install/update flows, plus optional review/API compatibility metadata, independent
  app-review receipts, trusted reviewer-key loading, review policy modes, and review trust
  decisions used by app update review, reviewer-key lifecycle parsing, local review transparency
  logging, governance snapshots, and review-history API support.
- `:platform-trustgraph` owns the Trust Graph Local RC statement model, strict JSON parser,
  canonical payload and signature helpers, process-local anchor/store abstractions, lifecycle
  status records, and deterministic direct-anchor scoring. It is a local preview library, not a
  peer protocol or full Web of Trust implementation.
- `:platform-devtools` owns the standalone `crypta-app` CLI for scaffolding, validating, signing,
  packaging, verifying, catalog-authoring, API contract snapshotting, compatibility verification,
  mock dev serving, offline app tests, developer key generation, and dry-run publication planning
  or explicit live USK publication for developer-owned staged bundles, including `crypta-app ui
  lint` and review receipt sign/verify helpers.
- `:platform-web-shell` owns `/app/node/` browser shell assets, bootstrap, app/catalog/update/review
  operator views, the operator beta dashboard/support-bundle panel, subscription recovery controls,
  app-data backup/restore controls, app-service dependency/grant-bundle review UI, and explicit
  legacy security/diagnostic fallback actions.
- `:adapter-http-legacy-admin` hosts the current `/api/v1/`, `/app/node/`, `/apps/{appId}/`
  compatibility bridge, isolated app-UI loopback origin server, Platform API form-password guard,
  operator subscription-recovery form-password guard, legacy admin retirement notices, diagnostic
  Wave 4 replacement/fallback routing, and diagnostics counters.
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
- App-data backup/restore is host/operator-only and is not an app-facing contract bump by itself.
  Restore previews and support evidence must stay metadata-only: no raw backup payloads, raw app
  data values, form passwords, private insert URIs, tokens, store roots, or absolute local paths.
- App-generated document insert routes accept generated document bytes, not local source paths.
  Keep raw generated documents, raw feed/profile/trust bodies, private insert URIs, raw
  signatures, and request bodies out of audit entries, logs, and release evidence.
- Trust Graph Local RC is local preview scoring and bounded statement import/sign/publish support.
  Do not claim full Web of Trust compatibility, old plugin compatibility, global moderation,
  background crawling, daemon-core identity sharing, or protocol/network behavior changes. Trust
  evidence must stay bounded and redacted; do not record raw trust documents from real users.
- App-service discovery and grants are local Platform API mediation only. Do not add generic RPC,
  arbitrary localhost proxying, bearer tokens apps can pass around, remote discovery, daemon-core
  plugin ABIs, cross-app app-data access, or provider run/cache/store path exposure. Invocation must
  check the authenticated app principal, declared capabilities, current provider descriptor, active
  grant, scope, and context at call time.
- App-service dependency graphs and grant bundles must remain bounded operator-mediated metadata.
  Revalidate signed consumer manifests and current provider descriptors before approval, renewal,
  or invocation. Evidence and Web Shell summaries must not include raw service request bodies, raw
  subject URIs, raw Trust Graph data, provider app data, tokens, private keys, private insert URIs,
  raw signatures, backup payloads, or local paths.
- Social Inbox Preview is a migration spike for social/mail-like workflows. Do not present it as
  encrypted mail transport, Freetalk/Sone/Freemail compatibility, full WoT, or a daemon-core message
  protocol.
- The legacy in-process plugin system is frozen and removed. Do not add
  `network.crypta.pluginmanager`, plugin toadlets, old plugin ABIs, old
  WebOfTrust/Freetalk/Sone/Freemail shims, or FCP plugin command execution. Legacy plugin FCP
  command names may only map to deterministic unsupported responses through the existing
  unsupported-command handler.
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
- App-update lifecycle state, including app-data migration summaries, must stay path-free and
  token-free. Do not expose catalog scratch directories, staged bundle paths, migration command
  paths, rollback directories, launch tokens, browser sessions, form passwords, private signing
  keys, private insert URIs, raw migration logs, or raw app-data values through API responses, Web
  Shell text, logs, audit entries, or certification output.
- The default app-update policy is `manual`. Do not introduce silent third-party auto-update; policy
  `stage` may stage eligible verified candidates, and `apply_when_stopped` may apply only when the
  app is already stopped and all review/compatibility gates pass.
- App-update routes under `/api/v1/apps/{appId}/updates` are mutating local-management routes when
  they check, stage, apply, rollback, or update policy. Browser/host requests must pass the
  form-password guard. App principals need the published app/catalog capabilities; do not let
  `apps.manage` alone trigger catalog refresh or artifact staging.
- Rollback normally restores only the immutable installed bundle. It must preserve AppHost-managed
  data/cache/run ownership boundaries and must not claim broad mutable app-data rollback. The
  narrow exception is the app-update migration path, where `AppUpdateService` may create and
  restore an internal, app-scoped, short-lived durable app-data snapshot; do not expose it as
  user-facing backup/restore or cross-app portability.
- Operator routes under `/api/v1/operator` are host/operator-only local management and support
  routes. They are not part of the app-facing Platform API compatibility contract, must deny app
  principals, and should not bump the integer contract version. Support bundles and dashboard
  summaries must exclude raw bodies, private insert URIs, app/session/process tokens, form
  passwords, local paths, command lines, and app-private values.
- Positive AppHost data/cache quotas must block launch or restart when usage is over limit or an
  enforced area cannot be measured completely. Quotas and current sandbox providers are operational
  controls, not hard OS isolation.
- Bubblewrap sandbox status is public only as provider/support-level metadata. Do not expose the
  configured `bwrap` executable path, generated wrapper command line, bind mount source paths, app
  tokens, or host private configuration.
- Legacy admin retirement changes must update both the code map
  (`LegacyAdminRetirementRegistry`) and `docs/legacy-retirement-plan.md`.
- Legacy admin Wave 4 removes only the `diagnostic` surface by default. Safe reads should use Web
  Shell diagnostics when available; the plaintext diagnostic export is retained only through the
  exact same-origin fallback marker `legacyFallback=diagnostic-export`. Do not add FProxy browse,
  content rendering, content filter, startup wizard/recovery, security recovery fallback, chat,
  translation, help, or node-to-node message routes to a removal wave without a separate audited
  replacement.
- Release-certification evidence must not expose private signing keys, app process tokens,
  browser-session tokens, form passwords, raw request bodies, raw feed bodies, raw trust documents,
  raw diagnostic exports, raw app-data backup payloads, private insert URIs, non-localhost endpoint
  metadata, or unsanitized local paths. Optional live AppHost smoke reads the form password from
  `CRYPTAD_CERT_FORM_PASSWORD`; do not pass it as a command-line argument. Dedicated live-network
  beta certification must stay localhost-only, env/protected-file driven for secrets, and disabled
  for normal PR/nightly/offline release-candidate runs unless explicitly requested.

## Release certification smoke

- `tools/release-certification/app_platform_smoke.py` is the app-platform evidence collector for
  release certification. It validates first-party staged bundles, static UI/SDK coherence,
  design-system adoption, strict UI lint JSON evidence, `crypta-app init/validate/pack/dev/test`,
  Platform API contract snapshots, app-vault capability evidence, generated document insert
  evidence, bounded content-fetch/subscription evidence, durable app-data and app-data
  backup/restore evidence, signed bundle evidence, signed catalog/live USK publication evidence,
  first-party beta catalog metadata, trusted app-review receipt evidence, sandbox-provider
  evidence, app-update lifecycle/scheduler/rollback and app-data migration contract evidence, Site
  Publisher/Profile Publisher/Social Inbox/Feed Reader/Trust Graph Local RC reference-app evidence,
  app-service registry/grant/dependency/grant-bundle/redaction evidence, legacy plugin freeze
  evidence, app-review governance and local transparency-log evidence, public-beta security
  hardening evidence, operator beta dashboard/recovery/support-bundle evidence, legacy-admin
  retirement and Wave 1-4 removal state, and optional
  localhost-only live AppHost lifecycle evidence.
- `tools/release-certification/live_network_beta_smoke.py` is the explicit release-manager
  live-network beta evidence collector. It validates a prepared localhost node, live catalog
  source/key metadata, app-principal browser-session workflows, content/feed/profile/trust
  fixtures, optional app-service scoring, timing metadata, cleanup, and redaction without leaking
  secrets or becoming a normal CI dependency.
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
python3 tools/release-certification/live_network_beta_smoke.py --self-test
```

When changing route contracts or bridge wiring, also run the relevant root router/toadlet tests
with `./gradlew :test --tests *PlatformApiRouterTest --tests *PlatformApiToadletTest`.

When changing `crypta-app` command wiring or distribution behavior, also run
`./gradlew :platform-devtools:installDist` and smoke the generated
`platform-devtools/build/install/crypta-app/bin/crypta-app --help` launcher.

When changing signed bundle/catalog, live USK publication, app-review receipts, static UI,
design-system assets, UI lint, SDK, Platform API contract, AppHost lifecycle, app-vault
capabilities, generated document inserts, content fetch/subscriptions, durable app data,
app-data backup/restore, app-service dependencies/grant bundles, Trust Graph Local RC, Social Inbox
RC, app-update lifecycle/scheduler/rollback, sandbox-provider evidence, operator beta
dashboard/support-bundle behavior, live-network beta certification behavior, reference
content/profile/social/feed/trust
apps, app platform beta docs evidence, or legacy-admin retirement evidence behavior, also run:

```bash
python3 tools/release-certification/app_platform_docs_check.py --self-test
python3 tools/release-certification/app_platform_smoke.py --self-test
python3 tools/release-certification/live_network_beta_smoke.py --self-test
tools/release-certification/run-release-certification.sh --mode pr --skip-gradle --skip-git-metadata
```
