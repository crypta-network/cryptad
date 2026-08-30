---
name: cryptad-platform-apps
description: "Work on Cryptad's app platform: Platform API v1/contract, signed app bundles/catalogs and mirrors, app review, production security, Trust Graph/Social Inbox RCs, app update/data/backup/services/UI/SDK, sandbox and support evidence, production beta gates, Stable 1.0 RC/GA, maintenance, lifecycle/deprecation governance, legacy plugin freeze, and legacy admin retirement routing."
---

# Cryptad platform apps

Use this skill before touching app-platform code, docs, or tests.

## Read first

Load only the docs needed for the change:

- App ecosystem beta entry point: `docs/app-platform-developer-portal.md`
- Offline beta tutorials: `docs/app-platform-beta-tutorials.md`
- Beta limitations and safety boundaries: `docs/app-platform-beta-known-limitations.md`
- Beta program, submission, feedback, and closeout runbook: `docs/app-platform-beta-program.md`
- Third-party developer beta program: `docs/third-party-developer-beta-program.md`
- Third-party app submission checklist: `docs/third-party-app-submission-checklist.md`
- Third-party app compatibility support window: `docs/platform-api-compatibility-support-window.md`
- Third-party Hello Stable SDK example: `docs/examples/third-party-hello-stable.md`
- Protected external third-party app pilot:
  `docs/stable-1.0-external-third-party-app-pilot.md`
- Federated catalog discovery and local trust:
  `docs/stable-1.0-federated-catalog-discovery-and-trust.md`
- Platform API and shell surface: `docs/platform-api-surface.md`
- Platform API compatibility contract: `docs/platform-api-contract.md`
- Platform API 1.0 stable baseline reference: `docs/platform-api-1.0-stable-reference.md`
- Signed bundles and first-party app tasks: `docs/app-distribution.md`
- Standalone app developer CLI: `docs/app-dev-cli.md`
- Signed catalogs: `docs/app-catalogs.md`
- Production first-party catalog channels: `docs/production-first-party-catalog-channels.md`
- Catalog operations and mirrors: `docs/catalog-operations-and-mirrors.md`
- Stable 1.0 catalog publication and key ceremony:
  `docs/stable-1.0-catalog-publication-and-key-ceremony.md`
- Ecosystem security advisories and denylists: `docs/ecosystem-security-advisories.md`
- Production security response runbook: `docs/production-security-response-runbook.md`
- App-store submission and review workflow: `docs/app-store-submission-and-review-workflow.md`
- App-review governance: `docs/app-review-governance.md`
- App update lifecycle and rollback: `docs/app-update-lifecycle.md`
- App upgrade data migrations: `docs/app-upgrade-data-migrations.md`
- User consent and permission upgrade UX: `docs/user-consent-and-permission-upgrade-ux.md`
- Durable app data: `docs/app-data-store.md`
- App-data backup/restore portability: `docs/app-data-backup-restore-portability.md`
- Local app-service discovery and grants: `docs/app-service-discovery-and-grants.md`
- App-owned static UI routes and bootstrap JSON: `docs/app-owned-ui.md`
- App UI design-system assets and offline UI lint: `docs/app-ui-design-system.md`
- Browser SDK behavior: `docs/platform-sdk-js.md`
- Feed Reader and content-fetch reference app: `docs/feed-reader-reference-app.md`
- Social Inbox RC reference app: `docs/social-inbox-reference-app.md`
- Trust Graph Local RC reference app and local trust-service API: `docs/trust-graph-preview.md`
- Network-scale content/subscription budget: `docs/network-scale-soak-and-subscription-budget.md`
- App secret and identity vault: `docs/app-secret-and-identity-vault.md`
- AppHost runtime/log/token boundary: `docs/apphost-runtime-hardening.md`
- App-token permission matrix and audit model: `docs/app-permissions-and-audit.md`
- Legacy admin replacement map and usage counters: `docs/legacy-retirement-plan.md`
- Legacy plugin freeze policy: `docs/legacy-plugin-freeze-policy.md`
- Legacy plugin migration guide: `docs/legacy-plugin-migration-guide.md`
- Operator beta dashboard and redacted support bundle: `docs/operator-beta-dashboard.md`
- Operator RC recovery and support workflow: `docs/operator-rc-recovery-and-support-workflow.md`
- App-platform release evidence: `docs/release-certification.md`
- Unified release-certification tooling and artifact layout: `tools/release-certification/README.md`
- Production beta release pipeline: `docs/production-beta-release-pipeline.md`
- Production beta go/no-go dashboard: `docs/production-beta-go-no-go-dashboard.md`
- Stable 1.0 readiness gate: `docs/stable-1.0-readiness-gate.md`
- Stable 1.0 RC execution and freeze: `docs/stable-1.0-rc-execution-and-release-freeze.md`
- Stable 1.0 RC validation and GA promotion:
  `docs/stable-1.0-rc-validation-and-ga-promotion.md`
- Stable 1.0 maintenance and security hotfix path:
  `docs/stable-1.0-maintenance-release-and-hotfix-path.md`
- Stable 1.0 support lifecycle and deprecation governance:
  `docs/stable-1.0-support-lifecycle-and-deprecation-governance.md`
- Multi-node beta soak and upgrade drill: `docs/multi-node-beta-soak-and-upgrade-drill.md`

## Ownership map

- `:platform-api` owns the transport-neutral Platform API v1 router, route families,
  deterministic compatibility contract, Platform API 1.0 stable baseline metadata, app-token
  authorization decisions, browser-session
  authorization decisions, capabilities, app-vault route handlers, generated app-document queue
  staging, bounded content fetch routing, shared app-network budget service/store, durable content
  subscriptions, durable app data, app-data backup/restore planning and commit routes, unified
  consent previews/decisions/audit stores, internal update snapshots, local Trust Graph Local RC
  route handlers, local app-service discovery/dependency/grant-bundle routes and adapters, bounded
  app audit logs, and the local app-update lifecycle service plus scheduler above AppHost, catalog,
  vault, app-data, content, trust, and runtime primitives, plus host/operator-only catalog
  operation routes for mirror management, source health, revision history, rollback, key-rotation
  status, and emergency advisory refresh; the host/operator-only beta dashboard, subscription
  recovery wrappers, typed operator RC recovery action planning/execution, safe network-budget
  snapshots, support-bundle preview metadata, redacted support-bundle assembly, and the
  host/operator-only Stable 1.0 lifecycle snapshot route.
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
  deterministic bundle packaging, manifest sandbox/quota/app-data schema migration fields, API
  target-stability metadata, and first-party signing/verification tooling.
- `:platform-appcatalog` owns signed catalog parsing, catalog writing, catalog source/artifact
  verification, `crypta:` catalog-source URI handling, safe ZIP extraction, and verified staging
  into AppHost install/update flows, plus optional review/API compatibility target-stability
  metadata, first-party maintenance metadata, catalog security advisory lifecycle/version
  denylists, production security response drill metadata, submission package
  writing/verification/pre-review/redaction, independent app-review receipts, trusted reviewer-key
  loading, review policy modes, and review trust decisions used by app update review,
  reviewer-key lifecycle parsing, local review transparency logging, governance snapshots,
  review-history API support, primary-plus-mirror source metadata, mirror fallback refresh,
  bounded verified revision history, explicit rollback re-verification, catalog key-rotation
  status, and emergency advisory refresh metadata.
- `:platform-trustgraph` owns the Trust Graph Local RC statement model, strict JSON parser,
  canonical payload and signature helpers, process-local anchor/store abstractions, lifecycle
  status records, and deterministic direct-anchor scoring. It is a local RC library, not a
  peer protocol or full Web of Trust implementation.
- `:platform-devtools` owns the standalone `crypta-app` CLI for scaffolding, validating, signing,
  packaging, verifying, catalog-authoring, app-store submission package/pre-review/candidate
  commands, API contract snapshotting, compatibility verification, stable-only `hello-stable`
  third-party templates and review-note scaffolds, mock dev serving with deterministic Platform API
  contract fixtures, offline app tests, developer key generation, and dry-run publication planning
  or explicit live USK publication for developer-owned staged bundles, including `crypta-app ui
  lint` and review receipt sign/verify helpers.
- `:platform-web-shell` owns `/app/node/` browser shell assets, bootstrap, app/catalog/update/review
  operator views, catalog source/mirror health and guarded catalog operations, the operator beta
  dashboard/support-bundle panel, the Operator RC Recovery surface, subscription recovery
  controls, app-data backup/restore controls, app-service dependency/grant-bundle review UI,
  security response and Stable 1.0 lifecycle status rendering, and explicit legacy
  security/diagnostic fallback actions.
- `:adapter-http-legacy-admin` hosts the current `/api/v1/`, `/app/node/`, `/apps/{appId}/`
  compatibility bridge, isolated app-UI loopback origin server, Platform API form-password guard,
  mutating catalog-operation form-password guard, operator recovery/subscription form-password
  guards, legacy admin retirement notices, Wave 5 final-surface policy, replacement/fallback
  routing, and diagnostics counters.
- `:apps:queue-manager` stages the first-party queue-control static UI bundle.
- `:apps:publisher` stages the legacy-publisher replacement static UI bundle.
- `:apps:site-publisher` stages the first-party content reference static UI bundle.
- `:apps:profile-publisher` stages the first-party identity-profile reference static UI bundle.
- `:apps:social-inbox` stages the first-party Social Inbox RC static UI bundle for beta
  social/mail-like threading, multi-source subscriptions, local read/filter/export state, and
  operator-approved Trust Graph score annotations through app-service grants.
- `:apps:feed-reader` stages the first-party feed reader/subscription reference static UI bundle.
- `:apps:trust-graph` stages the first-party Trust Graph Local RC static UI bundle, including local
  anchor lifecycle controls, import previews, recovery/export/import affordances, and the local
  `trust.score` app-service provider.

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
- Material install, update, app-data migration, backup-before-update, app-service grant, and Trust
  Graph import-preview decisions must use unified consent snapshots when required. Approval is
  bound to the exact snapshot digest, stale approvals must fail closed, and consent audit evidence
  must stay path-free and token-free.
- Platform API 1.0 is the stable app-facing baseline named `stableBaseline.name=1.0`, frozen at
  contract version 19 and distinct from the current integer contract version. Later contract bumps
  must not expand or shrink that baseline unless the change deliberately defines a new baseline.
- Stable baseline membership is bounded to app-facing stable descriptors introduced no later than
  contract version 19 and backed by the baseline capability set. Do not silently promote app-vault,
  app-service, Trust Graph Local RC, internal, or operator-only routes into the 1.0 stable surface.
- App manifests and catalog descriptors use `api.targetStability=stable|experimental`. Stable
  targets may use only Platform API 1.0 baseline capabilities; experimental app-facing use still
  requires `api.experimentalCapabilitiesAccepted=true`; internal and operator-only capabilities
  are rejected for third-party app compatibility even with experimental acceptance.
- `vault.identities.manage` is host/operator-only identity management. Keep it out of
  requestable third-party app capability guidance, scaffolds, manifests, and stable baseline
  examples.
- Contract JSON parsing must remain backward compatible for pre-freeze version 19 snapshots that
  omit `stableBaseline`. Contract versions after 19 must include stable-baseline metadata, and the
  parsed metadata must match descriptor membership instead of being silently recomputed.
- App-facing `POST /api/v1/content/fetch` is bounded foreground content retrieval only. It must
  require `content.fetch`, cap bytes and timeouts, allow only Crypta/Freenet content-key forms, and
  reject `file:`, arbitrary HTTP(S), loopback/LAN URLs, and absolute local paths before calling the
  runtime fetch port.
- Shared app-network budgets are required for app-initiated network work: foreground content
  fetch, subscription manual refresh, subscription scheduler poll, Trust Graph direct import, and
  Trust Graph import-by-URI. Use `AppNetworkBudgetService` with reserved internal scopes for
  global and host/operator counters; do not add per-feature counters that bypass the shared global
  content-fetch budget. Full runtime should fail closed when durable budget state is unavailable.
- Durable content subscriptions are bounded USK follow metadata plus scheduled refresh requests.
  Manual refresh and scheduler polls consume shared app-network budget after queue-pressure checks.
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
- Trust Graph Local RC is local RC scoring and bounded statement import/sign/publish support.
  Direct import and pasted import preview consume Trust Graph import budget; import-by-URI and URI
  preview consume both Trust Graph import budget and the shared content-fetch budget. URI previews
  must fetch one root `crypta.trust.statement.v1` document so `import-preview-uri` and `import-uri`
  agree. Pasted previews may summarize arrays or `{ "statements": [...] }` wrappers, but commits
  must send one direct statement document. Do not claim full Web of Trust compatibility, old plugin
  compatibility, global moderation, background crawling, daemon-core identity sharing, or
  protocol/network behavior changes. Trust evidence must stay bounded and redacted; do not record
  raw trust documents from real users.
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
- Social Inbox RC is a first-party beta reference app for social/mail-like local workflows. It may
  manage multiple bounded USK sources, local read/unread state, local mute/block filters, redacted
  exports, author profile summaries, and Trust Graph score annotations only through app-service
  grants. Do not present it as encrypted mail transport, Freetalk/Sone/Freemail compatibility, full
  WoT, network moderation, or a daemon-core message protocol.
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
- Keep Stable catalog, first-party app, reviewer, and offline recovery keys role-distinct. Catalog
  verification uses the catalog-specific registry when configured; AppHost keeps the app-bundle
  registry, and review keeps `TrustedReviewerKeys`. The legacy AppHost-registry fallback is allowed
  only when catalog-specific configuration is absent, must warn, and cannot satisfy Stable
  production certification. When catalog-specific trust is present, reject cross-registry overlap
  by stable key ID or SHA-256 X.509 public-key fingerprint across every lifecycle state. Within
  each catalog or app-bundle registry, reject one public-key fingerprint under multiple IDs so an
  unsigned sidecar ID cannot select active policy for revoked key material. Retain every
  non-staged catalog/app identity in its role registry, mapping revoked, suspected, or compromised
  material to `revoked`. Authenticate the preceding signed transparency artifact for every
  non-genesis ceremony and keep key identity membership append-only so a later transition cannot
  prune and reassign an old ID or fingerprint across roles. Reverify an installed
  bundle with historical lifecycle policy before every explicit launch and automatic
  restart; retiring and retired keys are bounded by their support windows, while revoked,
  compromised, and out-of-window keys fail closed. Never auto-trust a key because a catalog or
  mirror lists it. Derived reviewer registries must retain revoked, suspected, and compromised
  reviewer identities as `revoked`; omitting them downgrades a force-blocking known revocation to
  an unknown-reviewer result. Omit only staged reviewers, and preserve retired/uncompromised
  historical reviewed-at semantics.
- At a release boundary, verify the exact detached catalog sidecar and the independently frozen
  signer id. `crypta-app catalog verify --catalog-signature-file <path> --expected-key-id <id>`
  prevents another key in a broad trusted registry from satisfying that binding. Do not replace
  this with a digest-only check or infer signer identity from the registry.
- Trusted app-review receipts are independent reviewer evidence. Do not treat publisher advisory
  `review.status`, app signing keys, or catalog signing keys as reviewer trust.
- App-store submission packages are review inputs, not install approvals. Keep package bodies,
  rationale documents, maintainer/source metadata, pre-review findings, transparency events, and
  catalog candidates deterministic and redacted; consent previews may summarize review metadata but
  must not include raw package bodies, local paths, keys, or tokens.
- Third-party developer beta artifacts are non-production unless explicitly promoted through the
  normal signed bundle, review, catalog, consent, and compatibility gates. The checked-in
  `hello-stable` sample and generated `review/*.md` files must stay stable-only by default,
  use only non-production reviewer material in tests, write generated ZIPs/reports outside the
  bundle root, and avoid private insert URIs, private keys, bearer/session tokens, raw fetched
  content, raw app data, raw rationale bodies, local absolute paths, and production signing or
  reviewer material.
- Reviewer governance is local trusted-key configuration plus a local tamper-evident transparency
  log. Do not present catalog-listed reviewer keys as automatically trusted, and do not describe
  the local transparency log as a global public log.
- `crypta:` catalog sources still require signed catalog verification. They do not make catalog
  artifacts trusted, and catalog entry bundle artifacts remain limited to the schemes documented in
  `docs/app-catalogs.md`.
- Catalog mirrors are transport fallbacks only. Every primary or mirror refresh must preserve safe
  source URI validation, signed catalog verification, catalog-id matching, trusted-key policy,
  parser/security-advisory checks, digest/revision calculation, and stale/downgrade prevention.
  Mirror refresh must not silently roll back to older bytes; only an explicit operator rollback to
  a previously verified revision may move backward.
- Stable GA must publish or confirm the exact frozen signed stable catalog, signature, revision,
  artifact URLs, first-party app bundles, trusted review receipts, signing identities, maintenance
  policy, Platform API snapshot, and content-format profile registry. Do not rewrite, re-sign,
  relabel, or substitute any of those bytes after RC freeze. A required change returns to the
  authorized RC exception/refreeze path and restarts post-freeze validation.
- Stable catalog publication targets must be canonical, public HTTPS locations with a distinct
  primary and mirrors. Resolve and pin public addresses at the protected fetch boundary; verify the
  current and rollback signed catalog bytes before any public release mutation and again afterward.
  A mirror is never a trust authority. Never serialize private insert URIs or publication
  credentials in the plan, maintenance baseline, or receipt.
- PR-293 adds a public Crypta USK network primary; it does not remove the Stable GA HTTPS checks.
  Bind the exact frozen catalog and detached signature, revision and USK edition, signer ID and
  fingerprint, PR-291 release root, PR-292 catalog subject, independently operated mirror, and
  eligible rollback subject. Only the protected mutation job may materialize insert capability.
  Run that job on the dedicated protected Stable catalog-publication runner with a managed
  localhost daemon and matching form-password secret. Its bounded greeting and Platform API
  contract preflight must pass before secrets enter the job; daemon lifecycle remains a protected
  runner-provisioning responsibility, not a release-workflow action.
  Local engines, fixtures, docs, or workflow definitions never prove ceremony, publication,
  observation, rotation, or rollback completion.
- Catalog operation routes under `/api/v1/app-catalogs/{catalogId}/mirrors` and
  `/api/v1/app-catalogs/{catalogId}/operations/*` are host/operator-only local-management routes.
  They must deny app-process and app-browser principals, and mutating bridge requests must pass the
  form-password guard. Support/API/Web Shell output must remain redacted: no private insert URIs,
  private keys, app/session/process tokens, form passwords, raw catalog bytes, raw signature bytes,
  raw fetched content, raw app data, scratch paths, staged paths, rollback paths, or absolute local
  paths.
- Production security response is catalog/app/reviewer governance only. Keep emergency advisories,
  exact-version denylists, reviewer-key/receipt revocations, catalog signing-key rotation evidence,
  replacement guidance, and safe uninstall/update labels compact and operator-facing. Do not expose
  raw incident artifacts, raw catalog bytes, private insert URIs, tokens, private keys, raw fetched
  content, raw app data, command lines containing secrets, CI secret values, or local absolute paths
  through API responses, Web Shell text, support bundles, release notes, or certification evidence.
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
- `GET /api/v1/updates/support-lifecycle` is likewise host/operator-only and
  `OPERATOR_ONLY` in the compatibility contract. Keep the app-readable
  `GET /api/v1/updates/core` response limited to updater availability and download readiness; do
  not expose lifecycle state through it as a shortcut around the direct-route principal check.
  Web Shell must treat failure of the lifecycle request as an unknown best-effort diagnostic while
  preserving a successful core response and its independently authorized controls.
- Operator RC recovery routes must stay typed and allowlisted. Clients request an
  `OperatorRecoveryPlan` for a known `OperatorRecoveryActionId`, then execute that exact action
  with the matching one-time `planToken`; destructive actions require explicit confirmation. Do
  not add generic route proxying, arbitrary method/path execution, broad shell commands,
  token-persistent dashboards, or support bundles that include plan tokens, raw backup payloads,
  raw Trust Graph statements, private insert URIs, raw app data, command lines, or local paths.
- Positive AppHost data/cache quotas must block launch or restart when usage is over limit or an
  enforced area cannot be measured completely. Quotas and current sandbox providers are operational
  controls, not hard OS isolation.
- Bubblewrap sandbox status is public only as provider/support-level metadata. Do not expose the
  configured `bwrap` executable path, generated wrapper command line, bind mount source paths, app
  tokens, or host private configuration.
- Legacy admin retirement changes must update both the code map
  (`LegacyAdminRetirementRegistry`) and `docs/legacy-retirement-plan.md`.
- Legacy admin Wave 5 is the production-beta final admin surface. It adds no new removed-by-default
  route ids, keeps Wave 1-4 removals stable, marks legacy admin maintenance-only, and retains FProxy
  browse/content rendering, content filter, startup/recovery, support, and exact emergency fallback
  surfaces. Do not add new daily legacy-admin surfaces; route new operator workflows through Web
  Shell, Platform API, or first-party apps.
- Release-certification evidence must not expose private signing keys, app process tokens,
  browser-session tokens, form passwords, raw request bodies, raw feed bodies, raw trust documents,
  raw diagnostic exports, raw app-data backup payloads, private insert URIs, non-localhost endpoint
  metadata, or unsanitized local paths. Optional live AppHost smoke reads the form password from
  `CRYPTAD_CERT_FORM_PASSWORD`; do not pass it as a command-line argument. Dedicated live-network
  beta certification must stay localhost-only, env/protected-file driven for secrets, and disabled
  for normal PR/nightly/offline release-candidate runs unless explicitly requested.
- Unified app-platform, live-network, multi-node, security, production, dashboard, Stable, and
  release-certification inputs are candidate-bound v2 envelopes. Do not bypass kind, release-ID,
  exit-code, or common-redaction validation through legacy aliases, fixture switches, or command
  passthrough arguments. Attached legacy payloads are scanned again before extraction, and
  security-drill sidecars are scanned and digest-checked before copying.
- Release artifacts live under `<out-root>/<release-id>/<component>/`. Common v2 files are at the
  component root, engine-native output is under `artifacts/legacy/`, and validated attached inputs
  are under `artifacts/inputs/`. All writers must remain symlink-safe and confined to the marked
  workspace. If engine output fails the fallback scan, remove the unsafe raw copies and emit only a
  sanitized failed envelope with `promotionReady=false`.

## Release certification smoke

- `tools/release-certification/certify.py app-platform` is the app-platform evidence collector for
  release certification. It validates first-party staged bundles, static UI/SDK coherence,
  design-system adoption, strict UI lint JSON evidence, `crypta-app init/validate/pack/dev/test`,
  Platform API contract snapshots, Platform API 1.0 stable-baseline and target-stability evidence,
  app-vault capability evidence, generated document insert
  evidence, bounded content-fetch/subscription evidence, durable app-data and app-data
  backup/restore evidence, app-network budget and network-scale soak evidence, signed bundle
  evidence, signed catalog/live USK publication evidence,
  first-party beta catalog metadata, app-store submission/pre-review evidence, third-party
  developer beta docs, template, sample flow, checklist, compatibility, feedback,
  plugin-migration, and redaction evidence, trusted app-review
  receipt evidence, sandbox-provider evidence, app-update lifecycle/scheduler/rollback and
  app-data migration contract evidence, Site Publisher/Profile Publisher/Social Inbox RC/Feed
  Reader/Trust Graph Local RC reference-app evidence, unified consent evidence, app-service
  registry/grant/dependency/grant-bundle/redaction evidence, legacy plugin freeze
  evidence, app-review governance and local transparency-log evidence, public-beta security
  hardening evidence, catalog operations and mirrors evidence, operator beta
  dashboard/recovery/support-bundle evidence, operator RC recovery/support workflow evidence,
  production security response runbook evidence,
  legacy-admin retirement Wave 1-5/final-surface state, and optional localhost-only live AppHost
  lifecycle evidence.
- `tools/release-certification/certify.py live-network-beta` is the explicit release-manager
  live-network beta evidence collector. It validates a prepared localhost node, live catalog
  source/key metadata, app-principal browser-session workflows, content/feed/profile/trust
  fixtures, optional app-service scoring, timing metadata, cleanup, and redaction without leaking
  secrets or becoming a normal CI dependency.
- `tools/release-certification/certify.py stable-third-party-pilot` is the side-effect-free
  external-pilot authenticator. Keep its `third-party-pilot.*` operational evidence separate from
  sample-oriented `third-party-intake.*` rows. A fixture can reach only
  `fixture-verification-complete`; operational completion requires signed external handoff,
  PR-293 reviewer/catalog receipts, the bounded pilot publisher approval, the existing
  live-network collector receipt, exact rollback/cleanup, and PR-291/292/293 roots.
- External pilot trust uses a dedicated or ephemeral app registry and
  `PilotPublisherVerificationPolicy`. Bind the exact normal Stable, canonical PR-293 catalog, and
  pilot registry byte digests; keep all three roles disjoint by key id and public key. Pilot cleanup,
  expiry, or revocation must disable only the approved external publisher, not ordinary Stable app
  or catalog verification. Never add the publisher key silently to the normal Stable registry,
  authorize another app/version/sidecar, or let intake `install-smoke` substitute for a live AppHost
  drill.
- External-pilot closeout must derive the expected PR-293 catalog subject from the authenticated
  PR-291 selected RC, exact selected-RC freeze, and PR-292 subject inventory. Never use PR-293's own
  closeout subject as its expected revision, edition, catalog/signature digest, or signer.
- `tools/release-certification/certify.py stable-federated-catalog` is the side-effect-free PR-295
  verifier. Signed discovery and endorsement records are public hints only; they must not install
  keys, add sources, create trust, disclose subscriptions, or authorize publishers/reviewers.
  Runtime evidence must preserve catalog/app/reviewer/recovery role separation, classify hard
  conflicts without lexical trust decisions, keep updates pinned to installed origin, require
  explicit source/publisher-switch consent, restore origin with rollback, and isolate one
  catalog's suspension/revocation. Operational closeout requires exact authenticated PR-291,
  PR-292, PR-293, and PR-294 coordinates plus a signed non-partial protected runtime observation.
  Compose catalog/app-scoped publisher verification with any existing PR-294 pilot approval; do
  not replace the exact pilot app/version/sidecar boundary. Lifecycle source switching must carry
  an explicit target catalog and its exact preview digest through retained-plan verification before
  any migration dry run.
  Capture the authenticated catalog-origin subject in the retained install plan and reverify it
  before mutation. A legacy plan may carry non-federation-scoped context for that retained-plan
  check, but default nodes must not persist it as installed origin, pin updates, apply federation
  conflicts, or require source-switch consent. Commit federation-scoped catalog origin through
  AppHost together with bundle install/update so migration or health rollback always sees matching
  current/rollback slots; provenance write failure must leave or restore the prior bundle state.
  Before committing or restoring a catalog bundle, AppHost must compare the copied bundle's actual
  signing-key ID, canonical signing-key fingerprint, and signed content commitment with the stored
  origin; a broadly trusted signature plus matching manifest metadata is insufficient.
  AppHost interface defaults must reject catalog install/update and standalone origin persistence
  before bundle mutation. Dispatch rollback from the retained rollback slot: catalog provenance
  requires the authorized overload, while an untracked legacy slot retains the original
  `rollback(String)` compatibility path.
  Resource-consuming source-switch previews are host/operator-only form-password-guarded `POST`
  routes; never expose catalog download, extraction, or verification preparation through `GET`.
  Suspension blocks routine work but may authorize explicit rollback of exact retained bytes when
  the stable binding identity and current signer, catalog, channel, and historical lifecycle policy
  still match; revocation, removal, and pending state remain blocked. Fixtures and self-tests can
  reach only
  `fixture-verification-complete`.
- `tools/release-certification/certify.py app-platform-docs` is the deterministic docs evidence
  collector for the app ecosystem beta portal, tutorials, beta program, issue templates, internal
  Markdown links, and docs redaction checks.
- `pr` mode must stay fast and offline-safe. It must not require a live node, signing keys, Hyphanet
  downloads, or production credentials.
- `release-candidate` mode treats missing required signed bundle/catalog/app-platform evidence as
  failing unless a release-manager waiver is recorded by the aggregator.
- Stable 1.0 readiness is a stricter promotion layer over production beta evidence. App-platform
  changes that affect Platform API stability, first-party app maturity, third-party intake,
  security response, legacy migration, public beta support, diagnostics redaction, or app-data
  migration/backup evidence must keep the corresponding `stable-1.0.*` readiness rows complete and
  redaction-safe.
- Stable RC freezes the selected signed catalog/app set, maintenance metadata, API contract/diff,
  content profiles, limitations, product archive, and provenance. Stable GA consumes those exact
  identities plus protected post-freeze install/upgrade/rollback/migration/backup/live/security/
  support evidence. It must prove `rcProductDigest == gaProductDigest`; it cannot regenerate app or
  catalog payloads.
- `stable-1.0-maintenance-baseline.json` is the post-publication comparison anchor for the Platform
  API 1.0 surface, stable catalog revision/key, app versions/bundles/reviews/data schemas,
  content-profile canonicalization, limitations, advisory/denylist/reviewer state, support, and
  legacy boundaries. Future maintenance or hotfix work compares against it rather than mutating it.
- Stable API release evidence must include stable capability names, stable endpoint identities,
  stable endpoint required-capability sets, stable endpoint action labels, and stable endpoint
  app-process/app-browser access flags, compatibility-window metadata, and descriptor-level stable
  deprecation/removal metadata.
  `platform-api.contract` details should include `stableDescriptorDeprecations`, and
  `platform-api.deprecation-window-policy` should expose descriptor-level errors/warnings for
  missing `deprecatedSinceContractVersion`, future deprecation starts, invalid
  `removalContractVersion`, and too-short removal windows. Production history checks fail closed on
  stable removals, required-capability changes, access regressions, missing current metadata,
  malformed stable descriptor deprecation metadata, or missing previous metadata when history is
  required.
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
python3 tools/release-certification/certify.py self-test all
python3 tools/release-certification/certify.py stable-rc --self-test
python3 tools/release-certification/certify.py stable-ga --self-test
python3 tools/release-certification/certify.py stable-maintenance --self-test
python3 tools/release-certification/certify.py stable-lifecycle --self-test
python3 tools/release-certification/certify.py stable-catalog-authority --self-test
```

When changing route contracts or bridge wiring, also run the relevant root router/toadlet tests
with `./gradlew :test --tests *PlatformApiRouterTest --tests *PlatformApiToadletTest`.

When changing `crypta-app` command wiring or distribution behavior, also run
`./gradlew :platform-devtools:installDist` and smoke the generated
`platform-devtools/build/install/crypta-app/bin/crypta-app --help` launcher.

When changing signed bundle/catalog, catalog operations/mirrors, live USK publication, app-review
receipts, static UI, design-system assets, UI lint, SDK, Platform API contract, stable-baseline
metadata, manifest or catalog target-stability behavior, AppHost lifecycle, app-vault
capabilities, generated document inserts, content fetch/subscriptions, shared app-network budgets,
network-scale soak evidence, durable app data, app-data backup/restore, app-service
dependencies/grant bundles, Trust Graph Local RC, Social Inbox RC, app-update
lifecycle/scheduler/rollback, sandbox-provider evidence, operator beta dashboard/support-bundle
behavior, production security response runbook/verifier behavior, live-network beta certification
behavior, production beta release/go-no-go dashboard behavior, third-party developer beta
docs/template/sample/submission evidence, reference content/profile/social/feed/trust apps, app
platform beta docs evidence,
operator RC recovery/support behavior, or legacy-admin retirement evidence behavior, also run:

```bash
python3 tools/release-certification/certify.py self-test all
```

Run a candidate-bound component only after copying the appropriate example manifest to `build/`,
replacing every placeholder, and arranging any required v2 migration or attached evidence with the
same finalized `release.id`.

## Stable 1.0 maintenance compatibility

Use `stable-maintenance` after GA for both routine maintenance and critical security hotfixes. It
compares Platform API, stable catalog, first-party apps, content profiles, security/support state,
limitations, and legacy boundaries against both the immutable GA baseline and the immediate
predecessor. Preserve original Platform API deprecation clocks and frozen v1 canonicalization and
signature rules. Reject app removal/id substitution, channel or support downgrade, untrusted
signers/reviewers, unexplained permission expansion, or missing migration, rollback, backup, and
restore evidence. If catalog bytes, signature, or signing-key identity changes, require the edition
or revision to advance. Validate known-limitations added/resolved/unchanged ids as a disjoint,
canonical partition of the authenticated predecessor membership; retain the sorted current ids in
each successor baseline so a later release cannot replace membership with an unauthenticated
digest.

Treat app support as a closed ordered commitment: promotion is allowed, downgrade or an unknown
level is not. Compare app versions with the canonical dotted-numeric `AppUpdateService` semantics.
A version cannot regress below GA or the predecessor, and changed bundle bytes require a strict
version increase so an installed node can discover the patch.

Bind all app/catalog/update and durable-state scenarios to the exact candidate and predecessor
digests. A security hotfix cannot waive these gates; only policy-listed observation windows may be
shortened, creating a follow-up obligation. Follow
`docs/stable-1.0-maintenance-release-and-hotfix-path.md`.

## Stable 1.0 lifecycle and deprecation governance

Platform API 1.0 deprecation clocks are historical commitments. A maintenance baseline may carry
them forward but must not move `deprecatedSinceContractVersion` or scheduled removal later to reset
the clock. Do not remove a stable endpoint or capability while an authenticated supported Stable
1.0 build or required stable third-party sample depends on it. Lifecycle end-of-support never
rewrites a published contract snapshot or makes a prohibited critical-removal waiver valid.

Reuse signed catalog, review, app-maintenance, advisory/denylist, and content-profile metadata when
building lifecycle governance output. The projection informs certification and operator support;
it does not replace those trust models. Keep first-party app IDs and support commitments stable,
require explicit replacement/migration guidance for deprecation where policy requires it, preserve
backup/restore commitments, and never change a frozen content-profile canonicalization or signature
rule in place.

Expose the running build's lifecycle through the detached updater SPI, read-only update/operator
routes, the redacted support bundle, and the Web Shell. Distinguish unknown, stale, full support,
security-only, deprecated, end-of-support, and revoked states. Show integer build identifiers and
safe replacement guidance, and offer an update action only when the existing updater can honor it.
Use `recommendedBuild` for an optional upgrade from `supported-maintenance`; do not label it as a
required replacement. Do not expose changed future-effective guidance early. An already-effective
terminal revocation remains visible with its predecessor-authenticated recovery guidance until the
successor activates, including when the last-known-good descriptor is stale. Do not include raw
descriptors, private update URIs, advisory bodies, local paths, app data, or node identity in these
surfaces. Follow
`docs/stable-1.0-support-lifecycle-and-deprecation-governance.md`.
