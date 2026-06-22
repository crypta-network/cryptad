# Release certification

Release certification is the reproducible evidence bundle for a Cryptad release candidate. It
aggregates compatibility, performance, app-platform, catalog, app-owned UI, operator beta recovery,
network-scale soak, ecosystem RC certification, optional live-network beta certification,
legacy-admin retirement, and CI metadata into one redacted report.

The generated artifacts are:

```text
build/release-certification/release-certification-summary.json
build/release-certification/release-certification-report.md
build/release-certification/history-comparison.json
build/release-certification/history-comparison.md
build/release-certification/ecosystem-certification-matrix.json
build/release-certification/ecosystem-certification-matrix.md
build/release-certification/artifacts/
build/release-certification/app-platform-smoke/summary.json
build/release-certification/app-platform-smoke/app-platform-smoke-report.md
build/release-certification/app-platform-smoke/artifacts/
build/release-certification/network-scale-soak/summary.json
build/release-certification/live-network-beta-smoke/summary.json
build/release-certification/live-network-beta-smoke/live-network-beta-smoke-report.md
```

The Markdown report and ecosystem matrix are intended for human release review. The JSON summary
is the stable machine-readable companion for later automation and report comparison. The
`live-network-beta-smoke/` files are written only when live-network beta certification is explicitly
enabled.

## Modes

| Mode | Purpose | Behavior |
| --- | --- | --- |
| `pr` | Quick local or normal PR evidence. | Runs Python-only certification and lightweight app-platform checks.  It does not require a live node, signing keys, Hyphanet baseline download, or packaged-node smoke. |
| `nightly` | Scheduled/manual evidence aggregation. | Records missing optional evidence as warnings and can run heavier app-platform checks. |
| `release-candidate` | Strict release gate. | Fails when required evidence is missing, skipped, or failing unless a release-manager waiver is recorded. |

Production beta candidates use a separate wrapper around this release-candidate evidence gate:
`tools/release-certification/run-production-beta-release.sh`. That command builds and signs
first-party app bundles, creates a signed first-party catalog, generates review receipts, runs the
app-platform/live-network/soak/certification collectors, scans the final public artifact tree, and
writes `reports/production-beta-summary.json`. See
[production-beta-release-pipeline.md](production-beta-release-pipeline.md) for the exact command,
mode semantics, required secrets, artifact layout, failure classes, and rerun guidance.

## Run locally

The release-certification tools require Python 3.10 or newer and use only the Python standard
library.

Run self-tests first:

```bash
python3 tools/release-certification/app_platform_docs_check.py --self-test
python3 tools/release-certification/release_certification.py --self-test
python3 tools/release-certification/app_platform_smoke.py --self-test
python3 tools/release-certification/network_scale_soak.py --self-test
python3 tools/release-certification/live_network_beta_smoke.py --self-test
python3 tools/release-certification/production_beta_release.py --self-test
```

Run the offline wrapper modes from a clean release workspace:

```bash
tools/release-certification/run-release-certification.sh --mode pr --skip-gradle --skip-git-metadata
tools/release-certification/run-release-certification.sh --mode nightly --out-dir build/release-certification
tools/release-certification/run-release-certification.sh \
  --mode release-candidate \
  --out-dir build/release-certification
```

Run a production beta candidate from the repository root:

```bash
tools/release-certification/run-production-beta-release.sh \
  --workspace-root . \
  --out-dir build/production-beta-release \
  --mode production-beta \
  --catalog-channel stable \
  --artifact-base-uri "$CRYPTAD_PRODUCTION_BETA_ARTIFACT_BASE_URI" \
  --require-live-network \
  --require-sandbox-provider-tests
```

Use `--mode developer-dry-run` for local and PR-safe non-release artifacts. Dry-runs do not require
real signing keys or live-network evidence, and the summary marks the output as `nonRelease=true`.
`release-candidate` and `production-beta` runs require a real HTTPS artifact base URI through
`--artifact-base-uri` or `CRYPTAD_PRODUCTION_BETA_ARTIFACT_BASE_URI`.

The wrapper may be invoked from outside the repository. Relative `--out-dir` values are resolved
under the repository root so shell cleanup, app-platform smoke output, and aggregation read the same
evidence directory.

Compare a release candidate with the previous certified release:

```bash
tools/release-certification/run-release-certification.sh \
  --mode release-candidate \
  --previous-summary path/to/previous/release-certification-summary.json \
  --out-dir build/release-certification
```

Use `--require-history` when the release-candidate run must fail if the previous summary is
missing or malformed. Without `--require-history`, missing history is skipped in `pr` mode and
recorded as a warning in `nightly` and `release-candidate` modes.

The wrapper consumes the existing gate outputs when present:

```text
build/interop-smoke/summary.json
build/interop-extended/summary.json
build/perf-smoke/summary.json
build/perf-smoke/artifacts/perf-report.md
build/release-certification/app-platform-smoke/summary.json
build/release-certification/network-scale-soak/summary.json
build/release-certification/live-network-beta-smoke/summary.json
```

Run the source gates before the release-candidate aggregation when their evidence is required:

```bash
tools/interop/run-hyphanet-interop-smoke.sh
INTEROP_MODE=extended INTEROP_SKIP_BUILD=1 tools/interop/run-hyphanet-interop-smoke.sh
tools/perf/run-performance-smoke.sh
```

## Required evidence

Release-candidate mode requires these evidence ids:

| Evidence id | Source | Required condition |
| --- | --- | --- |
| `interop.smoke` | `build/interop-smoke/summary.json` | Tier 1 Hyphanet interop smoke passed with CHK, SSK, USK, peer exchange, and restart-recovery coverage. |
| `performance.smoke` | `build/perf-smoke/summary.json` | Performance smoke did not fail required metrics or deterministic regression thresholds. |
| `app-platform.first-party` | App-platform smoke summary. | The first-party staged apps, including Queue Manager, Publisher, Site Publisher, Profile Publisher, Social Inbox RC, Feed Reader, and Trust Graph Local RC, have valid manifests, launchers, static UI assets, and SDK wiring. |
| `app-platform.devtools-cli` | App-platform smoke summary. | `crypta-app init`, `validate`, and `pack` work for a generated sample app. |
| `app-platform.developer-beta-toolkit` | App-platform smoke summary. | Developer beta toolkit command, template, mock-dev, offline-test, catalog entry, dry-run publication, live publication CLI wiring, docs, and self-test evidence is present. |
| `app-platform.docs-portal` | App-platform docs check. | The developer portal, required docs, known limitations page, portal links, and README portal link are present. |
| `app-platform.beta-program` | App-platform docs check. | The beta program doc and app platform beta feedback/submission issue templates are present. |
| `app-platform.beta-tutorials` | App-platform docs check. | Offline beta tutorials cover the required `crypta-app` commands, first-party app map, Platform API capabilities, review governance, update/rollback, and retained FProxy browse concepts. |
| `app-platform.docs-redaction` | App-platform docs check. | Local Markdown links resolve without network access, and docs/templates pass obvious secret, token, private key, cookie, form-password, and local-path redaction checks. |
| `app-platform.signed-bundles` | App-platform smoke summary. | First-party and sample bundle signing/verification evidence exists with configured non-production or release signing inputs. |
| `catalog.smoke` | App-platform smoke summary. | Signed catalog create/sign/verify evidence exists and records digest, catalog id, and app id without private key material. |
| `catalog.live-usk-publication` | App-platform smoke summary. | `crypta-app publish-usk --live` validates and verifies signed catalog sidecars, reads the private insert URI and form password only from secure sources, enqueues real localhost live insertion, and writes sanitized evidence. |
| `catalog.live-usk-source-verification` | App-platform smoke summary. | `crypta:USK@.../cryptad-app-catalog.properties` refresh resolves matching editions, fetches `cryptad-app-catalog.signature` from the same USK edition, and stores replacements only after signed catalog verification. |
| `app-catalog.first-party-beta` | App-platform smoke summary. | Recommended first-party beta catalog descriptor, Platform API/Web Shell onboarding, CHK artifact transport tests, first-party metadata docs, and configuration readiness reporting are present without a live public-network fetch. |
| `catalog.production-channels` | App-platform smoke summary. | Catalog schema v3, stable/beta/nightly/deprecated metadata, stable-only default automation, deprecated replacement metadata, API/Web Shell exposure, signed catalog/review verification, and redaction guarantees are present. |
| `app-catalog.first-party-maintenance-policy` | App-platform smoke summary. | The first-party maintenance policy source covers every first-party app, catalog v5 parser/writer/descriptor support exists, CLI/API/Web Shell surfaces expose maintenance metadata, production beta descriptors consume it, and docs state local-RC and legacy-protocol non-goals. |
| `catalog.security-advisories` | App-platform smoke summary. | Catalog schema v4 parser/writer support for strict signed catalog-level security advisory records is present. |
| `catalog.version-denylist` | App-platform smoke summary. | Exact app-version denylist records reference known advisory IDs, expose redacted security decisions, and surface installed vulnerable versions with safe uninstall guidance. |
| `app-review.receipt-revocation` | App-platform smoke summary. | Receipt fingerprints, registry v3 receipt revocations, `revoked_receipt` trust status, and fail-closed review policy behavior are present. |
| `app-review.reviewer-key-compromise-flow` | App-platform smoke summary. | Reviewer-key `status=revoked` compromise handling remains fail-closed as `revoked_reviewer` and is visible through governance, CLI, and Web Shell summaries. |
| `app-update.security-denylist-gates` | App-platform smoke summary. | Install, update, stage, apply, and scheduler policy paths block denylisted candidates, warning advisories require `securityAcknowledged=true` for manual actions, and security acknowledgement does not bypass other gates. |
| `web-shell.security-advisory-trust-warnings` | App-platform smoke summary. | Web Shell renders advisory, denylist, revoked-review, security acknowledgement, and safe uninstall guidance using safe DOM construction. |
| `ecosystem-security.advisory-revocation-redaction` | App-platform smoke summary. | Advisory and revocation evidence excludes raw signatures, raw public keys, private keys, private insert URIs, tokens, request bodies, raw fetched content, app-data backup payloads, local filesystem paths, catalog scratch paths, and staged bundle paths. |
| `production-security.response-runbook` | App-platform smoke summary. | [production-security-response-runbook.md](production-security-response-runbook.md), the deterministic drill model, verifier script, security release notes template, advisory lifecycle coverage, reviewer compromise drill, catalog key rotation drill, app signing key compromise drill, emergency catalog update workflow, API/Web Shell security response summary, and support redaction test coverage are present. |
| `app-review.governance` | App-platform smoke summary. | Reviewer-key lifecycle statuses, policy-version constraints, governance API routes, and Web Shell governance rendering are present and redacted. |
| `app-review.reviewer-key-lifecycle` | App-platform smoke summary. | Trusted reviewer registry v2 parsing, active/retired/revoked semantics, duplicate-id fail-closed behavior, strict instants, and lifecycle verifier tests are present. |
| `app-review.transparency-log` | App-platform smoke summary. | A local hash-chained review transparency log exists, can be verified, deduplicates receipt observation, and has tamper/redaction tests. |
| `app-review.review-history-api` | App-platform smoke summary. | Review governance, reviewer-key, transparency-log, verification, and catalog-app review-history Platform API routes are present and Web Shell consumes review-history data. |
| `app-review.first-party-review-chain` | App-platform smoke summary. | First-party review receipt evidence, review-history/governance readiness, and transparency-log evidence are tied together for release promotion. |
| `app-store.*` | App-platform smoke summary. | Third-party submission package schema, `crypta-app submission` CLI, pre-review reports, decision states, receipt issuance, rejection metadata, resubmission links, transparency events, catalog candidates, fixture sample flow, and redaction checks are present. |
| `platform-api.contract` | App-platform smoke summary. | The deterministic Platform API compatibility contract snapshot was generated, parsed, and used for offline compatibility verification of first-party/sample apps. |
| `platform-api.stable-baseline` | App-platform smoke summary. | The Platform API 1.0 stable baseline metadata is present with deterministic capability and endpoint counts. |
| `platform-api.stable-breaking-change-check` | App-platform smoke summary and release history. | Release certification compares the current stable baseline against previous production release evidence and blocks stable API breaking changes. |
| `platform-api.manifest-target-stability` | App-platform smoke summary. | Manifest, catalog, and CLI metadata preserve `api.targetStability`. |
| `platform-api.first-party-stability-declarations` | App-platform smoke summary. | First-party staged manifests declare stable or experimental API targets and matching experimental acceptance flags. |
| `platform-api.stable-reference-docs` | App-platform smoke summary. | The stable API 1.0 reference and contract docs describe baseline membership and operator-only exclusions. |
| `app-vault.capabilities` | App-platform smoke summary. | App secret and identity vault capability docs, devtools vocabulary, grant lifecycle notes, and redaction checks are present. |
| `app-platform.identity-profile-publish` | App-platform smoke summary. | The profile-document signing route `POST /api/v1/app-vault/identities/{identityId}/profile-document` is present, documented, capability-gated by `vault.identities.read` plus `vault.identities.use`, and covered by redaction evidence. |
| `app-platform.generated-document-insert` | App-platform smoke summary. | The app-generated document insert route `POST /api/v1/queue/inserts/app-document` is present, documented, capability-gated by `content.insert.app-document` plus `queue.write`, and avoids local file-path request authority. |
| `app-platform.content-fetch` | App-platform smoke summary. | The content fetch route `POST /api/v1/content/fetch` is present, documented, capability-gated by `content.fetch`, and covered by feed-body/request-body/token/path redaction evidence. |
| `app-platform.content-subscriptions` | App-platform smoke summary. | The content subscription routes under `/api/v1/content/subscriptions` are present, documented, app-principal scoped, capability-gated by `content.subscribe` plus `content.fetch` for create/refresh, and covered by raw-content/token/path/queue HTML redaction evidence. |
| `network-content.subscription-scheduler` | App-platform smoke summary. | Offline source and test evidence proves deterministic content-subscription `tick(Instant)`, no-overlap execution, per-app/global/per-tick limits, failure backoff, dedupe, queue pressure handling without parsing queue HTML, and path-free durable metadata. |
| `app-platform.durable-app-data-store` | App-platform smoke summary. | The `/api/v1/app-data` route family, `app.data.read`, and `app.data.write` are present in the current contract, file-backed records use path-safe atomic storage, quotas/import/export/schema metadata are bounded, and evidence excludes raw app values, request bodies, tokens, private insert URIs, and local paths. |
| `app-data.backup-restore-portability` | App-platform smoke summary. | The `backupVersion = 1` `crypta-app-data-backup` envelope, single-app and all-app export, host/operator-only restore plan and commit routes, `merge`, `replaceNamespace`, and `replaceApp` modes, app-principal denial, Web Shell controls, first-party app backup-scope docs, and support-bundle redaction checks are present without raw backup payloads in evidence. |
| `app-platform.trust-graph-preview` | App-platform smoke summary. | The original trust graph route evidence remains present and is now documented as local RC trust-service behavior, capability-gated by `trust.read` and `trust.write`, SDK trust helpers exist, and evidence is redacted. |
| `app-platform.trust-graph-rc-scope-and-safety` | App-platform smoke summary. | Trust Graph status, docs, app UI, Web Shell wording, lifecycle records, source metadata, score evidence, and `trust.score` service boundaries prove local RC scope: local anchors, imported public signed statements, no crawling, no global moderation/blocking/routing, no legacy WoT/Freetalk/Sone/Freemail compatibility, lifecycle exclusions, bounded explanations, and redaction. |
| `app-platform.trust-graph-durable-store` | App-platform smoke summary. | The file-backed trust graph store is present, runtime wiring injects it into Platform API, anchors/statements/lifecycle/source/audit entries are bounded and redacted, lifecycle state survives restart, and evidence excludes raw trust bodies, raw fetched content, private insert URIs, tokens, signatures, and local paths. |
| `app-platform.trust-graph-exchange` | App-platform smoke summary. | Trust URI import and audit descriptors, SDK exchange helpers for URI import, publish, and subscription wrappers, and exchange evidence use only route names, capability names, booleans, counts, and redacted identifiers without adding a Trust Graph crawler. |
| `app-platform.trust-social-beta-hardening` | App-platform smoke summary. | Trust Graph import preview, duplicate issuer/conflict summaries, anchor lifecycle, bounded score explanations, recovery/export/import docs, Social Inbox multi-source controls, read/unread state, local mute/block filters, redacted message export, mediated Trust Graph score grants, additive Social Inbox schema-1 beta data readiness, consent markers, and redaction markers are present. |
| `app-platform.trust-statement-signing` | App-platform smoke summary. | The bounded AppVault route `POST /api/v1/app-vault/identities/{identityId}/trust-statement` is present, documented, requires `trust.write`, `vault.identities.read`, and `vault.identities.use`, and does not expose private material in evidence. |
| `app-platform.social-message-signing` | App-platform smoke summary. | Contract v11 exposes the bounded AppVault route `POST /api/v1/app-vault/identities/{identityId}/social-message`, fixes the signing domain to `crypta.social.message.v1`, requires `vault.identities.read` and `vault.identities.use`, and does not expose generic browser signing or private material in evidence. |
| `app-services.registry` | App-platform smoke summary. | Contract v12 exposes `/api/v1/app-services`, `app.services.read`, and `app.services.call`, parses signed manifest service descriptors and requests, wires a shared coordinator, and includes SDK service helpers. |
| `app-services.grants` | App-platform smoke summary. | The app-service grant model, statuses, in-memory/file-backed stores, host-only approval, revocation, expiry, compatibility fingerprints, active-grant invocation check, and deterministic tests are present. |
| `app-services.dependency-graph` | App-platform smoke summary. | Contract v16 dependency graph routes exist, parse signed dependency metadata while preserving legacy requests, enforce app-principal scoping, and emit deterministic path-free graph JSON. |
| `app-services.grant-bundles` | App-platform smoke summary. | Grant-bundle models, stores, routes, app-request flow, host/operator-only approve/reject controls, and rejected-bundle no-active-grant behavior are present. |
| `app-services.grant-expiry-renewal` | App-platform smoke summary. | Bundle-approved grants can expire, expired grants fail closed, and host/operator renewal revalidates the signed manifest and provider descriptor before restoring access. |
| `app-services.provider-revalidation` | App-platform smoke summary. | Provider descriptor fingerprint, service version, scope, context, kind, or adapter drift forces `revalidation-required` behavior and blocks invocation until explicit operator renewal/revalidation. |
| `app-services.trust-score-provider` | App-platform smoke summary. | Trust Graph Local RC advertises read-only `trust.score` through a `trust-graph.score` platform adapter that returns a bounded redacted score summary, is not a localhost proxy, and cannot mutate anchors, imports, or lifecycle records. |
| `reference-app.social-inbox-service-grant` | App-platform smoke summary. | Social Inbox declares a `trust.score` request, uses `app.services.read` and `app.services.call`, invokes through `CryptaPlatform.services.invoke`, and shows neutral missing/pending/revoked grant states. |
| `reference-app.social-inbox-service-dependency` | App-platform smoke summary. | Social Inbox declares the optional `trust-annotations` dependency bundle for Trust score annotations, requests it through the SDK, and degrades safely when the dependency is unavailable. |
| `app-services.web-shell` | App-platform smoke summary. | Web Shell lists advertised services, dependencies, grant bundles, grants, expiry, revalidation warnings, and redacted audit events, and lets the operator approve/reject/renew bundles or revoke active grants. |
| `app-services.redaction` | App-platform smoke summary. | App-service evidence excludes raw tokens, raw subject URIs, raw request bodies, private insert URIs, local paths, provider app data, and generic proxy behavior. |
| `app-services.dependency-redaction` | App-platform smoke summary. | Dependency graph, bundle, Web Shell, and release evidence exclude raw service request bodies, raw subject URIs, raw Trust Graph data, raw signatures, tokens, private insert URIs, private keys, local paths, and app-data backup payloads. |
| `app-platform.user-consent-flow` | App-platform smoke summary. | Unified install/update/service-grant/app-data consent model, digest-tied approvals, stale approval rejection, auto-update gating, redacted audit decisions, Web Shell consent UI, docs, and tests are present. |
| `app-ui.design-system` | App-platform smoke summary. | Canonical app UI design-system assets exist and first-party staged bundles contain matching local copies. |
| `app-update.live-catalog-refresh` | App-platform smoke summary. | App-update scheduler evidence shows configured signed catalog refresh, including live USK catalog refresh, before candidate discovery while keeping manual update policy as the default. |
| `app-update.data-migration-contract` | App-platform smoke summary. | Signed app manifests declare app-data schema and migration metadata; update summaries expose path-free migration plans; dry-run, snapshot, missing-path, rollback-incompatible, Feed Reader, Trust Graph Local RC UI-state, and redaction checks are present. |
| `app-ui.lint` | App-platform smoke summary. | `crypta-app ui lint --strict --json` passed for first-party staged static UI bundles and produced sanitized path-free summaries. |
| `app-ui.first-party-adoption` | App-platform smoke summary. | First-party source/staged UIs load design-system CSS in order, use stable `cr-*` classes, and show permission disclosure for declared permissions across the repo-owned static apps. |
| `app-ui.smoke` | App-platform smoke summary. | First-party static UI and `crypta-platform.js` remain coherent and do not expose process-token names. |
| `reference-apps.content` | App-platform smoke summary. | Site Publisher exists as the first content reference app, declares content publishing permissions, uses the browser SDK content/queue helpers, and avoids vault identity permissions. |
| `reference-app.profile-publisher` | App-platform smoke summary. | Profile Publisher exists as the first identity-profile reference app, declares the expected vault/content/queue permissions, uses the profile-document and app-document insert routes, and keeps release evidence free of signatures and private material. |
| `reference-app.profile-publisher-app-data` | App-platform smoke summary. | Profile Publisher requires at least contract v9, is tested through v14, declares `app.data.*`, uses SDK JSON record helpers for bounded profile draft, selected identity, last published URI, and recent publish summaries, and keeps identity private material in AppVault rather than app data. |
| `reference-app.social-inbox` | App-platform smoke summary. | Social Inbox RC exists as the threaded social inbox reference app, preserves `app.id=social-inbox`, declares vault/content/subscription/queue/app-data/app-service permissions, uses SDK and design-system assets, and documents that it is not full WoT, Freetalk/Sone/Freemail compatibility, encrypted mail, crawler, or a daemon-core message protocol. |
| `reference-app.social-inbox-signed-message` | App-platform smoke summary. | Social Inbox signs bounded `crypta.social.message.v1` documents through AppVault without exposing arbitrary browser signing, private identity material, raw request bodies, or raw signatures in evidence. |
| `reference-app.social-inbox-subscriptions` | App-platform smoke summary. | Social Inbox follows bounded USK social outbox sources with durable content subscriptions, displays last checked, last seen edition, update count, and bounded error state, fetches bounded JSON only on explicit refresh/import paths, and excludes raw fetched content from evidence. |
| `reference-app.social-inbox-app-data` | App-platform smoke summary. | Social Inbox uses app data for sources, outbox summaries, imported-message summaries, UI filters, message/thread read state, additive schema-1 beta records, and explicit drafts while excluding private insert URIs, browser-session tokens, private identity material, raw fetched documents, raw profile documents, and raw signatures. |
| `reference-app.social-inbox-trust-annotations` | App-platform smoke summary. | Social Inbox queries Trust Graph Local RC's `trust.score` service through an active app-service grant with `subjectKind=identity` and `context=message-author`, renders scores as advisory annotations, and keeps unscored or ungranted messages visible without hiding, archiving, blocking replies, or changing network behavior. |
| `reference-app.social-inbox-rc-threading` | App-platform smoke summary. | Social Inbox RC builds local threads from `replyTo`, provides reply context, channel filters, bounded local search, thread-level read/unread/archive/pin behavior, safe author/profile display, and dedupe source summaries without storing raw fetched content or raw message bodies. |
| `migration.social-mail-preview` | App-platform smoke summary. | The baseline migration evidence proves the social/mail-like layer composes AppVault, content insert/fetch/subscriptions, durable app data, and the mediated Trust Graph score service outside daemon core and legacy plugin APIs. |
| `legacy-plugin.freeze-policy` | App-platform smoke summary. | The production RC freeze policy exists, is linked from plugin-system and app-platform docs, documents the old in-process plugin runtime as removed/frozen, keeps old FCP plugin commands mapped only to deterministic unsupported responses, and proves no in-core plugin runtime/API surface has been reintroduced. |
| `legacy-plugin.migration-guide` | App-platform smoke summary. | The legacy plugin migration guide exists, is linked from plugin-system and app-platform docs, documents old plugin runtime removal, and maps legacy plugin categories to out-of-process app-platform mechanisms without restoring old plugin ABI or FCP command compatibility. |
| `legacy-plugin.social-inbox-spike` | App-platform smoke summary. | Social Inbox RC is certified as the executable app-platform replacement path for social/message-board plugin patterns with AppVault, app data, content subscriptions, app-generated documents, and mediated Trust Graph score service grants. |
| `reference-app.feed-reader` | App-platform smoke summary. | Feed Reader exists as the first content-subscription reference app, declares `content.fetch`, `content.subscribe`, and generated-document publication permissions, uses SDK feed helpers, and keeps evidence free of raw feed bodies and private fetch inputs. |
| `reference-app.feed-reader-subscriptions` | App-platform smoke summary. | Feed Reader requires at least API v9, is tested through v14, uses `CryptaPlatform.content.subscriptions.*` for durable USK follow behavior, shows scheduler metadata, and does not rely on a tab-local timer as the durable follow path. |
| `reference-app.feed-reader-app-data` | App-platform smoke summary. | Feed Reader requires at least contract v9, is tested through v14, declares `app.data.*`, uses SDK JSON record helpers for bounded feed sources, selected source, read/render metadata, safe publisher draft state, and a signed v1-to-v2 migration example, and keeps evidence free of raw feed bodies and app-data values. |
| `reference-app.trust-graph` | App-platform smoke summary. | Trust Graph Local RC exists as the local trust-service reference app, requires and is tested through API v22, declares trust/content/vault/queue/app-data permissions, advertises read-only `trust.score`, renders local-only warnings, import preview, anchor lifecycle, duplicate/conflict, and bounded score state, uses SDK trust helpers and design-system assets, declares a signed UI-state migration example, and keeps evidence free of raw trust documents and private material. |
| `reference-app.trust-graph-durable-exchange` | App-platform smoke summary. | Trust Graph Local RC demonstrates durable backend status, URI import, redacted audit, trust-statement subscription management, AppVault-backed publication, local public statement import, safe source metadata, and lifecycle status without hard-coded API URLs, crawling, or private insert URI persistence. |
| `reference-app.trust-graph-app-data-preview` | App-platform smoke summary. | Trust Graph Local RC uses app data only for UI-local draft/filter/import-summary state, keeps app data separate from the platform trust graph backend and app-data backup payloads, and redacts raw trust statements, private identity material, and local paths. |
| `legacy.retirement` | App-platform smoke summary. | The legacy-admin retirement registry is visible, counts are stable, replaced surfaces are absent from primary shell fallback links, and retained/pending legacy routes remain documented. |
| `legacy-admin.removal-wave-1` | App-platform smoke summary. | The first removal wave records the removed-by-default route ids, replacement URLs, safe-read redirect behavior, mutating-request block behavior, retained browse status, diagnostics counters, and redaction checks without requiring a live node. |
| `legacy-admin.removal-wave-2` | App-platform smoke summary. | The second removal wave records the next removed-by-default route ids, queue/config/statistics route-scope expansion metadata, replacement URLs, partial mutation fallback policy, retained diagnostic export status, diagnostics counters, and redaction checks without requiring a live node. |
| `legacy-admin.removal-wave-3` | App-platform smoke summary. | The third removal wave records `security-levels` safe-read redirects to Web Shell security, mutating legacy fallback for incomplete security flows, stable wave 1/2 route sets, retained browse/filter/diagnostic/wizard surfaces, and redaction checks without requiring a live node. |
| `legacy-admin.removal-wave-4` | App-platform smoke summary. | The fourth removal wave records `diagnostic` as the only new removed-by-default route, Web Shell diagnostics as the primary destination, exact safe-read plaintext export fallback behavior, retained FProxy/content-filter/startup/security fallback scope, and redaction checks without requiring a live node. |
| `legacy-admin.removal-wave-5` | App-platform smoke summary. | The fifth wave records production-beta final-surface readiness, no additional promoted route ids, stable Wave 1-4 route sets, retained browse/content-filter/startup/recovery/support scope, and redaction checks without requiring a live node. |
| `legacy-admin.final-admin-surface` | App-platform smoke summary. | The final-surface policy records removed-by-default admin surfaces, retained browse and browse-safety surfaces, explicit support/emergency fallbacks, startup/recovery fallbacks, pending gaps, retained support pages, and infrastructure route ids. |
| `legacy-admin.browse-retained` | App-platform smoke summary. | FProxy browse, key/content rendering, and the content filter remain explicitly retained and outside admin-removal prefix matching. |
| `legacy-admin.emergency-fallback-retained` | App-platform smoke summary. | Diagnostic export, security recovery, startup wizard, and support fallbacks remain explicit, bounded, and redacted. |
| `apphost.sandbox-provider` | App-platform smoke summary. | AppHost sandbox provider source and deterministic offline tests prove bubblewrap selection, enforced status reporting, fail-closed required sandbox behavior, and token/path-free public status. |
| `public-beta-security.app-ui-csp` | App-platform smoke summary. | Static app UI CSP uses `default-src 'none'`, local script/style/connect directives, no object/base/frame/worker/media execution paths, defensive browser headers, and local-only origin validation for CSP roots. |
| `public-beta-security.app-origin-policy` | App-platform smoke summary. | Web Shell app launch/probe logic accepts only registered local loopback isolated origins and safe same-origin fallback paths, rejects credentials, query/hash confusion, remote schemes, and keeps probe fetches credential-free CORS. |
| `public-beta-security.content-fetch-bounds` | App-platform smoke summary. | App-facing content fetch accepts only bounded Crypta/Freenet content-key families, rejects HTTP(S), file, local-path, protocol-relative, query/fragment, and backslash inputs, and keeps UTF-8 and error output redacted. |
| `public-beta-security.feed-sanitization` | App-platform smoke summary. | Feed Reader renders hostile feed/source/item fields as text, validates Crypta content URIs, bounds imported state, and includes adversarial markup fixtures. |
| `public-beta-security.social-inbox-sanitization` | App-platform smoke summary. | Social Inbox renders hostile social/source/trust annotation fields as text, validates Crypta content URIs, bounds imported summaries, and includes adversarial markup fixtures. |
| `public-beta-security.profile-sanitization` | App-platform smoke summary. | Profile Publisher bounds profile fields and queue/import display, renders profile text as text, validates URI-like fields, and does not expose private vault material. |
| `public-beta-security.trust-statement-hardening` | App-platform smoke summary. | Trust statement parsing/signing/import checks cover byte caps, unknown fields, duplicate/malformed structures, ISO controls, range checks, expiry ordering, unsupported signing parameters, and redacted rejected-import audit. |
| `public-beta-security.apphost-env-minimization` | App-platform smoke summary. | AppHost process-launch tests prove unrelated host environment variables are not inherited and only the documented AppHost variables plus minimal platform launch variables remain. |
| `public-beta-security.sandbox-host-checks` | App-platform smoke summary. | Sandbox provider checks prove path-free unavailability reasons, required sandbox fail-closed behavior, bubblewrap command containment flags, token-free command arguments, and honest filesystem-only bubblewrap scope. |
| `public-beta-security.audit-redaction-fuzz` | App-platform smoke summary. | Deterministic redaction fixtures scan app audit, app-service, trust graph, AppHost, Web Shell, release evidence, and publication-style summaries for tokens, form passwords, private insert URIs, private keys, raw bodies, raw signatures, and local paths. |
| `public-beta-security.transparency-log-privacy` | App-platform smoke summary. | App-review governance and local transparency-log evidence exposes counts, hashes, policy ids, lifecycle state, reviewer key ids, timestamps, status, and public evidence digests while excluding private keys, raw key bytes, raw signatures, paths, tokens, passwords, and raw bodies. |
| `app-update.lifecycle` | App-platform smoke summary. | Offline source and test evidence proves manual/stage/apply-when-stopped update policy, candidate detection semantics, compatibility/review/permission gates, and process health-gated apply behavior. |
| `app-update.scheduler` | App-platform smoke summary. | Offline source and test evidence proves background catalog refresh, installed-app update checks through `AppUpdateService.check(...)`, durable path-free scheduler summaries, failure backoff, and the manual default policy. |
| `app-update.rollback` | App-platform smoke summary. | Offline source and test evidence proves durable installed-bundle backup/restore behavior and confirms rollback is scoped to the immutable bundle, not app data/cache/run state. |
| `operator-beta.dashboard` | App-platform smoke summary. | Host/operator-only beta dashboard route, app-principal denial, route wiring, section shape, and docs evidence are present. |
| `operator-beta.catalog-health` | App-platform smoke summary. | The dashboard shows catalog health, trusted-key state, last fetch state, redacted source display, first-party recommendation warnings, and refresh recovery. |
| `operator-beta.app-update-recovery` | App-platform smoke summary. | The dashboard exposes safe app lifecycle/update recovery actions while preserving existing review policy, running-app guards, and uninstall restrictions. |
| `operator-beta.subscription-recovery` | App-platform smoke summary. | Host/operator subscription recovery wrappers list all subscriptions safely and provide refresh/pause/resume without granting app principals cross-app authority. |
| `operator-beta.trust-review-warnings` | App-platform smoke summary. | Trust Graph Local RC and app-review warnings are surfaced as local operator-curated state, not global truth, moderation, blocking, routing policy, node-to-node propagation, or complete Web of Trust. |
| `operator-beta.app-data-quota-warnings` | App-platform smoke summary. | App-data and AppHost quota warnings are summarized as counts, booleans, and status labels without raw app data values. |
| `operator-beta.app-data-backup-restore` | App-platform smoke summary. | Web Shell and operator route evidence expose sensitive app-data backup, restore preview, restore commit, all-app backup, and export-before-delete controls while keeping restore previews metadata-only and support bundles free of raw backup values. |
| `operator-beta.support-bundle-redaction` | App-platform smoke summary. | The support bundle route, redactor, and tests exclude tokens, form passwords, raw bodies, private insert URIs, local paths, command lines, and app-private values. |
| `operator-beta.web-shell` | App-platform smoke summary. | Web Shell renders the operator beta panel, refresh controls, support-bundle export/copy actions, read-only hints, and recovery submit handling. |
| `operator-rc.dashboard` | App-platform smoke summary. | Host/operator-only RC dashboard route, Web Shell RC-first load, beta fallback, typed recovery state, network-budget visibility, and app-principal denial are present. |
| `operator-rc.recovery-plan-execute` | App-platform smoke summary. | Recovery actions use closed `OperatorRecoveryActionId` dispatch, one-time plan-token enforcement, unknown-action rejection, destructive confirmation, and route-proxy rejection. |
| `operator-rc.catalog-repair` | App-platform smoke summary. | Catalog refresh, reverify, and safe first-party recommended-source repair use existing signed-catalog APIs without bypassing channel, security, review, or signature gates. |
| `operator-rc.app-reinstall-rollback` | App-platform smoke summary. | App update check/stage/apply/rollback, start/stop, and reinstall planning preserve running-app guards and block reinstall until a dedicated verified catalog reinstall API exists. |
| `operator-rc.export-before-uninstall` | App-platform smoke summary. | Export-before-uninstall creates an explicit sensitive backup response before uninstall while keeping raw backup payloads out of support bundles, dashboards, audit, and release evidence. |
| `operator-rc.subscription-recovery` | App-platform smoke summary. | Subscription refresh/pause/resume/reset-backoff/reschedule-now/delete recovery keeps reset/reschedule metadata-only and keeps refresh budgeted through the PR-256 budget services. |
| `operator-rc.app-service-grant-recovery` | App-platform smoke summary. | Grant revoke and bundle renew/revalidate/reject recovery uses the app-service coordinator while preserving expired-grant and descriptor-drift fail-closed behavior. |
| `operator-rc.trust-graph-recovery` | App-platform smoke summary. | Trust Graph export/recompute are metadata-only, while reset and audit-clear plans remain unavailable until tested store clear methods exist. |
| `operator-rc.network-budget-visibility` | App-platform smoke summary. | Operator network-budget snapshots expose safe counters only: app id, operation, window, counts, limits, active leases, and next availability. |
| `operator-rc.support-bundle-wizard` | App-platform smoke summary. | Web Shell and operator routes expose support-bundle preview metadata, included sections, omitted fields, and review-before-sharing workflow. |
| `operator-rc.redaction` | App-platform smoke summary. | RC recovery responses, support bundles, Web Shell panels, audit events, and release evidence exclude tokens, private URIs, raw content, raw app data, backup payloads, Trust Graph raw statements/signatures, and local paths. |
| `app-review.trusted-receipts` | App-platform smoke summary. | Offline source and test evidence proves signed review receipts, canonical payload verification, reviewer-key trust, rejection handling, and publisher-advisory-only fallback behavior. |
| `app-review.policy` | App-platform smoke summary. | Review policy evidence proves `advisory`, `warn_untrusted`, `require_trusted_review`, and `require_trusted_review_for_apply_when_stopped` modes are present and fail closed. |
| `app-review.first-party-catalog` | App-platform smoke summary. | First-party catalog evidence packs every staged first-party app, then signs, verifies, and embeds an independent review receipt for each catalog entry with configured reviewer inputs, without private reviewer key material in the report. |

`legacy-admin.removal-wave-1` is deterministic offline evidence. It proves that `/downloads/`,
`/uploads/`, `/insertfile/`, `/insert-browse/`, `/friends/`, `/addfriend/`, `/strangers/`, and
`/connectivity/` are removed by default when their replacements are reachable, that `GET` and
`HEAD` return replacement responses in that state, that mutating methods are blocked before legacy
handlers execute in that state, that unavailable replacements fall back to legacy rendering with
fallback diagnostics, that FProxy browse remains retained, and that diagnostics expose aggregate
counters without query strings, form data, file paths, peer refs, Freenet/Crypta URIs, tokens,
request bodies, or remote addresses. Optional live-node checks may record status codes for the
same routes, but normal PR and release-candidate certification do not require a live node.

`legacy-admin.removal-wave-2` is also deterministic offline evidence. It proves that `/alerts/`,
`/config/` and `/config/{section}`, `/core-update/`, `/stats/`, `/stats/requesters.html`, and the
reviewed queue count/key-list helpers are removed by default only when their replacements are
reachable. It distinguishes covered config POST mutations from mutating legacy alert bulk actions
and core-update installer and package-store actions that remain fallback. It also proves that
FProxy browse remains retained, content filter remains retained, pending wizard and node-to-node
message routes remain out of scope, the diagnostic export remained retained at that stage, and the
new diagnostics scope metadata stays bounded and redacted.

`legacy-admin.removal-wave-3` is deterministic offline evidence for `/seclevels/` only. It proves
that safe reads redirect to `/app/node/#security` when Web Shell security is reachable, that POST
and other mutating requests remain legacy fallback for master-password, password-file, high
physical security, and recovery flows, and that the route scope is limited to the canonical path
and slashless alias. It also proves that FProxy browse and content rendering remain retained, the
content filter remains retained, diagnostic export remained retained before Wave 4, startup wizard
and emergency fallback remain pending, node-to-node messages remain pending, and evidence excludes
query strings, form passwords, tokens, private insert URIs, raw bodies, raw signatures, and local
paths.

`legacy-admin.removal-wave-4` is deterministic offline evidence for `/diagnostic/` only. It
proves that `diagnostic` is the only Wave 4 route id, safe reads use Web Shell diagnostics at
`/app/node/#diagnostics` when the shell is reachable, mutating requests are blocked before the
legacy diagnostic handler runs, and the plaintext diagnostic export remains available only through
the exact support/emergency fallback marker. It also proves that FProxy browse and content
rendering remain retained, the content filter remains retained, startup wizard and recovery flows
remain retained or pending, the Wave 3 security fallback remains intact, and evidence excludes
arbitrary query strings, request bodies, form passwords, tokens, private insert URIs, raw
diagnostic output, raw fetched content, raw app data, raw signatures, and absolute local paths.

`legacy-admin.removal-wave-5` is deterministic offline evidence for the production-beta final admin
surface. It proves that Wave 5 promotes no additional route ids, that Wave 1-4 route sets remain
stable, and that remaining surfaces are explicitly classified as retained, pending,
support/emergency fallback, startup/recovery fallback, browse-owned, retained non-admin support, or
infrastructure. `legacy-admin.final-admin-surface` exposes those final route-id buckets in a
machine-checkable form. `legacy-admin.browse-retained` proves FProxy browse, key/content rendering,
and the content filter remain retained. `legacy-admin.emergency-fallback-retained` proves startup,
recovery, diagnostic export, and support fallbacks remain explicit. These evidence items exclude
query strings, request bodies, form passwords, browser and app tokens, private insert URIs, raw
diagnostic output, raw fetched content, raw app data, support-bundle payloads, raw signatures, and
absolute local paths.

`interop.extended` is optional in the machine gate but required by the release runbook when a
release changes compatibility-sensitive behavior. `apphost.sandbox-provider` does not require
host-installed bubblewrap in normal CI; it uses source checks and fake/offline provider tests.
The `public-beta-security.*` rows are deterministic public-beta hardening evidence. They inspect
source files, focused tests, staged first-party app bundles, redaction helpers, and docs. They do
not require a live network, private keys, private insert URIs, raw fetched bodies, raw trust
statements, or app/session tokens, and they do not claim live-network beta certification. Use the
PR-246 live-network beta certification command below for that release-manager evidence.
`app-update.lifecycle`, `app-update.scheduler`, `app-update.live-catalog-refresh`, and
`app-update.rollback` do not require a live node; missing update evidence blocks
release-candidate mode unless a release-manager waiver is recorded. The `operator-beta.*` evidence
ids are deterministic checks for the local dashboard, support bundle redaction, and recovery
wiring; missing operator beta evidence blocks release-candidate mode unless a release-manager
waiver is recorded. `app-data.backup-restore-portability` and
`operator-beta.app-data-backup-restore` are deterministic PR-250 checks for durable app-data
backup/restore portability. They verify source, docs, Web Shell, and redaction behavior without
placing raw backup payloads or raw app-data values in release evidence. The `operator-rc.*`
evidence ids are deterministic PR-257 checks for the RC recovery workflow, typed
plan-before-execute dispatch, destructive confirmation, catalog/app/subscription/app-service/
Trust Graph/network-budget coverage, the support-bundle wizard, and redaction. They verify the
`operator-rc-recovery-and-support-workflow` matrix row and the
`ecosystem.operator-rc-recovery` gate without requiring a live node, raw backup payloads, raw
Trust Graph statements, app tokens, private insert URIs, or local paths. `apphost.live` is
optional stronger evidence because normal PR and scheduled CI must not require a live local node or
operator form password.

`app-catalog.first-party-beta` reports whether `CRYPTAD_FIRST_PARTY_CATALOG_SOURCE` and the trusted
catalog key hints are configured in the certification environment, but it does not fetch a public
Crypta catalog during normal tests. It uses source checks, documentation checks, and deterministic
`platform-appcatalog` tests for `crypta:CHK@` artifact support.

`catalog.production-channels` is the Phase 9 production first-party catalog channel gate. It is
offline and deterministic: it checks catalog schema v3 parser/writer/descriptor support, stable
default channel policy, `channel_policy_blocked` handling, deprecated-entry replacement metadata,
API and Web Shell exposure, and redaction of private insert URIs, tokens, private keys, raw fetched
content, raw app data, catalog scratch paths, staged bundle paths, and absolute local paths. See
[production-first-party-catalog-channels.md](production-first-party-catalog-channels.md).

`app-catalog.first-party-maintenance-policy` is the Phase 10 first-party maintenance policy gate.
It is offline and deterministic: it checks the
`tools/release-certification/first-party-app-maintenance-policy.json` source, catalog v5
`maintenance.*` parser/writer/descriptor support, CLI descriptor flags, Platform API summaries,
Web Shell catalog cards, production beta release integration, and docs. See
[first-party-app-maintenance-policy.md](first-party-app-maintenance-policy.md).

`ecosystem-security-advisory-and-revocation` is the Phase 9 security response matrix row. The
`ecosystem.security-advisory-revocation` gate checks catalog v4 advisory records, exact
app-version denylists, warning acknowledgements, install/update/stage/apply/scheduler enforcement,
review receipt revocation, reviewer-key compromise, Web Shell warning rendering, safe uninstall
guidance, and redaction. See
[ecosystem-security-advisories.md](ecosystem-security-advisories.md).

`app-platform.user-consent-flow` verifies the unified consent layer for material install, update,
app-service grant, app-data migration, backup, channel/support, deprecation/replacement,
review/trust, security, and automatic-update decisions. It also checks digest-tied approvals,
stale approval rejection, redacted consent audit records, Web Shell rendering, docs, and tests. See
[user-consent-and-permission-upgrade-ux.md](user-consent-and-permission-upgrade-ux.md).

`catalog.live-usk-publication` and `catalog.live-usk-source-verification` are offline source
evidence by default. They prove live publication support, redaction behavior, same USK sibling
signature handling, and signed catalog verification for resolved USK editions. Optional live
publication smoke may be run only against a localhost node with secrets supplied through environment
variables or protected files; certification output must not include private insert URIs, form
passwords, tokens, raw request bodies, private keys, or absolute staging paths.

`app-platform.docs-portal`, `app-platform.beta-program`,
`app-platform.beta-tutorials`, and `app-platform.docs-redaction` are deterministic local docs
evidence. They check that the app platform developer portal, beta tutorials, known limitations,
beta program, required source docs, issue templates, README link, critical concept coverage,
relative Markdown links, and obvious secret/redaction rules are present without fetching external
URLs. Missing docs or redaction failures block release-candidate mode unless a release manager
records an explicit waiver for a docs-only gap; redaction failures should not be waived.

`platform-api.contract` is generated offline with `crypta-app api snapshot`. The companion
`platform-api.stable-baseline` evidence records the Platform API 1.0 baseline name, capability
count/list, endpoint count/list, stable endpoint required-capability sets, and stable endpoint
app-principal access flags. `platform-api.stable-breaking-change-check` is required evidence and
the ecosystem gate compares current stable capabilities, endpoint identities, endpoint
required-capability sets, and app-process/app-browser access flags against the previous production
release summary. In `--require-history` release-candidate runs, missing previous stable-baseline or
stable endpoint metadata is a blocker. Stable baseline removals, stability demotions,
required-permission breaks, app-principal access regressions, snapshot generation failure, contract
parse failure, missing contract evidence, or strict compatibility verifier failure are blockers
unless a release-manager waiver is recorded. Developer dry runs without previous history warn
instead of claiming production comparison coverage.

`app-vault.capabilities` is deterministic offline evidence. The app-platform smoke runner checks
that [app-secret-and-identity-vault.md](app-secret-and-identity-vault.md) documents the six vault
capabilities, app-owned versus shared identities, process/browser restrictions, at-rest local
limitations, update/rollback/uninstall/reinstall grant behavior, audit/redaction, browser-safe
app-owned identity creation, the profile-document route, the bounded social-message route, and the
content/social/mail extension point. The runner also checks that devtools recognizes the same
capability names and that
certification redaction keeps capability names while removing vault secret values, identity private
material, seed phrases, recovery phrases, signatures, raw request bodies, private insert URIs, and
absolute staging paths.

App-review evidence is separate from signed catalog and signed bundle evidence. In
release-candidate mode, the app-platform smoke runner requires reviewer inputs for first-party
catalog review receipt evidence:

```text
CRYPTAD_APP_REVIEWER_KEY_ID
CRYPTAD_APP_REVIEWER_PRIVATE_KEY_BASE64
CRYPTAD_APP_REVIEWER_PRIVATE_KEY_FILE
CRYPTAD_APP_REVIEWER_PUBLIC_KEY_BASE64
CRYPTAD_APP_REVIEWER_PUBLIC_KEY_FILE
CRYPTAD_APP_REVIEW_POLICY_ID
CRYPTAD_APP_REVIEW_POLICY_VERSION
```

`CRYPTAD_APP_REVIEW_POLICY_ID` defaults to `crypta-app-review-v1` and
`CRYPTAD_APP_REVIEW_POLICY_VERSION` defaults to `1`. The runner uses `crypta-app review sign`,
`crypta-app review verify`, and `crypta-app catalog create --review-receipt` to prove that
review receipt evidence can be created and consumed offline for every staged first-party app. The
release report summarizes the configured review policy, whether first-party receipt evidence blocks
promotion, the first-party catalog apps inspected, and the receipt
coverage categories: trusted positive, missing, expired, mismatched, unknown reviewer, and trusted
rejected. Reports may include reviewer key ids, reviewer display names, policy ids, and key
fingerprints; they must not include private reviewer keys, raw public key bytes, local evidence
paths, app/session/process tokens, or local staging paths.

Review governance evidence extends that receipt check with reviewer-key lifecycle readiness and the
local transparency log. Registry v1 remains valid, but release candidates should prefer v2
registries with explicit `active`, `retired`, or `revoked` status, optional validity windows, and
policy-version constraints. The transparency log is local and tamper-evident, not a public global
log. In release-candidate mode, missing governance, reviewer-key lifecycle, transparency-log,
review-history API, or first-party review-chain evidence is blocking unless a waiver is recorded in
the release summary. Reports may include lifecycle counts, status names, policy ids/versions,
record counts, and latest hashes; they must not include raw public key bytes, private keys, raw
receipt signatures, local transparency-log paths, local evidence paths, browser sessions, AppHost
process tokens, form passwords, request bodies, or catalog scratch paths.

App UI design evidence is offline. Release-candidate mode treats first-party strict UI lint errors
as blocking evidence because first-party apps ship with the node. Advisory
third-party-style warnings are recorded by `crypta-app ui lint` but are not turned into a global
release blocker by default. The app-platform smoke report must keep UI lint output sanitized:
relative bundle paths and finding ids are acceptable, while tokens, form passwords, query strings,
private file paths, and local file contents are not.

Profile Publisher supplies the identity-profile publishing reference path. Release evidence must
prove `reference-app.profile-publisher`, `reference-app.profile-publisher-app-data`,
`app-platform.identity-profile-publish`, and `app-platform.generated-document-insert` before a
release claims identity-profile support. Site
Publisher remains the content-reference app and should not claim `vault.identities.*` coverage.
Feed Reader supplies the content-subscription reference path. Release evidence must prove
`reference-app.feed-reader`, `reference-app.feed-reader-subscriptions`,
`reference-app.feed-reader-app-data`, `app-platform.content-fetch`,
`app-platform.content-subscriptions`, `network-content.subscription-scheduler`, and
`app-platform.durable-app-data-store` before a release claims feed-reader subscription support.
Feed evidence must not include raw feed bodies, raw fetched content, raw request bodies, private
insert URIs, app process tokens, browser-session tokens, form passwords, private keys, absolute
staging paths, store root paths, queue HTML, or local paths.
Social Inbox RC supplies the threaded social inbox reference path. Release evidence must prove
`app-platform.social-message-signing`, `reference-app.social-inbox`,
`reference-app.social-inbox-signed-message`, `reference-app.social-inbox-subscriptions`,
`reference-app.social-inbox-app-data`, `reference-app.social-inbox-trust-annotations`,
`reference-app.social-inbox-service-grant`, `reference-app.social-inbox-rc-threading`,
`app-platform.trust-social-beta-hardening`,
`app-services.registry`, `app-services.grants`, `app-services.dependency-graph`,
`app-services.grant-bundles`, `app-services.grant-expiry-renewal`,
`app-services.provider-revalidation`, `app-services.trust-score-provider`,
`reference-app.social-inbox-service-dependency`, `app-services.web-shell`,
`app-services.redaction`, `app-services.dependency-redaction`, and `migration.social-mail-preview`
before a release claims Social Inbox RC support.
`legacy-plugin.freeze-policy`, `legacy-plugin.migration-guide`, and
`legacy-plugin.social-inbox-spike` certify the broader legacy plugin freeze boundary,
plugin-to-app migration guidance, and the executable Social Inbox app-platform replacement path.
Social Inbox evidence must not include raw social message bodies, raw fetched social documents,
raw profile documents, raw request bodies, raw signature values, private insert URIs, private
identity material, app process tokens, browser-session tokens, form passwords, private keys,
absolute staging paths, or local paths.
Trust Graph Local RC supplies the local trust-service reference path. Release evidence must prove
`reference-app.trust-graph`, `reference-app.trust-graph-durable-exchange`,
`reference-app.trust-graph-app-data-preview`, `app-platform.trust-graph-preview`,
`app-platform.trust-graph-rc-scope-and-safety`, `app-platform.trust-graph-durable-store`,
`app-platform.trust-social-beta-hardening`,
`app-platform.trust-graph-exchange`, `app-platform.trust-statement-signing`,
`app-services.registry`, `app-services.grants`, `app-services.dependency-graph`,
`app-services.grant-bundles`, `app-services.grant-expiry-renewal`,
`app-services.provider-revalidation`, `app-services.trust-score-provider`,
`app-services.web-shell`, `app-services.redaction`, and `app-services.dependency-redaction` before a
release claims Trust Graph Local RC support. The evidence must prove local anchors, imported public
signed statements, local lifecycle states, bounded score explanations, redacted source metadata,
and read-only app-service score boundaries. It must also prove the non-goals: no crawling, no
global moderation or blocking, no
routing decisions, no node-to-node trust propagation, and no legacy WebOfTrust, Freetalk, Sone, or
Freemail compatibility claim. Trust and app-service evidence must not include raw trust statement
bodies from real users, raw fetched content, raw request bodies, raw signature values, private
insert URIs, private identity material, app process tokens, browser-session tokens, form passwords,
absolute staging paths, store roots, provider app data, raw subject URIs, app-data backup payloads,
or local paths. Final ecosystem RC certification is covered by
[ecosystem-rc-certification-gate.md](ecosystem-rc-certification-gate.md) through the
`ecosystem.rc-certification` gate and the `ecosystem-rc-certification-gate` matrix row. Trust
Graph evidence contributes to that final gate without expanding the Trust Graph non-goals above.

## Historical comparison

Historical comparison combines the current evidence list with a previous certified
`release-certification-summary.json`. The output contract is stable and path-free:

```text
historyComparison.status
historyComparison.previous.generatedAt
historyComparison.previous.gitSha
historyComparison.previous.releaseVersion
historyComparison.current.generatedAt
historyComparison.evidenceDiffs[]
historyComparison.ecosystemGates[]
ecosystemMatrix
```

Each evidence diff records the evidence id, previous status, current status, classification
(`regression`, `improvement`, `unchanged`, `new`, or `removed`), release-blocker flag, and reason.
Required evidence that changes from `pass` to `fail`, `missing`, or `skip` is a
release-candidate blocker unless a waiver applies. Required evidence that changes from `pass` to
`warn` remains visible as a warning. New required evidence is not automatically waived; its current
status determines whether it passes, warns, or blocks. Removed optional evidence is a warning;
removed required evidence is a blocker.

Local history storage is optional and does not make network calls:

```bash
tools/release-certification/run-release-certification.sh \
  --mode release-candidate \
  --previous-summary build/release-certification-history/latest-summary.json \
  --write-history \
  --history-label 2026.05.0
```

`--write-history` writes sanitized summaries under `build/release-certification-history/`,
including `latest-summary.json`, `latest-history-comparison.json`, and
`releases/<history-label>/`. Only non-failing, promotable runs update those latest and release
baselines; failed or non-promotable attempts are preserved under `failed/<history-label>/`. These
generated files are release-manager artifacts; do not commit them by default. If CI cannot
download a prior artifact safely, restore it manually before running the workflow and pass the
manual `previous-summary-path` input. The manual workflow also exposes `require-history`,
`write-history`, `history-label`, and `waiver-file-path` inputs; it does not attempt brittle
cross-run artifact downloads.

## Ecosystem gates

The certification summary embeds deterministic ecosystem gates so release managers can review
app-platform regressions without reading every evidence detail. The current gate ids are:

```text
ecosystem.required-evidence-regressions
ecosystem.platform-api-compatibility
ecosystem.first-party-apps
ecosystem.app-ui-quality
ecosystem.app-review-trust
ecosystem.app-update-rollback
ecosystem.operator-rc-recovery
ecosystem.security-advisory-revocation
ecosystem.app-vault
ecosystem.sandbox-provider
ecosystem.reference-content-apps
ecosystem.legacy-retirement
ecosystem.live-network-beta
ecosystem.rc-certification
```

## Ecosystem certification matrix

The aggregator writes `ecosystem-certification-matrix.json` and
`ecosystem-certification-matrix.md` beside the summary and report. The matrix is the primary
release-candidate checklist for the networked app layer. It does not replace the detailed evidence
or ecosystem gates; it summarizes them into deterministic rows that answer:

| Field | Meaning |
| --- | --- |
| `category` and `title` | The ecosystem area being certified, such as app updates, review governance, Platform API compatibility, first-party apps, reference apps, or legacy retirement. |
| `requiredEvidenceIds` and `optionalEvidenceIds` | The evidence ids that prove the row. Missing, skipped, or failing required evidence is a release-candidate blocker. Optional evidence that is missing, skipped, failing, or warning is visible as a row warning. |
| `gateIds` and `gateStatus` | The ecosystem gates that cover the row. A release-blocking referenced gate makes the row a blocker unless an active release-candidate waiver applies. |
| `status` | Row result: `pass`, `warn`, `fail`, `missing`, or `skip`. |
| `previousStatus` and `regressionStatus` | Previous row status when the previous summary contains matrix metadata, plus `unchanged`, `improved`, `regressed-warning`, `regressed-blocker`, `new-row`, `previous-missing`, or `not-comparable`. |
| `releaseBlocker` | Whether this row blocks release-candidate promotion. Waived blockers become `warn` and keep the waiver id visible. |
| `waiverIds` | Active waiver ids that match the row id, a referenced evidence id, a referenced gate id, or a row issue id. |
| `docs` | Existing release-manager documentation that explains the row's domain. |
| `recommendation` | The next stable release-manager action. |

The matrix validates its own coverage on every run. `requiredEvidenceCovered` requires every
current `requiredForReleaseCandidate` evidence id to appear in at least one row. `ecosystemGatesCovered`
requires every emitted `ecosystem.*` gate to appear in at least one row, including
`ecosystem.waivers` when waiver-file validation emits it. `firstPartyAppsCovered` requires visible
coverage for `queue-manager`, `publisher`, `site-publisher`, `profile-publisher`, `feed-reader`,
and `trust-graph`. `docsCovered` requires every non-synthetic row to name at least one existing
docs path. `redactionPassed` requires the matrix to stay within the same sanitized, path-free
release evidence contract as the summary and report.

The first-party app coverage is intentionally split. `queue-manager`, `publisher`, and the shared
bundle set are grouped under the first-party app bundle row. `site-publisher` is covered by the
reference content row. `profile-publisher`, `feed-reader`, and `trust-graph` each have their own
rows because they validate distinct identity publishing, content fetch, and Trust Graph Local RC
behavior. The `app-platform-beta-docs-and-program` row records Phase 7 docs portal, tutorials,
beta program, issue-template, link, and redaction readiness.

The `network-scale-soak-and-subscription-budget` row records PR-256 evidence. It requires
`network-scale.app-network-budget`, `network-scale.content-fetch-budget`,
`network-scale.subscription-budget`, `network-scale.queue-pressure-backoff`,
`network-scale.trust-graph-import-budget`, `network-scale.social-inbox-multi-source-soak`,
`network-scale.redaction`, and `network-scale.rc-soak-summary`. These evidence items prove that
foreground content fetch, subscription polling/manual refresh, and Trust Graph import-by-URI share
bounded budgets, queue pressure can delay polling without budget consumption, Social Inbox
multi-source refresh remains capped, and release evidence excludes raw content, queue HTML, tokens,
private insert URIs, raw signatures, app-data payloads, and absolute local paths.

The `ecosystem-rc-certification-gate` row records PR-258 final ecosystem release-candidate
certification. It is the release-manager summary row for the `ecosystem.rc-certification` gate and
is documented in [ecosystem-rc-certification-gate.md](ecosystem-rc-certification-gate.md). The row
must remain sensitive to required-evidence failures, ecosystem-gate failures, matrix coverage gaps,
network-scale RC soak status, live-network beta status when required, redaction failures, and
waiver visibility. Passing the row means the release evidence is complete enough for promotion; it
does not claim global network propagation, deletion of published bytes, legacy WebOfTrust or
plugin compatibility, production-key handling, or third-party app safety beyond the recorded gates.

## Network-scale soak

Normal PR and CI evidence uses deterministic simulated time, not a wall-clock 24-hour test:

```bash
tools/release-certification/run-release-certification.sh \
  --mode release-candidate \
  --out-dir build/release-certification
```

The wrapper writes a fresh `build/release-certification/network-scale-soak/summary.json` with
`network_scale_soak.py` and forwards that exact path to `release_certification.py`. When a release
candidate has externally collected live RC soak evidence, pass
`--network-scale-soak-summary <path>` to the wrapper or set
`CRYPTAD_CERT_NETWORK_SCALE_SOAK_SUMMARY`; the attached file is then used instead of generating the
deterministic simulated summary.

The summary may be `simulated-rc-soak` or `live-rc-soak`, but it must use the same redacted schema:
bounded app counts, budget skips, queue-pressure skips, update counts, Trust Graph import counts,
budget enforcement booleans, and redaction booleans. It must not include raw fetched content, raw
request bodies, queue HTML, browser-session tokens, app process tokens, private insert URIs, raw
signatures, raw Trust Graph statement bodies, app-data values, app-data backup payloads, rejected
source strings, or absolute local paths.

A literal 24-hour live soak is optional release-candidate evidence. It is represented by an
attached redacted summary; it is not part of ordinary unit tests, nightly certification, or
Python-only self-tests. Record the external soak source, collector mode, runner identity, and
redaction status in the release log without copying raw node output into the release record.

In `release-candidate` mode, unmapped required evidence, unmapped ecosystem gates, missing docs,
or failed redaction make the matrix fail. In `pr` and `nightly` mode, coverage gaps warn unless
redaction fails. The summary embeds only compact matrix metadata under `ecosystemMatrix`, plus
`ecosystemMatrixStatus`, `ecosystemMatrixPath`, and `ecosystemMatrixReportPath`; the full row list
belongs in `ecosystem-certification-matrix.json`.

Previous summaries produced before PR-231 do not contain matrix metadata. When such a summary is
used as `--previous-summary`, `previousMatrixPresent=false` and row regressions are marked
`previous-missing`. That warning does not fail the first PR-231 release candidate by itself; record
the baseline transition in the release log. Once a previous summary contains `ecosystemMatrix`,
row-level regressions are compared directly.

## Ecosystem gate behavior

The gates are intentionally conservative. Final ecosystem RC certification blocks on any unwaived
required-evidence failure, release-blocking ecosystem gate, matrix coverage gap, stale or missing
network-scale RC soak evidence, required live-network beta failure, or redaction failure. Platform
API compatibility blocks on contract status failure, contract version rollback, or available stable
endpoint/capability removals. First-party
app gates require `queue-manager`, `publisher`, `site-publisher`, `profile-publisher`,
`feed-reader`, and `trust-graph`, and
block when a previously certified first-party app disappears without a waiver. App UI gates block failing or missing
first-party strict lint/design-system evidence and warn when lint warning counts increase. Review
trust gates block trusted receipt, review-policy, or first-party review catalog regressions. Update
rollback gates block lifecycle, scheduler, or rollback evidence regressions and warn if rollback
scope cannot be proven as installed-bundle-only. Vault gates block missing capability/redaction
evidence or missing profile-document route evidence.
Sandbox gates warn when enforced evidence regresses to best-effort, and block in
`release-candidate` mode when enforced evidence is required but absent. Reference-content gates
block if Site Publisher evidence disappears, Profile Publisher evidence disappears, Feed Reader
evidence disappears, Trust Graph Local RC evidence disappears, generated document insert evidence
disappears, content-fetch evidence disappears, trust-statement signing evidence disappears, or a
reference app no longer proves its required helper usage. Legacy
retirement gates block missing removal-wave evidence, including
`legacy-admin.removal-wave-2`, `legacy-admin.removal-wave-3`, and
`legacy-admin.removal-wave-4`, `legacy-admin.removal-wave-5`,
`legacy-admin.final-admin-surface`, `legacy-admin.browse-retained`, and
`legacy-admin.emergency-fallback-retained`, or failed retained browse safety evidence and warn on
removed-route count changes without update-note metadata.

## Waivers

Use waivers sparingly and only with a concrete release-manager reason:

```bash
tools/release-certification/run-release-certification.sh \
  --mode release-candidate \
  --waive interop.extended="No FCP, peer, datastore, restart, USK/SSK, packaging, or startup compatibility behavior changed."
```

A waiver turns that evidence item into `warn`, records `details.waived=true`, and includes the
reason in `details.waiverReason`.  Waivers are visible in both the report and the JSON summary.
For schema-version 1 summaries, the top-level `waivers` field remains the CLI waiver map; full
CLI and structured waiver records are emitted under `waiverRecords`.

Do not use waivers to hide failed required smoke evidence.  Fix the failing gate or record a
release-manager decision that explicitly accepts the risk.

Structured waiver files are also supported:

```bash
tools/release-certification/run-release-certification.sh \
  --mode release-candidate \
  --waiver-file docs/release-waivers/2026.05.0.json
```

```json
{
  "version": 1,
  "release": "2026.05.0",
  "waivers": [
    {
      "id": "ecosystem.sandbox-provider.best-effort-only",
      "evidenceId": "ecosystem.sandbox-provider",
      "status": "approved",
      "approvedBy": "release-manager",
      "reason": "Bubblewrap evidence is not required for this developer preview release.",
      "expiresAt": "2026-06-30T00:00:00Z",
      "allowReleaseCandidate": true
    }
  ]
}
```

Structured waivers are merged with CLI `--waive` records and remain visible in the report,
summary, and history comparison. Active waivers downgrade matching evidence or ecosystem gate
blockers to `warn`; they do not erase the gate. Expired or malformed waivers do not apply.
Malformed waiver files fail `release-candidate` mode and warn in `pr` or `nightly` mode.

## Optional live-node evidence

Live AppHost evidence is opt-in:

```bash
CRYPTAD_CERT_APP_SMOKE_LIVE=1 \
CRYPTAD_CERT_NODE_BASE_URL=http://127.0.0.1:<port> \
CRYPTAD_CERT_FORM_PASSWORD=<redacted> \
tools/release-certification/run-release-certification.sh --mode nightly
```

When enabled, the app-platform smoke runner uses the generated sample app and localhost Platform
API routes to install, read runtime status, start, stop, update, uninstall, and read diagnostics.
The live smoke only records localhost metadata, status codes, and redacted JSON response summaries.
It does not write the form password, raw request bodies, app process tokens, or browser-session
tokens.

The wrapper can also receive `--live`, but it deliberately rejects `--form-password`. Supply the
form password through `CRYPTAD_CERT_FORM_PASSWORD` only. If the smoke fails after installing the
sample app, the runner attempts `POST /apps/cert-smoke/stop` and `DELETE /apps/cert-smoke`; verify
cleanup manually before reusing the node.

## Live-network beta certification

Live-network beta certification is required before a release claims first-party beta catalog
readiness on the public network. It is an explicit release-manager mode in the certification
wrapper, separate from optional AppHost lifecycle smoke and disabled for normal PR/nightly runs.

```bash
CRYPTAD_CERT_LIVE_NETWORK_BETA=1 \
CRYPTAD_CERT_REQUIRE_LIVE_NETWORK_BETA=1 \
CRYPTAD_CERT_NODE_BASE_URL=http://127.0.0.1:8888 \
CRYPTAD_CERT_FORM_PASSWORD=<redacted> \
CRYPTAD_CERT_LIVE_CATALOG_SOURCE=crypta:USK@<catalog-key>/cryptad-app-catalog.properties \
CRYPTAD_CERT_LIVE_CATALOG_EXPECTED_KEY_ID=crypta-first-party-beta \
CRYPTAD_CERT_LIVE_CONTENT_FETCH_URI=crypta:CHK@<artifact-key> \
CRYPTAD_CERT_LIVE_FEED_USK_URI=crypta:USK@<feed-key>/feed.json \
CRYPTAD_CERT_LIVE_TEST_INSERT_URI_FILE=<protected-insert-uri-file> \
tools/release-certification/run-release-certification.sh \
  --mode release-candidate \
  --live-network-beta \
  --require-live-network-beta \
  --node-base-url http://127.0.0.1:8888
```

Use disposable fixture catalog keys for certification rehearsals. Public fixture references may be
recorded as `crypta:USK@<catalog-key>/cryptad-app-catalog.properties` and
`crypta:CHK@<artifact-key>`. The matching private insert URI is a bare private USK directory insert
URI for the same public source parent; load it through `CRYPTAD_CERT_LIVE_TEST_INSERT_URI_ENV` or
`CRYPTAD_CERT_LIVE_TEST_INSERT_URI_FILE`, never as a command-line value or inline shell
assignment. Use `CRYPTAD_CERT_LIVE_TEST_INSERT_URI_ENV` only when the private URI has already been
exported through a protected channel and the command names that variable without showing its value.
If both indirections are present, the environment-name source wins deterministically. The report
records only fixture presence, not the value, hash, length, environment variable name, or file path.
`CRYPTAD_CERT_LIVE_CATALOG_EXPECTED_KEY_ID` is mandatory when live-network beta certification is
required. The smoke compares it with the node-observed public `signatureKeyId` from the verified
catalog summary; unset, unavailable, or mismatched signing-key metadata fails the catalog evidence.
Set `CRYPTAD_CERT_LIVE_PROFILE_PUBLIC_URI` and `CRYPTAD_CERT_LIVE_TRUST_PUBLIC_URI` when the run
should fetch back the synthetic profile and trust statement after publish. Timing knobs are
`CRYPTAD_CERT_LIVE_TIMEOUT_SECONDS`, `CRYPTAD_CERT_LIVE_POLL_INTERVAL_SECONDS`,
`CRYPTAD_CERT_LIVE_MAX_POLL_ATTEMPTS`, `CRYPTAD_CERT_LIVE_MAX_DURATION_SECONDS`, and
`CRYPTAD_CERT_LIVE_MAX_STEP_DURATION_SECONDS`.

App-facing live workflow calls use app principals, not host/operator form-password authority. The
runner fetches each app's static bootstrap from
`/apps/{appId}/.well-known/cryptad-bootstrap.json`, keeps the returned `browserSessionToken` in
memory, sends it as `X-Crypta-App-Session`, and excludes the token value and response body from
all artifacts. Required mode fails when a configured app cannot mint a browser session. Defaults
are `site-publisher` for lifecycle, `feed-reader` for content and feed subscriptions,
`profile-publisher` for profile publish, `trust-graph` for trust publish/import, and
`social-inbox` for optional app-service scoring. Release managers can override those ids with
`CRYPTAD_CERT_LIVE_APP_ID`, `CRYPTAD_CERT_LIVE_CONTENT_APP_ID`,
`CRYPTAD_CERT_LIVE_FEED_APP_ID`, `CRYPTAD_CERT_LIVE_PROFILE_APP_ID`,
`CRYPTAD_CERT_LIVE_TRUST_APP_ID`, and `CRYPTAD_CERT_LIVE_APP_SERVICE_CALLER_APP_ID`.

The runner proves localhost preflight, live catalog fetch/verification, app
install/update/rollback, bounded content fetch, feed subscription metadata, synthetic profile
publish, synthetic trust statement publish/import, interop/performance timing, and redaction guard
results. It can also invoke the read-only Trust Graph `trust.score` app-service when
`CRYPTAD_CERT_LIVE_APP_SERVICE_SCORE=1` is set; otherwise
`live-network-beta.app-service-score` is optional skipped evidence, not a pass claim. It does not
prove global propagation, user adoption, app safety beyond the signed catalog/bundle/review gates,
or deletion of published bytes. Preserve only the sanitized summary, report, and ecosystem matrix.
Lifecycle cleanup deletes only an app that was absent before the smoke and installed successfully
by this run; use disposable app ids for rehearsals on nodes that already have first-party apps
installed.
Assume live synthetic content may not be deletable once published. Do not use real keys, production
secrets, or user content in fixture certification runs.

The aggregator records the live evidence under `ecosystem.live-network-beta` and the
`live-network-beta-certification` matrix row. Required mode expects
`live-network-beta.preflight`, `live-network-beta.catalog-usk-fetch`,
`live-network-beta.app-install-update-rollback`, `live-network-beta.content-fetch`,
`live-network-beta.feed-subscription`, `live-network-beta.profile-publish`,
`live-network-beta.trust-statement-publish-import`,
`live-network-beta.interop-perf-budget`, and `live-network-beta.redaction` to pass.
When live-network beta is disabled, stale `live-network-beta-smoke/` summaries must be ignored and
must not be copied into the release record. When live-network beta is enabled but not required,
failing, missing, or warning live evidence is visible as a warning. It becomes release-blocking
only when `--require-live-network-beta` or `CRYPTAD_CERT_REQUIRE_LIVE_NETWORK_BETA=1` is set.

## Redaction

The report, matrix, and copied artifacts must not contain:

- private signing keys;
- private reviewer keys;
- raw trusted reviewer public key bytes;
- app process tokens;
- app browser session tokens;
- the host/operator form password;
- raw request bodies;
- raw feed bodies;
- raw social message bodies or fetched social documents;
- raw trust statement documents or trust-document bodies from real users;
- raw app-vault secret values, identity private keys, identity seeds, or recovery phrases;
- raw profile-document signatures or signed profile-document payloads;
- raw social-message signatures or signed social-message payloads;
- raw update or rollback command output;
- full query strings that may contain secrets;
- private insert URIs;
- absolute developer-specific filesystem paths, including absolute staging paths;
- catalog scratch paths, staged bundle paths, installed bundle paths, data/cache/run paths, and
  rollback backup paths;
- non-localhost remote addresses.

`artifacts/private-insert-uris.json` from interop runs must never be uploaded or pasted into a
public release record.  The certification aggregator filters that private artifact reference and
copies only sanitized summaries and public reports into `build/release-certification/artifacts/`.
