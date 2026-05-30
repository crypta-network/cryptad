# Release certification

Release certification is the reproducible evidence bundle for a Cryptad release candidate.  It
aggregates compatibility, performance, app-platform, catalog, app-owned UI, legacy-admin
retirement, and CI metadata into one redacted report.

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
```

The Markdown report and ecosystem matrix are intended for human release review. The JSON summary
is the stable machine-readable companion for later automation and report comparison.

## Modes

| Mode | Purpose | Behavior |
| --- | --- | --- |
| `pr` | Quick local or normal PR evidence. | Runs Python-only certification and lightweight app-platform checks.  It does not require a live node, signing keys, Hyphanet baseline download, or packaged-node smoke. |
| `nightly` | Scheduled/manual evidence aggregation. | Records missing optional evidence as warnings and can run heavier app-platform checks. |
| `release-candidate` | Strict release gate. | Fails when required evidence is missing, skipped, or failing unless a release-manager waiver is recorded. |

## Run locally

The release-certification tools require Python 3.10 or newer and use only the Python standard
library.

Run self-tests first:

```bash
python3 tools/release-certification/app_platform_docs_check.py --self-test
python3 tools/release-certification/release_certification.py --self-test
python3 tools/release-certification/app_platform_smoke.py --self-test
```

Generate a lightweight local report:

```bash
tools/release-certification/run-release-certification.sh
```

The wrapper may be invoked from outside the repository. Relative `--out-dir` values are resolved
under the repository root so shell cleanup, app-platform smoke output, and aggregation read the same
evidence directory.

Generate a release-candidate report:

```bash
tools/release-certification/run-release-certification.sh \
  --mode release-candidate \
  --out-dir build/release-certification
```

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
| `app-platform.first-party` | App-platform smoke summary. | The first-party staged apps, including Queue Manager, Publisher, Site Publisher, Profile Publisher, Social Inbox Preview, Feed Reader, and Trust Graph Preview, have valid manifests, launchers, static UI assets, and SDK wiring. |
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
| `app-review.governance` | App-platform smoke summary. | Reviewer-key lifecycle statuses, policy-version constraints, governance API routes, and Web Shell governance rendering are present and redacted. |
| `app-review.reviewer-key-lifecycle` | App-platform smoke summary. | Trusted reviewer registry v2 parsing, active/retired/revoked semantics, duplicate-id fail-closed behavior, strict instants, and lifecycle verifier tests are present. |
| `app-review.transparency-log` | App-platform smoke summary. | A local hash-chained review transparency log exists, can be verified, deduplicates receipt observation, and has tamper/redaction tests. |
| `app-review.review-history-api` | App-platform smoke summary. | Review governance, reviewer-key, transparency-log, verification, and catalog-app review-history Platform API routes are present and Web Shell consumes review-history data. |
| `app-review.first-party-review-chain` | App-platform smoke summary. | First-party review receipt evidence, review-history/governance readiness, and transparency-log evidence are tied together for release promotion. |
| `platform-api.contract` | App-platform smoke summary. | The deterministic Platform API compatibility contract snapshot was generated, parsed, and used for offline compatibility verification of first-party/sample apps. |
| `app-vault.capabilities` | App-platform smoke summary. | App secret and identity vault capability docs, devtools vocabulary, grant lifecycle notes, and redaction checks are present. |
| `app-platform.identity-profile-publish` | App-platform smoke summary. | The profile-document signing route `POST /api/v1/app-vault/identities/{identityId}/profile-document` is present, documented, capability-gated by `vault.identities.read` plus `vault.identities.use`, and covered by redaction evidence. |
| `app-platform.generated-document-insert` | App-platform smoke summary. | The app-generated document insert route `POST /api/v1/queue/inserts/app-document` is present, documented, capability-gated by `content.insert.app-document` plus `queue.write`, and avoids local file-path request authority. |
| `app-platform.content-fetch` | App-platform smoke summary. | The content fetch route `POST /api/v1/content/fetch` is present, documented, capability-gated by `content.fetch`, and covered by feed-body/request-body/token/path redaction evidence. |
| `app-platform.content-subscriptions` | App-platform smoke summary. | The content subscription routes under `/api/v1/content/subscriptions` are present, documented, app-principal scoped, capability-gated by `content.subscribe` plus `content.fetch` for create/refresh, and covered by raw-content/token/path/queue HTML redaction evidence. |
| `network-content.subscription-scheduler` | App-platform smoke summary. | Offline source and test evidence proves deterministic content-subscription `tick(Instant)`, no-overlap execution, per-app/global/per-tick limits, failure backoff, dedupe, queue pressure handling without parsing queue HTML, and path-free durable metadata. |
| `app-platform.durable-app-data-store` | App-platform smoke summary. | The `/api/v1/app-data` route family, `app.data.read`, and `app.data.write` are present in the current contract, file-backed records use path-safe atomic storage, quotas/import/export/schema metadata are bounded, and evidence excludes raw app values, request bodies, tokens, private insert URIs, and local paths. |
| `app-platform.trust-graph-preview` | App-platform smoke summary. | The v7 trust graph routes are present, documented, capability-gated by `trust.read` and `trust.write`, SDK trust helpers exist, and evidence is redacted. |
| `app-platform.trust-graph-durable-store` | App-platform smoke summary. | The file-backed trust graph store is present, runtime wiring injects it into Platform API, anchors/statements/audit entries are bounded and redacted, and evidence excludes raw trust bodies, raw fetched content, private insert URIs, tokens, signatures, and local paths. |
| `app-platform.trust-graph-exchange` | App-platform smoke summary. | Contract v10 exposes trust URI import and audit descriptors, SDK exchange helpers cover URI import, publish, and subscription wrappers, and exchange evidence uses only route names, capability names, booleans, counts, and redacted identifiers. |
| `app-platform.trust-statement-signing` | App-platform smoke summary. | The bounded AppVault route `POST /api/v1/app-vault/identities/{identityId}/trust-statement` is present, documented, requires `trust.write`, `vault.identities.read`, and `vault.identities.use`, and does not expose private material in evidence. |
| `app-platform.social-message-signing` | App-platform smoke summary. | Contract v11 exposes the bounded AppVault route `POST /api/v1/app-vault/identities/{identityId}/social-message`, fixes the signing domain to `crypta.social.message.v1`, requires `vault.identities.read` and `vault.identities.use`, and does not expose generic browser signing or private material in evidence. |
| `app-services.registry` | App-platform smoke summary. | Contract v12 exposes `/api/v1/app-services`, `app.services.read`, and `app.services.call`, parses signed manifest service descriptors and requests, wires a shared coordinator, and includes SDK service helpers. |
| `app-services.grants` | App-platform smoke summary. | The app-service grant model, statuses, in-memory/file-backed stores, host-only approval, revocation, active-grant invocation check, and deterministic tests are present. |
| `app-services.trust-score-provider` | App-platform smoke summary. | Trust Graph Preview advertises `trust.score` through a `trust-graph.score` platform adapter that returns a redacted score summary and is not a localhost proxy. |
| `reference-app.social-inbox-service-grant` | App-platform smoke summary. | Social Inbox declares a `trust.score` request, uses `app.services.read` and `app.services.call`, invokes through `CryptaPlatform.services.invoke`, and shows neutral missing/pending/revoked grant states. |
| `app-services.web-shell` | App-platform smoke summary. | Web Shell lists advertised services, service requests, grants, and redacted audit events, and lets the operator approve pending grants or revoke active grants. |
| `app-services.redaction` | App-platform smoke summary. | App-service evidence excludes raw tokens, raw subject URIs, raw request bodies, private insert URIs, local paths, provider app data, and generic proxy behavior. |
| `app-ui.design-system` | App-platform smoke summary. | Canonical app UI design-system assets exist and first-party staged bundles contain matching local copies. |
| `app-update.live-catalog-refresh` | App-platform smoke summary. | App-update scheduler evidence shows configured signed catalog refresh, including live USK catalog refresh, before candidate discovery while keeping manual update policy as the default. |
| `app-ui.lint` | App-platform smoke summary. | `crypta-app ui lint --strict --json` passed for first-party staged static UI bundles and produced sanitized path-free summaries. |
| `app-ui.first-party-adoption` | App-platform smoke summary. | First-party source/staged UIs load design-system CSS in order, use stable `cr-*` classes, and show permission disclosure for declared permissions across the repo-owned static apps. |
| `app-ui.smoke` | App-platform smoke summary. | First-party static UI and `crypta-platform.js` remain coherent and do not expose process-token names. |
| `reference-apps.content` | App-platform smoke summary. | Site Publisher exists as the first content reference app, declares content publishing permissions, uses the browser SDK content/queue helpers, and avoids vault identity permissions. |
| `reference-app.profile-publisher` | App-platform smoke summary. | Profile Publisher exists as the first identity-profile reference app, declares the expected vault/content/queue permissions, uses the profile-document and app-document insert routes, and keeps release evidence free of signatures and private material. |
| `reference-app.profile-publisher-app-data` | App-platform smoke summary. | Profile Publisher requires at least contract v9, is tested through v12, declares `app.data.*`, uses SDK JSON record helpers for bounded profile draft, selected identity, last published URI, and recent publish summaries, and keeps identity private material in AppVault rather than app data. |
| `reference-app.social-inbox` | App-platform smoke summary. | Social Inbox Preview exists as the first social/mail migration reference app, declares vault/content/subscription/queue/app-data/app-service permissions, uses SDK and design-system assets, and documents that it is not full WoT, Freetalk/Sone/Freemail compatibility, encrypted mail, or a daemon-core message protocol. |
| `reference-app.social-inbox-signed-message` | App-platform smoke summary. | Social Inbox signs bounded `crypta.social.message.v1` documents through AppVault without exposing arbitrary browser signing, private identity material, raw request bodies, or raw signatures in evidence. |
| `reference-app.social-inbox-subscriptions` | App-platform smoke summary. | Social Inbox follows bounded USK social outbox sources with durable content subscriptions, displays subscription metadata, fetches bounded JSON, and excludes raw fetched content from evidence. |
| `reference-app.social-inbox-app-data` | App-platform smoke summary. | Social Inbox uses app data for sources, outbox summaries, imported-message summaries, read state, and explicit drafts while excluding private insert URIs, browser-session tokens, private identity material, raw fetched documents, and raw signatures. |
| `reference-app.social-inbox-trust-annotations` | App-platform smoke summary. | Social Inbox queries Trust Graph Preview's `trust.score` service through an active app-service grant with `subjectKind=identity` and `context=message-author`, renders scores as annotations, and keeps unscored or ungranted messages visible. |
| `migration.social-mail-preview` | App-platform smoke summary. | The migration spike evidence proves the social/mail-like layer composes AppVault, content insert/fetch/subscriptions, durable app data, and the mediated Trust Graph score service outside daemon core and legacy plugin APIs. |
| `legacy-plugin.migration-guide` | App-platform smoke summary. | The legacy plugin migration guide exists, is linked from plugin-system and app-platform docs, documents old plugin runtime removal, and maps legacy plugin categories to app-platform mechanisms without restoring old plugin ABI or FCP command compatibility. |
| `legacy-plugin.social-inbox-spike` | App-platform smoke summary. | Social Inbox is certified as the executable social/mail-like migration spike with AppVault, app data, content subscriptions, app-generated documents, and mediated Trust Graph score service grants. |
| `reference-app.feed-reader` | App-platform smoke summary. | Feed Reader exists as the first content-subscription reference app, declares `content.fetch`, `content.subscribe`, and generated-document publication permissions, uses SDK feed helpers, and keeps evidence free of raw feed bodies and private fetch inputs. |
| `reference-app.feed-reader-subscriptions` | App-platform smoke summary. | Feed Reader requires at least API v9, is tested through v12, uses `CryptaPlatform.content.subscriptions.*` for durable USK follow behavior, shows scheduler metadata, and does not rely on a tab-local timer as the durable follow path. |
| `reference-app.feed-reader-app-data` | App-platform smoke summary. | Feed Reader requires at least contract v9, is tested through v12, declares `app.data.*`, uses SDK JSON record helpers for bounded feed sources, selected source, read/render metadata, and safe publisher draft state, and keeps evidence free of raw feed bodies and app-data values. |
| `reference-app.trust-graph` | App-platform smoke summary. | Trust Graph Preview exists as the local trust-service reference app, requires at least API v10, is tested through v12, declares trust/content/vault/queue/app-data permissions, advertises `trust.score`, uses SDK trust helpers and design-system assets, and keeps evidence free of raw trust documents and private material. |
| `reference-app.trust-graph-durable-exchange` | App-platform smoke summary. | Trust Graph Preview demonstrates durable backend status, URI import, redacted audit, trust-statement subscription management, AppVault-backed publication, and local public statement import without hard-coded API URLs or private insert URI persistence. |
| `reference-app.trust-graph-app-data-preview` | App-platform smoke summary. | Trust Graph Preview uses app data only for UI-local draft/filter/import-summary state, keeps app data separate from the platform trust graph backend, and redacts raw trust statements, private identity material, and local paths. |
| `legacy.retirement` | App-platform smoke summary. | The legacy-admin retirement registry is visible, counts are stable, replaced surfaces are absent from primary shell fallback links, and retained/pending legacy routes remain documented. |
| `legacy-admin.removal-wave-1` | App-platform smoke summary. | The first removal wave records the removed-by-default route ids, replacement URLs, safe-read redirect behavior, mutating-request block behavior, retained browse status, diagnostics counters, and redaction checks without requiring a live node. |
| `legacy-admin.removal-wave-2` | App-platform smoke summary. | The second removal wave records the next removed-by-default route ids, queue/config/statistics route-scope expansion metadata, replacement URLs, partial mutation fallback policy, retained diagnostic export status, diagnostics counters, and redaction checks without requiring a live node. |
| `legacy-admin.removal-wave-3` | App-platform smoke summary. | The third removal wave records `security-levels` safe-read redirects to Web Shell security, mutating legacy fallback for incomplete security flows, stable wave 1/2 route sets, retained browse/filter/diagnostic/wizard surfaces, and redaction checks without requiring a live node. |
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
message routes remain out of scope, the raw diagnostic export remains retained, and the new
diagnostics scope metadata stays bounded and redacted.

`legacy-admin.removal-wave-3` is deterministic offline evidence for `/seclevels/` only. It proves
that safe reads redirect to `/app/node/#security` when Web Shell security is reachable, that POST
and other mutating requests remain legacy fallback for master-password, password-file, high
physical security, and recovery flows, and that the route scope is limited to the canonical path
and slashless alias. It also proves that FProxy browse and content rendering remain retained, the
content filter remains retained, raw diagnostic export remains retained, startup wizard and
emergency fallback remain pending, node-to-node messages remain pending, and evidence excludes
query strings, form passwords, tokens, private insert URIs, raw bodies, raw signatures, and local
paths.

`interop.extended` is optional in the machine gate but required by the release runbook when a
release changes compatibility-sensitive behavior. `apphost.sandbox-provider` does not require
host-installed bubblewrap in normal CI; it uses source checks and fake/offline provider tests.
The `public-beta-security.*` rows are deterministic public-beta hardening evidence. They inspect
source files, focused tests, staged first-party app bundles, redaction helpers, and docs. They do
not require a live network, private keys, private insert URIs, raw fetched bodies, raw trust
statements, or app/session tokens, and they do not claim live-network beta certification. PR-246
owns live-network beta certification.
`app-update.lifecycle`, `app-update.scheduler`, `app-update.live-catalog-refresh`, and
`app-update.rollback` do not require a live node; missing update evidence blocks
release-candidate mode unless a release-manager waiver is recorded. `apphost.live` is optional
stronger evidence because normal PR and scheduled CI must not require a live local node or operator
form password.

`app-catalog.first-party-beta` reports whether `CRYPTAD_FIRST_PARTY_CATALOG_SOURCE` and the trusted
catalog key hints are configured in the certification environment, but it does not fetch a public
Crypta catalog during normal tests. It uses source checks, documentation checks, and deterministic
`platform-appcatalog` tests for `crypta:CHK@` artifact support.

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

`platform-api.contract` is generated offline with `crypta-app api snapshot`. In
release-candidate mode, snapshot generation failure, contract parse failure, missing contract
evidence, or strict compatibility verifier failure is a blocker unless a release-manager waiver is
recorded.

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
Social Inbox Preview supplies the social/mail migration reference path. Release evidence must prove
`app-platform.social-message-signing`, `reference-app.social-inbox`,
`reference-app.social-inbox-signed-message`, `reference-app.social-inbox-subscriptions`,
`reference-app.social-inbox-app-data`, `reference-app.social-inbox-trust-annotations`,
`reference-app.social-inbox-service-grant`, `app-services.registry`, `app-services.grants`,
`app-services.trust-score-provider`, `app-services.web-shell`, `app-services.redaction`, and
`migration.social-mail-preview` before a release claims social/mail migration preview support.
`legacy-plugin.migration-guide` and `legacy-plugin.social-inbox-spike` certify the broader legacy
plugin-to-app migration guidance and the executable Social Inbox spike.
Social Inbox evidence must not include raw social message bodies, raw fetched social documents,
raw request bodies, raw signature values, private insert URIs, private identity material, app
process tokens, browser-session tokens, form passwords, private keys, absolute staging paths, or
local paths.
Trust Graph Preview supplies the local trust-service reference path. Release evidence must prove
`reference-app.trust-graph`, `reference-app.trust-graph-durable-exchange`,
`reference-app.trust-graph-app-data-preview`, `app-platform.trust-graph-preview`,
`app-platform.trust-graph-durable-store`, `app-platform.trust-graph-exchange`,
`app-platform.trust-statement-signing`, `app-services.registry`, `app-services.grants`,
`app-services.trust-score-provider`, `app-services.web-shell`, and `app-services.redaction` before
a release claims trust graph preview support. Trust and app-service evidence must not include raw
trust statement bodies from real users, raw fetched content, raw request bodies, raw signature
values, private insert URIs, private identity material, app process tokens, browser-session tokens,
form passwords, absolute staging paths, store roots, provider app data, raw subject URIs, or local
paths.

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
ecosystem.app-vault
ecosystem.sandbox-provider
ecosystem.reference-content-apps
ecosystem.legacy-retirement
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
rows because they validate distinct identity publishing, content fetch, and trust graph preview
behavior. The `app-platform-beta-docs-and-program` row records Phase 7 docs portal, tutorials,
beta program, issue-template, link, and redaction readiness.

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

The gates are intentionally conservative. Platform API compatibility blocks on contract status
failure, contract version rollback, or available stable endpoint/capability removals. First-party
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
evidence disappears, Trust Graph Preview evidence disappears, generated document insert evidence
disappears, content-fetch evidence disappears, trust-statement signing evidence disappears, or a
reference app no longer proves its required helper usage. Legacy
retirement gates block missing removal-wave evidence, including
`legacy-admin.removal-wave-2` and `legacy-admin.removal-wave-3`, or failed retained browse safety
evidence and warn on removed-route count changes without update-note metadata.

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
