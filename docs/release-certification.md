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
build/release-certification/artifacts/
build/release-certification/app-platform-smoke/summary.json
build/release-certification/app-platform-smoke/app-platform-smoke-report.md
build/release-certification/app-platform-smoke/artifacts/
```

The Markdown report is intended for human release review.  The JSON summary is the stable
machine-readable companion for later automation and report comparison.

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
| `app-platform.first-party` | App-platform smoke summary. | The first-party staged apps, including Queue Manager, Publisher, Site Publisher, Profile Publisher, Feed Reader, and Trust Graph Preview, have valid manifests, launchers, static UI assets, and SDK wiring. |
| `app-platform.devtools-cli` | App-platform smoke summary. | `crypta-app init`, `validate`, and `pack` work for a generated sample app. |
| `app-platform.developer-beta-toolkit` | App-platform smoke summary. | Developer beta toolkit command, template, mock-dev, offline-test, catalog entry, dry-run publication, docs, and self-test evidence is present. |
| `app-platform.signed-bundles` | App-platform smoke summary. | First-party and sample bundle signing/verification evidence exists with configured non-production or release signing inputs. |
| `catalog.smoke` | App-platform smoke summary. | Signed catalog create/sign/verify evidence exists and records digest, catalog id, and app id without private key material. |
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
| `app-platform.trust-graph-preview` | App-platform smoke summary. | The v7 trust graph routes are present, documented, capability-gated by `trust.read` and `trust.write`, SDK trust helpers exist, and evidence is redacted. |
| `app-platform.trust-statement-signing` | App-platform smoke summary. | The bounded AppVault route `POST /api/v1/app-vault/identities/{identityId}/trust-statement` is present, documented, requires `trust.write`, `vault.identities.read`, and `vault.identities.use`, and does not expose private material in evidence. |
| `app-ui.design-system` | App-platform smoke summary. | Canonical app UI design-system assets exist and first-party staged bundles contain matching local copies. |
| `app-ui.lint` | App-platform smoke summary. | `crypta-app ui lint --strict --json` passed for first-party staged static UI bundles and produced sanitized path-free summaries. |
| `app-ui.first-party-adoption` | App-platform smoke summary. | First-party source/staged UIs load design-system CSS in order, use stable `cr-*` classes, and show permission disclosure for declared permissions across the repo-owned static apps. |
| `app-ui.smoke` | App-platform smoke summary. | First-party static UI and `crypta-platform.js` remain coherent and do not expose process-token names. |
| `reference-apps.content` | App-platform smoke summary. | Site Publisher exists as the first content reference app, declares content publishing permissions, uses the browser SDK content/queue helpers, and avoids vault identity permissions. |
| `reference-app.profile-publisher` | App-platform smoke summary. | Profile Publisher exists as the first identity-profile reference app, declares the expected vault/content/queue permissions, uses the profile-document and app-document insert routes, and keeps release evidence free of signatures and private material. |
| `reference-app.feed-reader` | App-platform smoke summary. | Feed Reader exists as the first content-fetch reference app, declares `content.fetch` plus generated-document publication permissions, uses SDK feed helpers, and keeps evidence free of raw feed bodies and private fetch inputs. |
| `reference-app.trust-graph` | App-platform smoke summary. | Trust Graph Preview exists as the local trust-service reference app, declares API v7 trust/content/vault/queue permissions, uses SDK trust helpers and design-system assets, and keeps evidence free of raw trust documents and private material. |
| `legacy.retirement` | App-platform smoke summary. | The legacy-admin retirement registry is visible, counts are stable, replaced surfaces are absent from primary shell fallback links, and retained/pending legacy routes remain documented. |
| `legacy-admin.removal-wave-1` | App-platform smoke summary. | The first removal wave records the removed-by-default route ids, replacement URLs, safe-read redirect behavior, mutating-request block behavior, retained browse status, diagnostics counters, and redaction checks without requiring a live node. |
| `apphost.sandbox-provider` | App-platform smoke summary. | AppHost sandbox provider source and deterministic offline tests prove bubblewrap selection, enforced status reporting, fail-closed required sandbox behavior, and token/path-free public status. |
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

`interop.extended` is optional in the machine gate but required by the release runbook when a
release changes compatibility-sensitive behavior. `apphost.sandbox-provider` does not require
host-installed bubblewrap in normal CI; it uses source checks and fake/offline provider tests.
`app-update.lifecycle`, `app-update.scheduler`, and `app-update.rollback` do not require a live
node; missing update evidence blocks release-candidate mode unless a release-manager waiver is
recorded. `apphost.live` is optional stronger evidence because normal PR and scheduled CI must not
require a live local node or operator form password.

`app-catalog.first-party-beta` reports whether `CRYPTAD_FIRST_PARTY_CATALOG_SOURCE` and the trusted
catalog key hints are configured in the certification environment, but it does not fetch a public
Crypta catalog during normal tests. It uses source checks, documentation checks, and deterministic
`platform-appcatalog` tests for `crypta:CHK@` artifact support.

`platform-api.contract` is generated offline with `crypta-app api snapshot`. In
release-candidate mode, snapshot generation failure, contract parse failure, missing contract
evidence, or strict compatibility verifier failure is a blocker unless a release-manager waiver is
recorded.

`app-vault.capabilities` is deterministic offline evidence. The app-platform smoke runner checks
that [app-secret-and-identity-vault.md](app-secret-and-identity-vault.md) documents the six vault
capabilities, app-owned versus shared identities, process/browser restrictions, at-rest local
limitations, update/rollback/uninstall/reinstall grant behavior, audit/redaction, browser-safe
app-owned identity creation, the profile-document route, and the content/social/mail extension
point. The runner also checks that devtools recognizes the same capability names and that
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
prove `reference-app.profile-publisher`, `app-platform.identity-profile-publish`, and
`app-platform.generated-document-insert` before a release claims identity-profile support. Site
Publisher remains the content-reference app and should not claim `vault.identities.*` coverage.
Feed Reader supplies the content-fetch reference path. Release evidence must prove
`reference-app.feed-reader` and `app-platform.content-fetch` before a release claims feed-reader
support. Feed evidence must not include raw feed bodies, raw request bodies, private insert URIs,
app process tokens, browser-session tokens, form passwords, or local paths.
Trust Graph Preview supplies the local trust-service reference path. Release evidence must prove
`reference-app.trust-graph`, `app-platform.trust-graph-preview`, and
`app-platform.trust-statement-signing` before a release claims trust graph preview support. Trust
evidence must not include raw trust statement bodies from real users, raw request bodies, raw
signature values, private identity material, app process tokens, browser-session tokens, form
passwords, or local paths.

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
evidence disappears, generated document insert evidence disappears, content-fetch evidence
disappears, or a reference app no longer proves its required helper usage. Legacy
retirement gates block missing removal-wave evidence or failed retained browse safety evidence and
warn on removed-route count changes without update-note metadata.

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

The report and copied artifacts must not contain:

- private signing keys;
- private reviewer keys;
- raw trusted reviewer public key bytes;
- app process tokens;
- app browser session tokens;
- the host/operator form password;
- raw request bodies;
- raw feed bodies;
- raw app-vault secret values, identity private keys, identity seeds, or recovery phrases;
- raw profile-document signatures or signed profile-document payloads;
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
