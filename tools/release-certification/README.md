# Release certification tooling

This directory contains the release-candidate evidence aggregator used by the release runbook.

The tooling requires Python 3.10 or newer and depends only on the Python standard library.  The
self-tests do not start Cryptad, download a Hyphanet baseline, require signing keys, or contact the
network.

## Commands

Run the Python-only self-tests:

```bash
python3 tools/release-certification/app_platform_docs_check.py --self-test
python3 tools/release-certification/release_certification.py --self-test
python3 tools/release-certification/app_platform_smoke.py --self-test
python3 tools/release-certification/live_network_beta_smoke.py --self-test
```

Run the offline wrapper modes from a clean release workspace:

```bash
tools/release-certification/run-release-certification.sh --mode pr --skip-gradle --skip-git-metadata
tools/release-certification/run-release-certification.sh --mode nightly --out-dir build/release-certification
tools/release-certification/run-release-certification.sh \
  --mode release-candidate \
  --out-dir build/release-certification
```

The wrapper can be run from any working directory. Relative `--out-dir` values are resolved under
the repository root before shell cleanup, app-platform smoke generation, and certification
aggregation run.

The wrapper runs the app-platform smoke collector, then aggregates existing interop and
performance summaries when they are present.  In `pr` mode it skips Gradle by default so local and
normal CI use stay lightweight.  Set `CRYPTAD_CERT_RUN_GRADLE=1` or pass `--mode nightly` or
`--mode release-candidate` to run the app-platform Gradle staging and CLI checks.

## Outputs

The stable release evidence outputs are:

```text
build/release-certification/
  release-certification-summary.json
  release-certification-report.md
  history-comparison.json
  history-comparison.md
  ecosystem-certification-matrix.json
  ecosystem-certification-matrix.md
  artifacts/
  app-platform-smoke/
    summary.json
    app-platform-smoke-report.md
    artifacts/
  live-network-beta-smoke/
    summary.json
    live-network-beta-smoke-report.md
```

The `live-network-beta-smoke/` directory is present only when `--live-network-beta` or
`CRYPTAD_CERT_LIVE_NETWORK_BETA=1` is set. Normal PR, nightly, and offline release-candidate runs
must not consume stale live summaries when live-network beta mode is disabled.

The summary uses stable evidence ids and status values:

```text
pass
warn
fail
skip
missing
```

Each item contains `id`, `status`, `requiredForReleaseCandidate`, `summary`, `source`, and
`details`.

## Required release-candidate evidence

Release-candidate mode fails when required evidence is missing, skipped, or failing unless a waiver
is recorded.  The required evidence ids are:

```text
interop.smoke
performance.smoke
app-platform.first-party
app-platform.devtools-cli
app-platform.developer-beta-toolkit
app-platform.docs-portal
app-platform.beta-program
app-platform.beta-tutorials
app-platform.docs-redaction
app-platform.signed-bundles
catalog.smoke
app-catalog.first-party-beta
catalog.production-channels
platform-api.contract
app-vault.capabilities
app-platform.identity-profile-publish
app-platform.generated-document-insert
app-platform.content-fetch
app-platform.content-subscriptions
network-content.subscription-scheduler
app-data.backup-restore-portability
app-platform.trust-graph-preview
app-platform.trust-graph-rc-scope-and-safety
app-platform.trust-statement-signing
app-platform.social-message-signing
app-services.registry
app-services.grants
app-services.trust-score-provider
reference-app.social-inbox-service-grant
app-services.web-shell
app-services.redaction
app-ui.design-system
app-ui.lint
app-ui.first-party-adoption
app-ui.smoke
reference-apps.content
reference-app.profile-publisher
reference-app.social-inbox
reference-app.social-inbox-signed-message
reference-app.social-inbox-subscriptions
reference-app.social-inbox-app-data
reference-app.social-inbox-trust-annotations
reference-app.social-inbox-rc-threading
migration.social-mail-preview
legacy-plugin.migration-guide
legacy-plugin.social-inbox-spike
reference-app.feed-reader
reference-app.feed-reader-subscriptions
reference-app.trust-graph
legacy.retirement
legacy-admin.removal-wave-1
legacy-admin.removal-wave-2
legacy-admin.removal-wave-3
apphost.sandbox-provider
public-beta-security.app-ui-csp
public-beta-security.app-origin-policy
public-beta-security.content-fetch-bounds
public-beta-security.feed-sanitization
public-beta-security.social-inbox-sanitization
public-beta-security.profile-sanitization
public-beta-security.trust-statement-hardening
public-beta-security.apphost-env-minimization
public-beta-security.sandbox-host-checks
public-beta-security.audit-redaction-fuzz
public-beta-security.transparency-log-privacy
app-update.lifecycle
app-update.scheduler
app-update.live-catalog-refresh
app-update.rollback
app-update.data-migration-contract
operator-beta.dashboard
operator-beta.catalog-health
operator-beta.app-update-recovery
operator-beta.subscription-recovery
operator-beta.trust-review-warnings
operator-beta.app-data-quota-warnings
operator-beta.app-data-backup-restore
operator-beta.support-bundle-redaction
operator-beta.web-shell
app-review.trusted-receipts
app-review.policy
app-review.governance
app-review.reviewer-key-lifecycle
app-review.transparency-log
app-review.review-history-api
app-review.first-party-catalog
app-review.first-party-review-chain
release-certification.ecosystem-matrix
```

The app-platform, app-review, reference-app, public-beta security, legacy-retirement, and matrix
evidence ids above use deterministic source checks, fixtures, and fake/offline tests; they do not
require a live node or host-installed bubblewrap in normal CI. The `public-beta-security.*` rows
prove hardened local boundaries and redaction behavior without committing secrets, private insert
URIs, private keys, live fetched bodies, raw trust statements, or app/session tokens.
`app-platform.docs-portal`,
`app-platform.beta-program`, `app-platform.beta-tutorials`, and
`app-platform.docs-redaction` run a deterministic local docs check for required docs, concept
coverage, issue templates, internal Markdown links, README/portal links, and obvious secret leaks.
`app-catalog.first-party-beta` reports source/key configuration readiness but does not fetch the
public Crypta catalog. `catalog.production-channels` verifies schema v3 stable/beta/nightly/
deprecated metadata, stable-only default update automation, deprecated replacement metadata, API
and Web Shell exposure, signature/review verification preservation, and redaction guarantees.
`app-update.data-migration-contract` verifies signed app-data schema migration metadata, dry-run
before bundle replacement, internal app-scoped snapshot/restore, missing-path and
rollback-incompatible blockers, Feed Reader and Trust Graph Local RC UI-state examples, and path-free
redacted update summaries.
`app-data.backup-restore-portability` verifies the `backupVersion = 1`
`crypta-app-data-backup` envelope, single-app and all-app backup, host/operator-only restore plan
and commit routes, app-principal denial, `merge`, `replaceNamespace`, and `replaceApp` restore
modes, Web Shell controls, first-party app backup-scope docs, and support-bundle redaction without
recording raw backup payloads. `operator-beta.app-data-backup-restore` verifies the operator
dashboard controls for sensitive backup, restore preview, restore commit, all-app backup, and
export-before-delete.
`app-platform.trust-graph-rc-scope-and-safety` verifies Trust Graph Local RC scope and safety:
local anchors, imported public signed statements, local lifecycle states, bounded score
explanations, redacted source metadata, read-only `trust.score` service boundaries, no crawling, no
global moderation or blocking, no routing decisions, no node-to-node trust propagation, and no
legacy WebOfTrust, Freetalk, Sone, or Freemail compatibility claim.
`reference-app.social-inbox-rc-threading` verifies the Social Inbox RC reference-app source for
local thread reconstruction, reply actions using the existing `replyTo` field, channel filters,
bounded local search, thread read/archive/pin actions, safe author profile display, mediated
Trust Graph service annotations only, a non-blocking schema-1 app-data namespace contract, and
path-free redacted evidence.
`app-review.first-party-catalog`
also runs offline, but release-candidate mode requires explicit reviewer key inputs so the runner
can pack every staged first-party app and sign, verify, and embed a matching first-party review
receipt for each catalog entry. `interop.extended` and `apphost.live` are recorded as optional
stronger evidence. Extended interop is still required by the release runbook when
compatibility-sensitive behavior changed. Live AppHost lifecycle evidence is optional because
normal PR CI must not require a running node or operator credentials.

Record an explicit waiver when a release manager accepts missing optional or replacement evidence:

```bash
tools/release-certification/run-release-certification.sh \
  --mode release-candidate \
  --waive interop.extended="No compatibility-sensitive behavior changed in this release."
```

Waivers change the evidence item to `warn`, preserve the original reason in `details`, and keep the
release-candidate gate from failing for that item.

## Historical comparison and ecosystem gates

Release certification can compare the current candidate with a previous certified summary without
making network calls:

```bash
tools/release-certification/run-release-certification.sh \
  --mode release-candidate \
  --previous-summary path/to/previous/release-certification-summary.json \
  --out-dir build/release-certification
```

The comparison writes `history-comparison.json` and `history-comparison.md`, emits the standalone
ecosystem certification matrix, and embeds `historyComparison`, `ecosystemGates`, and compact
`ecosystemMatrix` metadata in `release-certification-summary.json`. If no previous summary is
provided, `pr` mode records skipped history, while `nightly` and `release-candidate` mode record a
visible warning. Add `--require-history` when a release-candidate must fail without a valid
previous certified baseline.

The ecosystem gates summarize release-relevant regressions across the app-platform evidence:

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

The aggregator also writes `ecosystem-certification-matrix.json` and
`ecosystem-certification-matrix.md` beside the summary and report. The matrix is the
release-manager-facing checklist for ecosystem promotion. Each deterministic row names the area
being certified, required and optional evidence ids, ecosystem gate ids, docs, waiver ids, current
status, previous row status when available, regression status, release-blocker flag, and the next
release-manager action.

Matrix coverage is self-checked on every run:

| Coverage check | Meaning |
| --- | --- |
| Required evidence covered | Every current `requiredForReleaseCandidate` evidence id appears in at least one matrix row. |
| Ecosystem gates covered | Every emitted `ecosystem.*` gate appears in at least one matrix row, including `ecosystem.waivers` when waiver-file validation emits it. |
| First-party apps covered | The rows visibly cover `queue-manager`, `publisher`, `site-publisher`, `profile-publisher`, `feed-reader`, and `trust-graph`. |
| Docs covered | Every non-synthetic row references at least one existing docs path. |
| Redaction | Matrix JSON and Markdown are built from sanitized, path-free summary fields only. |

`queue-manager`, `publisher`, and the shared staged-bundle set are grouped under the first-party
app bundle row. `site-publisher` is covered by the reference content row, while
`profile-publisher`, `feed-reader`, and `trust-graph` have app-specific rows for their distinct
networked app-layer behavior. The `app-platform-beta-docs-and-program` row records Phase 7 docs
portal, tutorials, beta program, issue-template, link, and redaction readiness.

In `release-candidate` mode, unmapped required evidence, unmapped ecosystem gates, missing docs,
or failed redaction make the matrix fail. In `pr` and `nightly` mode, coverage gaps are warnings
unless redaction fails. A previous summary that predates PR-231 and has no `ecosystemMatrix`
metadata does not fail by itself; `nightly` and `release-candidate` runs record a visible
`previous-missing` matrix warning so the release log can explain the first baseline transition.
Active waivers are projected onto matching row ids, evidence ids, gate ids, or issue ids. A waived
blocker row becomes `warn`, never a silent `pass`.

Required evidence that regresses from `pass` to `fail`, `missing`, or `skip` blocks
release-candidate promotion unless a visible waiver applies. `pass` to `warn` is a warning.
`legacy-plugin.migration-guide`, `legacy-plugin.social-inbox-spike`, and
`legacy-admin.removal-wave-3` are required release-candidate evidence. The migration evidence
verifies that legacy plugin categories have a documented app-platform migration path without old
plugin ABI or FCP command compatibility, and that Social Inbox remains the executable
social/mail-like migration spike. Wave 3 verifies only the `security-levels` route, safe-read
redirect behavior, mutating legacy fallback, retained browse/filter/diagnostic/wizard surfaces,
and redacted diagnostics counters without a live node.
Platform API contract version rollback, stable endpoint/capability removal, first-party app
disappearance, missing Site Publisher evidence, strict first-party UI lint failure, review receipt
regression, update rollback regression, vault capability/redaction regression, required enforced
sandbox evidence loss, and missing legacy removal-wave evidence are reported as ecosystem gate
blockers.

Local history artifacts are supported for release-manager workflows:

```bash
tools/release-certification/run-release-certification.sh \
  --mode release-candidate \
  --previous-summary build/release-certification-history/latest-summary.json \
  --write-history \
  --history-label 2026.05.0
```

`--write-history` writes sanitized current artifacts under:

```text
build/release-certification-history/
  latest-summary.json
  latest-history-comparison.json
  releases/<history-label>/release-certification-summary.json
  releases/<history-label>/history-comparison.json
  failed/<history-label>/release-certification-summary.json
  failed/<history-label>/history-comparison.json
```

Only non-failing, promotable certification runs update `latest-summary.json` and the
`releases/<history-label>/` baseline. Failed or non-promotable attempts are preserved under
`failed/<history-label>/` so they cannot replace the last certified comparison baseline.

Do not commit generated history summaries by default. Release managers should restore or download
the previous release's sanitized certification artifact into the local workspace or CI job before
running certification, then pass its path with `--previous-summary`.

## Structured waiver files

CLI `--waive ID=REASON` remains supported. Structured waiver files can be merged in with
`--waiver-file`:

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

Structured waivers are visible in JSON and Markdown output. For schema-version 1 summaries,
top-level `waivers` remains the CLI waiver map, and full CLI plus structured waiver records are
emitted under `waiverRecords`. Active waivers downgrade matching evidence or ecosystem gate
blockers to `warn`; they do not remove the evidence, gate, or reason.
Expired, unapproved, malformed, or release-candidate-disallowed waivers do not apply. A malformed
waiver file fails `release-candidate` mode and warns in `pr` or `nightly` mode.

## App-platform smoke

The app-platform smoke runner validates first-party staged app manifests, static app UI/SDK
coherence, canonical design-system asset staging, strict `crypta-app ui lint` JSON summaries, the
`crypta-app` developer CLI, Platform API contract snapshots and compatibility verification,
app-vault capability documentation and redaction evidence, signed bundle evidence when signing
inputs are present, signed catalog authoring/verification, AppHost
sandbox-provider evidence, app-update lifecycle/scheduler/rollback evidence, operator beta
dashboard/recovery/support-bundle evidence, independent app-review receipt evidence,
Profile Publisher identity-profile publishing evidence,
app-generated document insert evidence, content-fetch evidence, content-subscription scheduler
evidence, Feed Reader reference-app and subscription evidence,
Trust Graph Local RC evidence, app-review governance evidence, and the legacy-admin retirement map.

Signing inputs use the documented first-party app environment variables:

```text
CRYPTAD_APP_SIGNING_KEY_ID
CRYPTAD_APP_SIGNING_PRIVATE_KEY_BASE64
CRYPTAD_APP_SIGNING_PRIVATE_KEY_FILE
CRYPTAD_APP_SIGNING_PUBLIC_KEY_BASE64
CRYPTAD_APP_SIGNING_PUBLIC_KEY_FILE
```

In `pr` and `nightly` modes, missing signing inputs are recorded as skipped or warning evidence.
In `release-candidate` mode, missing signed bundle or signed catalog evidence is a failing required
item.

Review receipt inputs use a separate reviewer-key namespace:

```text
CRYPTAD_APP_REVIEWER_KEY_ID
CRYPTAD_APP_REVIEWER_PRIVATE_KEY_BASE64
CRYPTAD_APP_REVIEWER_PRIVATE_KEY_FILE
CRYPTAD_APP_REVIEWER_PUBLIC_KEY_BASE64
CRYPTAD_APP_REVIEWER_PUBLIC_KEY_FILE
CRYPTAD_APP_REVIEW_POLICY_ID
CRYPTAD_APP_REVIEW_POLICY_VERSION
```

In `pr` and `nightly` modes, missing reviewer inputs are recorded as skipped or warning evidence.
In `release-candidate` mode, missing first-party review receipt evidence is a failing required
item. The report records reviewer key ids, policy ids, first-party catalog coverage, receipt status counts, and redacted command
metadata; it must not include reviewer private keys, raw public key bytes, local evidence paths, or
app/session/process tokens.

Optional live-node AppHost lifecycle smoke is enabled only when requested:

```bash
CRYPTAD_CERT_APP_SMOKE_LIVE=1 \
CRYPTAD_CERT_NODE_BASE_URL=http://127.0.0.1:<port> \
CRYPTAD_CERT_FORM_PASSWORD=<redacted> \
tools/release-certification/run-release-certification.sh --mode nightly
```

The live smoke only records localhost node metadata. It redacts the form password and does not
write raw request bodies. The wrapper also accepts `--live`, but it does not accept
`--form-password`; set `CRYPTAD_CERT_FORM_PASSWORD` in the environment.

## Live-network beta certification

PR-246 live-network beta certification is an explicit release-manager mode in the certification
wrapper. Run it only against a prepared localhost node and disposable live fixtures, unless the
release manager is intentionally publishing the candidate first-party beta catalog.

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

Use fixture public URIs such as `crypta:USK@<catalog-key>/cryptad-app-catalog.properties` and
`crypta:CHK@<artifact-key>` in docs and reports. The matching private insert URI is a bare private
USK directory insert URI for the same catalog parent and must never appear in docs, reports, shell
history, issue comments, or release artifacts. Prefer `CRYPTAD_CERT_LIVE_TEST_INSERT_URI_FILE` for
copyable one-shot commands. If you use `CRYPTAD_CERT_LIVE_TEST_INSERT_URI_ENV`, export the private
URI from a protected channel before running the wrapper and put only the environment-variable name
in the command. If both `CRYPTAD_CERT_LIVE_TEST_INSERT_URI_ENV` and
`CRYPTAD_CERT_LIVE_TEST_INSERT_URI_FILE` are present, the environment-name indirection wins
deterministically; the summary records only that a private fixture was present.
`CRYPTAD_CERT_LIVE_CATALOG_EXPECTED_KEY_ID` is required in required live-network beta mode. The
smoke compares it with the public `signatureKeyId` returned by the node after catalog signature
verification; an unset, missing, or mismatched key id fails the catalog evidence.
Set `CRYPTAD_CERT_LIVE_PROFILE_PUBLIC_URI` and `CRYPTAD_CERT_LIVE_TRUST_PUBLIC_URI` when the run
should fetch back the synthetic profile and trust statement after publish. Timing knobs are
`CRYPTAD_CERT_LIVE_TIMEOUT_SECONDS`, `CRYPTAD_CERT_LIVE_POLL_INTERVAL_SECONDS`,
`CRYPTAD_CERT_LIVE_MAX_POLL_ATTEMPTS`, `CRYPTAD_CERT_LIVE_MAX_DURATION_SECONDS`, and
`CRYPTAD_CERT_LIVE_MAX_STEP_DURATION_SECONDS`.

App-facing live steps authenticate as app principals. The runner fetches each required static app
bootstrap from `/apps/{appId}/.well-known/cryptad-bootstrap.json`, keeps the
`browserSessionToken` in memory, and sends it as `X-Crypta-App-Session`; the token is never written
to summary, report, matrix, or logs. Required mode fails if the configured app cannot mint a
browser session. The default app ids are `site-publisher` for lifecycle, `feed-reader` for content
and subscriptions, `profile-publisher` for profile publish, `trust-graph` for trust publish/import,
and `social-inbox` for optional score invocation. Override them with
`CRYPTAD_CERT_LIVE_APP_ID`, `CRYPTAD_CERT_LIVE_CONTENT_APP_ID`,
`CRYPTAD_CERT_LIVE_FEED_APP_ID`, `CRYPTAD_CERT_LIVE_PROFILE_APP_ID`,
`CRYPTAD_CERT_LIVE_TRUST_APP_ID`, and `CRYPTAD_CERT_LIVE_APP_SERVICE_CALLER_APP_ID` when using
disposable certification apps.

The runner validates localhost-only node access, live USK catalog fetch/verification, app
install/update/rollback, content fetch, feed subscription metadata, synthetic profile publish,
synthetic trust statement publish/import, interop/performance timing, and artifact redaction. It
can also invoke the read-only Trust Graph `trust.score` app-service when
`CRYPTAD_CERT_LIVE_APP_SERVICE_SCORE=1` is set; otherwise
`live-network-beta.app-service-score` is reported as optional skipped evidence, not a false pass.
Aggregation records these results under the `ecosystem.live-network-beta` gate and the
`live-network-beta-certification` matrix row.
Lifecycle cleanup deletes only an app that was absent before the smoke and installed successfully
by this run. Use a disposable app id when the prepared node already has first-party apps installed.
It does not prove global network propagation, app safety beyond signature/review policy, catalog
trust beyond the configured expected key, or deletion of published bytes. Keep local fixture outputs
only until cleanup is verified, preserve the sanitized certification summary and report, and assume
live synthetic content may remain retrievable and may not be deletable from the network. Do not use
real keys, production secrets, or user content in fixture certification runs.

## Redaction

Certification outputs must remain suitable for release-candidate evidence.  Do not upload or paste:

- private signing keys;
- private reviewer keys;
- raw trusted reviewer public key bytes;
- app process tokens;
- browser-session tokens;
- the host/operator form password;
- raw request bodies;
- raw feed bodies;
- raw social message bodies or fetched social documents;
- raw trust statement documents or trust-document bodies from real users;
- raw app-vault secret values, identity private keys, identity seeds, or recovery phrases;
- raw profile-document signatures or signed profile-document payloads;
- raw social-message signatures or signed social-message payloads;
- raw app-service invocation request bodies, raw subject URIs, raw service tokens, provider app
  data, or local app-service store paths;
- raw update or rollback command output;
- full query strings that may contain secrets;
- private insert URIs;
- developer-specific absolute filesystem paths, including absolute staging paths;
- catalog scratch paths, staged bundle paths, installed bundle paths, data/cache/run paths, and
  rollback backup paths;
- non-localhost remote endpoint metadata.

The aggregator sanitizes paths as `<repo>`, `<workdir>`, `<home>`, or `<path>` placeholders.  It
also filters `artifacts/private-insert-uris.json` from interop evidence even when the source
`summary.json` mentions that private diagnostics file.
