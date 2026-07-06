# Release certification tooling

This directory contains the release-candidate evidence aggregator used by the release runbook,
including the final ecosystem RC certification gate.

The tooling requires Python 3.10 or newer and depends only on the Python standard library.  The
self-tests do not start Cryptad, download a Hyphanet baseline, require signing keys, or contact the
network.

## Commands

Run the Python-only self-tests:

```bash
python3 tools/release-certification/app_platform_docs_check.py --self-test
python3 tools/release-certification/release_certification.py --self-test
python3 tools/release-certification/app_platform_smoke.py --self-test
python3 tools/release-certification/network_scale_soak.py --self-test
python3 tools/release-certification/multi_node_beta_soak.py --self-test
python3 tools/release-certification/live_network_beta_smoke.py --self-test
python3 tools/release-certification/stable_1_0_readiness.py --self-test
python3 tools/release-certification/production_beta_go_no_go_dashboard.py --self-test
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

The wrapper can be run from any working directory. Relative `--out-dir` values are resolved under
the repository root before shell cleanup, app-platform smoke generation, and certification
aggregation run.

The wrapper runs the app-platform smoke collector, then aggregates existing interop and
performance summaries when they are present.  It also generates a fresh deterministic
`network-scale-soak/summary.json` with `network_scale_soak.py` unless
`--network-scale-soak-summary` or `CRYPTAD_CERT_NETWORK_SCALE_SOAK_SUMMARY` points at an externally
attached simulated or live soak summary.  In `pr` mode it skips Gradle by default so local and
normal CI use stay lightweight.  Set `CRYPTAD_CERT_RUN_GRADLE=1` or pass `--mode nightly` or
`--mode release-candidate` to run the app-platform Gradle staging and CLI checks.
Attached network-scale summaries must use the same redacted schema as the deterministic collector.
The summary kind may be `simulated-rc-soak` or `live-rc-soak`, but raw fetched content, queue HTML,
tokens, private insert URIs, raw signatures, app-data values, backup payloads, rejected source
strings, and absolute local paths must stay out of the release record.

The wrapper also generates a fresh deterministic
`multi-node-beta-soak/summary.json` with `multi_node_beta_soak.py` unless
`--multi-node-soak-summary` or `CRYPTAD_CERT_MULTI_NODE_SOAK_SUMMARY` points at an attached
summary. Use `--multi-node-mode simulated|hybrid|live`, `--multi-node-soak-config <path>`, and
`--require-multi-node-soak` when release-manager evidence needs a specific topology or strict
promotion behavior. See
[docs/multi-node-beta-soak-and-upgrade-drill.md](../../docs/multi-node-beta-soak-and-upgrade-drill.md).

Previous beta candidate summaries are normalized with the same tool:

```bash
python3 tools/release-certification/multi_node_beta_soak.py previous-summary \
  --release-certification-summary build/previous/release-certification-summary.json \
  --production-beta-summary build/previous/production-beta-summary.json \
  --out build/previous/previous-beta-candidate-summary.json \
  --report build/previous/previous-beta-candidate-summary.md

python3 tools/release-certification/multi_node_beta_soak.py verify-previous-summary \
  --summary build/previous/previous-beta-candidate-summary.json \
  --strict \
  --max-age-days 90
```

The generated summary has `kind=cryptad-previous-beta-candidate-summary`. Production-beta promotion
requires this formal summary rather than a raw previous release-certification summary.
It is upgrade evidence only. Release-certification history comparison still requires a previous
`release-certification-summary.json` through `run-release-certification.sh --previous-summary` or
the configured release-certification history store. The normalizer writes the current UTC time to
`generatedAt` unless `--generated-at` is supplied for deterministic fixture generation. Source
summaries must carry the sanitized previous-candidate catalog, Platform API, first-party app,
app-data, Trust Graph, Social Inbox, support-bundle, and redaction metadata; the normalizer copies
that metadata and rejects missing or conflicting source values instead of fabricating release
state.

Build a production beta app-ecosystem candidate:

```bash
tools/release-certification/run-production-beta-release.sh \
  --workspace-root . \
  --out-dir build/production-beta-release \
  --mode production-beta \
  --catalog-channel stable \
  --artifact-base-uri "$CRYPTAD_PRODUCTION_BETA_ARTIFACT_BASE_URI" \
  --require-live-network \
  --require-multi-node-soak \
  --require-sandbox-provider-tests \
  --previous-summary "$PREVIOUS_BETA_CANDIDATE_SUMMARY" \
  --previous-release-certification-summary "$PREVIOUS_RELEASE_CERTIFICATION_SUMMARY" \
  --multi-node-soak-summary "$MULTI_NODE_BETA_SOAK_SUMMARY"
```

The production beta command writes signed first-party app bundles, a signed first-party catalog,
review receipts, extracted evidence, a redaction report, JSON/Markdown summaries, and a final
go/no-go dashboard under `reports/`, plus `dist/crypta-production-beta-<version>.tar.gz`.
`release-candidate` and `production-beta` runs require a real HTTPS artifact base URI through
`--artifact-base-uri` or
`CRYPTAD_PRODUCTION_BETA_ARTIFACT_BASE_URI`; developer dry-runs may use the non-release fallback
URI. Catalog bundle URLs are signed under the published layout root, for example
`<base>/build/app-bundles/<app>-<version>.zip`. `--use-fixture-evidence` is accepted only for
`developer-dry-run` and internal self-tests. Use
`developer-dry-run` for PR-safe local runs without release keys or live-network access. Protected
`production-beta` also requires a schema-valid previous beta candidate summary through
`--previous-summary`, a previous release-certification history summary through
`--previous-release-certification-summary` or the restored history store, and passing multi-node
upgrade evidence through either `--multi-node-soak-summary` or an explicit non-self-test
`hybrid`/`live` topology config. Simulated multi-node mode, fixture evidence, test signing,
skipped build stages, missing sandbox evidence, and missing live-network evidence remain
non-release/no-go in production-beta. See
[docs/production-beta-release-pipeline.md](../../docs/production-beta-release-pipeline.md) for
mode semantics, required environment variables, artifact layout, failure classes, redaction rules,
and rerun guidance.

Generate a Stable 1.0 readiness report from production beta outputs:

```bash
python3 tools/release-certification/stable_1_0_readiness.py \
  --workspace-root . \
  --out-dir build/stable-1.0-readiness \
  --production-beta-summary build/production-beta-release/reports/production-beta-summary.json \
  --go-no-go-summary build/production-beta-release/reports/go-no-go-dashboard.json \
  --release-certification-summary build/production-beta-release/evidence/ecosystem-rc-certification.json \
  --ecosystem-matrix build/production-beta-release/evidence/ecosystem-certification-matrix.json \
  --app-platform-summary build/production-beta-release/evidence/app-platform-smoke.json \
  --multi-node-beta-soak-summary build/production-beta-release/evidence/stable-readiness-multi-node-beta-soak.json \
  --network-scale-soak-summary build/production-beta-release/evidence/stable-readiness-network-scale-soak.json \
  --security-drills-summary build/production-beta-release/security-drills/security-drills-summary.json \
  --public-beta-known-issues tools/release-certification/public-beta-known-issues.json
```

`run-production-beta-release.sh --generate-stable-readiness` writes the same artifacts under
`reports/stable-1.0-readiness/`. Add `--require-stable-readiness` only for a Stable promotion
review. The default production beta pipeline remains advisory-only for Stable readiness. See
[docs/stable-1.0-readiness-gate.md](../../docs/stable-1.0-readiness-gate.md).

Use the Stable-specific soak extracts shown above when rerunning the readiness tool against a
production beta bundle. The generic compact production beta soak extracts are optimized for the
production beta summary and may not carry the `generatedAt` freshness metadata required by the
Stable gate. Stable readiness also binds attached go/no-go and security drill summaries to the
production beta `releaseId`, requires Stable-specific multi-node soak extracts to carry or derive
the same candidate release identity, requires `release-candidate` release-certification evidence,
accepts the existing boolean release-certification redaction schema, and validates security drill
artifact freshness from either per-artifact `generatedAt` or the existing `stale`/`ageDays` fields.

Production beta catalog descriptors also consume
`tools/release-certification/first-party-app-maintenance-policy.json`. The pipeline copies that
policy into `inputs/first-party-app-maintenance-policy.json`, writes redacted per-app maintenance
summaries into `catalog/channel-metadata.json`, and relies on
`app-catalog.first-party-maintenance-policy` evidence for release-candidate certification.

Production security response drills are verified offline with:

```bash
python3 tools/release-certification/security_response_runbook.py verify
python3 tools/release-certification/security_response_runbook.py drill create \
  --scenario reviewer-key-compromise \
  --out build/security-drills/reviewer-key-compromise.json
python3 tools/release-certification/security_response_runbook.py drill verify \
  --input build/security-drills/reviewer-key-compromise.json
python3 tools/release-certification/security_response_runbook.py drill run-all \
  --out-dir build/security-drills \
  --release-id cryptad-beta-<version> \
  --mode production-beta \
  --summary-out build/security-drills/security-drills-summary.json \
  --release-notes-out build/security/security-release-notes-draft.md
python3 tools/release-certification/security_response_runbook.py drill verify-all \
  --input-dir build/security-drills \
  --release-id cryptad-beta-<version> \
  --mode production-beta \
  --summary-out build/security-drills/security-drills-summary.json
python3 tools/release-certification/security_response_runbook.py advisory template \
  --scenario vulnerable-app-version \
  --out build/security-advisory-template.md
```

These commands are deterministic, do not require live network access or private keys, and verify
[docs/production-security-response-runbook.md](../../docs/production-security-response-runbook.md)
for the `production-security.response-runbook` evidence used by production beta promotion.
`drill run-all` creates one redacted schema-version 2 artifact for each required scenario and a
`cryptad-security-response-drills-summary` aggregate. Release certification, the production beta
release wrapper, and the go/no-go dashboard consume the summary through
`--security-drills-summary`. Attached summaries must use the candidate release id,
`cryptad-beta-<version>`, and the matching release mode (`release-candidate` for RC certification,
`production-beta` for protected production-beta attachment). Keep the seven per-scenario JSON files
beside the attached summary; the release wrapper copies and verifies those artifacts before
accepting the summary. The release wrapper and strict go/no-go dashboards reject summaries generated
for another candidate. Production-beta promotion fails closed when the summary is missing, a
required scenario is missing, a scenario fails, an artifact is stale or malformed, production
evidence is marked fixture-only, or any drill/advisory/release-note redaction check fails.
Redaction failures are critical and non-waivable.

The required scenarios are:

```text
vulnerable-app-version
app-signing-key-compromise
reviewer-key-compromise
catalog-signing-key-rotation
malicious-catalog-entry
emergency-replacement-app
support-bundle-intake-redaction
```

Drill artifacts, summaries, and generated release notes must contain only safe scenario ids,
statuses, bounded operator guidance, evidence ids, counts, and digests. They must not contain
private keys, private insert URIs, tokens, raw receipt signatures, raw support bundle bodies, raw
fetched content, raw app data, raw profile/feed/trust/social documents, raw app-service bodies,
nested backup material, or absolute local paths.

The command cleans existing output directories only under `build/production-beta*` or when the
directory already contains the `.cryptad-production-beta-release-output` sentinel. Output is
refused for source-controlled workspace paths such as `docs`, `tools`, `apps`, `.git`, and
`.github`. The `dist/` directory is regenerated on every run, including `--no-clean-out-dir`
reruns, so stale archives or side files are not carried into uploaded artifacts.

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
  network-scale-soak/
    summary.json
  multi-node-beta-soak/
    summary.json
    multi-node-beta-soak-summary.md
  live-network-beta-smoke/
    summary.json
    live-network-beta-smoke-report.md
  security-drills/
    security-drills-summary.json
```

The production beta wrapper uses a separate public artifact layout under
`build/production-beta-release/`:

```text
inputs/release-config.json
inputs/first-party-app-maintenance-policy.json
build/staged-apps/
build/app-bundles/
build/crypta-app-launcher/
catalog/first-party-catalog.properties
catalog/cryptad-app-catalog.signature
catalog/first-party-catalog.sig
catalog/channel-metadata.json
reviews/review-receipts/
reviews/review-transparency-log.json
security-drills/security-drills-summary.json
security-drills/<scenario>.json
security/security-release-notes-draft.md
evidence/
evidence/security-drills-summary.json
reports/production-beta-summary.json
reports/production-beta-summary.md
reports/redaction-report.json
reports/go-no-go-dashboard.json
reports/go-no-go-dashboard.md
reports/go-no-go-redaction-report.json
dist/crypta-production-beta-<version>.tar.gz
dist/checksums.txt
```

The `live-network-beta-smoke/` directory is present only when `--live-network-beta` or
`CRYPTAD_CERT_LIVE_NETWORK_BETA=1` is set. Normal PR, nightly, and offline release-candidate runs
must not consume stale live summaries when live-network beta mode is disabled.

The `network-scale-soak/summary.json` file is generated by the wrapper by default and removed before
each generated run so stale default soak evidence is not reused. Pass
`--network-scale-soak-summary <path>` or set `CRYPTAD_CERT_NETWORK_SCALE_SOAK_SUMMARY` when
attaching an external live RC soak summary.

The `multi-node-beta-soak/summary.json` file is generated by the wrapper by default and removed
before each generated run so stale multi-node evidence is not reused. Pass
`--multi-node-soak-summary <path>` or set `CRYPTAD_CERT_MULTI_NODE_SOAK_SUMMARY` when attaching a
hybrid or live summary.

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

The production beta go/no-go dashboard emits `go`, `no-go`, or `go-with-waivers` from the sanitized
pipeline summaries. Waiver rendering preserves ids, rationale, owner, approver, expiry, scope, and
usage, but production-beta launch evidence, redaction findings, and unsafe artifact hygiene
findings are never downgraded by waivers.

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
public-beta.docs-onboarding
public-beta.user-guide
public-beta.developer-quickstart
public-beta.troubleshooting
public-beta.security-reporting
public-beta.limitations
public-beta.links-redaction
public-beta.support-feedback-loop
public-beta.support-feedback-docs
public-beta.issue-templates
public-beta.triage-taxonomy
public-beta.known-issues-tracker
public-beta.feedback-to-backlog
public-beta.release-notes-template
public-beta.support-bundle-guidance
public-beta.security-reporting-handoff
public-beta.app-specific-feedback
public-beta.catalog-incident-feedback
public-beta.redaction-fixtures
third-party-developer.beta-program
third-party-developer.docs
third-party-developer.template
third-party-developer.sample-app-flow
third-party-developer.submission-checklist
third-party-developer.compatibility-window
third-party-developer.feedback-workflow
third-party-developer.plugin-author-migration
third-party-developer.redaction
legacy-plugin.migration-finalization
app-platform.signed-bundles
catalog.smoke
app-catalog.first-party-beta
catalog.production-channels
catalog.operations-and-mirrors
app-catalog.first-party-maintenance-policy
catalog.security-advisories
catalog.version-denylist
app-review.receipt-revocation
app-review.reviewer-key-compromise-flow
app-store.submission-package-schema
app-store.submission-cli
app-store.pre-review
app-store.review-decision-states
app-store.review-receipt-issued
app-store.rejection-record
app-store.resubmission-link
app-store.transparency-log
app-store.catalog-candidate
app-store.third-party-sample-flow
app-store.redaction-clean
app-update.security-denylist-gates
web-shell.security-advisory-trust-warnings
ecosystem-security.advisory-revocation-redaction
production-security.response-runbook
platform-api.contract
platform-api.stable-baseline
platform-api.stable-breaking-change-check
platform-api.compatibility-window
platform-api.previous-contract-snapshot
platform-api.deprecation-window-policy
platform-api.experimental-graduation-policy
platform-api.manifest-target-stability
platform-api.first-party-stability-declarations
platform-api.stable-reference-docs
app-vault.capabilities
app-platform.identity-profile-publish
app-platform.generated-document-insert
app-platform.content-fetch
app-platform.content-subscriptions
network-content.subscription-scheduler
app-data.backup-restore-portability
app-platform.trust-graph-preview
app-platform.trust-graph-rc-scope-and-safety
app-platform.trust-social-beta-hardening
app-platform.trust-social-content-format-profiles
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
legacy-plugin.freeze-policy
legacy-plugin.migration-guide
legacy-plugin.social-inbox-spike
legacy-plugin.migration-finalization
reference-app.feed-reader
reference-app.feed-reader-subscriptions
reference-app.trust-graph
legacy.retirement
legacy-admin.removal-wave-1
legacy-admin.removal-wave-2
legacy-admin.removal-wave-3
legacy-admin.removal-wave-4
legacy-admin.removal-wave-5
legacy-admin.final-admin-surface
legacy-admin.browse-retained
legacy-admin.emergency-fallback-retained
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
operator-rc.dashboard
operator-rc.recovery-plan-execute
operator-rc.catalog-repair
operator-rc.app-reinstall-rollback
operator-rc.export-before-uninstall
operator-rc.subscription-recovery
operator-rc.app-service-grant-recovery
operator-rc.trust-graph-recovery
operator-rc.network-budget-visibility
operator-rc.support-bundle-wizard
operator-rc.redaction
app-review.trusted-receipts
app-review.policy
app-review.governance
app-review.reviewer-key-lifecycle
app-review.transparency-log
app-review.review-history-api
app-review.first-party-catalog
app-review.first-party-review-chain
app-platform.user-consent-flow
multi-node-beta.soak
multi-node-beta.upgrade-drill
multi-node-beta.catalog-channel-update
multi-node-beta.app-install-update-rollback
multi-node-beta.app-data-migration
multi-node-beta.backup-restore
multi-node-beta.subscription-pressure
multi-node-beta.trust-graph-import
multi-node-beta.social-inbox-multi-source
multi-node-beta.support-bundle-drill
multi-node-beta.redaction
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
The `public-beta.*` rows add the public-beta onboarding front door, user/operator guide,
install/update/rollback path, catalog/app path, permissions/consent path, Trust Graph and Social
Inbox limitations, third-party developer quickstart, app-submission walkthrough, troubleshooting,
security reporting, former plugin author path, support-bundle redaction warning, and local
public-beta link/redaction checks. PR-281 extends those rows with the public beta
support-feedback-loop gate: canonical support docs, structured issue templates, triage taxonomy,
known issue tracker, feedback-to-backlog workflow, beta release notes template, digest-first
support bundle guidance, security handoff, app-specific feedback, catalog incident reporting, and
positive/negative redaction fixtures. `public-beta.links-redaction` and
`public-beta.redaction-fixtures` scan for private insert URIs, private keys, tokens, raw support
bundles, raw fetched/social/trust/profile/feed/app-data content, unsafe file URI links, and
absolute local paths without fetching external URLs.
The `platform-api.stable-baseline` and `platform-api.stable-breaking-change-check` rows prove the
Platform API 1.0 baseline is present and compare stable capability names, stable endpoint
identities, stable endpoint required-capability sets, stable endpoint action labels, and stable
endpoint app-process/app-browser access flags against release history. `platform-api.compatibility-window`,
`platform-api.previous-contract-snapshot`, `platform-api.deprecation-window-policy`, and
`platform-api.experimental-graduation-policy` make the support-window metadata, previous snapshot
requirement, minimum removal windows, waiver boundaries, and future-baseline graduation process
release evidence. Production history mode fails closed when previous baseline, compatibility
window, or endpoint metadata is missing; developer dry runs warn instead of claiming production
comparison coverage. Critical stable removals, undeclared stable-baseline mutations, current
metadata gaps, production-beta history gaps, and redaction/security blockers are not waiverable.
The app-platform summary includes `stableDescriptorDeprecations` in `platform-api.contract`
details, and the deprecation-window row reports descriptor-level `descriptorErrors` and
`descriptorWarnings`. Stable descriptors with missing deprecation metadata, future
`deprecatedSinceContractVersion`, or too-short `removalContractVersion` windows fail the release
evidence before the go/no-go dashboard is generated.
`app-catalog.first-party-beta` reports source/key configuration readiness but does not fetch the
public Crypta catalog. `catalog.production-channels` verifies schema v3 stable/beta/nightly/
deprecated metadata, stable-only default update automation, deprecated replacement metadata, API
and Web Shell exposure, signature/review verification preservation, and redaction guarantees.
`catalog.operations-and-mirrors` verifies the primary source plus mirrors model, mirror transport
fallback with signed verification, stale/downgrade prevention, bounded verified revision history,
explicit rollback re-verification, key-rotation status, emergency advisory refresh, Platform API
routes, Web Shell rendering, docs coverage, and redaction without needing a live mirror or
production signing key.
The `catalog.security-advisories`, `catalog.version-denylist`,
`app-review.receipt-revocation`, `app-review.reviewer-key-compromise-flow`,
`app-update.security-denylist-gates`, `web-shell.security-advisory-trust-warnings`, and
`ecosystem-security.advisory-revocation-redaction` rows verify the Phase 9
`ecosystem-security-advisory-and-revocation` matrix row and
`ecosystem.security-advisory-revocation` gate. They prove catalog v4 security policy, exact
app-version denylist records, warning acknowledgement, install/update/stage/apply/scheduler
security gates, review receipt revocation, reviewer-key compromise handling, Web Shell warnings,
safe uninstall guidance, and redaction.
`app-platform.user-consent-flow` proves unified operator consent previews, digest-bound approval,
stale approval rejection, service-grant consent, app-data migration and backup consent,
automatic-update gating, redacted audit events, Web Shell UI, docs, and focused tests.
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
The `operator-rc.*` evidence verifies PR-257's
`operator-rc-recovery-and-support-workflow` matrix row and the
`ecosystem.operator-rc-recovery` gate. The checks cover host/operator-only route enforcement,
app-principal denial, closed action-id dispatch, plan-before-execute behavior, destructive
confirmation, one-time plan-token enforcement, catalog repair/reverify, app
rollback/reinstall/export-before-uninstall planning,
stuck-subscription recovery, app-service grant/bundle recovery, metadata-only Trust Graph recovery,
network-budget visibility, the support-bundle wizard, and redaction.
`app-platform.trust-graph-rc-scope-and-safety` verifies Trust Graph Local RC scope and safety:
local anchors, imported public signed statements, local lifecycle states, bounded score
explanations, redacted source metadata, read-only `trust.score` service boundaries, no crawling, no
global moderation or blocking, no routing decisions, no node-to-node trust propagation, and no
legacy WebOfTrust, Freetalk, Sone, or Freemail compatibility claim.
`reference-app.social-inbox-rc-threading` verifies the Social Inbox RC reference-app source for
local thread reconstruction, reply actions using the existing `replyTo` field, channel filters,
bounded local search, thread read/archive/pin actions, safe author profile display, mediated
Trust Graph service annotations only, additive schema-1 beta app-data records, and path-free
redacted evidence.
`app-platform.trust-social-beta-hardening` verifies PR-264 beta hardening across Trust Graph Local
RC and Social Inbox RC: import preview, duplicate issuer/conflict summaries, anchor lifecycle,
bounded score explanations, recovery/export/import docs, multi-source Social Inbox controls,
read/unread state, local mute/block filters, redacted message export, mediated app-service trust
annotations, additive schema readiness, consent markers, and redaction markers.
`app-platform.trust-social-content-format-profiles` verifies the shared registry, SDK mirrors,
AppVault/profile/social/trust builders, trust graph drift tests, reference app format-profile UI,
docs, malformed/oversized/unsupported/deprecated validation coverage, and production beta
content-format risk summaries without raw fetched content, raw document bodies, raw signatures,
private insert URIs, tokens, raw app-data values, or local paths.
`app-review.first-party-catalog`
also runs offline, but release-candidate mode requires explicit reviewer key inputs so the runner
can pack every staged first-party app and sign, verify, and embed a matching first-party review
receipt for each catalog entry. `interop.extended` and `apphost.live` are recorded as optional
stronger evidence. Extended interop is still required by the release runbook when
compatibility-sensitive behavior changed. Live AppHost lifecycle evidence is optional because
normal PR CI must not require a running node or operator credentials.

PR-258 final ecosystem RC certification is represented by the `ecosystem.rc-certification` gate
and the `ecosystem-rc-certification-gate` matrix row. That row summarizes whether the
release-candidate evidence set is complete enough for promotion. It is documented in
[../../docs/ecosystem-rc-certification-gate.md](../../docs/ecosystem-rc-certification-gate.md) and
does not replace the detailed required evidence listed above.

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
ecosystem.operator-rc-recovery
ecosystem.security-advisory-revocation
ecosystem.app-vault
ecosystem.sandbox-provider
ecosystem.reference-content-apps
ecosystem.multi-node-beta
ecosystem.legacy-retirement
ecosystem.live-network-beta
ecosystem.rc-certification
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
The `multi-node-beta-soak-and-upgrade-drill` row records PR-267 evidence for multi-node topology,
previous-candidate upgrade, app lifecycle, migration, backup, subscription pressure, Trust Graph,
Social Inbox, support bundle, and redaction checks.
The `previous-candidate-upgrade-path` row records PR-272 evidence for formal previous beta
candidate summary validation, previous-to-current upgrade drill status, app-data migration,
backup/restore, Social Inbox schema migration, Trust Graph state migration, rollback, failed-path
support bundle evidence, and redaction pass.
The `ecosystem-rc-certification-gate` row records final release-candidate readiness for
`ecosystem.rc-certification`: required evidence, emitted ecosystem gates, matrix coverage,
network-scale RC soak status, multi-node beta soak status, required live-network beta status,
waiver visibility, and redaction.
The row is documented in
[../../docs/ecosystem-rc-certification-gate.md](../../docs/ecosystem-rc-certification-gate.md).

In `release-candidate` mode, unmapped required evidence, unmapped ecosystem gates, missing docs,
or failed redaction make the matrix fail. In `pr` and `nightly` mode, coverage gaps are warnings
unless redaction fails. A previous summary that predates PR-231 and has no `ecosystemMatrix`
metadata does not fail by itself; `nightly` and `release-candidate` runs record a visible
`previous-missing` matrix warning so the release log can explain the first baseline transition.
Active waivers are projected onto matching row ids, evidence ids, gate ids, or issue ids. A waived
blocker row becomes `warn`, never a silent `pass`.

Required evidence that regresses from `pass` to `fail`, `missing`, or `skip` blocks
release-candidate promotion unless a visible waiver applies. `pass` to `warn` is a warning.
`legacy-plugin.freeze-policy`, `legacy-plugin.migration-guide`,
`legacy-plugin.social-inbox-spike`, `legacy-plugin.migration-finalization`,
`legacy-admin.removal-wave-3`,
`legacy-admin.removal-wave-4`, `legacy-admin.removal-wave-5`,
`legacy-admin.final-admin-surface`, `legacy-admin.browse-retained`, and
`legacy-admin.emergency-fallback-retained` are required release-candidate evidence. The plugin evidence
verifies that the old in-process plugin runtime is frozen and removed, that no in-core plugin
runtime/API surface has been reintroduced, that old plugin command names still map only to
deterministic unsupported responses, and that legacy plugin categories have a documented
out-of-process app-platform migration path without old plugin ABI or FCP command compatibility.
The finalization row proves the public-beta cookbook, migration matrix, examples, template,
app-service grant examples, data/identity/subscription preservation guidance, beta submission
flow, source-surface audit, redaction-negative fixtures, retained FProxy browse boundary, and
maintenance-only legacy admin boundary. Social Inbox remains the executable social/mail-like
migration spike. Wave 3 verifies only the
`security-levels` route, safe-read redirect behavior, mutating legacy fallback, retained
browse/filter/diagnostic/wizard surfaces, and redacted diagnostics counters without a live node.
Wave 5 verifies the maintenance-only final admin surface, retained FProxy browse/content
rendering, retained content filter, explicit startup/recovery and diagnostic support fallbacks, and
redacted route-id evidence without promoting unproven legacy routes.
Wave 4 verifies only the `diagnostic` route, Web Shell diagnostics at `/app/node/#diagnostics` as
the primary destination, the exact safe-read plaintext export fallback, retained
FProxy/content-filter/startup/security fallback scope, and evidence redaction without a live node.
Platform API contract version rollback, missing stable baseline metadata, stable
endpoint/capability removal, stable endpoint required-capability changes, stable endpoint
action-label changes, stable endpoint app-principal access regressions, first-party app
disappearance, missing Site Publisher evidence, strict first-party UI lint failure, review receipt
regression, update rollback regression, vault
capability/redaction regression, required enforced sandbox evidence loss, and missing legacy
removal-wave evidence are reported as ecosystem gate blockers.

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

Manual production beta pipeline GitHub Actions dispatches can also materialize prior JSON evidence
before the pipeline starts. For the `previous_summary`,
`previous_release_certification_summary`, `multi_node_soak_summary`, and `waiver_file` workflow
inputs, pass a local checked-out path, an HTTPS JSON URL, or a GitHub Actions artifact reference:

```text
actions-artifact://<run-id>/<artifact-name>/<path-inside-artifact>
```

The workflow restores these inputs into `$RUNNER_TEMP` and then passes the restored local path to
the release tool. Plain `http://` URLs, missing artifact paths, absolute artifact paths, and
artifact paths containing `..` are rejected before strict production-beta validation runs.

For `security_drills_summary`, pass a checked-out local path or an `actions-artifact://` reference
to `security-drills-summary.json` inside an artifact that also contains the seven per-scenario
drill JSON files beside the summary. HTTPS JSON URLs are rejected for this input because
`production_beta_release.py` re-verifies sibling drill artifacts and summary digests before the
attached evidence can contribute to promotion.

For `previous_summary`, strict validation runs
`multi_node_beta_soak.py verify-previous-summary --strict --max-age-days 90` before uploadable
production artifacts are accepted. Security drill summaries are validated by
`production_beta_release.py` and the go/no-go dashboard before promotion. The workflow must not
print raw summary bodies, private insert URIs, private keys, tokens, raw app data, raw social
message bodies, raw support bundle bodies, raw signatures, or raw trust statements.

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
The production beta go/no-go dashboard waiver schema is accepted by release certification too:
`schemaVersion` is treated like `version`, `rationale` is treated like `reason`, and
release-candidate scopes derive `allowReleaseCandidate=true`.
Redaction findings are not waiver material. Raw secrets, private URIs, credentials, raw payloads,
or local-path leaks keep the evidence, matrix row, and final ecosystem RC gate failing even when a
waiver targets the same evidence id, row id, gate id, or issue id.

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
`live-network-beta-certification` matrix row. Live-network beta remains optional when
`--require-live-network-beta` and `CRYPTAD_CERT_REQUIRE_LIVE_NETWORK_BETA=1` are absent; disabled
runs must ignore stale live summaries and must not copy stale live artifacts. When live-network
beta is enabled but not required, failing or missing live evidence is a warning. Required mode
turns the required `live-network-beta.*` evidence into release blockers.
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
