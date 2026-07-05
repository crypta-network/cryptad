# App Store Submission And Review Workflow

This document describes the local third-party app submission workflow added for Crypta app-store
review. It is an offline, deterministic packaging and review path, not a hosted public app store,
ranking service, payment system, or install-consent flow.

Public-beta app authors, reviewers, and release managers should start with
[public-beta/app-submission-walkthrough.md](public-beta/app-submission-walkthrough.md). This page
remains the detailed submission package, pre-review, decision, receipt, intake queue, transparency
log, and catalog-candidate source of truth.

The workflow turns a staged app bundle into a reviewable package:

```text
staged app / signed bundle
-> submission package
-> automated pre-review
-> reviewer decision
-> review receipt / rejection / caution metadata
-> transparency log event
-> catalog candidate descriptor
-> release certification evidence
```

The submission workflow does not approve installs or updates by itself. It records review status
and redacted reviewer evidence that the catalog, Web Shell, and unified consent layer can display
later. Install and update mutations still use the consent snapshot and digest checks described in
[user-consent-and-permission-upgrade-ux.md](user-consent-and-permission-upgrade-ux.md).

Third-party authors should start with
[third-party-developer-beta-program.md](third-party-developer-beta-program.md), prepare the
[third-party-app-submission-checklist.md](third-party-app-submission-checklist.md), and verify the
stability target against
[platform-api-compatibility-support-window.md](platform-api-compatibility-support-window.md) before
creating a package. Former plugin authors should also use
[legacy-plugin-migration-cookbook.md](legacy-plugin-migration-cookbook.md) before filing a
submission, because reviewers expect the migration plan, non-goals, redaction policy, and app/
app-service mapping to be explicit. The checked-in stable sample is
`samples/third-party/hello-stable-app/`.

## Submission Package

A submission package is a deterministic ZIP with this layout:

```text
crypta-app-submission.json
bundle/
  cryptad-app.properties
  static/...
  bin/...
artifacts/
  app-bundle.zip
  catalog-entry.properties
review/
  permission-rationale.md
  sandbox-rationale.md
  data-schema.md
  backup-restore.md
  security-notes.md
  changelog.md
metadata/
  maintainer.json
  source.json
```

`artifacts/catalog-entry.properties` and most review documents are optional unless the manifest
requires them. `artifacts/app-bundle.zip` is generated from the staged bundle with the existing
deterministic app bundle packager.

The top-level `crypta-app-submission.json` uses schema version `1` and records:

- `submissionId`
- `submissionCreatedAt`
- `submissionType`: `new_app`, `update`, or `resubmission`
- `resubmissionOf` for resubmissions
- `appId`
- `appVersion`
- `bundleDigest`
- `bundleSignatureKeyId` when the staged bundle has a signature sidecar
- `catalogEntryDigest` when a catalog descriptor is supplied
- `apiTargetStability`
- `experimentalCapabilitiesAccepted`
- `requestedPermissions`
- `permissionRationaleDigest` when a permission rationale is supplied
- `sandboxRequirement`
- `appDataSchemaDeclared`
- `appDataMigrationDeclared`
- `backupRestoreDeclared`
- `maintainer`
- `sourceReference`
- `redactionScanDigest`
- `nonProduction`

The package writer emits fixed-time STORED ZIP entries in lexicographic order. If
`--submission-created-at` and `--submission-id` are omitted, local tooling uses deterministic
fixture-safe values derived from the bundle identity and artifact digest.

## Developer Flow

Create a submission package from a staged bundle:

```bash
crypta-app submission create \
  --bundle-dir apps/example/build/cryptad-app/example \
  --output build/submissions/example-submission.zip \
  --submission-type new_app \
  --permission-rationale review/permission-rationale.md \
  --sandbox-rationale review/sandbox-rationale.md \
  --data-schema review/data-schema.md \
  --backup-restore review/backup-restore.md \
  --security-notes review/security-notes.md \
  --changelog review/changelog.md \
  --maintainer-name "Example Maintainer" \
  --maintainer-contact "mailto:maintainer@example.invalid" \
  --source-url "https://example.invalid/repo" \
  --non-production
```

Verify it offline:

```bash
crypta-app submission verify \
  --submission build/submissions/example-submission.zip
```

Verification checks package layout, path normalization, metadata-to-manifest binding, artifact
digests, rationale requirements, app-data declarations, and redaction cleanliness. It does not
fetch network content.

## Required Rationale Files

`review/permission-rationale.md` is required when `app.permissions` is non-empty. It should explain
each requested permission family in operator-facing terms.

`review/sandbox-rationale.md` is required when `sandbox.mode` is not `none` or
`sandbox.required=true`.

`review/data-schema.md` is required when the manifest declares app-data schema or migration
metadata.

`review/backup-restore.md` is required when the app owns durable app data. The app may state that
backup/restore is unsupported, but that unsupported state must be explicit and explained.

`review/security-notes.md` and `review/changelog.md` are optional review context unless a reviewer
policy requires them.

Former plugin authors should include a migration-plan review note based on
[templates/plugin-migration-plan.md](templates/plugin-migration-plan.md). Reviewers use it to
check state classification, AppVault boundaries, app-service grants, content subscription limits,
backup/restore behavior, explicit unsupported old plugin behavior, and redaction.

## API Stability Rules

Third-party submissions inherit the Platform API 1.0 rules from
[platform-api-1.0-stable-reference.md](platform-api-1.0-stable-reference.md).

Stable-target apps must set `api.targetStability=stable` and use only stable app-facing
capabilities. They must not request experimental capabilities unless a reviewer policy explicitly
allows the app to target experimental APIs and the manifest changes to
`api.targetStability=experimental`.

Experimental app-facing APIs require `api.targetStability=experimental` and
`api.experimentalCapabilitiesAccepted=true`.

Internal or host/operator-only capabilities always fail third-party submission pre-review.

The pre-review API compatibility artifact must include the current contract snapshot and the
support-window result from `crypta-app api policy` or equivalent release evidence. Stable
submission review relies on the same Platform API 1.0 compatibility-window policy that production
beta release certification enforces: previous contract snapshots are required for production
promotion, stable deprecation/removal windows must meet policy, and critical stable removals are
not waiverable.

## Automated Pre-Review

Run pre-review after package verification:

```bash
crypta-app submission pre-review \
  --submission build/submissions/example-submission.zip \
  --contract platform-api-contract.json \
  --output build/submissions/example-pre-review.json
```

Before pre-review, reviewers can reproduce the API-only check:

```bash
crypta-app api snapshot --output build/submissions/platform-api-contract.json
crypta-app api policy \
  --contract build/submissions/platform-api-contract.json \
  --output build/submissions/platform-api-policy.json
crypta-app compat verify \
  --bundle-dir apps/example/build/cryptad-app/example \
  --contract build/submissions/platform-api-contract.json \
  --target-stability stable \
  --strict \
  --json build/submissions/example-api-compatibility.json
```

The report is deterministic JSON:

```json
{
  "schemaVersion": 1,
  "submissionId": "sub-...",
  "appId": "example",
  "appVersion": "1.0.0",
  "status": "pass",
  "promotionReady": true,
  "findings": [],
  "artifacts": {
    "submissionDigest": "...",
    "bundleDigest": "...",
    "manifestDigest": "..."
  }
}
```

Finding severities are:

- `blocker`: the package cannot be promoted or receive a reviewed/caution receipt.
- `warning`: the package can continue, but reviewers must preserve the warning.
- `info`: evidence-only context.

Pre-review runs package integrity checks, bundle validation, Platform API compatibility checks, UI
lint, rationale checks, sandbox declaration checks, app-data checks, backup/restore checks, and
redaction checks.

## Reviewer Decisions

Record a final decision:

```bash
crypta-app submission decide \
  --submission build/submissions/example-submission.zip \
  --pre-review build/submissions/example-pre-review.json \
  --decision reviewed \
  --reviewer-key-id reviewer-dev \
  --reviewer-private-key reviewer-dev.key \
  --trusted-reviewer-keys trusted-reviewers.properties \
  --reason review-decision.md \
  --receipt-output build/submissions/example-review-receipt.properties \
  --transparency-log build/review-transparency.jsonl \
  --allow-non-production
```

`reviewed` and `caution` decisions issue an independent review receipt using the existing review
receipt mechanism. The receipt binds reviewer key id, policy id/version, app id, app version,
bundle digest, bundle artifact size, pre-review digest, and the SHA-256 digest of
`--reason`. Receipts that include the decision-rationale digest use
`review.receipt.version=2`; existing v1 receipts remain supported only when they omit that field.

`rejected` decisions write rejection metadata when `--rejection-output` is supplied and append
rejection transparency events, but they do not create installable catalog candidates.

Production decisions fail closed when the submission is marked `nonProduction` or the reviewer key
id looks like a test/development key unless `--allow-non-production` is supplied.

## Caution And Rejection

`caution` means the reviewer allows a catalog candidate only with operator-visible warning
metadata. Caution candidates require an explicit catalog policy choice, represented in local
tooling by `--allow-caution`.

`rejected` means the submitted artifact must not become an installable reviewed catalog entry.
Rejected submissions can still be linked by a later `resubmission` package through
`resubmissionOf`.

## Catalog Candidate

Create a candidate descriptor after a reviewed or caution receipt exists:

```bash
crypta-app submission catalog-candidate \
  --submission build/submissions/example-submission.zip \
  --review-receipt build/submissions/example-review-receipt.properties \
  --trusted-reviewer-keys trusted-reviewers.properties \
  --output build/submissions/example-catalog-entry.properties \
  --allow-caution
```

The descriptor includes app identity, artifact digest, API stability metadata, submission id,
submission digest, pre-review digest, reviewer key id, reviewer policy, review receipt
fingerprint, reviewer decision-rationale digest, resubmission link, and the non-production marker
when applicable. Rejected receipts are refused. Third-party candidate descriptors emit
`catalog.version=6` metadata when converted into signed catalogs, and they are not promoted into
first-party stable channels automatically. The command verifies the receipt signature and reviewer
key against the local trusted reviewer registry before writing any candidate descriptor or copied
artifact.

The Web Shell and local catalog API expose this workflow metadata as `thirdPartyReview`, separate
from publisher advisory `review` metadata and independent trusted receipt `reviewTrust` evaluation.

## Public Beta Intake Queue

Public beta intake wraps the existing submission package, pre-review, decision, transparency-log,
and catalog-candidate commands in a file-backed local queue. The queue is operated by beta
reviewers or release managers, not by third-party apps. Queue records store safe metadata only:
submission ids, SHA-256 digests, app identity, requested permissions, reviewer assignment state,
pre-review status, decision status, receipt fingerprints, candidate digests, beta channel status,
redaction status, and warnings. They do not contain raw ZIP contents, raw rationale text, private
keys, private insert URIs, app tokens, browser session tokens, raw fetched content, raw app data,
or absolute local paths.

An end-to-end beta intake run uses the `crypta-app submission intake` commands:

```bash
CRYPTA_APP=build/install/platform-devtools/bin/crypta-app

"$CRYPTA_APP" submission create \
  --bundle-dir samples/third-party/hello-stable-app \
  --output build/submissions/hello-stable-submission.zip \
  --submission-type new_app \
  --maintainer-name "Example Maintainer" \
  --maintainer-contact "https://example.invalid/contact" \
  --source-url "https://example.invalid/hello-stable" \
  --permission-rationale samples/third-party/hello-stable-app/review/permission-rationale.md \
  --sandbox-rationale samples/third-party/hello-stable-app/review/sandbox-rationale.md \
  --data-schema samples/third-party/hello-stable-app/review/data-schema.md \
  --backup-restore samples/third-party/hello-stable-app/review/backup-restore.md \
  --security-notes samples/third-party/hello-stable-app/review/security-notes.md \
  --changelog samples/third-party/hello-stable-app/review/changelog.md

"$CRYPTA_APP" submission intake import \
  --queue-dir build/app-intake \
  --submission build/submissions/hello-stable-submission.zip \
  --transparency-log build/app-intake/review-transparency.jsonl

"$CRYPTA_APP" submission intake assign \
  --queue-dir build/app-intake \
  --submission-id sub-... \
  --reviewer-key-id reviewer-prod-1 \
  --trusted-reviewer-keys config/trusted-reviewers.properties \
  --reason docs/review-assignment-reason.md \
  --transparency-log build/app-intake/review-transparency.jsonl

"$CRYPTA_APP" submission intake pre-review \
  --queue-dir build/app-intake \
  --submission-id sub-... \
  --artifacts-dir build/app-intake/artifacts/sub-... \
  --transparency-log build/app-intake/review-transparency.jsonl

"$CRYPTA_APP" submission intake decide \
  --queue-dir build/app-intake \
  --submission-id sub-... \
  --decision reviewed \
  --reviewer-key-id reviewer-prod-1 \
  --reviewer-private-key-env CRYPTAD_APP_REVIEWER_PRIVATE_KEY \
  --trusted-reviewer-keys config/trusted-reviewers.properties \
  --reason docs/review-decision-reason.md \
  --decision-dir build/app-intake/decisions/sub-... \
  --transparency-log build/app-intake/review-transparency.jsonl

"$CRYPTA_APP" submission intake stage-candidate \
  --queue-dir build/app-intake \
  --submission-id sub-... \
  --trusted-reviewer-keys config/trusted-reviewers.properties \
  --beta-candidate-dir build/beta-catalog-candidates \
  --bundle-uri https://example.invalid/crypta-apps/hello-stable.zip \
  --decision-dir build/app-intake/decisions/sub-... \
  --transparency-log build/app-intake/review-transparency.jsonl

"$CRYPTA_APP" submission intake install-smoke \
  --queue-dir build/app-intake \
  --submission-id sub-... \
  --beta-candidate-dir build/beta-catalog-candidates \
  --transparency-log build/app-intake/review-transparency.jsonl

"$CRYPTA_APP" review transparency verify \
  --log-file build/app-intake/review-transparency.jsonl
```

`submission intake list --queue-dir build/app-intake --json` exports redacted summaries for Web
Shell diagnostics, release certification, and audit review. Reviewer assignment validates a trusted
reviewer key id when a registry is supplied, records the display name and assignment reason digest,
and appends an audit event. Reassignment requires a new reason and creates a second assignment
event.

`submission intake pre-review` writes `pre-review.json`, `submission-verification.json`,
`api-compatibility.json`, `ui-lint.json`, `redaction-scan.json`, and `artifact-manifest.json`
under the requested artifacts directory. The artifact manifest records relative paths and SHA-256
digests. Third-party packages that request internal/operator-only capabilities fail pre-review.
Findings with blockers prevent `reviewed` and `caution` decisions; reviewers can still record
`rejected` or `resubmission_requested`.

`submission intake decide` records one of `reviewed`, `caution`, `rejected`, or
`resubmission_requested`. Reviewed and caution decisions issue review receipts. Rejected and
resubmission-requested decisions store decision reason digests and transparency events but do not
produce installable candidates. Production decisions fail closed for non-production submissions or
test reviewer keys unless the caller explicitly uses the developer/test escape hatch.

`submission intake stage-candidate` writes a beta candidate directory with
`catalog-candidate.properties`, `app-bundle.zip`, `candidate-manifest.json`,
`candidate-review-receipt.properties`, and a candidate transparency export when a log path is
supplied. It verifies the receipt against trusted reviewer keys before writing the candidate.
Reviewed submissions can be staged directly. Caution submissions require `--allow-caution` and keep
operator-visible warnings in the candidate metadata. Rejected submissions cannot be staged. Staging
leaves the queue record at `staged_to_beta_catalog` with `installSmokeStatus=pending`; it does not
claim install-from-beta-catalog smoke success.

`submission intake install-smoke` is the local structural install-from-beta-catalog proof. It
re-inspects the staged catalog descriptor, the referenced bundle ZIP, the candidate review receipt,
the third-party review metadata, and the candidate manifest before writing
`candidate-install-smoke.json` and updating the queue record to `beta_install_smoke_passed`.

The local operator API exposes safe diagnostics under `/api/v1/operator/app-submissions` when the
queue directory is configured with `cryptad.appSubmissionIntakeDir` or
`CRYPTAD_APP_INTAKE_QUEUE_DIR`. These routes are operator/internal diagnostics, not part of the
stable third-party app-facing Platform API 1.0 surface.

## Transparency Log

Submission tooling can append local hash-chained transparency log events:

- `submission_created`
- `pre_review_completed`
- `review_decision_recorded`
- `review_receipt_issued`
- `submission_rejected`
- `submission_resubmitted`
- `catalog_candidate_created`

Verify the log with:

```bash
crypta-app review transparency verify \
  --log-file build/review-transparency.jsonl
```

The log records digests, ids, status values, reviewer key ids, and policy ids only. It is local
tamper-evident evidence, not a global public transparency service and not an authorization gate.

## Redaction Rules

Submission creation, verification, pre-review, decision metadata, transparency records, and release
certification fail closed or redact when they encounter:

- private keys
- reviewer private keys
- app signing private keys
- bearer tokens
- authorization headers
- browser session tokens
- private insert URIs
- raw fetched content
- raw app data
- local absolute paths
- AppleDouble files
- `__MACOSX/`
- `.DS_Store`
- multiline untrusted descriptor values

Reports use digests, fingerprints, relative paths, ids, and short status summaries. Do not paste raw
package contents, rationale bodies, receipt signatures, request bodies, private insert URIs, or
local paths into issue templates or release evidence.

## Release Certification

Release certification includes deterministic PR-262 evidence:

- `app-store.submission-package-schema`
- `app-store.submission-cli`
- `app-store.pre-review`
- `app-store.review-decision-states`
- `app-store.review-receipt-issued`
- `app-store.rejection-record`
- `app-store.resubmission-link`
- `app-store.transparency-log`
- `app-store.catalog-candidate`
- `app-store.third-party-sample-flow`
- `app-store.redaction-clean`

The sample flow is fixture-safe and non-production. It covers submission creation, offline
verification, pre-review, reviewed receipt issuance, transparency-log verification, catalog
candidate generation, rejected-decision metadata, and resubmission linkage.

PR-273 adds deterministic public-beta intake evidence:

- `third-party-intake.queue-schema`
- `third-party-intake.import`
- `third-party-intake.reviewer-assignment`
- `third-party-intake.pre-review-artifacts`
- `third-party-intake.review-decision`
- `third-party-intake.resubmission-flow`
- `third-party-intake.catalog-candidate-staging`
- `third-party-intake.beta-catalog-install-smoke`
- `third-party-intake.transparency-export`
- `third-party-intake.rejected-candidate-blocked`
- `third-party-intake.caution-warning`
- `third-party-intake.redaction`

These rows prove sample app package creation, intake import, reviewer assignment, pre-review
artifacts, reviewed/caution/rejected/resubmission decisions, beta catalog candidate staging,
install-from-beta-catalog smoke status, transparency export verification, rejected-candidate
blocking, caution warnings, and redaction. Fixture evidence remains non-production and must not be
used as production promotion evidence.

PR-281 support-feedback-loop evidence links review appeals, app submission feedback, compatibility
reports, known issues, backlog candidates, and beta release notes. Use
[public-beta/support-and-feedback.md](public-beta/support-and-feedback.md),
[public-beta/feedback-to-backlog.md](public-beta/feedback-to-backlog.md), and
[templates/beta-release-notes.md](templates/beta-release-notes.md) for the redaction-safe loop.

## Out Of Scope

This workflow does not provide:

- a centralized hosted submission portal
- public app-store search, ranking, payments, or user reviews
- install/update consent UX
- permission upgrade UX
- social trust-graph hardening
- network protocol changes
- legacy plugin compatibility
- production reviewer credentials or private keys
