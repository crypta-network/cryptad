# App Store Submission And Review Workflow

This document describes the local third-party app submission workflow added for Crypta app-store
review. It is an offline, deterministic packaging and review path, not a hosted public app store,
ranking service, payment system, or install-consent flow.

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
creating a package. The checked-in stable sample is
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

## API Stability Rules

Third-party submissions inherit the Platform API 1.0 rules from
[platform-api-1.0-stable-reference.md](platform-api-1.0-stable-reference.md).

Stable-target apps must set `api.targetStability=stable` and use only stable app-facing
capabilities. They must not request experimental capabilities unless a reviewer policy explicitly
allows the app to target experimental APIs.

Experimental app-facing APIs require `api.targetStability=experimental` and
`api.experimentalCapabilitiesAccepted=true`.

Internal or host/operator-only capabilities always fail third-party submission pre-review.

## Automated Pre-Review

Run pre-review after package verification:

```bash
crypta-app submission pre-review \
  --submission build/submissions/example-submission.zip \
  --contract platform-api-contract.json \
  --output build/submissions/example-pre-review.json
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
