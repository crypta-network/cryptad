# Release certification tooling

This directory contains the release-candidate evidence aggregator used by the release runbook.

The tooling requires Python 3.10 or newer and depends only on the Python standard library.  The
self-tests do not start Cryptad, download a Hyphanet baseline, require signing keys, or contact the
network.

## Commands

Run the Python-only self-tests:

```bash
python3 tools/release-certification/release_certification.py --self-test
python3 tools/release-certification/app_platform_smoke.py --self-test
```

Generate a quick local report without running expensive Gradle or node gates:

```bash
tools/release-certification/run-release-certification.sh
```

The wrapper can be run from any working directory. Relative `--out-dir` values are resolved under
the repository root before shell cleanup, app-platform smoke generation, and certification
aggregation run.

Generate release-candidate evidence under the standard output directory:

```bash
tools/release-certification/run-release-certification.sh \
  --mode release-candidate \
  --out-dir build/release-certification
```

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
  artifacts/
  app-platform-smoke/
    summary.json
    app-platform-smoke-report.md
    artifacts/
```

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
app-platform.signed-bundles
catalog.smoke
app-catalog.first-party-beta
platform-api.contract
app-vault.capabilities
app-platform.identity-profile-publish
app-platform.generated-document-insert
app-platform.content-fetch
app-ui.design-system
app-ui.lint
app-ui.first-party-adoption
app-ui.smoke
reference-apps.content
reference-app.profile-publisher
reference-app.feed-reader
legacy.retirement
legacy-admin.removal-wave-1
apphost.sandbox-provider
app-update.lifecycle
app-update.scheduler
app-update.rollback
app-review.trusted-receipts
app-review.policy
app-review.first-party-catalog
```

`platform-api.contract`, `app-vault.capabilities`, `app-platform.identity-profile-publish`,
`app-platform.generated-document-insert`, `app-platform.content-fetch`,
`app-platform.developer-beta-toolkit`,
`app-ui.design-system`, `app-ui.lint`, `app-ui.first-party-adoption`,
`reference-apps.content`, `reference-app.profile-publisher`, `reference-app.feed-reader`, `apphost.sandbox-provider`, `app-update.lifecycle`,
`app-update.scheduler`, `app-update.rollback`, `app-catalog.first-party-beta`,
`app-review.trusted-receipts`, and
`app-review.policy` use deterministic source checks, fixtures, and fake/offline tests; they do not
require a live node or host-installed bubblewrap in normal CI. `app-catalog.first-party-beta`
reports source/key configuration readiness but does not fetch the public Crypta catalog.
`app-review.first-party-catalog`
also runs offline, but release-candidate mode requires explicit reviewer key inputs so the runner
can pack every staged first-party app and sign, verify, and embed a matching first-party review
receipt for each catalog entry. `interop.extended` and `apphost.live`
are recorded as optional stronger evidence. Extended interop is still required by the release runbook when
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

The comparison writes `history-comparison.json` and `history-comparison.md`, and embeds
`historyComparison` plus `ecosystemGates` in `release-certification-summary.json`. If no previous
summary is provided, `pr` mode records skipped history, while `nightly` and `release-candidate`
mode record a visible warning. Add `--require-history` when a release-candidate must fail without
a valid previous certified baseline.

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

Required evidence that regresses from `pass` to `fail`, `missing`, or `skip` blocks
release-candidate promotion unless a visible waiver applies. `pass` to `warn` is a warning.
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
sandbox-provider evidence, app-update lifecycle/scheduler/rollback evidence, independent
app-review receipt evidence, Profile Publisher identity-profile publishing evidence,
app-generated document insert evidence, content-fetch evidence, Feed Reader reference-app evidence,
and the legacy-admin retirement map.

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
CRYPTAD_CERT_NODE_BASE_URL=http://127.0.0.1:8888 \
CRYPTAD_CERT_FORM_PASSWORD=<redacted> \
tools/release-certification/run-release-certification.sh --mode nightly
```

The live smoke only records localhost node metadata.  It redacts the form password and does not
write raw request bodies.

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
- raw app-vault secret values, identity private keys, identity seeds, or recovery phrases;
- raw profile-document signatures or signed profile-document payloads;
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
