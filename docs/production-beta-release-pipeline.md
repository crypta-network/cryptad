# Production beta release pipeline

Use the production beta command to build, certify, redact, and package a first-party app ecosystem
candidate in one release-scoped workspace.

## Run the pipeline

Copy the example manifest and replace every placeholder:

```bash
cp tools/release-certification/manifests/production-beta.example.json \
  build/production-beta.json
python3 tools/release-certification/certify.py production-beta \
  --manifest build/production-beta.json
```

The manifest selects the profile, candidate identity, catalog channel, public HTTPS artifact base
URI, previous-candidate/history inputs, third-party intake summary, soak inputs, Stable requirement,
waivers, and execution controls. Signing keys, reviewer keys, form passwords, live insert material,
and other secrets stay in protected environment variables or protected files.

For a protected `.github/workflows/production-beta-release.yml` dispatch, set
`third_party_intake_summary` to a release-capable intake summary. The workflow accepts a checked-out
path, HTTPS JSON URL, or `actions-artifact://<run-id>/<artifact-name>/<path>` reference. It refuses
to construct the production manifest when the summary is absent, sets
`requirements.thirdPartyIntake=true`, and binds the materialized path as
`inputs.thirdPartyIntake`. The deterministic sample-flow option is non-release evidence and cannot
replace this production input.

For a local CI-safe exercise, use:

```bash
python3 tools/release-certification/certify.py production-beta \
  --manifest tools/release-certification/manifests/developer-dry-run.json
```

## Profiles

| Profile | Signing and network behavior | Promotion behavior |
| --- | --- | --- |
| `developer-dry-run` | May use generated fixture keys and omit live evidence. | Always remains non-release and not promotion-ready. |
| `release-candidate` | Requires staged/signed/verified apps, catalog and review artifacts, certification, and a public HTTPS artifact base URI. | Fails on critical missing evidence; candidate signing labels may remain non-production. |
| `production-beta` | Requires production signing, a complete in-pipeline Gradle build/stage/sign/verify run, live-network evidence, third-party intake, sandbox evidence, previous-candidate upgrade evidence, and a clean workspace. | Promotion is ready only when every mandatory gate and redaction result passes. |
| `stable-review` | Adds the Stable policy, limitations, freshness, and complete Stable domain requirements. | Stable readiness must pass before archive publication. |

Fixture evidence, skipped Gradle stages, emergency build skips, dirty or unknown workspace state,
test signing, missing live evidence, and missing previous-candidate upgrade evidence cannot produce
a promotable production-beta result.

Security drill operations and incident-response evidence follow the
[production security response runbook](production-security-response-runbook.md).

## Pipeline stages

The pipeline orchestrates:

1. Gradle build and developer-tool installation.
2. First-party app staging, signing, and verification.
3. Signed catalog, channel metadata, and trusted review receipt generation.
4. App-platform, documentation, live-network, network-scale, multi-node, and security-drill
   evidence collection.
5. Release certification and ecosystem matrix evaluation.
6. Production beta go/no-go evaluation and optional Stable readiness.
7. Recursive artifact redaction, checksum generation, and public archive creation.

All component summaries use evidence envelope v2 and carry the same release ID. Consumers reject
wrong-candidate, wrong-kind, malformed, incomplete, stale, or redaction-unsafe summaries.
Attached unified evidence must use the expected envelope kind and the manifest's candidate ID;
native interop, performance, ecosystem-matrix, and third-party-intake inputs keep their documented
legacy contracts. The adapter scans an attached envelope's legacy payload before extraction rather
than trusting the outer redaction claim. It also verifies and scans every referenced security-drill
sidecar before copying it into the release workspace. Configured live-network and network-scale
summary paths remain the source for their production evidence extracts.

## Previous-candidate evidence

Production beta requires a validated previous candidate and release-history record. The multi-node
upgrade drill must bind the previous summary digest and cover daemon upgrade, app-data migrations,
backup before update, clean-node restore, failed-migration rollback, Social Inbox migration, Trust
Graph migration, and a redacted support bundle after failure.

Use `certify.py migrate-v1` for the first v2 candidate. Set `inputs.previousCandidate` and
`inputs.releaseHistory` to the resulting candidate-bound v2 migration summaries. Normal production
commands do not accept v1 history directly.

Choose the production candidate release ID before migration and use it as `release.id` in both the
migration manifest and the production manifest. For a protected workflow dispatch, supply the same
value through `candidate_release_id`. This stable ID lets the workflow validate artifacts prepared
before its GitHub run ID exists.
Developer and release-candidate workflow dispatches must also supply `candidate_release_id` when
attaching a pre-generated multi-node or security-drill v2 summary; those summaries carry the same
candidate binding even when history is not attached.

## Output and reruns

Outputs live under `<out-root>/<release-id>/production-beta/`. The component writes the common v2
`summary.json`, `report.md`, and `redaction-report.json`. Engine-native catalog, review, evidence,
security, distribution, checksum, archive, and detailed dashboard output lives below
`artifacts/legacy/`. In particular, release managers should inspect:

```text
<out-root>/<release-id>/production-beta/artifacts/legacy/reports/go-no-go-dashboard.json
<out-root>/<release-id>/production-beta/artifacts/legacy/reports/go-no-go-dashboard.md
<out-root>/<release-id>/production-beta/artifacts/legacy/reports/go-no-go-redaction-report.json
<out-root>/<release-id>/production-beta/artifacts/legacy/evidence/
<out-root>/<release-id>/production-beta/artifacts/legacy/dist/checksums.txt
```

Validated attached input extracts live under `artifacts/inputs/`. Those extracts are diagnostic
copies, not a way to bypass candidate binding or redaction checks.

A rerun must use `output.reset=true` and a matching release marker. The command refuses unmarked
directories and never reuses stale dashboard, soak, Stable, archive, or checksum artifacts.
All output directories and files are checked for symlinks before use. If production setup exits
early, an engine returns nonzero, or a fallback payload scan finds unsafe material, the adapter
removes the unsafe raw output and writes only a sanitized failed v2 envelope with
`promotionReady=false`.

## Publication gates

CI may upload or publish the workspace only when release artifact redaction, go/no-go redaction,
and any required Stable redaction all pass. Private interop insert URIs, raw support bundles, raw
diagnostics, AppleDouble files, `.DS_Store`, `__MACOSX`, secret-like filenames, symlinks, and unsafe
nested archives remain excluded.
