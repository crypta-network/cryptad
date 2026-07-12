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
URI, previous-candidate/history inputs, soak inputs, Stable requirement, waivers, and execution
controls. Signing keys, reviewer keys, form passwords, live insert material, and other secrets stay
in protected environment variables or protected files.

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
| `production-beta` | Requires production signing, a complete in-pipeline Gradle build/stage/sign/verify run, live-network evidence, sandbox evidence, previous-candidate upgrade evidence, and a clean workspace. | Promotion is ready only when every mandatory gate and redaction result passes. |
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

Outputs live under `<out-root>/<release-id>/production-beta/`. The component writes the common
`summary.json`, `report.md`, `redaction-report.json`, and its catalog, review, evidence, security,
distribution, checksum, and archive files below `artifacts/`.

A rerun must use `output.reset=true` and a matching release marker. The command refuses unmarked
directories and never reuses stale dashboard, soak, Stable, archive, or checksum artifacts.

## Publication gates

CI may upload or publish the workspace only when release artifact redaction, go/no-go redaction,
and any required Stable redaction all pass. Private interop insert URIs, raw support bundles, raw
diagnostics, AppleDouble files, `.DS_Store`, `__MACOSX`, secret-like filenames, symlinks, and unsafe
nested archives remain excluded.
