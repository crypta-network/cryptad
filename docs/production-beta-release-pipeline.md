# Production beta release pipeline

This document describes the command that builds, certifies, redacts, and packages a Crypta
app-ecosystem production beta candidate.

## Scope

The production beta pipeline is a release-manager workflow for first-party app ecosystem artifacts.
It does not rewrite the app platform, change peer protocols, or publish a public app store by
itself. It combines the existing Gradle build, first-party app staging tasks, `crypta-app` signing
and catalog tools, app-platform smoke checks, live-network beta evidence, network-scale soak
evidence, first-party app maintenance policy metadata, user-consent flow evidence, ecosystem RC
certification, multi-node beta soak and upgrade evidence, and final artifact redaction.

The entrypoint is:

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

Add multi-node drill flags when a release run needs a specific topology or attached evidence:

```bash
tools/release-certification/run-production-beta-release.sh \
  --mode developer-dry-run \
  --multi-node-mode simulated \
  --run-multi-node-soak
```

Use `--multi-node-soak-config <path>` for a topology config, `--multi-node-soak-summary <path>` to
attach existing evidence, and `--require-multi-node-soak` to make the promotion gate fail closed
outside production beta mode.

Protected `production-beta` workflow dispatches must provide either a production multi-node topology
config or an attached passing multi-node summary. The checked-in self-test topology is only for
developer dry-runs and PR-safe validation because it intentionally leaves previous-candidate
upgrade evidence as a warning.

Relative `--out-dir` values are resolved under the workspace root. The command cleans that output
directory by default only when it is under the dedicated `build/production-beta*` prefix or already
contains the `.cryptad-production-beta-release-output` sentinel from an earlier pipeline run.
Source-controlled workspace areas such as `docs`, `tools`, `apps`, `.git`, and `.github` are
refused as output directories. Use `--no-clean-out-dir` only when inspecting a failed run and you
understand which artifacts may be stale. The `dist/` directory is regenerated on every run, even
when `--no-clean-out-dir` is used, so stale public archives or side files are not preserved for
upload.

## Modes

| Mode | Use | Signing and network behavior | Promotion behavior |
| --- | --- | --- | --- |
| `developer-dry-run` | Local and PR-safe pipeline exercise. | Uses configured keys when present, otherwise generates ephemeral non-production keys outside the artifact tree. Live network is not required. If no artifact base URI is supplied, the command uses a `.invalid` non-release URI. | Exits successfully only when pipeline commands and redaction pass, and always marks artifacts as `nonRelease=true` and `promotionReady=false`. |
| `release-candidate` | Release branch or manual candidate evidence. | Requires staged apps, signed bundles, signed catalog artifacts, review receipts, smoke summaries, ecosystem certification, and a real HTTPS artifact base URI. Test keys are allowed when no release keys are configured, and outputs remain labeled non-production. | Fails on critical missing evidence. Promotion is not marked ready unless all production-beta-only requirements are also satisfied. |
| `production-beta` | Protected production beta candidate build. | Requires real signing/reviewer inputs, a full in-pipeline Gradle build/stage/sign run, a real HTTPS artifact base URI, app-platform evidence, sandbox evidence, ecosystem RC certification, and live-network beta evidence unless an explicitly named emergency/test flag is used. | Fails closed when critical evidence, live evidence, production signing, a complete build, or redaction is missing. |

`--use-fixture-evidence` is accepted only with `developer-dry-run` and internal self-tests. Strict
`release-candidate` and `production-beta` runs reject fixture evidence before certification.

Production beta supports three explicit test/emergency escape hatches:

- `--emergency-skip-live-network` records that live-network evidence was skipped. The run still
  records a failed live-skip gate and keeps `promotionReady=false`.
- `--emergency-skip-build` allows a controlled test or emergency run to continue after
  `--skip-gradle` or `--skip-full-build`. The run still records a failed build-complete gate,
  sets `nonRelease=true`, and keeps `promotionReady=false`.
- `--allow-test-signing-in-production` permits a controlled test run of production-beta mode with
  non-production signing labels. It sets `nonRelease=true`, keeps `promotionReady=false`, and must
  not be used for release publication.

Production beta requires `production-security.response-runbook` evidence. Missing runbook
documentation, drill model, reviewer compromise drill, catalog key rotation drill, app signing key
compromise drill, emergency catalog update drill, support redaction proof, or security release
notes template is a production blocker. The runbook procedure is
[production-security-response-runbook.md](production-security-response-runbook.md).

Production beta mode requires multi-node beta soak evidence by default. Missing soak,
upgrade-drill, scenario, or redaction evidence keeps `promotionReady=false`. Developer dry-runs may
run the deterministic simulated drill without live nodes and may show warnings for missing previous
candidate summaries.

## Required inputs

Dry-runs do not require release secrets. Production beta requires configured signing and review
inputs through environment variables or protected files:

| Input | Purpose |
| --- | --- |
| `CRYPTAD_PRODUCTION_BETA_ARTIFACT_BASE_URI` or `--artifact-base-uri` | Public HTTPS base URI where the production beta artifact layout will be published. Signed catalog bundle URLs resolve under this root, for example `<base>/build/app-bundles/<app>-<version>.zip`. Required for `release-candidate` and `production-beta`; `.invalid`, localhost, query-string, and credentialed URIs are rejected. |
| `CRYPTAD_APP_SIGNING_KEY_ID` | Key id written into first-party bundle and catalog signatures. |
| `CRYPTAD_APP_SIGNING_PRIVATE_KEY_FILE` or `CRYPTAD_APP_SIGNING_PRIVATE_KEY_BASE64` | App/catalog signing private key source. Prefer protected files in CI. |
| `CRYPTAD_APP_SIGNING_PUBLIC_KEY_FILE` or `CRYPTAD_APP_SIGNING_PUBLIC_KEY_BASE64` | Trusted public key for bundle and catalog verification. |
| `CRYPTAD_APP_REVIEWER_KEY_ID` | Reviewer key id written into first-party review receipts. |
| `CRYPTAD_APP_REVIEWER_PRIVATE_KEY_FILE` or `CRYPTAD_APP_REVIEWER_PRIVATE_KEY_BASE64` | Reviewer private key source. |
| `CRYPTAD_APP_REVIEWER_PUBLIC_KEY_FILE` or `CRYPTAD_APP_REVIEWER_PUBLIC_KEY_BASE64` | Trusted reviewer public key source. |
| `CRYPTAD_APP_REVIEW_POLICY_ID` | Review policy id. Defaults to `crypta-app-review-v1`. |
| `CRYPTAD_APP_REVIEW_POLICY_VERSION` | Review policy version. Defaults to `1`. |
| `CRYPTAD_CERT_NODE_BASE_URL` | Local node URL for live-network beta evidence. It must be localhost-only. |
| `CRYPTAD_CERT_FORM_PASSWORD` | Local node form password for live collectors. Pass it through the environment only. |
| Live fixture variables from `live_network_beta_smoke.py` | Catalog source, expected catalog key id, content/feed/profile/trust fixtures, and protected private insert URI indirection for required live evidence. |
| `CRYPTAD_CERT_LIVE_TEST_INSERT_URI_ENV=CRYPTAD_CERT_LIVE_TEST_INSERT_URI` plus `CRYPTAD_CERT_LIVE_TEST_INSERT_URI` | GitHub Actions production-beta runs use this environment-name indirection for the private insert URI fixture. The raw URI lives only in the secret-valued `CRYPTAD_CERT_LIVE_TEST_INSERT_URI` variable. |

Do not pass private keys, private insert URIs, form passwords, app tokens, or browser session tokens
as command-line arguments.

## Artifact layout

The production beta command writes this deterministic public layout:

```text
build/production-beta-release/
  inputs/
    release-config.json
    first-party-app-maintenance-policy.json
  build/
    staged-apps/
    app-bundles/
    crypta-app-launcher/
  catalog/
    first-party-catalog.properties
    cryptad-app-catalog.signature
    first-party-catalog.sig
    channel-metadata.json
  reviews/
    review-receipts/
    review-transparency-log.json
  evidence/
    api-compatibility.json
    app-ui-lint.json
    sandbox-provider-tests.json
    app-platform-smoke.json
    live-network-beta-smoke.json
    network-scale-soak.json
    multi-node-beta-soak.json
    ecosystem-rc-certification.json
    ecosystem-certification-matrix.json
  reports/
    production-beta-summary.json
    production-beta-summary.md
    redaction-report.json
  dist/
    crypta-production-beta-<version>.tar.gz
    checksums.txt
```

Temporary descriptors, generated test private keys, trusted-key scratch files, and raw command work
directories are kept outside the public artifact tree.

## Summary files

`reports/production-beta-summary.json` is the machine-readable result. Important fields:

| Field | Meaning |
| --- | --- |
| `status` | `pass` when command execution and redaction passed. For release-candidate and production-beta runs, critical promotion gates must also pass. |
| `promotionReady` | `true` only for production-beta mode when the final summary `status` is `pass`, production signing is used, the in-pipeline build/stage/sign run completed, the workspace is clean, redaction passed, and all required gates passed. |
| `nonRelease` | `true` for developer dry-runs, fixture runs, generated test keys, explicit test signing, skipped production-beta build stages, or dirty-workspace runs. |
| `workspaceStatusKnown` | `false` when `git status --porcelain` could not be read. Strict `release-candidate` and `production-beta` runs fail closed when workspace cleanliness is unknown. |
| `dirtyWorkspace` | `true` when `git status --porcelain` found uncommitted changes. Dirty production-beta runs fail the `workspace.clean-production-beta` gate even if `--allow-dirty-workspace` was used for a controlled rerun. |
| `signingProfile.kind` | `production`, `configured`, `test`, `test-fixture`, or `missing`. |
| `promotion.gates` | Per-gate pass/fail records for signed artifacts, evidence ids, live-network evidence, ecosystem certification, and signing profile checks. |
| `promotion.securityResponse` | Compact status for the production security response runbook, advisory lifecycle, reviewer compromise drill, catalog key rotation drill, app signing key compromise drill, emergency catalog update drill, support redaction, security release notes template, blockers, and warnings. |
| `multiNodeBetaSoak` | Compact status for multi-node soak and upgrade evidence, including mode, scenario statuses, blockers, warnings, promotion readiness, and the `evidence/multi-node-beta-soak.json` artifact path. |
| `artifacts.firstPartyMaintenancePolicy` | Redacted copy of the checked-in first-party maintenance policy source used to generate signed catalog descriptors. |
| `redaction` | Final artifact scanner result and findings. |
| `commands` | Redacted command metadata, exit codes, durations, and scrubbed output tails. |

Production beta promotion includes `app-platform.user-consent-flow` evidence. That evidence proves
that install/update previews, service-grant consent, migration and backup consent, automatic update
gating, stale snapshot protection, audit redaction, Web Shell UI, tests, and docs are present
without requiring a live node. Consent evidence must not include private insert URI values, secret
inputs, raw fetched content, raw app data, backup payloads, or host-local paths.

Production beta promotion also includes `multi-node-beta.*` evidence. The generated or attached
summary must prove catalog channel behavior, first-party install/update/rollback, app-data
migration, backup/restore, subscription pressure, Trust Graph import, Social Inbox multi-source
behavior, support bundle redaction, previous-candidate upgrade handling, and artifact redaction.
Use [multi-node-beta-soak-and-upgrade-drill.md](multi-node-beta-soak-and-upgrade-drill.md) for the
topology schema and local commands.

`reports/production-beta-summary.md` is the human-readable companion. It lists failed gates, artifact
paths, the security response summary, known limitations, and the production beta readiness decision.

## Third-party submission evidence

Production beta and release-candidate aggregation require deterministic third-party app-store
submission evidence from `app_platform_smoke.py`. These evidence ids prove the offline submission
package schema, CLI workflow, automated pre-review, decision states, reviewed/caution receipt
issuance, rejection metadata, resubmission linkage, transparency log events, catalog candidate
metadata, fixture sample flow, and redaction checks:

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

The evidence uses fixture/test inputs and must remain marked non-production. It does not require
production reviewer private keys, a hosted submission portal, or live network access.

Production beta summaries also include a compact `developerBetaProgram` object with status fields
for docs, template, sample app flow, submission checklist, compatibility window, feedback workflow,
plugin-author migration, and redaction. The summary records only pass/warn/fail-style status,
blocker summaries, and warning ids; it must not include local absolute paths, raw submission
package bodies, raw rationale text, private keys, tokens, private insert URIs, raw app data, or raw
fetched content.

Developer beta program evidence is required alongside the app-store evidence:

- `third-party-developer.beta-program`
- `third-party-developer.docs`
- `third-party-developer.template`
- `third-party-developer.sample-app-flow`
- `third-party-developer.submission-checklist`
- `third-party-developer.compatibility-window`
- `third-party-developer.feedback-workflow`
- `third-party-developer.plugin-author-migration`
- `third-party-developer.redaction`

## Failure classes

The pipeline classifies failures into these groups:

| Class | Examples | Result |
| --- | --- | --- |
| Build and staging | Gradle toolchain failure, `stageFirstPartyApps` failure, missing `crypta-app` launcher. | Fails release-candidate and production-beta. |
| Signing and catalog | Missing production keys in production-beta, bundle verification failure, catalog signature failure, review receipt verification failure. | Fails release-candidate and production-beta. |
| Evidence | Missing Platform API, UI lint, sandbox, app-platform smoke, first-party maintenance policy, network-scale soak, or ecosystem certification evidence. | Fails release-candidate and production-beta when critical. |
| Multi-node beta soak | Missing required multi-node soak, upgrade-drill, scenario, previous-candidate, or redaction evidence. | Fails production-beta promotion when `--require-multi-node-soak` is set or production-beta mode is used. |
| Live network | Required live-network beta evidence missing, stale, wrong mode, failed, or explicitly skipped. | Blocks production-beta promotion. `--emergency-skip-live-network` records an explicit failed skip gate instead of silently treating missing live evidence as acceptable. |
| Redaction | Private insert URI, private key, bearer token, app/browser session token, raw fetched content, raw app data, host path, AppleDouble, `__MACOSX`, `.DS_Store`, or CI secret value found. | Always fails. Redaction findings are not waivable. |

## Redaction enforcement

The final scanner checks the public output tree before the tarball is created, then checks the
tarball entries after packaging. It expands public ZIP and JAR artifacts while scanning, rejects
secret-bearing binary filenames before treating binary content as unscannable, and fails on:

- private insert URIs;
- private key blocks;
- app tokens and browser session tokens;
- bearer tokens and authorization headers;
- raw fetched content bodies and raw app-data values;
- host-local absolute paths and file URIs;
- AppleDouble `._*` files;
- `__MACOSX/` directories;
- `.DS_Store`;
- known CI secret environment variable names with values;
- non-empty protected secret values present in the runner environment, including live-network
  private insert URI indirection values such as `CRYPTAD_CERT_LIVE_TEST_INSERT_URI_ENV`.

The scan writes `reports/redaction-report.json`. If the report status is `fail`, the top-level
summary also fails and the pipeline does not mark the candidate promotion-ready.

## First-party maintenance policy

The pipeline reads `tools/release-certification/first-party-app-maintenance-policy.json` and passes
the declared `maintenance.*` fields to `crypta-app catalog entry` for every first-party app. The
signed catalog entries therefore expose maintenance owner, support level, data schema policy,
migration policy, backup/restore support, security policy, deprecation policy, and support links.

`catalog/channel-metadata.json` includes a redacted per-app `maintenance` object plus
`maintenancePolicyComplete`. Strict `release-candidate` and `production-beta` modes fail when a
required first-party app is missing from the policy or has an incomplete maintenance block.
`developer-dry-run` records warnings for the same condition. Release certification records the
deterministic evidence id `app-catalog.first-party-maintenance-policy`.

## Rerunning failed stages

The top-level command is intentionally a clean-run orchestration. To reproduce a failed stage before
rerunning the full pipeline, use the lower-level command for that stage:

```bash
./gradlew :platform-devtools:installDist
./gradlew stageFirstPartyApps
./gradlew signFirstPartyApps verifyFirstPartyApps
python3 tools/release-certification/app_platform_smoke.py --self-test
python3 tools/release-certification/live_network_beta_smoke.py --self-test
python3 tools/release-certification/network_scale_soak.py --self-test
python3 tools/release-certification/multi_node_beta_soak.py --self-test
python3 tools/release-certification/release_certification.py --self-test
tools/release-certification/run-release-certification.sh --mode release-candidate --out-dir build/release-certification
```

After the focused issue is fixed, rerun `run-production-beta-release.sh` with the same mode and
output directory. The default clean step prevents stale evidence from being reused.

## CI behavior

`.github/workflows/production-beta-release.yml` runs the pipeline in a CI-safe mode for pull
requests and release-candidate mode for release refs or manual dispatch. Production beta mode is
manual and should run only from a protected environment with the signing, review, live-node, and
fixture inputs described above.

Normal PR runs do not require real signing keys or live network access. They still run the
production-beta self-test and exercise the dry-run path with non-production labels. PR-triggered
runs do not receive protected release artifact, live-node, form-password, catalog, or private-insert
secrets; those are wired only for protected production-beta dispatches or manual release-candidate
dispatches that explicitly require live-network evidence.

The workflow uploads the full production beta artifact tree only when
`reports/production-beta-summary.json` reports `redaction.status=pass`. Redaction failures keep the
raw output on the runner and do not publish rejected artifacts through GitHub Actions.

## Known limitations

- Production beta does not publish artifacts to a public Crypta catalog by itself. Release managers
  still control protected live publication.
- Live-network beta evidence is localhost-only and release-manager driven. It is not a normal PR
  dependency.
- Generated dry-run keys are never release keys. Any output with `nonRelease=true` must not be
  promoted.

## Legacy admin Wave 5 gate

Production beta promotion now requires `legacy-admin.removal-wave-5`,
`legacy-admin.final-admin-surface`, `legacy-admin.browse-retained`, and
`legacy-admin.emergency-fallback-retained` evidence. The promotion summary reports the Wave 5
statuses and promoted route ids. A production-ready result must show no missing Wave 5 evidence and
must keep the evidence redacted: no query strings, request bodies, form passwords, app or browser
tokens, private insert URIs, raw diagnostic output, raw fetched content, raw app data,
support-bundle payloads, or absolute local paths.
