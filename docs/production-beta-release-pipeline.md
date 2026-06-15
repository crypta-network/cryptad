# Production beta release pipeline

This document describes the command that builds, certifies, redacts, and packages a Crypta
app-ecosystem production beta candidate.

## Scope

The production beta pipeline is a release-manager workflow for first-party app ecosystem artifacts.
It does not rewrite the app platform, change peer protocols, or publish a public app store by
itself. It combines the existing Gradle build, first-party app staging tasks, `crypta-app` signing
and catalog tools, app-platform smoke checks, live-network beta evidence, network-scale soak
evidence, ecosystem RC certification, and final artifact redaction.

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
  non-production signing labels. It must not be used for release publication.

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
| `promotionReady` | `true` only for production-beta mode with production signing, a complete in-pipeline build/stage/sign run, a clean workspace, and all required gates passing. |
| `nonRelease` | `true` for developer dry-runs, fixture runs, generated test keys, explicit test signing, skipped production-beta build stages, or dirty-workspace runs. |
| `workspaceStatusKnown` | `false` when `git status --porcelain` could not be read. Strict `release-candidate` and `production-beta` runs fail closed when workspace cleanliness is unknown. |
| `dirtyWorkspace` | `true` when `git status --porcelain` found uncommitted changes. Dirty production-beta runs fail the `workspace.clean-production-beta` gate even if `--allow-dirty-workspace` was used for a controlled rerun. |
| `signingProfile.kind` | `production`, `configured`, `test`, `test-fixture`, or `missing`. |
| `promotion.gates` | Per-gate pass/fail records for signed artifacts, evidence ids, live-network evidence, ecosystem certification, and signing profile checks. |
| `redaction` | Final artifact scanner result and findings. |
| `commands` | Redacted command metadata, exit codes, durations, and scrubbed output tails. |

`reports/production-beta-summary.md` is the human-readable companion. It lists failed gates, artifact
paths, known limitations, and the production beta readiness decision.

## Failure classes

The pipeline classifies failures into these groups:

| Class | Examples | Result |
| --- | --- | --- |
| Build and staging | Gradle toolchain failure, `stageFirstPartyApps` failure, missing `crypta-app` launcher. | Fails release-candidate and production-beta. |
| Signing and catalog | Missing production keys in production-beta, bundle verification failure, catalog signature failure, review receipt verification failure. | Fails release-candidate and production-beta. |
| Evidence | Missing Platform API, UI lint, sandbox, app-platform smoke, network-scale soak, or ecosystem certification evidence. | Fails release-candidate and production-beta when critical. |
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
- Legacy admin Wave 5 readiness is outside PR-259. The summary records that it belongs to a later
  release gate.
- Generated dry-run keys are never release keys. Any output with `nonRelease=true` must not be
  promoted.
