# Release certification

Use release certification to collect a candidate’s compatibility, performance, app-platform,
security, soak, recovery, and release-policy evidence into one redacted release workspace.

Python 3.12 or newer is required. The public command is
`tools/release-certification/certify.py`; the previous per-tool Python scripts and shell wrappers
were removed when evidence envelope v2 became the release contract.

## Run locally

Run all offline tests first:

```bash
python3 tools/release-certification/certify.py self-test all
```

Copy and complete the release-candidate manifest, then run:

```bash
cp tools/release-certification/manifests/release-candidate.example.json \
  build/release-candidate.json
python3 tools/release-certification/certify.py release-certification \
  --manifest build/release-candidate.json
```

The manifest is the source of truth for release identity, profile, output policy, requirements,
input summaries, waivers, history, and command options. Keep private keys, passwords, tokens,
private insert material, and raw reviewer key bytes in their protected environment variables or
files, never in the manifest.

## Profiles

| Profile | Use | Gate behavior |
| --- | --- | --- |
| `pr` | Local and normal pull-request checks. | Missing release-only evidence is skipped or warned. |
| `nightly` | Scheduled evidence collection. | Optional evidence remains visible as warnings. |
| `developer-dry-run` | End-to-end local or PR-safe rehearsal. | May use fixtures or skip expensive build stages, but can never become promotion-ready. |
| `release-candidate` | Strict candidate certification. | Missing, stale, skipped, malformed, or failing required evidence blocks promotion unless policy permits a valid waiver. |
| `production-beta` | Protected beta candidate. | Adds production signing, live-network, previous-candidate, sandbox, archive, and dashboard requirements. |
| `stable-review` | Stable 1.0 promotion review. | Requires production-beta evidence plus the Stable readiness policy and complete Stable domain rows. |

## Release workspace

Each run writes:

```text
<out-root>/<release-id>/
  .cryptad-certification-run.json
  app-platform/
  app-platform-docs/
  network-scale-soak/
  multi-node-beta/
  live-network-beta/
  security-response/
  release-certification/
  production-beta/
  go-no-go/
  stable-readiness/
  stable-rc/
```

Each component contains `summary.json`, `report.md`, `redaction-report.json`, and `artifacts/`.
Artifact references are relative to the release-run root. Reset is allowed only for a directory
with a matching marker, release ID, version, and profile. Detailed engine-native output lives
below `artifacts/legacy/`; validated attached input extracts live below `artifacts/inputs/`.

Manifests are non-secret configuration: both secret-like field names and scalar values containing
private keys or URIs, authorization data, credentials, or secret assignments are rejected before
workspace creation. Published input references are resolved first and represented only as
`<repo>/...` or `<external-input>`. Evidence from a nonzero component exit is always failed and
cannot be reused as a passing or warning input.

Legacy outputs that lack a redaction block are scanned in full before the common envelope can pass;
malformed metadata, detected private/path material, and false direct or nested guarantees fail
closed. Production-beta envelopes copy the final `goNoGo.decision` into `result.decision`.
Known negative live-network safety facts are semantically inverted into positive v2 guarantees, so
safe `…Stored: false` metadata passes while an unsafe true value remains a blocker.
The full scan recursively rejects sensitive JSON field names that can carry passwords, tokens,
private keys or insert URIs, raw bodies, or raw app data. It also rejects local POSIX, Windows
drive, and UNC absolute filesystem paths instead of relying on a small directory-prefix list.
Canonical `<repo>/relative/path` values emitted by the existing sanitizer remain valid migration
inputs. Malformed placeholders, traversal segments, backslashes, and strings containing an
additional absolute path still fail closed.
Candidate-scoped recollection validates every component path segment before cleanup and refuses
intermediate symlinks without removing their targets.
Nested engine output directories, including `artifacts/legacy`, receive the same symlink and
resolved-path confinement checks before an engine can write through them.
Inputs produced by unified components must be candidate-bound evidence envelope v2 records of the
expected kind, component, compatible profile, and declared candidate version. Strict profiles
reject evidence produced under PR, nightly, or developer-dry-run policy even when its kind and
release ID match. Stable review may consume production-beta evidence, while release or production
aggregation may consume an explicit Stable-review summary. Explicit external or non-envelope
interop, performance, ecosystem-matrix, and third-party-intake artifacts retain their native JSON
contracts.
Any `release-candidate`, `production-beta`, or `stable-review` manifest that attaches a unified v2
input must set a non-null `release.version`. The adapter rejects the input before extraction when
the expected version is absent; `null` is never a wildcard for strict reusable evidence.
Command-specific policy modes cannot override the policy derived from `release.profile`.

Attached v2 payloads are scanned again before extraction instead of trusting their claimed outer
redaction status. Security-drill sidecars are scanned and digest-checked before copying. Unsafe
legacy engine output is removed from the publishable tree, and early exits, nonzero exits, or
redaction failures still produce a sanitized failed envelope with `promotionReady=false`.
Completed migration records and component summaries cannot be overwritten with
`output.reset=false`.

The `stable-rc/` component is created only by the canonical Stable 1.0 RC command under the
`stable-review` profile. It contains the common v2 summary/report/redaction surface plus the
versioned freeze, drift report, promotion summary, RC go/no-go report, known limitations, release
notes, checksums, provenance, and deterministic public archive. Its schema and release-manager
procedure are documented in
[Stable 1.0 RC execution and release freeze](stable-1.0-rc-execution-and-release-freeze.md).

## Required evidence

Release-candidate certification continues to require:

- passing Hyphanet Tier 1 interop and comparable performance evidence;
- complete Platform API stable-baseline and compatibility-window evidence;
- signed first-party app, catalog, review, maintenance, update, and rollback evidence;
- app data, backup/restore, subscriptions, app services, consent, sandbox, and reference-app
  evidence;
- public-beta documentation, support, security, operator recovery, and privacy-preserving
  diagnostics evidence;
- fresh network-scale and multi-node soak evidence, including previous-candidate upgrade and
  support-bundle redaction drills;
- legacy plugin freeze/migration and legacy-admin retirement evidence;
- a complete ecosystem certification matrix and production beta go/no-go evidence when the
  selected profile requires them.

Live-network beta evidence is release-blocking only when required by the manifest profile or
requirements. Disabled live evidence is ignored; stale live artifacts must not be copied into a
new release record.

`requirements.history=true` may intentionally be used without `inputs.releaseHistory`. In that
case the manifest remains valid and the certification engine records the unavailable mandatory
history evidence; release-candidate policy emits a failed aggregate and report that blocks
promotion.

Required security-drill evidence follows the
[production security response runbook](production-security-response-runbook.md).

## History and v1 cutover

Normal v2 consumers reject legacy release-certification summaries. Convert the previous candidate
and release-history record explicitly:

```bash
python3 tools/release-certification/certify.py migrate-v1 previous-candidate \
  --manifest build/release-candidate.json
python3 tools/release-certification/certify.py migrate-v1 release-history \
  --manifest build/release-candidate.json
```

Migration validates the legacy shape, candidate binding, status, and redaction state. The v2
migration record contains the source digest and sanitized converted artifact; it does not make
normal consumers accept v1 indefinitely.

The legacy redaction block must contain either a passing status with an empty findings array or a
recognized set of all-true boolean guarantees. Missing, unrecognized, malformed, or contradictory
redaction metadata fails migration.

Use a second run manifest for certification. Its `inputs.previousCandidate` and
`inputs.releaseHistory` fields must point to the candidate-bound v2 migration summaries, not the
original v1 files. The aggregator unwraps those summaries only after validating their kind,
candidate identity, passing result, and redaction status.

Keep `release.id` unchanged between the migration manifest and the consuming certification or
production manifest. When dispatching the protected production workflow, enter that same value as
`candidate_release_id`; the workflow does not generate a new identity for migrated inputs.
Both release workflows set `release.version` from the checked-out build with
`./gradlew -q printVersion`. Prepare attached v2 evidence and migration records with that same
build version; matching only the candidate release ID is not sufficient.
When dispatching `.github/workflows/release-certification.yml`, supplying
`previous-summary-path` likewise requires `candidate-release-id` with that same value.
Supplying an optional `stable-readiness-summary-path` also requires that candidate ID because every
Stable v2 envelope is candidate-bound regardless of whether the Stable gate is mandatory.
Production workflow dispatches require the same explicit ID when attaching multi-node or
security-drill v2 evidence. The adapter preserves the validated envelope release ID when extracting
multi-node evidence, so custom candidate IDs are not reconstructed from version text.

## History archives

Set `execution.writeHistory=true` to write the current sanitized certification record. The default
shared store remains `build/release-certification-history/`; configure `policies.historyDir` only
when the release process preserves a different shared location. Passing runs update
`latest-summary.json` and `releases/<history-label>/`. Failed runs are retained under
`failed/<history-label>/` and do not replace the latest passing record. The GitHub workflow uploads
the shared history directory together with the release workspace.

## Waivers and redaction

Waivers remain evidence-specific, approved, owned, scoped, referenced, and time-bounded. A waiver
for release-candidate scope does not apply to production beta or Stable review. Malformed,
expired, under-severity, unknown-evidence, or incomplete waivers fail validation.

Redaction findings involving secrets, private insert URIs, private or signing keys, tokens,
cookies, authorization headers, raw fetched content, raw app data, raw trust/social/profile/feed
documents, identity material, browser sessions, local absolute paths, unsafe archives, symlinks,
or special files are non-waivable. Stable redaction remains separate from dashboard and release
archive redaction, and every required redaction result must pass before publication.

See [the tooling README](../tools/release-certification/README.md) for the command tree, manifest
schema, evidence envelope v2, and focused self-test commands.
