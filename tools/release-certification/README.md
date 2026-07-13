# Release certification tooling

Use `certify.py` to collect, evaluate, redact, and package Cryptad release evidence.

The tooling requires Python 3.12 or newer and uses only the Python standard library. Run commands
from the repository root unless a command supplies `--workspace-root` explicitly.

## Quick start

Run every offline characterization and contract test:

```bash
python3 tools/release-certification/certify.py self-test all
```

Run one focused suite:

```bash
python3 tools/release-certification/certify.py app-platform --self-test
python3 tools/release-certification/certify.py release-certification --self-test
python3 tools/release-certification/certify.py production-beta --self-test
```

Run a CI-safe app-platform collection with the checked-in manifest:

```bash
python3 tools/release-certification/certify.py app-platform \
  --manifest tools/release-certification/manifests/developer-dry-run.json
```

All non-test commands require a versioned JSON manifest. Copy one of the examples under
`tools/release-certification/manifests/`, replace its placeholders, and keep private keys,
passwords, tokens, private insert material, and reviewer key bytes out of the file.

## Command tree

The public entry point is `tools/release-certification/certify.py`.

| Command | Purpose |
| --- | --- |
| `app-platform` | Collect app-platform source, contract, app, security, recovery, and redaction evidence. |
| `app-platform-docs` | Validate developer portal, tutorial, beta-program, and documentation evidence. |
| `network-scale-soak` | Generate deterministic network-scale and budget evidence. |
| `live-network-beta` | Collect explicitly configured localhost live-network evidence. |
| `multi-node-beta` | Plan, run, or verify multi-node soak and previous-candidate upgrade evidence. |
| `security-response` | Verify the runbook or create and verify security drill artifacts. |
| `release-certification` | Aggregate release evidence and evaluate ecosystem certification gates. |
| `production-beta` | Build, certify, redact, and package a production-beta candidate. |
| `go-no-go` | Build the release-manager launch dashboard. |
| `stable-readiness` | Evaluate the Stable 1.0 promotion gate. |
| `migrate-v1` | Convert validated v1 previous-candidate or history summaries for the first v2 release. |
| `self-test` | Run one focused `unittest` suite or all suites. |

Use `--help` on the entry point or a command for its exact syntax.

## Source layout

`certify.py` is a thin entry point. Keep the public contract and shared safety boundaries in the
`cryptad_certification` package:

```text
cryptad_certification/
  cli.py                 command tree and collection orchestration
  manifest.py            strict release-run manifest loading
  workspace.py           marked, candidate-scoped workspace confinement
  envelope.py            evidence envelope v2 normalization and validation
  redaction.py           reusable evidence and migration scanning
  migration.py           one-time v1 history conversion
  legacy.py              controlled adapters for the split engines
  engines/               component implementations, split by responsibility
  tests/                 contract, characterization, workflow, and safety tests
```

Do not restore the removed top-level per-engine scripts or shell wrappers. Split an engine by
responsibility before a Python source file exceeds 5,000 lines; `self-test core` enforces that
limit.

## Release-run manifest

The manifest schema is `schemas/release-run-v1.schema.json`. A manifest contains:

- release identity, version, and profile;
- output and reset policy;
- required evidence and promotion gates;
- non-secret input paths;
- catalog, artifact, freshness, and signing-profile labels;
- execution controls and command-specific arguments.

The structured maps are closed contracts. Unknown keys and values of the wrong type fail before
the release workspace is prepared:

| Map | Supported fields |
| --- | --- |
| `requirements` | Boolean `history`, `liveNetwork`, `multiNodeSoak`, `sandboxProviderTests`, `stableReadiness`, and `thirdPartyIntake` gates. |
| `inputs` | Non-empty paths for interop, performance, app-platform, live-network, network-scale, multi-node, security-drill, production, dashboard, certification, Stable, waiver, policy, known-limitation, previous-candidate, and release-history artifacts. |
| `policies` | `artifactBaseUri`, `catalogChannel`, `expectedPreviousReleaseId`, `historyDir`, `historyLabel`, and string-valued `metadata`. |
| `execution` | Boolean collection/build/test controls plus positive integer `timeoutSeconds`. |

`commands.<name>.args` remains an advanced engine-specific escape hatch. The unified command owns
workspace, output, mode, and release identity arguments and removes attempts to override them.
Exact controlled options are removed, and abbreviated forms are rejected before legacy argparse
processing so prefixes cannot escape the marked workspace or replace candidate policy and identity.
For commands that evaluate release policy, `commands.<name>.mode` may only restate the mode derived
from `release.profile`; a conflicting value is rejected instead of weakening or relabeling the
candidate. `commands.multi-node-beta.mode` remains the separate topology execution mode.

Supported profiles are `pr`, `nightly`, `developer-dry-run`, `release-candidate`,
`production-beta`, and `stable-review`. Unknown fields, unsafe release IDs, incompatible types,
secret-like field names, and secret-bearing scalar values fail before a command creates artifacts.
The loader rejects private SSK/USK material, private keys, authorization values, credentials, and
secret assignments without copying the rejected value into its error message.

`--workspace-root` and `--out-root` are the only location overrides outside the manifest. Relative
input paths are resolved from the workspace. Secret inputs continue to use the protected
environment variables and protected files documented by the production release workflow.

## Release workspace

Every command writes below one release-scoped directory:

```text
<out-root>/<release-id>/
  .cryptad-certification-run.json
  <component>/
    summary.json
    report.md
    redaction-report.json
    artifacts/
```

Nested operations use nested component names, for example `multi-node-beta/run/` and
`security-response/drill-run-all/`. JSON and Markdown artifact references are relative to the run
root. The common `summary.json`, `report.md`, and `redaction-report.json` are the public component
surface. Component-specific engine output remains below `artifacts/legacy/`; extracted reusable
inputs remain below `artifacts/inputs/`.

A manifest with `output.reset=true` may replace only a directory containing a matching run marker.
The command rejects unmarked directories and markers for another release, version, or profile.
This prevents a misspelled output path from deleting source-controlled files and prevents stale
candidate evidence from being silently reused.

When `execution.collectEvidence=true`, every internally collected component is deleted and rebuilt
before aggregation, even when `output.reset=false`. To reuse evidence intentionally, provide it
through the corresponding `inputs` field; the adapter then applies that evidence type's identity,
status, freshness, and redaction validation instead of treating an interrupted component as a
cache.
Before replacing an internally collected component, every path segment is checked for symlinks and
workspace confinement so cleanup cannot follow an intermediate link into another component.
Nested legacy-engine output directories are checked before and after creation so a restored or
tampered `artifacts/legacy` symlink cannot redirect engine writes outside the marked run.
The shared JSON and text writers also reject symlinked file targets. Extracted-input directories,
security-drill sidecars, and production output staging receive the same resolved-path confinement
checks before a write or cleanup.
When an aggregate `release-certification/summary.json` already exists, recollection is rejected
before any component is deleted or rebuilt; use `output.reset=true` for a complete rerun.

## Evidence envelope v2

Every `summary.json` follows `schemas/evidence-envelope-v2.schema.json`. The common envelope
contains:

- `subject`: release ID, version, profile, and component;
- `result`: normalized `pass`, `warn`, or `fail`, a component decision, promotion readiness, and
  exit code;
- evidence, blocker, warning, and waiver counts;
- standard evidence rows, issues, and waiver records;
- a redaction result and non-secret guarantees;
- relative input and artifact references;
- component-specific data under `payload`.

Consumers validate every required envelope field, nested field type, evidence kind, candidate
identity, array count, result consistency, and redaction status before unwrapping `payload.legacy`.
Relative and absolute manifest inputs are resolved against the workspace before publication and
rendered only as `<repo>/...` or `<external-input>`. A component process with a nonzero exit always
produces failed evidence; `pass` and `warn` envelopes require `exitCode: 0`.
Legacy outputs without native redaction metadata pass only after a complete payload scan; malformed
metadata, scan findings, or false direct/nested guarantees fail the envelope. Production-beta
envelopes expose the final nested `goNoGo.decision` through the common `result.decision` field.
Negative live-network safety facts such as `rawBodiesStored: false` are converted to positive v2
guarantees such as `rawBodiesNotStored: true`; an unsafe true value still fails closed.
Migration and fallback scans inspect nested JSON field names as well as values, rejecting
payload-bearing password, token, key, private-URI, raw-body, and raw-app-data fields. They also
reject POSIX, Windows drive, and UNC absolute filesystem paths outside the documented public route
shapes before any migrated artifact or envelope is written. Canonical sanitized
`<repo>/relative/path` values are allowed so existing release-certification history can migrate;
malformed, traversing, mixed, or backslash-bearing placeholders remain blocked.
Each unified component input has one expected v2 kind and rejects raw v1 summaries as well as v2
envelopes of another kind. Explicit external or non-envelope inputs—interop, performance,
ecosystem matrix, and third-party intake—retain their native JSON contracts, and their input slots
reject v2 envelopes instead of accepting an arbitrary kind.
Non-migration policy consumers may inspect `warn` evidence with
passing redaction so Stable waiver evaluation can run. Failed results and failed redaction remain
rejected, and migrated previous-candidate/history evidence remains pass-only. Reused
`inputs.securityDrills` envelopes also restore the referenced public drill JSON files beside the
extracted legacy summary so downstream digest and scenario validation sees the same complete
artifact set that the v2 producer published. Every referenced drill sidecar is parsed, scanned,
and checked against its recorded digest before it is copied. The verification adapter copies from
the effective configured input directory, not from a previous internally generated drill run.

Attached v2 payloads are scanned before extraction even when their outer redaction record says
`pass`. Safety-labelled fields are exempt only when their value has the expected scalar, boolean,
or digest shape; containers are still traversed. Credential assignments, cookie or authorization
values, credential-bearing URLs, local `file:` URIs, filesystem roots, and labelled absolute paths
remain findings. Canonical sanitizer output such as `<repo>/...`, `<path>/python3`, relative app
assets, and public API routes remains reusable.

If an engine writes unsafe output, the adapter removes the raw legacy copies from the publishable
workspace and emits only sanitized failed evidence. Early engine `SystemExit`, nonzero exits, and
redaction failures all produce a failed common envelope with `promotionReady=false`. Common
normalization preserves production failure reasons as blockers and release-certification
`waiverRecords` as auditable v2 waivers.

## V1 history migration

Normal v2 consumers reject legacy release-certification summaries. Convert the previous beta
candidate once with:

```bash
python3 tools/release-certification/certify.py migrate-v1 previous-candidate \
  --manifest path/to/release-run.json
```

Set `inputs.previousCandidate` in the manifest. Use `migrate-v1 release-history` with
`inputs.releaseHistory` for the previous certification record. Migration validates the source
shape, release binding, status, and redaction state, records its SHA-256 digest, and writes the
converted artifact under the marked release workspace. It does not run automatically.

Redaction must use either an explicit passing status with an empty findings array or the older
recognized boolean-guarantee form with every recognized guarantee set to true; missing,
unrecognized, malformed, or contradictory redaction metadata is rejected.

For the subsequent certification or production run, point `inputs.previousCandidate` or
`inputs.releaseHistory` at the corresponding migration component’s v2 `summary.json`. Normal
adapters validate its candidate binding and redaction result, then extract the legacy payload into
the current component’s adapter area. They reject a raw v1 path.

The migration manifest and the consuming run manifest must use the same `release.id`. For a
protected production workflow dispatch, set `candidate_release_id` to that value. Do not use a
workflow run number as the candidate identity because the migration artifacts must be prepared
before the consuming workflow starts.
For a release-certification workflow dispatch, set `candidate-release-id` whenever
`previous-summary-path` is supplied; the workflow rejects migrated history without its bound
candidate identity. The same explicit identity is required for any attached candidate-bound v2
multi-node, security-drill, or Stable-readiness summary, even when the corresponding gate is
optional.

Migration output is immutable within a completed marked workspace. A second migration for the
same release and kind is rejected when `output.reset=false`; use an explicit matching reset to
replace the candidate-bound record and its source digest.

## Release history output

Set `execution.writeHistory=true` to archive a completed certification result. Unless
`policies.historyDir` is set, the legacy aggregator keeps its shared default at
`build/release-certification-history/`, outside the per-candidate run root. Passing runs update
`latest-summary.json`, `latest-history-comparison.json`, and
`releases/<history-label>/`; failed candidates are retained under `failed/<history-label>/`
without replacing the last passing summary. Set `policies.historyLabel` when the release label
cannot be derived safely. The release-certification workflow uploads both the candidate workspace
and this shared history directory.

## Failure and redaction policy

Release-candidate, production-beta, and Stable review modes remain fail closed. Missing, stale,
malformed, wrong-candidate, skipped, fixture-only, or redaction-unsafe required evidence cannot
promote a release unless the existing policy explicitly permits a valid waiver.
Requirements are evaluated by the gate engine rather than treated as manifest dependencies. In
particular, `requirements.history=true` without `inputs.releaseHistory` is valid configuration and
records the missing mandatory history in the certification report; release-candidate policy fails
the aggregate and blocks promotion.

Redaction findings involving private insert URIs, private keys, signing material, form passwords,
tokens, cookies, authorization headers, raw fetched content, raw app data, identity material,
browser sessions, local absolute paths, unsafe archives, symlinks, or special files remain
non-waivable. Do not publish private interop insert material or raw live-node fixtures.

## CI

The multi-OS CI job runs:

```bash
python3 tools/release-certification/certify.py self-test all
```

The characterization suite runs on Ubuntu, macOS, and Windows with Python 3.12. Ubuntu and macOS
retain a 30-minute job limit; Windows has a 60-minute limit because the same subprocess-heavy
scenarios run materially slower there. Integration assertions compare canonical paths so macOS
aliases such as `/var` and Windows temporary-directory aliases do not create false failures.

Release workflows generate their runtime manifest with `jq` from workflow-dispatch inputs. Secret
values remain in protected environment variables or files and are never serialized into the
manifest or uploaded workspace.

Follow the [production security response runbook](../../docs/production-security-response-runbook.md)
when collecting release-blocking drill evidence or responding to an app ecosystem incident.
