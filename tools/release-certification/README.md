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
python3 tools/release-certification/certify.py stable-rc --self-test
python3 tools/release-certification/certify.py stable-ga --self-test
python3 tools/release-certification/certify.py stable-backport --self-test
python3 tools/release-certification/certify.py stable-maintenance --self-test
python3 tools/release-certification/certify.py stable-lifecycle --self-test
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
| `stable-rc` | Execute, freeze, package, and verify a protected Stable 1.0 release candidate. |
| `stable-ga` | Validate and prepare explicit promotion of one exact frozen Stable 1.0 RC without rebuilding or publishing it. |
| `stable-backport` | Classify Stable 1.0 fixes, authenticate source-to-candidate provenance, account for one release train, and verify completion without changing Git or public state. |
| `stable-maintenance` | Authenticate, validate, freeze, and prepare one built-once Stable 1.0 maintenance or security-hotfix release. |
| `stable-lifecycle` | Evaluate and prepare authenticated Stable 1.0 build-support lifecycle transitions without publishing them. |
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
| `inputs` | Non-empty paths for interop, performance, app-platform, live-network, network-scale, multi-node, security-drill, production, dashboard, certification, Stable, waiver, policy, known-limitation, previous-candidate, release-history, stable catalog operations, previous Stable RC freeze, Stable RC freeze exceptions, and the selected Stable RC/GA validation, authorization, policy, lineage, or optional publication-receipt artifacts. |
| `policies` | `artifactBaseUri`, `catalogChannel`, `candidateSourceCommit`, `candidateSourceRef`, `expectedPreviousReleaseId`, `expectedPreviousProductDigest`, `historyDir`, `historyLabel`, `publicationIntent`, `stableRcFreezeMode` (`first-freeze` or `refreeze`), and string-valued `metadata`. |
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

For Stable 1.0 RC execution, copy
`manifests/stable-1.0-rc.example.json`, replace every placeholder, and run:

```bash
python3 tools/release-certification/certify.py stable-rc \
  --manifest build/stable-1.0-rc.json
```

The manifest retains the `stable-review` profile and integer build number. The command generates a
unified production-beta component inside the same marked run; that protected pipeline produces and
binds its go/no-go, release-certification, app-platform, ecosystem-matrix, and Stable-readiness
native artifacts for the Stable RC engine. Do not attach unrelated precomputed copies to the
canonical manifest. External prerequisites use the coordinated `stableCatalogOperations`,
`previousStableRcFreeze`, and `stableRcFreezeExceptions` input names. Stable RC output lives under
`<out-root>/<release-id>/stable-rc/`; see the
[Stable RC runbook](../../docs/stable-1.0-rc-execution-and-release-freeze.md) for its freeze schema,
artifact inventory, drift and exception semantics, and protected workflow.

`stableCatalogOperations.artifactTimestamp` is the immutable producer timestamp for the signed
catalog and first-party review receipts. The same protected value is used on every refreeze. The
production pipeline emits `crypta-stable-1.0-rc-<build>-product.tar.gz` with normalized member
metadata and no run-specific evidence reports; this is the exact distribution bound by the Stable
RC freeze. The ordinary production-beta evidence archive remains available to its existing
consumers. These requirements apply only when `stable-rc` orchestrates the production stage; a
direct `production-beta` run with the `stable-review` profile keeps the pre-existing manifest and
intake contracts.

Set `policies.stableRcFreezeMode=first-freeze` only for the initial candidate baseline and omit
`inputs.previousStableRcFreeze`. Every later run uses `stableRcFreezeMode=refreeze` and must supply
the exact freeze from the latest successful protected workflow run. The workflow authenticates
that parent against the latest uploaded artifact when available. Each successful protected run
also creates a commit-bound check-run lineage anchor for the exact freeze file digest, release,
build, run, and attempt. After the uploaded artifact expires, a retained freeze is accepted only
when its digest matches that latest authenticated anchor; stale or unauthenticated lineage fails
closed. The canonical freeze binds the exact deterministic product-distribution digest. Rebuilding
the unchanged candidate must produce identical bytes; a catalog, review receipt, bundle, launcher,
policy, or product member change remains candidate drift even when semantic producer summaries are
unchanged.

For Stable 1.0 GA validation, copy
`manifests/stable-1.0-ga.example.json`, replace every placeholder, and run:

```bash
python3 tools/release-certification/certify.py stable-ga \
  --manifest build/stable-1.0-ga.json
```

`stable-ga` retains the `stable-review` profile and writes to
`<out-root>/<release-id>/stable-ga/`. It is side-effect-free: the command authenticates one exact
successful Stable RC, evaluates post-freeze production validation and explicit GA authorization,
and prepares promotion records. It does not rebuild the product, create a branch or tag, publish a
GitHub Release, change a catalog, insert an update descriptor, or perform a network insert.

The GA manifest uses these exact input names:

```text
selectedStableRcSummary
selectedStableRcFreeze
selectedStableRcFreezeSidecar
selectedStableRcArchive
selectedStableRcProduct
selectedStableRcChecksums
selectedStableRcProvenance
selectedStableRcLineage
previousCandidate
stableRcValidation
stableGaAuthorization
stableGaPolicy
stableGaPublicationReceipt
```

`stableGaPublicationReceipt` is optional and is used only to verify a returned protected
publication result. `stableGaPolicy` normally points to the checked-in
`stable-1.0-ga-policy.json`. The non-secret policy values bind the public HTTPS artifact base,
stable catalog primary/mirror/rollback confirmation URIs, stable catalog channel, exact candidate
source commit/ref, and publication intent. The canonical metadata keys are
`catalogPrimaryUri`, `catalogMirrorUris`, and `catalogRollbackUri`; all three are included in the
authorized publication-target digest. Stable GA also requires `expectedPreviousReleaseId` and
`expectedPreviousProductDigest`. The exact migrated `previousCandidate` envelope authenticates the
predecessor release/build against the PR-283 freeze and provenance, while the manifest supplies the
published predecessor product digest; the authorization identity binds all four predecessor
fields. Signing keys,
private insert URIs, GitHub credentials, authorization headers, tokens, and publication credentials
remain protected environment or file inputs and must never appear in the manifest.

The selected RC files must form one authenticated, symlink-free artifact set. Stable GA verifies
the common RC envelope; freeze schema, canonical digest, and sidecar; exact checksums; provenance;
outer archive; immutable product; catalog, app, Platform API, content-profile, limitation, waiver,
and freeze-exception bindings; and latest protected refreeze lineage. The post-freeze
`stable-1.0-rc-validation` record must bind every scenario to the exact frozen product digest and
meet the checked-in policy, including at least 24 hours of real production soak measured from the
long-soak scenario's own timestamps. Top-level validation and scenario start times must not precede
the authenticated protected RC run completion in the selected lineage.

For the explicit authorization review pass, set `commands.stable-ga.mode` to
`prepare-authorization` and omit `stableGaAuthorization`. The command validates the exact RC and
writes `stable-1.0-ga-validation-authorization-identity.json`, but it does not report promotion
readiness. The protected authorization's `gaValidationDigest` is the canonical semantic SHA-256 of
that identity. The identity and authorization also bind a canonical publication-target digest for
the expected tag and release branch, artifact base, catalog primary, ordered mirror list, and
rollback catalog location.
Changing any destination requires a new preparation, authorization, and protected evidence pass.
Rerun in `validate-only` mode with the authorization input. This two-pass contract prevents an
authorization/final-record circular digest and rejects authorization or publication receipt inputs
during the preparation pass.

Input acquisition and producer authentication are separate controls. A confined repository path,
public HTTPS URL, or `actions-artifact://` reference only determines how the workflow obtains a
record. Before publication, run `.github/workflows/stable-1.0-ga-promotion.yml` with
`publish=false` on the exact `release/<build-number>` candidate. The protected
`stable-1-0-ga-evidence` job attests the exact validation, authorization, and canonical
publication-target identity bytes. A later `publish=true` dispatch accepts only identical bytes and
destinations with attestations from that workflow, release ref, candidate commit, and a
GitHub-hosted runner. After protected publication approval, it reruns `stable-ga` before every
tag, Release, asset-upload, or finalization mutation and again before recording completion. Thus,
evidence, waivers, authorization, or targets that expire or change during a lengthy publication
attempt fail closed at the next mutation boundary.

The protected publication environment also supplies `STABLE_CATALOG_TRUSTED_KEYS_BASE64`, a
base64-encoded production trusted catalog public-key properties registry. The workflow uses it
only to verify freshly fetched primary, mirror, and rollback catalog signatures and deletes the
decoded file before job exit. It must not contain private signing keys and is never a manifest or
public artifact input. The retained rollback revision must verify under the catalog signing-key
identity frozen by the selected RC.

The native public output includes:

```text
stable-1.0-ga-validation.json
stable-1.0-ga-validation-authorization-identity.json
stable-1.0-ga-authorization-summary.json
stable-1.0-ga-promotion-summary.json
stable-1.0-ga-go-no-go.md
stable-1.0-ga-known-limitations.json
stable-1.0-ga-release-notes.md
stable-1.0-ga-publication-plan.json
stable-1.0-ga-publication-receipt.json
stable-1.0-ga-checksums.txt
stable-1.0-ga-provenance.json
stable-1.0-maintenance-baseline.json
```

The public checksum file names the six non-checksum Release assets. The checksum file is the
seventh planned asset and is itself bound by its size and digest in the publication plan,
provenance, and receipt. Internal validation, authorization, and redaction records are not added to
the public checksum rows because they are not public Release assets.

All seven planned assets must already exist at the independently populated `artifactBaseUri`
before a protected `publish=true` dispatch. The publication job verifies them immediately before
its first mutation and again after GitHub publication. The canonical publication receipt is
generated only when a returned publication result is independently verified. A
passing pre-publication run records `validated` or `publication-authorized`; it must not claim
`publication-complete`. Publication verification fetches every planned asset from both the GitHub
Release and its exact `artifactBaseUri + <asset-name>` public location. The receipt binds that base
and each asset's exact public URI, size, and digest, and rejects every unplanned or non-passing
asset row. See the
[Stable GA runbook](../../docs/stable-1.0-rc-validation-and-ga-promotion.md) for exact-RC selection,
24-hour validation, authorization, protected publication, conflict recovery, catalog verification,
receipt semantics, and the post-1.0 maintenance baseline.

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
identity, profile compatibility, component identity, declared version, array count, result
consistency, and redaction status before unwrapping `payload.legacy`. Strict profiles reject
evidence produced by PR, nightly, or developer-dry-run policy. Stable review may consume the
production-beta evidence it evaluates, and release or production aggregation may consume an
explicit Stable-review summary; these are the only cross-profile input transitions.
For `release-candidate`, `production-beta`, and `stable-review`, an attached v2 input also requires
a non-null manifest `release.version`. The adapter rejects the input instead of treating an absent
expected version as a wildcard.
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
The release workflows derive `release.version` from `./gradlew -q printVersion`. Bind migrated and
attached v2 evidence to that checked-out build version; a matching release ID does not authorize
evidence for another build version.
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

`.github/workflows/stable-1.0-rc-release.yml` is manual and protected. It requires an explicit
candidate release ID and integer build, JDK 25, a clean candidate commit, production
signing/reviewer material, full build/stage/sign/verify, and real live, sandbox, multi-node,
previous-candidate, network-scale, security-drill, third-party-intake, and catalog-operations
evidence. It verifies the post-package freeze, checksums, archive hygiene, final v2 redaction, and
`go`/`go-with-waivers` result before uploading only the public RC component. It does not tag,
release, merge, or publish Stable 1.0 GA.

`.github/workflows/stable-1.0-ga-promotion.yml` keeps validation, protected evidence attestation,
and publication in separate jobs. The validation job authenticates the latest protected Stable RC
run and has no tag or GitHub Release permission. Protected HTTPS acquisition rejects redirects,
URL credentials, query strings, fragments, non-public DNS results, and local/private targets;
repository and Actions-artifact inputs remain path-confined and reject symlinks and special files.
The evidence job requires `stable-1-0-ga-evidence` approval and attests the exact validation,
authorization, and canonical publication-target identity bytes. The publication job requires an
explicit dispatch selection, passing validation, prior evidence attestations, and approval in the
`stable-1-0-ga` environment. It reruns
the gate at every publication mutation boundary, uses the required `leumor` GitHub identity,
creates or verifies the annotated `v<build-number>` tag and exact GitHub Release assets, fetches the
same assets from the declared artifact base, and verifies the unchanged stable catalog at the
primary, mirrors, and authorized rollback URI. It never merges a release branch automatically.
Matching existing public state is idempotent only after a fresh latest-RC lineage query;
conflicting state fails closed. The failure audit path is read-only and uploads a sanitized failed
receipt even when no side-effect marker or GitHub Release exists. Recovery distinguishes an
observed absence from an unavailable GitHub observation and records only counts and SHA-256
identifiers for unplanned remote asset names. The receipt must pass its closed schema, placeholder,
and redaction checks before upload. Only a verified publication receipt may record
`publication-complete`.

The Stable RC and Stable GA workflows share one integer-build concurrency group across validation,
protected approval waits, and publication. Cancel a waiting GA run before an urgent refreeze and
inspect the shared build queue, because GitHub retains at most one pending run for the group. During
publication the workflow also rereads `release/<build-number>` at every side-effect boundary,
before creating a tag reference from a newly created tag object, and before accepting idempotent or
new public state as `publication-complete`.

Follow the [production security response runbook](../../docs/production-security-response-runbook.md)
when collecting release-blocking drill evidence or responding to an app ecosystem incident.

## Stable 1.0 backport and release-train certification

Use `stable-backport` before `stable-maintenance` to govern the exact contents of one routine or
security-hotfix candidate:

```bash
python3 tools/release-certification/certify.py stable-backport \
  --manifest build/stable-1.0-backport.json
```

The component has four side-effect-free modes:

- `evaluate` validates intake, policy, lifecycle coverage, prior queue state, and proposed
  dispositions before any accepted fix is required to be landed;
- `prepare-candidate` binds the exact candidate, source-to-candidate provenance, evidence, and
  complete commit/change coverage;
- `validate-authorization` validates a narrow authorization for the exact train composition and
  candidate handoff;
- `verify-release-completion` authenticates publication, lifecycle activation or an explicit
  pending state, and no-squash `--no-ff` reconciliation into `main` and `develop`.

The candidate may advance between `evaluate` and `prepare-candidate` while approved fixes are
landed. Candidate equality is frozen from `prepare-candidate` through authorization, maintenance,
and completion; it is not required for the pre-landing evaluation handoff.

The versioned policy closes classifications, dispositions, states, provenance modes, deadlines,
roles, Git object rules, queue bounds, evidence windows, redaction, and non-waivable blockers. The
two release lanes are `routine-maintenance` and `security-hotfix`; `future-milestone`, `deferred`,
and `rejected` keep ineligible or unscheduled work outside a Stable candidate.

Git evidence uses full canonical commit object ids and verified object graph operations. It rejects
abbreviations, symbolic revision syntax, wrong repositories, spoofed branch roles, wrong bases,
parallel predecessors, patch-id misuse, missing candidate ancestry, and incomplete manual conflict
evidence. Routine manifests carry `policies.developmentLineageCommit`: the protected workflow
resolves and freezes the exact protected `develop` tip independently of `candidateBaseCommit`,
then the engine requires the declared base to be the exact candidate/lineage merge base and a
member of that protected tip's first-parent chain. A merged side-parent tip is not an authenticated
`develop` base. Patch
identity supports a reviewed `clean-cherry-pick`; it never authorizes one.
Clean cherry-pick and manual-conflict records also require an exact
`stableBackportReviewAuthorizations` protected input. Each row comes from the successful
`.github/workflows/stable-1.0-backport-review-authorization.yml` producer in the
`stable-1.0-backport-review` environment and binds the reviewer role, policy, source,
predecessor, candidate, normalized diff, path inventory, focused tests, validity interval, run,
workflow, and artifact. Matching caller-provided digests without that producer artifact fail.
Security-hotfix manifests instead carry `policies.mainLineageCommit`, independently resolved from
the exact protected `main` tip. The hotfix base must equal that tip, while the tagged publication
predecessor must remain its ancestor; branching directly from the predecessor cannot omit a later
`main` reconciliation merge or its resolution.

The queue is append-only and digest chained. It carries unresolved accepted fixes, deferred and
rejected history, superseding relationships, critical obligations, hotfix follow-up, and prior
merge-back obligations. Candidate coverage assigns every commit or change to an accepted fix,
approved release metadata/tooling/docs, explained merge context, or `unaccounted`; any
`unaccounted` entry blocks the train.

Each evidence row carries the exact reviewed policy and queue digests. The queue digest normalizes
only its embedded evidence queue-binding slots before hashing, which provides deterministic
self-binding without excluding the evidence content or any other queue field. Policy-designated
protected evidence must remain `visibility: protected`.

Landed fix provenance is immutable. Resolving a carried obligation requires a new evidence digest,
and both that digest and its resolution timestamp are immutable after resolution.
Security incident/advisory identity and severity are immutable across queue snapshots. A disposition
or lane change must be explained by an appended state transition, which prevents a critical
security record from being relabeled as noncritical routine work.

GA is the sole queue genesis. A later maintenance successor must provide both
`previousStableBackportQueue` and `previousStableBackportValidation`; the published successor
baseline authenticates the validation file digest, and that validation binds the exact queue
digest and predecessor commit. Critical 4/8/12-hour response windows are computed from state
transition timestamps, not from a caller-selected final deadline. An expired critical deferral
review remains blocking. Rejecting a critical record does not remove it from the blocker index;
an append-only authorized `rejected`-to-`triaged` transition reopens investigation without
rewriting that history. The record remains critical and blocking throughout re-triage.
superseding one requires a critical replacement with the same incident, advisory, and affected
scope.

Every accepted `security-hotfix` row is a critical `security-fix` under one incident/advisory pair;
package, app, or tooling effects are recorded in the security fix’s affected scope and evidence,
not as unrelated ordinary rows. A superseding hotfix may carry one publication-created follow-up
even when it was not present in the prior authorized train queue: the first queue projection must
bind the authenticated predecessor baseline’s exact open/overdue obligation digest, build/train and
generation time to the prior queue’s critical source fixes. Subsequent queues inherit it unchanged.

A new transition to `released` is valid only from an authenticated prior queue and with the exact
`previousStableBackportCompletion` artifact. The fix transition and its
`stable-backport.release-completion` evidence row both bind that artifact's file digest, train,
queue, and candidate identity. The immutable per-fix provenance commit must be an ancestor of the
publication tip; it is not required to equal that tip. The intake snapshot, completion-evidence
row, and final state transition must be timestamped no earlier than the authenticated maintenance
publication receipt, completion artifact, and protected completion handoff. Backdating any of
those events cannot make a later train authorization appear to postdate publication.
Every fix included by the prior authorized validation must complete this released-state proof
before it can be superseded.
When an otherwise authenticated reconciliation merge contains non-automatic content, strict Git
inspection does not certify that content as reconciled. Completion instead derives the exact
policy-named blocker, marks `reconciliationStatus: content-review-required`, and binds its evidence
digest to the merge record and bounded resolution-path digest. The next intake must seed that exact
completion-created obligation before moving the published fixes to `released`; its queue remains
blocked pending separately authenticated content-review evidence. Other Git, parent, branch-tip,
or attestation failures still produce no completion artifact.
The successor also requires `previousStableBackportCompletionHandoff`. The protected workflow
creates this record only after authenticating the successful prior completion run and exact
Actions artifact, byte-comparing its completion and validation, resolving current protected
`main`/`develop`, and proving both merge commits remain on their first-parent chains.

Stable 1.0 remains one successor chain. Historical `supported-maintenance`,
`security-fixes-only`, or `deprecated` builds are upgrade/advisory coverage sources.
`end-of-support` and `revoked` builds are recovery sources only when policy explicitly permits it.
They are never mutable release targets or parallel LTS branches.

Every train re-authenticates the full existing GA promotion, validation, authorization-summary,
publication-plan, receipt, checksums, provenance, and maintenance-baseline bundle as its immutable
root. For the first post-GA train, the exact authenticated GA baseline and publication receipt are
the predecessor and `latestPublishedMaintenancePointer` must be absent. Every later train requires
that input and verifies that it selects the exact immediate maintenance predecessor. This matches
the existing `stable-maintenance` genesis/no-fork invariant.
The lifecycle authority input also includes a fresh public observation receipt bound to the exact
descriptor edition, descriptor bytes, ledger, publication plan, update-key scope, and prior
authorization. Train authorization must be issued no earlier than that observation or any state,
evidence, obligation, or intake event it approves.
The checked-in `stable-1.0-backport.example.json` deliberately models only that first post-GA
shape. Replace its complete predecessor identity—integer build, release id, and product
digest—before use. A later successor must add `latestPublishedMaintenancePointer`,
`previousStableBackportQueue`, and `previousStableBackportValidation`; copying the genesis shape
unchanged is rejected.

When an authenticated `hotfixFollowUpClosure` closes the predecessor's publication-created
shortened-window follow-up, the backport command uses the maintenance authority's closure-adjusted
predecessor state. Its protected queue, candidate, lineage, and validation bind the closure digest
so the next routine train can proceed without mutating the published baseline; the public
validation omits that protected digest, and train authorization cannot predate the closure.

Successful applicable modes write the canonical intake, plan, lineage, authoritative queue,
public queue projection, candidate,
authoritative validation, filtered public validation, authorization summary, optional completion,
train summary/report, checksums,
provenance, redaction, and component summary records below
`build/release-certification/<release-id>/stable-backport/`. Failure does not manufacture
placeholder success artifacts.

The authorization-summary filename contains the complete schema-validated train authorization.
The protected `validate-authorization` envelope contains that exact file together with the exact
train validation. `stable-maintenance` requires both manifest inputs, recomputes their complete
binding, and the protected maintenance workflow resolves the source run, workflow, candidate,
artifact name, and Actions artifact digest from the manifest’s
`stableBackportRunId`, `stableBackportArtifactName`, and
`stableBackportArtifactDigest` metadata. Producer copies must match the authenticated artifact
byte-for-byte. Maintenance then reseals those two authoritative files for every freeze,
preparation, validation, publication, and independent-verification handoff. Repository-readable
maintenance artifacts contain the encrypted envelope and no plaintext duplicate under either
`authenticated-inputs` or staged `protected-inputs`. Train `candidateDigest` is the candidate JSON
file digest and is intentionally not the maintenance candidate’s separate semantic
`candidateIdentityDigest`.

The protected `.github/workflows/stable-1.0-backport-release-train.yml` workflow maps
`evaluate-intake`, `prepare-candidate`, `validate-authorization`, and
`verify-release-completion` to those command modes. It binds an exact checkout and reviewed input
digest, runs with a read-only token, and separates the exact protected handoff from an allowlisted
public-safe projection. It
does not create or modify branches, commits, tags, pull requests, releases, catalogs, update
descriptors, or lifecycle state.

The authoritative `stable-1.0-release-train-queue.json` remains inside the protected component
and input chain. The workflow uploads two distinct artifacts: an authenticated encrypted envelope
for the next protected phase or maintenance consumer, and an allowlisted public artifact. The
latter contains
`stable-1.0-release-train-queue-public.json` and
`stable-1.0-release-train-validation-public.json`, not the authoritative queue, full validation,
authorization record, completion record, predecessor-completion handoff, or internal
checksums/provenance. The public schemas exclude touched/conflict paths, protected evidence ids
and digests, private-record digests, and exact per-fix source/backport internals while retaining
digest-bound public disposition, decision, and status projections.

Each non-initial phase resolves and downloads the exact prior Actions artifact and authenticates
its run, workflow, commit, operation, run attempt, digest, and encrypted-envelope binding before
decrypting the checksums, provenance, queue, and validation inside a protected environment. Use
the same canonical base64 32-byte
`CRYPTAD_STABLE_BACKPORT_HANDOFF_KEY_BASE64` secret in the protected backport-review,
backport-evidence, backport-authorization, maintenance-evidence,
`stable-1.0-maintenance-publication`, and
`stable-1.0-security-hotfix-publication` environments. Never expose that key in an input,
variable, log, summary, or artifact, and retain required plaintext records only in the separately
access-controlled support-lifetime input archive. The
completion phase uses that downloaded validation as `stableBackportFrozenValidation`. It also
supports a support-lifetime predecessor-completion reauthentication path: the protected input
bundle retains the exact completion, validation, authoritative queue, receipt, and lifecycle
authority after Actions retention expires. A new protected evaluation rechecks that digest-pinned
bundle and the current protected `main` and `develop` first-parent histories, then emits the exact
handoff consumed by later phases. Supplying an unexpired completion artifact remains an optional
byte-comparison fast path.

The release-train candidate-handoff authorization is bounded to 72 hours. That covers the required
24-hour post-freeze routine-maintenance soak plus up to 48 hours for evidence review and handoff;
it remains separate from, and never substitutes for, maintenance publication authorization.
The protected publisher requires that grant to have been current at the exact
maintenance-authorization handoff frozen into the bundle. It does not re-age that composition-only
grant against each later publication target or retry. Candidate evidence freshness and the separate
maintenance publication/activation authorizations retain their existing current-time checks.

The evaluate-to-prepare handoff is deliberately different from the later frozen-candidate
handoffs: the candidate may advance while approved fixes are landed, but the evaluated composition
may not be exchanged. The public queue contains a digest commitment to the protected immutable
fix/obligation composition and opaque transition digests. `prepare-candidate` requires the same
fix and obligation identities, the same composition commitment, and prefix-only state-transition
evolution. The obligation commitment includes its exact source train and source-fix identities;
otherwise rerun `evaluate-intake`.
The workflow resolves the protected `main` and `develop` tips and binds their exact reachability
evidence.
Routine phase provenance carries the frozen protected-development commit; a later phase rejects
the handoff if that commit is no longer reachable from the live protected `develop` tip.
Completion fetches the exact GitHub-API-selected protected-tip commit identities from the canonical
origin before checking their local object types and ancestry, so a protected branch advancing
after checkout does not create a false missing-object failure.

Completion verifies separate no-ff merges of the same published release/hotfix candidate into
`main` and `develop`; the `develop` merge does not name the `main` merge commit as its merged tip.
Because completion is read-only proof over the already published train digest, it may run after
the original candidate-handoff authorization expires. The receipt-bound frozen validation is
replayed at authorization issuance rather than re-aging candidate evidence against completion
time.

Authorization projections preserve the exact schema-valid `expiresAt` text from the full
authorization, including fractional seconds or an explicit UTC offset.
Protected provenance-review authorization uses an exclusive expiry boundary: it is invalid when
the captured validation time equals `expiresAt`.

See the [backport and release-train
runbook](../../docs/stable-1.0-backport-and-release-train-governance.md) for the full fix model,
Git provenance contract, security projection, maintenance integration, release-note behavior, and
manual operations.

## Stable 1.0 maintenance and security hotfix certification

Use one command and policy family for both release classes:

```bash
python3 tools/release-certification/certify.py stable-maintenance \
  --manifest build/stable-1.0-maintenance.json
```

The manifest selects `maintenance` or `security-hotfix` and one side-effect-free mode:
`validate-only`, `prepare-authorization`, or `close-hotfix-follow-up`. Output is release-scoped
under `build/release-certification/<release-id>/stable-maintenance/`. Self-tests and ordinary local
execution never tag, publish, insert a CoreUpdater descriptor, or update the latest baseline.
The generated `stable-1.0-maintenance-checksums.txt` names only noncircular public payloads:
product and package bytes, the stable catalog and detached signature, release notes, the
known-limitations delta, provenance, and `core-info.json`. It does not name internal certification
records. The checksum file itself and the public authorization are separately bound by exact size
and digest in the publication plan and receipt because including either would introduce a checksum
or authorization cycle. The separate
`stable-1.0-maintenance-audit-checksums.txt` deterministically inventories every other file in the
component output for internal audit and recovery and is never a planned public asset.
Candidate construction has a separate protected `freeze-candidate` boundary. Its versioned
`stable-1.0-maintenance-candidate-freeze.json` records the one-build producer and source identities,
toolchain and dependency-verification state, latest predecessor observation, exact checksum digest,
and the complete product, catalog, and package byte/signing/notarization receipt set. Subsequent
validation supplies that file as `inputs.maintenanceCandidateFreeze`; the candidate declaration,
candidate provenance, authorization, evidence envelope, and every evidence row bind its exact file
digest. Evidence must start after the recorded `frozenAt`. A rebuild, stale predecessor, extra or
replaced asset, or pre-freeze evidence requires a new freeze and cannot be repaired during
authorization preparation.

Production evidence rows bind the immediate predecessor build and product. The
`stable-maintenance.direct-ga-upgrade` row also binds the separately authenticated immutable GA
release id, build, and product digest; all non-GA rows forbid those GA fields. Normal validation and
hotfix follow-up closure enforce both identities, so a later successor cannot relabel its immediate
predecessor as the direct-GA upgrade source.
For immutable security hotfixes published before release-train governance, the v1 maintenance
authorization schema continues to accept an absent `backportReleaseTrainDigest` only so
`close-hotfix-follow-up` can authenticate the original authorization digest. Current preparation,
validation, and protected publication still require that field semantically and reject its
absence.

The standard manifest supplies `previousStableLifecycleLedger`,
`previousStableLifecycleDescriptor`, `stableLifecycleAuthorization`,
`stableLifecyclePublicationPlan`, and `stableLifecyclePublicationReceipt` from
`build/protected-inputs/lifecycle/`. The five inputs are indivisible: the engine authenticates the
predecessor's lifecycle eligibility, exact mutable descriptor edition and bytes, approved
authorization digest, authorized plan digest, trusted update-key scope, ledger digest, and verified
public receipt before it can report promotion readiness. Every post-GA successor predecessor
requires the exact five-artifact authority chain. A chain-depth-0 GA genesis run may omit all five
only to evaluate the first proposal; that bootstrap result is deliberately
`promotionReady=false` and `decision=no-go` until the separately protected GA-rooted lifecycle
descriptor has been published and verified.

The protected maintenance workflow uses four closed operations in four runs:
`freeze-candidate`, `prepare-authorization`, `validate-authorization`, and `publish`. Freeze is the
only operation that builds packages; it signs, notarizes, staples, and verifies the DMG before
recording any digest. Prepare consumes the exact attested freeze plus later candidate-bound evidence
and cannot replace an asset. Authorization validation consumes the exact prepared artifact plus an
approval artifact containing only the authorization JSON. Publish consumes the exact authorized
bundle and rejects separately supplied candidate, evidence, package, manifest, or authorization
inputs. Its provider is one protected, attested wheel pinned by producer run, artifact digest,
source commit, wheel digest, signer workflow, and entry point, then installed on each clean hosted
runner without dependency resolution. Publication and latest-baseline activation reread the remote
release/hotfix ref at their mutation boundaries. Publication requires the original authorization to
remain current before every public target. After the protected activation environment gate, the
workflow issues a separate activation-only authorization, valid for at most one hour and bound to
the exact verified receipt, successor, history, original authorization, and predecessor pointer.
That renewable grant prevents an environment wait from stranding already-published exact bytes;
activation audit state is uploaded even if post-mutation verification fails.

The protected input producer requires the lifecycle authority chain's exact five files in the normal post-GA
freeze and preparation bundles. Authorization validation still accepts only the approval JSON, so
the maintenance workflow restores the complete prepared manifest and protected-input tree, proves
that only the mode and authorization field changed, and stages exact lifecycle audit copies again.
Publish consumes the authorized artifact unchanged and retains those copies in its publication
audit; it cannot substitute a new lifecycle state at a later phase. Before re-attesting the phase
manifest, the producer verifies every lifecycle file against the canonical lifecycle workflow and
the exact reviewed lifecycle source commit.

Hotfix closure authenticates the already published successor baseline, publication receipt,
latest-published pointer, original authorization, and obligation, then emits a separately versioned
closure overlay. The next release lineage binds that overlay digest; closure never changes the
published hotfix bytes or rewrites an activated baseline. When a later hotfix carries the
obligation, candidate-freeze authentication uses the original predecessor observation in the exact
authorized freeze while the latest baseline, receipt, and pointer independently authenticate the
current carrier.
Protected publication writes `stable-1.0-maintenance-publication-receipt.json` only for a complete,
independently verified result. Failure and partial state use the closed
`stable-1.0-maintenance-publication-failure-audit.json` schema so unavailable observations and
possible side effects are recorded without manufacturing a canonical receipt.
An interrupted operation can resume only when the observed public targets are an exact matching
prefix in canonical mutation order followed solely by absent targets; any other partial topology is
a conflict and is never overwritten or deleted automatically.
The protected evidence environment must configure exact input and Windows signer-workflow
identities. It must also configure `STABLE_CATALOG_TRUSTED_KEYS_BASE64` as a base64-encoded
`TrustedAppKeys` properties registry containing production catalog public keys only. Before
freezing, the workflow decodes that registry into a mode-`0600` temporary file, verifies the exact
candidate catalog and detached signature with `AppCatalogVerifier`, and requires the signature key
id to equal the candidate's declared `signingKeyId`. The workflow deletes the registry before job
exit and records only the catalog digest, signature digest, key id, trusted-key-registry SHA-256,
algorithm, verifier identity, and passing status. It never writes public-key bytes or raw signature
content into a JSON verification record. The exact detached signature sidecar remains a separately
frozen and published asset.

Configure the approved publication backend source commit, wheel digest, signer workflow,
and entry point as repository-level Actions variables so the evidence-scoped independent verifier
and both publication environments receive the same immutable, public-safe identity pins. Do not
scope those four backend identity variables only to a publication environment. Keep the separate
catalog, CoreUpdater, and maintenance-state protected inputs in their purpose-specific publication
environments. Private target values are environment indirections only and are forbidden in
manifests, component outputs, failure audits, and receipts.

Build that backend only through
`.github/workflows/stable-1.0-maintenance-publication-backend-producer.yml` at a reviewed `main`
commit. The consumer pins the producer run, artifact name and digest, source commit, deterministic
wheel digest, signer workflow, and `cryptad_stable_maintenance_backend:factory` entry point before
installing it outside the candidate import path. The deployment service accepts canonical public
HTTPS roots with or without a trailing slash and non-root endpoints with at most one terminal
slash; it rejects internal empty or dot segments and non-global destinations. Its
`verify-publication` request receives the closed, digest-bound `verificationInputs` record set
needed to construct receipts, successor state, and history without out-of-band candidate data.
See [the publication-backend protocol](publication-backend/README.md).

The adapter materializes each target input, permanently scrubs all target-input names from its
local and ambient environments before importing the provider, and passes an opaque value only to
the one matching target operation. It also expands every concrete artifact, catalog/signature,
mirror/rollback, GitHub Release, and update-descriptor URI before authorization and rejects any
canonical cross-role collision.
The canonical signer workflows are
`.github/workflows/stable-1.0-maintenance-input-producer.yml` and
`.github/workflows/stable-1.0-maintenance-windows-package-producer.yml`. The former authenticates an
exact-digest public-safe phase ZIP from a secret protected-environment HTTPS locator. It rejects any
non-global DNS answer, pins the connection to the validated numeric endpoints, verifies the actual
peer, and uses the original hostname for TLS certificate verification before transmitting an
optional bearer credential. The complete extracted tree is allowlisted: only the canonical phase
manifest and its referenced protected inputs may survive into the attested artifact, so unrelated
root-level or sibling files fail intake. The latter builds the Windows EXE once,
Authenticode-signs and verifies it, rechecks the immutable tracked source, and attests the exact
EXE and producer receipt. Neither
workflow publishes release state.

The protected workflow performs current-time revalidation before exact-byte public mutations and
independent receipt verification afterward. See the [Stable 1.0 maintenance release and security
hotfix path](../../docs/stable-1.0-maintenance-release-and-hotfix-path.md) for required inputs,
lineage, evidence, authorization, private secret boundaries, idempotency, and recovery.

## Stable 1.0 support lifecycle certification

The lifecycle command authenticates the immutable Stable 1.0 GA root and every published
maintenance or security-hotfix successor before it assigns support state:

```bash
python3 tools/release-certification/certify.py stable-lifecycle \
  --manifest build/stable-1.0-support-lifecycle.json
```

The command has four side-effect-free modes: `evaluate`, `prepare-transition`,
`validate-authorization`, and `verify-publication`. It writes below
`build/release-certification/<release-id>/stable-lifecycle/`. Evaluation derives the release
inventory from exact GA and maintenance publication receipts, successor baselines, history links,
and the latest published pointer. A manifest label cannot add a release to that inventory.

`stable-1.0-support-lifecycle-policy.json` is the reviewed source of product support windows,
transition rules, authorization roles, descriptor freshness, Platform API removal constraints,
governance references, and non-waivable blockers. The closed lifecycle order is
`current-stable`, `supported-maintenance`, `security-fixes-only`, `deprecated`, and
`end-of-support`. Any non-revoked state can instead enter the separately authorized terminal
`revoked` state. The engine does not infer update-key compromise from build revocation.

Normal descriptors select exactly one `current-stable` authenticated chain tip. The versioned
policy permits zero current builds only when that exact tip is explicitly revoked before a safe
successor is available. Recovery-only transitions keep current, recommended, and replacement build
fields null and publish bounded recovery guidance; certification never manufactures the unsafe tip
as its own replacement.

Generated descriptors must remain directly consumable by the runtime parser. The complete
inventory is capped at 256 entries, each `statusEffectiveAt` is no later than descriptor
`effectiveAt`, and a revoked entry uses the same value for `statusEffectiveAt` and
`securityRevocationEffectiveAt`. A `supported-maintenance` entry leaves `replacementBuild` null;
the descriptor-level `recommendedBuild` carries its optional upgrade guidance. Certification and
the protected adapter reject schema/runtime text or release-identity mismatches before
publication.

Lifecycle output includes the authenticated inventory, append-only digest-chained ledger, proposed
transition set, runtime descriptor, Platform API deprecation timeline, catalog/app/content-profile
governance projection, publication plan, provenance, checksums, summary, report, and redaction
report. Historical GA and maintenance artifacts, including already published `core-info.json`
files, remain immutable. Changing support state produces a new edition of the separately
authenticated `support-lifecycle` update-key document.

Descriptor edition 1 requires a fresh protected proof that the exact lifecycle target returned
HTTP `404` and has never been published. Bootstrap may occur against the authenticated GA alone or
against a complete no-fork history containing already-published maintenance/hotfix builds. The
proof binds the inventory digest, GA root, chain tip, public URI, and update-key scope. HTTP `410`
is a tombstone, not absence, and fails closed. Once edition 1 exists, both
`previousStableLifecycleLedger` and `previousStableLifecycleDescriptor` are mandatory.

Ordinary certification never inserts that document. The protected
`stable-1.0-support-lifecycle-input-producer.yml` workflow first fetches one reviewed public-safe
ZIP by exact digest, rejects redirects, private endpoints, unsafe archives, unreferenced files, and
non-production execution flags, then attests its manifest and every protected input. The
`stable-1.0-support-lifecycle.yml` consumer pins that canonical producer identity.

Lifecycle input and publication jobs run only from protected `main`, the exact
`release/<build_version>`, or the exact `hotfix/<build_version>` ref. Their job conditions first
require GitHub's protected-ref context. The `source_commit` input must equal both the
workflow-dispatch `GITHUB_SHA` and the checked-out `HEAD`, which keeps GitHub's attested source
digest aligned with the code handling protected inputs. The jobs then query the live GitHub branch
record, require `protected=true`, fetch the same remote branch, and require the dispatch commit to
remain its ancestor. This ancestry check tolerates the branch advancing after dispatch; it does not
permit an independently selected older commit. The publication job repeats that proof before
insert material is made available; the input producer first completes it in a credential-free job
before requesting its environment, then repeats it before receiving the protected bundle locator
and bearer token.

Configure the lifecycle evidence, authorization, and publication environments with deployment
branch rules limited to protected `main`, `release/*`, and `hotfix/*` refs. Workflow job conditions
retain the exact-build allowlist independently of those repository settings.

Authorization validation restores those attested inputs and reruns `stable-lifecycle`; it does not
trust a caller-assembled authorization summary or publication plan. Publication repeats the same
certification immediately before mutation, then performs a live read of the separately bound
maintenance latest-pointer URI. GA-only history requires pointer absence. Post-GA history requires
the exact pointer digest and tip identity. Lifecycle and maintenance publication share the
`stable-1-0-maintenance-publication` concurrency lock so the pointer cannot advance between that
read and lifecycle insertion within the protected workflows.

Publication material is supplied only through the protected lifecycle environment. The publisher
accepts identical existing bytes as an idempotent verification, rejects conflicting bytes without
overwrite, fetches the public result again, and emits an exact-byte receipt. It preserves the
authorized component and its checksum closure unchanged; the actual receipt, preflight, and
operation summary are root-level siblings in the complete published bundle. Independent
verification consumes that complete bundle, proves the original publication receipt was generated
inside the bound authorization window, and writes a separate receipt. The read-only re-fetch may
run after that approval expires; validation and publication may not. Pull requests,
self-tests, and the default `evaluate` path cannot invoke publication.

See the [support lifecycle and deprecation governance runbook](../../docs/stable-1.0-support-lifecycle-and-deprecation-governance.md)
for policy clocks, descriptor rollback protection, runtime behavior, Platform API and ecosystem
deprecation rules, security revocation, protected operations, recovery, and public-data boundaries.
