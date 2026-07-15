# Stable 1.0 RC execution and release freeze

Use this workflow to turn an already promotable, Stable-ready candidate into a reproducible Stable
1.0 release candidate. The command executes the existing protected production and Stable-review
gates, freezes the reviewed candidate, packages public artifacts, verifies the package against the
freeze, and produces the final RC go/no-go record.

Stable 1.0 is a product and Platform API milestone. Cryptad release identity remains an integer
build number, a `release/<build-number>` branch when release operations begin, and a
`v<build-number>` tag if the candidate is later published. The RC workflow does not create a
branch or tag, merge code, publish a GitHub Release, or declare Stable 1.0 generally available.

## Before running the RC

Start with a finalized candidate commit and one path-safe release ID. Every unified component
summary supplied to the run must be evidence envelope v2 bound to that release ID, integer build,
compatible protected profile, and candidate source commit where the producer records it. Explicit
native inputs such as interop, performance, third-party intake, public known issues, and stable
catalog operations retain their versioned native contracts and must pass the corresponding
release/build/source binding, freshness, and redaction checks.

The protected run requires all of the following:

- a clean, known Git workspace bound to the candidate commit;
- a complete Gradle build plus first-party app stage, production sign, and verify stages;
- protected production app-signing and reviewer identities whose key IDs are public metadata but
  whose private material remains outside the manifest and artifacts;
- passing production-beta, production go/no-go, release-certification, ecosystem-matrix, and
  Stable-readiness results;
- real live-network, sandbox-provider, multi-node, previous-candidate upgrade, network-scale,
  security-drill, third-party-intake, and catalog-operations evidence;
- third-party intake evidence that explicitly records `fixtureOnly=false`, `simulatedOnly=false`,
  `nonRelease=false`, and `nonProduction=false`; omitted classification flags fail closed;
- the Stable readiness policy, public beta known issues, Stable known limitations, and required
  first-party app maintenance/readiness data;
- a stable catalog channel with verified primary or mirror transport, signature trust, rollback,
  and key-rotation state; and
- redaction-safe source evidence and a public HTTPS artifact base URI.

Fixture evidence, test or candidate-only signing, simulated-only live evidence, skipped build
stages, stale or wrong-candidate summaries, dirty or unknown workspace state, and unresolved
redaction findings are never Stable RC promotion evidence.

Stable readiness may be `ready` or `ready-with-allowed-limitations`. In the latter case every
limitation must be policy-recognized, bounded, owned, and copied without omission into the freeze,
RC known-limitations artifact, and release-note draft. An allowed limitation is not a waiver.
Disallowed or beta-only limitations block the RC.

## Prepare the manifest

Copy the fail-closed example and replace every `REPLACE_...` value. Review every protected input
path instead of treating the example as runnable configuration.

```bash
cp tools/release-certification/manifests/stable-1.0-rc.example.json \
  build/stable-1.0-rc.json
```

The manifest uses the existing `stable-review` profile. Do not change it to a semantic version or
invent a separate release profile. The Stable RC command orchestrates the strict existing
production-beta, go/no-go, release-certification, and Stable-readiness pipeline within the same
release-scoped workspace.

The example deliberately contains placeholder paths and an `example.invalid` artifact base URI,
so an unedited copy fails closed. Private keys, private insert URIs, form passwords, tokens,
cookies, and live authorization values belong only in the protected execution environment or
protected files. Never add them to the manifest.

The RC-specific manifest inputs are:

- `stableCatalogOperations`: the candidate-bound catalog operations and mirrors summary for the
  exact stable catalog revision being frozen; its evidence kind is
  `stable-1.0-rc-catalog-operations` and its schema is
  `tools/release-certification/schemas/stable-1.0-rc-catalog-operations-v1.schema.json`. Its
  `artifactTimestamp` is part of the reviewed evidence and must be the timestamp used to generate
  the signed catalog and every first-party review receipt;
- `previousStableRcFreeze`: the previous Stable RC freeze when verifying a later candidate or
  refreeze; it is required in `refreeze` mode and forbidden in `first-freeze` mode; and
- `stableRcFreezeExceptions`: an optional redaction-safe exception collection whose kind is
  `stable-1.0-rc-freeze-exceptions` and whose schema is
  `tools/release-certification/schemas/stable-1.0-rc-freeze-exceptions-v1.schema.json`.

Previous-candidate upgrade and release-history evidence remain mandatory even when there is no
earlier Stable RC freeze. Omit an optional waiver or exception input rather than creating an empty,
under-authorized, or placeholder production record.

Set `policies.stableRcFreezeMode` explicitly. Use `first-freeze` only for the initial immutable
baseline for one release ID and integer build. Use `refreeze` for every later execution and supply
the exact `stable-1.0-rc-freeze.json` from the latest successful protected run. The workflow
prefers to download that run's authenticated artifact and compare the freeze bytes before
execution. Each successful run also records the exact freeze file digest in an authenticated
GitHub Actions check-run lineage anchor tied to the run, attempt, candidate, build, and source
commit. If the short-lived artifact has expired or is otherwise unavailable, a retained copy of
the freeze is accepted only when its digest matches that exact anchor for the latest successful
run. A stale parent, missing or mismatched anchor, or unavailable workflow history fails closed.
The protected workflow also serializes executions for the same candidate and rejects reruns in
`first-freeze` mode. Release managers must retain the canonical freeze outside the expiring
workflow artifact when future refreezes may be required.

Signing secrets and live insert material must be supplied through the protected environment
described by the workflow. The manifest contains only paths to sanitized evidence and public-safe
policy metadata.

The protected production pipeline reads `artifactTimestamp` before it signs the in-run catalog and
review receipts. The generated catalog's `catalog.generatedAt` must match that instant. This makes
an independently reviewed catalog-operations record reproducible from the same source, signing
identities, catalog revision, app bundles, and artifact base URI. `generatedAt` on the operations
record remains the time when the operational checks completed; it must not precede
`artifactTimestamp`.

Do not add separately precomputed `productionBeta`, `goNoGo`, `releaseCertification`,
`ecosystemMatrix`, `appPlatform`, or `stableReadiness` inputs to the canonical manifest. They are
generated and consumed inside the same protected `stable-review` orchestration and are bound through
its release-scoped workspace. The example's `https://REPLACE_ME.invalid` URI is intentionally
unusable until the release manager replaces it with the reviewed public artifact base URI.

## Execute the canonical workflow

Run the focused deterministic self-test before protected execution:

```bash
python3 tools/release-certification/certify.py stable-rc --self-test
```

Then run the canonical command from the candidate commit:

```bash
python3 tools/release-certification/certify.py stable-rc \
  --manifest build/stable-1.0-rc.json
```

The release-scoped component is:

```text
build/release-certification/<release-id>/stable-rc/
```

Do not run separate `production-beta` and `stable-review` manifests with the same release ID under
the same output root. The workspace marker binds the run to one release ID, integer version, and
profile. The `stable-rc` command is the canonical orchestration boundary.

## What the freeze records

The versioned schema is
`tools/release-certification/schemas/stable-1.0-rc-freeze-v1.schema.json`. Canonical serialization
uses stable key and collection ordering, path-safe relative names, and a content digest that does
not vary with incidental filesystem metadata.

The freeze covers these domains:

- candidate identity: release ID, integer build, Stable milestone `1.0`, source provenance,
  generator version, prerequisite evidence digests, and the exact deterministic Stable RC product
  distribution digest;
- Platform API 1.0: authoritative baseline and generated-contract digests, compatibility-window
  policy, stable and experimental counts, and stable-breaking-change verification;
- stable catalog: ID, stable channel, edition/revision, frozen artifact timestamp, signed bytes and
  sidecar digests, signing key ID, key rotation, primary/mirror health, rollback verification,
  advisory and denylist counts, and the exact ordered app entries;
- first-party apps: exact policy-required app set, versions, bundle and manifest digests,
  permissions, signing and reviewer key IDs, review receipts, API compatibility, app-data schemas,
  migrations, backup/restore state, support metadata, and redacted diagnostics readiness;
- content formats: Profile, Feed, Trust Statement, Social Message, and Social Outbox profile
  versions, statuses, canonicalization rules, size policies, signing payload rules, and compatibility
  evidence; and
- policy and limitations: Stable-readiness policy, exact allowed limitations, public beta known
  issues, Stable known limitations, security drills, legacy plugin/admin freeze, and support and
  feedback readiness.

Experimental API or profile state is recorded separately. An experimental-only API change may be
reviewable when the authoritative stable surface remains identical, but a stable baseline or
generated stable-surface mismatch blocks the RC. This workflow does not change Platform API 1.0
membership.

Trust Graph or Social Inbox may retain an explicit `local-rc` status only when the authoritative
Stable policy recognizes and binds that status to an allowed limitation. The freeze and notes must
not relabel it as globally stable or legacy-protocol compatible.

## Generated artifacts

The component writes the common evidence envelope v2 files:

```text
summary.json
report.md
redaction-report.json
```

Its native public artifacts are:

```text
stable-1.0-rc-freeze.json
stable-1.0-rc-freeze.sha256
stable-1.0-rc-freeze-report.md
stable-1.0-rc-drift-report.json
stable-1.0-rc-promotion-summary.json
stable-1.0-rc-go-no-go.md
stable-1.0-rc-known-limitations.json
stable-1.0-rc-release-notes.md
platform-api-current-contract.json
platform-api-stable-diff.json
content-format-profiles.json
<first-party-app-id>-api-compatibility.json
checksums.txt
provenance.json
<deterministic Stable RC archive>
```

The release-note artifact is generated from
[the Stable 1.0 RC notes template](templates/stable-1.0-rc-release-notes.md). It identifies the
candidate as an RC, not GA, and does not claim a tag or publication has occurred.
The template has a version marker and one ordered token for each documented review section. A
missing, duplicate, unknown, or reordered token fails the RC instead of producing a partial draft.

The public archive contains only release artifacts, required release reports, checksums, freeze and
provenance metadata, and redacted summaries. It excludes raw evidence, private signing sidecars,
insert material, diagnostics, support bundles, app data, identities, and credentials.

Production-beta still emits its broad evidence archive for existing production-beta consumers.
Stable RC additionally requires `crypta-stable-1.0-rc-<build>-product.tar.gz`. That product
distribution contains the staged and signed first-party app payloads, app bundles, candidate-built
developer launcher, signed stable catalog, channel metadata, review receipts, transparency record,
and the two public first-party policy inputs. It excludes run-specific reports, command durations,
CI attempt metadata, and live evidence. The production packager writes members in stable order and
normalizes gzip/tar timestamps, ownership, and modes. Rebuilding the same candidate with the same
protected `artifactTimestamp` therefore produces the same signed bytes and product-distribution
digest while all release gates still execute again.

The deterministic archive is named `cryptad-stable-1.0-rc-<build>.tar.gz` and has one normalized
`stable-1.0-rc/` root. Its `payload/` directory contains the exact deterministic
`crypta-stable-1.0-rc-<build>-product.tar.gz`; `metadata/` contains the freeze, freeze sidecar and report,
promotion summary, go/no-go report, known limitations, release-note draft, drift report,
provenance, redaction report, generated Platform API snapshot and diff, authoritative content-format
registry export, and each first-party app API-compatibility result. All supporting verifier files
pass the same redaction scan and are included in both checksum allowlists. Root
`payload-checksums.txt` binds every payload and metadata member without a parent path or circular
self-reference. External `checksums.txt` binds those source artifacts, the deterministic product
distribution, and the final outer archive.

## Verify drift

Generation is not promotion. After packaging, the command recomputes and verifies the freeze,
checksums, provenance bindings, archive members, and redaction state against the packaged
candidate. The drift report uses these statuses:

- `no-drift`: current candidate and packaged artifacts match the active freeze;
- `approved-freeze-exception`: an authorized blocker fix is recorded, but the old freeze and
  release artifacts are invalid and cannot be promoted;
- `unapproved-drift`: a frozen item changed without an acceptable exception;
- `invalid-freeze`: the freeze is malformed, unsafe, wrong-candidate, or cannot be verified.

Only final `no-drift` is promotable. Drift includes changes to candidate identity, Platform API
stable surface, generated contract, catalog bytes/signature/revision/channel, app set or metadata,
content profiles, policy and limitations, evidence provenance, production distribution bytes,
archive contents, checksums, or redaction status. Accepted freeze-exception records are immutable
audit history: later refreezes carry them forward automatically, and removal or modification is
unapproved drift. Missing or newly introduced artifacts are also drift.

Archive verification rejects unsafe or absolute member names, traversal, symlinks, hard links,
special files, AppleDouble files, `.DS_Store`, `__MACOSX`, secret-like files, and unsafe nested
archives. A checksum mismatch after packaging makes the final decision `no-go`.

## Repair a blocker after freeze

After freeze generation, only a blocker or security fix should change the candidate. Record it in
the versioned `stable-1.0-rc-freeze-exceptions` collection. The collection must carry
`authorizationRole=stable-release-manager` and a passing redaction result with zero findings; a
nonempty approver name alone is not sufficient authorization. Each exception identifies the
release and integer build, affected frozen item, before and after digests, reason, `blocker` or
`security` issue kind and reference, owner, approver, creation and expiry or review time, required
rerun scope, and final verification result.

An accepted exception follows this sequence:

1. Record and authorize the narrow blocker fix.
2. Invalidate the old archive, checksums, provenance, and freeze.
3. Apply the fix without changing unrelated frozen state.
4. Rerun every affected check and every final promotion gate.
5. Regenerate the complete freeze and public artifacts.
6. Verify the regenerated candidate and package to final `no-drift`.
7. Surface the exception in the RC report and release-note draft.

An exception cannot bypass redaction, an unknown or compromised signing identity, production
signing, live/multi-node/previous-candidate evidence, security drills, candidate binding, or a
beta-only/disallowed limitation. It cannot authorize a Stable API break outside the existing
compatibility and deprecation process. An expired, malformed, stale, wrong-release, or
under-authorized exception fails closed.

## Interpret the final decision

The common `summary.json` is evidence envelope v2. A promotable result requires:

```text
result.status = pass
result.promotionReady = true
result.exitCode = 0
redaction.status = pass
payload.legacy.nonRelease = false
payload.legacy.stableReady = true
payload.legacy.freeze.status = pass
payload.legacy.freeze.driftStatus = no-drift
payload.legacy.decision = go or go-with-waivers
```

The summary subject must also match the requested release ID, integer build, `stable-review`
profile, and `stable-rc` component. The native promotion summary repeats the decision-critical
fields for review.

`go-with-waivers` is eligible only when every waiver is policy-compliant, scoped, approved,
unexpired, and cannot conceal a non-waivable blocker. Allowed Stable limitations are reported
separately and do not change the decision vocabulary. Any missing, malformed, failing, stale,
wrong-candidate, fixture, skipped-stage, redaction-unsafe, or drifted input produces `no-go` and
`promotionReady=false`.

## Run in the protected workflow

The manual `.github/workflows/stable-1.0-rc-release.yml` job uses the protected Stable RC
environment and JDK 25. It requires the candidate release ID and integer build, checks the build
against `./gradlew -q printVersion`, binds the clean checkout to the workflow commit, materializes
sanitized protected evidence under an ignored repository-relative `build/` directory and signing
files under the runner temporary directory, runs the Stable RC command, verifies the final
envelope, and uploads only the public RC component after final go and redaction pass. No absolute
runner path is serialized into the release manifest or public artifacts.

Select `first-freeze` for the candidate's first successful workflow only. The workflow records the
release ID and build in its run title, serializes that candidate's executions, and refuses another
first freeze after a successful baseline. Select `refreeze` for verification, blocker repair, or
any later run and provide the freeze from the latest successful protected run. The workflow rejects
an older lineage parent even when its release ID and build match. It authenticates the exact
artifact bytes while that artifact is available and otherwise authenticates the retained file
against the latest run's commit-bound check-run digest. The final gate binds that baseline and the
exact production distribution bytes in both the canonical freeze and provenance.

Catalog-operations evidence must conform exactly to the closed
`stable-1.0-rc-catalog-operations-v1.schema.json` contract. Unknown or non-production fields block
promotion. The verified rollback target must have a lower revision than the frozen current catalog,
must bind different catalog bytes, and must pass signature verification.

The workflow does not tag, create a GitHub Release, merge a release branch, insert release
descriptors, or publish GA. If the reviewed RC is later selected for release, follow
[the Cryptad release workflow](cryptad-release-workflow-and-runbook.md) and
[the standard Git workflow](standard-git-branching-and-release-workflow.md) as a separate,
authorized operation.
