# Stable 1.0 protected release execution

This runbook is the operator procedure for one protected Stable 1.0 release execution. It wraps,
but does not replace, the canonical `stable-rc` freeze and `stable-ga` exact-byte promotion
authorities. A repository checkout, a passing self-test, or a preflight report is implementation or
offline evidence only. None of those facts proves that a protected RC was frozen, GA was published,
or public bytes were observed.

Stable GA never rebuilds the Stable RC. Any payload change, including a packaging-only change,
requires a new protected RC refreeze and a new GA authorization.

## Authority and evidence boundaries

| Classification | What it can prove | What it cannot prove |
| --- | --- | --- |
| Repository implementation | Workflows, engines, schemas, policy, and tests exist at an exact commit. | That any protected workflow ran. |
| Offline verification | One exact dispatch package passed deterministic preflight. | That GitHub environments approved it or remote state exists. |
| Protected operation | An authenticated workflow run, immutable attempt, artifact digest, and receipt completed in its required environment. | Public availability unless separately observed. |
| Public observation | Independently fetched public bytes match the authenticated publication receipt and final RC digests. | Independent reproducibility unless separately performed. |

The phase-11 assurance closeout remains a repository-delivery closeout. It is not a substitute for
the per-execution contract or any remote receipt. Missing protected receipts must remain missing;
an operator must never replace them with a repository claim, fixture, self-test, or simulated
result.

The four canonical protected environments are:

| Environment | Workflow boundary | Expected protection |
| --- | --- | --- |
| `stable-1-0-rc` | `stable-1.0-rc-release.yml` freeze job | Stable release-manager reviewers; protected `release/<build>` branches only; administrator bypass disabled; production signing secrets scoped here. |
| `stable-1-0-ga-evidence` | `stable-1.0-ga-promotion.yml` evidence approval job | Reviewers independent of the dispatch author where repository policy requires it; no publication authority; administrator bypass disabled. |
| `stable-1-0-ga` | `stable-1.0-ga-promotion.yml` publication job | Manual publication approval after validation and evidence approval; protected release branches only; administrator bypass disabled; publication secrets scoped here. |
| `stable-1-0-public-observation` | `stable-1.0-public-observation.yml` read-only observer | Independent reviewer approval after publication; no write permissions or publication secrets; administrator bypass disabled. |

Environment configuration lives in GitHub, not in workflow YAML. Before the first real execution,
an administrator must inspect the environment configuration using the `leumor` GitHub identity and
record the non-secret settings in the execution review. The local preflight validates the expected
names and workflow paths; it cannot prove remote reviewer lists, branch restrictions, or bypass
settings.

## Non-secret execution contract

Copy
`tools/release-certification/manifests/stable-1.0-protected-release.example.json` to a
repository-relative ignored working path such as
`build/protected-release/stable-1.0-protected-release.json`. Replace every placeholder and zero
digest with authentic values, and replace the sentinel `evaluationTime` with the current runner
UTC immediately before preflight. The repository-selected evidence IDs, kinds, and schema names in
the example are policy values and must not be replaced. The contract schema is
`stable-1.0-protected-release-execution-v1.schema.json`.

The contract binds:

- `github.com/crypta-network/cryptad`, the lowercase 40-character candidate commit, and
  `refs/heads/release/<build>`;
- release ID, positive integer build, and `first-freeze` or `refreeze` mode;
- the exact previous freeze file and digest for a refreeze, or `null` for a first freeze;
- credential-free HTTPS artifact, catalog primary, mirror, and rollback targets;
- every required upstream evidence file, exact byte digest, freshness, candidate binding, and
  truthful authority class; protected producers additionally bind the exact workflow commit, run,
  attempt, artifact name, Actions digest, environment, and conclusion;
- every RC supplemental input under `rcInputs`, including known issues and any optional
  waiver/exception file that will actually be dispatched;
- the protected workflow paths, environments, and public key/reviewer/policy labels;
- selected RC, GA validation, evidence approval, authorization, publication, and separate
  read-only public-observation coordinates when those facts become available;
- publication intent and the separate public-observation requirement; and
- lifecycle and evidence-classification state without turning an absent receipt into success.

Do not put secrets, private insert URIs, raw vulnerability or support content, raw app data,
reporter identity, private identity material, credentials, or absolute workspace paths in the
contract. `actions-artifact://` and HTTPS strings are transport locators, not producer
authentication. The protected RC job accepts those locators only for acquisition and then compares
the materialized bytes with the reviewed contract before freezing.
For the Stable vulnerability authorities, repository policy requires PR-288 evidence from
`.github/workflows/stable-1.0-vulnerability-intake.yml` in
`stable-1.0-vulnerability-case`, and PR-290 prepublication evidence from
`.github/workflows/stable-1.0-dependency-vulnerability-evaluation.yml` in
`stable-1.0-dependency-vulnerability-evaluation`. A matching summary from another workflow or an
unprotected environment is not protected release evidence.

The required evidence identities, authority classes, and repository-selected schemas are closed
by `stable-1.0-protected-release-policy.json`; a contract row cannot select a more permissive
schema or claim a producer that does not exist. Stable vulnerability, Stable supply chain, and
Stable dependency vulnerability are `protected-producer` evidence with exact GitHub coordinates.
Catalog operations, live network, network scale, multi-node, previous-candidate, release history,
and security drills are `exact-dispatch-input` evidence whose reviewed bytes must be supplied
unchanged. App platform, Hyphanet interop, performance, release certification, sandbox provider,
Stable readiness, and the production-beta aggregate are `rc-generated-prerequisite` rows: their
preflight evidence establishes readiness to dispatch, and the protected RC job regenerates and
gates them before freezing. The native third-party intake JSON remains a separate required exact
binding under `rcInputs.thirdPartyIntake`; it is not relabeled as a production-beta envelope.
Together these identities cover app platform, catalog operations, Hyphanet
interop, performance, live network, network scale, multi-node, sandbox, security drills,
third-party intake, previous-candidate and release history, release certification, Stable
readiness, Stable vulnerability, Stable supply chain, and Stable dependency vulnerability. Each
must be real release evidence for this exact candidate; fixtures, simulated-only evidence,
non-release output, test signing, stale evidence, and merely aggregate passing summaries are
rejected.

## Secrets and public identities

Only names and purposes belong in operator records. Never record values.

| Environment | Name | Purpose |
| --- | --- | --- |
| RC | `CRYPTAD_STABLE_VULNERABILITY_ANCHOR_READ_TOKEN` | Read the authenticated current Stable vulnerability ledger anchor. |
| RC | `CRYPTAD_STABLE_VULNERABILITY_HANDOFF_KEY_BASE64` | Open/authenticate the protected vulnerability promotion handoff. |
| RC | `CRYPTAD_STABLE_SUPPLY_CHAIN_HANDOFF_KEY_BASE64` | MAC-authenticate the attested PR-289 supply-chain handoff. |
| RC | `CRYPTAD_STABLE_DEPENDENCY_VULNERABILITY_ANCHOR_READ_TOKEN` | Read the current PR-290 ledger anchor. |
| RC | `CRYPTAD_STABLE_DEPENDENCY_INTELLIGENCE_LINEAGE_READ_TOKEN` | Verify the current dependency-intelligence lineage. |
| RC | `CRYPTAD_STABLE_DEPENDENCY_VULNERABILITY_HANDOFF_KEY_BASE64` | Authenticate the PR-290 evaluation handoff. |
| RC | `CRYPTAD_APP_SIGNING_KEY_ID` | Public production app-signing key label. |
| RC | `CRYPTAD_APP_SIGNING_PRIVATE_KEY_BASE64` or `CRYPTAD_APP_SIGNING_PRIVATE_KEY_FILE` | Production app-signing private key, supplied by exactly one trusted materialization route. |
| RC | `CRYPTAD_APP_SIGNING_PUBLIC_KEY_BASE64` or `CRYPTAD_APP_SIGNING_PUBLIC_KEY_FILE` | Matching production app-signing public key. |
| RC | `CRYPTAD_APP_REVIEWER_KEY_ID` | Public production reviewer key label. |
| RC | `CRYPTAD_APP_REVIEWER_PRIVATE_KEY_BASE64` or `CRYPTAD_APP_REVIEWER_PRIVATE_KEY_FILE` | Production reviewer private key, supplied by exactly one trusted materialization route. |
| RC | `CRYPTAD_APP_REVIEWER_PUBLIC_KEY_BASE64` or `CRYPTAD_APP_REVIEWER_PUBLIC_KEY_FILE` | Matching production reviewer public key. |
| RC | `CRYPTAD_APP_REVIEW_POLICY_ID`, `CRYPTAD_APP_REVIEW_POLICY_VERSION` | Exact production review policy identity. |
| GA publication | `CRYPTAD_STABLE_VULNERABILITY_ANCHOR_READ_TOKEN`, `CRYPTAD_STABLE_VULNERABILITY_HANDOFF_KEY_BASE64` | Reauthenticate current vulnerability state immediately before mutation. |
| GA publication | `CRYPTAD_STABLE_DEPENDENCY_VULNERABILITY_ANCHOR_READ_TOKEN`, `CRYPTAD_STABLE_DEPENDENCY_INTELLIGENCE_LINEAGE_READ_TOKEN`, `CRYPTAD_STABLE_DEPENDENCY_VULNERABILITY_HANDOFF_KEY_BASE64` | Reauthenticate current PR-290 state immediately before mutation. |
| GA publication | `LEUMOR_GITHUB_TOKEN` | The only token authorized for tag, draft Release, asset, and Release-finalization mutations. It must belong to `leumor`. |
| GA publication | `STABLE_CATALOG_TRUSTED_KEYS_BASE64` | Public trusted catalog-key registry used to verify the exact catalog targets. |
| Closeout operator | `GH_TOKEN` | Read-only GitHub API authentication of every retained protected run/attempt/artifact. It must authenticate as `leumor`; use a token with repository Actions metadata read access and no release-mutation purpose. |

On the hosted Linux runner, base64 materialization is the normal key-file route. A `*_FILE` value
is valid only when a separately trusted setup has placed that readable file on the runner. Do not
set both routes, and never echo a secret or key file.

The execution contract records the app signing key ID, reviewer key ID, review policy ID and
version, and catalog signing key ID. Immediately before `stable-rc`, the protected workflow writes
the actual runtime labels into its closed materialized-input map; the catalog label comes from the
exact reviewed catalog-operations document. `rc-dispatch` requires all five labels to equal the
reviewed contract. It never records private key bytes.

## Deterministic local preflight

Use a clean checkout of the exact release commit with Java 25 and the checked-in Gradle wrapper.
The source ref must resolve unambiguously to that commit and `build.gradle.kts` must contain the
same integer build.

```bash
python3 tools/release-certification/certify.py stable-protected-release \
  --mode preflight \
  --execution-contract build/protected-release/stable-1.0-protected-release.json
```

The command is side-effect-free with respect to release and remote state. It writes deterministic
JSON, Markdown, and a redaction report beneath
`build/release-certification/<execution-id>/stable-protected-release/`. Review the JSON dispatch
package and bind its `contractDigest` into the operator approval record. A changed contract requires
a new preflight and review. Once the summary is bound as `operationEvidence.preflight`, retain its
exact bytes as immutable input evidence. The `rc-dispatch` and `closeout` modes write by default to
the `rc-dispatch/` and `closeout/` subdirectories beneath that Stable protected-release directory;
they never reuse the preflight receipt path. An explicit output directory is rejected if any output
file would replace the contract, RC input map, or a contract-bound evidence file. The declared
`evaluationTime` must be within the policy's five-minute
skew of the runner's observed UTC; replaying an old contract cannot extend evidence or authorization
freshness. That skew is checked when the reviewed preflight receipt is created, not used as a
five-minute dispatch TTL. The protected RC job preserves the exact contract and receipt across
environment approval and build time, then rechecks every materialized evidence expiration and
native intake age against its current dispatch clock before invoking `stable-rc`.

Preflight fails closed for dirty or ambiguous Git state, wrong commit/ref/build, toolchain drift,
placeholder or non-HTTPS public targets, missing catalog identities, contradictory freeze mode,
missing/stale/wrong-candidate evidence, incomplete Stable governance, fixture/test-signing output,
unsafe archives or links, AppleDouble/`__MACOSX`/`.DS_Store`, nested archives, secret or private
material, unexpected environments/workflows, unpinned actions, and publish intent without an exact
RC, evidence approval, and unexpired authorization.

Also run the Stable self-tests listed in `tools/release-certification/README.md`. A passing local
preflight is a dispatch prerequisite, not permission to publish.

## First Stable RC freeze

Use `.github/workflows/stable-1.0-rc-release.yml` on the protected
`release/<integer-build>` ref. Supply:

- candidate release ID, integer build, and the exact lowercase 40-character candidate commit;
- `first-freeze`, an empty `previous_stable_rc_freeze`, and the reviewed artifact base URI;
- exact live-network, multi-node, network-scale, previous-candidate, release-history,
  security-drill, third-party-intake, known-issues, and catalog-operations inputs;
- optional waiver/exception files only when the canonical authorities permit them; and
- exact run ID, immutable attempt, expected artifact name, and `sha256:` Actions artifact digest
  for the Stable vulnerability, supply-chain, and dependency-vulnerability producers.

After preflight, add its exact summary file binding to `operationEvidence.preflight` without
changing any planned field, then supply both `protected_execution_contract` and
`protected_preflight_receipt`. The contract must be the exact compact JSON document whose plan
digest the receipt authenticated; pass the receipt input as its exact compact JSON, not as a local
path that will be absent from the hosted runner. Do not reconstruct either document from the other
dispatch fields.
Immediately before the freeze, the protected job writes a closed materialized-input map and runs:

```bash
python3 tools/release-certification/certify.py stable-protected-release \
  --mode rc-dispatch \
  --execution-contract build/stable-rc-protected-inputs/stable-1.0-protected-release-execution.json \
  --rc-input-map build/stable-rc-protected-inputs/stable-1.0-rc-materialized-input-map.json
```

That verifier requires the exact ten externally materialized evidence files, the three Stable
producer coordinates, all five actual runtime signing/review identities, the canonical passing
preflight receipt, native third-party intake, known
issues, optional waivers/exceptions, and any refreeze predecessor to match the reviewed contract.
It also requires the exact seven-item RC-generated gate set. Any byte, coordinate, authority class,
release, source, mode, or target substitution stops the workflow before `stable-rc`.

Because GitHub limits a manual workflow to 25 top-level inputs, the RC dispatch carries those
twelve coordinate fields as one closed `stable_authority_coordinates` JSON value:

```json
{
  "stableDependencyVulnerability": {
    "artifactDigest": "sha256:<64-lowercase-hex>",
    "artifactName": "<exact-artifact-name>",
    "runAttempt": "<positive-integer>",
    "runId": "<positive-integer>"
  },
  "stableSupplyChain": {
    "artifactDigest": "sha256:<64-lowercase-hex>",
    "artifactName": "<exact-artifact-name>",
    "runAttempt": "<positive-integer>",
    "runId": "<positive-integer>"
  },
  "stableVulnerability": {
    "artifactDigest": "sha256:<64-lowercase-hex>",
    "artifactName": "<exact-artifact-name>",
    "runAttempt": "<positive-integer>",
    "runId": "<positive-integer>"
  }
}
```

The key set is closed; do not add transport paths, tokens, or private material.

The protected job checks the exact source and workflow commit, protected ref, clean tree, integer
build, pinned JDK/Gradle setup, all candidate gates, production signing, archive hygiene, and
post-package drift. It invokes `stable-rc` as the only freeze authority. It must not create a tag,
GitHub Release, public catalog update, or other GA mutation.

After success, retain outside the 30-day Actions retention window, without altering bytes:

- repository and workflow path;
- run ID and immutable attempt;
- artifact name and Actions artifact digest;
- source commit and protected source ref;
- freeze JSON and sidecar digests, product and outer archive digests;
- authenticated check-run lineage anchor and completion time; and
- the redacted artifact as a safe retained copy.

If the job fails, retain its bounded failure closeout. Do not describe the RC as frozen.

## Refreeze after a blocker or payload change

Set `refreeze` and provide the exact `stable-1.0-rc-freeze.json` from the latest successful
protected run for the same release ID and build. The workflow authenticates that it is the latest
successful parent using the retained artifact or its check-run lineage anchor. An absent,
ambiguous, stale, or older predecessor stops the run.

Any byte change, source change, target change that affects frozen metadata, signing change, or gate
remediation that changes the payload requires a refreeze. Never patch RC bytes in place and never
reuse an earlier GA authorization after a refreeze.

## RC review

Before GA work, reviewers confirm:

- the workflow conclusion is successful and the run attempt is the immutable selected attempt;
- the artifact digest and every retained member match the RC lineage and freeze;
- product, archive, checksums, provenance, app/catalog signatures, and normalized archive layout
  agree exactly;
- Stable vulnerability, dependency-vulnerability, supply-chain, readiness, security, live,
  network-scale, multi-node, sandbox, intake, interop, performance, and release-history child gates
  are present and passing;
- redaction passed and no private/raw material crossed the artifact boundary; and
- the RC workflow performed no GA mutation.

## GA validation and authorization

Select exactly one final successful protected RC run and immutable attempt. Expired or unavailable
artifacts are a stop condition; do not rebuild them.

First run the existing `stable-ga` engine in `prepare-authorization` mode with the exact RC inputs,
post-freeze production validation, public targets, and no authorization or publication receipt.
This produces the final-record and authorization identity without authorizing publication. An
authorized reviewer issues the existing GA authorization format, binding the exact RC digests,
validation identity, target digest, and validity interval.

Rerun `stable-ga` in `validate-only` mode with that authorization. Then dispatch
`.github/workflows/stable-1.0-ga-promotion.yml` with `publish=false`, the exact selected RC
run/attempt/artifact/digest, candidate commit/ref/build, post-freeze validation, authorization,
public targets, and current PR-288/PR-290 coordinates. Validation performs no product build and no
publication. The separate `stable-1-0-ga-evidence` job attests and approves the supplied validated
bytes; it does not manufacture an authorization.

Retain that `publish=false` workflow run ID, immutable attempt, canonical validated-artifact name,
and Actions artifact digest. A later `publish=true` dispatch requires all four coordinates,
authenticates the exact successful evidence job, downloads that exact artifact, and compares the
three attested validation/authorization/target-identity subjects byte for byte before mutation.
Supply them in the closed `ga_evidence_coordinates` JSON input with keys `runId`, `runAttempt`,
`artifactName`, and `artifactDigest`; the artifact name must be the canonical
`stable-1-0-ga-validated-<release>-<build>-<run>-<attempt>` value.

## GA publication

Before `publish=true`, the public artifact objects and catalog primary/mirror/rollback objects must
already exist at the exact reviewed targets under their separately authorized staging authority.
This workflow verifies those objects; it does not grant an operator permission to stage or rewrite
them. If no canonical staging operator, credentials, and authentic staging receipt are available,
publication is blocked.

Dispatch the exact same GA package with `publish=true` only after a fresh preflight and fresh
authorization. The validation and evidence jobs run again without mutation. The publication job
then waits for manual `stable-1-0-ga` approval, reauthenticates current vulnerability and
dependency-vulnerability state, verifies catalog primary/mirror/rollback identity, and uses the
`leumor` mutation token. The job may create or reuse only exact matching tag, draft Release, and
asset state. It may never rebuild or substitute the RC payload.

## Conflict and retry handling

| Observed state | Operator action |
| --- | --- |
| No mutation occurred | Preserve the failed receipt; correct the non-payload blocker; obtain fresh current evidence and authorization; rerun the same exact RC and targets. |
| Exact authenticated prefix exists | Verify every existing tag/Release/asset byte and target; preserve the prior partial receipt; retry only the missing suffix with the same RC and targets plus fresh evidence and authorization. |
| Payload, source, or destination changed | Stop, refreeze if frozen content changed, then revalidate and reauthorize. |
| Existing state conflicts or cannot be authenticated | Stop. Do not delete, overwrite, retag, or rerun blindly. Obtain separately authorized recovery. |
| Retained artifact expired or exact attempt is unavailable | Stop. A rebuild is forbidden; create a new protected refreeze. |
| Authorization or vulnerability evidence is stale | Stop before mutation and obtain fresh authenticated evidence/authorization. |

The publication logic is idempotent only for an exact authenticated prefix. It is deliberately
fail-closed for conflicting or unknown state.

## Public observation and closeout

Publication and public observation are different states. After a successful publication receipt,
dispatch `.github/workflows/stable-1.0-public-observation.yml` with the exact release/build/commit
and the GA publication run, immutable attempt, canonical receipt-artifact name, and Actions
artifact digest, selecting `release/<build>` as the workflow dispatch ref. The observer rejects an
unprotected ref or workflow SHA that differs from the candidate. The protected
`stable-1-0-public-observation` job has read-only repository
permissions. It authenticates the selected GA run and artifact, then independently fetches the
annotated tag, public GitHub Release, all seven GitHub Release assets, the matching artifact-base
objects, catalog primary, every mirror, the rollback object, and each catalog object's canonical
detached-signature sibling. It requires the fetched signature bytes to match the publication
receipt's primary or rollback signature digest. It emits
`stable-1.0-protected-release-public-observation-v1.schema.json` bytes containing the publication
receipt digest, candidate commit, exact product digest, every observed URI/digest/size/status,
observation time, and a passing redaction result. The receipt deliberately omits its own Actions
artifact digest to avoid a circular value. Download the observation artifact through the Actions
artifact API without extracting it, retain the exact ZIP bytes at a repository-relative evidence
path, and bind that file as `operationEvidence.publicObservationArtifact`. Record the workflow
summary's normalized `sha256:<artifact-digest>` value in both that file binding and
`workflowCoordinates.publicObservation.artifactDigest`; do not copy the raw 64-character action
output without the `sha256:` prefix. Closeout hashes the ZIP, checks it against the workflow
coordinate, applies the archive-safety rules, and requires its sole
`stable-1.0-public-observation.json` member to be byte-identical to
`operationEvidence.publicObservation`. Upload success alone is not public observation.

Update the execution contract only with authentic repository-relative receipt paths and exact
workflow coordinates. `operationEvidence.rcFreeze` must bind the authenticated
`stable-1.0-rc-lineage.json`, while `operationEvidence.rcFreezeRecord` binds the exact
`stable-1.0-rc-freeze.json` whose file digest is carried by that lineage. This anchors the selected
catalog revision and digest to the frozen candidate rather than to mutually agreeing GA files.
Retain the RC artifact ZIP downloaded through the Actions artifact API without extracting or
repacking it and bind it as `operationEvidence.rcFreezeArtifact`, with `schema: null`. Its digest
must equal `workflowCoordinates.rc.artifactDigest`, and closeout requires the extracted freeze
record to be byte-identical to the ZIP member
`artifacts/legacy/stable-1.0-rc-freeze.json`. The RC workflow also retains the exact preflight
receipt consumed by `rc-dispatch` as
`artifacts/protected-execution/stable-1.0-protected-release-preflight-summary.json`; bind the
downloaded copy separately as `operationEvidence.rcPreflight`. Closeout requires exact member
bytes, the canonical summary schema, a passing/redaction-safe preflight decision, and the same RC
source, release, evidence, supplemental inputs, targets, and public signing/review identities.
Re-serializing or regenerating an equivalent local receipt is not accepted. The RC ZIP is rooted
at the Stable RC component contents; it has no `build/`, release-ID, or `stable-rc/` wrapper
directory. The lineage file is not an RC ZIP member. The GA validation artifact retains it as
`publication-inputs/stable-1.0-rc-lineage.json` and retains the same freeze as
`publication-inputs/stable-1.0-rc-freeze.json`; closeout authenticates both members there.
Publication closeout also requires that lineage, freeze, exact passing preflight receipt, and the
canonical GA validation receipt to complete first. Bind
`operationEvidence.gaValidationIdentity` to the exact retained
`stable-1.0-ga-validation-authorization-identity.json` member and
`operationEvidence.gaPromotionPlan` to the exact retained
`stable-1.0-ga-publication-plan.json` member from that same protected GA validation artifact.
Retain the Actions API download ZIP without extraction as
`operationEvidence.gaValidationArtifact`; its digest must equal the attested
`workflowCoordinates.gaEvidenceApproval.artifactDigest`. Closeout verifies that the validation,
authorization, authorization-identity, and publication-plan bindings are byte-identical to their
canonical paths inside that exact retained artifact, preventing correlated local substitutions.
Closeout validates the authorization identity against the selected RC, authorization, targets,
catalog, and exact-byte payload, reconstructs the canonical promotion identity independently, and
then requires both the plan and publication receipt to bind that derived digest and every planned
asset. Retain the GA publication Actions ZIP without extraction or repacking and bind it as
`operationEvidence.gaPublicationArtifact`, with `schema: null`. Its digest must equal
`workflowCoordinates.gaPublication.artifactDigest`, and its root
`stable-1.0-ga-publication-receipt.json` member must be byte-identical to
`operationEvidence.gaPublication`; a locally reconstructed receipt is not protected-operation
evidence. The authorization's validation-identity digest and the derived promotion-identity digest
remain different authorities. A publication receipt alone cannot advance the lifecycle. Then run:

```bash
python3 tools/release-certification/certify.py stable-protected-release \
  --mode closeout \
  --execution-contract build/protected-release/stable-1.0-protected-release.json
```

Without `--out-dir`, closeout writes its JSON, Markdown, and redaction report beneath
`build/release-certification/<execution-id>/stable-protected-release/closeout/`. It does not modify
the exact preflight summary bound by `operationEvidence.preflight`; subsequent closeout runs must
be able to authenticate those same retained preflight bytes.

Closeout is side-effect-free but intentionally online. Set `GH_TOKEN` to a read-only credential
for the `leumor` GitHub identity. For every claimed RC, GA evidence, GA publication, and public
observation artifact it queries GitHub and requires the exact repository, manual workflow path,
candidate commit, run, immutable attempt, successful conclusion, unexpired canonical artifact
name, and Actions artifact digest. Both the original dispatch actor and any rerun-triggering actor
must be `leumor`; the GA validation coordinate must identify the same retained artifact approved
by the protected GA evidence environment. Closeout also queries the immutable evidence run
attempt's jobs and requires exactly one successful `Attest protected Stable GA evidence bytes`
job, including its exact verification and attestation steps. The candidate workflow binds that
job to `publish == false` and `stable-1-0-ga-evidence`; run-level success and a retained validation
artifact do not constitute evidence approval. An absent token, unavailable API response, expired
artifact, incomplete job result, or locally coordinated ZIP/digest substitution remains partial
or not performed; local agreement between a contract and downloaded files is never sufficient
protected-operation evidence.

To close independent reproducibility, retain the exact ZIP downloaded through the Actions
artifact API for the canonical `stable-1.0-supply-chain-<release-id>-comparison` artifact. Bind
that ZIP as `operationEvidence.independentReproducibilityArtifact`, with `schema: null`, and bind
its extracted `stable-1.0-reproducibility-report.json` as
`operationEvidence.independentReproducibility`. Keep the Stable supply-chain upstream-evidence row
bound to `.github/workflows/stable-1.0-supply-chain.yml`, the
`stable-1.0-supply-chain-evidence` environment, and the same run, immutable attempt, artifact name,
and digest. Closeout authenticates those coordinates through GitHub, requires the extracted result
and supply-chain summary to be byte-identical to their ZIP members, reads the comparison plan
directly from that ZIP, and validates the plan/result/builder-receipt digests through the canonical
Stable supply-chain engine. A local self-digested result or an upload claim without that retained
artifact remains `pending`.

Closeout emits `stable-1.0-protected-release-execution-summary.json`,
`stable-1.0-protected-release-execution-report.md`, and `redaction-report.json`. It reports
repository implementation, offline verification, protected RC completion, GA validation, GA
publication, public observation, and independent reproducibility separately. Fixture, simulated,
stale, wrong-repository, wrong-commit, wrong-run, wrong-attempt, or wrong-digest evidence is
rejected. Independent reproducibility remains `pending` until a separate authentic production
receipt exists.

## Stop conditions and non-goals

Stop on any missing or ambiguous input, failed gate, stale authority, changed source ref, expired
artifact, unexpected workflow/environment, invalid signature, digest disagreement, redaction
finding, partial unknown state, reviewer-policy mismatch, or unavailable staging/public target.

This procedure does not authorize key rotation, deletion or replacement of conflicting public
state, catalog rollback, tag removal, GitHub Release removal, or generic updater publication. Those
actions require their own protected recovery authority. The generic release runbook is supporting
context only; it does not supersede this Stable procedure.
