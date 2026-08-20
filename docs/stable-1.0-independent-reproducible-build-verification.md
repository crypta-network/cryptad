# Stable 1.0 independent reproducible-build verification

This runbook defines how Cryptad proves that a Stable 1.0 release candidate was rebuilt by an
authenticated authority outside the producer's provider and control plane. It adds a narrow
authority and transport layer around the existing Stable supply-chain comparison engine. It does
not define another product inventory, SBOM, normalization implementation, release format, or
publication authority.

Repository implementation and passing self-tests do not mean an external build occurred. At merge
time, independent reproducibility remains `pending` unless a protected coordinator authenticates a
real external workload attestation, imports the already sealed output bundle, compares every
required subject with the exact selected RC, and emits an authenticated closeout. Public
verification is a further, separate fact.

## Threat model and security claim

The producer's GitHub Actions account, workflows, environments, runners, artifacts, and
attestations belong to one control plane. Separate jobs or runs within that control plane are useful
reproducibility evidence, but compromise or coercion of that provider could influence both builds.
The independent protocol therefore requires a verifier with a different provider ID, control-plane
ID, trust domain, and, when selected by policy, organization/account. It also requires an immutable
pipeline revision, a reviewed workload identity, an authenticated output seal, and an attestation
verified against a policy-pinned trust root.

The protocol addresses receipt substitution, provider relabeling, source or material drift,
candidate-oracle access before sealing, subject omission, and unexplained product differences. It
does not prove that either provider is free from compromise, that public mirrors served the same
bytes, or that signing/notarization authorities are reproducible.

## Evidence classifications

Treat these classifications as distinct and monotonic. None may be inferred from the existence of
a later workflow file or a local JSON document.

| Classification | What it proves | What it does not prove |
| --- | --- | --- |
| Repository implementation | Contracts, policy, coordinator, and validation code exist in the repository. | Any build or protected operation ran. |
| Fixture or self-test | Deterministic negative and positive test vectors passed locally or in CI. | An operational provider, identity, runner, or release candidate was used. |
| Same-provider reproducibility | The existing Stable supply-chain producer and verifier completed separate builds and comparison under GitHub Actions. | Provider- or control-plane-distinct independence. |
| Protected coordinator | The protected acceptance environment ran this repository's import and comparison protocol. | The imported receipt was authentic or the comparison passed unless the closeout says so. |
| Authenticated external build | A policy-supported external authority sealed its outputs and its workload attestation and receipt were authenticated. | That its product bytes match the selected RC. |
| Independently reproduced | The authenticated external build and selected RC passed the complete existing comparison policy. | Public availability or third-party public observation. |
| Public verification | A separately authenticated public observer verified published evidence and subjects. | Publication merely because a local or Actions artifact exists. |

The machine-readable execution contract carries these facts separately in
`evidenceClassification`. Operational closeout uses only `pending`,
`authenticated-external-build`, `comparison-failed`, `independently-reproduced`, `blocked`, or
`partial`. A fixture profile is never eligible for operational success.

## Authorities and trust boundaries

The existing `.github/workflows/stable-1.0-supply-chain.yml` workflow remains the producer and
same-provider verifier authority. Its candidate freeze, release-subject inventory, component
inventory, build materials, dependency-resolution snapshot, SBOM, builder receipts, normalization
views, comparison plan, and reproducibility result remain canonical.

The external verifier receives a product-byte-free kit, reconstructs the source with its own
provider, and seals its builder receipt, subject manifest, subject bundle, and authority
attestation. It has no access to the selected RC bundle while building. A repository-approved
transport can then carry those sealed files into GitHub Actions. That transport is not the external
authority: the external workload attestation is.

The dedicated
`.github/workflows/stable-1.0-independent-reproducibility.yml` workflow is the protected
coordinator. Its `stable-1.0-independent-reproducibility-external-receipt` environment is the human
approval boundary for accepting an external receipt. The workflow has no publication permission,
tag or Release operation, catalog credential, or external-provider credential.

## Closed execution contract

Use `tools/release-certification/schemas/stable-1.0-independent-reproducibility-execution-v1.schema.json`
and the canonical `tools/release-certification/stable-1.0-independent-reproducibility-policy.json`.
The execution schema is closed: unknown fields, malformed paths, duplicate JSON keys, non-finite
numbers, and mutable or incomplete identities fail before digest binding.

The contract binds all of the following:

- repository identity, exact 40-character source commit and authenticated source ref, source-tree
  digest, authenticated source-archive digest, and canonical commit epoch;
- release ID, integer build, Stable tag, milestone, and selected RC class;
- the selected RC workflow revision, run, attempt, artifact name and digest, freeze and product
  digests, release-subject inventory digest, and the exact Stable supply-chain workflow/run/attempt
  and artifact coordinates retained by that RC;
- Stable supply-chain and independent-policy digests, comparison-plan and result schema digests;
- component inventory, subject inventory, build materials, dependency-resolution snapshot, direct
  immutable inputs, and SBOM digests;
- exact build tasks, four execution partitions, JDK and Gradle identities, canonical environment,
  normalization authority, subject keys, expected filenames, and reproducibility classes;
- producer authority and expected verifier provider profile, including the required independence
  dimensions;
- verifier-kit expiry, external receipt/attestation/output bindings, comparison inputs, closeout
  outputs, lifecycle state, and evidence classification.

`operationMode` and `lifecycleState` must describe the operation that has actually occurred. A
planned contract cannot assert an external build, and a locally generated file cannot advance
`externalProviderExecution` or `publicVerification`.

Keep the contract non-secret. Do not include tokens, private keys, private insert URIs, unpublished
vulnerability details, fetched bodies, raw app data, absolute local paths, or credentials.

## Verifier kit contents and exclusions

Generate the kit with:

```bash
python3 tools/release-certification/certify.py stable-independent-reproducibility \
  --mode prepare-verifier-kit \
  --execution-contract build/stable-independent/execution.json \
  --out-dir build/stable-independent/kit
```

The deterministic output is:

```text
stable-1.0-independent-verifier-kit.json
stable-1.0-independent-verifier-kit.sha256
```

The kit contains the authenticated source identity and epoch, JDK and Gradle identities, wrapper
and verification-metadata identities, dependency and repository constraints, direct immutable
input digests, closed environment, exact tasks and execution routing, required subject keys and
classes, normalization rule identities, policy/schema identities, receipt schemas, packaging
instructions, the immutable `executionContractDigest`, kit digest, and expiration. The execution
digest is an opaque commitment to the coordinator's immutable release plan; it is not a selected-RC
product digest or a candidate-byte oracle. Copy that exact kit value into the v2 builder receipt.

The kit excludes selected-RC product bytes, candidate subject digests, the primary builder receipt,
signing keys, notarization credentials, catalog insert material, tokens, private URLs,
vulnerability details, raw app data, and local paths. The digest file authenticates the kit; it is
not a digest oracle for candidate product bytes.

## Candidate-byte withholding

The verifier must finish its build and seal all outputs before any candidate product is available
to its authority or build job. Its attestation must state
`candidateProductAvailableBeforeBuild: false`, and `outputsSealedAt` must follow the authenticated
build interval. A retry that has seen candidate bytes requires a fresh isolated verifier execution;
it cannot reuse the earlier provider run, workspace, cache namespace, receipt, or output seal.

The coordinator enforces the ordering twice. `prepare-verifier-kit` has no selected-RC coordinates
or download step. For receipt acceptance, it downloads only the sealed external bundle, runs
`verify-external-receipt`, and requires the authenticated builder-attestation output. Only after
that command succeeds does it query and download the canonical primary supply-chain comparison
handoff and selected RC artifact for `compare` or `closeout`. Failure artifacts contain only
bounded status fields and never copy an input bundle.

## External authority identity and attestation

The closed authority model authenticates:

- provider type and ID, control plane, trust domain, organization, account, and project;
- pipeline definition, immutable pipeline revision, run/build, attempt, and job/stage;
- runner OS and architecture, executor identity, and immutable image identity when required;
- OIDC issuer, subject, audience, and the provider-profile claim constraints;
- artifact attestation format, predicate, subject/output digest, verification mechanism, and
  verification status, including the exact raw DSSE/Sigstore bundle and bounded verification
  transcript;
- receipt producer, exact source, materials, dependency resolution, toolchain, tasks, environment,
  subjects, output manifest, output bundle, and seal time.

The policy defines adapter contracts for GitHub artifact attestations and external OIDC-backed
DSSE/in-toto provenance. Operational success requires both a concrete reviewed provider profile and
real adapter verification of the raw attestation bundle against its pinned trust root and workload
claims. A schema-valid assertion or verification-status boolean is insufficient. The checked-in
generic external OIDC entry is a non-operational template, not an approved provider. The fixture
profile is also non-operational. The engine's operational external-adapter allowlist is empty in
this repository revision: policy activation alone cannot bypass the missing cryptographic verifier.
Until a real provider profile and its offline cryptographic adapter implementation—with pinned
issuer, audience, subject, organization, pipeline, trust root, executor policy, and immutable
revision—are reviewed, tested, and digest-bound, real external completion remains `pending`.

The verifier is rejected if it shares the producer's provider, control plane, trust domain, or a
policy-required organization; reuses a workflow/run/job or attestation; was produced by the
candidate workflow; relies on a producer-controlled self-hosted runner; uses a mutable workflow or
uncontrolled runner image; presents unauthenticated JSON; or relabels a GitHub Actions job,
environment, or worktree as external.

## External verifier procedure

The independent authority performs these steps outside GitHub's Cryptad producer control plane:

1. Verify the kit digest, schema and policy digests, freshness, repository identity, source archive,
   commit/ref, source-tree identity, and canonical epoch.
2. Create an isolated workspace and cache namespace. Do not import producer outputs or selected-RC
   product digests.
3. Resolve only the policy-authorized repositories and immutable direct inputs. Verify the Gradle
   wrapper, dependency verification metadata, build materials, and dependency-resolution snapshot.
4. Set the closed locale, timezone, encoding, `SOURCE_DATE_EPOCH`, and other kit environment
   values. Use the exact JDK, Gradle, task set, and execution partition routing.
5. Build portable archives, runtime images, first-party apps, and each platform installer. For the
   app partition, run the kit-selected
   `:packageUnsignedFirstPartyAppsForIndependentReproducibility` task. It packages the seven
   staged app payloads deterministically in an isolated output directory without reading a signing
   key and fails if signing or catalog sidecars are present. Stage each resulting ZIP unchanged at
   its kit `expectedOutputs[].fileName` before sealing the receipt. Do not substitute
   `packageFirstPartyApps`,
   `signFirstPartyApps`, or `verifyFirstPartyApps`. Record every required subject, payload
   manifest, normalized view, and package extraction identity.
6. Reject missing or extra subjects, unsafe paths, symlinks or hard links with ambiguous targets,
   unsafe nested archives, AppleDouble, `__MACOSX`, `.DS_Store`, and expansion beyond policy bounds.
7. Create the closed v2 builder receipt and subject/output manifest. Each normalized subject that
   uses a payload view has one `payloadManifests` row binding its canonical
   `payload-manifests/<subject-key>.json` bundle path, exact file SHA-256 and size, payload-manifest
   schema, and semantic manifest digest. Package exactly those manifest bytes and the allowlisted
   output subjects into the external output bundle.
   For each `builderExecutions` row, compute `subjectSetDigest` only from the matching
   `expectedOutputs` rows in the kit, ordered by `subjectKey` and projected to exactly
   `subjectKey`, `fileName`, `reproducibilityClass`, and `normalizationRuleId`. Do not copy or derive
   this execution digest from the producer subject inventory. The output manifest's separate
   `subjectSetDigest` binds the verifier's actual sealed output rows, including their digests and
   sizes; the artifact attestation and verification transcript bind that actual-output digest.
8. Seal the receipt, output manifest and output bundle, then generate the provider-native raw
   DSSE/Sigstore workload-attestation bundle over their exact digests. Record the build interval and
   `outputsSealedAt`.
9. Run the policy-selected real attestation adapter and retain its bounded verification transcript,
   including the verified trust root, workload claims, attested subjects and result. A producer
   assertion that verification passed is not a transcript.
10. Transfer all six exact core files—the builder receipt, authority attestation, raw artifact-
    attestation bundle, verification transcript, output manifest and output bundle—to the protected
    coordinator without modifying or reserializing them. Keep the original provider receipt and
    public verification material.

The provider must not receive a signing private key or notarization credential. Signed or
notarized outer envelopes are compared only through the normalization rule assigned by the Stable
supply-chain policy; the external verifier does not reproduce production signatures. For a
first-party app, `crypta-app-signature-envelope-v1` removes exactly
`cryptad-app.digests` and `cryptad-app.signature` from the provider-distinct payload view. It
   rejects a partial pair and does not exclude any catalog sidecar, app payload, path, permission,
or metadata for the remaining archive members. The selected RC's complete signed ZIP, signature receipt, signer identity, and
catalog binding remain authenticated release evidence; the external authority proves the app
payload, not possession of the producer's signing authority.

## Protected coordinator procedure

Run the side-effect-free CLI locally first:

```bash
python3 tools/release-certification/certify.py stable-independent-reproducibility --self-test
```

Then dispatch the dedicated workflow at the exact protected `release/<build>` ref and source SHA.
Supply the complete reviewed execution contract as non-secret JSON. For external operations,
supply the exact run, attempt, workflow path, artifact name, and `sha256:` digest of the Actions
artifact used to transport the already sealed external bundle. For comparison and closeout, also
supply the exact selected RC run, attempt, canonical artifact name, and Actions digest, plus the
exact existing Stable supply-chain comparison run, attempt, canonical artifact name, and Actions
digest that carry the primary receipt and authority attestation. Also supply the closed JSON
coordinates of the attempt-scoped primary subject-bundle artifact from that same run and attempt.
The transport artifact name is closed to
`stable-1-0-independent-external-bundle-<release>-<build>-<run>-<attempt>` so a rerun cannot
silently select an earlier attempt's artifact.
The primary handoff name is closed to
`stable-1.0-supply-chain-<release>-comparison`; its authenticated Actions digest and contract file
bindings select the exact primary receipt and authority attestation.
Primary product bytes are deliberately not stored in that bounded legacy handoff. They are in the
separately attested
`stable-1.0-supply-chain-<release>-independent-primary-subjects-attempt-<attempt>` artifact; its
run and attempt must equal the canonical comparison handoff's coordinates, and its Actions digest
and the contract's exact file binding must both pass before comparison. This preserves the 256 MiB
limit enforced by existing Stable RC and post-publication certification consumers.
The Stable RC workflow retains the closed, non-secret supply-chain coordinate that it consumed.
The coordinator requires that retained coordinate, the execution contract, the authenticated
primary artifact, and the primary receipt/authority run identity to agree exactly.

The coordinator authenticates transport coordinates through the GitHub API before downloading.
The external bundle's GitHub uploader is not treated as the verifier. Before any primary or
selected-RC download, the coordinator requires an exact six-file transport allowlist containing the
receipt, authority attestation, raw DSSE/Sigstore bundle, adapter verification transcript, output
manifest and sealed output bundle. The command authenticates these inputs only when a separately
reviewed policy-pinned adapter with an implemented cryptographic verifier is installed. This PR
ships no approved external provider or verifier implementation, so its checked-in template and
fixture profiles remain non-operational and fail closed:

```bash
python3 tools/release-certification/certify.py stable-independent-reproducibility \
  --mode verify-external-receipt \
  --execution-contract build/stable-independent/execution.json \
  --out-dir build/stable-independent/result
```

An authentic result produces
`stable-1.0-independent-builder-attestation.json`. Only then materialize the exact selected RC
bundle and primary Stable supply-chain comparison handoff and run:

```bash
python3 tools/release-certification/certify.py stable-independent-reproducibility \
  --mode compare \
  --execution-contract build/stable-independent/execution.json \
  --out-dir build/stable-independent/result

python3 tools/release-certification/certify.py stable-independent-reproducibility \
  --mode closeout \
  --execution-contract build/stable-independent/execution.json \
  --out-dir build/stable-independent/result
```

The command performs no network retrieval, Git mutation, release creation, publication, or catalog
operation. The workflow's API calls authenticate exact same-repository transport and selected-RC
artifacts; they do not validate an external provider by themselves.

## Comparison authority and coverage

`stable_1_0_supply_chain_reproducibility.py` remains the product-comparison authority. The
independent adapter validates and projects the external receipt into its existing builder receipt,
comparison-plan, and result contracts. It does not reinterpret a mismatch or downgrade a subject.

The comparison binds the source tree, build materials, immutable direct inputs, dependency
snapshot, JDK/Gradle toolchain, exact task-set digest, canonical environment, payload and extraction
manifests, component inventory, SBOM subject, and complete release-subject inventory. Coverage
includes the core JAR; portable TAR and ZIP; runtime-image TAR and ZIP; every first-party app
bundle; DEB and RPM payloads; Windows installer payload; and macOS installer payload.
For every normalized subject, the output-manifest row and sealed bundle must agree on the canonical
payload-manifest path, exact bytes, file digest and size, schema identity and semantic manifest
digest. Each payload manifest's `publishedSubjectDigest` must also equal the digest of the packaged
DEB, RPM, DMG, or EXE in the same builder receipt. A stale manifest paired with different package
bytes therefore fails before normalized comparison. A subject-row digest without those manifest
bytes cannot authorize normalized equality.

The existing classes retain their meaning:

- `byte-identical` requires exact outer bytes;
- `normalized-payload-identical` permits only the envelope variation already accounted for by its
  policy-selected normalization rule;
- `not-a-product-subject` is bound governance or inventory evidence and is never silently promoted
  to a product comparison.

The canonical output names remain `stable-1.0-rebuild-comparison-plan.json` and
`stable-1.0-reproducibility-report.json`. Their self-digests, producer and verifier receipt digests,
plan/result binding, complete row set, and row seals prevent a reserialized, omitted, substituted,
or resealed result from passing.

The seven first-party app ZIPs use `normalized-payload-identical` for provider-distinct comparison
because the external authority is intentionally denied the producer's private app key. Their
closed `crypta-app-signature-envelope-v1` view excludes only the required signature pair. Any app
payload, mode, ordering, timestamp, compression, encoding, unexpected sidecar, or other ZIP
difference remains a failure. This does not make the external builder an app signer and does not
weaken authentication of the signed selected-RC subjects.
The established same-provider producer/verifier gate additionally requires each signed app ZIP's
outer digest and size to match exactly, preserving its pre-PR-292 exact-byte behavior.

## Difference attribution

Failure output is deterministic, bounded, and redacted. It can classify source-tree,
build-material, dependency-resolution, toolchain, task-set, environment, missing/extra subject,
file-content, archive ordering, archive timestamp, owner/group/mode, compression parameter,
embedded timestamp, manifest/property ordering, line-ending/encoding, signing/notarization
envelope-only, normalized payload, and payload-permission drift.

`unknown-or-unexplained-difference` always blocks independent reproduction. Reports contain stable
field names, bounded counts and digests, never arbitrary binary excerpts, raw application data,
private URIs, secrets, or absolute paths. An envelope-only classification passes only where the
existing subject class and normalization rule explicitly authorize it; it cannot excuse normalized
payload drift.

## Failure and retry

Preserve the failed coordinator artifact and external provider's original receipt/attestation. Do
not edit or reseal evidence to make it pass. Classify the failure before retrying:

- identity, policy, expiry, source, material, task, toolchain, or environment drift requires a new
  contract or a fresh compliant external run;
- missing/extra subjects or product drift requires a fresh isolated rebuild and seal;
- a transport-coordinate failure can retry import of the same sealed bytes only when the original
  external attestation and seal remain fresh and unchanged;
- any run or workspace that received candidate bytes cannot return to the pre-candidate verifier
  state;
- a partial platform rebuild remains `partial`; it cannot be combined with unauthenticated rows
  from another build.

The coordinator retains a bounded `blocked` failure summary even when validation, kit preparation,
receipt acceptance, comparison, or closeout fails. That summary explicitly reports that no
publication or public verification occurred.

## PR-291 protected closeout integration

Protected release closeout consumes the authenticated independent summary; it does not trust a
contract assertion. The summary is bound to the selected RC workflow/run/attempt/artifact/digest,
source commit and integer build, release-subject inventory, primary receipt and authority
attestation, external receipt and authority attestation, comparison plan and result digests,
provider-independence decision, and evidence classification.
The local PR-292 command can report `authenticated-external-build` and a completed comparison, but
it never self-asserts protected operational success from a coordinator object in local JSON.
PR-291 derives `independently-reproduced` only after authenticating the exact retained coordinator
artifact and revalidating its members.

Closeout rejects self-asserted or fixture evidence, same-provider receipts, wrong RC or producer
coordinates, missing external attestation, result/member substitution, evidence generated before
the external seal, partial coverage, and tampered/resealed comparison rows. Missing evidence stays
`pending`; an authenticated receipt without a passing comparison is
`authenticated-external-build`; a failed comparison is `comparison-failed`. Local files never
imply remote or public completion.

The independent closeout emits:

```text
stable-1.0-independent-reproducibility-summary.json
stable-1.0-independent-reproducibility-report.md
stable-1.0-independent-reproducibility-redaction-report.json
```

Retain the exact protected coordinator artifact and its Actions digest for the PR-291 execution
contract. Do not copy just the summary out of its authenticated container and treat it as closeout
evidence.

## Redaction and archive safety

All inputs and outputs use closed schemas and bounded sizes. Reject duplicate keys before digest
binding; absolute, traversal, Windows drive, UNC, and ambiguous case-colliding paths; unsafe
symlinks, hard links, and special files; nested archives beyond member or expansion limits; and
AppleDouble, `__MACOSX`, or `.DS_Store` members.

Never put a token, cookie, authorization header, private key, private insert URI, unreleased
vulnerability finding, raw fetched content, raw app data, arbitrary binary content, or runner path
in the contract, transport bundle, logs, report, or documentation. Generated errors identify only
the stable field/classification and a bounded digest when needed.

## Adding an external provider profile

Do not change the generic template in place or mark it operational. Add a new closed profile with a
new profile ID and digest, then obtain supply-chain and release-authority review. The review must:

1. Pin the provider ID, control plane, trust domain, organization/account/project, issuer, audience,
   subject pattern, pipeline definition, and immutable revision format.
2. Pin the attestation adapter, format, predicate, verification roots, revocation behavior, and
   freshness rules.
3. Define provider-hosted or independently controlled executor requirements and immutable runner
   image identity.
4. Demonstrate that the producer cannot control the verifier executor, identity, attestation key,
   or pipeline revision.
5. Add accepting fixtures and negative tests for relabeling, mutable revisions, wrong claims,
   same-provider/control-plane/trust-domain/organization reuse, stale attestations, output
   substitution, and producer-controlled self-hosting.
6. Implement the adapter's offline cryptographic verification in the certification engine, add its
   adapter ID to the code-level operational allowlist, and test signature, certificate/key,
   statement, subject-set, transparency/timestamp, and workload-claim failures.
7. Recompute and review the profile and policy digests. Set `operationalAllowed: true` only after
   all trust roots and validation behavior are closed.

Supporting a commercial provider is a policy decision, not a string alias. A second GitHub
organization or self-hosted runner does not become independent if it shares GitHub Actions as its
control plane or remains controlled by the producer.

## Non-goals and remaining protected operations

This implementation does not rebuild or republish Stable GA, create a tag or GitHub Release,
upload an SBOM publicly, mutate a catalog, install external credentials, approve a provider, run a
protected workflow, or claim a public verification. It does not alter product formats or relax
JDK, Gradle, dependency verification, signing, archive, or release-subject policy.

After merge, release authorities still must approve a real external provider profile; generate and
transfer a fresh verifier kit; execute the isolated cross-provider builds on every platform;
verify the provider-native workload attestation; accept the sealed receipt in the protected
environment; authenticate the exact selected RC; run comparison and closeout; bind the resulting
Actions artifact into PR-291; and, if desired, perform a separately authenticated public
verification. Until those operations occur, the repository correctly reports independent
reproducibility as `pending`.
