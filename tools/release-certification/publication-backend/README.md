# Stable maintenance and lifecycle publication backends

This directory contains the dependency-free provider used by the protected Stable 1.0
maintenance workflow. It is the concrete implementation behind
`cryptad_stable_maintenance_backend:factory`; it is not loaded from the candidate checkout.

The canonical producer is
`.github/workflows/stable-1.0-maintenance-publication-backend-producer.yml`. Dispatch it for the
current reviewed `main` commit. The workflow builds the wheel twice, requires byte-identical
results, checks the closed wheel layout and provider protocol, attests the one wheel, and uploads
the fixed `stable-1.0-maintenance-publication-backend` artifact. Release environments then pin the
source commit, wheel SHA-256, canonical signer workflow, and canonical entrypoint. A release
dispatch additionally supplies the exact producer run id and Actions artifact digest. The setup
action verifies all six bindings and the GitHub attestation before installing the wheel without
dependency resolution.

The same deterministic wheel also carries the separate lifecycle-only factory
`cryptad_stable_maintenance_backend:lifecycle_factory`. It returns an object whose only operations
are `observe_lifecycle`, `observe_latest_maintenance_tip`, `publish_lifecycle`, and
`verify_lifecycle`; it cannot create a tag or
release, publish catalog/CoreUpdater state, activate a maintenance pointer, or revoke an update
key. The canonical lifecycle producer is
`.github/workflows/stable-1.0-support-lifecycle-publication-backend-producer.yml`. The protected
lifecycle workflow independently pins that producer, source commit, artifact digest, wheel digest,
fixed artifact name, and fixed lifecycle factory before loading it outside the repository checkout.
The lifecycle insert capability is supplied only to the publication call and is never available
during provider import or read-only verification.

Configure these immutable public-safe identity pins where the evidence verifier and both
publication environments can read the same values:

- `CRYPTAD_STABLE_MAINTENANCE_PUBLICATION_BACKEND_SOURCE_COMMIT`;
- `CRYPTAD_STABLE_MAINTENANCE_PUBLICATION_BACKEND_WHEEL_SHA256`;
- `CRYPTAD_STABLE_MAINTENANCE_PUBLICATION_BACKEND_SIGNER_WORKFLOW`;
- `CRYPTAD_STABLE_MAINTENANCE_PUBLICATION_BACKEND`, fixed to
  `cryptad_stable_maintenance_backend:factory`.

Each `publish` dispatch separately supplies the producer run id, fixed artifact name, and Actions
artifact digest. Keep the catalog, CoreUpdater, and latest-pointer capability values in their
purpose-specific protected environments; they are not provider identity configuration and must not
be visible while the wheel is imported or while an unrelated target is observed or mutated.

The lifecycle evidence and publication environments use corresponding immutable pins:

- `CRYPTAD_STABLE_LIFECYCLE_PUBLICATION_BACKEND_RUN_ID`, set to the successful canonical producer
  run that owns the pinned artifact;
- `CRYPTAD_STABLE_LIFECYCLE_PUBLICATION_BACKEND_ARTIFACT_NAME`, fixed to
  `stable-1.0-support-lifecycle-publication-backend`;
- `CRYPTAD_STABLE_LIFECYCLE_PUBLICATION_BACKEND_ARTIFACT_DIGEST`, set to that run's exact Actions
  artifact digest;
- `CRYPTAD_STABLE_LIFECYCLE_PUBLICATION_BACKEND_SOURCE_COMMIT`;
- `CRYPTAD_STABLE_LIFECYCLE_PUBLICATION_BACKEND_WHEEL_SHA256`;
- `CRYPTAD_STABLE_LIFECYCLE_PUBLICATION_BACKEND_SIGNER_WORKFLOW`, fixed to the canonical lifecycle
  producer above;
- `CRYPTAD_STABLE_LIFECYCLE_PUBLICATION_BACKEND`, fixed to
  `cryptad_stable_maintenance_backend:lifecycle_factory`.

The protected maintenance workflow reads the run id, artifact name, and artifact digest from these
repository variables instead of adding them to its already full manual-dispatch contract. Every
authorization or publication run reauthenticates the run, artifact, attestation, source, wheel,
signer, and entrypoint. The dedicated lifecycle publication workflow continues to accept explicit
backend coordinates for its own protected publication and verification operations.

The distinct `CRYPTAD_STABLE_LIFECYCLE_PUBLICATION_INPUT` protected secret is required only in the
publication environment. It identifies the narrowly scoped compare-and-swap deployment capability;
the read-only verification job receives no insert material.

## Stable supply-chain evidence assets

The wheel also exports
`cryptad_stable_maintenance_backend:supply_chain_factory`. The protected Stable supply-chain
workflow uses this entry point only after the existing maintenance publication has created the
exact `v<build-number>` GitHub Release. The backend cannot create or change a tag, Release body,
catalog, CoreUpdater descriptor, or latest-maintenance pointer.
The adapter supplies only the explicitly authenticated `leumor` GitHub token already required by
the maintenance publication boundary.

One closed supply-chain publication plan carries exactly these roles and filenames:

| Role | Filename |
| --- | --- |
| `build-materials` | `stable-1.0-build-materials.json` |
| `component-inventory` | `stable-1.0-component-inventory.json` |
| `component-reverse-index` | `stable-1.0-component-reverse-index.json` |
| `license-inventory` | `stable-1.0-license-inventory.json` |
| `reproducibility-report` | `stable-1.0-reproducibility-report.json` |
| `release-subject-inventory` | `stable-1.0-release-subject-inventory.json` |
| `sbom` | `stable-1.0-sbom.spdx.json` |
| `supply-chain-summary` | `stable-1.0-supply-chain-summary.json` |

Before the first upload, the backend requires canonical plan bytes, a valid self-digest, the exact
integer build and `v<build-number>` tag, the exact source commit, the eight-role set, immutable
GitHub Release download URIs, and confined regular local files with the planned size and SHA-256.
The protected adapter must authenticate the backend wheel, workflow commit, and attestation before
constructing the producer identity passed to the backend.

For each role, an absent asset is uploaded once and recorded as `created`. An existing asset is
recorded as `verified-existing` only after the backend downloads it through the GitHub API and
matches its exact URI, size, and SHA-256. A duplicate name, mismatched URI, different byte stream,
or incomplete role set fails before any missing asset is uploaded. The backend never deletes or
overwrites conflicting bytes.

The maintenance plan records these files in the separate
`supplyChainCompanionAssets` suffix. A maintenance retry authenticates any present companion bytes
and continues to upload only maintenance-owned `assets`; partial or complete companion publication
does not invalidate that retry. Unknown Release assets still conflict, and companion presence does
not replace the supply-chain receipt or public observation.

The three independently published dependency-vulnerability companion names are a prospective
exception to the maintenance Release allowlist. The closed publication plan and its exact
authorization both bind `dependencyVulnerabilityGovernanceActive`, derived from the authenticated
PR-290 policy and candidate freeze. The maintenance backend accepts those independently governed
names only when both records bind `true`; a historical pre-activation release treats every such
name as an unexpected conflicting asset.

The returned publication receipt and later public observation preserve the policy-declared role
order and use canonical JSON self-digests. Observation performs no mutation: it re-fetches all
eight published assets and binds the authenticated observer identity, observation time, and exact
publication-receipt digest.
The offline backend tests use an in-memory transport and never contact GitHub:

```bash
python3 -m unittest discover \
  -s tools/release-certification/publication-backend/tests \
  -p 'test_*.py' -v
```

## Dependency-vulnerability public evidence

The same deterministic wheel exports the closed
`cryptad_stable_maintenance_backend:dependency_vulnerability_factory`. It accepts exactly the
three public-safe PR-290 roles (`dependency-vulnerability-summary`, `dependency-source-status`,
and `dependency-public-findings`) at their derived `v<build>` GitHub Release asset URIs. The plan
binds the annotated integer tag, target source commit, promotion summary, public summary, policy,
and protected authorization. Existing bytes are re-downloaded and verified; conflicting bytes are
never overwritten. Publication returns an authenticated run/attempt receipt, and observation
re-fetches every role and emits an expiring exact-byte observation. It has no issue, catalog,
CoreUpdater, lifecycle, tag, or Release-creation authority.

For lifecycle state, the configured public request URI serves the canonical descriptor bytes.
Immediately before a lifecycle insertion, the read-only
`observe_latest_maintenance_tip` operation fetches the separately authorization-bound maintenance
pointer URI. GA-only state requires a public `404` or `410`. Post-GA state requires the exact
pointer bytes, digest, release id, integer build, baseline digest, and publication-receipt digest
from the authenticated lifecycle inventory. This method has no maintenance mutation capability.
The observer accepts the legacy closed pointer shape and the train-aware closed shape that adds one
valid `backportReleaseTrainDigest`; newly activated maintenance pointers use the train-aware shape.
Unknown fields and malformed train digests remain conflicts, so this compatibility rule does not
make the pointer contract open-ended.
Observation accepts only an exact authorized target or its exact declared predecessor; redirects,
private DNS answers, malformed JSON, noncanonical bytes, unrelated editions, and digest or
update-key-scope changes fail closed. The protected capability accepts one canonical
`cryptad-stable-support-lifecycle-publication-request` carrying the exact descriptor bytes and
previous edition/digest. It must compare-and-swap rather than overwrite a conflict, and return the
closed `cryptad-stable-support-lifecycle-publication-result`. Success is not trusted until the
provider fetches the public request URI again and the protected adapter verifies the exact bytes.
An update-key revocation operation is deliberately absent from this lifecycle protocol.

## Protected deployment-service protocol

GitHub annotated tags, Releases, and assets are observed and mutated directly through the GitHub
API. Public artifact-base objects are streamed and checked against the exact size and digest in the
authorized plan before the first GitHub mutation. The artifact base is a verify-only target for
this provider: an independent deployment step must pre-stage every planned object, and an absent,
partial, or mismatched artifact base fails preflight. The first mutation-safe state is therefore an
exactly matching artifact base followed by an absent tag, Release, assets, catalog, and CoreUpdater
suffix; the adapter treats that state as a resumable matching prefix and begins with the tag.
After the Release is created, an empty asset list remains the absent `assets` target. If an upload
is interrupted, the provider streams and digest-verifies every existing planned asset, skips those
exact rows, and uploads only missing rows in deterministic plan order. The target becomes matching
only when the complete planned set is exact. Any unexpected, duplicate, malformed, size-mismatched,
or digest-mismatched row is a conflict; recovery never deletes or overwrites an asset.
The authorization plan must use the canonical
`https://github.com/crypta-network/cryptad/releases/tag/v<build>` page. Release observation binds
that page, the integer-build tag, target commit, exact note bytes, draft/prerelease flags, assets,
and the release-class title before treating existing state as idempotent. Stable GA uses
`Cryptad Stable 1.0 (v<build>)`; maintenance and security-hotfix releases use
`Cryptad v<build>`. The protected plan carries one exact title, and the provider requires the
observed Release title to match it.
Catalog, CoreUpdater, and latest-baseline state
are handled by a deployment service whose public observation endpoint is the exact
`deploymentServicePublicUri` in the publication plan. The plan also carries the exact catalog
primary, signature, mirror, rollback, CoreUpdater, GitHub Release, artifact-base, and latest-pointer
URIs. These fields are schema closed, part of `publicationTargetsDigest`, repeated in the verified
maintenance receipt where needed for activation, and compared byte-for-byte with the authorized
plan. The service endpoint follows the certification URI contract: an HTTPS authority root may be
spelled with or without its trailing slash, and a non-root endpoint may end in one slash. The
provider preserves that authorized spelling while rejecting internal empty path segments and dot
segments.

Requests and responses use canonical UTF-8 JSON with sorted keys, two-space indentation, one final
newline, no duplicate keys, and `schemaVersion: 1`. The public endpoint supports these
side-effect-free operations:

- `observe-publication`, returning predecessor/candidate identities and exact catalog/CoreUpdater
  target statuses;
- `verify-publication`, returning the complete maintenance receipt, CoreUpdater receipt, successor
  baseline, and history entry for adapter validation;
- `observe-latest-pointer`, returning the exact active pointer digest and baseline identity.

The three protected environment values are purpose-specific capability URLs, not general account
credentials. The stable-catalog capability accepts only `publish-stable-catalog`, the CoreUpdater
capability only `publish-core-update`, and the maintenance-state capability only
`activate-latest-pointer`. Mutation responses are closed and must report either an exact idempotent
match or the exact newly created state. Pointer activation is compare-and-swap against the
authorized predecessor pointer digest. A conflict, unavailable observation, redirect chain,
non-global address, malformed response, or byte mismatch fails closed and is never overwritten.

Capability URLs are materialized only for their matching call. The adapter removes them from the
environment before importing the wheel, passes an opaque purpose-bound object to the target call,
then drops the reference. They must never be placed in manifests, logs, artifacts, job summaries,
or public receipts.

`verify-publication` is self-contained. Its subject adds a closed `verificationInputs` map whose
required entries are the publication plan, candidate, candidate input, lineage, CoreUpdater plan
and descriptor, GA baseline, predecessor baseline, evidence summary, and provenance. The current
hotfix follow-up obligation and authenticated closure overlay are nullable entries. Every present
entry has exactly `digest` and `record`: `digest` is the SHA-256 of the canonical physical JSON
bytes, and `record` is the parsed value of those same bytes. Before sending the request, the
provider cross-checks the bindings already frozen into the candidate, lineage, authorization,
publication plan, and provenance. This gives the deployment verifier all data needed to construct
the deterministic receipts, successor baseline, and history entry without undocumented state.
Observation and mutation requests do not receive this expanded record set.

All verification records have already passed the adapter's schema, canonical-JSON, path
confinement, and public-value/redaction checks. The subject must never contain target capability
URLs, tokens, private insert material, raw content or app data, identity material, or local paths.
The deployment service must treat the input digests as construction bindings rather than producer
authentication: the independently running adapter remains authoritative and rejects every returned
record that does not match its own authenticated bundle.
