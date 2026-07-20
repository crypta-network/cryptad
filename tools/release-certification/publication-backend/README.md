# Stable maintenance publication backend

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
that page, the integer-build tag, target commit, deterministic `Cryptad v<build>` title, exact note
bytes, draft/prerelease flags, and assets before treating existing state as idempotent.
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
