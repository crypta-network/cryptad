# Stable 1.0 RC validation and GA promotion

Use this runbook to validate one exact frozen Stable 1.0 release candidate, authorize its
promotion, publish those bytes without rebuilding them, and establish the Stable 1.0 maintenance
baseline.

Stable 1.0 is a product and Platform API milestone. Cryptad continues to use the integer build in
`build.gradle.kts`, the release branch `release/<build-number>`, and the tag
`v<build-number>`. Do not create a semantic `1.0.0` project version.

This runbook begins after the
[Stable RC execution and release-freeze workflow](stable-1.0-rc-execution-and-release-freeze.md)
has produced a successful final RC. It does not replace that workflow. The GA path consumes its
freeze, product, archive, checksums, provenance, catalog, app, API, profile, limitation, and
decision records as immutable release inputs.

## Promotion rule

GA promotes the exact product distribution frozen by the selected RC. It does not rebuild the
daemon, repackage the product, re-sign apps, rewrite the stable catalog, change Platform API 1.0
membership, or regenerate content-format profiles.

GA metadata is separate from the immutable RC payload. The promotion record identifies the
Stable 1.0 milestone and final publication state, but the product digest remains identical:

```text
payloadIdentity.rcProductDigest == payloadIdentity.gaProductDigest
```

If a product or catalog member must change, stop GA validation. Record an authorized blocker or
security exception through the Stable RC process, apply the fix, run every affected gate, and
complete a new protected refreeze to final `no-drift`. Start GA validation again from the new
exact freeze. A GA waiver cannot bypass refreeze.

## Separate validation, authorization, and publication

The Stable GA process has three distinct boundaries:

1. **Validation** authenticates the selected RC and verifies post-freeze production evidence. It
   is side-effect-free.
2. **Authorization** records an explicit Stable release-manager approval bound to the final
   validation digest and exact RC identities. It permits only its contracted publication scope.
3. **Publication** is an explicitly selected protected operation. It may create or verify the
   annotated tag and GitHub Release and may invoke an existing protected catalog or network
   operation. It never merges a release branch automatically.

A passing validation is not evidence that publication happened. A publication plan is not a
publication receipt. The final public state is successful only after post-publication verification
records `publication-complete`.

The state vocabulary is:

| State | Meaning |
| --- | --- |
| `validated` | Exact RC authentication, post-freeze evidence, authorization preparation, payload identity, and redaction passed. No publication is claimed. |
| `publication-authorized` | A valid, current, scoped authorization binds the final immutable validation identity and exact publication plan. Publication has not necessarily run. |
| `publication-complete` | The protected operation completed and the public tag, release assets, notes, and catalog state were independently verified. |
| `publication-verification-failed` | A side effect may have occurred, but one or more public results do not match the authorized state. Do not report GA as complete. |

## Select the exact final RC

Select the latest successful protected Stable RC freeze or refreeze for one release ID and integer
build. The selected source commit, product distribution, and outer RC archive must be the exact
bytes retained from that run.

The protected Stable RC workflow records a candidate-scoped Actions artifact and a commit-bound
freeze-lineage anchor. While the Actions artifact is retained, authenticate its producer workflow,
run, attempt, repository, source commit, environment, artifact name, and exact bytes. If a retained
freeze is checked against the fallback lineage anchor after artifact expiry, remember that the
anchor authenticates the freeze file. It does not by itself authenticate an arbitrary retained
outer archive. The GA workflow must also authenticate the retained checksums and archive through a
protected release record.

Reject the selection when:

- a later successful refreeze exists;
- the selected run, attempt, source commit, environment, or artifact name is not the expected
  protected Stable RC producer;
- the RC summary, freeze, sidecar, provenance, product, checksums, or outer archive do not belong
  to the same selected run;
- an accepted freeze-exception record is missing or changed;
- the release ID or integer build matches but the source or product digest differs; or
- an archive verifies internally but is not the archive bound by the authenticated checksum set.

Do not use a new build with the same integer version as a substitute for the selected RC.

Protected post-freeze validation and authorization files may be materialized from a confined
repository path, an authenticated `actions-artifact://` reference, or public HTTPS. HTTPS
acquisition rejects credentials, query strings, fragments, redirects, non-default ports,
localhost and `.local` names, and any hostname that resolves to a non-public address. Actions
artifacts are extracted into a confined root and reject traversal, symlinks, and special files.
These acquisition rules apply before parsing or copying evidence into a public bundle.

Acquisition safety is not producer authentication. Before publication, the exact
`stable-1.0-rc-validation.json`, `stable-1.0-ga-authorization.json`, and generated
`stable-1.0-ga-validation-authorization-identity.json` bytes must have a GitHub artifact
attestation issued by this repository's Stable GA workflow on the exact
`release/<build-number>` candidate commit. The protected `stable-1-0-ga-evidence` environment
controls that attestation. A hand-written record, an unattested repository file, or an unattested
HTTPS download cannot authorize publication even when all of its claimed digests match.

## Prepare the manifest

Copy the fail-closed example and replace every placeholder:

```bash
cp tools/release-certification/manifests/stable-1.0-ga.example.json \
  build/stable-1.0-ga.json
```

The manifest retains the `stable-review` profile. The command and component are both `stable-ga`.
The canonical input names are:

| Input | Required content |
| --- | --- |
| `selectedStableRcSummary` | Common evidence-envelope v2 `summary.json` from the selected `stable-rc` component. |
| `selectedStableRcFreeze` | Exact `stable-1.0-rc-freeze.json`. |
| `selectedStableRcFreezeSidecar` | Exact `stable-1.0-rc-freeze.sha256`. |
| `selectedStableRcArchive` | Exact `cryptad-stable-1.0-rc-<build>.tar.gz`. |
| `selectedStableRcProduct` | Exact `crypta-stable-1.0-rc-<build>-product.tar.gz`. |
| `selectedStableRcChecksums` | Exact RC `checksums.txt`. |
| `selectedStableRcProvenance` | Exact RC `provenance.json`. |
| `selectedStableRcLineage` | Protected `stable-1.0-rc-lineage` record for the latest successful RC run. |
| `previousCandidate` | Exact migrated previous-candidate envelope whose file digest is frozen in both the selected RC freeze and RC provenance. |
| `stableRcValidation` | Post-freeze `stable-1.0-rc-validation` evidence for the exact selected product. |
| `stableGaAuthorization` | Explicit `stable-1.0-ga-authorization` record. |
| `stableGaPolicy` | Checked-in `tools/release-certification/stable-1.0-ga-policy.json`. |
| `stableGaPublicationReceipt` | Optional returned publication receipt to verify after a protected publication attempt. |

The relevant non-secret policies are:

- `artifactBaseUri`: reviewed public HTTPS base for release assets;
- `catalogChannel`: `stable`;
- `candidateSourceCommit`: exact selected commit;
- `candidateSourceRef`: the exact immutable `commit:<candidateSourceCommit>` identity frozen by
  Stable RC (the protected workflow verifies `release/<build>` independently);
- `expectedPreviousReleaseId`: release ID parsed from the exact PR-283-frozen previous-candidate
  envelope;
- `expectedPreviousProductDigest`: independently selected SHA-256 of the exact published
  predecessor product used by the protected upgrade drill;
- `metadata.catalogPrimaryUri`, `metadata.catalogMirrorUris`, and
  `metadata.catalogRollbackUri`: distinct, credential-free public HTTPS locations used to confirm
  the exact frozen current and rollback catalog bytes;
- `publicationIntent`: non-secret intent metadata. The `stable-ga` command remains side-effect-free
  for every value; the protected workflow owns publication.

Keep every selected RC file under one symlink-free authenticated input root. The validator rejects
absolute archive member names, traversal, symlink or hard-link members, special files, duplicate
or ambiguous files, AppleDouble metadata, unsupported nested archives, and paths that resolve
outside that root.

The manifest must not contain signing keys, private insert URIs, GitHub tokens, cookies,
authorization headers, form passwords, app or browser tokens, or publication credentials. Supply
protected inputs through the `stable-1-0-ga` environment or protected files. Do not serialize
their values or absolute runner paths into public artifacts.

## Run side-effect-free GA validation

Run the focused offline test first:

```bash
python3 tools/release-certification/certify.py stable-ga --self-test
```

Then run validation from the selected candidate checkout:

```bash
python3 tools/release-certification/certify.py stable-ga \
  --manifest build/stable-1.0-ga.json
```

The release-scoped component is:

```text
build/release-certification/<release-id>/stable-ga/
```

This command validates and packages promotion metadata. It does not create a branch, tag, GitHub
Release, update descriptor, catalog insert, network insert, or public announcement.

Authorization uses a deliberate two-pass review when an approval record has not yet been created.
Set `commands.stable-ga.mode` to `prepare-authorization`, omit `stableGaAuthorization`, and run the
same command. A successful preparation validates every immutable RC and post-freeze input, returns
without publication readiness, and writes
`stable-1.0-ga-validation-authorization-identity.json`. The release manager reviews that record and
authorizes its canonical semantic SHA-256 in `gaValidationDigest`. Add the resulting protected
authorization input, restore mode `validate-only`, and rerun from the beginning. The final
`stable-1.0-ga-validation.json` records both the authorization and its exact file digest. This
separation avoids a circular hash while ensuring the approval covers all immutable validation
facts. The reviewed identity also contains a canonical publication-target object and digest that
bind the expected integer-build tag and release branch, public artifact base, stable-catalog
primary, and ordered mirror list. A destination change requires a new preparation pass, protected
authorization, and evidence attestation. `prepare-authorization` rejects an authorization or
publication receipt and can never be treated as publication ready.

## Authenticate the frozen RC

The GA command requires the selected common Stable RC envelope to have:

```text
schemaVersion = 2
kind = stable-1.0-rc
subject.releaseId = selected release ID
subject.version = selected integer build
subject.profile = stable-review
subject.component = stable-rc
result.status = pass
result.promotionReady = true
result.exitCode = 0
redaction.status = pass
redaction.findingCount = 0
payload.legacy.nonRelease = false
payload.legacy.stableReady = true
payload.legacy.freeze.status = pass
payload.legacy.freeze.driftStatus = no-drift
payload.legacy.decision = go or go-with-waivers
```

The validator then verifies the complete RC chain:

1. Validate the closed freeze schema and recompute its canonical content digest.
2. Verify the SHA-256 sidecar against the exact freeze file bytes.
3. Validate provenance against release ID, build, source commit and ref, freeze content and file
   digests, exact product digest, input digests, previous-freeze binding, and archive layout.
4. Require the external RC checksum file to contain the exact sorted public artifact allowlist and
   verify every entry.
5. Verify the normalized outer archive, exact member allowlist, embedded payload checksums, and
   equality between every archived metadata member and its reviewed standalone file.
6. Verify the product digest in the freeze, provenance, standalone product, external checksums,
   and outer archive member is identical.
7. Verify the frozen Platform API baseline, stable catalog, signatures, first-party app set,
   reviewer receipts, content profiles, limitations, accepted waivers, and accepted exception
   history without regenerating them.

The provenance record describes the outer archive layout but cannot contain the archive's own
digest without a circular dependency. The exact external RC checksum set is therefore mandatory
for authenticating the outer archive.

## Require post-freeze production validation

The post-freeze validation record has kind `stable-1.0-rc-validation`. Every scenario binds the
release ID, integer build, source commit, freeze digest, exact product digest, outer archive
digest, stable catalog digest and revision, start and end times, and production classification.

The checked-in GA policy requires at least 24 hours of real post-freeze soak. A duration exactly
equal to 24 hours passes. `validationStartedAt` and every scenario `startedAt` must be at or after
the authenticated protected RC run completion recorded by the selected lineage. The long-soak
scenario's own `startedAt`/`endedAt` interval must cover both `actualDurationSeconds` and the policy
minimum; a longer top-level validation window cannot substitute for the soak interval. Fixture,
simulated-only, skipped, stale, non-production, or wrong-candidate evidence does not satisfy the
policy.

The validation record's `policyDigest` is the SHA-256 of the exact checked-in policy file bytes.
The GA command separately compares the parsed policy with the repository copy, so neither a
semantic policy mutation nor an unreviewed formatting/file substitution is accepted.

The protected evidence must cover:

- multiple nodes running the exact frozen product for the policy duration;
- memory, thread, queue, restart, corruption, and subscription-growth budgets;
- required live-network and Hyphanet interoperability outcomes;
- performance comparison with the accepted release baseline;
- clean installation or unpack, startup, shutdown, first-run state, launcher/runtime discovery,
  operator access, diagnostics, metadata and checksum verification, and cleanup for every claimed
  supported OS/package target;
- the checked-in minimum GA packaging matrix: Linux DEB and RPM, macOS DMG, and Windows EXE,
  with architecture and artifact identity recorded for every protected target; any additional
  format selected for the release must also have a protected target row before it is claimed;
- upgrade from the required previous published or public-beta candidate;
- daemon recovery or rollback, stable catalog update and rollback, and first-party app
  install/update/rollback;
- app-data migration with a pre-migration backup and verified restore;
- Social Inbox thread and read-state preservation, Trust Graph anchor/statement/lifecycle
  preservation, Feed Reader subscription/read-state preservation, and Profile Publisher state
  preservation;
- a redacted support bundle after a deliberately failed upgrade or recovery scenario;
- current mandatory security-response drills, production sandbox evidence, signing and reviewer
  key health, denylist/advisory fail-closed behavior, privacy-preserving diagnostics, support
  readiness, and primary/mirror/rollback/key-rotation catalog health; and
- confirmation that no new Stable blocker or disallowed limitation appeared after freeze.

Evidence may aggregate existing protected collectors, but it must state and prove the exact frozen
product digest. General beta evidence that cannot identify the exercised bytes is not GA evidence.
The upgrade scenario additionally records the exact frozen `previousCandidate` envelope digest,
predecessor release ID and integer build, and predecessor product digest. The GA gate authenticates
the envelope against both PR-283 bindings, derives release/build from its redaction-safe legacy
payload, and compares the product digest with the manifest selection. All four values are copied
into the authorization identity; changing the predecessor therefore requires a new validation and
authorization pass.

## Validate explicit GA authorization

The authorization is a protected input bound to:

- release ID and integer build;
- exact source commit;
- freeze, product, outer archive, and stable catalog digests;
- canonical `stable-1.0-ga-validation-authorization-identity` semantic digest;
- required predecessor release/build, frozen previous-candidate digest, and exact predecessor
  product digest;
- canonical publication-target object and digest, including the exact artifact base, catalog
  primary, ordered mirrors, expected `v<build>` tag, and `release/<build>` branch;
- authorization role and public-audit approver identity;
- approval timestamp and expiration or review time;
- a narrow allowed publication scope; and
- passing redaction with zero findings.

Placeholder approvers, expired approval, an under-authorized role, a wrong candidate, any digest
mismatch, a wildcard scope, or missing redaction metadata fails closed. Authorization cannot waive
archive integrity, candidate binding, redaction, signing identity, Platform API compatibility,
catalog trust, security drills, sandbox, live network, upgrade, migration, backup/restore, or any
other non-waivable gate.

Existing RC waivers are copied only when they remain active, in scope, unexpired, policy-compliant,
and explicitly allowed for Stable GA. GA does not create broader post-freeze waivers.

## Interpret the GA decision

The pre-publication decision remains `go`, `no-go`, or `go-with-waivers`. Promotion readiness
requires:

```text
status = pass
promotionReady = true
nonRelease = false
selectedRc.status = pass
selectedRc.promotionReady = true
selectedRc.driftStatus = no-drift
postFreezeValidation.status = pass
postFreezeValidation.exactRcBinding = true
authorization.status = authorized
redaction.status = pass
payloadIdentity.rcProductDigest = payloadIdentity.gaProductDigest
decision = go or go-with-waivers
```

Digest mismatch, stale lineage, rebuild or member drift, API/profile/catalog/app drift, insufficient
soak, missing platform coverage, failed upgrade or recovery, failed security or live evidence,
unsafe archives, publication conflicts, and new disallowed limitations are non-waivable.

## Review generated artifacts

The common public surface remains:

```text
summary.json
report.md
redaction-report.json
```

The native GA artifacts are:

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

`stable-1.0-ga-publication-receipt.json` is present only when verifying a returned protected
publication result. Before publication, the notes and promotion summary must say that publication
has not occurred.

`stable-1.0-ga-checksums.txt` lists the six non-checksum assets in the public publication plan.
The checksum file is the seventh planned asset; its own size and digest are bound by the promotion
plan, provenance, and publication receipt. It does not name internal validation, authorization,
or redaction records that are deliberately absent from the public GitHub Release.

The release-note generator uses
[the Stable 1.0 GA template](templates/stable-1.0-ga-release-notes.md). Its version marker and
ordered tokens are a closed contract. A missing, duplicate, unknown, reordered, or unresolved
token fails validation.

## Publish only through the protected workflow

`.github/workflows/stable-1.0-ga-promotion.yml` separates evidence attestation, validation, and
publication. It uses JDK 25 and two protected environments:

- `stable-1-0-ga-evidence` approves and attests exact validation, authorization, and canonical
  publication-target identity bytes;
- `stable-1-0-ga` approves the side-effecting publication job.

The Stable RC and Stable GA workflows share one concurrency group for the integer build. That lock
is held across validation, protected-environment approval waits, and publication, so a refreeze
cannot supersede the selected RC while GA is mutating or accepting public state. GitHub retains at
most one pending run per concurrency group; release managers must inspect the build queue and
cancel a waiting GA run before dispatching an urgent refreeze rather than expecting the refreeze to
preempt it.

Configure `STABLE_CATALOG_TRUSTED_KEYS_BASE64` as an environment-scoped secret in
`stable-1-0-ga`. Its decoded value is the production trusted catalog **public-key** properties
registry consumed by `crypta-app catalog verify`; it is temporary verification input, is deleted
at job exit, and is never uploaded. Do not place private catalog signing material in this value.

The validation job checks out the exact source commit, verifies a clean workspace, authenticates
the selected Stable RC artifact, runs `stable-ga`, and uploads only redaction-safe promotion
material. It has no permission to create tags or GitHub Releases.

First dispatch the workflow from the exact `release/<build-number>` ref with `publish=false`. After
validation passes, the protected evidence job downloads the same-run artifact, verifies its
artifact name and digest, and attests the exact post-freeze validation and GA authorization files.
It also attests the generated authorization identity that fixes the public artifact and catalog
destinations. Approval of this job is the producer-authentication boundary; it is not a GA
publication.

For publication, dispatch again from the same exact release ref and commit with `publish=true` and
the identical evidence bytes and identical publication destinations. The publication job runs
only after that dispatch's validation job passes and protected publication approval is granted.
It verifies all three prior attestations against
the repository, Stable GA workflow, release ref, candidate commit, and GitHub-hosted runner. It
then reruns `stable-ga` before every tag, Release, asset-upload, or finalization mutation and again
before recording completion. An authorization, carried waiver, or evidence freshness window that
expires while publication is in progress therefore stops the next mutation even if the earlier
validation job passed. The job also rechecks checksums, provenance, release branch, integer build,
expected tag, notes, assets, and stable catalog plan.

Before the `publish=true` dispatch, stage all seven planned assets at the authorized
`artifactBaseUri`. This is an independently populated public distribution base, not a GitHub
Release URL that comes into existence during this workflow. Immediately before the first tag or
Release mutation, the job freshly resolves the base, requires every A/AAAA address to be globally
routable, pins HTTPS downloads to those approved addresses, and verifies every planned size and
digest. It repeats the resolution and byte verification after GitHub publication; only the final
observations enter the completion receipt.

The publication job rereads `release/<build-number>` at each side-effect boundary, again before
creating the tag reference after an annotated tag object exists, and once more before recording a
successful receipt. If the branch no longer points to the authorized commit, the job fails closed
and its recovery path only records the observed partial or conflicting state.

The same pre-publication boundary freshly authenticates the selected Stable RC run and all matching
freeze/refreeze attempts. Successful attempts are ordered by GitHub completion/update time rather
than run ID; an active attempt, equal-time ambiguity, newer successful refreeze, or mismatch with
the retained lineage record stops publication before tag creation.

All GitHub operations must use the repository-required `leumor` identity. The operation creates or
verifies an annotated `v<build-number>` tag on the authorized commit and creates or verifies the
GitHub Release from the validated notes and exact assets. It never creates `v1.0.0`, rewrites a
tag, or merges `release/<build-number>` into `main` or `develop`.

Catalog or network publication remains a separate explicit protected operation. Reuse an existing
release-manager operation when one exists. Do not put private insert URIs or credentials in the
GA manifest, plan, logs, or receipt.

## Handle conflicts and retries

Publication is idempotent only when the existing public state exactly matches the authorization.

- An existing tag passes only when it is the expected annotated `v<build-number>` tag and resolves
  to the authorized source commit.
- An existing GitHub Release passes only when its tag, normalized release-note digest, exact asset
  names, sizes, and digests match the plan and it has no unexpected asset.
- Every planned asset must also be retrievable as the exact authorized bytes from
  `artifactBaseUri + <asset-name>`. A matching GitHub Release does not compensate for a missing or
  mismatched declared artifact base.
- An existing stable catalog publication passes only when the primary and every required mirror
  return the exact frozen signed catalog bytes, revision, signature, signing identity, app entries,
  receipts, and public artifact URLs. The separately authorized rollback URI must return the exact
  frozen rollback digest and a signature under the frozen catalog signing-key identity that
  verifies against the protected trusted-key registry.
- A mirror is a transport fallback, not a trust authority. Verify its signature independently.

Matching state may be reused and recorded in the receipt. A tag pointing elsewhere, a different
asset, changed notes, stale mirror, untrusted signature, wrong catalog revision, or unexpected
public asset is a conflict. Do not overwrite or delete the conflicting state automatically. Record
`publication-verification-failed`, stop further publication, and require release-manager recovery.
The failure handler is observation-only: it never creates a tag ref, Release, asset, or catalog
publication. It writes a sanitized conflict/partial-state receipt even when this run made no side
effect and no GitHub Release exists. GitHub read failures are recorded as `unavailable`, never as
an observed absence. Unplanned remote asset names are represented only by a count and SHA-256
identifiers. The workflow uploads the receipt only after its closed schema, placeholder, and
redaction checks pass.

## Verify publication and record the receipt

After every publication attempt, independently verify:

- the annotated tag resolves to the authorized commit;
- the GitHub Release public identifier and URL match the planned tag;
- every asset name, size, and SHA-256 matches the authorized checksum set;
- every asset's declared public URI is exactly `artifactBaseUri + <asset-name>` and returns those
  exact bytes;
- no unexpected or private artifact was uploaded;
- release notes match the authorized digest or the contracted normalized representation;
- the stable catalog primary and mirrors return the exact frozen catalog and signature bytes;
- the authorized rollback URI returns the frozen rollback catalog digest and a cryptographically
  trusted signature under the frozen catalog signing-key identity, with the observed signature
  digest and signing key recorded in the receipt;
- key-rotation, advisory, and denylist state remains the authorized state; and
- the receipt itself is redaction-safe.

The publication step first writes an internal receipt candidate. Only a fresh `stable-ga` run can
promote that observation to the canonical completion receipt; verifier failure instead writes a
`publication-verification-failed` audit receipt. The closed receipt binds release/build/source
identity, tag and target, public release identity,
the artifact base, each asset's name/size/digest/public URI, RC freeze/product/archive digests, GA
promotion digest, catalog result, release-note digest, publication time, public-safe workflow run
and attempt identity, verification status, redaction status, and explicit public-state observation
statuses. Every completion receipt asset must be planned and passing; any unexpected remote name
is counted and digest-identified without copying that untrusted name into a public audit artifact.

A partial operation is not successful GA. Preserve its receipt and public observations, mark
`publication-verification-failed`, and follow the recovery plan without changing authorized bytes.

## Stable catalog identity

GA publishes or confirms the exact signed stable catalog frozen by the RC. It must preserve:

- catalog ID and stable channel;
- edition and revision;
- catalog and signature digests;
- catalog signing key ID;
- frozen artifact timestamp;
- exact ordered app entries, bundle URLs, and review receipts;
- primary and public mirror locations;
- verified rollback revision;
- key-rotation state; and
- advisory and denylist state.

Re-fetch the primary and mirrors after publication. A remote byte mismatch, wrong revision,
untrusted signature, missing sidecar, or stale mirror prevents `publication-complete`.

## Establish the Stable 1.0 maintenance baseline

`stable-1.0-maintenance-baseline.json` is generated deterministically from the selected RC and GA
promotion records. It contains no volatile local paths or private material. It binds:

- GA integer build, expected tag, source commit, RC freeze, product, and GA promotion digests;
- Platform API 1.0 baseline/current stable surface and compatibility-window policy;
- stable catalog revision, signing key, exact app versions, bundles, and review receipts;
- first-party app data schemas and migration/backup support;
- content-format profile versions and canonicalization digests;
- carried Stable limitations and known issues;
- security advisory, denylist, reviewer, sandbox, support, and diagnostics state;
- legacy plugin/admin freeze boundaries and retained FProxy browse behavior; and
- evidence windows required for later maintenance and hotfix releases.

The checked artifact has `status=prepared` because side-effect-free validation must not claim GA
publication. A verified `publication-complete` receipt makes those exact prepared baseline bytes
authoritative; the workflow does not rewrite the baseline after publication merely to change a
label.

Future maintenance work compares against this baseline. Expected categories are:

- compatible bug fixes;
- security fixes and `hotfix/<build-number>` releases;
- Platform API-compatible additions and deprecations under the support window;
- stable catalog and app patch updates with migration and rollback evidence;
- emergency advisory and denylist updates; and
- maintenance-release upgrade, rollback, backup, and restore verification.

The baseline documents those comparison categories. It does not create a new versioning or release
branch model.

## Public artifact boundary

Public GA artifacts must not contain:

- private signing keys or private insert URIs;
- tokens, cookies, credentials, authorization headers, or private workflow inputs;
- raw fetched content, raw request/response bodies, raw app data, or backup payloads;
- raw support bundles, diagnostics, social messages, profile documents, or trust statements;
- identity material or raw reviewer key bytes;
- absolute runner paths, scratch directories, or command lines containing secrets;
- symlinks, hard links, special files, path traversal, AppleDouble files, `.DS_Store`, or
  `__MACOSX/`; or
- unsupported or unsafe nested archives.

Use public-safe key IDs, digests, counts, states, relative artifact names, and HTTPS locations.
Redaction, archive hygiene, provenance, candidate binding, and authorization failures are
non-waivable.

## Release-manager checklist

- [ ] The selected RC is the latest successful protected freeze/refreeze for the release and build.
- [ ] The common RC envelope, freeze, sidecar, checksums, provenance, product, and archive all pass.
- [ ] Product identity is exact across standalone and archived copies.
- [ ] At least 24 hours of real, exact-product post-freeze soak passed.
- [ ] Install, upgrade, rollback, migration, backup/restore, live, interop, performance, security,
      sandbox, and support evidence passed.
- [ ] Stable catalog, app, API, content-profile, limitation, waiver, and exception state is unchanged.
- [ ] Explicit GA authorization is current, scoped, and bound to the final immutable validation identity digest.
- [ ] The release branch is `release/<build-number>` and the expected tag is
      `v<build-number>`.
- [ ] The validation job passed with no publication permission.
- [ ] Publication was explicitly selected and approved in `stable-1-0-ga`, if publication is
      intended.
- [ ] GitHub operations use `leumor` and no branch merge is automatic.
- [ ] Public tag, release assets, notes, and catalog state match the authorization.
- [ ] The publication receipt says `publication-complete`; otherwise GA is not complete.
- [ ] The Stable 1.0 maintenance baseline is retained with the release record.

## Later Stable 1.0 releases

The GA baseline remains the immutable compatibility root. Later integer-build maintenance releases
and security hotfixes authenticate the GA publication receipt and those exact baseline bytes; they
do not refreeze the RC, rerun GA promotion, or replace the GA baseline. They also authenticate the
immediately preceding published Stable 1.0 release and advance a separate successor-baseline chain.

Use the [Stable 1.0 maintenance release and security hotfix
path](stable-1.0-maintenance-release-and-hotfix-path.md) for candidate freeze, compatibility
comparison, authorization, protected exact-byte publication, and hotfix follow-up closure.

After GA publication is independently verified, establish the separate mutable support-lifecycle
state. The first lifecycle edition requires a protected proof that the exact public
`support-lifecycle` target has never existed and currently returns HTTP `404`; a tombstone does not
qualify. That edition authenticates the GA publication receipt and immutable maintenance baseline,
then records GA as `current-stable` without changing either historical artifact.

Use the [Stable 1.0 support lifecycle and deprecation governance
runbook](stable-1.0-support-lifecycle-and-deprecation-governance.md) for genesis, later maintenance
transitions, protected publication, independent verification, and local runtime behavior.
