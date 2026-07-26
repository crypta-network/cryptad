# Stable 1.0 maintenance release and security hotfix path

Use this runbook to validate and prepare a later Stable 1.0 maintenance build or critical security
hotfix, publish the exact frozen bytes through the protected workflow, and activate the verified
result as the next maintenance baseline.

This path starts after Stable 1.0 GA publication. It does not replace the Stable RC freeze or GA
promotion process. Stable 1.0 remains a product and API milestone; Cryptad releases continue to use
one integer build number and an annotated `v<build-number>` tag.

## Command and scope

Copy the checked-in example, replace every placeholder with public-safe release data, and keep
private publication material in protected environment or file inputs:

```bash
cp tools/release-certification/manifests/stable-1.0-maintenance.example.json \
  build/stable-1.0-maintenance.json
python3 tools/release-certification/certify.py stable-maintenance \
  --manifest build/stable-1.0-maintenance.json
```

The component is `stable-maintenance`, uses `release.profile=stable-review`, and writes below:

```text
build/release-certification/<release-id>/stable-maintenance/
```

`policies.releaseClass` is closed to:

- `maintenance` for a routine `release/<build-number>` stabilization branch from `develop`;
- `security-hotfix` for a critical `hotfix/<build-number>` branch from the currently published
  `main` state.

`commands.stable-maintenance.mode` is closed to:

| Mode | Purpose | Public side effects |
| --- | --- | --- |
| `validate-only` | Authenticate lineage, freeze and compare a candidate, and evaluate all gates. | None. |
| `prepare-authorization` | Produce the exact candidate, comparison, publication target, note, and updater identities that a protected approver may authorize. | None. |
| `close-hotfix-follow-up` | Verify the full normal-window evidence for an already published expedited hotfix and close its obligation. | None. |

No mode creates a branch, merge, tag, GitHub Release, catalog revision, update descriptor, CHK or
USK insert, public announcement, or latest-baseline activation. Self-tests, pull-request workflows,
and ordinary local runs cannot publish.

## Deterministic artifact set

The component uses the versioned maintenance, successor-baseline v2, CoreUpdater, and hotfix
follow-up schemas under `tools/release-certification/schemas/`. Its canonical component files are:

```text
stable-1.0-maintenance-lineage.json
stable-1.0-maintenance-candidate.json
stable-1.0-maintenance-comparison.json
stable-1.0-maintenance-validation.json
stable-1.0-maintenance-authorization-summary.json
stable-1.0-maintenance-promotion-summary.json
stable-1.0-maintenance-go-no-go.md
stable-1.0-maintenance-known-limitations.json
stable-1.0-maintenance-release-notes.md
stable-1.0-maintenance-publication-plan.json
stable-1.0-maintenance-publication-receipt.json
stable-1.0-maintenance-publication-failure-audit.json
stable-1.0-maintenance-checksums.txt
stable-1.0-maintenance-audit-checksums.txt
stable-1.0-maintenance-provenance.json
stable-1.0-maintenance-successor-baseline.json
stable-1.0-maintenance-history-entry.json
stable-1.0-maintenance-latest-published.json
core-info.json
core-update-publication-plan.json
core-update-publication-receipt.json
redaction-report.json
```

`stable-1.0-maintenance-checksums.txt` is the public, operator-verifiable manifest. It lists only
the noncircular public payloads: the product and package assets, stable catalog and detached
signature, release notes, known-limitations delta, provenance, and `core-info.json`. The checksum
file cannot list itself, and it cannot list the authorization because the authorization already
binds the checksum-file digest. The publication plan and receipt bind both omitted public files by
their exact size and digest. Internal lineage, candidate-freeze, comparison, evidence, validation,
follow-up, publication, baseline, history, pointer, redaction, summary, and report records never
appear in the public checksum rows.

`stable-1.0-maintenance-audit-checksums.txt` is the separate internal component inventory. It is
written after the component summary and report and deterministically covers every other file
present in the release-scoped component output. It is retained for audit and recovery, but it is
not a GitHub Release or artifact-base publication asset.

The canonical publication receipt is emitted only after its closed schema and independent public
verification pass. A failed or partial operation emits the separately schema-validated
`stable-1.0-maintenance-publication-failure-audit.json`, including unavailable observations and a
conservative side-effect flag; it is never presented as a successful receipt. An expedited hotfix
also emits `stable-1.0-hotfix-follow-up-obligation.json`; a successful
full-window closure emits `stable-1.0-hotfix-follow-up-closure.json`. Routine maintenance forbids
the obligation. Prepared plans, receipts, baselines, history, and pointers do not assert public
activation: only a verified protected publication may finalize or activate them.
The protected activation audit additionally retains
`stable-1.0-maintenance-activation-authorization.json` and
`stable-1.0-maintenance-baseline-activation-receipt.json`; the former is a renewable workflow
authorization, not a release asset or successor-baseline input.

When closing an obligation carried by a later hotfix, the closure manifest keeps the originally
obligated release id and build as its candidate identity while selecting the latest activated
carrier as `expectedPredecessor*`. That carrier build may therefore be higher than the obligated
build. The exact original candidate freeze authenticates its own predecessor observation; the
carrier baseline, receipt, and pointer authenticate only the current location of the obligation.

## Stable GA root and immediate predecessor

Every candidate has two authenticated anchors:

1. the immutable Stable 1.0 GA maintenance baseline, which defines the long-term Stable 1.0 API,
   catalog, app, content-profile, security, support, limitation, and legacy boundaries;
2. the immediately preceding published Stable 1.0 build, which defines the upgrade, rollback,
   release-history, and short-term comparison boundary.

The GA root remains `stable-1.0-maintenance-baseline.json` schema v1 with `status=prepared`. That
file is trusted only when its exact digest is present in the authenticated GA publication plan,
promotion record, checksums, and a passing `publication-complete` GA receipt. The maintenance path
also authenticates the GA validation, authorization, annotated tag, GitHub Release assets,
artifact base, product digest, provenance, stable catalog primary and mirrors, and public-state
observations. It never rewrites or relabels the GA baseline.

For the first maintenance build, GA is both anchors. For a later build, the immediate predecessor
is the latest activated maintenance successor baseline and its passing publication receipt. The
engine walks every predecessor link back to the GA v1 root and rejects a stale pointer, fork,
missing receipt, skipped published predecessor, mismatched product, unverified public state, or
unpublished candidate presented as current stable state. Build numbers must increase strictly but
do not need to be consecutive.

The standard maintenance manifest also carries the exact active support-lifecycle authority chain:

```text
inputs.previousStableLifecycleLedger
inputs.previousStableLifecycleDescriptor
inputs.stableLifecycleAuthorization
inputs.stableLifecyclePublicationPlan
inputs.stableLifecyclePublicationReceipt
```

These five inputs are one authority and therefore must be supplied together. The ledger
authenticates the predecessor's release identity and eligibility, the descriptor is the current
mutable public projection, the approved authorization binds the exact lifecycle target, the
authorized plan binds that approval to the descriptor and ledger, and the verified publication
receipt binds the exact plan, descriptor bytes, edition, update-key scope, and ledger digest. Every
post-GA successor predecessor requires all five. Missing files, a partial authority chain, stale
descriptor, mismatched digest, non-current predecessor, or unverified publication keeps the
candidate non-promotion-ready or fails certification.

The five files authenticate what was published, but they do not prove that their edition is still
the public tip. For authorization preparation and validation, the protected maintenance workflow
therefore installs the independently attested lifecycle-only provider and re-fetches the exact
public descriptor while holding the shared `stable-1-0-maintenance-publication` lock. It emits and
attests a separate `stableLifecyclePublicObservationReceipt`; this sixth item is deliberately
regenerated instead of becoming part of the immutable five-file handoff. The receipt must report
`verified-existing` and bind the exact edition, semantic and byte digests, ledger, plan,
authorization, public request URI, and update-key identity/scope/docname. Its maximum age is the
policy field `supportWindows.maximumPublicObservationAgeMinutes` (30 minutes in policy v1); future,
expired, or pre-publication observations fail closed. The publish operation repeats the same
read-only exact-byte observation immediately before its side-effect-free maintenance preflight.
Because lifecycle mutation uses the same lock, a newer edition cannot race between that observation
and the protected maintenance publication. No package, tag, catalog, updater, or lifecycle insert
secret is available to the observation operation.

The maintenance workflow reads the lifecycle provider run id, fixed artifact name, and Actions
artifact digest from the repository variables
`CRYPTAD_STABLE_LIFECYCLE_PUBLICATION_BACKEND_RUN_ID`,
`CRYPTAD_STABLE_LIFECYCLE_PUBLICATION_BACKEND_ARTIFACT_NAME`, and
`CRYPTAD_STABLE_LIFECYCLE_PUBLICATION_BACKEND_ARTIFACT_DIGEST`. These are not manual dispatch
inputs. The workflow still verifies the canonical producer workflow, reviewed source commit,
pinned wheel digest, artifact digest, attestation, and lifecycle-only entrypoint before each
read-only observation. `freeze-candidate` does not materialize or invoke this provider.

The only omission exception is a chain-depth-0 GA genesis evaluation. That exception permits
operators to inspect the first maintenance proposal while bootstrapping the initial lifecycle
descriptor, but it explicitly returns `promotionReady=false` and `decision=no-go`. It is not an
authorization or publication bypass. Publish and verify the GA-rooted lifecycle descriptor through
the protected lifecycle workflow, then use its exact five-artifact authority chain—ledger,
descriptor, approved authorization, authorized publication plan, and verified receipt—before
authorizing the first maintenance build.

## Successor baseline and history

A verified maintenance or hotfix publication produces a reusable Stable 1.0 successor maintenance
baseline schema v2. It records:

- the immutable GA baseline digest and Stable 1.0 API identity;
- the previous baseline, lineage, product, and publication-receipt digests;
- chain depth and the current release id, integer build, tag, source commit, and release class;
- product, package, checksum, provenance, catalog, update-descriptor, and publication identities;
- current Platform API contract and stable-surface identities without resetting compatibility
  clocks;
- stable catalog, first-party app, content-profile, limitation, security, support, and legacy
  state;
- the evidence-window policy and any security-hotfix follow-up state.

The protected workflow writes a deterministic release-history entry and atomically replaces the
latest-published pointer only after independent publication verification passes. A failed or
partially published candidate remains in failed history and never becomes the predecessor for a
later release. The activation adapter supplies the backend with the exact canonical pointer bytes,
requires the independently observed post-activation byte digest to match them for both a new and an
idempotent activation, and records the expected and observed pointer digests in its activation
receipt. The immutable publication authorization is authenticated to the receipt but is not reused
as a time-limited activation credential. After the protected activation environment admits the
job, that job creates a renewable, activation-only authorization bound to the exact receipt,
successor baseline, history entry, original authorization digest, and compare-and-swap predecessor
pointer. The adapter requires that separate grant to be current and no more than one hour long.
This lets an approved retry finish activation after publication without replacing any public byte.
Immediately before invoking the compare-and-swap adapter, the workflow creates a retained
activation-boundary marker. Every activation outcome uploads that marker and an audit that treats
pointer mutation as possible after the boundary, even if the adapter process exits before writing
a receipt. When a success or failure receipt exists, the audit also preserves its independently
observed pointer digest; a missing receipt never implies that the pointer remained unchanged.

## Candidate build and exact-byte freeze

A maintenance build introduces new bytes. Build and freeze one candidate once, then preserve that
candidate through authorization and publication.

Portable archive modes are determined solely from canonical member paths, not host filesystem
execute checks. Directories, Unix/JRE launchers, jlink helper executables, and shipped wrapper
native libraries use the fixed executable mode; JARs, configuration, Windows launchers, and other
ordinary payloads use the fixed regular-file mode on every supported build host. Both the Gradle
and Python normalizers derive these modes anew, and the independent archive gate rejects a member
whose mode does not match its path role.

Every package producer verifies after its build that `HEAD` is still the declared candidate and
that neither the Git index nor any tracked working-tree path changed. Generated untracked build
outputs are deliberately excluded from this check. The source-lineage gate also requires the exact
`release.sourceCommit` from the authenticated latest predecessor baseline to be an ancestor of the
candidate. A release or hotfix that omits its predecessor's published fixes must stop until the
required manual merge and back-merge have carried those fixes forward.

The freeze binds:

- release id, integer build, release class, branch, immutable ref, source commit, and clean source
  state;
- Java and Gradle toolchain identity plus dependency-verification state;
- deterministic product archive and every package or installer digest, size, mode, and name;
- stable catalog bytes and detached-signature sidecar as separate exact assets, plus the signing
  key, edition, revision, mirrors, and rollback state;
- first-party bundle, manifest, signing, review, permission, data-schema, and support identities;
- Platform API contract, stable diff, compatibility policy, and third-party stable sample results;
- content-profile descriptors, canonicalization, size, and signature-payload rules;
- limitations, security, support, live, interop, performance, sandbox, upgrade, and recovery
  evidence digests;
- release notes, checksums, provenance, and deterministic `core-info.json` bytes;
- freeze time and redaction result.

Archive checks retain the Stable RC rules: canonical member order, normalized timestamps and
ownership, safe regular files/directories/symlinks, deterministic gzip metadata, no absolute or
traversal paths, no special files, no AppleDouble, `__MACOSX`, or `.DS_Store`, and recursive
inspection of nested archives.

The independent gate also rejects path aliases such as `a`, `a/`, or `bin/./x`, Windows drive and
UNC absolute paths, duplicate members at every nesting level, escaping symlink targets, optional
gzip header fields, noncanonical PAX records, ZIP comments or extra fields, and ZIP members without
explicit Unix type and mode metadata. Nested archives are read through a bounded stream before
materialization. Package rows must agree with their AppEnv selector, producer architecture,
suffix, container magic, and authenticated DEB, RPM, or PE architecture where that metadata is
available; a renamed or mislabeled installer is not an acceptable package.

After authorization, any changed product, package, signature, catalog, descriptor, checksum,
provenance, note source, archive member, or file mode invalidates the authorization. Produce a new
candidate freeze; a waiver cannot authorize byte drift.

## Compatibility comparison

### Platform API 1.0

Compare the candidate contract with both the authenticated GA contract and the immediate
predecessor contract. Preserve `stableBaseline.name=1.0`, baseline contract version 19, stable
capability and endpoint membership, required-capability sets, action labels, and app-process and
app-browser access flags.

The current contract version is monotonic. The candidate carries a canonical structured
deprecation history whose semantic digest is checked against the rows. Existing identities and
their original start versions carry forward from the authenticated predecessor; a maintenance
release cannot drop or backdate a row, restart a clock, or shorten a removal window.
Stable removal, reclassification, access regression, or critical-removal waiver is a non-waivable
blocker. Compatible additions remain outside the frozen 1.0 membership unless a separately
governed future baseline includes them. Experimental additions stay explicitly experimental.

### Stable catalog and first-party apps

The seven Stable 1.0 first-party app ids remain present on the stable channel with their support
commitments intact. Compatible bug and security patch bundles are allowed only when the signed
catalog, exact bundle, manifest, trusted review receipt, signing and reviewer keys, Platform API
target, permissions, data schema, migration, backup/restore, service grants, and support metadata
all pass.

Reject app removal or id substitution, support or channel downgrade, unsigned or unreviewed bytes,
revoked or compromised keys, unexplained permission expansion, incompatible API dependencies,
missing migration/restore paths, stale catalog editions, untrusted mirrors, rollback conflicts,
and advisory or denylist regressions. An approved signing-key rotation must include the complete
trust transition. The comparison artifact lists every exact catalog and app delta.

App support commitments are ordered rather than fixed: a promotion to a stronger defined support
level is allowed, but a downgrade or unknown level is not. App versions use the same canonical
dotted-numeric comparison as `AppUpdateService`; versions cannot regress below either anchor, and
changed bundle bytes require a strictly newer version so installed nodes can select the update.

### Content-format profiles

The frozen v1 identities remain compatible:

```text
crypta.profile.v1
crypta.feed.snapshot.v1
crypta.trust.statement.v1
crypta.social.message.v1
crypta.social.outbox.v1
```

Parser, validator, diagnostics, and bounds fixes may ship only when existing valid documents remain
valid and the profile id, canonical signed bytes, signature payload, field meanings, required
fields, and compatible size semantics do not change in place. An incompatible format requires a
new separately versioned profile and explicit migration and deprecation policy.

### Security, support, limitations, and legacy boundaries

Catalog, app, and reviewer keys must remain uncompromised. Advisory and exact-version denylist
changes use the signed catalog lifecycle and cannot regress active containment. Known limitations
are rendered as an exact added/resolved/unchanged delta; a maintenance baseline cannot hide a new
Stable blocker or relabel a beta-only limitation. Catalog bytes, signatures, or signing-key identity
may remain at the predecessor edition and revision only when all three identities are unchanged;
otherwise at least one of edition or revision must advance.

The limitation delta is a partition of the predecessor's authenticated membership. For the GA v1
root, membership comes from `allowedLimitations[].id`; successor v2 baselines carry the canonical
sorted membership in `limitations.currentIds`. Candidate `addedIds`, `resolvedIds`, and
`unchangedIds` are sorted, unique, disjoint, and must account for every predecessor id. The current
digest covers the sorted current id set, while the delta digest also covers the predecessor set and
all three transition sets. Self-reported counts or review flags cannot replace these comparisons.

Support evidence stays metadata-only and uses `cryptad-operator-support-bundle` schema v2 or later.
Legacy admin remains maintenance-only, mutating retired routes remain disabled, the legacy plugin
runtime and new in-core plugin APIs remain absent, and FProxy browse, content filtering, and the
documented emergency fallback routes remain retained.

## Production evidence

Every scenario is bound to the exact release id, build, source commit, candidate freeze, product,
archive, catalog, predecessor product, and evidence digest. It records start/end time,
environment class, production classification, node and operation counts where relevant, and a
passing final status. Fixture, simulated-only, skipped, stale, dirty-workspace, test-signing, or
wrong-candidate evidence cannot satisfy publication.

Routine maintenance uses the normal policy windows and complete target matrix. Evidence covers:

- clean install and launch for every required OS/package target;
- direct GA upgrade when policy requires it and upgrade from the immediate predecessor;
- CoreUpdater discovery, package selection, download containment, and installer validation;
- daemon and app rollback, catalog refresh/rollback, app-data migration dry-run/apply, backup before
  migration, restore after failure, and operator recovery;
- Social Inbox, Trust Graph, Feed Reader, Profile Publisher, app-service grant, subscription, and
  durable state preservation;
- live-network behavior, Hyphanet interop, performance comparison, network-budget soak, sandbox,
  security drills, catalog operations, and redacted support output.

Every evidence row remains bound to the immediate predecessor used for the candidate. The
`stable-maintenance.direct-ga-upgrade` row additionally records the exact authenticated GA release
id, GA build, and GA product digest; those GA fields are null on every other row. This keeps a later
maintenance build's direct-GA scenario anchored to the immutable GA root without substituting GA
for the predecessor used by rollback and ordinary upgrade scenarios. Follow-up closure applies the
same two bindings.

The existing multi-node, live-network, network-scale, interop, performance, app-platform, and
security-response collectors remain evidence producers. Their summaries must be protected,
candidate-bound v2 envelopes or explicitly authenticated external evidence; a path or URL alone
does not authenticate a producer.

## Package matrix and the protected Windows EXE producer

The normal policy requires the maintained package matrix, including Linux DEB and RPM, macOS DMG,
Windows EXE, and the portable product distribution when declared. Each row binds filename,
OS/architecture/type, digest, size, build, source commit, signing or notarization status,
install/launch/upgrade evidence, data-retention behavior, and redaction.

The protected Linux-and-portable producer cryptographically signs every exact staged subject with
a GitHub/Sigstore artifact attestation: both Linux installers and all four portable archives. It
then verifies every subject against the exact maintenance workflow, repository, candidate commit,
and GitHub-hosted-runner policy before upload, emitting one public-safe verification receipt per
asset. The freeze job downloads the immutable producer artifact, independently repeats
`gh attestation verify`, and binds the exact per-asset receipt digest into the selected product or
package freeze row. A producer Boolean, checksum, artifact path, or generic build receipt cannot
satisfy `signingStatus=pass`. This keyless boundary requires only the workflow's narrowly scoped
`id-token: write`, `attestations: write`, and `artifact-metadata: write` permissions; it introduces
no package-signing private-key or passphrase variable, and no signing secret may enter a command,
log, receipt, or artifact. Attestation does not modify the staged subject, so the verified bytes
remain the single built-once candidate bytes.

Dispatch `.github/workflows/stable-1.0-maintenance-windows-package-producer.yml` at the exact
candidate commit to run `jpackageInstallerWindowsExeCryptad` once on a GitHub-hosted Windows
runner. The protected evidence environment supplies the reviewed Authenticode certificate and
timestamp service. Configure the certificate P12 and password as protected secrets and its exact
uppercase SHA-1 certificate identity in `CRYPTAD_WINDOWS_CODE_SIGNING_CERTIFICATE_SHA1`. The exact
protected names are `CRYPTAD_WINDOWS_CODE_SIGNING_P12_BASE64`,
`CRYPTAD_WINDOWS_CODE_SIGNING_P12_PASSWORD`, and
`CRYPTAD_WINDOWS_CODE_SIGNING_TIMESTAMP_URI`; the consumer independently binds the reviewed signer
identity through a public-safe SHA-256 projection. The producer verifies the release/hotfix ref,
integer build, pristine tracked checkout before and after the build, amd64 PE identity, exact
Authenticode signer, trusted timestamp, and source/toolchain identity, then attests both the final
EXE and its public-safe producer receipt.
Pass that run id, artifact name, artifact digest, and exact EXE SHA-256 to `freeze-candidate`; the
consumer independently verifies the workflow, source digest, hosted-runner provenance, bytes, and
receipt. A local Linux or macOS run cannot synthesize or replace this artifact. A security hotfix
always declares a nonempty `affectedPackageKeys` subset of the maintained matrix. Shipping the full
matrix uses `unaffectedPackageProofStatus=not-applicable`; narrowing the published matrix is allowed
only when its package keys exactly equal that affected set and
`unaffectedPackageProofStatus=pass` proves the omitted targets do not ship the vulnerable code. A
valid narrowed hotfix that excludes `amd64.dmg` does not attach the authenticated macOS
notarization receipt to another package: every selected non-DMG row records notarization as
`not-applicable`.

## CoreUpdater descriptor

The candidate generates deterministic `core-info.json` with:

- `version` equal to the canonical integer build string;
- a public HTTPS release page;
- optional protected, candidate-bound short and full changelog CHKs;
- a sorted `<arch>.<ext>` package map using `AppEnv` platform keys;
- an exact public CHK or store URL and exact size for every candidate package.

Reject non-integer or stale versions, duplicate keys, placeholders, private insert URIs, local
paths, omitted or substituted packages, misleading local SHA-256 fields, unsupported package keys,
and changelog references not bound to the candidate. Descriptor bytes are part of the freeze,
checksums, provenance, and authorization.

The publication plan names the update USK edition but never contains the private insert URI or
key. The protected workflow reads private insertion material only from environment or protected
file indirection. After insertion, an independent fetch verifies the public descriptor bytes and
every referenced package identity, then records `core-update-publication-receipt.json`.

## Authorization and decision

`prepare-authorization` emits a closed authorization identity containing the release, class,
candidate, GA baseline, predecessor, freeze, product, package, compatibility delta, recovery
evidence, catalog, `core-info.json`, limitation delta, notes, publication targets, and, for a
hotfix, incident and follow-up digests.

Authorization requires the policy-defined role, named approver, expiration, and exact closed
scopes. Wildcard scopes are forbidden. Routine maintenance normally requires `go`.
`go-with-waivers` is limited to policy-allowlisted noncritical operational warnings; it cannot
cover lineage, byte identity, API/profile compatibility, signing, catalog/app trust, updater,
upgrade/recovery, affected-platform install, sandbox/security, redaction, authorization, public
conflict, or receipt verification.

Every warning-bearing evidence row must have an exact frozen `operationalWarnings` entry with the
same warning id and evidence digest. The authorization request carries those ids in
`acceptedWarningIds` and requires `go-with-waivers`; a warning omitted from the frozen set, a
declared warning without a matching `warn` row, or a plain `go` decision is a blocker.

## Protected publication

Dispatch `.github/workflows/stable-1.0-maintenance-release.yml` only after protected evidence and
authorization are ready. The workflow separates:

1. `freeze-candidate`, which builds each selected asset once, Developer-ID-signs, notarizes, and
   staples the DMG, and emits the attested candidate-freeze record plus those exact bytes;
2. `prepare-authorization`, which consumes that frozen artifact and protected post-freeze evidence
   without building, replacing, or signing any candidate byte;
3. `validate-authorization`, which derives a validation manifest from the attested prepared
   manifest by changing only the command mode and adding the exact protected authorization;
4. `publish`, which consumes only the attested authorized bundle and an authenticated publication
   provider, after the appropriate routine-maintenance or security-hotfix environment approval;
5. current-time exact-byte, remote source-ref, predecessor, authorization, key, and conflict
   revalidation before each mutation;
6. annotated tag, GitHub Release/assets, artifact base, stable catalog, and update-descriptor
   publication;
7. independent public-state verification;
8. publication receipt, successor baseline, history entry, and latest-pointer activation.

The four operations are separate protected workflow runs. The prepare run accepts only the exact
`freeze-candidate` run, artifact name, and artifact digest. The authorization-validation run accepts
only the exact prepared artifact and an approval artifact containing one authorization JSON file.
The publish run accepts only the exact authorized artifact; separately supplied candidate,
evidence, package, manifest, or authorization inputs are rejected. This ordering ensures that
post-freeze evidence can describe the bytes actually produced without requiring a speculative
earlier build or rebuilding native installers after authorization.

Use this handoff sequence; every artifact coordinate means the producing run id, exact artifact
name, and `sha256:<hex>` Actions artifact digest:

| Consumer operation | Authenticated inputs | Output for the next phase |
| --- | --- | --- |
| `freeze-candidate` | `freeze-candidate` phase bundle, including the exact five-artifact lifecycle authority chain for the standard post-GA path, plus the Windows producer artifact and EXE SHA-256 | Attested frozen-candidate artifact containing the one built asset set and retained protected lifecycle inputs. |
| `prepare-authorization` | `prepare-authorization` phase bundle with the same exact lifecycle authority chain plus the exact frozen-candidate artifact | Attested prepared-candidate artifact; its candidate asset directory is reconstructed only from the prior freeze, and authenticated-input audit copies retain the lifecycle authority chain. |
| `validate-authorization` | Approval-only `validate-authorization` phase bundle plus the exact prepared-candidate artifact | Attested authorized-candidate artifact. The workflow restores the prepared manifest and protected lifecycle inputs, changes only the command mode, and adds the exact authorization. |
| `publish` | Exact authorized-candidate artifact plus the authenticated publication-backend wheel | Publication audit, independent verification, and activation artifacts retain authenticated-input audit copies; no replacement phase bundle is accepted. |

Use the protected environments `stable-1.0-maintenance-evidence`,
`stable-1.0-maintenance-publication`, and `stable-1.0-security-hotfix-publication` with
least-privilege job permissions. The workflow validates branch/ref/commit identity but never
creates or merges `release/*` or `hotfix/*` branches. Release managers retain the no-squash,
`--no-ff` merge into `main` and back-merge into `develop`.

Configure the evidence environment with exact GitHub signer-workflow identities in
`CRYPTAD_STABLE_MAINTENANCE_INPUT_SIGNER_WORKFLOW` and
`CRYPTAD_STABLE_MAINTENANCE_WINDOWS_SIGNER_WORKFLOW`. The consumer verifies the selected run's
workflow path, dispatch event, repository, source commit, artifact digest, SLSA provenance signer,
source digest, and hosted-runner identity. The same environment must supply the public-key-only
`STABLE_CATALOG_TRUSTED_KEYS_BASE64` secret. Its decoded value is the production trusted catalog
key registry in `TrustedAppKeys` properties format; it must never contain a private key. The freeze
job builds the checked-out `crypta-app` verifier, rechecks that the build did not change tracked
source, and verifies the exact catalog and detached-signature bytes under the candidate's declared
`signingKeyId`. The temporary registry is mode `0600`, is deleted before job exit, and neither its
key bytes nor raw signature content is serialized into a candidate JSON record. The detached
signature file itself remains a separately frozen and published exact-byte asset. The freeze
records the registry's SHA-256 beside the signer ID so a same-ID trust-material change is auditable
without publishing any public-key material.

The macOS freeze job also requires the reviewed
`CRYPTAD_MACOS_DEVELOPER_ID_APPLICATION` identity; the protected
`CRYPTAD_MACOS_DEVELOPER_ID_APPLICATION_P12_BASE64` and
`CRYPTAD_MACOS_DEVELOPER_ID_APPLICATION_P12_PASSWORD` secrets; and the protected
`CRYPTAD_MACOS_NOTARY_APPLE_ID`, `CRYPTAD_MACOS_NOTARY_APP_PASSWORD`, and
`CRYPTAD_MACOS_NOTARY_TEAM_ID` secrets. The protected Gradle property signs and strictly verifies
the final enriched `Crypta.app` after `cryptad-dist` and the launcher configuration are installed.
It replaces jpackage signatures in explicit inside-out order with
`codesign --options runtime --timestamp`, preserves the JVM/framework identifier and entitlement
metadata, and signs the app root last.
Missing pre-existing jpackage metadata or any recursive signing attempt is a blocker. Jpackage then
uses that predefined image to create the DMG.
Installer-stage mac signing remains enabled, but the workflow does not treat it as proof that the
outer DMG container is signed. It Developer-ID-signs and verifies the exact DMG after jpackage and
before submitting those bytes to Apple, then staples and verifies the resulting DMG again before
computing the frozen digest. JDK 25's invalid `--type app-image --app-image` combination is never
used. Missing app signing, DMG signing, notarization, stapling, or Gatekeeper verification stops
the freeze.

Set the two signer variables to the full checked-in workflow identities
`crypta-network/cryptad/.github/workflows/stable-1.0-maintenance-input-producer.yml` and
`crypta-network/cryptad/.github/workflows/stable-1.0-maintenance-windows-package-producer.yml`.
The input producer
retrieves one reviewed public-safe ZIP from the evidence environment's protected secret HTTPS
locator `CRYPTAD_STABLE_MAINTENANCE_INPUT_BUNDLE_URL`, optionally using
`CRYPTAD_STABLE_MAINTENANCE_INPUT_BUNDLE_BEARER_TOKEN`, and requires an independently supplied
exact bundle SHA-256. It forbids redirects, proxies, private-address targets, unsafe archive
members, and every file outside the manifest's referenced phase inputs, including root-level and
sibling files that would otherwise survive artifact upload. It also forbids secrets, placeholders,
runner paths, wrong release/build/class/source identity, and phase-incompatible material. For
retrieval, it resolves the locator once, rejects the complete result if any address is non-global,
connects only to those validated numeric socket addresses, verifies the connected peer address, and
retains the original hostname for TLS SNI and certificate verification. The bearer credential is
therefore never transmitted through an unvalidated second DNS lookup. Before phase-specific
acceptance and attestation, every JSON file must already use the publication boundary's exact
canonical UTF-8 bytes: unescaped Unicode, two-space indentation, sorted object keys, and one final
newline, with duplicate keys forbidden. `freeze-candidate` and
`prepare-authorization` bundles contain
`stable-1.0-maintenance.json` plus `protected-inputs/`; a `validate-authorization` bundle contains
only `stable-1.0-maintenance-authorization.json`. The manifest's sole checkout-relative input is
the exact authoritative
`tools/release-certification/stable-1.0-maintenance-policy.json`; the producer resolves it from the
authenticated, pristine candidate checkout and the engine reauthenticates its exact bytes. Every
other file or directory input remains confined beneath `build/protected-inputs/`. The locator and
credential are never uploaded or serialized. Environment approval, exact bundle and artifact
digests, and the same-commit workflow attestation authenticate the producer; a URL alone does not.
For a post-GA predecessor, the producer requires the lifecycle ledger, descriptor, approved
authorization, authorized publication plan, and verified receipt keys and files as one complete
authority chain. It verifies all five files against the canonical lifecycle workflow and the exact
reviewed lifecycle source commit before re-attesting the phase manifest. The maintenance workflow
stages exact audit copies, retains the protected inputs when it derives authorization validation
from the prepared artifact, and carries them unchanged into the authorized and publication
artifacts.

Publication dispatches identify an exact protected provider artifact by run id, artifact name, and
artifact digest. The canonical provider wheel is produced only by
`.github/workflows/stable-1.0-maintenance-publication-backend-producer.yml` from the current reviewed
`main` commit. Its fixed artifact is `stable-1.0-maintenance-publication-backend` and its fixed
entrypoint is `cryptad_stable_maintenance_backend:factory`; see
`tools/release-certification/publication-backend/README.md` for the closed deployment-service and
capability protocol. Configure the reviewed source commit, wheel digest, signer workflow, and entry
point as repository-level Actions variables:
`CRYPTAD_STABLE_MAINTENANCE_PUBLICATION_BACKEND_SOURCE_COMMIT`,
`CRYPTAD_STABLE_MAINTENANCE_PUBLICATION_BACKEND_WHEEL_SHA256`,
`CRYPTAD_STABLE_MAINTENANCE_PUBLICATION_BACKEND_SIGNER_WORKFLOW`, and
`CRYPTAD_STABLE_MAINTENANCE_PUBLICATION_BACKEND`. These four immutable, public-safe identity pins
must be visible to the evidence-scoped independent-verification job as well as both publication
environments; do not configure them only on a publication environment. If organization policy
requires environment-scoped variables, configure the exact same four values on
`stable-1.0-maintenance-evidence`, `stable-1.0-maintenance-publication`, and
`stable-1.0-security-hotfix-publication`. Every clean hosted job authenticates the producer run and
attestation, installs that one wheel without dependency resolution, and loads the provider only
from the authenticated installation directory. Publication environments expose the purpose-bound
`CRYPTAD_STABLE_CATALOG_PUBLICATION_INPUT` only to catalog publication, the purpose-bound
`CRYPTAD_CORE_UPDATE_PUBLICATION_INPUT` only to CoreUpdater insertion, and the distinct
`CRYPTAD_STABLE_MAINTENANCE_STATE_INPUT` only to latest-baseline compare-and-swap activation. A
missing signer identity, provider, or target-specific protected input fails before mutation. The
adapter materializes these opaque values before provider construction, removes their names from
both its environment snapshot and ambient process environment, and passes only the intended value
to the corresponding target method; imports, observations, and unrelated targets see none of them.

The provider's `deploymentServicePublicUri` follows the same canonical public-HTTPS contract as
authorization: an authority root may appear with or without its trailing slash, and a non-root
endpoint may end in one slash, but internal empty segments, dot segments, credentials, fragments,
ambiguous whitespace, redirects, and non-global addresses are rejected. Independent
`verify-publication` calls are self-contained. They send a closed `verificationInputs` map with
the authenticated plan, candidate and candidate input, lineage, CoreUpdater plan and descriptor,
GA and predecessor baselines, evidence summary, provenance, and nullable follow-up records. Each
entry binds the canonical physical JSON digest to the parsed record. The deployment service does
not rely on undocumented out-of-band candidate state, and the adapter independently validates
every returned receipt, successor baseline, and history entry.

Configure `LEUMOR_GITHUB_TOKEN` as a secret in both Stable maintenance publication environments.
The protected job verifies `/user` resolves to exactly `leumor` before it gives that credential to
the publication adapter for tag, GitHub Release, and release-asset operations. The job-scoped
Actions token has read-only repository permission and remains limited to workflow-artifact and
attestation authentication; it is not a fallback publication identity.

Before each mutation, revalidate that the immutable ref did not move, the latest predecessor did
not change, no conflicting publication is active, authorization is current, candidate and public
artifact-base bytes match, tag/Release/catalog/update targets are conflict-free, and signing keys
remain uncompromised.
The canonical provider is verify-only for the artifact base. An independent protected deployment
must pre-stage every planned artifact-base object at its authorized URI before publication
preflight. An entirely absent, partially populated, or byte-mismatched artifact base is a hard stop;
the provider never creates or repairs those objects. Exact pre-staging followed by an absent public
suffix is the first safe resumable-prefix state, so publication begins with the annotated tag.
Before authorization, conflict checking expands every concrete artifact-base child plus the
catalog primary, detached-signature sibling, mirrors, rollback object, GitHub Release page, and
CoreUpdater descriptor. Canonical URI aliases across any two roles are a blocker.

Activation rereads the exact published authorization and checks its physical digest, role, closed
scope, and decision. It separately rereads the short-lived activation-only authorization created
after the protected environment gate and checks that grant's exact input digests, scope, and expiry
immediately before compare-and-swap, then verifies the remote release or hotfix ref again. The
activation step always uploads its authorization plus its receipt or a truthful workflow audit even
when post-mutation observation fails, then fails the job after retaining that state.

## Idempotency, conflicts, and recovery

Existing public state is idempotent success only when every authenticated byte and identity
matches: annotated tag object and target, Release notes and assets, artifact base, stable catalog
primary/mirrors/rollback, update USK edition, fetched `core-info.json`, and package mappings.

Fail closed and record observed partial state when a tag points elsewhere, a tag is lightweight,
an asset or note differs, an unexpected asset exists, a catalog is stale or untrusted, the update
edition conflicts, or a public observation is unavailable. An interrupted publication is resumable
only when public observation proves an exact matching prefix in the canonical target order and an
entirely absent suffix. Every remaining target receives the same byte, authorization, predecessor,
source-ref, and conflict revalidation before mutation. A non-prefix partial state remains a
conflict. Do not delete, overwrite, repair, or claim absence for conflicting state.

## Security-hotfix policy and follow-up

An expedited path is available only for `releaseClass=security-hotfix`, a critical public-safe
incident/advisory identity, a correctly based `hotfix/<build>` branch, the exact authenticated
`policies.candidateBaseCommit` from the currently published `main` state, declared affected surface
and platforms, explicit Stable security release-manager authorization, and a source-scope audit
that rejects unrelated feature work. The candidate declares the closed
`changeScope.shortenedEvidenceIds` set; the authorization binds that exact set and its dedicated
hotfix-policy authorization digest.

Lifecycle predecessor eligibility is release-class-specific. Routine `maintenance` still requires
the exact authenticated `current-stable` predecessor. A `security-hotfix` may recover from a
policy-eligible `security-fixes-only`, `deprecated`, or `revoked` predecessor only when its exact
incident and protected hotfix-policy authorization are bound. For a revoked tip with no safe
current build, the append-only lifecycle transition must additionally preserve that incident,
affected build, public security evidence, publication-target digest, authorization-request digest,
advisory, and reason. This emergency path never makes the same predecessor routine-maintenance
eligible and never admits an end-of-support predecessor.

The hotfix policy may shorten only its closed prepublication evidence durations or an explicitly
proved unaffected target matrix. It cannot skip candidate identity, archive and signing integrity,
redaction, API/content compatibility, updater integrity, affected-platform packaging/install,
upgrade, rollback, migration, backup/restore, sandbox/security, conflict, authorization, or receipt
verification. Evidence remains protected production evidence, not fixtures or simulations.

When the shortened policy is used, the command generates
`stable-1.0-hotfix-follow-up-obligation.json`. It records the incident, published build/product,
shortened scenarios, full evidence still required, deadline, owner/approver, closure criteria, and
escalation behavior. The successor baseline and dashboard show the obligation as open.

After the full window completes, run `close-hotfix-follow-up` with the latest activated successor
baseline, its publication receipt and latest-published pointer, the original authorization and
obligation, and exact full evidence for the originally obligated hotfix. The obligation binds the
original release id, build, product, candidate identity, freeze, and freeze time. If a later hotfix
carried the obligation forward, do not relabel the evidence or substitute the later hotfix's
authorization. The latest baseline, receipt, and pointer prove where the obligation is currently
carried; the original identities prove which published bytes completed the full window. The
side-effect-free command emits the versioned
`stable-1.0-hotfix-follow-up-closure.json` overlay; it does not rewrite the published hotfix,
successor baseline, receipt, or pointer. A later candidate must authenticate the overlay against
the original obligated candidate identity and product, latest carried successor-baseline digest,
latest publication-receipt digest and receipt identity, latest-pointer digest, obligation digest,
and exact original authorization digest. Its lineage records the exact closure digest that cleared
the obligation. An overdue or failed
obligation becomes a release incident and blocks the next routine maintenance publication. A
separately authorized superseding security hotfix may carry the obligation forward only when the
policy permits it.

## Public and private data boundaries

Manifests and public artifacts may contain public URLs, ids, counts, timestamps, status values,
digests, key ids, package names, and redacted summaries. They must not contain:

- private update or catalog insert URIs, private keys, seed material, or signing files;
- tokens, cookies, credentials, passwords, authorization headers, or CI secret values;
- raw content, fetched documents, app-data values, backups, support bundles, signatures paired
  with raw bodies, identity material, or incident artifacts;
- command lines containing secrets, absolute Unix/macOS/Windows/UNC paths, runner workspaces,
  staging paths, rollback paths, or local package paths.

Inputs with duplicate JSON keys, unsafe strings, symlinks, workspace escapes, untrusted archive
members, or placeholders fail before comparison. Public release notes describe validation and
availability only after the independently verified receipt proves publication. Checked-in docs,
templates, fixtures, and self-tests never claim that a maintenance build or hotfix was published.

## Local verification

Run the focused offline suite after changing the maintenance policy, schemas, engine, workflows,
provider, packaging logic, or this contract:

```bash
python3 tools/release-certification/certify.py stable-maintenance --self-test
python3 tools/release-certification/certify.py stable-ga --self-test
python3 tools/release-certification/certify.py stable-rc --self-test
./gradlew verifyMacAppImageSigningArguments verifyWindowsExeInstallerArguments
```

When portable archive construction changes, also build the affected `distZipCryptad`,
`distTarCryptad`, and `distJlinkCryptad` outputs and run the maintenance self-test so the Python
hygiene gate checks the Java-normalized bytes. These commands are validation only. Developer ID,
Authenticode, notarization, multi-OS installer production, public artifact staging, catalog or USK
insertion, and latest-pointer activation remain protected operations and must not be claimed from a
local run.

## Branch and merge completion

Publication does not merge branches. After the release manager verifies the receipt:

- merge `release/<build>` or `hotfix/<build>` into `main` with `--no-ff` and no squash;
- back-merge the same branch into `develop` with `--no-ff` and no squash;
- verify `main` contains the shipped commit and the annotated `v<build>` tag and publication
  receipt identify that exact commit. The `main` tip is normally the later `--no-ff` merge commit.

See [the standard Git workflow](standard-git-branching-and-release-workflow.md) for branch
operations and [the release runbook](cryptad-release-workflow-and-runbook.md) for the wider release
gate checklist.

## Support lifecycle activation

A verified maintenance publication is a prerequisite for lifecycle activation, not a substitute
for it. `stable-maintenance` prepares a deterministic lifecycle transition set, but the candidate
cannot become `current-stable` until its publication receipt and successor baseline authenticate
the new chain tip and the separately protected `support-lifecycle` descriptor publication verifies
the exact authorized bytes. The previous current build normally becomes
`supported-maintenance` in that same transition set.

The lifecycle policy and runtime parser both cap the complete schema-v1 release projection at 256
entries. Maintenance certification computes the proposed successor inventory from the
authenticated chain depth and blocks publication before a candidate would become entry 257. It
does not truncate history or invent an unreviewed rollover.

Routine maintenance must not treat an `end-of-support` or `revoked` predecessor as ordinarily
supported. A security hotfix from a `security-fixes-only` or revoked predecessor requires the
exact advisory/incident scope and lifecycle security authorization. Support, security, and
deprecation clocks carry forward; publishing another maintenance baseline does not reset them.

See [Stable 1.0 support lifecycle and deprecation governance](stable-1.0-support-lifecycle-and-deprecation-governance.md)
for the authenticated inventory, append-only ledger, mutable descriptor, protected publication,
operator behavior, and Platform API/app/profile governance rules.
