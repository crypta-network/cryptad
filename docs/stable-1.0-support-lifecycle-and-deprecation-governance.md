# Stable 1.0 support lifecycle and deprecation governance

Use this guide to evaluate, authorize, publish, verify, and consume the support state of already
published Stable 1.0 integer builds. The lifecycle process authenticates the immutable Stable 1.0
GA root and every published maintenance or security-hotfix successor before it assigns support
state. It does not build or publish a release, replace the Stable maintenance workflow, or change a
historical `core-info.json`.

Stable 1.0 remains a product and Platform API milestone. Cryptad releases continue to use one
integer build number and a `v<build-number>` tag.

## Lifecycle vocabulary

Every authenticated published Stable 1.0 build has exactly one status from this closed set:

| Status | Meaning | Local operator guidance |
| --- | --- | --- |
| `current-stable` | The one authenticated maintenance-chain tip selected by the latest published pointer. It receives routine compatible maintenance and security support. An emergency descriptor may have no current build only when that tip is explicitly revoked. | Normal healthy state. |
| `supported-maintenance` | A superseded build that remains inside the full-maintenance window. | Recommend the current build without claiming that the running build is unsupported. |
| `security-fixes-only` | A build outside full maintenance but still inside its security-fix window. | Show a high-visibility warning and prioritize security updates. Routine feature or compatibility work cannot target this build as a fully supported predecessor. |
| `deprecated` | A deprecation notice is effective and an authenticated upgrade or recovery path is known. | Keep persistent upgrade guidance visible. |
| `end-of-support` | No ordinary maintenance or security-fix commitment remains. | Mark diagnostics and support bundles unsupported and direct the operator to the current or required replacement build. |
| `revoked` | A protected security decision identifies the build as unsafe. | Show a critical security warning and only authenticated replacement or recovery guidance. |

Normal transitions are monotonic:

```text
current-stable
  -> supported-maintenance
  -> security-fixes-only
  -> deprecated
  -> end-of-support
```

Any non-revoked state can move to `revoked` only through the explicit security transition. A
revoked build is terminal under the ordinary policy. A routine transition cannot clear or hide the
revocation event.

The normal cardinality remains exactly one `current-stable` chain tip. The sole emergency exception
is an explicitly authorized revocation of that tip before a safe successor exists. That descriptor
has no `current-stable` entry and a null current-build field; it may recommend an authenticated
non-revoked published replacement, or preserve bounded recovery guidance with no invented build.
This exception cannot be used for a normal transition, an expired authorization, or an unverified
advisory.

Publishing a successor does not make it current merely because it has a larger user-supplied
number. The successor must have a complete authenticated publication receipt and activated
successor baseline. The same lifecycle transition set then makes that chain tip `current-stable`
and normally moves the previous current build to `supported-maintenance`.

## Versioned support-window policy

The reviewable policy is
`tools/release-certification/stable-1.0-support-lifecycle-policy.json`. Its closed schema defines:

- the status vocabulary and transition matrix;
- the duration unit and minimum full-maintenance, security-fix-only, and deprecation-notice
  windows;
- the minimum supported-build cardinality;
- the complete inventory/ledger/descriptor entry capacity of 256 published builds, matching the
  runtime parser's fail-closed bound;
- lifecycle descriptor and evidence freshness limits;
- normal and security authorization roles and exact scopes;
- revocation advisory, reason, replacement, recovery, and drill requirements;
- the closed emergency no-current state permitted only for an explicitly revoked chain tip;
- Platform API 1.0 deprecation and removal constraints;
- references to the existing first-party app, signed catalog, advisory, reviewer-revocation, and
  content-profile governance sources;
- non-waivable blockers and public-artifact redaction requirements.

Production durations live only in that policy. Python computes canonical UTC deadlines from the
authenticated publication time with deterministic whole-day arithmetic. Java receives explicit
timestamps in the authenticated descriptor; it does not hardcode product-policy durations.

The clocks have distinct meanings:

- `fullSupportUntil` ends the full-maintenance commitment;
- `securityFixesUntil` ends the security-fix commitment;
- `deprecationEffectiveAt` starts the published deprecation notice;
- `endOfSupportAt` starts the unsupported state;
- `securityRevocationEffectiveAt` exists only for an explicit security revocation.

A deadline cannot predate publication. The security-fix deadline cannot precede full support, and
end of support cannot bypass the policy's minimum deprecation notice.

## Authenticated release inventory

The lifecycle engine derives the release inventory from public release history, never from labels
in a transition request. It verifies this chain in order:

```text
Stable 1.0 GA publication receipt and immutable GA maintenance baseline
  -> zero or more maintenance/security-hotfix publication receipts
  -> matching successor baselines and maintenance history entries
  -> latest published maintenance pointer
```

Inventory, ledger, and descriptor schema v1 retain the complete authenticated release set and
allow at most 256 entries. They are never truncated or rolled over implicitly. Stable maintenance
certification blocks a candidate before its verified publication would create entry 257; a future
capacity change therefore requires an explicitly versioned policy, schema, runtime, and migration
design rather than a publication-time compatibility failure.

Each link binds the release id, integer build, `v<build>` tag, source commit, product digest,
publication-receipt digest, baseline digest, chain depth, previous-baseline digest, lineage digest,
and publication time. Integer builds must increase, every receipt must report complete exact-byte
publication, and the latest pointer must identify the only chain tip. Missing links, substituted
digests, alternate tips, forks, unpublished candidates, partial publications, and stale pointers
are blockers.

An unresolved security-hotfix follow-up obligation remains attached to the authenticated inventory.
The lifecycle policy determines which later normal transitions it blocks; no lifecycle descriptor
can erase or relabel the obligation.

## Append-only lifecycle ledger

`stable-lifecycle` computes lifecycle state only after it writes the authenticated release
inventory. Every transition records the old and new status, effective time, policy rule, reason,
target and replacement builds, advisory or incident id when required, an authorization-request
digest, the protected approval digest once authorization is granted, and the previous/resulting
ledger identities. A prepared but not yet approved transition therefore retains its exact
authorization request while its approval digest remains null.

Ledger entries form an append-only SHA-256 chain through `previousEntryDigest` and `entryDigest`.
A later descriptor can project the current status of each build, but it must retain the exact
ledger digest and previous descriptor identity. Removing an old transition, moving a build
backward, omitting a published build, or reversing a revocation changes the authenticated chain and
fails validation.

Descriptor edition 1 is a one-time bootstrap against the complete authenticated release inventory,
which may contain the GA alone or zero or more published maintenance/hotfix successors. Omitting
the prior ledger/descriptor pair requires a fresh, protected provider proof that the exact public
target returned HTTP `404`. The proof binds the inventory digest, GA root, chain tip, URI, and
update-key scope. HTTP `410` means deleted or tombstoned state and cannot authorize re-genesis.
After edition 1, the exact prior ledger and descriptor are mandatory. An identical published
edition may be verified idempotently, but different bytes cannot replace it.

Normally exactly one build must be `current-stable`, and it must be the authenticated
maintenance-chain tip. Zero current builds is valid only for the policy-declared emergency in which
that exact tip carries a protected terminal revocation. More than one current build always fails.
The ledger cannot use a mutable descriptor to change a build's release id, build, tag, source
commit, product digest, publication receipt, or baseline digest.

## Certification command and artifacts

Copy and complete the non-secret example manifest, then run the side-effect-free command:

```bash
cp tools/release-certification/manifests/stable-1.0-support-lifecycle.example.json \
  build/stable-1.0-support-lifecycle.json
python3 tools/release-certification/certify.py stable-lifecycle \
  --manifest build/stable-1.0-support-lifecycle.json
```

The component workspace is:

```text
build/release-certification/<release-id>/stable-lifecycle/
```

`commands.stable-lifecycle.mode` is closed to:

| Mode | Purpose | Side effects |
| --- | --- | --- |
| `evaluate` | Authenticate history and evaluate the current policy-derived state. | None. |
| `prepare-transition` | Produce a deterministic proposed transition, descriptor, plan, and expected authorization identity. | None. |
| `validate-authorization` | Validate one exact, scoped, unexpired protected authorization against the proposed bytes. | None. |
| `verify-publication` | Compare a supplied public receipt and fetched descriptor identity with the authorized plan. | None. |

The public-safe artifact family includes the inventory, ledger, transition set, summary, report,
descriptor, publication plan or receipt when applicable, Platform API deprecation timeline,
catalog/app/profile governance projection, checksums, provenance, and redaction report. JSON output
uses closed schemas and deterministic key/order rules. Self-tests and ordinary validation do not
publish, update a USK edition, create a tag or GitHub Release, or change catalog state.

## Mutable authenticated descriptor

Historical `core-info.json` files describe immutable published packages. Support status changes
with time, so lifecycle state is published separately at the `support-lifecycle` docname under the
same configured public update-key USK that CoreUpdater already trusts.

The descriptor has its own schema version and monotonic edition. It binds:

- Stable milestone `1.0`;
- `updateKeyDocName=support-lifecycle`, the normalized public `updateKeyScope`, and an
  `updateKeyIdentityDigest` rather than private insert material;
- the ledger digest and exact authenticated release identities;
- the current build, recommended build, and policy-defined minimum supported builds; current and
  recommended are explicitly null for a recovery-only revoked-tip emergency;
- generated, effective, and policy-derived `staleAt` UTC timestamps;
- the previous descriptor edition and digest;
- the redaction result.

`descriptorDigest` is the semantic digest over the descriptor with that self-identifying field
omitted. The publication plan and receipt additionally bind `descriptorBytesDigest`, the SHA-256
of the exact canonical descriptor bytes. This separates content identity from the exact-byte
publication proof without allowing either to float.

CoreUpdater rejects an unknown schema or status, wrong key scope or docname, key-identity mismatch,
edition rollback or replay, previous-digest mismatch, forked descriptor history, inconsistent
current-build cardinality, a no-current state whose chain tip is not revoked, unsafe replacement
guidance, and any attempt to change an authenticated running-build identity. A failed fetch or
parse does not replace the last-known-good descriptor.

Release certification does not infer the current public edition from an older valid receipt. The
versioned policy sets `supportWindows.maximumPublicObservationAgeMinutes` to 30 minutes. Protected
maintenance authorization re-fetches the exact descriptor bytes through the lifecycle-only
provider while holding the shared lifecycle/maintenance publication lock, attests that read-only
observation, and verifies its provenance before allowing `promotionReady=true`. The publication
boundary performs a second exact re-fetch before maintenance preflight. A future-dated or expired
observation, a newer public edition, or any semantic digest, byte digest, key identity, scope,
docname, plan, authorization, or ledger mismatch fails closed. Tests use injected fake providers;
they do not contact public infrastructure.

Disabling package updates does not stop this read-only lifecycle subscriber: support and security
status must continue to advance even when an operator has opted out of package downloads. An
authenticated update-key compromise still stops the subscriber because documents below the
compromised key can no longer establish lifecycle authority.

This is build lifecycle authentication, not update-signing-key revocation. `RevocationChecker`
continues to own update-key compromise. Marking a build deprecated, unsupported, or revoked never
blows the update key.

## Protected publication

`.github/workflows/stable-1.0-support-lifecycle.yml` separates evaluation, transition preparation,
authorization validation, publication, and independent verification. Only the explicit `publish`
operation enters the protected lifecycle publication environment. It consumes the exact attested
authorized artifact and receives the private support-lifecycle insert capability through a
purpose-specific protected environment value.

Start each side-effect-free phase with
`.github/workflows/stable-1.0-support-lifecycle-input-producer.yml`. The producer accepts one
reviewed ZIP by exact SHA-256, fetches it from a protected HTTPS locator with pinned public address
resolution, rejects redirects and unsafe archives, and emits only this closed layout:

```text
manifest/stable-lifecycle-manifest.json
protected-inputs/<exact manifest-referenced public-safe inputs>
```

The producer requires the exact production-safe execution profile. It attests the manifest and
every protected input at the selected source commit. It has no `publish` operation and never
receives the lifecycle insert capability. Configure
`CRYPTAD_STABLE_LIFECYCLE_INPUT_SIGNER_WORKFLOW` to the canonical producer path; the consumer
rejects an alias or arbitrary signer workflow.

`validate-authorization` consumes the producer's exact approval artifact. It restores the
attested input tree, reruns `stable-lifecycle` in `validate-authorization` mode, and regenerates the
descriptor, transition set, authorization summary, and publication plan. The workflow attests
those generated bytes. It does not accept a caller-assembled component as a substitute for this
rerun.

The publication boundary:

1. restores the original producer-attested input tree and reauthenticates the exact GA root,
   complete maintenance history, and authorization immediately before any mutation;
2. checks the exact descriptor bytes, edition, previous edition/digest, authorization digest, and
   public target;
3. performs a live read of the authorization-bound maintenance latest-pointer URI immediately
   before lifecycle insertion. GA-only maintenance history requires a missing public maintenance
   pointer; post-GA history requires the exact pointer digest, release id, build, baseline, and publication
   receipt from the authenticated inventory;
4. shares the `stable-1-0-maintenance-publication` concurrency lock with maintenance activation so
   the pointer cannot advance between that read and lifecycle insertion in the protected GitHub
   workflow;
5. accepts an existing lifecycle edition only when its bytes and digest match exactly;
6. treats an unavailable maintenance pointer, a new first-maintenance pointer, a different digest
   at either public target, or an unexpected newer state as a conflict rather than an overwrite
   opportunity;
7. fetches public lifecycle state again and writes a receipt only after exact-byte verification;
8. emits a redacted truthful failure audit when the mutation boundary may have been crossed.

The authorized certification component remains byte-for-byte unchanged after publication,
including its original checksums and non-publication placeholder receipt. The protected job stores
the actual publication receipt, preflight, and operation summary beside that component in the
complete published bundle. A later `verify-publication` run verifies the attested publication
receipt, independently re-fetches the descriptor without insert material, and writes a separate
independent-verification receipt. The original receipt's authenticated `generatedAt` must fall
within the exact authorization interval (`generatedAt` inclusive, `expiresAt` exclusive), but the
read-only verification may run after that authorization expires. Mutation and authorization
validation still require a currently valid approval. It does not overwrite the component or either
prior receipt.

The workflow does not create tags, GitHub Releases, maintenance candidates, catalog entries, or
`core-info.json`. It cannot run publication from a pull request or a self-test. A release manager
must configure the protected backend identity, approval environment, and purpose-specific private
insert capability before a real publication.

## Runtime and operator behavior

CoreUpdater persists only public-safe last-known-good lifecycle metadata. The detached runtime SPI
exposes `CoreSupportLifecycleSnapshot` through `CoreUpdateActionPort` rather than allowing Platform
API or Web Shell to reach updater internals. `GET /api/v1/updates/support-lifecycle` returns the
redacted snapshot. `GET /api/v1/updates/core` also includes it under `supportLifecycle` so Web Shell
can render one coherent updater panel. The operator beta/RC dashboard and support bundle include
the same local projection under `coreSupportLifecycle`.

The snapshot distinguishes `known=false` from a verified but stale descriptor. It reports the
running build and status, status/support deadlines, nullable current and recommended builds,
authenticated replacement or bounded recovery guidance, advisory and reason ids, descriptor
edition/digest, last verification time, upgrade availability, and bounded warnings. It does not
expose raw descriptor bytes, update URIs, insert material, tokens, keys, paths, peer identities, raw
advisories, or node/app data.

Web Shell renders current, supported, security-only, deprecated, end-of-support, revoked, stale,
and unknown states distinctly. It offers a package-download action only when the existing updater
reports that it can honor that action. Acceptance of a download request is not presented as a
completed update.

Lifecycle state does not silently shut down the node, delete user-owned data, uninstall apps,
disable FProxy browse or content filtering, restore the legacy plugin runtime, or force an update.
An unsupported or revoked node retains non-destructive local operation and shows actionable local
guidance. Any narrow restriction on a security-sensitive ecosystem operation must be explicitly
defined by the versioned policy and removed by a verified upgrade.

## Platform API 1.0 deprecation clocks

The lifecycle report reuses the frozen Platform API 1.0 baseline, current and previous contract
snapshots, `PlatformApiDeprecation`, and stable third-party samples. It proves that:

- `deprecatedSinceContractVersion` and the original effective time do not move later in a
  maintenance baseline;
- scheduled-removal metadata cannot be removed or delayed merely to restart the notice clock;
- a Stable 1.0 baseline endpoint or capability is not removed while any supported published build
  or required stable third-party sample depends on it;
- experimental-to-stable graduation remains explicit and cannot hide a breaking replacement;
- lifecycle transitions do not rewrite published contract history;
- a critical stable removal cannot use a waiver when the compatibility policy prohibits one.

`stable-maintenance` consumes this governance result. Routine maintenance and security hotfix
validation both fail on clock reset, premature stable removal, or an unauthenticated compatibility
claim.

## App, catalog, advisory, and profile governance

The lifecycle governance projection summarizes existing authenticated sources. It does not replace
their trust models:

- signed catalog channel, support, deprecation, replacement, advisory, and exact-version denylist
  metadata;
- the first-party app maintenance policy and stable app identities;
- trusted app-review receipts and local receipt/reviewer revocation records;
- versioned content-format profile status, replacement, canonicalization, signing, and migration
  metadata;
- authenticated security-hotfix follow-up obligations.

The projection fails when a stable first-party app disappears, changes id, loses its support
commitment, or loses required backup/migration guidance. It also fails when a content profile is
deprecated without a separately versioned replacement and migration policy, or when an active
advisory/denylist/revocation is hidden. Existing catalog signatures and review trust remain the
authorities for app decisions.

The report does not claim compatibility with the retired in-process plugin system or with old WoT,
Freetalk, Sone, or Freemail protocols.

## Security revocation

A build revocation requires a protected transition containing a public advisory or incident id,
severity and reason code, affected builds, effective time, authenticated safe replacement build or
recovery guidance, authorization digest, security-drill reference, and exact publication target
and descriptor digest.

An advisory does not revoke a build by itself. A lifecycle transition becomes effective only after
explicit security authorization, publication, and verification. A later authenticated security
hotfix can become current and replace a revoked build, but it cannot erase that build's revocation
history or unresolved follow-up obligation.

If the unsafe build is the current chain tip and no safe successor exists yet, the protected
transition publishes the critical revoked state with no claimed current build. Recovery-only
guidance stays intact through the ledger, descriptor, CoreUpdater snapshot, Platform API, support
bundle, and Web Shell; tooling never substitutes the affected tip as its own replacement. A later
hotfix must still pass exact publication, lineage, incident, and lifecycle activation checks before
it becomes current.

Public output contains bounded ids, severity, status, reason codes, and safe guidance. Embargoed
details, reporter information, raw incident records, raw support bundles, and private publication
material remain outside lifecycle artifacts.

## Stable maintenance integration

`stable-maintenance` consumes the authenticated lifecycle inventory and proposed transition set.
It verifies predecessor eligibility for the selected release class, refuses to treat an
end-of-support or revoked predecessor as ordinary supported maintenance, requires the exact
security authorization for a hotfix from a revoked or security-only predecessor, preserves support
and deprecation clocks, and leaves lifecycle activation pending until the maintenance publication
receipt exists. The hotfix exception is release-class-specific: it does not make a revoked or
security-only predecessor eligible for routine maintenance.

Before the first lifecycle publication, operators use the protected `prove-genesis` operation to
obtain an attested, short-lived HTTP `404` proof for the exact authenticated inventory. The input
producer independently verifies that proof's lifecycle-workflow attestation before certification.
After edition 1, lifecycle certification requires the exact prior ledger and descriptor. The
maintenance promotion gate additionally requires the complete five-artifact authority chain:
ledger, descriptor, approved authorization, authorized publication plan, and verified receipt. A
tombstone, omitted predecessor pair, or partial authority is a blocker.

Those five authenticated files remain byte-identical across maintenance phase handoffs. A separate
sixth public-observation receipt is never accepted from a reviewed input bundle or reused from the
prior phase: the protected maintenance workflow regenerates, attests, and verifies it under the
shared publication lock. This prevents a once-valid but superseded lifecycle edition from making a
maintenance candidate promotion-ready.

Maintenance validation can prepare deterministic lifecycle transition bytes. It cannot publish
them. The newly published build becomes `current-stable` only after the maintenance publication is
complete and the protected lifecycle descriptor publication is independently verified.

## Privacy and local-only operation

Lifecycle evaluation needs no centralized telemetry. Cryptad does not report node identifiers, IP
addresses, peer identities, installation counts, app data, usage metrics, or support bundles to a
central service. A node decides support state from authenticated update-key content and its local
last-known-good copy.

Public lifecycle artifacts can contain release ids, integer builds, `v<build>` tags, public source
commits, public digests, support statuses and deadlines, public advisory/reason ids, replacement
guidance, and descriptor edition/digest. Redaction blocks private insert URIs, tokens, cookies,
authorization headers, keys, raw content or app data, raw support bundles, identity material,
addresses, local usernames/paths, control characters, unsafe URLs, nested unsafe archives, and
embargoed incident detail.

## Safe local tests

Run the focused Python suites without publication credentials:

```bash
python3 tools/release-certification/certify.py stable-maintenance --self-test
python3 tools/release-certification/certify.py stable-lifecycle --self-test
```

Run the relevant Java module tests with the Gradle wrapper:

```bash
./gradlew :runtime-spi:test :runtime-node:test :platform-api:test :platform-web-shell:test
```

These commands use deterministic fixtures. They do not insert a descriptor, update a USK edition,
create a release, send telemetry, or mutate a running node.
