# Stable 1.0 catalog publication and key ceremony

This runbook defines the Stable 1.0 catalog key ceremony, role-specific trust deployment, and
network-native catalog publication boundary. It adds a narrow governance layer around the existing
Stable RC freeze, Stable GA exact-byte publication, runtime signature verifiers, and catalog
operations. It does not replace any of those authorities.

Merging the implementation does not perform a production key ceremony, publish a Stable USK,
observe an independent mirror, rotate a production key, or exercise a production rollback. Those
remain protected operations and are complete only when authentic protected receipts and public
observations have been verified.

## Authority boundaries

| Authority | Responsibility | Not authorized to do |
| --- | --- | --- |
| Stable RC | Freeze the exact catalog, detached signature, revision, signer identity, first-party apps, reviews, rollback subject, and release inputs. | Rebuild or relabel the selected bytes after freeze. |
| Stable GA | Validate and publish or confirm the frozen bytes on the existing public HTTPS surfaces. | Substitute a USK observation for the existing HTTPS checks. |
| Protected release execution | Authenticate the PR-291 workflow run, attempt, artifacts, approvals, and release root. | Assert independent reproducibility or network publication by itself. |
| Independent reproducibility | Authenticate the PR-292 provider-distinct rebuild and its selected catalog subject. | Sign, publish, or change the catalog. |
| Catalog authority | Authenticate the role-separated public keyset, ceremony, publication observations, drills, and closeout against the exact PR-291 and PR-292 subjects. | Rebuild, rewrite, re-sign, or automatically trust catalog content. |
| Runtime verifiers | Verify catalog, app-bundle, and reviewer signatures against their role-specific registries. | Infer trust from a key listed by an untrusted catalog or mirror. |
| Network primary and mirrors | Make the same signed subject available through distinct transports or control planes. | Act as signing or trust authorities. |

The Stable network primary is a public `crypta:USK@...` fetch location. The existing canonical
HTTPS catalog and signature locations remain mandatory Stable GA observations and can also provide
independent availability. Every location is untrusted transport until the exact catalog and
detached signature verify against the catalog registry.

Evidence classifications remain distinct:

- repository implementation proves that schemas, policy, commands, workflows, and tests exist;
- fixture verification proves only deterministic local behavior with visibly non-production keys;
- a protected ceremony receipt authenticates a real approved ceremony;
- a protected publication receipt authenticates the mutation result for one exact subject;
- mirror and public observations prove only the bytes fetched from their named public locations;
- rotation and rollback drill receipts prove only the exact drill they authenticate; and
- closeout advances only through states proved by authentic protected inputs.

A local JSON file, self-test, example manifest, workflow definition, or documentation statement
cannot cross any of these boundaries.

The [external third-party app pilot](stable-1.0-external-third-party-app-pilot.md) consumes this
authority without extending it. PR-293 signs and observes a distinct beta catalog subject; the
pilot coordinator receives only the public keyset and sanitized publication receipts. The external
publisher key is held in a dedicated pilot app registry and must remain distinct from all four
PR-293 roles. No pilot request can be relabeled as Stable publication.

## Key roles and custody

The Stable ecosystem keyset is closed to four roles:

| Role | Permitted use | Custody boundary |
| --- | --- | --- |
| `catalog-signing` | Sign exact Stable catalog bytes. | Online only within the approved catalog-signing boundary. |
| `first-party-app-signing` | Sign first-party app-bundle digest manifests. | Online only within the approved first-party build/signing boundary. It is not transferred to independent reproducibility builders. |
| `app-reviewer` | Sign app-review receipt payloads. | Reviewer workflow only; existing reviewed-at lifecycle semantics remain authoritative. |
| `offline-recovery` | Authorize keyset bootstrap, successor transitions, and recovery statements. | Offline, quorum-controlled, and never materialized in routine catalog, app, review, CI, or publication jobs. |

One key ID or one public-key fingerprint must not appear in more than one role. The public keyset
records Ed25519 public keys as canonical X.509 SubjectPublicKeyInfo, stable key IDs, SHA-256
fingerprints, lifecycle and validity, predecessor and successor links, proof-of-possession
bindings, compromise state, ceremony and receipt bindings, and public-transparency eligibility.
Links must be reciprocal where required, acyclic, and within one role. Invalid windows, duplicate
identities, unknown lifecycle values, and a revoked key presented as active fail closed.

Private keys are never repository inputs or outputs. Custody and approval metadata is bounded to
roles, quorum counts, policy identifiers, and protected provenance; it must not identify private
locations, devices, people, or recovery instructions. Public key bytes are intentional public
material, but they belong only in the dedicated transparency artifact and derived trust registries.
Ordinary summaries, receipts, logs, support bundles, API responses, and reports expose only key
IDs, fingerprints, lifecycle, and digests.

## Ceremony types

### Genesis

The first ceremony establishes the initial role-separated keyset and offline recovery-root
fingerprint. Protected release policy and explicit protected approvals bind that fingerprint to
the exact Stable release identity, PR-291 release root, and PR-292 catalog subject. Genesis cannot
be inferred from a self-signed local document or a fixture keyset.

For each routine signing key, verify public-key encoding, fingerprint, lifecycle, validity, and
proof of possession before accepting the keyset. Verify that the recovery key has recovery-only
purpose. The recovery key signs the canonical initial keyset transition authorization; it does not
sign a catalog, app bundle, review receipt, or routine proof-of-possession statement.

### Planned rotation

A planned rotation stages a successor in the same role with its own proof of possession. The
current offline recovery key authorizes the canonical successor keyset and transition statement.
Catalog-key rotation keeps the predecessor and successor in an explicit overlap registry until a
current catalog and a successor-signed next edition have been verified by the required clients and
locations. Only then may the predecessor become retired.

Changing catalog bytes, detached-signature bytes, or signing-key identity requires a later catalog
revision and USK edition. Never re-sign one Stable edition in place. Retirement is not compromise:
a retired app-signing key can remain valid for supported installed bundles during its declared
verification window, while new Stable app production must use the active successor. Existing
reviewer lifecycle rules preserve receipts made at an eligible reviewed-at time by a retired,
non-revoked reviewer key.

### Compromise recovery

A compromised routine signing key has no normal overlap assumption. Stop accepting new subjects
from it, authenticate the recovery authorization, stage a distinct successor, and publish a later
edition signed by that successor. A rollback target signed by a compromised catalog key is
ineligible even if its bytes were previously valid.

The preceding offline recovery key authorizes the transition when it remains sound. If that key is
also unavailable or compromised, only the separately authenticated protected recovery quorum
defined by policy may authorize recovery. A caller-supplied quorum claim, local file, or ordinary
workflow approval is insufficient. Public records contain bounded reason and authority codes, not
private incident details.

The first quorum receipt is produced only by
`stable-1.0-catalog-recovery-quorum.yml`. Its fixed release-controlled and security-controlled
protected approval jobs must both complete before the workflow derives `recordedApprovals=2` and
emits the exact transition-bound receipt. The receipt also binds the fixed approval role and logical
key-ceremony environment. It grants no catalog publication, routine signing, or incident-response
authority beyond that one recovery statement. Provisioning both protected environments and their
independent reviewer policies is a protected operational prerequisite after merge.

The transition statement and resulting signed transparency artifact both name the exact
`transparencySigningKeyId`. That identity is the eligible offline recovery key that signs the
resulting artifact and becomes the root for the next ordinary transition. It is deliberately
distinct from `recoveryAuthorization.signingRecoveryKeyId`, which is null when the protected
quorum authorized the current transition. A later rotation verifies the previous detached
transparency signature through this signed identity; it never guesses a recovery key or falls back
to the prior transition's authorization field.

### Emergency replacement authorization

An emergency replacement uses the current authorized routine keys or a recovery-authorized
successor transition. Bind the advisory, denylist, replacement app identity, bundle digest,
catalog edition, release root, and independent-reproducibility subject before publication. This
path does not bypass review, bundle verification, update consent, scheduler checks, redaction, or
exact-byte publication rules.

## Canonical proof of possession

Every staged, active, or retiring routine signing key proves control of its corresponding private
key without disclosing that key. The Ed25519 signature covers one canonical, domain-separated
statement binding:

- ceremony ID and Stable release milestone;
- key role, stable key ID, algorithm, and public-key fingerprint;
- validity window;
- predecessor and successor identities;
- the exact keyset digest; and
- the proof schema and domain version.

The verifier reconstructs canonical bytes, verifies the signature with the declared public key,
and binds the statement digest into the ceremony receipt. A signature over an ad hoc message, a
key ID plus public bytes, a proof copied from another ceremony, or a proof for another keyset does
not establish possession. The recovery key does not need a routine-signing proof that grants it a
routine role; its recovery authorization is verified only for the closed recovery domains.

Retired and revoked routine keys do not sign the successor keyset. Their closed
`retained-historical` proof carries the complete canonical statement and signature from an earlier
keyset. Verification rechecks that signature, statement digest, immutable public identity,
validity window, and compatible lineage, while requiring the statement to name an earlier keyset
digest. The current ceremony binds that retained record through its recovery-authorized keyset and
transparency signer, whose detached signature covers the proof classification and digests. A
staged, active, or retiring key must instead provide a
`current-keyset` proof over the exact current digest; it cannot replay a historical proof. This
separation permits destroyed or unavailable predecessor private keys without treating historical
keys as current signing authorities. Offline recovery keys use the explicit
`not-applicable-recovery` proof classification and carry no routine proof material.

Every non-genesis ceremony authenticates the immediately preceding transparency artifact and its
detached signature, including a transition authorized by the protected recovery quorum. Stable
keyset membership is append-only: each previous key ID remains present with the same role,
algorithm, public key, and fingerprint after retirement or revocation. The closed 64-key bound is
a stop condition that requires a future policy/schema revision; it is not permission to prune a
revoked identity or reuse its ID or fingerprint under another role.

## Role-specific trust deployment

Derive three public registries from the accepted keyset:

- a catalog registry containing every non-staged catalog-signing identity;
- an app-bundle registry containing every non-staged first-party app-signing identity; and
- the reviewer registry using `TrustedReviewerKeys` lifecycle semantics.

Deploy the catalog registry through `cryptad.appcatalog.trustedKeysFile` or
`CRYPTAD_APPCATALOG_TRUSTED_KEYS_FILE`. AppHost continues to use its existing app-bundle registry,
and reviewer verification continues to use its separate reviewer registry. Configure exactly one
source for each role. Conflicting or partial role configuration fails closed.

Derived reviewer registries retain revoked, suspected, and compromised reviewer identities as
`revoked` entries. They must remain distinguishable from unknown reviewers so advisory or manual
install policy cannot downgrade an authenticated revocation to a warning. Staged reviewers remain
absent, while retired and uncompromised reviewers retain the existing bounded historical
reviewed-at semantics.

Catalog and app-bundle registries apply the same tombstone rule. A revoked, suspected, or
compromised identity remains present with runtime status `revoked`; only a staged identity is
omitted. This preserves cross-role overlap detection and prevents a later registry from treating a
known compromised key ID or fingerprint as unused.

Each catalog or app-bundle lifecycle registry must also reject one canonical X.509 public-key
fingerprint under multiple stable key IDs, including active, retiring, retired, and revoked aliases.
The detached bundle and catalog key ID selects policy but is not itself part of the signed payload;
allowing aliases would let revoked key material select an active policy under another ID.

When catalog-specific trust is configured, runtime composition rejects any catalog and app-bundle
registry pair that overlaps by stable key ID or SHA-256 X.509 public-key fingerprint. This check
includes staged, active, retiring, retired, and revoked entries so lifecycle changes cannot create
a cross-role trust path. The only shared-registry case is the explicitly documented legacy fallback
when catalog-specific configuration is absent.

For compatibility, if the catalog-specific setting is absent, catalog verification may fall back
to the existing AppHost trusted-key registry and emit a bounded operator warning. The fallback is
a migration bridge only: Stable production certification requires separate role-specific files
and distinct key identities. Configure and validate the catalog registry before removing reliance
on the fallback. Existing v1 catalog and app signature sidecars remain unchanged.

Installed-app verification must evaluate key lifecycle for the verification purpose. Planned
retirement may permit an already installed, supported bundle during its bounded support window,
but does not authorize a new Stable bundle. Revoked or compromised keys fail closed. Direct
install and update paths must use the same role and lifecycle policy as scheduled updates. AppHost
reverifies the installed bundle with the historical lifecycle policy before every explicit launch
and automatic restart; rollback restoration uses the same historical purpose without weakening new
bundle admission.

## Side-effect-free preparation and verification

Use the catalog-authority command for deterministic preparation and verification:

```bash
python3 tools/release-certification/certify.py stable-catalog-authority --self-test
python3 tools/release-certification/certify.py stable-catalog-authority --help
```

Non-fixture operations also require `--evidence-dir` pointing at one confined, authenticated
handoff. Depending on the mode, that handoff contains the exact PR-291 protected-release summary,
PR-292 summary and subject inventory, GA plan/receipt/HTTPS observation, canonical
`cryptad-app-catalog.properties` and `cryptad-app-catalog.signature` bytes, and protected live or
mirror observation receipts. Rotation-drill and closeout evidence also carries the exact retained
rollback catalog and detached signature as `stable-1.0-rollback-app-catalog.properties` and
`stable-1.0-rollback-app-catalog.signature`, plus the original protected
`stable-1.0-catalog-drill-receipts.json` bundle. Each manifest drill `subjectDigest` must equal the
semantic receipt digest for the same type and completion time. The bundle binds all six closed
drill types to the exact release, PR-291 root, PR-292 result and inventory, ceremony, keyset, and
frozen catalog subject. The rollback sidecars' digest, size, key, signature, older revision, and
older USK edition must match the reviewed rollback subject. The command rejects links, special
files, case collisions, macOS metadata, nested archives, excess members, and byte-bound violations.
Digest strings in the authority manifest never substitute for those exact files. The protected
publication job may also
pass its sanitized Java result with `--live-publication-result`; that result is compared with the
reviewed network-primary URI, edition, exact catalog/signature digests, and signer before a partial
publication receipt is retained. The mutation step captures publisher and certification exit
statuses instead of exiting before cleanup. It removes the private insert URI and form password,
requires a regular single-link result no larger than 64 KiB, and runs side-effect-free
certification even when the publisher reports failure. If the generated and receipt-local
redaction checks both pass and the receipt binds the exact live-result digest, the workflow
atomically stages exactly the live result, partial receipt, and redaction report before returning
the original nonzero status. The artifact upload runs under `always()`, so a queued or confirmed
remote mutation cannot lose its sanitized predecessor evidence merely because post-publication
verification failed. The failed job and non-operational partial receipt still cannot claim
publication success.

Every protected workflow operation uses a closed v1 aggregate of exact Actions artifact
coordinates. The required member set is operation-specific: ceremony modes require the PR-291
summary, PR-292 summary and inventory, the direct public-observation receipt, and the original
attempt-scoped primary subject bundle; publication modes add the Stable GA handoff, and observation
adds the live
publication and mirror receipts, and drill modes add the retained rollback sidecars and protected
drill-receipt bundle. The bundle is accepted only from
`.github/workflows/stable-1.0-catalog-drill-acceptance.yml`, whose fixed release and security
approval boundaries emit the original root receipt artifact. Catalog-authority verification may
consume that artifact but cannot reupload itself as its producer. A successful
first ceremony takes its PR-291 summary from the dedicated protected-release closeout workflow,
its PR-292 summary and subject inventory from the independent-reproducibility closeout, and its
public observation directly from the read-only observation workflow. It takes the exact subject
bundle only from the selected supply-chain attempt; a catalog-authority reupload is not a bootstrap
authority. The verifier matches every bundled subject to the PR-292 inventory, verifies the frozen
first-party bundle signatures with the ceremony app key, and verifies the inline frozen review
receipts with the ceremony reviewer key at each signed `reviewedAt` timestamp. A matching key ID
without a matching public key therefore cannot produce a deployable registry. The protected-release
closeout materializes only files already digest-bound by the reviewed PR-291 contract, verifies
their exact producer coordinates, and invokes the existing `stable-protected-release --mode
closeout` authority. Its bootstrap contract must leave the optional PR-293 coordinate and evidence
null, preventing a PR-291/PR-293 digest cycle. The RC preflight or RC-dispatch summary is never a
substitute for this final `publicly-observed` root.

A successful
side-effect-free publication-preparation run retains the exact PR-291, PR-292,
subject-inventory, and public-observation members it verified; the retained RC-dispatch summary is
not accepted as a publicly observed PR-291 closeout. Stable GA separately retains its verified
plan, final receipt, current sidecars, and rollback sidecars. Preparation, GA, network publication,
mirror observation, and transition evidence remain distinct protected phases. Each
aggregate row binds the workflow path, run ID, run attempt, artifact name, Actions artifact digest,
and the digest of every selected canonical member. The workflow authenticates every producer run,
downloads each artifact into an isolated directory, and copies only the exact required member set
into a fresh evidence directory. It rejects a legacy single coordinate, missing or duplicate
members, cross-role workflows, unsafe paths or links, archive collisions, and artifact or member
digest drift. Each member uses its fixed path in the preparation, publication, observation, or
verification artifact; callers cannot select arbitrary same-basename files or renames.

All generated values are scanned before the first output write. A redaction finding aborts the
operation with an empty output directory, and a nonempty output directory is rejected at entry so
stale successful evidence cannot survive a failed retry.

The local security-response and maintenance commands do not authenticate GitHub Actions
coordinates. Their digest-only `catalogAuthority` compatibility seam therefore cannot accept an
operational PR-293 claim. Until those consumers receive an exact protected archive and coordinate
through a protected intake, omit the binding; arbitrary local JSON cannot promote a drill or
maintenance authorization to an operational catalog-authority state.

Its closed modes prepare or verify ceremonies and publication, use `verify-rotation-drill` for the
closed typed rotation and rollback drill evidence, and produce closeout. These modes read local
authenticated inputs and write confined, deterministic, redacted evidence. They do not access
publication credentials, insert a USK, mutate a tag or GitHub Release, sign with a production
private key, or claim a remote operation.

Preparation must bind the exact PR-291 protected release summary and release-root digest plus the
exact PR-292 independent-reproducibility summary and catalog subject. A wrong release ID, build,
source commit, selected RC, catalog digest, detached-signature digest, signer, revision, channel,
or fixture/provider classification is a blocker. Duplicate JSON keys, unknown enum values,
non-canonical key material, path escapes, and unbound or replayed lineage fail closed.

The confined output set uses fixed names:

- `stable-1.0-key-ceremony-summary.json` and
  `stable-1.0-key-ceremony-receipt.json`;
- `stable-1.0-public-key-transparency.json` and its detached
  `stable-1.0-public-key-transparency.signature`;
- `stable-1.0-catalog-publication-plan.json` and
  `stable-1.0-catalog-publication-receipt.json`;
- `stable-1.0-catalog-rotation-drill.json`;
- the catalog, app, and reviewer derived public registries; and
- `stable-1.0-catalog-authority-summary.json`,
  `stable-1.0-catalog-authority-report.md`, and
  `stable-1.0-catalog-authority-redaction-report.json`.

The presence of any output is not operational evidence by itself. Authenticate its producer,
container, digest, candidate bindings, and evidence classification before consumption.

## Protected ceremony and publication

Run the protected catalog-authority workflow only after side-effect-free preflight and the required
human approvals. Its orchestration operations distinguish `prepare-ceremony`, `verify-ceremony`,
`prepare-publication`, `publish-network-primary`, `verify-publication`,
`verify-rotation-drill`, `rollback-drill`, and `closeout`. The protected `rollback-drill`
operation uses the local typed drill verifier. Its exact receipt digest and authenticated original
producer keep rollback distinct from rotation; caller-authored `pass`, timestamp, or digest fields
cannot complete a drill. Keep these phases separate:

1. Prepare the proposed public keyset, per-key proofs, recovery authorization, and ceremony plan.
2. Accept the ceremony only from the authenticated protected receipt and verified public artifact.
3. Prepare a publication plan for the exact frozen catalog and detached signature.
4. In the publication environment only, materialize the private insert URI and form password and
   invoke the existing live `crypta-app publish-usk --live` boundary.
5. Remove secret values from ambient state before constructing any receipt or uploading evidence.
6. Run `stable-1.0-catalog-mirror-observation.yml` on the managed read-only observation node. It
   authenticates the exact preparation, GA handoff, and sanitized live-publication artifacts,
   revalidates the reviewed observation time after protected-environment and runner admission,
   fetches the public network primary and every required mirror, and compares both exact sidecars.
   The closed receipt records the collector's actual start and completion instants so later
   authority verification reevaluates catalog-key lifecycle at completion rather than trusting the
   earlier reviewed observation timestamp alone.
   Catalog transfers are limited to 1 MiB and detached signatures to 64 KiB before either a final
   file or an in-memory value is accepted.
7. Verify scheduler/catalog refresh behavior through that preconfigured read-only observation
   node. An exact successful primary refresh must fall inside the protected collector's actual
   start-to-completion window, and scheduler health must expose a configured mirror fallback;
   persisted primary successes from an earlier observation do not qualify. Ordinary refresh stops
   after a successful primary response, so mirror availability is proved separately by the
   collector's exact catalog-and-signature fetch from every declared mirror rather than by
   manufacturing a fallback scheduler attempt. The collector has no insert capability or
   publication credentials.
8. Run separately authorized rotation and rollback drills when required, then accept their exact
   evidence digests through `stable-1.0-catalog-drill-acceptance.yml`. Its independent release and
   security approval boundaries emit one closed bundle with six self-digested receipt rows. Both
   initial validation and protected receipt construction reject a completion time more than five
   minutes ahead of runner UTC.
9. Publish and observe the signed public key-transparency artifact.
10. Close out only the monotonic states proved by the retained receipts.

The catalog-authority verification workflow may retain derived verification summaries, but neither
it nor a reuploaded input receipt is an admissible first producer for mirror observation or recovery
quorum evidence. Every later operation must continue to name the original producer run, artifact,
root member, and digests.

The signer of the catalog being newly inserted or refreshed must be `active`, uncompromised, and
valid when the signed transparency keyset becomes effective and through the actual completion of
the protected publication observation. The collector rejects a delayed start, an observation that
runs beyond the reviewed 15-minute window, or a signer that expires during collection. A planned
rotation keeps a retiring predecessor only for historical
verification and uses an active successor for a newly published catalog. A rollback signer may be
active, retiring, or retired, but it must be uncompromised and its declared support window must
contain the transparency effective time, the latest authenticated publication observation, and an
authenticated rollback drill when one is being certified. It must also remain valid through the
protected mirror collector's authenticated completion instant. Runtime rollback continues to
reevaluate that half-open validity window at the actual rollback time.

The mutation job stages only the frozen `cryptad-app-catalog.properties` and
`cryptad-app-catalog.signature`. Publication does not rebuild, rewrite, or re-sign them. The
workflow has no tag or GitHub Release authority. A command line containing a secret value must
never be printed or retained.

The mutation job runs only on the protected `cryptad-stable-catalog-publication` self-hosted
runner. That runner must already own a managed, network-connected Cryptad daemon on
`127.0.0.1:7654`, share the job's local filesystem identity, and have a protected form-password
secret that matches the running daemon. Before materializing either publication secret, the
workflow performs bounded, read-only greeting and Platform API contract checks. It fails closed if
the daemon or the required directory-insert and content-fetch routes are unavailable. Daemon
installation, startup, restart, shutdown, and form-password rotation remain protected runner
provisioning operations; the catalog workflow does not rebuild or mutate that infrastructure.

## Network primary, mirrors, and rollback

The publication subject binds catalog ID, Stable channel, catalog revision, USK edition, exact
catalog digest and size, exact detached-signature digest and size, signing key ID and public-key
fingerprint, selected release/freeze/product identity, PR-292 result, and policy-governed
timestamps.

The public locations have distinct roles:

- the network primary is a public Crypta USK fetch URI;
- public web mirrors include the canonical HTTPS catalog and signature locations already required
  by Stable GA;
- an optional second network mirror is a separate approved public source; and
- rollback names an immutable, retained older signed edition or revision.

Protected public-web observation uses canonical credential-free HTTPS on port 443. The authority
rejects an explicit non-443 port during planning because the hardened collector resolves, pins,
and fetches only that same approved port; a plan the collector cannot execute is invalid.

At least one mirror must identify an operator, provider, or control plane independent from the
network-primary publication boundary. This is availability evidence, not additional signature
trust. Reject duplicate or aliased locations, a mirror presented as a trust authority, stale or
unauthorized newer bytes, catalog/signature sibling mismatch, and any mismatch in catalog ID,
channel, revision, edition, signer, digest, or size.

Exact already-published state is idempotent success after observation. Conflicting existing state
fails closed and must not be overwritten. If only some locations succeed, record `partial` with
the successful immutable evidence and bounded blockers; never promote it to a complete state.

Rollback verifies a retained previous catalog and detached signature with an older edition or
revision and a different digest. Re-evaluate current key lifecycle and compromise policy before
selection, then re-check primary and mirror health. Catalog rollback changes catalog selection
only; it does not uninstall, downgrade, update, or remove app data.

## Drills

Deterministic self-tests use visibly non-production keys and subjects. Protected drills consume
authenticated operational inputs and produce separate receipts. Neither type performs an
unapproved live mutation.

Operational verification requires the original protected six-receipt bundle. Every receipt row
contains a nonempty bounded set of supporting evidence digests, a completion instant, and a
semantic self-digest; the bundle has its own self-digest and exact candidate bindings. The rollback
key lifecycle check uses the authenticated rollback receipt's completion instant, never the
manifest's unauthenticated timestamp. If any producer evidence or protected acceptance remains
pending, the corresponding drill and closeout remain blocked.

- Planned catalog-key rotation proves successor proof of possession, recovery-authorized lineage,
  overlap acceptance, a successor-signed later edition, mirror/client verification, and delayed
  predecessor retirement.
- Catalog-key compromise proves that new compromised-key catalogs and compromised-key rollback
  targets fail, and that emergency successor publication requires protected recovery authority.
- App-signing-key rotation proves historical installed-bundle verification during planned
  retirement while new Stable production requires the active successor.
- Reviewer-key rotation reuses reviewed-at lifecycle semantics: retired, non-revoked keys may
  preserve eligible historical receipts; new receipts use the successor; compromise revocation
  remains distinct.
- Emergency replacement proves exact advisory, denylist, replacement bundle, catalog edition,
  scheduler, and operator-status bindings without claiming fixture publication.
- Rollback proves exact retained bytes, older revision and edition, current trust eligibility, and
  post-rollback source health without changing installed apps.

## Public key transparency

The deterministic transparency artifact is a signed Stable release-governance record, not a
global transparency service and not an instruction for nodes to auto-trust its contents. It binds
keyset version and predecessor digest, ceremony identity and type, release/build/commit, PR-291 and
PR-292 digests, role-separated public keys and lifecycle, rotation links, recovery authorization,
the frozen catalog subject, public location identifiers, effective timestamps, and its own digest.

Verify its detached signature and exact public bytes before recording publication. Public key
bytes are permitted in this artifact and the derived public registries only. Ordinary operational
views should expose a key ID, fingerprint prefix, lifecycle or rotation state, successor ID,
network-primary health, mirror exact-subject status, rollback availability, transparency digest,
and bounded blockers.

## Retry, partial state, and stop conditions

Retain authenticated evidence for every completed phase. A retry must authenticate its predecessor
and revalidate every still-current input; it must not reseal an earlier result under a new run or
silently replace conflicting public state. Exact existing state can be confirmed idempotently.
Unavailable or mismatched remote state remains `partial` or `blocked` according to the closeout
contract.

Stop immediately when:

- protected approval, custody quorum, PR-291, or PR-292 authentication is missing or stale;
- any key role, key identity, fingerprint, proof, lifecycle, lineage, or recovery authorization is
  invalid or ambiguous;
- catalog, detached signature, signer, revision, edition, release, or mirror identity drifts;
- a catalog or signature would be rebuilt, rewritten, re-signed, or relabeled after freeze;
- an existing public location conflicts with the authorized bytes;
- a private insert URI, credential, secret-bearing command line, private key, or local path enters
  publishable evidence;
- a mirror is not independent as declared or is treated as a trust authority;
- a rollback target uses a compromised signer; or
- a fixture, self-test, workflow definition, or local file is offered as operational completion.

After a stop, preserve only sanitized partial-state evidence. Correct frozen-byte defects through
the authorized Stable RC refreeze path; do not repair them inside catalog publication.

## Redaction and archive safety

Reject or remove private key material, private insert URIs, insert-key material, form passwords,
tokens, cookies, authorization headers, secret environment values, secret-bearing command lines,
absolute or runner-temporary paths, staging paths, raw catalog or signature bodies outside their
exact protected asset containers, raw app data, fetched content, support payloads, and unpublished
incident details.

Archive intake also rejects traversal, symlinks, hard links, case collisions, platform metadata,
and unsafe nested archives. Failure summaries use bounded codes and digests only. Do not upload an
ambient environment snapshot, shell trace, scratch directory, or raw HTTP response.

## Operations still required after merge

Before any operational closeout, protected operators must still:

1. conduct and authenticate the real genesis ceremony or authorized successor ceremony;
2. deploy independently reviewed catalog, app, and reviewer registries;
3. approve and perform the live Stable USK insertion in the protected publication environment;
4. fetch and verify the network primary plus an independently operated mirror;
5. authenticate the retained rollback subject and perform any required protected drills;
6. publish and independently observe the signed public key-transparency artifact; and
7. verify and retain the final catalog-authority closeout against the exact PR-291 and PR-292
   authorities.

Until those receipts are supplied and verified, the highest truthful result is implementation or
fixture-verification complete, with protected operational states pending.

## Relationship to federated local trust

The PR-293 catalog keyset and transparency artifacts remain the public-key material and lifecycle
authority for the Stable catalog. Federation adds a host-owned catalog-ID/signer authorization
layer; it does not let another catalog, descriptor, endorsement, mirror, publisher, or reviewer
modify this ceremony or delegate its key. The federation coordinator consumes sanitized PR-293
receipts and has no publication or signing authority. See
[stable-1.0-federated-catalog-discovery-and-trust.md](stable-1.0-federated-catalog-discovery-and-trust.md).
