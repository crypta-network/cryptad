# Stable 1.0 external third-party app pilot

This runbook defines the protected pilot for one genuinely external app publisher. It surrounds
the existing submission queue, reviewer governance, PR-293 beta catalog authority, AppHost, consent,
and live-network collector. It does not replace any of them.

Merging the implementation does not prove that an external developer handed off an app, that a
reviewer made a protected decision, that a beta catalog was published, or that a node performed a
live drill. The checked-in example and self-tests use visible fixture identities and can reach only
`fixture-verification-complete`. Only authentic protected receipts can reach
`operational-pilot-complete`.

The pilot is later ecosystem evidence. It does not change the meaning of an already completed
Stable 1.0 GA release and never promotes the pilot app to the Stable channel.

## Authority boundaries

| Authority | Responsibility | Material it may receive | It cannot do |
| --- | --- | --- | --- |
| External developer | Build and sign the deterministic submission, app bundle, and developer attestation. | Its own source, public handoff policy, and its own private app-signing key. | Use a Crypta reviewer or catalog key; assert its own externality; publish to Stable. |
| Import boundary | Authenticate the exact Actions producer/run/attempt/artifact and confine the opaque archive. | Public external artifacts and public keys only. | Receive any Crypta signing or node secret; extract unauthenticated bytes. |
| Existing intake queue | Import, assign, pre-review, decide, retain resubmission links, and stage candidates. | Deterministic submission packages and public review metadata. | Treat structural `install-smoke` as a live AppHost drill. |
| PR-293 reviewer | Sign the protected cohort receipt with the active app-reviewer key. | Reviewer signing material and exact decision inputs only. | Receive catalog, first-party app, recovery, publisher, insert-URI, or node secrets. |
| Pilot publisher approver | Authorize one external public key for one app, node, validity interval, and exact eligible subjects. | The reviewer authority and public publisher metadata. | Add the external key to the normal Stable first-party registry. |
| PR-293 catalog authority | Sign and publish later beta editions and produce sanitized observations. | Catalog authority material inside its existing protected boundary. | Give its private key or insert URI to the pilot coordinator; promote the app to Stable. |
| Isolated pilot node | Use an ephemeral registry, install, update, acknowledge caution, roll back, and clean up. | Node-local credentials and a dedicated public-key registry. | Receive reviewer or catalog private keys; authorize another app or bundle. |
| Closeout verifier | Authenticate exact PR-291, PR-292, PR-293, handoff, review, catalog, runtime, and redaction receipts. | Public or sanitized digest-bound evidence only. | Perform remote mutation or infer completion from a Boolean. |

The protected coordinator workflow is
`.github/workflows/stable-1.0-third-party-app-pilot.yml`. Its repository permissions are read-only.
Its import, review-observation, catalog-observation, node-observation, and closeout jobs use distinct
protected environments. The workflow verifies receipts; it does not hold the private signing keys
that produced them.

The node-attestation key must be distinct from the external publisher and workload keys and from
every fingerprint in PR-293's complete retained keyset, including staged, retiring, retired, and
revoked identities. A protected secret name or environment boundary does not by itself prove
cryptographic role separation.

## State model

The certifier derives state from evidence instead of trusting `requestedState`:

| State | Required authenticated evidence |
| --- | --- |
| `planned` | Contract preparation only. |
| `preflight-passed` | Closed contract, role-distinct keys, immutable external source, bounded cohort, and policy checks. |
| `fixture-verification-complete` | Non-production signatures and receipts exercise the implementation. This state is never operational. |
| `external-handoff-authenticated` | Valid publisher bundle signatures, developer attestations, approved workload signature, exact packages, and source bindings. |
| `review-cohort-complete` | Active PR-293 reviewer, exact assignment/pre-review/decision bindings, transparency head, and pilot publisher approval. |
| `beta-catalog-published` | PR-293 catalog signature plus exact primary and mirror observations for the beta subject. |
| `runtime-drill-complete` | Signed isolated-node receipt for the exact live collector sequence, consent, rollback, and cleanup. |
| `operational-pilot-complete` | All preceding evidence plus the exact operational PR-291, PR-292, and PR-293 roots. |
| `blocked` | No authenticated stage can advance. |
| `partial` | Some prior stage passed, but publication, runtime, cleanup, or closeout is incomplete or invalid. |

`partial` never becomes success. A resealed JSON object cannot repair an invalid upstream signature,
missing observation, wrong subject, incomplete rollback, or failed cleanup.

## External developer eligibility

Before accepting a handoff, review the external-authority profile. Operational eligibility requires:

- a source repository other than `github.com/crypta-network/cryptad`;
- an owner, organization, account, repository, and workload identity outside the prohibited
  first-party control list;
- an immutable 40- or 64-character commit or content-addressed revision, never a branch-only ref;
- authenticated source archive and tree digests;
- an operational workload profile approved by the active reviewer key;
- a workload public key and signed workload statement bound to the exact source and cohort;
- a publisher public key distinct from every catalog, first-party app, reviewer, recovery, and
  workload key; and
- bounded public maintainer metadata only when policy permits it.

The same commercial CI provider may be used when organization, account, repository, workload, and
key authority are distinct and authenticated. A generic provider template is non-operational until
its trust root and adapter have been reviewed. `external=true`, a repository URL, a key ID sidecar,
or an unsigned JSON document proves nothing.

The execution contract carries PR-293's complete canonical public keyset subject, not an
independent list of trusted pilot keys. The certifier recomputes the subject digest and requires
each selected catalog, first-party app, reviewer, and recovery key to match an exact subject member
before it verifies any pilot receipt. Operational closeout then binds that digest to the
authenticated PR-293 closeout artifact.

The checked-in `samples/third-party/hello-stable-app` app, fixture/test keys, sample owners, template
profiles, mutable refs, and first-party repositories cannot satisfy operational externality.

## Immutable source and build attestation

The execution contract records the external repository identity, host, owner, name, revision type,
immutable revision, archive digest, and tree digest. Its workload profile records provider,
organization, account, issuer, audience, subject, pipeline definition, immutable pipeline revision,
workload public key, validity, and reviewer approval.

The release binding also records the exact Stable product-distribution digest. Operational
closeout requires that digest to equal the authenticated PR-292 selected-RC product digest; a
digest supplied only by the pilot coordinator is not sufficient.

The handoff's workload signature covers the source, app, publisher, and all four submission and
bundle digest rows. This provider-neutral signature is the adapter output authenticated by the
reviewed profile. A changed provider run, source revision, source digest, bundle digest, or
submission digest invalidates the statement.

Each developer attestation uses the domain
`cryptad.stable-1.0.external-third-party-app-pilot.developer-attestation.v1`. It binds pilot, app,
version, submission identity and type, resubmission link, source, build identity, bundle and
signature digests, publisher key and fingerprint, submission digest, manifest digest, and validity
times. The same external Ed25519 key must verify both that statement and the bundle's exact
`cryptad-app.digests` bytes.

The verifier then recomputes every listed bundle member digest and compares the embedded app id and
version. A signature sidecar that merely names the expected key does not pass.

## Handoff archive and redaction

The protected evidence producer accepts only a canonical public HTTPS locator plus an exact digest
and byte size. It disables redirects and proxies, pins the resolved global peer address, rejects
fixture or self-test contracts, and uploads the canonical
`stable-1-0-third-party-pilot-<pilot>-<run>-<attempt>` artifact. The coordinator accepts only that
reviewed producer workflow; arbitrary in-repository, normalized, review, runtime, and closeout
artifacts cannot bootstrap the pilot.

The protected import job downloads the raw Actions artifact by exact workflow, repository, source
commit, run, attempt, artifact id, name, digest, and size. It does not use an action that extracts
the external artifact automatically. The confinement boundary first verifies the opaque archive
bytes, then accepts only sorted, flat, unique, case-distinct regular `.json` and `.zip` members. It
derives the exact allowed member set from `execution.json` and the bound handoff cohort, so an
otherwise safe but unreferenced JSON or ZIP is rejected.

Submission and bundle verification rejects traversal, absolute paths, symlinks, hard-link
ambiguity, special files, encryption, duplicate or case-colliding paths, AppleDouble files,
`__MACOSX`, `.DS_Store`, oversized entries, unexpected nested archives, malformed UTF-8 text, and
non-canonical digest inventories. Text evidence is scanned for private keys, credentials, cookies,
tokens, private insert URIs, raw app data, raw fetched content, and local paths.

The authenticated submission ZIP may remain in the short-lived protected handoff artifact. Public
outputs contain only ids, bounded status, key fingerprints, digests, and blocker codes. Do not put
raw source archives, app data, rationale text, receipt signatures, personal contact details, or
local file paths in public reports or support bundles.

## External publisher key onboarding

Do not edit the ordinary Stable app trusted-key registry. Construct a dedicated registry containing
the external public key and deploy it only to the isolated pilot job.

The signed pilot approval binds:

- pilot and isolated node ids;
- exact app id and source identity;
- publisher key id and canonical X.509 fingerprint;
- handoff digest;
- normal Stable, PR-293 catalog-authority, and pilot-registry digests;
- the node-attestation public-key fingerprint;
- exact version, bundle, and bundle-signature subjects;
- the closed install, update, caution-update, rollback, and cleanup operation set;
- validity, revocation, cleanup, and reviewer authority.

`PilotPublisherVerificationPolicy` applies that projection at AppHost's copied-bundle boundary. It
authenticates the exact bytes of all three registries, requires them to be pairwise disjoint by key
id and public key, runs the cryptographic bundle verifier, then checks the exact publisher, app id,
version, and signature-sidecar digest. Therefore the external key cannot authorize an unrelated app
even if it signs that app correctly, and it cannot also serve as catalog authority.

The protected runtime uses the same new-bundle policy during catalog extraction and retained-plan
reverification. This check occurs before an update migration dry-run and before AppHost copies the
staged bundle. Catalog authority still uses the separate PR-293 catalog registry.

Registry digests are SHA-256 over the exact trusted-key registry file bytes. The catalog digest must
equal the deterministic registry projection of every non-staged `catalog-signing` key in the
authenticated PR-293 keyset; a coordinator-authored opaque digest is insufficient. Pilot mode
requires file-backed normal Stable and catalog registries and rejects direct trusted-key additions,
so the authenticated normal-registry digest covers all ordinary app-bundle trust. The dedicated
pilot registry must contain exactly one identity: the approved external publisher key.

Provision the isolated daemon with all of these settings or none of them:

| Purpose | System property | Environment variable |
| --- | --- | --- |
| Expected pilot | `cryptad.apphost.pilot.id` | `CRYPTAD_APPHOST_PILOT_ID` |
| Expected isolated node | `cryptad.apphost.pilot.nodeId` | `CRYPTAD_APPHOST_PILOT_NODE_ID` |
| Exact signed approval receipt | `cryptad.apphost.pilot.approvalFile` | `CRYPTAD_APPHOST_PILOT_APPROVAL_FILE` |
| Authenticated approval-file digest | `cryptad.apphost.pilot.approvalDigest` | `CRYPTAD_APPHOST_PILOT_APPROVAL_DIGEST` |
| Dedicated external-key registry | `cryptad.apphost.pilot.trustedKeysFile` | `CRYPTAD_APPHOST_PILOT_TRUSTED_KEYS_FILE` |

The normal registry remains configured through `cryptad.apphost.trustedKeysFile`, and the catalog
authority remains configured through `cryptad.appcatalog.trustedKeysFile`. The approval digest must
come from the authenticated `execution.json` evidence binding; do not compute the expected value
from the approval file during daemon startup.

At bootstrap, the runtime authenticates the approval plus the persistent normal Stable and catalog
registry snapshots. Each new or historical bundle decision reads the canonical signature key id
from the AppHost-controlled copy. The approved external publisher is then routed through a fresh
approval and all-registry validation, including validity, revocation, exact digests, and subject
bounds. Every other signer is verified only against a fresh exact normal Stable snapshot whose
digest matches the authenticated approval; failure on that path never falls back to pilot trust.

Catalog verification reloads only the approval plus exact normal and catalog snapshots. It does not
require the temporary publisher registry, but it still rejects digest substitution or role overlap.
Missing, changed, symlinked, overlapping, or digest-mismatched persistent material fails closed.
Removing or quarantining the pilot registry, or allowing the approval to expire or become revoked,
therefore disables later external install, update, launch, restart, and rollback verification while
ordinary Stable app and PR-293 catalog verification remain available.

The protected runtime adapter must start or restart a per-pilot managed daemon after it stages the
authenticated approval and registries. It must pass `--require-managed-daemon` and
`--require-apphost-policy stable-1.0-pilot-publisher-v1`, verify the effective policy before the
first catalog refresh, then stop that daemon or restart it without pilot configuration after
cleanup. Environment variables supplied only to an adapter cannot reconfigure an unrelated daemon
that was already running. No HTTP route mutates app trust for this pilot.

After the drill, delete the ephemeral registry or quarantine it according to the protected receipt.
Registry cleanup failure leaves the pilot `partial`.

## Submission, review, rejection, and resubmission

Use the existing commands and file-backed queue. Do not create a pilot-specific queue:

1. Run `crypta-app submission verify` on each exact deterministic package.
2. Import with `crypta-app submission intake import`.
3. Assign the active PR-293 reviewer with `submission intake assign`.
4. Generate fresh artifacts with `submission intake pre-review`.
5. Record the decision with `submission intake decide`.
6. Verify the standard review receipts and local transparency chain.
7. Stage eligible candidates with `submission intake stage-candidate`.

Use one bounded protected assignment-reason document when assigning the active reviewer to all four
cohort submissions. The signed cohort's `assignmentDigest` is the SHA-256 of those exact reason
bytes. Every `reviewer_assigned` transparency record must carry that digest, and every
`pre_review_completed` record must carry its row's exact pre-review report digest.

For each submission, the authenticated transparency chain must contain exactly one
`reviewer_assigned`, one `pre_review_completed`, and one `review_decision_recorded` event in that
order. The records use the production intake subject shape: `subjectType=submission`, the submission
id as `catalogId`, and `<submissionId>:<event-kind>` as `recordId`. A receipt or rejection event
cannot substitute for the missing decision record.

The four rows are fixed:

| Cohort row | Required behavior |
| --- | --- |
| Version 1 | `reviewed`; eligible for beta candidate and exact install. |
| Version 2 initial | `rejected` or `resubmission_requested`; no candidate and no catalog install. |
| Version 2 corrected | `resubmission` with the exact prior submission id; fresh package, bundle, pre-review, decision, and receipt; eligible after review. |
| Version 3 | `caution`; nonempty warning codes and explicit candidate allowance; runtime acknowledgement required. |

The initial and corrected version 2 submissions use the same exact app version. The installable
versions use the dotted-numeric ordering supported by `AppUpdateService` and strictly advance from
version 1 to corrected version 2 to caution version 3. A prerelease label, numerically equivalent
version spelling, or descending version cannot satisfy this runtime pilot contract.

The corrected row must not reuse the old submission id, submission digest, bundle digest, signature
digest, or pre-review digest. A stale decision or receipt cannot be carried forward.

The protected cohort carries the existing canonical `AppReviewReceipt` payload for every reviewed
or caution decision and verifies its Ed25519 signature independently of the cohort signature.
Canonical intake receipts may omit their optional expiry, and each retains its own signed review
time no later than the protected cohort completion time. Rejected and `resubmission_requested`
decisions have no synthetic catalog receipt; their exact decision digests and transparency records
remain bound by the signed cohort. The cohort also carries the existing
redacted JSONL transparency-record shape and recomputes every record hash, predecessor, sequence,
canonical log digest, count, and head. Missing predecessors, forked heads, substituted receipt
bytes, wrong reviewer keys, revoked or expired reviewers, rejected candidate eligibility, or
caution without explicit allowance fail closed.

## Beta catalog inclusion

Prepare the inclusion subject from the reviewed candidate, but delegate signing and publication to
the PR-293 authority. The coordinator never receives the catalog private key or private insert URI.

Only the beta channel is valid. Version 1, corrected version 2, and caution version 3 occupy three
strictly advancing revisions and editions. Each entry binds the exact bundle, signature, publisher,
submission, review receipt, decision, warning list, acknowledgement requirement, and entry digest.
Each edition also binds the digest of its exact signed catalog subject and detached-signature
sibling. These publication coordinates are separate from the entry digest so the entry commitment
does not depend circularly on the catalog bytes that contain it. The rejected initial version 2 is
absent.

The catalog authority's signed receipt must bind the active catalog key, PR-293 keyset digest, and
catalog authority digest. One primary and at least one control-plane-distinct mirror must report the
same subject and signature-sibling digests with passing, fresh observations. Stale, mismatched, or
partial observations remain `partial`. A locally staged candidate cannot assert publication.

Changing app version, bundle bytes, signature bytes, publisher key, review receipt, or warning
metadata requires a later revision and edition. No pilot path requests, signs, or publishes a
Stable-channel entry.

## Isolated-node runtime drill

Use a disposable or dedicated node with no production user's persistent data. The runtime receipt
must identify the existing `live-network-beta-smoke` collector and bind the exact summary file
name, raw-byte digest, and byte size. The verifier loads those exact bytes, applies the closed
collector schema, requires every release-candidate evidence row, and verifies app/catalog identity,
one of the three canonical port-bearing HTTP loopback endpoint shapes, redaction, and cleanup. A
digest written only inside the node receipt is not evidence. Intake `install-smoke` is structural
evidence and cannot satisfy this stage.

The node-side producer is
`.github/workflows/stable-1.0-third-party-app-pilot-runtime.yml`, not the read-only coordinator
job. It runs only on the protected `cryptad-third-party-pilot-node` self-hosted runner and requires
an operator-reviewed `cryptad-third-party-pilot-runtime` adapter whose exact executable digest is
bound at dispatch. Generic templates or an adapter that has not been reviewed and provisioned on
that isolated node are non-operational. The adapter must reuse the existing live-network collector,
perform the sequence below through the real AppHost and consent boundaries, and emit only the
closed observation and collector summary. The workflow first retains that immutable observation,
then signs the exact runtime receipt with the node attestation key in a separate protected step.
This ordering lets the receipt bind the observation artifact's Actions digest without a circular
self-digest.

For each catalog refresh, the adapter must record the exact app version, bundle digest, publisher
key, review status, catalog revision, catalog edition, entry digest, signed-subject digest, and
signature-sibling digest from the catalog-key-signed publication receipt. The caution refresh must
also retain the exact warning codes. A passing refresh name or a final-catalog digest reused for an
earlier edition cannot satisfy the runtime contract. Updating this closed projection requires a
newly reviewed adapter executable and a new dispatch-pinned adapter digest.

Before provisioning the node, the runtime producer derives the exact normalized artifact name from
the authenticated coordinator pilot, run, and run-attempt coordinates. It also requires the
downloaded execution contract to carry that same pilot id, repository, and source commit and to be
non-fixture, non-self-test evidence. A differently named or cross-pilot artifact is rejected before
the adapter receives node credentials.

The retained observation and node-signed receipt must include
`managed-daemon-product-attestation-v1`: the exact release id, integer build, source commit,
PR-291 protected-release root, product-distribution digest, effective
`stable-1.0-pilot-publisher-v1` AppHost policy, and observation time. The reviewed adapter must
derive those values from the exact distribution it launches and the managed daemon's packaged or
runtime identity. Copying the workflow checkout or `execution.json` values without verifying the
launched distribution is not an attestation. The verifier binds the product digest to authenticated
PR-292 closeout evidence and requires the daemon observation before the fresh collector execution.
The collector's public `node.version` and `node.build` fields remain redacted.

The retained observation and node-signed receipt also carry the exact normal Stable, PR-293
catalog, and dedicated pilot registry digests observed by the protected adapter. The adapter hashes
the same confined, symlink-rejected registry snapshots that it stages for the managed daemon. It
must not copy these observations from `execution.json` or the publisher approval. Runtime
verification compares all three observed digests with the contract and approval before checking
that the three trust roots remain distinct. Updating this observation shape requires review of the
adapter and a new dispatch-pinned adapter executable digest.

After the producer succeeds, pass its signed evidence artifact through the authenticated evidence
producer again before running the coordinator's `verify-runtime-drill` or `closeout` operation.
Closeout authenticates the runtime producer's repository, workflow, source commit, run, attempt,
observation artifact name and digest, protected job, and the required run and signing steps. A
node-signed JSON file that merely claims the coordinator workflow is rejected.

Perform the sequence exactly:

1. Verify the external key is absent from the normal Stable registry.
2. Install the approved dedicated pilot registry.
3. Add or refresh the authenticated beta catalog edition for version 1.
4. Install reviewed version 1 and verify app, version, bundle, publisher, review, permissions,
   sandbox, and app-data boundary metadata.
5. Confirm rejected version 2 is absent and blocked.
6. Refresh to the corrected version 2 edition.
7. Update to corrected version 2 and verify the exact subject and fresh review metadata.
8. Refresh to the caution version 3 edition.
9. Attempt the update without acknowledgement and verify it is blocked.
10. Record explicit consent through the real consent boundary.
11. Update to version 3 and verify warning codes and consent snapshot remain observable.
12. Roll back to the exact corrected version 2 bundle, key, review, and metadata.
13. Remove or restore the app and catalog without deleting pre-existing state.
14. Remove or quarantine the pilot registry and record the final clean state.

The collector records explicit Boolean state for a pre-existing install, whether it was running,
whether the smoke started a stopped app, and whether this run installed the app. Those values must
agree with the node-signed runtime receipt's initial-state claim. An originally running app requires
explicit evidence that the smoke stopped and restarted it. An originally stopped app that the smoke
started requires an explicit successful lifecycle stop or fallback restoration. Missing applicable
restore results are incomplete cleanup evidence and cannot reach `runtime-drill-complete`.

The signed runtime receipt also records whether the catalog existed before the drill. Cleanup must
restore the exact prior app and catalog conditions. It never includes a form password, browser
token, private URI, registry path, app data, fetched body, or scratch path.

## Certification commands

Run the implementation self-test:

```bash
python3 tools/release-certification/certify.py stable-third-party-pilot --self-test
```

For a protected evidence directory, run cumulative verification modes:

```bash
python3 tools/release-certification/certify.py stable-third-party-pilot \
  --mode preflight \
  --execution-contract build/pilot/evidence/execution.json \
  --evidence-dir build/pilot/evidence \
  --out-dir build/pilot/preflight

python3 tools/release-certification/certify.py stable-third-party-pilot \
  --mode verify-external-handoff \
  --execution-contract build/pilot/evidence/execution.json \
  --evidence-dir build/pilot/evidence \
  --out-dir build/pilot/handoff

python3 tools/release-certification/certify.py stable-third-party-pilot \
  --mode verify-review-cohort \
  --execution-contract build/pilot/evidence/execution.json \
  --evidence-dir build/pilot/evidence \
  --out-dir build/pilot/review

python3 tools/release-certification/certify.py stable-third-party-pilot \
  --mode verify-catalog-publication \
  --execution-contract build/pilot/evidence/execution.json \
  --evidence-dir build/pilot/evidence \
  --out-dir build/pilot/catalog

python3 tools/release-certification/certify.py stable-third-party-pilot \
  --mode verify-runtime-drill \
  --execution-contract build/pilot/evidence/execution.json \
  --evidence-dir build/pilot/evidence \
  --out-dir build/pilot/runtime

python3 tools/release-certification/certify.py stable-third-party-pilot \
  --mode closeout \
  --execution-contract build/pilot/evidence/execution.json \
  --evidence-dir build/pilot/evidence \
  --out-dir build/pilot/closeout
```

Fixture and self-test modes use the contract's fixed `evaluationTime` and remain deterministic.
Each operational invocation captures runner UTC once and uses that time for every key-lifecycle,
authorization, and receipt-freshness check in the cumulative verification. The retained
`evaluationTime` is preparation metadata: it is rejected when implausibly future-dated, but it is
not rewritten and does not expire the authenticated `execution.json` between protected jobs.

Every mode is path-confined, schema-validated, redaction-safe, and incapable of remote mutation.
Preflight through runtime verification are offline. Operational `closeout` uses a
protected `leumor` read-only token as `GH_TOKEN` to authenticate the protected root artifacts
against GitHub Actions. It receives no signing, publication, insert, or node mutation secret. Use
the example at
`tools/release-certification/manifests/stable-1.0-third-party-app-pilot.example.json` only to study
the shape. It contains non-production identities and null operational evidence.

The output uses separate evidence ids:

- `third-party-pilot.external-developer`
- `third-party-pilot.bundle-signature`
- `third-party-pilot.reviewed-install`
- `third-party-pilot.rejected-resubmission`
- `third-party-pilot.caution-consent`
- `third-party-pilot.catalog-publication`
- `third-party-pilot.update-rollback`
- `third-party-pilot.transparency`
- `third-party-pilot.redaction`

These do not replace the existing sample-oriented `third-party-intake.*` evidence.

## Closeout

Operational closeout additionally requires the exact retained PR-291 protected-release, PR-292
independent-reproducibility, and PR-293 catalog-authority Actions ZIPs, plus the small canonical
`stable-1.0-rc-freeze.json` member from the selected PR-291 RC artifact. PR-292's selected-RC record
binds the exact freeze-file digest; PR-291 and PR-292 must agree on the RC run, attempt, artifact,
freeze, and product identities. Closeout validates the complete freeze and derives the expected
catalog ID, channel, revision, edition, digest, detached-signature digest, and signer from that
authenticated freeze—not from the PR-293 result under verification.

The PR-291 and PR-292 summaries must be exact members of their authenticated artifacts; PR-292 is
checked with its canonical self-digest and provider-independence validator. Closeout also reads the
canonical PR-292 subject inventory from that same authenticated ZIP and requires its exact
byte-identical catalog and detached-signature rows to match the selected freeze. The exact PR-293
closeout ZIP is then checked with the existing catalog-authority closeout verifier. Repository,
workflow, commit, run, attempt, artifact name and digest, environment, conclusion, semantic roots,
release, build, source commit, operational state, independent result, catalog subject, and keyset
must match. Pass-shaped JSON and a digest declared only by the same execution contract cannot
satisfy closeout.

Closeout writes a machine-readable summary, Markdown report, and redaction result. The summary's
digest covers its derived state. It reports `operational=true` only when every required stage and
root passes and the contract is neither fixture nor self-test evidence.

Use a verified operational summary as an optional Phase 12 or future federated-catalog input. Do
not make historical Stable GA evidence depend retroactively on it. The existing known limitation
remains open until authentic operational evidence—not implementation or self-tests—supports a
separate governance decision.

## Stop conditions and recovery

Stop and retain only bounded diagnostics when any of these occurs:

- source or workload identity cannot be authenticated;
- a developer, workload, reviewer, catalog, or node signature fails;
- any role key overlaps another role;
- the handoff is stale, malformed, unsafe, or contains prohibited material;
- review assignment, pre-review digest, decision, resubmission, or transparency lineage differs;
- a rejected row appears in a candidate or catalog;
- caution warnings or explicit acknowledgement are absent;
- catalog revision, edition, keyset, primary, mirror, or signature sibling differs;
- installed app, version, bundle, publisher, review, permissions, sandbox, data boundary, consent,
  rollback, or collector summary differs;
- a pre-existing app or catalog would be removed;
- cleanup fails or the pilot registry remains active; or
- a public output contains private material, raw content, unbounded personal data, or a local path.

Do not edit a failed receipt into success. Correct the protected operation, produce a new signed
receipt with fresh immutable coordinates, advance the relevant catalog edition when the subject
changed, and rerun the side-effect-free verifier.

## Explicit non-goals

This pilot does not create a centralized store, redesign federated catalog trust, authorize silent
third-party updates, weaken consent, change sandbox policy, modify Stable trust roots, publish a
Stable entry, create a tag or release, or make Crypta rebuild or re-sign the external app. Completion
means only that the exact protected pilot lifecycle was authenticated. It is not Stable-catalog
promotion and is not a general endorsement of the developer or future app versions.

PR-295 federation may use the authenticated publisher identity, review receipts, beta-catalog
subject, and closeout from this pilot as explicit local evidence. It does not copy the handoff,
review, signing, or publication authority, and it does not automatically turn the pilot publisher
or reviewer cohort into global trust. Long-lived authorization remains scoped to an exact local
catalog/app policy. See
[stable-1.0-federated-catalog-discovery-and-trust.md](stable-1.0-federated-catalog-discovery-and-trust.md).
