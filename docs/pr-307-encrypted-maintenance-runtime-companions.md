# Encrypted maintenance runtime companions

PR-307 carries selected-federation runtime metadata from native verification through maintenance
freeze v3, exact artifact retention and original product admission. It is internal evidence
transport within the existing maintenance workflow. It does not authorize release publication,
add apps to a Stable role, or establish protected execution and Phase 12 completion.

## Integrated source and audit

Work started from clean `develop` commit `1dc69847ea86e61db2d674e05a09b6b5150ae27b`, tree
`d1ec28ae4445d394adfe12835f6f308f8e4dc528`. GitHub PR #1408 merged at
`2026-09-13T10:25:05Z`; its final head `8e51038b45421971f245567e241c3df933347741` has the same
tree as that squash commit. Its original base was `214f863bc166412cb8a9e657dbb41fc4aed46c84`.
The initially planned `22cb0d4` and `0d38bd1` heads are not the implementation base.

At the source requery, final-head Java CI, exact packaged runtime integration, release-certification
self-tests, SonarCloud and the Production Beta dry-run were successful. Production Beta publication,
extended interop and performance execution were skipped. Those checks are predecessor evidence;
they do not validate PR-307.

| Owner | Audited gap | Prospective change | Required evidence boundary | Mandatory regression |
| --- | --- | --- | --- | --- |
| `maintenance_runtime_metadata` | Selected cohort v2 and inventory v4 cannot enter plaintext runtime output | Explicit private producer and native re-verification | All five original runtime members remain private | Real signed native v4/v3 producer and canaries |
| Freeze schema | v2 identifies a plaintext manifest | Separate closed v3 with sealed descriptor | Existing public asset roles/checksums unchanged | v1/v2 dispatch and unchanged public roster |
| `maintenance_runtime_companion` | Selection CMS purpose cannot authorize maintenance transport | Fixed maintenance policy and bounded AEAD transport | Ciphertext integrity is not original authority | Real CMS randomness, CBC/tag/trailing/key rejection |
| `cross_version_product_admission` | Runtime files are materialized before individual member attestations | Authenticate fixed ciphertext member before opening | No plaintext digest enters attestation lookup | Original member ordering and substituted authority |
| Runtime transfer/workflow | Recursive copies could retain cohort/selection inputs | Fixed rosters and public-safe input marker | Approved internal artifact retention only | Exact handoffs, missing/mutated bytes and provider intake |
| Supervisor and measurement | Shallow filtering exposes private bindings and hashes | Allowlisted public identities, owned private service state, measurement v4 | Private native relations are recomputed, never publicly hashed | Private service substitution and outward hash canaries |
| Phase 12 | Offline byte checks cannot admit selected native context | Explicit collector capability; offline missing-proof blocker | No implicit network, keys or executable authority | Offline blocker, typed context lifetime and v5 chain downgrade |

## Format and order

The retained original freeze tree is:

```text
freeze/
  stable-1.0-maintenance-candidate-freeze.json
  checksums.txt
  assets/<existing public payloads>
  runtime/runtime-companion.json
  runtime/runtime-companion.cms
```

Freeze v3 retains the original product/package/catalog/signature asset schema. Its `runtimeMetadata`
identity hashes the exact descriptor bytes. The descriptor identifies the fixed maintenance purpose,
selected-federation mode, policy identifier, epoch and exact ciphertext name, size and SHA-256.
Neither outer file identifies apps, selection generations, scope/cohort commitments, original
projection coordinates or private plaintext member digests.

The encrypted container is canonical JSON with an exact five-member map. Each member contains its
size, digest and base64-encoded original JSON bytes. There are no recursive archives or arbitrary
member names. The members are `runtime-subjects.json`, `snapshot.json`, `baseline-registry.json`,
`projection-inventory.json` and `native-admissions.json`. Original inventory bytes come from
`AuthenticatedProjection.original_bytes()`; serialization is not substituted for original identity.

The private context binds release/build/source, public asset-set/checksum identities, original
producer context, a new preparation UUID/time, and the fixed recipient policy/epoch. Its manifest
binds the portable archive and contained executable separately, exact API snapshot and full baseline
registry, complete approved cohort, scoped original projection/native declarations, tools and JDK.
Platform API baseline 1.0 remains contract 19. Original upstream app producer identities retain
their separate meanings; tool, app, projection and candidate SHAs are not required to be universal
equals.

```text
original products + provisioned private selection
  -> authenticate original app/projection/tool inputs
  -> exact packaged API export and scoped native verification in private scratch
  -> complete deterministic private runtime set
  -> randomized CMS encryption once
  -> final freeze commits exact descriptor/ciphertext after preparation
  -> original artifact and member attestations
  -> exact prepare/validate/publication handoffs
  -> original member verification before private opening
  -> full native/original re-verification
  -> owning product capability and existing bounded consumers
```

The inner container does not contain the final freeze digest. The final freeze binds the ciphertext;
original outer admission binds that freeze and original workflow attempt. Preparation must finish
before `frozenAt`, so the graph has no self-digest cycle.

## Provisioning and stage access

A selected freeze's `maintenanceRuntimeInputs` directory contains exactly this public-safe marker:

```json
{"schemaVersion":1,"mode":"selected-federation"}
```

It cannot contain caller-selected coordinates, cohort, scoped registries or keys. Legacy plaintext
input construction still rejects selected cohort v2. Private provisioning supplies the existing
root-owned `app-subject-cohort.json`, approved tools/JDK, original encrypted selection and inventory
authorities, and the fixed records below under `/etc/cryptad-certification/`:

| Record | Purpose |
| --- | --- |
| `maintenance-runtime-projection.json` | Closed original projection coordinates used before freeze |
| `maintenance-runtime-source.json` | Closed original freeze coordinates and exact `freezeDigest` for protected maintenance validation |
| `maintenance-runtime-recipient.json` | Closed active maintenance purpose/policy/epoch, certificate digest and validity interval |
| `maintenance-runtime-recipient.pem` | Approved operational RSA recipient certificate |
| `maintenance-runtime-recipient.key` | Recipient private key, root-owned mode 0600, only at private resolvers |

The selected freeze invokes the fixed source-owned `maintenance_runtime_production.py` through
noninteractive sudo, preserving only `GITHUB_ACTIONS` and `GH_TOKEN`. It opens the provisioned
projection pointer and encrypted original inventory under root authority, with a new root-private
scratch directory. Only the inspected descriptor/CMS roster returns to the invoking runner's
ownership; recipient keys and plaintext do not. The original selection decrypt key is required at
this stage even though maintenance companion creation itself needs only its encryption certificate.

The projection pointer follows the existing root-owned cohort reader policy; only the approved
runner group may read a group-readable pointer. Source selection and recipient private key remain
owner-only. The protected selected validation wrapper runs under the owning root authority, with
only the existing explicitly named original-authentication and evidence-verification environment
values. It does not invoke the publication backend. The ordinary offline `certify.py` engine cannot
create this capability from JSON or silently acquire keys/network access.

Recipient policy fields are `schemaVersion`, `purpose`, `policy`, `epoch`, `certificateDigest`,
`notBefore`, `notAfter` and `status`. Purpose is `stable-maintenance-runtime`, policy is
`maintenance-runtime-v1`, and only `status=active` admits an operation. Provisioning must approve an
operational recipient identity; personal/contact identities are not approved recipients. The build
does not generate production keys or certificates, install real policies, select alternate paths,
or borrow app, Mail, catalog, reviewer or recovery keys.

| Stage | Ciphertext handling | Private authority/key access | Public behavior |
| --- | --- | --- | --- |
| App-product producers | Existing signed handoff | Existing scoped app/catalog signing authority | No new publication |
| Freeze | Encrypts once; installs exact closed roster | Root original resolver uses existing selection decrypt key; maintenance encryption certificate; confined native verifiers | Existing public products unchanged |
| Prepare authorization | Retains original complete freeze | Root private resolver authenticates originals, opens and reruns native verification | Sanitized candidate artifact only |
| Validate authorization | Retains original complete freeze | Same explicit original private resolver | No publication |
| Publication preflight/retry | Rechecks exact committed companion through authenticated authorized handoff | Authorization producer owns prior native validation; backend gets no decrypt key/context | Existing plan assets only |
| Runtime admission | Authenticates original freeze/member before opening | Private original resolver and bounded native verification | Safe product/ciphertext identities |
| Supervisor service | Reopens root-owned service-private admission state | Existing `cryptad-soak` group; no key or original-provider network | Safe activation and reports |
| Measurement/Phase 12 | Refers to exact frozen ciphertext | Explicit authenticated collector reopens native context | Safe measurement identities; broad rows stay blocked |
| Successor/hotfix follow-up | Existing immutable freeze relationship | Existing maintenance authority | No companion in public successor payload |
| Transparency renderer | Existing allowlisted public facts | No implicit private resolution | Cannot turn ciphertext retention into public publication authority |

Publication consumes the authenticated prepare/validate chain and verifies retained sealed bytes;
it does not rerun a key-bearing validator inside the provider. If a separate caller reruns the
maintenance engine, it must supply an already authenticated in-process private context under the
owning wrapper. Missing context is a blocker. Public rendering never gains a decrypt capability.

## Cryptographic and filesystem limits

The maintenance wrapper narrowly reuses the fixed CMS command construction from
`federation_selection`. It uses `/usr/bin/openssl`, binary DER and explicit AES-256-GCM. The
maintenance path additionally checks OpenSSL's parsed authenticated-enveloped shape, a single RSA
key-transport recipient, no unbound optional fields, and exact DER re-encoding equality. The latter
rejects trailing bytes that OpenSSL decryption alone accepts. Cipher, provider, engine, command and
key paths are not dispatch options.

Installed OpenSSL 3.5.7 was exercised locally. [OpenSSL CMS documentation](https://docs.openssl.org/3.5/man1/openssl-cms/)
describes the command and explicitly leaves recipient revocation checks to the application.
[CMS authenticated enveloping](https://docs.openssl.org/3.0/man3/CMS_EnvelopedData_create/)
explains AEAD content handling. A recipient key supplies confidentiality access, not producer,
selection, signing, publication or Phase 12 authority. Original workflow attestations establish
producer provenance under the [GitHub attestation model](https://docs.github.com/en/actions/concepts/security/artifact-attestations);
they are not independent audits of runtime behavior. [Offline attestation verification](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/verify-attestations-offline)
requires explicitly retained proofs and trusted roots.

Bounds are 2 MiB per private JSON member, 16 MiB for the container/ciphertext and process output
files, JSON depth 32/count 32,768, fixed member count five, fixed subprocess deadline 60 seconds,
and OpenSSL virtual address space 256 MiB under `/usr/bin/prlimit`. OpenSSL's textual CMS inspection
has a separate 128 MiB bounded output because it includes encoded ciphertext. Native package and
app verifiers retain their owning archive/process budgets and use confined mounts without
recipient key access.

Reads reject links, multiple hard links, changing identities and unexpected files. The fixed member
map excludes traversal, filename aliases, nested archives and sidecars. Plaintext is parsed only
after authenticated decryption succeeds. Native results are regenerated from original signed
sources and compared with retained metadata; encrypted `nativeAdmission=accepted` JSON is not an
authority. Scratch directories are owner-restricted and lifetime-bound. Cleanup limits retention;
it does not promise secure erasure from memory, swap or arbitrary filesystems. Interrupted service
state is private reconciliation material, never a success receipt.

Ciphertext length, timing and CMS recipient identifiers remain visible. Internal encrypted evidence
is not anonymous and is not automatically approved for GitHub Release, Pages, USK or public uploads.
No global `.cms`, digest or path-based redaction exemption is added.

## Compatibility and retries

Freeze v1 retains app-free historical semantics. Freeze v2 retains the fixed public-safe plaintext
runtime set and ordinary inventory v2/v3 meanings; inventory v4 remains rejected there. Only freeze
v3 with the maintenance companion type can reach selected private admission. Native declarations
v1/v2 and selected v3 retain separate meanings. Mail remains experimental, and the shipped Stable
seven and each startup role remain unchanged.

Encryption is randomized. Two new preparations can produce different ciphertext for identical
plaintext. Once frozen, every copy/validation/retry uses the exact committed bytes. Re-encryption,
rewrapping, a different epoch or a missing member cannot repair an old freeze. Public product
reproducibility remains distinct from encrypted evidence identity. Historical key/policy retention
is an explicit operational prerequisite: a missing, expired or revoked policy/key blocks opening;
it never authorizes plaintext fallback, current-key rewriting or synthetic production keys.

Sealed authorization report v5 authenticates original products before selecting its format. Its
public selection identity commits a random operation UUID and public plan/service facts. Exact
private configuration and authorization commitments remain in root-owned mode-0600
`runtime-authorization.json`; retries retain its original bytes. Activation v2 excludes private
configuration/authorization hashes. The root-owned, service-readable runtime product record carries
those bindings privately, and the service rechecks them without decrypt keys or network access.
Successful finish removes owned private state; interrupted operations require reconciliation.
Execution still expires at the activation deadline. A later root-owned `finish` can inspect the
stopped run through a separate two-minute terminal evidence capability, bound to the same activation
and boot. It rechecks stopped service state at every private read and after the final journal
snapshot; it cannot admit further service execution. The validation wrapper inspects confined inputs
without creating output, leaving fresh run-root/marker initialization to the normal certification CLI.

Supervisor report v5 carries measurement v4 for sealed subjects. Measurement v4 replaces private
manifest/matrix hashes with exact descriptor/CMS identities while deriving native status privately.
PR-306 scheduler/resource components retain their existing causal and reviewed-baseline checks.
Ciphertext identity alone leaves native subject admission blocked and proves no executed workload.

## Local validation and Phase 12

Build native prerequisites through the supported graph:

```bash
./gradlew :platform-devtools:installDist assembleCryptadDist
PYTHONPATH=tools/release-certification python3 -m unittest \
  cryptad_certification.tests.test_pr307_product_consumer_integration
python3 -m unittest discover -s tools/release-certification/protected -p 'test_*.py'
python3 tools/release-certification/certify.py stable-maintenance --self-test
python3 tools/release-certification/certify.py phase-12-closeout --self-test
```

The ordinary Linux native CI lane includes PR-307 and fails if required native tests are skipped or
empty. Private native test roots and logs are not added to upload globs. Real CMS/native integration
is separate from mock schema/transport tests and from protected hosted execution. Original-provider
attestation transport and the prior selection-envelope fixture remain synthetic test seams; the
maintenance CMS and native signed projection/export/re-verification execute for real.

The fixed assessment cutoff is `2026-09-13T10:30:00Z`, with separate
`build/pr307-phase12-before` and `build/pr307-phase12-after-final` roots. Both assessments report
49 mandatory requirements, 47 unresolved, `phaseDecision=incomplete`, `phaseComplete=false`.
The implementation changes only the supported encrypted runtime admission/consumer dimension.
Historical requirement IDs, clocks and public repository statements remain intact; no operational
receipt, review approval, elapsed campaign duration, publication or activation is inferred.

Local verification passed the supported distribution build and full Gradle test suite (4 minutes
33 seconds; 469 tasks, 110 executed). No Java sources changed. Existing compiler/deprecation
warnings remain (98 compiler warnings); this run is not a fresh all-clean static-analysis result.
JUnit reports contain 17,350 tests, zero failures/errors and 10 platform/optional-test skips. Protected discovery
passed 177 tests without skips. The real PR-307 native/CMS integration passed one test without
skips, including the confined native exporter and protected validation capability. The PR-304/305
real native consumer regressions passed three tests without skips (201.618 seconds). The existing
PR-306 packaged scheduler and borrowed-supervisor regressions passed both tests without skips
(256.407 seconds). Existing
maintenance, backport, RC/GA, supply-chain, transparency, platform API, federation, cross-version
and Phase 12 self-tests were also run; final Phase 12 self-tests passed 184 tests.
Assessment recomputation passed, and `--require-complete` returned exit 2 as required. Local original-provider test transports are not authentic
hosted operational receipts.

The private native verifier uses the existing single provisioned cohort and its exact release/source
context. A plan that independently opens several sealed releases needs the appropriate approved
original native context for each; this change does not introduce an automatic context registry or
policy selector. Missing historical recipient material or native authority remains a blocker.

The next bounded dependency remains authenticated runtime-baseline approval and scoped performance
consumption. PR-306's baseline is measured-but-uncompared, with missing original approval and an
insufficient reference repetition count. Older latency bytes need recollection with the corrected
driver. Full native pending-key backlog, complete Trust Graph/import budgets, normal-profile
throughput, full catalog/runtime matrices, 24/72-hour evidence, Mail recovery, independent review,
protected operations and public deployment remain separate requirements. This work does not begin
Phase 13 or complete the nine broader maintenance rows.
