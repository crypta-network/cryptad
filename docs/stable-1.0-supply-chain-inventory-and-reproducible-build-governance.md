# Stable 1.0 supply-chain inventory and reproducible-build governance

Use this guide to produce, compare, and verify the component, license, SBOM, and rebuild evidence
required for a Stable 1.0 maintenance or security-hotfix candidate.

This gate applies after the immutable Stable 1.0 GA root. It does not rebuild GA. A later
maintenance candidate introduces new bytes and must pass this gate before
`stable-maintenance` may authorize those bytes.

## Guarantee boundary

The supply-chain record answers four separate questions:

1. Which components and build materials were resolved for the exact source commit?
2. Which release subjects contain each component, including first-party apps and catalogs?
3. Are license conclusions complete and bound to those exact component identities?
4. Did an isolated verifier reproduce the declared candidate subjects under the policy-defined
   comparison rules?

No single file answers all four questions. A component inventory is not an SBOM, an SBOM is not a
license approval, and matching rebuilds are not publication. Promotion requires the complete
candidate-bound evidence set and publication requires a separately verified receipt.

## Authority and evidence classes

The policy keeps authoritative release evidence separate from informational discovery:

| Record | Authority | What it establishes |
| --- | --- | --- |
| Resolved dependency snapshot | Authoritative for the named Gradle configurations and source commit | Selected components, variants, dependency edges, artifacts, and content digests. |
| Release-subject inventory | Authoritative for the frozen candidate | Portable archives, platform packages, first-party app bundles, catalog and signature sidecars, and their exact digests. |
| Component inventory | Derived, candidate-bound authority | Canonical component identities, roles, classes, origins, and containment links. |
| License inventory | Derived, candidate-bound authority | Per-component concluded and declared licenses, evidence, overrides, and review status. |
| Stable supply-chain SBOM and binding | Derived, candidate-bound authority | A machine-readable component graph plus an exact binding to release subjects and the component inventory. |
| Build-material record | Authoritative for the protected build | Wrapper, toolchain, source, policy, dependency snapshot, external input, and build-recipe identities. |
| Builder receipt | Protected producer statement | Builder identity, source commit, workflow identity, resolution digest, task set, and payload-manifest digests. |
| Reproducibility result | Comparison authority | Which subjects matched exactly, which used an approved semantic comparison, and every mismatch. |
| Promotion summary | Maintenance-gate input | Whether the complete supply-chain policy passed for the exact frozen candidate. |
| Publication receipt and public observation | Protected publication authority and later verification | Which exact evidence assets were created or verified as already identical, and whether a fresh re-fetch found those same public bytes. |

IDE indexes, source scans, dependency-update reports, vulnerability scanner matches, and local
developer exports are informational until a protected phase binds them to the exact candidate.
They can find omissions and trigger review, but they cannot replace the records above.

## Canonical component roles and classes

Each component has one canonical identity and one or more closed roles: `runtime`, `build`, `test`,
`packaging`, or `publication`. The closed component kinds are `maven`, `gradle-plugin`,
`internal-module`, `vendored-binary`, `vendored-source`, `jdk-module`, `native`,
`first-party-app`, `web-asset`, `packaging-tool`, and `publication-tool`. Repeating the same
library under several release subjects does not create several component identities.

| Component kind | Typical role | Required identity material |
| --- | --- | --- |
| Maven module or Gradle plugin | runtime, build, test, or packaging | Group, module, selected version, variant attributes, artifact name, and SHA-256. |
| Internal module | runtime, build, test, packaging, or publication | Exact project identity, source commit, version, and output digest or containment mapping. |
| Vendored binary/source or native input | runtime, build, or packaging | Stable logical name, reviewed origin, immutable reference, and SHA-256; never an absolute path. |
| JDK module | runtime | Exact post-jlink module name, pinned Java 25 build, aggregate installation-set digest, and protected per-platform material binding. |
| First-party app or web asset | runtime or publication | App id/version or asset identity, content digest, containment subjects, and catalog/app binding. |
| Packaging/publication tool | packaging or publication | Immutable tool identity, origin, digest, and the subjects or publication roles it affects. |

Release subjects use a separate closed class vocabulary: `core`, `portable`, `runtime-image`,
`installer`, `updater`, `catalog`, `first-party-app`, `app-metadata`, `companion-artifact`, and
`publication-material`. Their required fields include the subject key, filename, digest, size,
component ids, reproducibility class, and any applicable payload, app, catalog, signature-receipt,
or package-metadata binding.

Every policy subject also has one closed evidence phase. `independent-builder` is limited to the
core JAR, portable and runtime-image archives, selected native installers, and seven first-party
app bundles. Only that exact selected set may appear in builder receipts or comparison results.
The current protected builder matrix authorizes the AMD64 DEB, RPM, DMG, and EXE installers.
Flatpak and Snap remain maintenance package-format vocabulary, but this supply-chain policy does
not authorize them as release subjects because it has no isolated builder and extraction receipt
for either format. A future reviewed policy edition must add those builders and comparison rules
before a governed candidate can select either package.

`authenticated-post-build` covers frozen updater/catalog/signature bytes and the publication
backend material that the current Gradle recipe does not regenerate. `derived-governance` covers
review metadata, release notes/checksums/provenance, and supply-chain companion records; those rows
use `not-a-product-subject` and remain exact-byte inventory/publication bindings rather than
synthetic reproducibility assertions.

Test and build-tool components remain visible but are not labeled as shipped runtime components.
Likewise, an internal project folded into `cryptad.jar` is mapped to that subject instead of being
reported as a separately shipped leaf JAR when packaging does not ship one.

A component with the `runtime` role may map only to a policy subject that carries an actual
packaged payload; release notes, checksums, provenance, and other governance companions cannot
stand in for product containment. Every runtime component must map to at least one present product
subject. Components with independently digestible shipped bytes—Maven and Gradle artifacts,
vendored binaries, native files, web assets, and first-party app payloads—must also match either the
exact subject digest or an exact payload-manifest entry digest. Cross-references in two JSON files
are not sufficient evidence that a component is present in the product.

## Deterministic Gradle resolution snapshot

Use the Gradle wrapper and Java 25. The release-relevant Gradle toolchains select
Adoptium/Temurin explicitly; when a matching installation is not available locally, the checked-in
Foojay resolver provisions it. This keeps compilation, jlink, jpackage, and installed-tree
fingerprinting on the same policy-selected distribution instead of accepting an arbitrary Java 25
installation. A local export refresh intentionally remains unlocked:

```bash
./gradlew exportStableSupplyChainResolution
```

The tasks write:

```text
build/stable-supply-chain/resolved-dependency-snapshot.json
build/stable-supply-chain/resolved-dependency-export.json
build/stable-supply-chain/build-material-inputs.json
```

Protected inventory, producer, and verifier jobs first download and authenticate the closed phase
bundle. It must contain exactly one confined reviewed `resolved-dependency-export.json` and one
confined reviewed `resolved-dependency-snapshot.json`; aliases, links, extra unreferenced files, and
paths outside the bundle fail. Only then do those jobs invoke the strict comparison:

```bash
./gradlew exportStableSupplyChainResolution verifyStableSupplyChainResolution \
  -PstableSupplyChainExpectedResolutionExport=build/stable-supply-chain-phase/resolved-dependency-export.json \
  -PstableSupplyChainExpectedResolutionSnapshot=build/stable-supply-chain-phase/resolved-dependency-snapshot.json
```

Tracked Gradle lockfiles remain digest-bound build materials, but their presence does not label the
whole multi-project resolution as locked. The current snapshot has no configuration-by-configuration
lock-coverage proof, so even a valid lockfile for one project or configuration cannot replace the
authenticated reviewed export. A future Gradle-locking authority would require a versioned schema
that proves complete coverage for every exported release, build-logic, plugin, and settings-plugin
configuration before the gate could accept it.

The no-property export is useful for producing bytes for review; it is not a protected strict
verification result. The two project properties are public-safe file identities, not JVM options,
and a protected run never substitutes newly generated output as its own reviewed expectation.

`exportStableSupplyChainResolution` resolves the policy-selected configurations through Gradle's
resolution model. It records selected component identifiers, requested-to-selected dependency
edges, variants, capabilities where relevant, artifact digests, project components, and file
dependencies. Records and arrays use stable keys and bytewise ordering. Host-specific absolute
paths, repository credentials, cache locations, timestamps, and Gradle daemon state are excluded.

`verifyStableSupplyChainResolution` is the strict gate. It rejects unresolved dependencies,
unapproved dynamic or changing selections, missing artifacts, duplicate canonical identities,
unsafe file dependencies, absent digests, and output that changes when canonicalized again. The
snapshot must cover the configurations named by policy; resolving only the root runtime classpath
does not silently satisfy app, build-tool, or packaging coverage.

The final build-material record cross-binds that snapshot's build-logic, plugin, and test-only
resolution digests as separate identities. It also binds both dependency-verification keyring
files (`verification-keyring.gpg` and `verification-keyring.keys`), rather than treating the
verification metadata file as sufficient on its own. A producer or verifier mismatch in any of
those identities is release-blocking even when the runtime component set is unchanged.

The canonical build epoch is the exact Unix timestamp of the authenticated source commit; a
candidate-supplied wall-clock value is rejected. Before any product task, every protected builder
installs only the closed environment variables `LANG`, `LC_ALL`, `SOURCE_DATE_EPOCH`, and `TZ` from
the authenticated material record. The attested handoff records their observed values rather than
repeating a later aggregation claim. `LANG` and `LC_ALL` must equal the selected policy locale,
`TZ` must be `UTC`, and `SOURCE_DATE_EPOCH` must equal the authenticated commit epoch.

Each execution also observes the installed Java runtime before building. `javaVendor` is
`java.vendor`, `javaVersion` is the Java specification version, and `javaBuild` is the canonical
Temurin build coordinate. Temurin may render the same coordinate in `java.runtime.version` with
the presentation suffix `-LTS`; only that exact optional suffix is removed before comparison.
Other suffixes and malformed versions fail closed. Encoding and normalized architecture are
recorded separately. The policy also pins the complete Temurin setup version rather than the
mutable Java `25` selector. Each builder hashes its actual `java.home` with
`crypta-jdk-installed-tree-sha256-v1`: sorted relative paths, regular-file digests and sizes,
directory records, and confined symlink targets, with no timestamps or host paths. The `release`
file has a separate byte digest, so normalizing the presentation suffix does not weaken exact
installation authentication. Special files, escaping links, case-fold collisions, oversized
entries, and unsafe Java-home roots fail closed.

Linux, macOS, and Windows installations are different byte trees, so the reviewed build-material
record carries one closed installation row per platform. Its `distributionDigest` is the canonical
digest of that exact sorted row set; it is not presented as an upstream archive checksum. The raw
Gradle toolchain export and pre-build Java observation must both match the relevant reviewed row,
and aggregation copies the observations into the builder receipt. Producer and verifier receipts
must therefore agree on the same platform installation bytes. Requesting Java 25 from a setup
action or repeating Java version strings is not itself toolchain evidence.

`inventoryJreModules` runs the generated runtime's `java --list-modules` after `jlink`. The
canonical component graph must contain exactly one `jdk-module` component for each resulting
module and map every such component to the selected runtime-image and installer subjects. The
requested `jdeps` root set is diagnostic build input; it cannot replace the complete module closure
actually present in the shipped runtime image.

`createJreImage` binds Gradle's up-to-date decision to the exact task-produced module list, the
normalized `jlinkCompression` value, the selected `jlink` executable, its `jmods` tree or Java 25
run-time module image, and the selected Java toolchain metadata. Current Temurin images support
linking directly from `lib/modules` and may omit `jmods`; older layouts use the explicit `jmods`
module path. A missing module source or module list fails closed. Changing any declared input
regenerates `build/jre` before packaging.

The exporter is evidence about Gradle resolution, not every release input. The policy separately
requires exactly five direct material identities: the Gradle wrapper distribution, the seedrefs
source archive, the Tanuki wrapper delta pack, and the AMD64 and ARM64 Windows wrapper binaries.
The final build-material record binds each both as `external/<name>` in `packagingInputs` and as a
closed `directInputs` row containing its digest, immutable origin, and immutability class. Builder
receipts repeat its origin, class, digest, status, and verification mechanism. Seedrefs uses a
full-commit codeload URL, and Windows wrappers use exact release-asset URLs; `master`, `latest`,
API release selectors, queries, fragments, alternate hosts, and short revisions block before a
network request. The wrapper distribution
is authenticated by `distributionSha256Sum` in `gradle-wrapper.properties`; the protected workflow
supplies the other four reviewed digests through the corresponding Gradle project properties
before any download or extraction and then re-exports the model to prove the bytes match. An
ordinary export without those reviewed values deliberately reports promotion-blocking materials.

JDK images, signing sidecars, first-party bundle outputs, and catalogs enter through the remaining
build-material and release-subject inventories. Mutable developer defaults remain available only
when no reviewed Stable digest was supplied.

Do not confuse the exporter's `cryptad-stable-build-material-inputs-v1` document with the final
`stable-1.0-build-materials-v1` record. `inputs.buildMaterials` always names the confined, attested
final record in the phase bundle; it must never point to the checkout-local generated
`build-material-inputs.json`. After strict resolution verification, the inventory job cross-checks
the live raw export digest, Gradle version and distribution URI, wrapper, version-catalog,
repository-configuration, verification-metadata, and verification-keyring digests across the raw
generated document, reviewed compact snapshot, and final build-material record. It then retains
the raw generated document as separately named, attested workflow evidence at
`stable-supply-chain/workflow-evidence/cryptad-stable-build-material-inputs.json`. The public
`build-materials` publication role remains the final record.

## Inventory, SBOM, and licenses

The unified command uses a `stable-review` manifest and writes engine-native records under
`<out-root>/<release-id>/stable-supply-chain/artifacts/legacy/`, with the common
`summary.json`, `report.md`, and redaction report at the component root:

```bash
python3 tools/release-certification/certify.py stable-supply-chain \
  --manifest build/stable-supply-chain-phase.json
```

`commands.stable-supply-chain.mode` is closed to:

| Mode | Purpose |
| --- | --- |
| `assemble-inventory` | Validate and join the resolution snapshot, component graph, release subjects, license evidence, overrides, and policy into canonical inventory, SPDX, binding, reverse-index, and build-material records. |
| `verify-inventory` | Revalidate those records against the primary payload manifests and fail on omissions, ambiguous identities, unbound subjects, or incomplete licenses. |
| `prepare-rebuild-comparison` | Authenticate producer and verifier receipts and freeze the exact comparison plan before candidate bytes are compared. |
| `compare-rebuilds` | Compare the isolated subject roots and payload manifests according to that plan. |
| `evaluate-promotion` | Bind inventory, rebuild, maintenance-freeze, and protected vulnerability evidence into the promotion summary. |
| `verify-publication` | Verify the publication plan, receipt, and independent public observation without publishing anything. |

The SBOM and license inventory use the component inventory's canonical ids. Overrides are narrow,
reviewed evidence: each binds one component id and SHA-256 to an SPDX expression, exact license
text and text digest, policy edition, and bounded rationale. An override does not suppress an
unknown component, change a component digest, or authorize an incompatible license. License texts
are content-addressed and deduplicated; local source paths and internal review material do not
enter public output.

`inputs.licenseTextRoot` is the repository root, `.`. That root is required because the reviewed
registry may bind the root `LICENSE` as well as notices below `docs/licenses/`. The closed evidence
projection recognizes only `LICENSE` and regular files below `docs/licenses/`; setting the root to
`.` does not make arbitrary repository files eligible as license notices. Symlinks, missing files,
paths outside those two locations, digest substitutions, and orphaned recognized notices fail.

The checked-in governance inputs are
`tools/release-certification/stable-1.0-supply-chain-policy.json` and
`tools/release-certification/stable-1.0-supply-chain-license-overrides.json`. Release subjects are
candidate-specific: the protected phase bundle supplies the manifest path for the exact
release-subject inventory. Do not check in a release-specific inventory or replace it with a
locally discovered file.

## First-party apps and catalogs

Every frozen first-party bundle is a release subject even when it is distributed through a signed
catalog instead of the daemon archive. Its inventory row binds the app id and version to the bundle
and manifest digests, bundle-signature and review-receipt digests, permissions, maintenance policy,
and app-data schema/migration identity. The separately frozen signing identity remains part of the
catalog/release trust evidence. Copied browser SDK and design-system assets are mapped to the
bundle that contains their bytes.

The protected producer and verifier both run `packageFirstPartyApps`. That task signs, verifies,
and then invokes the repository's deterministic `AppBundlePackager` for all seven apps. Signing
key material is available only as protected job environment input and is never placed in an
argument, handoff, inventory, or public artifact. Ed25519 signing and the canonical stored-ZIP
writer make the complete signed bundle a `byte-identical` subject; a differing signature sidecar
or ZIP byte therefore fails comparison instead of being normalized away.

The signed catalog is a separate release subject. Its catalog digest, detached signature, signer
id, revision, channel, and entry-to-bundle links must match the freeze. A catalog license display
field is metadata; it does not replace the reviewed license inventory or bundle content evidence.
Catalog, signature, and updater descriptor rows retain an exact `byte-identical` byte requirement,
but the repository build recipe does not currently regenerate them. `verify-inventory` is their
authenticated post-build evidence phase: it checks the actual frozen bytes and existing
signature/publication bindings, and promotion binds the resulting subject-inventory digest. They
are intentionally absent from both builder receipts and the reproducibility result. Moving one to
`independent-builder` requires a reviewed policy edition and deterministic repository producer.

## Isolated producer and verifier builds

`.github/workflows/stable-1.0-supply-chain.yml` is manual-dispatch only and accepts the closed
operations `inventory`, `producer-build`, `verifier-build`, `compare-evaluate`, `publish`, and
`verify-publication`. Dispatch it from the protected `release/<build>` or `hotfix/<build>` ref for
the exact source commit. The six engine modes remain side-effect-free; `publish` is a separate
workflow operation and is never enabled by a manifest mode or local CLI flag.

The protected maintenance input producer has two supply-chain-only intake phases.
`supply-chain-inventory` authenticates the initial inventory manifest and its actual subject
inputs; `supply-chain-prebuild` authenticates the distinct product-free builder recipe. Both use
the existing digest-pinned protected ZIP intake and attest every resulting file. The latter is not
an executable `prepare-rebuild-comparison` manifest: it deliberately omits both receipts until the
comparison job derives them from the completed authenticated builder artifacts.

The producer and verifier use separate jobs and fresh workspaces. Both use Java 25, the Gradle
wrapper, the strict resolution exporter, and the closed build recipe. Each authenticates the
reviewed raw resolution export and canonical snapshot before the build. Both pre-build downloads
are closed to the same five-input recipe: policy, resolution snapshot, component inventory,
subject inventory, and build materials, plus the reviewed raw resolution-export companion.
Builder receipts are prohibited before the builds. Subject roots, payload roots,
product archives, and installers are rejected for both roles. The producer first completes its
closed local build, then authenticates the existing maintenance `freeze-candidate` run, its
run-bound `stable-1-0-maintenance-frozen-...` artifact, the freeze record, and every attested file
under `freeze/assets`. Each frozen asset must match the subject inventory by canonical filename,
digest, size, signing receipt, and notarization receipt. Those immutable bytes are the producer
handoff wherever the maintenance freeze selected the subject; deterministic companion/app
subjects outside that selected set use the just-built bytes only when their digest and size match
the authenticated inventory. The verifier builds and digests its own subjects before any frozen
candidate byte can become available.

Each builder role is one protected workflow run with four closed executions. `portable-apps` runs
on the pinned Ubuntu image, `linux-installers` produces DEB and RPM payloads on Ubuntu,
`macos-installer` runs on the Intel macOS image, and `windows-installer` runs on the amd64 Windows
image. Every execution records its immutable hosted-runner image identity and digest, exact job,
source tree, Java vendor/version/build, Gradle wrapper/distribution, dependency-verification,
plugin/build-logic, task-set, canonical environment, direct-input, payload-manifest-set,
extraction-manifest-set, and resolution identities, plus its subject partition, handoff digest,
and attestation digest. The aggregate job downloads the four current-run artifacts
without merging their directories, verifies every file attestation, and emits a sorted
`builderExecutions` array. Missing executions, subjects routed through the wrong operating system,
duplicate subject paths, mutable `latest` runner identities, or an aggregate that drops the
per-platform handoff fail closed.

Workflow run ids and attempts are JSON integers throughout handoffs and builder receipts; a
numeric-looking string is rejected. The producer's installer rows must equal the exact frozen
candidate digest and size. A verifier's normalized installer container records its own digest and
size instead, because independently signed or packaged container bytes may legitimately differ;
only the subsequent policy-controlled payload comparison can accept that difference. The verifier
never inherits candidate signing or notarization receipts.

Each execution's `extractionManifestSetDigest` authenticates its role-specific extraction facts;
it is not a producer/verifier equality assertion. In particular, the DMG producer binds the signed
and notarized frozen container while the verifier binds its independently built unsigned
container. Cross-builder equality uses `payloadManifestSetDigest`, which contains the role-neutral
normalization rule, pre-signing payload digest, package metadata, normalized entries, and empty
ignored-path set. Changing that role-neutral view remains release-blocking.

DEB, RPM, DMG, and EXE evidence comes from the actual container on its native runner. The workflow
uses `dpkg-deb`, `rpm2cpio` plus `cpio`, `hdiutil`, or 7-Zip plus an MSI administrative extraction.
The full extracted installed tree is canonicalized with no ignored path. DEB, RPM, EXE, and the
independent verifier's unsigned DMG must contain their staged app-image root exactly. The frozen
Developer-ID-signed DMG uses the separate, closed `macos-code-signature-normalized` binding
described below; it is never treated as raw-equal to an unsigned staged app. The extraction record
binds the package digest, payload-manifest digest, binding method, extractor name and runner image,
full extracted payload digest, embedded staged digest, and candidate signing/notarization receipts
where applicable. Missing tools, excessive expansion, an unsupported EXE/MSI layout, multiple
possible embedded roots, or an unaccounted staged-root difference blocks the platform without a
staged-only fallback.

The verifier recipe is validated before any Gradle build with the canonical supply-chain schemas
and semantic validators. This is an exact pre-build recipe validation, not an early reproducibility
claim: `prepare-rebuild-comparison` cannot run until both final builder receipts exist. The recipe
has exactly the policy, resolution snapshot, component inventory, subject inventory, and build
materials. It cannot contain either builder receipt, a primary or verifier subject root,
payload-manifest root, comparison result, publication record, product archive, or installer.

Every handoff names the repository, exact workflow path and revision, protected source ref, source
commit, run and attempt, artifact name, Actions artifact digest, and subject attestations.
`compare-evaluate` accepts separate original producer and verifier run, attempt, artifact-name, and
artifact-digest coordinates. It downloads those original artifacts directly, authenticates each
run and exact Actions artifact through the GitHub API, and re-verifies every original file
attestation. It then derives the formal builder receipts from those verified bytes, inserts them
into a new authenticated manifest, and only then invokes the side-effect-free CLI. A receipt in a
pre-build phase bundle is rejected and cannot replace the original artifacts or their
attestations. Artifact names, digests, successful job status, or a repackaged receipt alone are not
provenance.

All component-execution and aggregate builder artifact names include the GitHub run attempt. The
aggregate accepts only the four artifacts from its current attempt and checks the run id and
attempt inside every handoff. After a builder failure, use **Re-run all jobs**; a failed-jobs-only
rerun intentionally lacks a complete current-attempt set and fails closed instead of mixing
attempts.

Promotion evaluation also treats the Stable vulnerability summary as protected input. The phase
bundle contains the fixed summary, successor binding, provenance, and sealed-successor files. The
workflow authenticates those files, opens the sealed handoff into a mode-`0700` directory below
`RUNNER_TEMP`, byte-compares the opened summary with the fixed manifest input, and verifies the
current protected tip. Only the external root and six nonsecret tip identities cross through the
job environment; the handoff key remains step-scoped and the protected files never enter the
public comparison output.

Exact-byte equality is the default. A semantic comparison is allowed only for a policy-named
subject class with a canonical normalizer and an output digest in the frozen comparison plan. The
result records both original digests and normalized digests. Unlisted differences, missing
subjects, extra subjects, archive aliases, signatures in a supposedly unsigned comparison set, or
normalizer failure block promotion.

JAR, ZIP, TAR, app-ZIP, and publication-wheel content rules additionally inspect the exact subject
bytes entry by entry. Their canonical manifests bind normalized relative paths, kinds, SHA-256,
sizes, mode classes, symlink targets, component mappings, container metadata, bounded expansion,
and nested-archive depth. Duplicate or case-fold-colliding paths, traversal, escaping links,
special files, AppleDouble/macOS metadata, malformed nested archives, or a component whose exact
artifact bytes are absent fail before rebuild comparison. Installer payload manifests remain
platform-produced authenticated views. DEB, RPM, and EXE require raw staged containment. A verifier
DMG also requires raw containment before its normalized pre-sign view is emitted. The signed DMG
uses the exact policy-defined code-signature transition while the complete published container
digest and existing signing/notarization receipts remain separate exact authorities.

### Signed and notarized macOS packages

`amd64.dmg` uses `crypta-dmg-payload-v2`; the candidate cannot select another normalizer or add an
ignored path. The candidate execution completes its own unsigned staged build before downloading
the authenticated maintenance freeze. It then binds the selected DMG by exact filename, size,
SHA-256, signing-receipt digest, and notarization-receipt digest, mounts those immutable bytes
read-only, locates exactly one `Crypta.app`, and requires `/usr/bin/codesign --verify --deep
--strict` to pass on that mounted app. The verifier receives no frozen candidate bytes or receipts
and must prove that its independently built unsigned DMG contains its raw staged app exactly.

The candidate mounts both its already-built local unsigned DMG and the frozen signed DMG. The local
mounted app must equal the pre-download staged app exactly. The two complete mounted roots must
then have the same non-signature path set, kinds, modes, symlink targets, and non-code file bytes;
top-level links, backgrounds, package metadata files, and every other path outside `Crypta.app`
remain part of the comparison. An addition, deletion, or change is accepted as signature material
only below the one exact app prefix and only when it is one of the three policy-named structures:
`_CodeSignature` directory, `_CodeSignature/CodeResources` regular file, or the legacy
`CodeResources` symlink whose target is exactly `_CodeSignature/CodeResources`. Every such entry is
listed with its raw before/after digest, size, mode, target, and change kind. These entries are
accounted for; they are not ignored.

Every other differing regular file must be a recognized thin or fat Mach-O. The workflow copies
both versions into a mode-`0700` temporary directory and invokes the fixed Apple `codesign` tool to
remove signatures from those copies. It records the original digests, signed states, stripped
digest, and stripped size, and requires the stripped bytes to be identical. Failure to classify a
Mach-O, remove a signature from a copy, or reproduce the same non-signature bytes blocks the
release. The staged app, mounted app, and DMG are never modified. The emitted payload comparison
view is the complete sorted local mounted-DMG tree with only recognized Mach-O digests and sizes
below the app prefix replaced by their signature-stripped-copy values. No outside-app entry is
populated from the frozen mount or removed from the view. Producer and verifier must reproduce
that same full view.

Candidate evidence additionally requires nonempty, sorted, unique code-object and signature-entry
sets, strict mounted-app verification, and exact frozen DMG, signing, and notarization bindings.
The verifier evidence cannot claim mounted Developer-ID verification and carries no frozen receipt
digests. The full signed DMG remains the publication subject; this comparison neither strips its
signature nor substitutes rebuilt bytes for the release artifact.

## Vulnerability reverse index

The component reverse index maps canonical component ids and digests to daemon archives, platform
packages, first-party bundles, and catalog entries. Protected vulnerability intake uses this index
to identify candidate subjects that may contain an affected component. It does not set severity,
embargo, exploitability, or remediation authority.

An `evaluate-promotion` run consumes only the redaction-safe, candidate-bound vulnerability
summary required by policy. It must set `execution.evaluationClock` and authenticate the fixed
`stable-1.0-vulnerability-summary.json` protected handoff, including its sealed producer bytes,
producer provenance, expiry, and the freshly observed current ledger-tip identity. A raw
self-digested summary, an expired summary, or a summary from a superseded ledger edition blocks
promotion. Authoritative case records, reporter identity, exploit material, raw advisory drafts,
and the protected ledger remain inside the vulnerability workflow. See
[Stable 1.0 vulnerability intake and coordinated disclosure
operations](stable-1.0-vulnerability-intake-and-coordinated-disclosure-operations.md).

## Maintenance and publication gates

`stable-maintenance` requires the passing supply-chain promotion summary for the exact source
commit, build, candidate-freeze digest, subject set, and immediate predecessor. Routine maintenance
and security hotfixes use the same non-waivable identity, inventory, license, redaction, and
rebuild-authentication rules. A hotfix may narrow its package matrix only through the existing
affected-package proof; it cannot omit an affected subject from the reverse index or SBOM.

The summary's sibling provenance is accepted only after the protected maintenance job has checked
the exact Actions run, artifact digest, and GitHub/Sigstore attestation and then authenticated the
closed provenance bytes with a dedicated domain-separated HMAC. The consumer receives
`CRYPTAD_STABLE_SUPPLY_CHAIN_HANDOFF_KEY_BASE64` only through its protected step environment. The
MAC, summary, and provenance all bind the exact candidate commit, and generic release
certification independently compares that commit with `git rev-parse HEAD`; asserted booleans or
caller-supplied report metadata are not authentication.

Preparation, comparison, promotion evaluation, publication, and publication verification remain
separate. `publish` is the only mutating operation. It runs only in the protected
`stable-1.0-supply-chain-publication` environment and is the only job in this workflow with
job-scoped `contents: write`. The ordinary inventory, producer, verifier, comparison, and
publication-verification jobs retain read-only contents permission and receive no publication
credential.

The publish dispatch consumes the exact attested, promotion-ready comparison handoff and the exact
reviewed `stable-1.0-maintenance-publication-backend` wheel. It authenticates the protected source
branch and commit, annotated `v<build>` tag, existing non-draft GitHub Release, phase run and
attempt, artifact digest, every phase-file attestation, backend producer run and source commit,
wheel artifact and byte digest, wheel attestation, signer workflow, and the fixed entry point
`cryptad_stable_maintenance_backend:supply_chain_factory`. The GitHub Release must already have
been created by maintenance publication; this operation cannot create or change a tag, Release
body, catalog, CoreUpdater descriptor, or latest-maintenance pointer.

The publication plan is closed to exactly eight public roles:

- `build-materials`;
- `component-inventory`;
- `component-reverse-index`;
- `license-inventory`;
- `release-subject-inventory`;
- `reproducibility-report`;
- `sbom`; and
- `supply-chain-summary`.

Before the first upload, the protected adapter verifies every local filename, URI, size, and
SHA-256 and checks every existing asset. An absent asset may be uploaded once and is recorded as
`created`. An existing asset is accepted only after an authenticated re-download matches exactly
and is recorded as `verified-existing`. Duplicate names, an incomplete or extra role set, or any
conflicting existing byte stream fails without deletion or overwrite. A race that prevents an
exact upload fails; it is never repaired by replacing the public asset.

The authenticated maintenance publication plan carries these eight rows separately as
`supplyChainCompanionAssets`. Maintenance Release observation accepts an absent, partially
published, or complete companion suffix only when every observed companion has the planned name,
size, and SHA-256. Maintenance never uploads those rows and their presence never proves
`stable-supply-chain.publication`; that evidence still requires the supply-chain publication
receipt and fresh public observation. Any Release asset outside the maintenance asset set and this
exact companion suffix remains a conflict.

Publication verification independently reconstructs each role's canonical filename and exact
`https://github.com/crypta-network/cryptad/releases/download/v<build>/<filename>` URI from the
checked-in policy. A plan, receipt, and observation that agree with each other at another HTTPS
origin, tag, path, or filename still fail.

`LEUMOR_GITHUB_TOKEN` exists only in the protected publication environment. The job authenticates
its `/user` result as exactly `leumor` before backend construction and supplies the secret only via
the step environment; it is never interpolated into a command-line argument or serialized into
the receipt. The backend emits a canonical receipt, immediately re-fetches all eight public assets,
and emits a fresh canonical observation. The workflow stages the receipt, observation, exact plan,
promotion summary, and a closed `verify-publication` manifest as one attested immutable handoff.

`verify-publication` consumes that supply-chain-signed handoff, validates the receipt and public
observation through the side-effect-free engine, and reports whether they match. It has no
publication token and cannot upload release assets, create a tag or GitHub Release, update a
catalog, or mutate CoreUpdater state.

Do not say an inventory or SBOM was published until the protected publication receipt and the
independent public observation both pass. Do not say a build is reproducible when only one build
ran, the verifier was given producer bytes before its build, a comparison was skipped, or the
result contains an unresolved mismatch.

## Redaction and public artifacts

Public records may contain component coordinates, versions, public upstream URIs, hashes, license
identifiers and texts, release-subject names, public catalog/app identities, builder workflow
identities, and comparison results. They must not contain:

- repository, Gradle cache, toolchain, signing, staging, or runner absolute paths;
- credentials, tokens, private keys, private insert URIs, authorization headers, or environment
  dumps;
- private vulnerability records, reporter data, exploit details, raw incident artifacts, or
  embargo-only package scope;
- raw app data, app tokens, browser sessions, review private material, or signing commands;
- unredacted build logs or command lines that may contain protected values.

Publish only the policy-approved projections. Builder workspaces, raw dependency metadata,
license-review notes, and protected vulnerability bindings remain protected even when their
digests appear in the public provenance record.

## External verification and limitations

An external verifier should:

1. authenticate the exact workflow and source-commit attestations;
2. validate the component, license, SBOM, binding, build-material, and subject schemas;
3. recompute every published file digest and SBOM-to-subject binding;
4. confirm the promotion summary selects those exact digests;
5. compare the public observation with the publication plan and receipt; and
6. check the Stable maintenance publication receipt before claiming the candidate was released.

The gate improves traceability and detects differences under its declared build recipe. It is not
a proof that an upstream project is benign, that every vulnerability is known, that license
metadata is legal advice, or that builds on different operating systems must be byte-identical.
Gradle verification, pinned inputs, protected runners, attestations, review, sandboxing, and
vulnerability response remain separate controls. A local successful run is useful diagnostic
evidence but is not a protected producer, verifier, promotion, or publication receipt.

The macOS result is intentionally narrower than byte reproducibility of the signed DMG container.
It proves that two isolated builds produce the same normalized pre-sign app view and that the exact
frozen signed app differs from the candidate execution's staged app only through the closed Apple
code-signature transition. Notarization tickets, filesystem-image identity, signature timestamps,
and the complete signed DMG digest remain separately authenticated. A toolchain change that
`codesign --remove-signature` cannot reverse exactly, an unsupported Mach-O form, a non-code byte
difference, an unexpected signature-resource structure, or a failed mounted signature check is a
release blocker. This evidence must not be described as byte-identical DMG reproduction.
