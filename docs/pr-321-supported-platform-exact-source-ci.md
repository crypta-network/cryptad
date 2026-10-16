# PR-321 supported-platform tests and exact-source CI

This runbook describes the supported-provider verification, selected-source discovery and original CI
report producer/consumer changes in PR-321.

The work starts from PR-320's integrated product at commit
`82fbe160454cde9cce821d1d0acf305314036235`, tree
`c9c97be3836ff35d0e03cb4eef5d6be615f3b645`. PR-320's final head
`dc5f9c7e6dbc06daedc33386c56a5a719fea7851` has that same tree. Its earlier planning head and
provisional test merge do not identify this integration. The current changes are working-source
evidence until committed and observed by the original hosted jobs.

Use Java 25 or later, the checked-in Gradle 9.7.1 wrapper and checksum, Python 3, and the selected
Node/browser tooling. Run Gradle sequentially in one checkout. The repository owns daemon,
parallelism and JVM settings in `gradle.properties`.

## Support owners and execution scope

The Java API/core and filesystem tests belong to their owning Gradle source sets. Distribution and
installer behavior remains root-owned; the [packaging reference](../.agents/skills/cryptad-packaging/references/layout-and-wrappers.md)
and [installer reference](../.agents/skills/cryptad-packaging/references/jpackage.md) define the product
boundary. A provider lane observes its actual host architecture and filesystem; its result cannot
stand in for another host or an installer acceptance run.

| Scope | Existing owner and selected verification | Applicability and execution limit |
| --- | --- | --- |
| Linux Java/core/API and analyzers | Reusable `build.yml`, fixed lane `linux-amd64`, `ubuntu-latest`, Java 25 | Full `build errorproneReport`, with the existing optional Sonar lane. Local container execution is working-source evidence and lacks hosted image/job/attestation authority. |
| macOS Java/core/API and analyzers | Reusable `build.yml`, fixed lane `macos-arm64`, `macos-latest`, Java 25 | `test spotbugsMain spotbugsTest errorproneReport`; requires actual ARM64/provider observations. Configured workflow changes do not establish execution. |
| Windows Java/core/API and analyzers | Reusable `build.yml`, fixed lane `windows-amd64`, `windows-latest`, Java 25 | Same native verification cohort, on actual Windows. Junction, sharing, path and ACL behavior cannot be established by Linux tests with a mocked OS. |
| Other architecture/package combinations | Existing packaging/runtime owners, including portable distributions and Windows x86_64/arm64 wrapper inputs | The three ordinary CI lanes do not reduce product support or prove every package/architecture combination. Additional native/installed observations remain required by their owners. |
| Distribution/app image | Root `assembleCryptadDist`, `buildJar`, jlink/jpackage owners; standalone `:platform-devtools:installDist` | Portable assembly differs from installation. macOS DMG and Linux DEB/RPM require their host tools. This repository does not build Windows installers by default. Signing/notarization/publication remains separate. |
| Python interop/performance offline tools | Existing Linux/macOS/Windows self-test jobs in `ci.yml` | Portable parser/import failures remain failures even when privileged operations in the same package are Linux-only. |
| Release certification offline tools | Existing Linux/macOS certification jobs | Offline producer/consumer boundaries and reconciliation execute without protected inputs. They do not authenticate installed or protected execution. |
| Browser rendering and support digest | Existing browser/tool owners and PR-320 regressions | Intercepted local HTTP transport establishes rendering, exact digest, copy/download and failure behavior; it does not establish installed listener/origin provenance. |
| Restricted worker, POSIX UID/cgroups/namespaces and installed acceptance | Existing protected/restricted owners | Linux-only capabilities and original authority remain mandatory where applicable. Exit-78 prerequisites and synthetic seams are separate observations. PR-322 owns the finite installed/restricted campaign. |

The applicability adapter recognizes eleven exact source-owned OS branches: Windows junction and
file-handle cases, complementary Linux/non-Linux native-thread cases, and complementary
Windows/non-Windows legacy allocation cases. Each rule binds its module, class, exact method or
parameterized variant, and lane. Current source-owned Linux selection has eight such N/As; the
Windows complementary branches have three. These expectations never overwrite actual skip facts. It retains the executed skip count and the approved/unowned
split. Missing tools, insufficient privileges, permission failures and new skips receive no blanket
platform exemption. Historical v1 retains its original zero-skip meaning. The encrypted-buffer Windows parameterized
cases include their method identity to avoid collisions with other parameterized methods. The JCE
provider test runs on the supported JDK rather than inheriting an obsolete JRE21–23 restriction;
unexpected provider absence fails. Evidence mode enables the sole existing FEC smoke benchmark
without changing a timing threshold or ordinary developer defaults.

## Source and filesystem boundaries

Selected source uses bounded Git metadata for tracked and current untracked working files. History
and cache exclusions apply to untracked discovery; a tracked file does not disappear because it has
a history-like name. Git-reported working-tree deletions are removed from the index roster before
validating current files, so an unstaged deletion or rename does not block Gradle initialization.
Deletions still classify the checkout as working source. Git-less installed/source exports require
the exact approved source manifest; missing declared members remain invalid.
There is no recursive fallback admitting arbitrary local history.

The active-source reader rejects linked/reparse ancestors, unsafe names, special files and private
hardlinks, bounds reads, and checks observable file/ancestor identity before and after reading. Where
the provider offers descriptor-relative no-follow opens it uses them. Portable Windows handle and
reparse observations do not claim persistent race-free confinement.

Java and included-build Kotlin static sources consult one bounded selected roster, preserving
tracked or export-listed history-named sources while pruning unselected files and directories.
Ordinary filenames omitted from an export roster receive the same treatment as unselected history.
Precompiled Kotlin DSL plugin discovery receives that selection before plugin application. Its
resource-copy task replaces its own generated plugin-descriptor output when it executes, preventing
stale descriptors from surviving a source removal. Declared generated roots remain visible.
Source packaging uses the selected roster instead of
copying an unrestricted repository tree.
External signed archives retain their separate exact member policy: an unexpected `.stversions`
member is rejected rather than removed by source-discovery exclusions. Tests prepare their owned real
temporary roots once; callers' untrusted link ancestors remain forbidden.

Source exports seal portable execute bits. POSIX providers validate those bits directly; Windows
ACL execute access is not compared with them. Providers without POSIX modes retain the declaration
and continue exact roster/content/link validation. Git-backed exports on those providers recover
tracked execute bits from the index; untracked files default to non-executable. Repackaging a
Git-free export preserves its original manifest and archive mode declarations.

Java report observation checks hardlink counts where the provider exposes `unix:nlink`. On other
providers the private collector still rejects a non-single-link report using Python's actual stat
link count before parsing. Recorder consistency does not bypass that admission check.

Private Gradle task observations use the actual `JavaCompile.source`, selected JUnit class inputs,
owning test sources and SpotBugs classes. This includes the generated `Version.java` and excludes
the template from compilation. The included `build-logic` Kotlin JUnit suite has its own recorder
because it runs in a separate Gradle instance. Both recorders retain actual candidate class bytes
and output class bytes; incidental Kotlin metadata remains a separately typed private input.

## Fresh task observations and bounded reports

Routine PR and non-release push builds exclude SpotBugs to bound CI runtime. For the complete
analyzer cohort, add the `phase12-evidence` PR label before the next push; release-branch pushes
select that cohort automatically. Both Linux and native callers pass the same `run-spotbugs` input
to the reusable workflow, which defaults to full analysis when used independently. The label selects
execution only: ordinary partial reports, analyzer findings and unavailable input provenance still
block Phase 12 admission.

Normal developer builds retain ordinary caching. `-Pphase12Evidence=true` selects the final evidence
mode: required JUnit/SpotBugs tasks execute freshly, and Error Prone compilation disables incremental
and cache reuse for the selected analyzer cohort. The Error Prone report identifies completed
compiler execution and the source count; a missing hook, incomplete compile or missing report is
not an empty clean analysis.

Evidence mode also observes fresh Kotlin/Java producers, processed resources and project archives.
Complete ordered runtime, compiler and auxiliary classpaths include every directory member.
Retention binds standard project outputs to fresh source-owned producers and dependency bytes to
the reviewed verification metadata and, where required, offline signatures with the pinned keyring.
Unsupported generated inputs or unavailable verification material retain unavailable coverage.

Classpath membership and order come from the committed
[`phase-12-classpaths.json`](../tools/release-certification/phase-12-classpaths.json), which binds
210 standard Java task classpaths to 73 build-configuration files. Entries identify project paths
or complete dependency coordinates and filenames; host/cache prefixes are omitted. Retention checks
the roster and configuration bytes against the source commit before comparing the observed ordered
list. A captured list cannot provide its own expected roster. Missing, additional, duplicate or
reordered entries are invalid; absent/stale authority and unsupported bootstrap/generated profiles
remain unavailable. Artifact-byte and fresh-producer verification still apply after membership matches.

After a reviewed build-configuration change, prepare a candidate from a checkout without additional
init scripts or dependency overrides:

```sh
./gradlew --init-script tools/release-certification/phase-12-classpaths.init.gradle phase12ClasspathCandidate
PYTHONPATH=tools/release-certification python3 -m cryptad_certification.phase_12_classpaths \
  --input build/phase12-classpath-tasks.json --output build/phase12-classpaths.review.json
```

Use a fresh output filename on subsequent attempts. Review the configuration changes and complete
ordered artifact lists before replacing the committed roster. Candidate generation alone grants no
admission. V2 producers that predate this authority cannot establish the new ordered-classpath
contract; historical v1 evidence retains its separate original semantics.

The private task manifest records native execution/reuse/no-source/failure state, original listener
clocks, actual source identities, class coverage, report paths and selected filters. At task completion,
both recorders capture the exact bounded report member roster, sizes and byte digests privately.
Collection compares those bytes before parsing; edited, copied, added or removed reports cannot
inherit an earlier execution clock. SpotBugs selected classes must equal the owning source-set output
classes, and native class identities and counters must reconcile. Analyzer settings must match the
source-owned filter bytes and configuration; include filters, baselines, detector changes and Error
Prone suppression/argument changes cannot masquerade as full analysis. JUnit tag/engine
selection, CLI/name filters, changed source-owned class patterns, dry runs and disabled class scanning
remain visible. A focused `--tests` command cannot provide full-suite evidence. `NO-SOURCE` requires
an actually empty resolved cohort; missing observation does not receive that classification.

Each compiler, JUnit launcher and SpotBugs launcher also records its selected Gradle toolchain's
runtime version/vendor and bounded installation release-file architecture separately from the daemon
JVM. Missing or unobservable toolchain metadata remains `null`; it does not fall back to daemon
identity. The included-build JUnit adapter records the same separation.

The v2 public projection contains only fixed typed counts, task states, applicability counts, source
identities and bounded provider/runtime facts. Raw XML, case names, diagnostic messages, local paths,
input rosters and private payload digests remain private. Authenticated failed/incomplete artifacts
can be retained without granting acceptance. Legacy v1 artifacts dispatch through their historical
consumer and retain their original limits.

Each fixed lane uploads a distinct
`phase-12-ci-reports-<run>-<attempt>-<lane>` artifact. Admission checks the original subject,
attestation, signer, workflow, job, attempt, lane/provider, report clocks and complete applicable lane
set. The consumer retains three separate identities: the product checkout, top-level workflow/test
merge, and reusable workflow signer. A PR-head run under a test-merge workflow does not prove the
eventual squash commit.

Analyzer task success remains weaker than acceptance. SpotBugs keeps `ignoreFailures=true`, Error
Prone keeps `allErrorsAsWarnings=true`, and JaCoCo's 0.80 threshold remains non-blocking. Actual
findings, missing classes, unavailable reports, unowned skips and incomplete execution stay blocking.
No numeric warning budget or new blanket waiver is introduced. The existing no-Sonar-token lane and
`owner-skipped-standard-build` SonarLint classification remain distinct from executed-clean scans.

## Local execution record

The focused platform run observed 1,352 Platform API, 326 AppHost, 274 devtools, 135 HTTP bridge and
19 Web Shell JUnit cases, with no failures/errors. AppHost's two Windows-junction tests were skipped
on Linux. `:foundation-fs:test` is source-free; its historical/root-owned tests require the root suite.
These counts describe that focused observation, not the subsequent complete source-bound run.

The full local evidence command is:

```bash
./gradlew build errorproneReport :platform-devtools:installDist assembleCryptadDist -Pphase12Evidence=true
```

The environment's daemon JVM is Debian Java `25.0.4.1`; the observed jpackage invocation uses the
provisioned Eclipse Adoptium toolchain, whose release file identifies Temurin `25.0.4+7`. The daemon
runtime projection alone does not identify each test launcher/compiler toolchain. Python is `3.13.5`,
Node is `24.22`, and the checked-in wrapper is Gradle `9.7.1`.
Its private log is outside upload rosters. Authoritative task clocks and execution/reuse
states come from `build/phase12/task-evidence.json` and
`build-logic/build/phase12/task-evidence.json`, rather than XML modification times.

The first full attempt failed after 7m 6s: Gradle reported 649 actionable tasks, 572 executed and
77 up-to-date. Its selected verification task manifest contains 102 executed, two failed and two
source-free tasks, with no input-observation failures. Its observed task clocks run from
`2026-10-15T08:49:35.880Z` through `2026-10-15T08:56:12.369Z`.

Four boundary tests failed because the selected-source roster property was not passed to their test
JVM: two `PlatformApiBoundaryTest` methods and two `AppDistributionBoundaryTest` methods. The 14
observed module test tasks contain 2,720 JUnit cases, four failures, zero errors and one skip; the
included build's JUnit task executed separately. Earlier focused XML from modules not reached by
this attempt does not contribute to these counts.

The incomplete attempt produced 32 main SpotBugs reports with 706 findings, zero analysis errors,
two missing classes and 4,162 analyzed classes, plus 11 test reports with seven findings, zero
errors/missing classes and 109 analyzed classes. Every one of those 43 analysis clocks lies within
its matching executed task's original interval. It produced 32 main Error Prone reports with 275
warnings and 15 test reports with 21 warnings; all 47 identify completed compiler execution and a
source count matching the private task observation. No Error Prone error diagnostic was observed.
Failure stopped the remaining graph, so these are failed-attempt partial-cohort totals and cannot
establish complete analyzer or test acceptance.

The subsequent `M3UFilter` repair replaces unchecked one-byte bulk reads with the stream's unsigned
single-byte read contract. It avoids inventing a NUL byte when a delegate bulk read returns zero.
The existing root-owned regression class now covers that delegate behavior, unterminated EOF,
unsigned `0xff`, exact/oversized byte limits, CRLF and empty input. The focused root-owned suite executed all 13 cases without failures, errors or skips, and its
regenerated SpotBugs report contains no finding in `M3UFilter`. The final full run verifies the
subsequent test-fixture refinement separately from the failed-attempt observation above.

The next complete full attempt passed in 15m 14s, with 765 actionable tasks: 671 executed and
94 up-to-date. Its private root manifest observed all 210 fixed module verification rows: 164
executed and 46 source-free; the included build's test executed separately. Its retained JUnit
reports contain 17,544 cases (including 22 build-logic cases), zero failures/errors and ten skips.
SpotBugs produced 34 main reports with 713 findings/4,314 classes and 32 test reports with
191 findings/2,245 classes, with zero analysis errors or missing classes throughout. Error Prone
produced 34 main reports/488 warnings and 32 test reports/130 warnings; all captures declare
completed compilation and diagnostics. Coverage remained 0.72 against the existing non-blocking
0.80 threshold. This complete observation predates the final history-selection/skip corrections;
its original bytes remain retained separately, and findings are not dispositioned.

The final full run, including report-byte/configuration/class binding and exact static source
selection, passed in **13m 48s**: 765 actionable tasks, 651 executed and 114 up-to-date. The actual
211-record audit passed without mocks: all 165 required verification tasks executed freshly, and
46 were verified source-free. None of those verification records represents cache/up-to-date reuse.
All source paths/bytes, selected and owned classes, analyzer settings, report rosters/bytes and native
counters matched. The selected task window was `2026-10-15T11:43:39.437Z` through
`2026-10-15T11:57:11.657Z`. Original hosted authority is absent for these working-source bytes.

| Final native report cohort | Actual result |
| --- | --- |
| JUnit, 1,421 XML files | 17,548 cases, zero failures/errors, eight exact approved platform N/As and zero unowned skips; includes 26 passing build-logic cases |
| SpotBugs main, 34 reports | 713 findings, 4,314 classes, zero analysis errors/missing classes |
| SpotBugs test, 32 reports | 191 findings, 2,245 classes, zero analysis errors/missing classes |
| Error Prone main, 34 reports | 488 warnings, zero errors, all compiler/diagnostic captures complete |
| Error Prone test, 32 reports | 130 warnings, zero errors, all compiler/diagnostic captures complete |
| Coverage | Root 0.72 against 0.80; twelve bundles reported a below-threshold line ratio under the existing non-blocking policy |

The distribution assembly and Linux DEB task completed. The RPM task was skipped under its
existing `rpmbuild` prerequisite guard; that tool is unavailable here. This does not establish RPM
packaging or installed acceptance. SonarLint main/test tasks retained their existing owner-skipped
standard-build classification.

The retained 1,553 XML files total 13,212,994 bytes. Their exact task-completion bindings and clocks
all matched in the actual audit. Findings remain undispositioned; this establishes report integrity
and coverage, not complete analyzer triage or CI acceptance.

The final actual `./gradlew tar` passed in 28 seconds. Independent extraction and the production
Git-free reader verified all 6,203 selected members and executable modes. The legacy Bzip2 tar name
and prefix remain intact. The exported manifest declares working source, and its reader labels it
`manifest-source-export`; neither classification supplies original authority.

The selected compiler/test/analyzer toolchain in that actual run was Debian Java
`25.0.4.1+1-1-deb13u1-Debian` on `x86_64`; the filesystem observation was `ext4` and the provider was
`sun.nio.fs.LinuxFileSystemProvider`. The bounded public version grammar preserves this exact Debian
version only for its recognized vendor, rejecting arbitrary suffix text. Product jpackage used the
separately selected Temurin installation. The actual toolchain metadata is not inferred from the
daemon or the package runtime.

The final source-selection verification deliberately retained task-owned invalid untracked Java
histories during execution in root main/test and Platform API source trees. An initial formatter run reproduced
Spotless admitting that history; the corrected formatter passed with those files still present.
Source sets and formatters now share a lazy selected roster. The separate bootstrap fixture proved
that tracked history Kotlin compiles, untracked invalid history does not, approved Git-free exports
retain selected/generated classes, and missing/tampered/linked declared export inputs fail before
compilation. It passed 24 tests with zero skips and checked all 18 candidate/output class
fingerprints separately from Kotlin module metadata. The final static-selection fixture also
verified exactly ten selected plugin adapters/descriptors, omitted ordinary scripts, and replacement
of stale copied descriptors while preserving an unrelated resource. Only the three task-owned
history fixture files/subdirectories were removed after retaining the proof; their history parents
and other user history remain intact. These are local fixture results.

PR-320's recorded 17,498 cases, ten skips, 714/191 SpotBugs findings and 332/130 Error Prone findings
remain historical observations from its recorded working revisions. They are not copied into this
run's totals.

The current analyzer review identifies these closure obligations. The first attempt's `runtime-node` Error Prone output reached javac's default 100-warning cap, so its emitted
counts do not establish a complete finding roster. Report mode now uses a bounded 10,000 diagnostic
cap, records diagnostic completeness, and keeps truncated capture blocking. A candidate disposition still
requires the exact source/rule rationale and regenerated native report; this table grants no waiver.

| Observed blocker | Inspected source or cause | Evidence needed for closure |
| --- | --- | --- |
| Missing `com.sun.jna.Platform` and `network.crypta.fs.AppEnv` in `foundation-store` SpotBugs | The analyzer traverses `NativeThread` from the store cleaner. `foundation-support` declares JNA/filesystem dependencies as implementation details, so the store's compile auxiliary classpath omits them. | The focused regenerated report now observes zero analysis errors and zero missing classes after adding owning runtime dependencies to the auxiliary classpath while retaining compile-only annotations. The complete local cohort confirmed zero missing classes; no Java API dependency promotion was needed. |
| `NCR_NOT_PROPERLY_CHECKED_READ` | `M3UFilter.readNextLine` and three `thirdparty-onion` single-byte stream wrappers consume an array read after checking only EOF. | Review zero-return/short-read contracts, preserve stream/budget/EOF behavior, add behavioral coverage for any repair and regenerate reports. |
| `NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE` | Several filesystem enumerators dereference `Path.getFileName()` on directory-stream children; other cases require individual inspection. | Establish the exact path provenance and provider contract per location, then make a behavior-preserving repair or exact supported disposition. No broad filename/path exemption. |
| `NP_BOOLEAN_RETURN_NULL` | `ValidatedBundle.authenticatedExecutableBit()` deliberately distinguishes unauthenticated executable metadata using `null`. | Preserve signed digest semantics and prove the nullable contract before any exact source-owned disposition. |
| Error Prone `ArrayRecordComponent` | `AppVaultEnvelope` clones constructor inputs and accessor results and supplies array-aware equality. | Verify mutation/equality coverage and the exact rule/location before a narrow source disposition. Converting the public record representation is not an automatic fix. |
| Unsafe synchronization, inconsistent synchronization, exposed representations and reference equality | Long-lived request/status services, mutable API references, records and third-party code contribute repeated findings. | Inspect monitor ownership, caller mutation contracts and serialization/API compatibility before changes. Fix actionable cases with behavior tests; unresolved cases remain blocking. |
| Documentation/visibility/style diagnostics | Error Prone reports `EffectivelyPrivate`, `PreferThrowsTag`, `AlmostJavadoc` and other families. | Preserve intended API ownership, repair exact actionable diagnostics, and regenerate the full required report cohort. Large counts do not authorize module-wide suppression. |

Offline report and source-policy regression commands are:

```bash
PYTHONPATH=tools/release-certification python3 -m unittest discover \
  -s tools/release-certification/cryptad_certification/tests -p 'test_phase_12*.py'
python3 tools/release-certification/certify.py phase-12-closeout --self-test
python3 tools/release-certification/certify.py release-certification --self-test
python3 tools/release-certification/certify.py cross-version-soak --self-test
python3 tools/release-certification/certify.py network-scale-soak --self-test
python3 tools/release-certification/certify.py public-ecosystem-transparency --self-test
```

The complete Phase 12 offline self-test executed 251 tests in 278.340 seconds, with no failures or
skips. The final CI/source regression cohort executed 89 tests, and the source-binding closeout
guards executed 41 tests. Actual product-consumer integration executed all four PR-304/305/307
cases in 295.651 seconds using the compiled app tools and daemon distribution.

The existing required Linux root baseline/reviewer step also selects the nine socket peer-identity
cases and five root-owned role/projection cases. Its exact workflow command executed locally under
`sudo`: 92 tests passed in 29.709 seconds with zero skips. The workflow fails on any skip rather than
letting the ordinary non-root offline run waive those Linux prerequisites. Its fixtures intercept
service operations and use owned temporary state; this is offline identity verification.

The other requested offline components passed: release certification 50 tests, cross-version soak
156, network-scale soak three, and public ecosystem transparency 91. The composed-budget/native
privacy/browser consumers passed 124 tests after binding their observation cutoff to the actual
native fixture events. The broader cross-version package passed 319 tests with nine root-peer
skips, separately executed under the real root identity above. The physical export/owner cohort
passed 62 tests with five root-only skips, also covered by that root execution. The secure and
non-secure recovery browser runs used actual native support-wire bytes and intercepted local
transport; those successful rendering/digest checks do not establish installed provenance.

Commands are a reproducible verification path; the counts above identify the checks actually run.
Original macOS/Windows Java lane results, external analyzer outcomes and hosted attempts/artifacts
for the current working changes remain unexecuted. The integrated baseline's separately observed
hosted results are recorded below.

## Original integrated baseline

The actual PR-320 integration push run `38705949240`, attempt 1, completed successfully for
`82fbe160454cde9cce821d1d0acf305314036235`. Its original `build / build` job is
`116325290536`. Artifact `11959143611`, named `phase-12-ci-reports-38705949240-1`, has
archive digest `sha256:ee710f17d2f36ba32c6c954a2cef0a79ee97111e008e146595a1424a58a304e0`.
The original GET, artifact bytes and attestation were verified using the historical v1 producer
identity at that source. The product, workflow and signer commits are all the integration commit.

That authenticated historical artifact retains 164 rows and 1,547 reports: 17,503 JUnit cases,
zero failures/errors, 12 skips, 905 SpotBugs findings, two missing classes and 462 emitted Error Prone
warnings. Findings and undispositioned skips prevent Phase 12 CI acceptance despite successful
Gradle/job status. V1 does not establish the new native matrix or complete untruncated finding
identities. These facts are separate from PR-320's earlier author-recorded revisions and this PR's
uncommitted local checks.

The initial original commit-check query returned 35 check runs for that integration; the final
query returned 42. The actual source-owned external-check adapter admitted the complete latest
list and retained the same four scanner checks and the `original-sonarcloud-check-failed` blocker.
It includes a
completed failed `SonarCloud Code Analysis` check from `sonarqubecloud`; that is an actual external
failure, and the no-token local build does not disposition it. CodeQL's `Analyze (python)`,
`Analyze (actions)` and `Analyze (javascript-typescript)` checks completed successfully in run
`38705948208`. Those check conclusions alone do not establish an independently reviewed finding
roster, Java CodeQL execution, or results for this working tree. A later scheduled performance-smoke
failure on the same commit belongs to run `38711541118`, distinct from the successful push run's
owner-skipped scheduled jobs. Branch-protection requirements have not been independently verified.

The same run's successful Windows performance self-test job `116325290270` supplied a real checkout
log with a quoted Windows Git executable path. The updated bounded parser recovered the exact
integration commit inside the pinned checkout action's original interval. This validates that log
form; it does not establish execution of the new Windows Java lane.

## Source-pin disposition and remaining acceptance

The [source-pin review](pr-321-source-pin-review.md) records each inherited drift, its previous exact
bytes/source, affected owners, selected semantic delta, coverage and limitations. The immutable
PR-320 acceptance inventory remains available separately. The successor preserves all 49 mandatory
requirements, dimensions, subjects, prerequisites, histories and original clocks. Recomputed source
digests do not promote implementation state or supply operational evidence.

The fixed-cutoff pre-change assessment contains 49 mandatory requirements, 47 unresolved and Phase
12 incomplete. The separate after root measures implementation drift at that same historical
cutoff; fresh original CI needs an evaluation cutoff after its actual completion. The inherited
maintenance projection owner-policy digest with unavailable historical working bytes remains an
explicit unresolved authority pin.

A separate current assessment at `2026-10-15T12:00:20Z`, after the local verification completed, also
retains 49 requirements, 47 unresolved and an incomplete decision. It supplies no original hosted
or protected inputs and does not backdate the new local observations into the historical comparison.

Implementation verification, supported-provider execution and original exact-source CI acceptance
have separate completion criteria. Open findings and unavailable hosted/native results prevent the
latter claims. No local build, browser interception, offline fixture, safe export or configured
workflow establishes protected acquisition, installed VM acceptance, independent review,
publication or release eligibility.

PR-322 remains the finite-native installed-acceptance and restricted-execution work package. It
retains PR-313's unfinished obligations, PR-315's exact historical workload evidence, PR-320's
unexecuted original acquisition, Mail lifecycle, migration, independent provider/review, baseline,
long-soak, publication and transparency requirements. PR-321's ordinary CI adapter and unresolved
analyzer/provider acceptance stay visible in this package.

## Portability review follow-up

The follow-up prepares both new Kotlin classes' real owned test roots before constructing roster outputs,
separates Java recorder link-count capabilities from mandatory collector hardlink rejection, and
keeps portable source-export execute bits separate from host ACL execute access. Source readers
validate POSIX bits where available; other providers preserve the declared metadata while keeping
exact byte, roster and link validation. Source archive writing now uses the sealed manifest modes.

The follow-up checks ran on Linux: all 30 included-build tests, 24 tests with an aliased JVM temporary root, 92 focused source/CI Python tests,
and 41 closeout guards passed with zero skips. Formatting and `git diff --check` passed. Actual
source archive creation, Git-free Gradle initialization and Git-free source repackaging passed.
Independent verification matched all 6,203 selected members, their bytes, exact preserved manifest
and archive mode declarations. Deliberate POSIX execute-bit drift rejected in both the Python
reader and Gradle bootstrap. The unit provider seams and actual ZIP filesystem test do not establish
native Windows/macOS execution. The earlier full Java run describes its original working revision;
it was not rerun for this focused follow-up.

Only fourteen existing source/test commitments changed across eight reviewed paths. Scope,
requirements, declared states and the remaining historical authority blocker are unchanged. The
separate follow-up assessment still records 49 requirements, 47 unresolved and Phase 12 incomplete.

## Reader and manifest encoding review follow-up

V2 report retention uses the portable, bounded, link-checking source reader for both the original
start clock and current producer-source hashing. Their existing 4 MiB read limits remain intact.
Regression tests exercise both reads with the Unix-only open flags absent and preserve producer
digest semantics for both report schemas. Historical producer-source selection remains unchanged.

The Kotlin bootstrap and source-selection helper validate the restricted manifest's existing
newline-free encoding separately from the full source archive's newline-terminated encoding.
They preserve exact manifest bytes and continue to reject duplicate keys, extra whitespace and
source drift. This fixes initialization from the existing restricted export format.

All checks for this follow-up ran on Linux: 30 included-build tests, 94 focused source/CI Python
tests and 41 closeout guards pass without skips. Formatting, `git diff --check` and source archive
creation pass. Actual Git-free Gradle initialization and direct helper validation pass for a
6,203-member full-source archive and a 5,861-member restricted fixture encoded with the existing
`installation.encode()` function. Their manifest digests remain unchanged. An incorrectly appended
newline on the restricted fixture fails bootstrap validation. The restricted fixture contains
working-source bytes and does not establish `installation.plan()` execution or installation approval.

The five directly changed source/test paths advance only their five existing file commitments.
Acceptance scope and states remain unchanged; the separate fixed-cutoff assessment still records
49 requirements, 47 unresolved and Phase 12 incomplete. Private review records are under
`build/pr321-private-pin-review/reader-encoding-review-results/`; the
[source-pin review](pr-321-source-pin-review.md) identifies the corresponding prior bytes and pins.
Native Windows/macOS lanes and the full application suite were not rerun for this follow-up.

## Hosted macOS fixture follow-up

The [macOS ARM64 job](https://github.com/crypta-network/cryptad/actions/runs/38801065461/job/116649916408)
for commit `0583552b58066a3606bd9ef3f42deba32d61903a` failed eight `AppUiToadletTest` cases and
two `LauncherControllerTest` cases. Its bounded report retention, attestation and upload steps
completed, preserving the failed result without granting acceptance.

An actual aliased temporary root on Linux reproduced the same eight app-UI failures. The test now
resolves its owned JUnit root before constructing installed bundle paths, preserving the production
asset resolver's rejection of aliased or linked untrusted paths. The two launcher fixtures now keep
their child processes alive until the test releases them, rather than exiting after short sleeps.
Both tests release and stop the child in `finally`; readiness recovery also releases its injected
read gate during cleanup. Their existing state, port and browser assertions and wait limits remain.

Formatting and the focused run with the aliased temporary root passed all 35 app-UI tests and
34 launcher tests without failures, errors or skips. This is local Linux reproduction and
verification; the updated native hosted jobs must independently establish their own results.
The existing implementation-evidence commitments and acceptance obligations remain unchanged.

## Native jobs and report retention follow-up

Run `38807779388`, at `e977471a556877f1573b1e85627acf81e32a6071`, failed the
[macOS native job](https://github.com/crypta-network/cryptad/actions/runs/38807779388/job/116673005458),
[Windows native job](https://github.com/crypta-network/cryptad/actions/runs/38807779388/job/116673005546)
and [macOS certification self-test](https://github.com/crypta-network/cryptad/actions/runs/38807779388/job/116673005017).
The successor corrects their fixture assumptions and the Windows source-reader metadata comparison.
It preserves provider admission, exact source checks, signatures and bounded report redaction.

Pilot-approval fixtures now use real owned paths, and signed app fixtures choose Windows command
scripts or Unix shell scripts before signing. Hidden-file fixtures create native hidden attributes,
queue error-page assertions use canonical encoded paths, and file-backed bloom-filter tests use
JUnit temporary directories. The repeated-start AppHost test stops its child in `finally`. The
updater test controls the filesystem access observation without POSIX permission assumptions.

Launcher shutdown waits for wrapper-log reader closure and executor termination. A regression
reproduces the prior premature return on Linux and verifies reader/executor completion and log-file
removal. Starts after shutdown are ignored. Windows source reads compare stable identity and birth
time across pathname and handle observations, while retaining each API's complete change-time and
mode checks before and after reading. This accommodates CPython's Windows metadata differences
without removing hardlink, reparse-point, replacement, size or mutation checks. Linux report fixtures
supply image facts explicitly so inherited macOS image variables cannot alter their provider.

The [source-pin review](pr-321-source-pin-review.md#native-provider-and-shutdown-review-follow-up)
records the exact nine updated file commitments and preserved acceptance scope. Private diagnostics,
prior bytes and verification results remain under `build/pr1423-ci-three-jobs/`, outside upload
rosters. The fixed-cutoff assessment retains 49 requirements, 47 unresolved and Phase 12 incomplete.

Local Linux verification passed the full `./gradlew test` invocation: application reports contain
17,523 cases, zero failures/errors and nine skips; all 35 included-build tests pass without skips.
The affected Java suites pass 177 cases without skips. The earlier alias invocation reused the
core HTTP runtime test result (`UP-TO-DATE`), so it did not establish execution under that temporary
root; the fresh alias reproduction and correction are recorded below. SonarLint reports no findings
for either changed production Java file. Interop checks pass 319 cases with nine environment-gated
skips. These local results do not establish native hosted execution for the successor commit.

## Native temporary root, asset lifetime and scheduler capture correction

The next hosted run, `38814947603`, exposed a remaining macOS pilot fixture path, a Windows
loopback asset lifetime race and a packaged scheduler observation failure. The
[source-pin review](pr-321-source-pin-review.md#native-temporary-roots-asset-shutdown-and-scheduler-capture-follow-up)
records the original job links, reproduction limits and unchanged evidence contract.

All six pilot fixtures now resolve their owned temporary root before constructing member paths.
A forced fresh alias run reproduces the four macOS failures before the fix and passes all 56 tests
afterward. This replaces the earlier alias claim, whose invocation had reused an up-to-date result.
Loopback UI shutdown now awaits request executor termination for up to ten seconds so active asset
streams can close; its regression holds and releases a real asset stream during shutdown.

The scheduler collector waits for a fresh completed tick and released family/fetch work before
finalizing the original event prefix. It retains the existing deadline, sample bounds and strict
write/outcome validation. Synthetic regressions cover a pending metadata write, outstanding
family/fetch work and deadline expiration. Three standalone packaged executions passed locally
before this change; they did not reproduce the hosted scheduler failure end to end. The source
change addresses the independently reproduced capture race without changing acceptance criteria.

Local Linux verification passed the full Java suite: 17,524 application cases with zero
failures/errors and nine skips, plus all 35 included-build tests. The final executor-injection
refinement then passed all 191 adapter tests. All three changed Java files have clean SonarLint
reports with their owning main/test scope. Cross-version checks pass 322 tests with nine
environment-gated skips, and scheduler-input/runtime-pressure/storage-evidence checks pass all
48 tests. All 631 implementation-evidence file commitments match without policy changes.

Both packaged scheduler tests pass without skips after rebuilding the distribution: one borrowed
supervisor execution and three independent standalone executions (511 seconds total). All five
required narrow runtime claims are observed. The synthetic local baseline comparison reports
`fail` with `runtime-regression-exceeded` and `releaseEligible: false`; this allowed comparison
result is retained, not waived or treated as performance acceptance. Native macOS/Windows execution
for the successor commit and original hosted acceptance remain separate from these Linux results.

## Interpreter selection and archive classification review correction

The reusable workflow now invokes both report commands through setup-python's quoted absolute
interpreter output. This selects the pinned Python version without depending on a runner alias.
An actual local Bash smoke check passes both commands with a spaced interpreter path while the
`python3` alias deliberately fails; the generated facts are synthetic private test data.

Source archive classification now uses tracked changes plus selected untracked members. Excluded
untracked history leaves a committed archive manifest unchanged, while selected additions and
tracked edits/deletions retain working-source classification before and after staging. A real-Git
regression reproduces the previous manifest drift. The
[source-pin review](pr-321-source-pin-review.md#interpreter-selection-and-archive-source-classification-review)
records the three updated commitments, preserved acceptance rules and verification results.

Local verification passed the full `./gradlew test` invocation: 17,524 application test cases with
zero failures/errors and nine skips, plus all 38 included-build tests without skips. The focused
Python source-selector, CI-evidence and closeout suites pass all 107 tests. Workflow lint and
Kotlin formatting pass, and both report commands pass the spaced-interpreter/failing-alias smoke
check. The separate assessment at `2026-09-13T10:30:00Z` retains 49 requirements, 47 unresolved and
Phase 12 incomplete. These checks do not establish native hosted execution for the successor commit.
