# Installed finite native acceptance

PR-313 completes the executable verification path for PR-312's fixed keyless native service.
Use an unprivileged Linux host, extracted QEMU tools, the pinned Debian/JDK inputs, and newly
selected disposable guests. Provisioning affects only those guests. This procedure neither
publishes artifacts nor supplies original protected authority.

## Source and current execution status

The starting implementation is merged PR #1414, project work item PR-312, at
`31dc975ef5b65b7ec56e835e287b2ffa8a4a7342`. Its tree
`aed77ed1b376ab829516861dbcaaec0470c6f33d` equals the final feature head
`70966918457006ea6a588de87c4dc53ce83cc365`; containing implementation was checked without requiring
feature-commit ancestry after squash. The planning head `88a02530…` was superseded. Earlier CI and
development VM observations are not results for this successor.

A new preparation-schema-5 reference completed on **2026-09-16**, with the owned guest stopped
before conversion. Its standalone QCOW2 SHA-256 is
`a5bd921eb0327acea1e2ac3e64609ff8a92b14b239ed637a3c13859bacda7984`.
The preparation used extracted QEMU `10.0.13`, CPU `qemu64`, accelerator `tcg,thread=multi`, four
vCPUs, 5632 MiB, and the fixed `pc,smm=off` machine. The retained private inventory records actual
installed distro packages, copied ELF dependencies/modules, firmware and boot inputs.
The fresh preparation recorded kernel `6.12.107+deb13-amd64`, systemd `257.13-1~deb13u1`,
Python `3.13.5-1`, bubblewrap `0.12.0-1~deb13u1`, libc `2.41-12+deb13u4`, OpenSSL
`3.5.7-1~deb13u2`, polkit `126-2`, dbus `1.16.2-2`, sudo `1.9.16p2-3+deb13u2`,
Git `1:2.47.3-0+deb13u1`, and GitHub CLI `2.46.0-3`.

| Pinned input or retained executable | Verified identity |
| --- | --- |
| Debian 13 generic amd64 image, `20260914-2601` | SHA-512 `a733e7d49442a03e70d03e4eb5aaf3967f3efc69ef70952f9bb10fc1ee2c4876eb95956b5ad2d31350e5fada768feb651352535fb8cd1233f61998a5a7d2e93c` |
| Temurin `25.0.4.1+1` archive | SHA-256 `dbb698396d478e7fa2b1e50f4103324b2a99b90569ee27c33f2261f9215cf41e` |
| QEMU system executable | SHA-256 `d3c1a558ad220e77a4412048c8d96b44f8c2b41c7ad2a4ecfe522a4b122fe067` |
| QEMU image tool | SHA-256 `77a92b0ca43516403064a4d0939f91c38b9ab2447b32e8f66709dcf29432d626` |

The image/JDK origins and verification limits remain those in the
[reference preparation record](pr-311-observer-workload-isolation.md#disposable-reference-preparation-and-acceptance).
A content digest identifies bytes; it does not confer supply-chain authenticity or environment
approval. Current apt packages must match the preparer's explicit checks; changed repositories
fail preparation instead of silently selecting new versions.

**Complete installed acceptance of the final PR-313 source has not been recorded.** A stopped standalone
reference is preparation evidence only. The historical trusted-fixture SIGILL remains undiagnosed;
no CPU-model change or successful local fixture preparation establishes a QEMU/JDK remedy.
Actual in-service Java and CMS operations must still pass under the selected guest profile.

A second fresh preparation retained a compressed standalone QCOW2 with SHA-256
`6ab3c7a5199bcc2d528bb4cd01f09ff0c998069bbf7ae31aa3114faab85f1fca`. Its owned guest stopped
before `qemu-img convert -c`; the earlier reference remains unchanged. Compression reduces the
private backing-copy footprint of the fixed fresh-guest suite and changes the image identity.

The first PR-313 development positive attempt used helper
`07b28460c360d3558e8271f915d047d66445f6e6`, tree
`746da6a6aa4990d7e53883604f63e8577b1a5ccb`, bundle
`52304cdb1692eef188f954dda02dff4ef0e7f4777d26676828892a6e46e818c2`, the first reference above,
and separately built product `31dc975ef5b65b7ec56e835e287b2ffa8a4a7342` with JAR SHA-256
`6f8f5efefb98e5f7fe08c8ba74c09cf19b56c6feb0f08d318c951daf68d5b821`.
Readiness, socket denials, package export, signed-app validation and wrong-app rejection executed.
Prepared-input cohort verification then failed outside the installed service with Temurin
`SIGSEGV` in C1-compiled `java.lang.Long.rotateRight`; one integration test failed after 89.032
seconds, and the guest stopped. No CMS success or complete native acceptance is claimed.
The host's final identity check also exposed a test-script bug: its Python import created
bytecode in the immutable installed tree. The successor uses `-B` for that read-only check.
Earlier observation bindings were also strengthened to require exact invocation windows.
Neither correction upgrades the old attempt to acceptance.

The next bounded comparison selects `--profile tcg-single` explicitly, once, using prepared
inputs and unchanged JDK/native/readiness/owner limits. `tcg-multi` remains the default; there is
no automatic fallback and no per-run JVM override. Both fixed profiles retain `qemu64`, four
vCPUs and 5632 MiB. Single-threaded TCG remains a compatibility hypothesis until actual
verification completes; the historical shorter timeout is not rewritten.

That comparison at helper `337ae5d3f8025a99171f2c9f60798840b2f83721` reached wrong-product
rejection, then exposed a separate synthetic-controller setup bug: the harness duplicated its
listener onto FD 3 as inheritable, which the unchanged Worker correctly rejects. A private live
process observation recorded the exited child while the client waited. The successor supplies
the required non-inheritable FD and tests both original and moved listener descriptors through
the real Worker activation checks. This test-only correction does not diagnose the JVM crash
or make the incomplete comparison accepted. The queued `ce1de26641` suite was stopped before
any guest launched so its obsolete driver would not be run knowingly.

The subsequent suite at `0015f41b89e65a87a9a4f68df6c184fa4c807250` lost its execution context
during its first guest. On continuation, neither its controller nor emulator remained and no
terminal attempt report existed. The disk and logs are retained unchanged, with a separate
interruption record dated 2026-09-16; orderly guest shutdown is not inferred. Its partial
observations cannot satisfy acceptance.

Further review corrected the synthetic owner scopes and final consumer evidence. Trusted
fixture preparation no longer consumes a deadline spanning the entire unittest. Six fixed
independent owner operations each receive one 900-second budget, including assertions and
cleanup; the actual Worker request retains its existing budget. The final consumer case requires
three separately witnessed consumer windows, each with its own package export and exact nine-app
projection roster. It cannot borrow the preceding Worker's package invocation.

## Fixed contract and separate execution layers

The authoritative inventory is
[`pr313_acceptance.py`](../tools/release-certification/restricted/pr313_acceptance.py), including
case ID, owning operation, layer, prerequisites, phase, required witness, outcome and cleanup.
Its `implementation_coverage()` identifies emitted records separately from observed execution.
The suite in [`pr313_acceptance_runner.py`](../tools/release-certification/restricted/pr313_acceptance_runner.py)
predeclares groups before launching any guest and retains every attempt's actual identity and
history. It has no report-import, arbitrary-command or publication operation.

| Required group | Fixed case IDs or family | Evidence required |
| --- | --- | --- |
| Storage and installation | `reference-identity`, `installed-identity` | Private standalone backing copy; exact helper, test kit, product, boot and effective profile |
| Production entry | `bootstrap-ready`, `socket-wrong-uid`, `socket-unknown-handle`, `construction-probe`, `restart-ready` | Actual readiness and socket outcomes; owned cleanup |
| Java and owning consumers | `package-api`, `signed-app`, `wrong-app`, `wrong-product`, `product-selection-native-consumers` | Actual installed operations and semantic owner assertions |
| Maintenance encryption | `cms-five-member-context`, `cms-wrong-recipient`, `cms-tampered-envelope`, `cms-subject-substitution` | Real companion encryption/opening, witnessed rejection and removed plaintext context |
| Existing hostile inputs | `hostile-*`, `openat2-safe` | Attack-executed markers, relevant outcomes and native quiescence |
| Concurrent substitution | `input-*`, `output-*` | Witnessed inode/ancestor/link/truncation/growth mutations at acquisition barriers |
| Active endpoint | `sibling-control-canary` | Reachable owned control server before an actual denied native connection |
| Authority and durable state | `owner-revocation-running`, `worker-revocation-running`, `completed-revocation-retry`, `death-*`, `worker-death-*`, `retained-exact-retry` | Real owner checks, exact invocation identity, durable records and policy-correct retry/reconciliation |
| Public result boundary | `public-*` | Real collector/semantic owner/public projection, source-owned allowlist and private-canary absence |

Production bootstrap/socket observations use the unmodified installed controller. Native/CMS
cases use a separate administrator-owned synthetic original/provider context and unchanged owner
code. Actual protected operations require separately supplied original authorized input; none is
created by this suite. Test drivers and prepared synthetic inputs remain outside production
manifest-v2 installation members.

A denial is credited only after its attack executed at the required phase. Setup failure,
not-executed, inconclusive, rejected input and failed assertions retain distinct meanings.
Expected reconciliation-required state is never deleted merely to make a later case run.

Each launch checks available space for its private copies and a bounded guest-write reserve.
After a successful attempt has stopped and every declared causal record and identity verifies,
the runner can remove its generated disks, source archive and extracted source/bundle copies.
It records the exact file hashes and sizes in a private disposal intent before removal and keeps
the reports, observations, diagnostics and boot inventories. Failed, incomplete, inconclusive,
death/recovery and revocation attempts retain their disks. This cleanup never clears guest
active or retained-result state to make another case pass.
The fixed plan runs independently reclaimable groups before the recovery groups; all required
cases remain in the plan if capacity prevents a later launch.

## Reproducible preparation and execution

Build using the supported tasks, then select a clean source revision containing the exact helper
and tests. The product commit may differ only when its copied JAR marker and local Git identity
verify explicitly. Fixture verification binds its helper commit and producer bytes; prepare new
fixtures after a relevant source change. Paths and uppercase digests below are explicit inputs.

```bash
cd /absolute/clean-source-with-builds
./gradlew :platform-devtools:installDist assembleCryptadDist
python3 tools/release-certification/restricted/pr312_prepare_reference.py \
  --qemu-root /absolute/extracted-qemu \
  --image /absolute/pinned-debian.qcow2 \
  --jdk /absolute/pinned-temurin.tar.gz \
  --seed-tool /absolute/extracted-qemu/usr/bin/genisoimage \
  --output /absolute/new-private-reference
python3 tools/release-certification/restricted/pr313_fixtures.py \
  --source /absolute/clean-source-with-builds \
  --output /absolute/new-private-fixtures \
  --product-source-commit EXACT_PRODUCT_COMMIT
python3 tools/release-certification/restricted/pr313_acceptance_runner.py \
  --source /absolute/clean-source-with-builds \
  --output /absolute/new-private-suite \
  --prepared-image /absolute/new-private-reference/prepared-pristine.qcow2 \
  --prepared-image-digest EXACT_PREPARED_IMAGE_SHA256 \
  --qemu-root /absolute/extracted-qemu \
  --seed /absolute/new-private-reference/seed.iso \
  --ssh-key /absolute/new-private-reference/guest-key \
  --known-hosts /absolute/new-private-reference/known_hosts \
  --host-key-pin-origin preselected-host-key \
  --prepared-fixtures /absolute/new-private-fixtures \
  --fixture-manifest-digest EXACT_FIXTURE_MANIFEST_SHA256 \
  --product-source-commit EXACT_PRODUCT_COMMIT \
  --profile tcg-multi --timeout 3600
```

Read the fixture digest from its newly created `manifest.private.json`; retain its neighboring
bounded diagnostic privately. The existing Java producers create signed catalogs, apps and the
modified API fixture under an explicitly recorded local Java 25+ runtime. The closed input tree
excludes producer signing keys. This removes repeated trusted producer work from the guest;
installed export/signature verification and real CMS/consumers still execute there. Producer
inputs contain no precomputed acceptance verdict.

Failed trusted guest fixture commands produce a bounded private record of the actual executable,
JDK/tool identities, argument/environment digests, phase, deadline, elapsed time and fixed fatal
signal/frame classifications before fixture teardown. Raw `hs_err` files are not retained by this
recorder; that limitation is explicit. The attempt driver retrieves at most 256 KiB privately.
Neither this record nor private canaries are included in the public assessment.

Preparation schema 5 snapshots the base image, JDK, tools, resolved ELF dependencies/modules and
firmware. Attempt schema 7 snapshots its standalone backing, seed, SSH key and trust file before
launch. Fixed environment and loader options avoid ambient JVM/QEMU/SSH configuration. Disk,
seed, keys, private commitments, logs and full boot inventories remain owner-private; public
projection excludes seed and host-key commitments. Earlier reports remain unchanged.

The runner assigns `positive`, `native-hostile`, `output-hostile`, individual `fault`, `worker`
and `public` groups to fresh guests under one required identity. For focused diagnosis use
`pr312_reference_vm.py --mode native-slice --case-group GROUP`, with `--fault-case CASE_ID` for
individual cases and the same reference/fixture arguments. A focused group is not the complete
suite. The 180-second readiness limit, 900-second owner budget and native bounds are unchanged;
fixture preparation has its own 900-second ceiling.

Only a complete verified inventory with matching source/environment identities and owned guest
cleanup can satisfy `installedKeylessNativeAcceptanceSatisfied`. Offline positive verifier tests
exercise a reachable contract; they do not fabricate installed observations. Hosted prerequisites
remain offline/exit-78 when a VM is unavailable. Never upload private attempt roots, disks, seeds,
raw diagnostics or prepared signing material, including after failure.

## Local verification

The local verification below ran on 2026-09-16. Counts describe these commands, not unique
security requirements or installed coverage. The prepared PR-307 invocation explicitly selected
the separate product commit; an earlier invocation without that binding failed setup and was
retained. Native fault Java source also compiled with the actual Java 25 compiler.

| Check | Observed result |
| --- | --- |
| Restricted Python discovery, with extracted real `qemu-img` selected | 249 tests passed, no skips |
| Protected `test_restricted_*.py` discovery | 73 tests passed |
| Protected `test_native_*races.py` discovery | 21 tests, three root-only skips on the unprivileged host |
| `stable-maintenance --self-test` | 247 tests passed |
| `cross-version-soak --self-test` | 152 tests passed |
| `stable-platform-api-1x --self-test` | 88 tests passed |
| `phase-12-closeout --self-test` | 185 tests passed |
| Real prepared-input PR-307 integration at `ce1de26641` | One test passed in 44.561 seconds |
| Local PR-307 integration with independent owner-phase hooks | One test passed in 47.970 seconds; all six phase lifetimes observed |
| `./gradlew :platform-devtools:installDist assembleCryptadDist` | Successful; 342 tasks, 307 executed and 35 up-to-date |

The build was **not analyzer-clean**: its log contained 329 Error Prone warnings, including
86 `ReferenceEquality`, 77 `EffectivelyPrivate`, 55 `ExposedPrivateType`, 34 `PreferThrowsTag`,
29 `AlmostJavadoc`, and 48 other warnings. The Gradle problems report contained 66 warnings
(36 deprecation, 15 Kotlin and 15 compilation). No independent security review, standalone
Sonar/SpotBugs result, final-source hosted CI result or protected workflow execution is claimed.

## Preserved limits and PR-314 handoff

The scoped verdict remains distinct from implementation coverage, reference preparation,
production readiness, synthetic native/CMS observations and hostile/lifecycle execution.
`mandatoryIsolationTestSatisfied`, `productionAuthorityObserved` and `phase12Complete` remain
false for this local finite-native result. Retain all 49 mandatory requirement IDs and the
historical 47 unresolved assertions at their existing cutoff; new execution is dated separately.
The twelve PR-309 composed-budget consumer cases remain deferred, not waived.

PR-314 is `controller-owned-workload-role-isolation`: separate long-running daemon/app roles,
observer storage, sibling management networks, bounded observation, and full restart/terminal
reconciliation. The finite profile is the fixed `cryptad-restricted-native.service`, keyless
launcher, read-only selected inputs, fresh private proc/network, bounded writable scratch/output,
no host capabilities, no-new-privileges and disabled descendant user namespaces. Its exact
accepted reference identity must come from a completed suite; none is claimed above.

Keep `restricted-workload-observer-boundary-unavailable` on supervisor authorize/start/checkpoint.
Finite sibling-canary denial does not certify long-running administrative-plane separation.
Budget consumer work resumes according to the dependency audit after that boundary; no Phase 13
is opened by this result. Historical attempts, freezes, runtime approvals and original evidence
retain their existing bytes and clocks.
