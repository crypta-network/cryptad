# Installed resolver readiness and finite keyless native execution

PR-312 adds authenticated installed startup and a separate fixed service for the two finite
maintenance native verifiers. It does not implement long-running workload roles or complete
Phase 12. Installed acceptance is recorded separately from source and offline tests below.

Review correction: the earlier preparation/attempt reports hashed a QCOW2 overlay without
authenticating its backing file. Their recorded prepared-image digests do not bind the complete
guest filesystem. The observations below remain historical execution records, with this additional
environment-identity limitation; they are not acceptance of the corrected driver.

## Integration and bounded scope

The implementation starts from `develop` squash `e7ae58ef607c8073cd8db858f2366a387913572e`,
tree `af82f27acc7d1b2ab6ee856d50a5df9d98f96523`. The refreshed PR #1413 record reports a merge
at `2026-09-15T13:18:51Z`. Its final feature head `99bbb770a9a63f3c671b0c1ac92ea0bd302a7c6a`
has that same tree. This verifies containing changes rather than requiring squash ancestry.
The PR-triggered successful CI runs recorded by PR-311 remain predecessor results, including
skipped Beta publication and offline restricted prerequisites. They are not this branch's CI.

The outer interface remains `{method, handle}`. Supervisor authorize, start and checkpoint still
reject `restricted-workload-observer-boundary-unavailable`. Native success supplies no daemon-role
profile, runtime approval, original provider proof or independent security review.

| Existing owner | Observed gap | Implemented boundary | Compatibility and executable acceptance |
| --- | --- | --- | --- |
| Installed bootstrap and worker | `Type=simple` reports execution before Python admission; the bootstrap's native probe inherits resolver restrictions | Main-only systemd notification after source/dependency/kernel/profile and activation-descriptor checks; private bounded startup history | Fixed 180-second startup bound; actual installed socket UID/unknown-handle tests |
| `restricted_native` | UID-dropped resolver descendants inherit incompatible seccomp and protected proc mounts | One fixed manager-started `cryptad-restricted-native.service`, selected by root-retained invocation, separate from resolver ancestry | Actual bubblewrap setup under the new unit; fixed package API and app projection commands only |
| Package metadata and signed projection owners | Native status/output alone cannot authenticate a subject | Same native output contracts and existing Python/Java owner validators | Packaged product/API relationship, exact signed catalog/app/scope checks and wrong-subject rejection |
| Worker intent and retained results | Revocation could arrive during work/final validation | Recheck registration, inputs, expiry and revocation before retaining new result; original monotonic budget shared with native work | Completed exact retry returns retained bytes; interrupted intent never blindly reruns |
| Installer and disposable test owner | Production imports cannot include provider substitutions | Manifest-v2 physical exclusion, independently matched test kit and separate synthetic owner | Resealed production manifests containing test drivers reject; layer-2 execution is labelled synthetic |

## Readiness and private diagnostics

`cryptad-restricted.service` uses `Type=notify`, `NotifyAccess=main`, `Restart=no` and
`TimeoutStartSec=180`. Bootstrap captures only `/run/systemd/notify` from systemd, checks its
root-owned socket and ancestry, and connects a non-inheritable descriptor. Environment cleanup
removes the notification address. Native services inherit no controller descriptors or environment.

The fixed main process sends `READY=1` only after complete helper/dependency verification,
actual root UID/GID, five capability sets and `NoNewPrivs` checks, effective unit/policy checks,
and the fixed native prerequisite. Worker initialization also requires its exclusive lock and
FD 3 as the listening stream socket at the exact installed address. Exec success and socket
listening remain separate from readiness and request admission.

Private mode-0600 append-only attempt files under `restricted/bootstrap` contain fixed stage/status
names only. Creation and entries are synced. The 128-attempt cap refuses further startup rather
than replacing failed history. Exhaustion requires administrator reconciliation. Notification is
not sent if a prerequisite or diagnostic write fails. Public failure remains a fixed rejection;
raw exception text, input excerpts and dependency paths are not journal or socket output.

## Selected native construction profile

The resolver retains its existing `RestrictSUIDSGID`, protected kernel/proc/control-group settings,
no-new-privileges, capability bounds and private state restrictions. The only added writable root
is `/var/lib/cryptad-restricted-native`, provisioned root-owned with native-group traversal.
The controller uses fixed systemctl verbs for one literal unit; no request supplies transient
properties, a unit, executable, classpath, mounts, environment or PID.

The new unit starts immutable isolated Python as `cryptad-native`, with no host capabilities and
`NoNewPrivileges=yes`. Its private `/run` is limited to 16 MiB/256 inodes and private `/tmp`
to 80 MiB/4096 inodes; it also has fixed task, memory, CPU, file and time
limits. It does not inherit the resolver's incompatible sandbox-construction restrictions.
The trusted keyless launcher executes no candidate instruction until bubblewrap has established
the full namespace and mount boundary. After mounting the selected writable directories it
remounts the generated `/dev/pts`, `/dev` and root filesystems read-only, without recursively
changing the selected writable mounts. A local unprivileged probe established that root/device
directory writes fail while `/tmp`, `/scratch`, `/output`, null writes and random reads work;
the installed fixture independently checks the directory denials. This correction is newer than
the first changed-bundle VM observation recorded below.
The fixed read-only runtime mounts are `/usr`, `/lib` and `/lib64`; selected staged roles appear
only at `/jdk`, `/tools`, `/inputs` and `/work`. The candidate gets fresh `/proc` and fixed devices,
with writable `/tmp`, `/scratch` and `/output` backed by the bounded private filesystems. No
resolver, credential, host-home, management-socket or host-proc bind is added.
The launcher also requires bubblewrap's explicit user-namespace creation, `--disable-userns`
and `--assert-userns-disabled`. Dropping current capabilities alone permits a candidate to create
a descendant user namespace and obtain mount capabilities there, bypassing scratch mount quotas.
The fixed flags prevent that route; setup failure remains denial. The development container's
inherited proc restrictions prevent this stricter construction, so its success must be established
under the actual compatible VM unit. Local tests of the earlier profile are not evidence for it.

Source copying pins ancestors and entries with directory descriptors and `O_PATH`, validates
the pinned inode's size before reading, and rejects changed directory or parent/name bindings.
Installed source roots and members must be root-owned and nonwritable by group/other. A
root-owned sticky ancestor such as `/tmp` is allowed only above a root-owned nonwritable child.
This closes a reproduced ancestor-symlink substitution in the earlier copier; the previously
computed staged digest alone did not detect substitution from the authenticated source tree.
The fix postdates attempt 6 and therefore requires a new immutable installed bundle.

| Mechanism omitted from native construction parent | Original invariant | Replacement before candidate execution |
| --- | --- | --- |
| `RestrictSUIDSGID` | Prevent set-ID privilege acquisition | Empty host capability sets, kernel no-new-privileges, stripped copied modes, read-only runtime/input mounts and bubblewrap capability drop; set-ID/file-cap execution needs actual hostile testing |
| `ProtectKernelTunables` protected proc submounts | Deny host kernel control/visibility | Fresh proc inside the candidate PID namespace; no parent proc bind and no host sysfs mounts |
| `ProtectControlGroups` inherited protected mounts | Deny cgroup manipulation | Candidate root has no host cgroup filesystem; native UID has no manager authority; controller alone manages the fixed service |
| Parent-wide filesystem protection flags | Prevent trusted-file mutation and private-state access | Root-owned immutable staged inputs and a closed bubblewrap mount roster; only private bounded output/scratch writable; resolver/keys/home/sockets absent |

These replacements apply to the native service only. No host `CAP_SYS_ADMIN` or `CAP_SYS_PTRACE`,
privileged mount broker, shell-command service or seccomp emulation is introduced. Kernel
no-new-privileges alone is not treated as the complete boundary.

Systemd 257's SUID/SGID filter explicitly returns `ENOSYS` for `openat2`; an exec descendant cannot
remove inherited seccomp restrictions. Protected mounts inherited into a less-privileged namespace
can also remain locked. Those mechanisms motivate independent service construction, but do not
prove the effective distribution profile. See [systemd seccomp source](https://raw.githubusercontent.com/systemd/systemd/v257/src/shared/seccomp-util.c),
[service notification](https://raw.githubusercontent.com/systemd/systemd/v257/man/systemd.service.xml),
[Linux seccomp inheritance](https://raw.githubusercontent.com/torvalds/linux/v6.12/Documentation/userspace-api/seccomp_filter.rst)
and [mount namespaces](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html).

## Invocation, output and recovery

A root-retained record binds operation/registration/helper identity, invocation generation,
exact staged tree identities, fixed native sub-operation/profile, output bound and absolute
monotonic deadline. The launcher reconstructs package export or signed app projection; it never
accepts a generic command list. App inputs remain read-only at `/work`; the existing CLI's
`--private-root` uses separate scratch and its output goes to a dedicated bounded filesystem.
The scoped public verification keys are inputs; recipient keys and original-provider credentials
are never staged.

A serial lock prevents concurrent native lifetimes. Root records systemd's invocation ID and
literal cgroup, checks that identity during the wait, and stops the separate service on completion
and failure. The launcher requires its own PID to be the only remaining cgroup member before
exporting files. The controller then confirms the service cgroup is empty before collecting output
or allowing UID reuse. Revocation cannot prevent owned stop/reap. Cleanup failure retains the
active marker and private artifacts as reconciliation-required state.

Output is untrusted. Both pipes are drained concurrently under an absolute deadline and size
bound. Closed output rosters and descriptor-based collection reject special files, links,
multiple hardlinks, incomplete reads and detected ancestor/file replacement. The package operation
returns its existing bounded JSON on stdout; signed projection returns `projection.json` bounded
to 32 KiB. Existing owning validators reconstruct subject relationships; a success status or
native JSON cannot mint an authenticated Python capability.

Successful staged input copies may be removed only after confirmed quiescence; expected identities,
intent/results and failed attempts remain. At most 64 invocation directories are admitted.
An invocation stages at most 4 GiB; admission refuses when previously retained input bytes exceed
4 GiB, so the combined retained/staging ceiling is 8 GiB. An incomplete staging record reserves
its full 4 GiB in that accounting. Capacity exhaustion fails closed. Deleting an operation is not
a supported retry or recovery mechanism. There is no automatic reconcile/resume command for an
uncertain active marker; it requires operator resolution while artifacts remain private.
Exact completed outer retry/collection returns original retained bytes without native rerun,
decryption, approval renewal or re-encryption. An interrupted outer intent requires operator
resolution. This is local retained-result idempotence, not distributed exactly-once execution.

## Disposable reference and acceptance layers

Use the dated Debian image and verified JDK archive described in the
[PR-311 reference record](pr-311-observer-workload-isolation.md#disposable-reference-preparation-and-acceptance).
The driver uses unprivileged QEMU TCG, a fresh overlay for every installed bundle, restricted
localhost SSH forwarding, and no host filesystem sharing or guest-accessible management socket.
Provisioning runs only inside that explicitly selected fresh guest with synthetic material.
The private attempt directory retains failed disks/logs; its separately constructed stage report
is the only exportable output. Guest stop is checked on every exit.

```bash
./gradlew :platform-devtools:installDist assembleCryptadDist
python3 tools/release-certification/restricted/pr312_prepare_reference.py \
  --qemu-root /absolute/extracted-qemu \
  --image /absolute/pinned-debian.qcow2 \
  --jdk /absolute/pinned-temurin.tar.gz \
  --seed-tool /absolute/extracted-qemu/usr/bin/genisoimage \
  --output /absolute/new-private-reference
python3 tools/release-certification/restricted/pr312_reference_vm.py \
  --source /absolute/clean-source-with-builds \
  --attempt /absolute/new-private-attempt \
  --prepared-image /absolute/pinned-prepared-reference.qcow2 \
  --prepared-image-digest EXACT_PREPARED_IMAGE_SHA256 \
  --qemu-root /absolute/extracted-qemu \
  --seed /absolute/disposable-seed.iso \
  --ssh-key /absolute/disposable-guest-key \
  --known-hosts /absolute/preselected-guest-known-hosts \
  --host-key-pin-origin preselected-host-key \
  --product-source-commit EXACT_PRODUCT_COMMIT \
  --mode native-slice --timeout 3600
```

The preparer verifies the exact dated image/JDK bytes, provisions only its fresh selected guest,
and generates a guest SSH host key before boot. The execution driver requires an explicit host
key pin, disables agent forwarding, and ignores ambient SSH configuration. The private pin copy
is read through one opened source descriptor and hashed after copying, so
the reported pin digest identifies the file SSH actually uses even if the source path is replaced.
The product digest likewise comes from the copied JAR in the private archive tree, after all
product trees have been copied, rather than from the live build directory. This binds the reported
JAR bytes, not an atomic snapshot of a concurrently changing build. Preparation copies its three
reported executables (QEMU, qemu-img and genisoimage) through opened descriptors into private
mode-0500 files, then hashes and executes those copies. These executable hashes do not authenticate
the host loader, shared libraries, QEMU modules or firmware. Historical reports predating these
copy-before-hash fixes retain the corresponding source-replacement limitation.
Extracted QEMU and
the pinned downloads are explicit prerequisites. Neither driver creates production approval. Preserve the
prepared image digest and original base image/JDK verification. TCG timing is not a performance
baseline. A development snapshot has its own source identity and is not an authenticated later
commit merely because the files appear similar.

Schema-3 preparation now converts the stopped guest disk into a standalone QCOW2 image before
publishing its digest. It retains the original guest overlay as private diagnostic material.
Schema-3 attempts copy that standalone image into their new private directory, verify the copy's
expected digest and reject backing-file or external-data-file metadata before creating the guest
overlay. Only the private verified copy supplies backing bytes at boot. This costs one additional
prepared-image copy per attempt; it prevents later replacement of the caller's image from changing
the booted storage. Old backed prepared images are rejected even when their overlay digest matches.
Prepare a new reference with the corrected tool; flattening an old failed attempt does not repair
its historical evidence. No corrected full preparation or installed VM run has yet been observed.

Schema-4 preparation additionally copies the base image through one opened source descriptor,
verifies the private copy against the pinned SHA-512 and checks that it is standalone before using
it as the guest overlay's backing file. Schema-4 attempts retain the caller's seed through the
same descriptor-copy mechanism, publish `seedDigest` for that retained file, and mount only that
copy. This identifies the boot medium; it does not approve arbitrary cloud-init configuration.
Earlier reports do not establish these base-snapshot and seed-identity guarantees. The extra base
and seed copies remain private, and the base snapshot requires additional local disk capacity.

Schema-5 attempt reports add `qemuSha256` and `qemuImgSha256` from retained private executable
copies, which are used for image verification, overlay creation and guest execution. Preparation
and attempts share the executable-copy mechanism; these hashes do not assert equality with the
preparation toolchain or authenticate shared libraries, modules or firmware. The attempt driver
rejects root execution and comma, newline, carriage-return or NUL characters in its output path
before creating the attempt or invoking helpers. Earlier attempt reports do not establish these
tool-identity and host-admission checks. No corrected installed run is claimed by these changes.

Schema-6 attempts report `productSourceCommit` only after the full selected commit resolves to a
commit in local Git and the existing packaged-daemon verifier matches that commit against the
copied JAR's embedded revision. The verifier's JAR digest must also match the copied product digest.
This runs before archiving or boot in every mode, including baseline. The report labels the check
`productSourceVerification: local-git-and-embedded-marker-v1`. The embedded revision is a package
claim checked for consistency, not authenticated original-provider/build provenance; production
authority remains false. Earlier reports did not establish this host-side source-marker check.

The focused real-QEMU storage regression uses tiny synthetic disks without booting a guest. It
reproduces an unchanged overlay digest after backing-byte substitution, checks rejection, exercises
the preparer's conversion, then deletes the original backing file and verifies that the standalone
image still supplies the original bytes. It also rejects a real QCOW2 external data file. Run with
`qemu-img` on `PATH`, or set `PR312_TEST_QEMU_IMG` to an existing extracted binary (with its required
library environment); absent QEMU is an explicit skip, not executed storage coverage.
The host driver's finite 3,600-second installation/test envelope does not extend the installed
180-second startup limit, the existing 900-second owner request budget or either native bound.

1. **Production bootstrap:** exact installed production code and unit, verified readiness and real
   socket admission. No provider seam is used.
2. **Synthetic owning native/CMS integration:** separate administrator-owned test driver supplies
   synthetic upstream responses. Installed adapter, native Java, CMS and owner validators execute
   their actual implementations. The test driver is not the production controller and its output
   is not production-eligible retained evidence.
3. **Original protected operation:** requires actually supplied original authorized inputs. This
   session has none; this layer is not observed.

The hosted prerequisite job still treats exit 78 as `executed=false`. Its report cannot satisfy
`installedKeylessNativeAcceptanceSatisfied`. The broad `mandatoryIsolationTestSatisfied` flag
remains false even when finite native positives pass. Full hostile/lifecycle acceptance must be
reported individually; a harmless probe is not both real operations or the full matrix.

The fixture implements actual native UID/capability/NNP checks, synthetic resolver/sibling
canaries, fixed mount/env/FD/proc/network denials, set-ID/file-capability no-gain, safe `openat2`
with explicit symlink/traversal rejection, timeout, pipe overflow, `setsid` descendants and an
unexpected output roster. Those assertions count as executed only when the installed attempt
reaches and records their modes. Offline manager mocks cover lost responses, stale invocation
identity, revocation callbacks, failed collection and cleanup failure; they do not simulate the
kernel effect of those faults.

Additional local worker tests join the real registration-revocation checker to native cleanup
through a fake manager, interrupt the response after the real durable result write and verify
byte-exact retry/collection without reexecution, and reject a recognized bearer-secret pattern
through the actual public-result scanner before persistence. They preserve intent on failure.
The scanner case does not establish rejection of every arbitrary private identifier or hash.

Additional executable test-only cases now cover an exact prior invocation's retained output,
seeded private observer state, a synthetic revocation callback after the owned Java process
starts, and loss of the real manager's start response. These transport injections do not claim
production registration revocation. A separate fixed Python exporter exercises the installed
app adapter/collector with symlinks, a hardlink roster, FIFO/socket output, oversize output,
and detached writers racing or holding output until timeout. Its tiny unused synthetic JDK is
explicitly not Java verification evidence. The control case requires exact `EPERM` for native
character-device creation. Every hostile case requires an executed-attack marker and quiescence;
unrelated setup failure cannot pass it. These additions postdate attempt 3.

Executable VM fault coverage is still missing for direct concurrent input/collector replacement
injection, production registration revocation during native work, controller death between every
durable stage, and adversarial candidate data in public result export. There is no active sibling
management-server fixture. These are missing acceptance fixtures,
separately from an existing fixture whose execution stops at an earlier ladder stage. The
controller/native adapter and both owner call paths are implemented; original protected layer 3
remains unobserved without original authorized inputs. None of these gaps is closed by a local
unit test or a successful earlier installed probe.

## Execution record

A fresh exact predecessor guest installed merged source `e7ae58ef607c8073cd8db858f2366a387913572e`
with bundle `65f9514c58d325a4b8c059eb48f8fa0aee1f566129e2befb7e18f44e89b61f31` and the separately
recorded product source `7008f19c9f573b94c53d7b5381fc8f41ad07be87`. Its bounded 60-second real
unknown-handle observation failed. This external 60-second bound did not run out the original
900-second client budget or establish a bootstrap failure cause. No authenticated readiness or
semantic-denial success is claimed.
The failed guest was stopped; its private overlay and reports remain. Its original backing image
became unavailable during the session, so the overlay cannot currently support disk reinspection.
The retained request report records admission unavailable within that observation, separately
from historical snapshot `3c898024…`; the exact old capability diagnosis is
not attributed to this attempt.

The first changed-bundle execution (`development-native-attempt-2`) used development commit
`872805da630c91197353bffd282c883752365d74`, tree
`4b2d3f6b9ed62f4e93de4ee7d6c3bf8d85523093`, installed bundle
`8956cf2b37f5a6b2fbc2c0144391811629eb92f348993d660ef034644e6c7f28`, and product commit
`e7ae58ef607c8073cd8db858f2366a387913572e` with JAR SHA-256
`4dcbd698d2268124229cd2cbba15d7c939eaa6a587b28b098d500416c7576d1f`.
Its recovered prepared image SHA-256 was
`0354db86d4d081c8fb03ac2682d8bfed0783ab4de664e363cc04b9b438636553`.
This reference was prepared by a private recovery script; it does not establish execution of the
later tracked preparer. SSH used first-connection trust in this attempt, not a preselected host key.

The actual installed production main process completed all private bootstrap stages and sent
the notification accepted by systemd. Actual socket unknown-handle and wrong-UID rejection,
role capability/DAC denials, production/test separation, and the fixed manager-native probe
passed. Four native invocations were fixed probes; none was a Java operation. The run stopped
at `native-cms-owning-consumer`, guest exit 2, and stopped the owned guest. The fixture discarded
its unittest diagnostic, so this attempt establishes no cause for that failure and no native/CMS
consumer success. A subsequent source change retains a bounded private fixture log. This failed
attempt remains in history; later success cannot replace it.

An earlier changed-source attempt (`development-bootstrap-attempt-1`) did not launch a VM:
its original backing assets were unavailable. It remains `executed=false`, separately from the
executed failure above. Subsequent installed observations and final test counts are recorded
below as they complete.

The tracked reference preparer subsequently executed successfully with the same pinned base image
and JDK, verified the effective distro packages, and stopped its guest. Its prepared image SHA-256
is `60c746ff1a6a28329c20483931c5f233acb05a62bc91607b1f6376e78656354b`.
Attempt 3 used that reference and preselected SSH host-key verification with helper
`bba9e49e1084228a0a98f658f7adb32dc3d02235`, tree
`12b5dd59e1b7fc968711927b2009a0a778e27ddf`, bundle
`8c5a8a867722a3c1b624a19c292ca8a546f09ddaa11c348b1261a8d108e6f2ac`, and the same product bytes
as attempt 2. It again established production readiness, actual socket denials and fixed probes,
this time with the read-only generated mounts and disabled descendant user namespaces.

Attempt 3 stopped at `native-cms-owning-consumer`, exit 2; the guest stopped. One fixture ran
for 163.257 seconds before the owner rejected `runtime-metadata-input-link` while processing the
ordinary maintenance product. No Java native invocation ran. The private diagnostic established
that fixture resource paths traversed test-kit/current symlinks. The correction resolves resources
to the exact immutable installed bundle while leaving Python test imports in the separate kit;
the production input-link rejection is unchanged. This is a test-owner path fix, not a successful
native/CMS observation or an attribution of attempt 2's previously discarded diagnostic.

Attempt 4 used helper `62d7a4fcc5c17cc141335eda5bfe2fd10e51de23`, tree
`aa66dd5b91e62c983360e882b4c42fd1c915b194`, bundle
`f340784fa4f4cb6b7bdffa6331f0573f4f6352f1c67ae76ed185717dc473ab2c` and the same reference/product
as attempt 3. Readiness and socket/native-probe checks passed. Trusted fixture class setup failed
with `CalledProcessError` after 42.545 seconds, before any test method or native Java invocation;
the run exited 2 and stopped its guest. The available diagnostic did not identify subprocess
stderr, so no cause is attributed to that failure.

Two separate diagnostic overlays retained the stopped attempt-4 disk unchanged. The first failed
before imports because its standalone driver selected the wrong installation directory. The
second ran the unchanged trusted legacy fixture setup successfully and stopped. It did not repeat
a native operation, original request or acceptance lane. Thus the setup failure was not reproduced
outside the original harness context. The next source adds a bounded private setup diagnostic sink
and an independent package-API stage before the larger signed-fixture setup. That stage wraps exact
installed product bytes in a labelled synthetic archive, checks them against selected source-product
bytes, and runs the existing installed exporter, schemas and package-identity owner. It creates no
original release authority. All request/native budgets remain unchanged.

Attempt 5 used helper `34ad6d27481999c53e7dfa076da37c96134b8ba3`, tree
`cb184df077f3138b50fae2382cfc3eeef9b9a3d2`, bundle
`d3375cbbc40c1f4116c487a4693bb00663e068c1ace2a2b1af7566a1a51a967e` and the same pinned reference
and product. **The installed real package-API export and owning validation passed**, alongside
readiness and socket denials. Its five retained native invocations were four fixed probes and
the actual package operation. The native unit was quiescent before accepting that observation.

The run then failed in trusted signed-fixture preparation (`CalledProcessError`, one test,
117.929 seconds), before signed-app/CMS success, and stopped its guest with exit 2. A separate
diagnostic overlay subsequently completed the unchanged trusted setup, catalog compilation,
catalog generation and fixture export using the sanitized environment; it also stopped. The
failure was not reproduced outside the full harness context. The next test-only source extends
the bounded private diagnostic sink to the test body; no resolver or native protection is relaxed.
The closed host report now exposes only allowlisted completed dimensions, a fixed failed stage
and the installed bundle digest; raw diagnostics remain private.

Attempt 6 used helper `0f8bd99df6b3f94f0c99429c9b33af153d6da8b7`, tree
`93adb145ed19a1b3e49e72f46ad90a97e5e35a3e`, bundle
`c8544eabce09a287dd482cbec2199d6f861d035fab7de2b02b22d4aabbcefb41` and the same reference/product.
Readiness, socket denials and installed package export/owner validation passed again. Its labelled
synthetic package digest was `73b8f414e9daf10ad87ded08f783374589a9bed79b7285c47501e2f3dc230388`;
the contained `lib/cryptad.jar` was 10,231,556 bytes with digest
`4dcbd698d2268124229cd2cbba15d7c939eaa6a587b28b098d500416c7576d1f`, matching the selected product.
The bounded private package observation explicitly records `productionEligible=false`.

The trusted fixture setup then failed before running any test method (39.764 seconds). Its new
private diagnostic captured Temurin aborting after `SIGILL` in JIT-compiled
`java.lang.System$1.uncheckedCountPositives`, outside the installed native boundary. The run
stopped its guest and retained the fatal diagnostic privately. This establishes attempt 6's
failure; it does not retroactively prove the cause of earlier discarded subprocess diagnostics.
The QEMU `max` CPU configuration requires a separate bounded compatibility diagnosis. No JVM
flag, resolver protection, native deadline or acceptance assertion was changed for this failure.

A subsequent bounded diagnostic used separate overlays of the stopped attempt-6 disk and ran
the trusted fixture exactly three times per CPU model. Both `max` and `qemu64` compiled and
passed all three executions. The fatal instruction bytes did not establish a specific unsupported
AVX instruction, and this comparison did not reproduce the integrated failure or establish a
CPU-model remedy. Both diagnostic guests stopped; their observations are not acceptance attempts.
QEMU's [CPU-model documentation](https://www.qemu.org/docs/master/system/qemu-cpu-models.html)
describes `qemu64` as a generic model with a restricted feature set. Any prospective use of that
model must be recorded as a changed VM environment and tested through the full installed lane.
The prospective driver now selects fixed `qemu64` with `tcg,thread=multi` and records both fields.
It reuses the exact previously prepared image bytes, which were prepared under `max`; no old
preparation report is rewritten. This is a candidate compatibility configuration, not a proven
fix or a performance baseline.

Attempt 7 used helper `db0683a9f16abd30c58ba7c65bdd697ff7a7638d`, tree
`8c43ef11665c052a1025d0cca5a560c028bee7c5`, bundle
`99bf564b61e84b0e91e65d86bfbdbf379696b88d160ba37c8ff082813e2aaf3c`, the same prepared image and
product, and the recorded `qemu64` CPU model. Authenticated readiness, socket denials and real
package export/owner validation passed with the new anchored input-copy checks. Four fixed probes
and one package invocation ran. No installed app-projection invocation ran.

Trusted Java fixture setup progressed without an observed `SIGILL` in this attempt, but ordinary
maintenance-product fixture creation failed in a direct `crypta-app` invocation before the
installed app adapter. The available exception lacked that direct helper's stderr; no JVM or
semantic cause is attributed to it. The guest stopped with exit 2. A separate stopped-disk
diagnostic overlay subsequently ran the exact input-copy test kit against the installed native
module as guest root: 12 tests, 11 passed and the nonroot-only case skipped. This covered the
three root ownership/sticky-directory fixtures skipped locally, and did not launch native work.

One subsequent trusted `h.cohort` diagnostic with bounded direct-helper capture reproduced a
Temurin `SIGILL` in C1-compiled `java.util.regex.Pattern$Branch.match` under `qemu64` and
multi-threaded TCG. Its guest stopped. This rules out treating the narrower CPU model as an
established remedy; it does not establish a particular emulator or JDK defect. QEMU documents
[compiled-code invalidation and synchronization in multi-threaded TCG](https://www.qemu.org/docs/master/devel/multi-thread-tcg.html).
That mechanism motivates a separately recorded, single-execution diagnostic with
`tcg,thread=single`, preserving the JDK, command arguments and all operation limits. It is a
compatibility hypothesis rather than security or acceptance evidence.
That single-threaded diagnostic reached its predeclared 300-second script deadline without
completing, and the owned guest stopped. It did not establish a compatible replacement. The
execution driver therefore retains the explicitly recorded `qemu64`/multi-threaded TCG profile;
the next fresh ladder seeks the new focused app-stage observation before the larger fixture and
will stop at its first unsatisfied layer. No retry-until-success or deadline extension is used.

The prospective test kit adds a focused signed-app stage before the larger CMS fixture. It uses
the existing Java signed fixture, exact installed toolkit/materialized JDK, and unchanged installed
app adapter and Python owner. A wrong-app case must retain a real manager invocation and native
failure before it can count as rejection. Compile/generation diagnostics are bounded and private;
synthetic original artifacts never become production-eligible receipts. The larger test owner's
direct helper failures also retain bounded private diagnostics without changing command arguments,
environment, deadlines or output limits.

### Latest installed observation: attempt 8

Attempt 8 passed authenticated production-bootstrap readiness, real socket UID/unknown-handle
denials, the installed package API export and owning validation, and the installed signed-app
projection with owning validation. Its wrong-app case was rejected through an actual native
invocation. These are development observations with synthetic upstream context, not original
protected maintenance receipts or independent security review.

| Identity | Exact value |
| --- | --- |
| Helper commit | `84edcaf27187deab0145de917ee4fbf27d0f90f9` |
| Helper tree | `4fc71e5b20e1398670313a3ed921fc21bfa9bb29` |
| Installed bundle | `592433b43635a806dfcc4e4f783bba3f793803f127bf765c5f120f0523e25b9b` |
| Separate test-kit manifest SHA-256 | `78eb5c432a42e5c5ebc2e3c9c21b5543a1bc052d5bd5b4aaee85043ae3ecaba7` |
| Installed execution record SHA-256 | `099c9ff02633ef54e5ec2c622033a7144148914f479a8f144e287b3099423a3d` |
| Canonical dependency closure | `sha256:6385e23986910e5ab0b5f1dd84320ed5809f2b408d0ebbd2d965a296c2cf3936` |
| Source archive SHA-256 | `29e84c6bd90dc3acac3d4199fc9811703dea7539fb95d57dde44fb4df832c22e` |
| Prepared image SHA-256 | `60c746ff1a6a28329c20483931c5f233acb05a62bc91607b1f6376e78656354b` |
| Product source | `e7ae58ef607c8073cd8db858f2366a387913572e` |
| Product JAR SHA-256 | `4dcbd698d2268124229cd2cbba15d7c939eaa6a587b28b098d500416c7576d1f` |
| Synthetic package SHA-256 | `73b8f414e9daf10ad87ded08f783374589a9bed79b7285c47501e2f3dc230388` |
| Synthetic signed-app original SHA-256 | `2004adb228ea1170b70ce393e642c8c57f55c1e14a86f8430f2bf87780d7642d` |

The product member was `lib/cryptad.jar`, 10,231,556 bytes. The guest used kernel
`6.12.107+deb13-amd64`, systemd `257.13-1~deb13u1`, Python `3.13.5`, bubblewrap `0.12.0` and
Temurin `25.0.4.1+1`, with the recorded `qemu64`/`tcg,thread=multi` environment. A local byte
comparison found no differences across 754 certification, interop and workflow files between
the working tree and this isolated helper snapshot. This comparison does not authenticate a
future commit or approve a production environment.

The metadata-only offline audit verified the separate test kit's 181 files and
`productionEligible=false`, and the installed manifest's 5,853 files and
`production-without-test-seams-v1` export policy. The test-kit manifest records the helper commit;
it has no `sourceTree` field. The tree above was resolved from that exact retained local commit.
The audit records these distinctions in `offline-audit/metadata-identities.json` beneath the
attempt directory.

The larger CMS test then failed in `ordinary-maintenance-product` preparation: one unittest,
zero reported skips, 307.972 seconds, one failure. Its bounded private diagnostic captured a
Temurin `SIGILL` in C1-compiled `jdk.internal.classfile.impl.SplitConstantPool.entryByIndex`.
The failing invocation was a direct trusted fixture exporter, not the installed keyless adapter.
The subsequent installed hostile/fault, restart/retry and retained-result stages were not reached.
The run exited 2 and stopped its guest. Both installed acceptance flags remain false.

A bounded unprivileged offline audit of the stopped disk established exact native totals:
four probes, two package exports and two app projections. All eight retained manager identities;
seven completed and were collected. The one expected wrong-app rejection retained its failure
record, and no cleanup-failure record existed. The second package export occurred during CMS
fixture preparation. Existing `qemu-img`, `debugfs` and `e2fsck` operated only on private derived
sparse files, with no mounts, sudo, guest execution or edits to the original disk. The filesystem
was clean and `e2fsck -fn` returned 0. A final process check found no owned PR-312 QEMU guests.

The allowlisted report is
`/work/pr312-disposable-vm/development-native-attempt-8/stage-report.json`; the metadata-only
count audit is `offline-audit/audit-report.json` beneath that attempt directory. Raw logs, guest
disks, synthetic private material and candidate output remain private. Full installed acceptance
is incomplete; the missing fixtures listed above are distinct from implemented stages that were
not reached. No original protected operation or production approval was observed.

## Phase 12 and next slice

### Local verification

The following checks executed during implementation. They establish local behavior and source
consistency, separately from the installed attempt records above.

| Check | Observed result |
| --- | --- |
| `python3 -m unittest discover -s tools/release-certification/restricted -p 'test_*.py'` | 157 tests passed |
| Protected `test_restricted_*.py` discovery | 70 tests passed |
| Protected full `test_*.py` discovery | 365 tests, 53 skipped, remaining tests passed |
| PR-307 real product/consumer integration | One test passed, zero skips; actual wrong-app and wrong-product rejection included |
| Descriptor output race tests | Nine passed; real-file rewrite, inode/ancestor/link substitution, truncation and growth rejection, plus normal short reads |
| Descriptor input race tests | 12 tests: nine passed, three root-only fixtures skipped under development UID 1000; actual nonroot ownership denial passed |
| Worker lifecycle/result tests after fault additions | 24 passed; production revocation callback, post-durable lost response and actual redaction scanner included |
| `stable-maintenance --self-test` | 247 tests passed |
| `cross-version-soak --self-test` | 152 tests passed |
| `stable-platform-api-1x --self-test` | 88 tests passed |
| `phase-12-closeout --self-test` | 185 tests passed |
| Runtime snapshot readers / catalog original lifecycle | 10 / 10 tests passed |
| Cross-version test discovery | 184 tests passed |
| `./gradlew :platform-devtools:installDist assembleCryptadDist` | Passed with Java 25; 342 tasks, 91 executed and 251 up-to-date |
| Workflow actionlint / systemd unit syntax / whitespace check | Passed |

The Gradle problems report contained 49 warnings; task success is not an analyzer-clean result.
They comprise 34 Gradle deprecations and 15 Error Prone warnings: ten `ReferenceEquality`,
two `BooleanLiteral`, and one each of `AlmostJavadoc`, `UnnecessaryParentheses` and
`InlineFormatString`. The retained summary is `build/pr312-verification/gradle-problems-summary.json`.
The latest local PR-307 run after the private diagnostic callback change passed in 58.810 seconds.
The output race tests are local descriptor-reader evidence, not executed VM hostile probes.
No Java product source changed, and no new full Java-suite or resource-baseline pass is claimed.
The exact-base push Java/restricted prerequisite runs succeeded; the separately observed scheduled
dependency-intelligence failure is not attributed to these local changes. No CI ran on an
unpublished PR-312 commit. Local logs live under `build/pr312-verification`; some earlier temporary
logs became unavailable during the session, and later checks retain new logs rather than inventing
the missing ones.

### Preserved disposition

Runtime layout 2, layout-1 historical audit semantics, manifest-v2 physical test exclusion,
PR-307's five-member CMS/freeze and original authentication, baseline 1.0 and exact ciphertext
retry remain unchanged. The helper/profile change changes environment identity; no PR-308
reference, approval or historical freeze is rewritten.

Retain all 49 mandatory IDs and the existing 47 unresolved assertions at cutoff
`2026-09-13T10:30:00Z`. Fresh before/after assessments and their verifier establish local
consistency only. Long-running observer/workload storage, role launch, bounded observation and
sibling management-plane separation remain the PR-313 prerequisite. Then resume the twelve
PR-309 consumer cases in an explicitly selected follow-up; they are deferred, not deleted or
relabeled as operations-only debt. Mail, long observations, independent review, original protected
operations and publication obligations retain their existing scope and clocks.
