# PR-311 observer/workload isolation preparation

PR-311 is **implementation-incomplete**. The changes described here repair private identity
storage, hostile catalog output acquisition, production bundle contents, and disposable harness
lifecycle defects. They do not supply the controller-owned workload launch adapter. The restricted
supervisor authorize/start/checkpoint rejection remains in force. This is Phase 12 remediation.

## Actual starting source

The checkout started at PR-310's integrated squash
`7008f19c9f573b94c53d7b5381fc8f41ad07be87`, tree
`74743dc78517631a47856976bd6223e4ed043cf9`. GitHub #1412 merged on September 15, 2026 at
09:59:43 UTC, from amended head `52e30a7d3f9509859cccfd4bf6f1a7f40c54e800`. That head and the
squash have the same tree. The earlier planning head `5536c8f...` is historical.

The amended source already contains `preparation_provider()` with
`JOB_NAMES['maintenance-prepare']` and a regression through the real `authenticate_job()`.
The erroneous `JOB_NAMES['freeze-and-validate']` lookup is absent. The new tests extend the
original comparison checks; they do not replace the authenticator's verdict.

Changes are prepared on `feature/pr-311-observer-workload-isolation`. A local source snapshot,
installed helper bundle, dependency closure, and packaged daemon are separate identities. No
predecessor CI result validates an uncommitted successor diff or an installed guest.

## Implemented changes

### Prospective private identity layout

New runs write the observer's expected wrapper/JVM/config identity to:

```text
<experiment-root>/runtime/control/processes/<role>.json
```

`Supervisor.start`, periodic resource sampling, the standalone scheduler, and the scheduler
borrowing an existing supervisor all use the same private accessor. The recovery cohort has its
own experiment root. A candidate-authored `node/run/process-identity.json` is never a live fallback.

Directory traversal pins no-follow descriptors. Private control components require the observer's
owner-only permissions. Identity reads reject nonregular files, multiple hard links, oversized
records, replacement races, duplicate JSON members, and nonfinite/floating numeric tokens. Writes
use a new private temporary file, atomic replacement, and directory synchronization.

New checkpoints include `runtimeLayoutVersion: 2`. Live resume requires this version in addition
to the existing exact checkpoint authorization. Old checkpoints and identity files remain unchanged.
The explicit historical reader labels the old record layout 1 and isolation `not-established`;
it cannot authorize continuation or upgrade an old observation.

**The current daemon still shares the observer UID.** Moving the file removes its placement inside
the intended workload subtree, but does not yet prevent a same-UID daemon from accessing it.

### Bounded catalog observations

`runtime_snapshot.content_tree()` replaces the catalog adapter's unrestricted installed-tree
walk. It bounds depth, entries, per-file bytes, total bytes, and elapsed acquisition time. Linux
`O_PATH` pins a file before opening it for I/O; the helper validates a regular single-link object,
then reads its own fixed procfs descriptor reference. It rejects links, special files, changed
objects and replaced ancestors. A final metadata pass detects modifications to earlier files while
later files were being read. No partial row set is returned on failure.

These are sequential observations on the reference filesystem, not an atomic filesystem snapshot.
The time checks are cooperative; they do not preempt a blocked kernel filesystem operation. The
caller must still own an outer execution deadline. Candidate names and hashes remain private.
The resulting digest does not replace the expected admitted product digest.

The catalog packaged API exporter and both catalog scope-bootstrap calls now drain stdout and
stderr through the existing bounded-process owner. Oversized stderr cannot exhaust memory before
a post-exit size check. Only fixed error codes leave these paths. This transport change does not
confine their UID or establish cgroup-wide descendant termination.

### Production export and test separation

New installed bundle plans use manifest schema 2 and the fixed
`production-without-test-seams-v1` export policy. They retain exact source-commit and raw Git-blob
verification while excluding the disposable provider harness, unit probes, Python test modules,
and Python test directories. Verification independently rejects prohibited files even when an
otherwise matching manifest lists them.

Historical manifest v1 remains readable for retained verification. New installation, upgrade and
current full verification require the prospective policy. The referenced migration data fixture
under Java `src/test/resources` remains present because an existing production adapter consumes
it; this is not a provider/authentication seam.

The disposable test kit lives outside the production bundle. Its transport substitutions exercise
synthetic mechanics only. They are not original protected provider responses, independent review,
or production-eligible execution evidence.

Offline self-tests and synthetic demo/drill commands that import test modules run from the source
or separate test kit. They are not finite production socket operations and are not restored to the
production bundle to preserve those development commands.

### Disposable harness lifecycle

The synthetic preparation controller now has a bounded direct-child owner. Reaping clears its PID
before another fork can fail; a failed restart cannot cause cleanup to signal a reused PID. A
normal return from the child worker exits that child. Socket setup and client failures close the
owned listener and restore activation only after confirmed direct-child reap. Failed reap retains
the endpoint with activation stopped for reconciliation.

This helper owns the direct synthetic controller child. It does not establish that arbitrary
workload descendants have terminated.

## Launch and storage ownership matrix

| Executable or record | Existing owner reused | Remaining boundary |
| --- | --- | --- |
| Installed Python observer/service | Bootstrap and full helper/dependency verifier | Fixed observer service remains unchanged |
| Primary packaged `bin/cryptad`, wrapper/JVM | `cross_version_runtime.Supervisor` | Controller-owned per-role service launch is missing |
| Normal signed app children and bubblewrap | AppHost | Must inherit a confined daemon role; nested namespaces require testing |
| Catalog daemon | `federated_catalog_runtime.OwnedHost` | Separate launch call must use the same role controller |
| Packaged API exporter | Catalog and scheduler owners | Selected Java/classpath still execute under observer authority |
| Catalog scope-bootstrap and selected `bin/crypta-app` | Existing native/catalog authenticators | Bounded output alone does not establish launch confinement |
| Fixed Node budget driver | Installed reviewed driver | Keep only the selected app session and own-node endpoint; this is not a browser isolation test |
| Scheduler and app-budget daemons | Inherited supervisor | Must use the same confined launch/stop/observation path |
| Recovery clone and migration converter | Existing recovery/migration owners | Bind cohort/subject/epoch, or reject unsupported selections before admission |
| Expected process identity | Observer-private layout 2 | Physical UID separation remains missing |
| Journal, owner nonce, runtime state and canaries | Observer | Must remain outside role mounts and reachability |
| Catalog transport journal/intents | Catalog observer | Separate from candidate catalog state |
| Candidate config/data/cache/run/logs | Current node tree | Role-only writable projection; other direct readers still need bounded imports |
| Registration, original references, activation/revocation, baseline/resolver | Existing root authorities | Preserve exact owners and original approval semantics |

## Selected design direction and unresolved interfaces

The selected direction is a finite roster of static role UIDs and controller-owned systemd
services, with immutable admitted inputs and role-only writable roots. It is **not implemented by
this change**. No unit template or caller assertion substitutes for that adapter.

The root controller must derive each launch from registered original authorization and retain
run/cohort/role/subject/epoch, boot ID, invocation ID, fixed unit/cgroup, exact inputs, and the
original deadline. Observer requests must remain opaque registered handles with finite operations.
The outer runner protocol stays `{method, handle}`. Candidate control-plane ports also require a
tested network boundary; separate UIDs cannot deny sibling loopback access.

The current outer worker rejects an intent without a result. An idempotent inner launcher alone
will not reconcile a lost response. Supported owner-directed reconciliation must retain the
original intent/deadline, while safe administrative cancellation remains available after revocation.
Stopped collection currently checks the observer service; it must also prove every retained workload
invocation quiescent before terminal evidence, cleanup, conflicting launch or UID reuse.

The controller remains host-root TCB. Its existing capability set does not include
`CAP_SYS_PTRACE`, and relocating `/proc/<pid>/exe` reads into it does not restore cross-UID access.
That procfs link is subject to ptrace access checks.
[Linux proc_pid_exe(5)](https://man7.org/linux/man-pages/man5/proc_pid_exe.5.html)

A pidfd pins a task within one collector lifetime, not every descendant; its descriptor number is
not durable identity. Cgroup `populated` covers the subtree. A separate unit with
`KillMode=control-group` requires explicit teardown: the observer's unit cannot clean another
unit by inheritance. Cgroup memory and CPU accounting need new metric names and baseline
applicability; they must not be relabeled RSS or Java heap.
[pidfd_open(2)](https://man7.org/linux/man-pages/man2/pidfd_open.2.html),
[cgroup v2](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html),
[systemd 257 kill semantics](https://raw.githubusercontent.com/systemd/systemd/v257/man/systemd.kill.xml)

## Disposable reference preparation and acceptance

A dated Debian image is available from the official cloud-image archive:
[Debian 13 generic amd64, 20260914-2601](https://cloud.debian.org/images/cloud/trixie/20260914-2601/debian-13-generic-amd64-20260914-2601.qcow2).
Its [published SHA-512 manifest](https://cloud.debian.org/images/cloud/trixie/20260914-2601/SHA512SUMS)
contains:

```text
a733e7d49442a03e70d03e4eb5aaf3967f3efc69ef70952f9bb10fc1ee2c4876eb95956b5ad2d31350e5fada768feb651352535fb8cd1233f61998a5a7d2e93c
```

The local disposable guest uses unprivileged QEMU TCG, four virtual CPUs, 5632 MiB RAM, a fresh
24-GiB overlay, no host filesystem share, and localhost-only SSH forwarding. Its emulated PC
profile has SMM disabled after the initial firmware boot stalled. These details belong in the
environment identity; this is not the old PR-308 reference profile. Image HTTPS origin and pinned
digest were checked; no detached image signature is claimed.

Inside the booted guest, kernel `6.12.107+deb13-amd64`, systemd `257.13-1~deb13u1`, Python `3.13.5`,
and VM type `qemu` were observed. Guest dependency preparation and installed test execution must
be recorded separately. Booting this guest is not the mandatory positive workload path.

Guest preparation supplies OpenSSL, bubblewrap, util-linux, Git, GitHub CLI, sudo, D-Bus, Polkit,
the Java native library dependencies, and Temurin Java/Javac `25.0.4.1+1`. Polkit must be started
inside the prepared guest before the installer evaluates its actual policy engine. The package
installation alone left its D-Bus-activated service inactive. The installer still rejects an
inactive or substituted policy authority.

The observed package versions below describe this synthetic guest, not an administrator-approved
workload profile or a replacement for the installer's complete dependency-byte inventory.

| Dependency | Observed version |
| --- | --- |
| QEMU emulator, outside guest | `1:10.0.13+ds-0+deb13u1` |
| bubblewrap | `0.12.0-1~deb13u1` |
| D-Bus | `1.16.2-2` |
| GitHub CLI | `2.46.0-3` |
| Git | `1:2.47.3-0+deb13u1` |
| OpenSSL | `3.5.7-1~deb13u2` |
| Polkit | `126-2` |
| Python 3.13 package | `3.13.5-2+deb13u5` |
| sudo | `1.9.16p2-3+deb13u2` |
| systemd | `257.13-1~deb13u1` |
| util-linux | `2.41.5-0+deb13u1` |

The Temurin archive's SHA-256 was checked before and after transfer:
`dbb698396d478e7fa2b1e50f4103324b2a99b90569ee27c33f2261f9215cf41e`.
Native namespace and nested bubblewrap prerequisite commands executed successfully. Guest network
egress was then restricted to the emulator's explicit localhost SSH forwarding. This emulator
restriction is not a workload sibling/admin-plane policy.

The first installed attempt reached role provisioning but failed before publishing `current` or
the execution identity: Debian sudo `1.9.16p2-3+deb13u2` returned exit 0 with an explicit statement
that `cryptad-runner` has no sudo permissions. The previous verifier required exit 1. The corrected
verifier accepts exit 0 or 1 only with the exact denied-user stdout message and empty stderr;
granted commands, mixed diagnostics and other errors reject. This is a policy listing result,
not permission to execute a command.
[sudo 1.9.16p2 listing implementation](https://raw.githubusercontent.com/sudo-project/sudo/SUDO_1_9_16p2/plugins/sudoers/sudoers.c)

The same guest exposed a second policy-probe defect after Polkit started: runner-issued queries
with unit/verb details returned 127 because Polkit accepts those details only from a trusted
caller. That status is a failed query, not proof of denied unit authority. The verifier now creates
one fixed capability-free runner child, derives its PID/start-tick/UID subject from kernel state,
and issues the fixed queries as root **about that runner subject**. It checks the child's identity
before and after each query and accepts only denial/authentication-required statuses 1 and 2.
Readiness, each query, overall probing, and direct-child cleanup have finite bounds. It does not
execute a unit action or accept a caller-selected PID, executable or unit.
[Polkit caller and subject checks](https://cgit.freedesktop.org/polkit/tree/src/polkitbackend/polkitbackendinteractiveauthority.c)

The failed guest disk and its private log are retained separately from the clean preparation
snapshot. Corrections are tested from a fresh disposable domain, without editing an activated
bundle or erasing its authority history.

The second executed attempt used helper snapshot
`d9dcc878332ee321a388ad7faf1dd81b2f67e82e`, tree
`2829af378a705d2a21f6c5a24baa94de0ab3f8ca`, and passed the corrected sudo/Polkit and effective-unit
checks. It still stopped before execution-identity publication: the test's private-log wrapper
had applied `umask 077` to the entire installer, making its new public installation prefix mode
0700. The publication traversal guard rejected that state. The retry uses `umask 022` for the
installer while protecting a separately created log with mode 0600. The verifier was not relaxed,
and the failed installation was not repaired in place. This snapshot predates the last private
identity reader and catalog cleanup-timeout regressions.

### Installed snapshot 4 and confined diagnostics

The next fresh guest executed helper snapshot
`3c89802473b7d1efd5474e8b56bc6c7fa54121a4`, tree
`de63cd72d0a0a09d18a83fa195630190a1495887`, with the separately built product from
`7008f19c9f573b94c53d7b5381fc8f41ad07be87`. Its admitted helper bundle was
`0f678ccac58f78aff3e04daa7082c20b74cad30a5e77928b8056ca8d91177875`.
Installation published the execution record and physically separate test kit, then activated the
real socket. **The complete harness failed.** The production controller repeatedly exited before
accepting the queued unknown-handle request. A systemd `active` state was not bootstrap readiness.
The original request deadline was retained; no denial, baseline, native-consumer or workload
positive result is claimed from this attempt.

Separate diagnostic units in that disposable guest identified these failures without changing
the installed bundle or production units:

| Check | Observed result |
| --- | --- |
| Declared controller bounding set | `0x1eb`, as expected |
| Actual controller effective/permitted sets | `0x16b`: `CAP_SETUID` was missing |
| Sudo policy engine | `setresuid(-1, 1, -1)` failed; no denial verdict was returned |
| Explicit root plus ambient `CAP_SETUID` diagnostic | Effective/permitted/bounding `0x1eb`, ambient `0x80`, inheritable `0x180`, root UID/GID and `NoNewPrivs=1` |
| Sudo/Polkit after that diagnostic correction | Passed |
| Separately dropped native UID | All five capability sets zero |
| Native bubblewrap under all controller protections | Failed opening a fixed source with `openat2`/`ENOSYS` |
| Diagnostic removal of the SUID/SGID filter | Reached a second failure mounting proc with `EPERM` |
| Diagnostic removal of the inherited kernel/proc protections too | Fixed native `true` probe passed; this is not an admitted profile |

Systemd 257's explicit-UID/syscall-filter setup drops effective `CAP_SETUID` unless the ambient
set retains it. `NoNewPrivileges` then prevents execution from restoring the missing capability.
The prospective code correction retains that already-declared capability with explicit root
identity and checks the controller's own kernel capability/UID state at bootstrap. It does not
add a capability to the bounding set or to the observer. Native and runner children still clear
ambient, inheritable, permitted, effective and bounding capabilities before untrusted execution.
[systemd 257 execution setup](https://raw.githubusercontent.com/systemd/systemd/v257/src/core/exec-invoke.c)

The native incompatibilities remain unresolved. Systemd 257 deliberately returns `ENOSYS` for
`openat2` under `RestrictSUIDSGID`, because the indirect flags cannot be inspected by that filter.
The installed bubblewrap uses that syscall for safe opening. Inherited protected proc submounts
also prevent its new proc mount in the less-privileged namespace. Removing those protections in
diagnostic units established the conflict; it did not establish an acceptable production design.
The production protections, current bubblewrap and native rejection remain intact. Binding the
parent's proc tree or weakening the filter is not used as an acceptance workaround.
[systemd 257 SUID/SGID filter](https://raw.githubusercontent.com/systemd/systemd/v257/src/shared/seccomp-util.c)

The final capability correction follows snapshot 4 and has not completed a fresh installed
harness run. The failed disks and private diagnostics are retained and the owned guest is stopped.
There is still no working positive installed workload adapter, native-compatible replacement
launch profile, complete sibling/adversarial lane or original protected operation.

The existing explicit guest command remains:

```bash
umask 022
python3 tools/release-certification/restricted/disposable_integration.py \
  --disposable-vm --source /root/cryptad
```

If the test helper and packaged daemon were built from different revisions, the excluded harness
accepts `--product-source-commit <exact-40-character-commit>`. It retains helper and product source
identities separately and passes the product selection only to its synthetic fixture. The real
packaged-source authenticator still verifies the selected package bytes and embedded source marker.
The production bootstrap and client have no such option.

It is restricted to a fresh disposable guest, uses synthetic material, and reports its executed
dimensions separately from mandatory isolation acceptance. The current implementation has no
positive installed supervisor workload adapter and no runnable full sibling/candidate matrix.
An exit-78 probe, offline tests, local packaged lanes, or a native resolver test cannot satisfy it.

## Local verification

These counts describe separate commands and are not a sum of unique tests.

| Check | Result |
| --- | --- |
| Restricted Python discovery | 105 passed, no skips |
| Protected Python discovery | 305 discovered: 255 passed, 50 root/sudo-context prerequisite skips |
| Cross-version Python discovery | 184 passed, no skips on this Linux environment |
| `cross-version-soak --self-test` | 152 passed |
| `stable-maintenance --self-test` | 247 passed |
| `stable-platform-api-1x --self-test` | 88 passed |
| `phase-12-closeout --self-test` | 185 passed |
| Gradle `:platform-devtools:installDist assembleCryptadDist` | Passed; 342 tasks, 91 executed and 251 up-to-date |
| Packaged scheduler lane | 2 passed; numerical comparison separately reported `runtime-regression-exceeded`, not baseline acceptance |
| Packaged catalog lane | 1 passed |
| Packaged app-budget lane | 2 passed; incomplete PR-309 cases and `releaseEligible=false` retained |
| Changed-unit `systemd-analyze verify`, Python syntax and `git diff --check` | Passed |

Packaged lanes had no skips. They preceded the final private-reader, cleanup-error and controller
capability refinements; those refinements received focused regressions. An earlier scheduler run
overlapped changing build/helper identities and failed; the subsequent stable-source run passed.
The Gradle problems report contained 49 warning diagnostics, including compiler and deprecation
warnings. No Java sources changed, and no new full Java-suite or clean full-analyzer result is
claimed.

The integrated starting commit's restricted-prerequisite CI passed, but its Java CI failed in
`LocalProcessAppHostTest.restartPolicy_whenObservedHandoffChildExitsAfterGrace_expectUnknownExitRestarts`.
That job reported 316 AppHost tests, one failure and three skips. The later scheduled release
certification also failed its report-generation step. These are predecessor-source results;
the local successor changes have no published exact-head CI run.
[Restricted prerequisites](https://github.com/crypta-network/cryptad/actions/runs/34955519877),
[integrated Java CI](https://github.com/crypta-network/cryptad/actions/runs/34955520206),
[scheduled certification](https://github.com/crypta-network/cryptad/actions/runs/34958115615)

## Phase 12 disposition

The 49 mandatory requirement IDs, historical cutoff `2026-09-13T10:30:00Z`, retained reports and
47 unresolved acceptance assertions are unchanged. Storage and harness improvements do not close
the isolation assertion, original protected operation, external review, long-run, Mail, migration,
profile or publication dimensions.

A fresh no-operational-input assessment under `build/pr311-phase12-assessment` was evaluated and
verified at that same cutoff. It reports `assessmentIntegrity=verified-local-consistency`,
`phaseDecision=incomplete`, `phaseComplete=false`, publication/activation `not-performed`, and no
hosted CI evidence. The current inventory classifications are 33 implemented, 9 partial, 2 missing
and 5 unknown. Those classifications and 47 unresolved acceptance assertions measure different
things. This assessment does not insert these local tests as original operational evidence.

All twelve PR-309 consumer adapters remain incomplete: `import-concurrency`, `fetch-concurrency`,
`timeout`, `cancellation`, `retry`, `window-crossing`, `partial-rate-write`,
`graph-store-unavailable`, `graceful-restart`, `abrupt-restart`, `diagnostics-unavailable`, and
`privacy`. Kernel termination must not fabricate their native owner-terminal events or refund
durable rate usage. PR-312's composed-budget work follows completion of this isolation dependency.
