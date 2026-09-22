# Installed workload acceptance completion audit

This page records the PR-315 workload inventory, executable-path gaps, and the remaining
installed verification required for the finite four-role source-build profile.
**Implementation is incomplete; no installed workload case has a valid acceptance witness in
this revision's audit.** The first three installed attempts failed before role staging; the next
two failed network setup. The sixth and seventh prepared the fabric but timed out waiting for controller
readiness, before any role service was observed running.
Fixture preparation, offline tests, and a positive aggregate do not establish
complete installed workload acceptance.

The starting commit is `64a1708c17ebf02460d19ab66bfd7c8ed6b70700`, with tree
`452af57522c2d1bf98b0200c18dfa9d5da708c31`. Its commit subject identifies the integration of
GitHub #1416 (project PR-314), immediately after PR-313 integration
`45eb43d6654074df884f59415fa598c1cda93e36`. The implementation therefore starts from the
containing integration tree, not the originally inspected PR-314 feature head.
This source identity is an audit cutoff, not an assertion about final-source CI or execution.

The current [verifier](../tools/release-certification/restricted/pr314_acceptance.py) declares
`pr314-workload-roles-v8`, preserving the original 45 IDs and meanings. The selected profile
remains `debian13-systemd257-workload-v1`. Consult the
[PR-314 runbook](pr-314-controller-owned-workload-role-isolation.md) for the installed owners
and the [PR-313 runbook](pr-313-installed-native-acceptance.md) for copied-reference transport.

## Implemented preparation and positive orchestration

`pr315_workload_fixtures.py` prepares exact inputs from two real portable source builds and a
normally signed Mail ZIP. It checks embedded daemon source identities, different daemon bytes,
Linux x64 runtime compatibility, bounded archive expansion, packaged API export and ordinary
app signature verification. It stages the pinned flattened JDK and records the private input
inventory. It does not create original published-product provenance. Build the two source
revisions with `distTarCryptad`; stage Mail with `:apps:mail-prototype:stageApp`, then use the
ordinary `crypta-app keys`, `sign`, `verify` and `pack` commands on a private copy. Keep the
synthetic signing material private. Fixture preparation requires a clean exact helper checkout.
Private fixture schema 2 additionally binds and recomputes a canonical daemon class digest,
excluding the generated `Version.class` and archive metadata. Marker-only predecessor differences
are rejected. This proves a conservative class-byte distinction, not semantic equivalence or
original publication; resource-only changes are insufficient. Earlier fixture schemas require
fresh preparation.

The separate installed guest entry materializes the fixed selection only after production/test-kit
installation and binds the actual installed `runner_identity()`. `pr315_workload_runner.py`
uses the existing PR-312 copied reference transport, private SSH pin and boot closure. It has
one predeclared 45-case plan, but currently invokes only the positive aggregate driver. No
individual case or complete acceptance is granted from that aggregate. Missing hostile and
lifecycle emitters remain visible; there is no report-import or force-complete option.

The runner requires all reference/fixture inputs below its private task storage root, an explicit
total disk budget and free-space reserve, and a separate memory budget/reserve. It counts retained
attempts, serializes suites with a task-root lease and retains every attempted guest. `--probe`
records prerequisites without allocating a VM and returns 78, including when inputs are present.
The workload mode is an internal reuse of the reference runner; invoke the workload-specific
entrypoint to enforce both budgets. Example options are:

```text
--storage-root /absolute/private-task-root
--output /absolute/private-task-root/new-suite
--storage-budget-bytes 42949672960 --min-free-bytes 8589934592
--memory-budget-bytes 7516192768 --min-host-memory-bytes 1073741824
--profile tcg-multi --timeout 4200
```

Supply the source, prepared image/digest, copied QEMU root, seed, private SSH key/host pin,
prepared fixtures/digest and candidate product commit through the fixed named arguments shown
by `--help`. The recreated reference preparation selects `qemu64`, `tcg-multi`, four vCPUs and
5632 MiB explicitly. This differs from the historical PR-313 `tcg-single` positive observation;
results cannot be pooled. Preparation now installs pinned `nftables=1.1.3-1` and
`iproute2=6.15.0-1`, which the installed execution closure already requires but the old reference
producer omitted. The prepared image and effective closure must be measured anew.

The recreated standalone reference completed preparation and stopped successfully. Its private
records retain the prepared image, copied boot closure, seed, SSH credentials/host pin, and guest
identities. Observed versions include kernel 6.12.107, systemd 257.13, bubblewrap 0.12,
nftables 1.1.3, iproute2 6.15 and Temurin 25.0.4.1. These are preparation observations, not
workload acceptance. Only obsolete successful preparation copies were removed after exact
stopped ownership and standalone backing checks; failed attempts remain retained.

The first installed attempt failed immutable bundle verification after privileged Python imports
created bytecode files. Fixed installed entrypoints now suppress bytecode writes; a regression
reproduces the inventory mismatch and verifies byte-exact imports. The second attempt passed
base installation/test-kit provisioning but failed workload account creation: the recipient's
original account name exceeded systemd v257's strict 31-byte limit. The fixed account prefix is
now `cryptad-wl-` in the sysusers file, role unit and lookups. Role IDs and network namespace
names remain unchanged. Offline regression checks validate every account against the limit and
its unit/lookup binding; an installed rerun is still required. Both attempts stopped their guests
and retain private diagnostics. Neither reached a role campaign or yielded workload witnesses.
Their initial predecessor had only a generated-version class difference, so neither attempt can
establish distinct-product acceptance even independently of its setup failure.

The third attempt used a substantive historical source build with 24 differing implementation
classes beyond `Version.class`, passed fixture admission and created all four role accounts.
It failed before campaign creation because the shared sudo-denial parser recognized only
`cryptad-runner`, even when the workload installer queried another account. The parser now
matches the exact validated account supplied by the caller; default base-runner semantics are
preserved. Regression tests reject another account's denial, malformed names, grants and
ambiguous policy output. This fix awaits installed execution. The third guest is stopped and
retained, with eight positive cases setup-failed and all 37 fault cases unexecuted.

A subsequent capacity-only invocation returned 78 without allocating a guest. Retained task
data occupied 17,280,811,008 bytes and the next copied attempt required 29,208,264,845 bytes,
exceeding the selected 40 GiB task cap. The 8 GiB free-space reserve, 7 GiB host VM budget,
1 GiB host memory reserve, and all guest limits remain unchanged. New allocation requires a
prospective capacity decision; failed evidence is not disposable space. No attempt reached
role cgroups, JVMs or AppHost, so actual four-role demand and volatile role snapshots remain
unobserved. The stored QCOW2 files do not establish preservation of nonexistent or later
lost tmpfs state.

The user subsequently authorized removal of failed guests where safe while retaining the
40 GiB cap. After confirming stopped state, no live disk descriptors, and no retained backing
dependencies, the six per-attempt guest/base disk files were removed. The private disposal
records preserve their exact hashes, allocated sizes, backing metadata and the authorization.
This reclaimed 7,869,190,144 allocated bytes. All original failure reports, private logs,
source/tool snapshots, fixtures and the reusable standalone reference remain retained; no
failure verdict was changed. Full failed guest filesystems are no longer available for forensic
inspection. This explicit retention change resolves the capacity block without increasing
the task cap or changing guest limits; each future allocation still requires a fresh check.

The fourth attempt at helper `b80adc1ef353ca171b2c6f773cf086289e72038e` passed account setup
and staged all four roles within its original campaign deadline. It failed during the fixed
network fabric setup; no controller or role service started. Cleanup was reported completed,
and the guest stopped. The helper had discarded the underlying network command error, so this
attempt does not establish the failing command's cause. The network helper now reuses the
existing bounded-process capture with the same 15-second limit and capped private diagnostics;
its public error and network policy are unchanged. The evidence path now also captures fixed
controller/network projections after a pre-sentinel preparation failure. The fourth attempt's
uncaptured controller records and volatile state remain unavailable; no retrospective snapshot
is fabricated. Under the user's renewed instruction to remove failed VM disks after retaining
diagnostics, its two stopped, dependency-checked disks were removed, reclaiming 4,161,605,632
allocated bytes. Its failure, source/tool snapshots, logs and unit-state diagnostics remain.

The fifth attempt at helper `237cbf86d21d897d9976219c0335d55ec94114cf` reproduced the fabric
failure and retained the exact command: the kernel rejected the first peer route because its
output device was not yet up. Network setup now activates the already-filtered role links
before installing their peer routes; the switch bridge remains down until all roles are ready.
DROP policies and the fixed peer matrix are unchanged. Offline command-order regression checks
cover filter-before-link and link-before-route ordering; installed confirmation follows in a
fresh guest. The fifth attempt captured bounded controller projections after cleanup, explicitly
marked its sentinel not prepared, stopped its guest, and retained the failed result. Private
error capture also now preserves bounded setup/cleanup propagation diagnostics separately and
enforces its serialized byte cap for non-BMP text.

The sixth attempt at helper `1e255e56a78faacfe3594659919818c7e8eeb360` passed the corrected
network setup, created its synthetic sentinel and started the controller. The observer's fixed
30-second readiness window expired. Six sampled observations found the controller alive, with
about 21 MiB peak observed memory and zero observed cgroup OOM events; no role service was
observed running. These samples do not establish the controller's startup phase or full guest
memory demand. Cleanup completed, the sentinel matched, bounded controller projections were
captured, and the guest stopped. A fixed private runtime checkpoint now distinguishes entry,
installation verification, reconciliation and socket listening; the administrator snapshots it
before service stop removes the runtime directory. This is diagnostic state, not retained
authority, readiness proof or acceptance. No timeout or resource cap was increased.

The fifth and sixth stopped guests' disk pairs were subsequently removed under the user's
continuing authorization, after descriptor and backing-dependency checks. Their diagnostics,
failure verdicts and source/tool snapshots remain retained. Each new attempt still requires
the same task-wide 40 GiB budget and 8 GiB reserve check.

The seventh attempt at helper `7b20b3f7800f131503823a6888bf5e67d206f93c` again expired the
ordinary 30-second readiness poll. Its captured checkpoint was still at entry: installation
verification had not completed before the observer deadline. This establishes the last reached
phase, not eventual readiness or the correct replacement budget. Cleanup completed and the
guest stopped. Its stopped disks were removed after the same ownership/dependency checks.
Six older expanded source copies were also removed after byte/mode comparisons against their
digest-verified retained archives, reclaiming 4,252,184,576 allocated bytes. The original source
archives, exact exported bundles, logs, fixtures and reference inputs remain; no failed verdict
was changed.

`--startup-measurement` now selects a fixed administrator diagnostic in a fresh copied guest.
It prepares the same campaign/fabric and starts the actual controller, but stops before any
role start. Its prospective 120-second observation ceiling is clamped to the original retained
campaign deadline. At this diagnostic revision the ordinary positive driver's poll remained
30 seconds. A served
root-peer response is required; checkpoint or socket existence alone never establishes readiness.
The private checkpoint's prospective version 2 retains only the four fixed stage timestamps
within one startup epoch. Private samples additionally capture actual cgroup CPU quota and
usage/throttling counters. A diagnostic result cannot set installed positive execution, and all
45 workload case statuses remain unexecuted. A later operational polling change requires review
of the measured result under a new exact test-kit identity; this is not a campaign-clock reset.

The eighth attempt, a startup-only diagnostic at helper
`c474663f9ba0c9514649fb23f65875d8a46753d7`, completed installation verification,
reconciliation and an actual root-peer readiness exchange inside its diagnostic ceiling, after
the old 30-second poll would have expired. Exact stage times, CPU quota/throttling counters and
memory observations remain private. No workload role was launched. Cleanup completed and the
guest stopped; all 45 workload cases remain unexecuted for this diagnostic. This is not a full
performance baseline or a diagnosis of the historical JVM fatal signals.

Based on that measurement, the next positive test-kit revision prospectively uses a fixed
90-second readiness poll, capped by the original campaign deadline. The retained one-hour
campaign limit, QEMU selection and all production controller/role resource limits remain
unchanged. This is a narrow administrator observation-budget change, not a retry or extension
of an existing campaign. It requires fresh exact fixtures and a fresh installed positive run;
the successful startup diagnostic cannot be borrowed as workload acceptance.

The ninth attempt at helper `25e3f34aa8b50dba01f4d5827bc37e65db644b18` observed
controller readiness and started the first role service, then failed the unchanged 180-second
daemon readiness window. The remaining three roles were not launched. Observed role memory
stayed below its limit with no recorded OOM events; an active service does not prove a ready
packaged daemon or AppHost child. Cleanup completed, the selected sentinel matched, and the
guest stopped. Startup output was unavailable, so the cause remains undiagnosed.

The next revision enables the packaged wrapper's existing bounded log rotation at a fixed
role-local path (2 MiB per file, three rotated files). After verified cleanup, the administrator
kit uses the existing safe descriptor reader to retain at most the final 4096 bytes of each
fixed current log, under the shared 15-second snapshot deadline and 64-KiB evidence limit.
These private candidate-origin diagnostics are not acceptance witnesses. Unsafe, missing or
unavailable logs remain explicitly unavailable. No daemon readiness or role resource limit
was increased for this retry.

The tenth attempt at helper `30ecc2a009a4fe5e0e082cf5a45c3dddb2916172` again passed
controller readiness, but the first role service exited before daemon readiness. Its safely
captured wrapper log reports an abnormal Java bootstrap-child exit followed by the wrapper's
incorrect-bootstrap-output message. The message does not prove a corrupt JAR or identify a
signal: the pinned wrapper and its JAR both identify version 3.6.2. No other role was started.
Cleanup completed, the sentinel matched, and the guest stopped; the failed disks and verified
expanded duplicates were then removed under the user's authorization, preserving archives and
private diagnostics. No workload case passed.

The next diagnostic revision logs the fixed Java command and query at INFO level into the same
bounded private wrapper log. It also looks only for bounded JVM fatal-error headers in each
role's fixed temporary directory after cleanup. Missing files are unavailable evidence, not
proof that no JVM failure occurred. This does not establish where the previous fatal output
went or explain historical SIGILL/SIGSEGV observations. CPU, JDK, memory and campaign limits
remain unchanged; the previously demonstrated FCP deadline fix is included prospectively.

Two narrow network-helper fixes address separately demonstrated offline child-process failures.
Namespace emptiness checks now reuse the existing bounded helper rather than an exception path
and context manager with unbounded waits. Descriptor receipt and child reap share the existing
12-second connector deadline, followed by a bounded two-second termination reap on failure;
the child alarm and TCP connection limits are unchanged. Uncertain reap closes local descriptors
and fails without declaring quiescence. Real unprivileged child/descriptor tests cover EOF and
post-transfer stalls; mocked namespace entry and cleanup-timeout cases remain offline tests,
not installed hostile/lifecycle witnesses.

The positive driver now bounds socket EOF through actual child exit, covers partial preparation
and controller-start failure with cleanup, observes a root controller peer serving its existing
closed protocol, and writes its terminal positive report only after cleanup. Its parent wait
uses the original controller deadline plus the existing teardown grace, not a newly started
campaign budget. Real local fork tests cover closed-output/hanging and flooded-output children;
these are driver regressions, not installed lifecycle cases.

A real socketpair regression demonstrated that the general FCP GetNode read could outlast
the adapter's declared readiness window. The adapter now applies the existing absolute deadline
to every complete readiness attempt and clamps retry sleep to the original remaining budget.
The terminal timeout keeps its existing code and chains the last failure for private diagnosis.
The production 180-second readiness ceiling and original campaign deadline are unchanged.
This offline reproduction does not identify the cause of the ninth installed attempt.

Private memory diagnostics include before/after and sampled live cgroup demand. Missing cgroups
are unavailable, never zero or quiescence proof. The separate fixed evidence reader captures
bounded projected controller records and a 32-byte synthetic state sentinel after caller-verified
cleanup, before shutdown. The sentinel starts before role launch and is compared after cleanup;
this does not yet provide the independently captured immediate before/after restart epochs
required by `restart-durable-state`. The snapshot is diagnostic-only and cannot restore a runtime.

## Requirement-to-emitter mapping

In the following tables, “positive path” identifies existing production actions reached by
`pr314_workload_driver.py` and `InstalledWorkloadAdapter.run_positive()`. It does not mean that
the action emits a complete trusted acceptance observation. “Missing” means there is no installed
workload case driver at this audit cutoff. Synthetic verifier tests are not emitters.

| Positive ID | Existing path | Missing installed acceptance evidence |
| --- | --- | --- |
| `installed-ready` | Installation/test-kit checks in positive driver | Observed ready controller and exact installed before/after identity |
| `four-role-start` | Adapter starts four fixed role services | Trusted UID/GID, invocation, cgroup and namespace roster |
| `signed-apphost-child` | Signed Mail install/start and worker observation | Exact bundle and independently captured kernel child binding |
| `own-management` | Controller-bound FCP/HTTP descriptors | Per-operation request/control response and server invocation |
| `fnp-content-retrieval` | Relay topology and byte-checked content operation | Cross-node causal evidence excluding recipient preload/cache-only success |
| `dynamic-app-bootstrap` | Controller-verified Mail bootstrap | Current child/session/operation evidence captured independently |
| `kernel-resource-scope` | Controller kernel observation support | All four actual scoped cgroup measurements |
| `restart-durable-state` | Sender restart and app-inventory retention | Selected durable sentinel before/after, original deadline, both invocation epochs |

All denial rows below have **missing installed emitters**. The actor column preserves the
contract; it must not be replaced with a root probe or a same-UID process outside the asserted
role/AppHost boundary.

| Denial ID | Actor | Fixed target and required executable probe |
| --- | --- | --- |
| `observer-private-read` | candidate | Existing observer canary; role process attempts read after authorized control |
| `observer-private-write` | candidate | Existing observer canary; role process attempts write; control confirms unchanged bytes |
| `resolver-authority` | candidate | Active installed resolver; valid fixed authority request from role process |
| `provider-authority` | app | Active synthetic provider fixture; normal signed AppHost child attempts authority access |
| `sibling-data` | candidate | Existing recipient sentinel; sender process attempts access |
| `sibling-fcp` | candidate | Active recipient FCP; emitted cross-role probe with attributed filter evidence |
| `sibling-http` | candidate | Active recipient HTTP; emitted cross-role probe with attributed filter evidence |
| `sibling-app` | app | Active recipient AppHost endpoint; sender AppHost probe |
| `host-network` | candidate | Active synthetic host canary; emitted probe and attributed filter evidence |
| `runner-control` | runner | Installed system manager; valid disallowed control request |
| `observer-control` | observer | Installed system manager; valid disallowed control request |
| `arbitrary-endpoint` | observer | Existing nonapproved endpoint; valid disallowed connector selection |
| `hostile-app-origin` | candidate | Active own app; valid request with hostile origin |
| `package-expectation` | candidate | Admitted immutable package/identity; actual fixed mutation attempt |
| `forged-runtime-identity` | candidate | Process observer; fixed false claim compared with independent kernel identity |
| `namespace-mount-escape` | app | Outer role boundary; bounded nested namespace/mount escape attempt |
| `cgroup-migration` | candidate | Existing fixed cgroup target; actual migration attempt and unchanged ownership |
| `resource-exhaustion` | app | Role resource cap; finite allocation/task probe and actual cgroup events |
| `output-symlink` | candidate | Descriptor-based collector; role-created symlink |
| `output-fifo` | candidate | Descriptor-based collector; role-created FIFO and bounded rejection |
| `output-hardlink` | candidate | Descriptor-based collector; actual multiply linked file |
| `output-replacement` | candidate | Descriptor-based collector; coordinated replacement during pinned read |
| `output-flood` | candidate | Descriptor-based collector; finite cap-exceeding growth/output |
| `stale-handle` | observer | Controller; retired handle against successor authority |
| `stale-pid-uid` | observer | Process observer; retired invocation versus actual new process |
| `forged-counters` | candidate | Kernel metrics; false candidate values versus actual cgroup measurements |

All lifecycle rows below also have **missing installed emitters**. Triggers must follow observed
service/controller transitions; arbitrary sleeps and mocked manager callbacks do not establish
installed behavior.

| Lifecycle ID | Fixed installed trigger and terminal evidence |
| --- | --- |
| `lost-start-response` | Close the response transport after observed start intent; retry and prove one original manager invocation |
| `observer-death` | Kill exact owned observer after activity; observe real controller inactivity policy and exact role termination |
| `controller-restart` | Restart exact controller invocation; observe actual `BindsTo` stop and retained reconciliation |
| `late-child` | Synchronize one fixed late child with role stop; prove descendant ownership and terminal absence |
| `setsid-double-fork` | Fixed finite double-fork/session probe; prove continued role cgroup membership and cleanup |
| `deadline` | Reach original campaign deadline with roles running; observe actual owner stop without clock rewrite |
| `revocation-running` | Create fixed revocation marker after running observation; deny new work and retain owned termination |
| `cancellation` | Send existing stop operation for exact current handle; observe owned terminal state |
| `partial-launch` | Fail one owned role at a measured launch transition; reconcile all already started roles |
| `stuck-output` | Fixed owned process retains output channel; enforce collection deadline and descendant cleanup |
| `cleanup-race` | Synchronize stop with owned invocation/cgroup change; retain uncertainty and preserve siblings |

## Finite driver strategy

Reuse one administrator test kit and the copied PR-313 guest runner. Keep fixture building and
signature verification before campaign preparation. The private selection remains
`/root/pr314-workload-selection.json`; production requests must keep their closed fixed methods
and role handles. No arbitrary executable, shell, namespace, PID or systemd-property selection
belongs on the production socket.

Run the ordinary Mail positive profile separately from a prospective signed synthetic app cohort.
The latter needs a clearly named, exact-byte-bound app with fixed probe operations launched through
normal AppHost installation and sandboxing. Current preparation, adapter and bootstrap paths admit
Mail only; therefore the four app-origin denial rows cannot honestly run yet. Do not modify Mail
after signing or label a candidate-UID helper as an AppHost attack.

Use fixed bounded probe operations for file access, immutable-input mutation, namespace escape,
cgroup migration and output hazards. Capture the actual process epoch, UID, namespaces and
current role invocation before and after each operation. For app actors, also capture normal
AppHost parent/child and exact admitted bundle relationships. Administrator orchestration controls
only the declared disposable resources and cannot substitute for the asserted attack actor.

For network probes, keep DROP semantics. Add only fixed scenario-attributed counters or an
equivalent bounded kernel observer in the task-owned namespaces. Record the actual emitted probe,
exact ruleset/namespace identity, counter delta and causal interval, with an authorized active
target control before and after. Current rules have no such counters. A recipient loopback
listener does not prove that the recipient namespace address is the same valid endpoint; bind
the target and denied path explicitly. Timeout, missing listener and setup failure remain
inconclusive or failed, never fabricated `EACCES`/`EPERM`.

Use fresh guests for destructive lifecycle/revocation groups unless a separate reset contract is
verified. The real controller observer-loss policy is 240 seconds since the last successful
request. Allocate that time before preparation; never extend the original campaign deadline.
Lost-response and descendant tests need fixed synchronization barriers at observed transitions.
Late children and setsid processes must remain owned by the original service cgroup until stop.

The existing cleanup path treats a missing cgroup as quiescent, and its inactive/failed early
branch does not independently establish unchanged retained invocation identity. The cleanup-race
driver must test those transitions before claiming that missing/replaced cgroups prove safe
completion. This is a code-audit concern, not an observed installed failure or a completed fix.

## Records, budgets and private evidence

Version any new witness semantics prospectively while preserving v8 historical meaning. The
current attempt has one role roster, so it cannot faithfully bind both pre-restart operations and
post-restart observations to different epochs. Its denial actor proof is UID-only. It also
requires complete target/principal maps even for setup failures that never observed those
subjects. A small successor must represent these failures honestly and bind each passed case to
its actual process and invocation epoch; it must not invent missing target identities.

Predeclare the complete 45-case group plan and retain every failed, setup-failed, inconclusive or
unexecuted row. Compute operational acceptance only through pinned host transport and measured
test-kit execution. Guest JSON, caller-authored commitments, an imported old report and synthetic
unit records cannot authenticate an installed run. Final attempt completion follows exact role
quiescence, bounded private diagnostic extraction and independently observed guest stop.

Before every allocation, inventory actual allocated blocks, retained task attempts and backing
dependencies. Require stopped exact ownership before deleting disposable resources. Declare one
task-wide disk budget plus minimum free-space reserve, including reference/private copies,
staging, growth, snapshots and failed-attempt retention. Stop allocation when that total cannot
fit; leave remaining cases unexecuted/setup-blocked.

The guest remains 5632 MiB with the explicitly selected CPU/accelerator and pinned boot closure.
Each of four roles has a 1-GiB memory limit, zero swap and 512-task cap. Each role's 512-MiB,
32768-inode tmpfs consumes real memory; it is not additional guaranteed headroom. Measure
controller/JVM/AppHost demand and sibling/observer progress. Distinguish expected role-limit
denial from guest-wide OOM or loss of observation. The current attempts measured host admission
headroom but stopped during setup; they establish no running four-role memory observation.

After exact role quiescence, extract only fixed bounded sentinels and necessary controller records
with existing safe descriptor readers. Reject symlinks, FIFOs, sockets, hardlinks, races and
unbounded growth. Retained QCOW2 does not preserve tmpfs after shutdown. A private diagnostic
snapshot is not a runtime restore format or continuation of the same epoch. Guest crashes may
make volatile evidence unavailable; record that limitation without manufacturing a snapshot.

Public output includes only approved classifications, counts, case IDs and tool/product
identifiers. Actual actor IDs, endpoints, raw output, selections, credentials and correlatable
private hashes stay in private evidence. Administrator-only modules must remain excluded by
`installation.TEST_SEAMS` and production bundle manifests.

## Verification and remaining gates

Run the focused offline workload suites against final source:

```bash
python3 -m unittest discover -s tools/release-certification/protected -p 'test_restricted_workload*.py'
python3 -m unittest discover -s tools/interop -p 'test_cross_version_workload.py'
python3 -m unittest discover -s tools/release-certification/restricted -p 'test_pr314*.py'
```

Add fixture/runner/record/fault regressions as their implementations become executable. Run
root-only checks only in the dedicated disposable environment and report other root skips.
The actual installed suite is a separate invocation with declared storage/memory budgets;
prerequisite exit 78 means unexecuted installed testing.

Local regressions after the sudo/fixture corrections: protected discovery ran 466 tests with
74 skips; restricted discovery ran 350 with one QEMU-tool-availability skip; the workload adapter
ran 24 with eight root-only skips. The protected workload subset ran 101 with 21 skips.
The four certification self-tests ran 152, 247, 88 and 185 tests respectively, all passing after
the corrections at helper `90a9d63f7d28b78b3d2a1f369e140f469bef0378`. The Gradle wrapper completed
`:platform-devtools:installDist assembleCryptadDist`, candidate Mail staging/portable assembly,
and historical predecessor portable assembly. Existing compiler/ErrorProne warnings and Gradle
deprecation findings remain; task success does not establish analyzer cleanliness. No Java
behavior was edited, no full Java test suite was run, and no final-source hosted CI was dispatched.
These offline results and three retained setup failures grant no installed acceptance.

| Assessment dimension | Audit verdict |
| --- | --- |
| `implementationCoverage` | Incomplete: 37 installed hostile/lifecycle emitters and complete trusted positive records remain missing |
| `installedPositiveExecuted` | False for this revision; no observed installed positive attempt |
| `installedWorkloadAcceptanceSatisfied` | False; latest executed attempt has eight inconclusive positives and 37 unexecuted faults |
| `finiteNativeAcceptance` | Separate incomplete 65-case PR-313 contract; retain its historical 17-case positive observation |
| `protectedExecutionEnabled` | False; original authority and approved deployment gates are not supplied |
| `phaseComplete` | False; preserve all 49 Phase 12 assertions and historical 47 unresolved assessment |

The [Phase 12 register](phase-12-open-items.md) and
[workload boundary gap](pr310-workload-boundary-gap.md) remain authoritative for broader debt.
The 12 PR-309 composed-budget consumer gaps remain separate. Catalog, scheduler, recovery clone,
migration, historical-original-product and protected-origin adapters remain unsupported.
`InstalledAppHandle.mail_client()` still refuses higher-level Mail traffic; app startup/bootstrap
is not ciphertext delivery. Namespace-bound Mail is a subsequent workstream, not Phase 12
completion or authorization for Phase 13.
