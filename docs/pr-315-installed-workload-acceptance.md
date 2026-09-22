# Installed workload acceptance completion audit

This page records the PR-315 workload inventory, executable-path gaps, and the remaining
installed verification required for the finite four-role source-build profile.
**Implementation is incomplete; no installed workload case has a valid acceptance witness in
this revision's audit.** The first three installed attempts failed before role staging; the next
two failed network setup. The sixth and seventh prepared the fabric but timed out waiting for
controller readiness. The eighth observed readiness in a startup-only diagnostic. The ninth
through thirteenth reached first-role startup but failed daemon readiness; no four-role positive
run has completed. The fourteenth reached both candidate daemons, then failed predecessor readiness.
The fifteenth reached all four daemons, then exposed an incorrect peer-wait helper call.
The sixteenth failed first-role wrapper bootstrap with a JVM illegal-instruction crash.
The seventeenth passed four-daemon readiness and two-sided peer connection waits, then failed
host bootstrap before app installation.
The eighteenth again reached all four daemons, then hit a bounded operation deadline; the
retained failure does not identify the expired operation, and no content retrieval completed.
The nineteenth reached recipient CHK retrieval after peer, signed AppHost and bootstrap checks,
then timed out waiting for the FCP fetch response. The full positive sequence remains incomplete.
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
New preparation additionally requires the explicit `workload-launcher-policy-v2` runtime
revision described below. This is a prospective change within that profile family, not an
unchanged v1 configuration. Earlier policy observations and performance results cannot be pooled
with it; historical v8 record interpretation remains unchanged.

## Implemented preparation and positive orchestration

`pr315_workload_fixtures.py` prepares exact inputs from two real portable source builds and a
normally signed Mail ZIP. It checks embedded daemon source identities, different daemon bytes,
Linux x64 runtime compatibility, bounded archive expansion, packaged API export and ordinary
app signature verification. It stages the pinned flattened JDK and records the private input
inventory. It does not create original published-product provenance. Build the two source
revisions with `distTarCryptad`; stage Mail with `:apps:mail-prototype:stageApp`, then use the
ordinary `crypta-app keys`, `sign`, `verify` and `pack` commands on a private copy. Keep the
synthetic signing material private. Fixture preparation requires a clean exact helper checkout.
Private fixture schema 3 additionally binds the closed runtime policy and recomputes a canonical daemon class digest,
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
workload acceptance. Initial cleanup removed obsolete successful preparation copies. The user
subsequently authorized removing stopped failed guests to keep the 40-GiB budget. Their original
archives, failure records and captured diagnostics remain retained; their disposable disks and
verified duplicate expansions are removed only after ownership and dependency checks.

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

The eleventh attempt at helper `12d4eddc6344510a8dfa2acd1d620c88cec17576` retained a
first-role wrapper log showing repeated JVM launch attempts and a wrapper CPU-starvation
message before readiness expired. Its inspected temporary directory contained no matching JVM
fatal-error file; that does not rule out a crash elsewhere. The final log tail was dominated
by command lines, leaving earlier launch-failure messages unavailable after shutdown. No other
role started and no workload case passed. The guest stopped; failed disks and verified duplicate
expansions were removed after retaining the original archives and private diagnostics.

The next revision removes the temporary command/query logging overrides. In addition to the
existing tail, it retains at most 8192 bytes of selected wrapper warning/error and JVM-channel
lines from the same bounded safe read. These untrusted text labels are diagnostic selection,
not authenticated severity or acceptance. Immediate Python exception causes now survive the
bounded private observer response; the public result remains unchanged. No deadline, CPU,
JDK or memory limit was increased.

The twelfth attempt at helper `18bdbd327d` retained two concrete startup observations:
early Logback initialization tried to create files under read-only `/package/logs`, and the
wrapper subsequently timed out waiting for its JVM startup signal and requested termination.
The log reached `WrapperManager: Initializing...` shortly before that timeout. These messages
explain that observed wrapper termination, not the earlier abnormal bootstrap exit or historical
SIGILL/SIGSEGV. No matching fatal-error file was found in the fixed inspected directory. The
observer reached its original readiness deadline; no positive case completed, and the guest stopped.

The next launcher supplies the existing `crypta.log.dir` property at JVM creation, pointing only
to `/node/logs`, so early logging need not write into immutable package inputs. The fixture
producer and installed preparation both require the finite package's existing nine contiguous
additional JVM options; duplicates, gaps, includes and a conflicting tenth option are rejected.
The fixed tenth option therefore cannot overwrite a selected product option. Package bytes,
JDK, CPU, wrapper watchdog, role memory and campaign deadlines remain unchanged. This fix
addresses the demonstrated directory mismatch; startup timing still requires an installed rerun.

The thirteenth attempt at helper `e57825155f` no longer emitted the read-only logging-directory
errors, but the wrapper still terminated JVMs that had not sent their startup signal in time.
Its private log orders priority adjustment and crypto-provider initialization before
`WrapperManager: Initializing...`. A separate abnormal dry-run exit remains undiagnosed.
The first role never became ready, the remaining roles were not launched, teardown was reported
completed, and the guest stopped. Its failed disks and archive-verified duplicate expanded inputs
were removed under the continuing authorization; bounded diagnostics and original archives remain.

The Java entrypoint now explicitly initializes the wrapper backend before priority adjustment
and constructor-driven provider initialization. A regression failed on the original ordering
and passed with the change; standalone argument forwarding and the existing listener remain
unchanged. Backend threads can now be created before the main thread lowers its priority, so
their scheduling need not inherit that later adjustment. Existing role cgroup limits still
apply. The static logger still initializes before `main`, and this ordering fix alone does not
prove a successful native handshake. The wrapper watchdog and all campaign/guest caps are
unchanged. A rebuilt candidate, exact fresh fixture and installed retry are required.

The fourteenth attempt used helper and rebuilt candidate `cfe6b4ab14`, with the unchanged
substantive historical predecessor. Both candidate roles passed FCP daemon readiness. Their
private logs place wrapper initialization before priority/provider setup and record completed
node initialization. The predecessor still initialized the wrapper late and incurred three
initial-signal timeouts; its original 180-second readiness window expired. The relay was never
launched, and AppHost/FNP/restart stages were not reached. No complete positive case witness
resulted. Across 95 periodic samples, observed controller memory peaked near 26 MiB and the
three launched role services near 212, 214 and 128 MiB respectively, with no observed cgroup
OOM events. These are sampled peaks, not continuous maxima or four-role resource acceptance.
Teardown was reported completed, the synthetic sentinel matched, and the guest stopped.
Its stopped disks and archive-verified expanded source were removed after ownership checks;
bounded diagnostics and original archives remain. Further exact-match cleanup removed unused
copied boot tools while preserving their recorded pins and complete reusable reference closure.

The pinned native wrapper's absent-property default for `wrapper.startup.timeout` is 30 seconds.
Local binary inspection and the predecessor's repeated late handshake support a narrow
prospective compatibility allowance. `workload-launcher-policy-v2` explicitly sets 60 seconds
only for `previous` and 30 seconds for the other fixed roles. This does not modify the historical
portable/JAR bytes or introduce a startup shim. The full fixed policy is included in every
`configuration_identity`, schema-3 fixture, private host plan and installed terminal result;
the host rejects old or mismatched policy results. Selection cannot supply arbitrary wrapper
properties. The profile family name and 45 requirement IDs remain, but this runtime-policy
revision is explicit and earlier configuration identities cannot be reused.

This compatibility setting was reviewed as a prospective development change before a fresh
attempt, not as an independent security review or a demonstrated success. It leaves the FCP
180-second ceiling, original campaign deadline, selected CPU/JDK and all resource/storage caps
unchanged. It does change the historical role's initial wrapper watchdog, so this is not an
unchanged-profile retry. Fresh exact fixture preparation and installed execution are required;
no campaign is resumed or extended. The earlier abnormal dry-run exits and fatal signals remain
undiagnosed.

The fifteenth attempt used the prospective launcher policy and reached FCP readiness for all
four packaged daemons. It then failed with a `TypeError` because the installed adapter called
the existing two-client peer waiter with the wrong argument list. The corrected caller supplies
both clients and their exact node identities; the shared runtime connect, restart and rejoin
callers received the same correction. Regression tests exercise the real peer waiter over
synthetic FCP endpoints, including rejection of a one-sided connection. The original 150-second
peer wait and 180-second outer bound remain. This attempt did not verify connected FNP peers,
AppHost startup, remote content or restart persistence. Its stopped disposable disks were
removed after retaining private diagnostics and checking ownership and backing dependencies.

The sixteenth attempt used the corrected peer caller with unchanged daemon products, JDK,
CPU/accelerator and explicit launcher policy. Its first role failed wrapper bootstrap before
FCP readiness. A bounded private JVM fatal header recorded `SIGILL` in compiled Java code;
this does not establish a cause for this or earlier fatal signals. The retained header did not
include instruction bytes, limiting further diagnosis after guest shutdown. Across 49 periodic
samples, observed controller and role memory peaked near 27 and 33 MiB; no sampled cgroup OOM
event was recorded, and minimum observed guest available memory exceeded 4.6 GiB. These are
sampled diagnostics, not attribution of the signal or resource acceptance. Reported teardown
completed, the retained synthetic sentinel matched, and host-observed guest stop completed.
No peer, app, content, restart or hostile/lifecycle assertion passed. Its stopped disks and
verified redundant expanded copies were removed while retaining private diagnostics, manifests
and original archives. Two older fixture payloads also exactly matched an original archive;
their differing manifests were preserved separately before redundant payload disposal.

The diagnostic successor retains at most 2 KiB of instruction hex rows and 1 KiB of explicitly
labelled CPU lines from already safely read crash logs, in addition to the existing 4 KiB header.
The same 15-second capture deadline and 64 KiB overall private evidence limit remain. Adjacent
environment sections and unrecognized formats are omitted. Thirty focused descriptor/evidence
tests pass; these candidate-origin excerpts do not authenticate CPU features or diagnose SIGILL.

The seventeenth attempt used the same products, JDK, CPU/accelerator, memory limits and launcher
policy. All four daemons became ready and the three relay connections passed the real two-sided
peer waiter. The first host bootstrap then failed with `owned-host-bootstrap-unavailable`.
No HTTP status or redirect location was retained, so this is not an observed redirect diagnosis.
Source inspection established an omitted prerequisite: the fixed fixture did not set
`fproxy.hasCompletedWizard`, whose false default permits the HTTP router to redirect host UI
requests to first-run setup. The prospective fixture now explicitly marks its preselected
synthetic configuration complete. This changes its configuration identity; previous fixtures
and observations cannot be relabelled. Global product defaults and redirect handling remain
unchanged. Bootstrap errors now distinguish HTTP status from document shape using fixed labels,
without exposing response bodies, locations or credentials.

The seventeenth attempt captured all four exact stop receipts, a terminalizing campaign, the
matching synthetic sentinel, completed reported cleanup and host-observed guest stop. This is
installed evidence of the new cleanup mechanism, not a predeclared lifecycle-case verdict.
No AppHost install/start, content retrieval or restart completed. Bounded private diagnostics
and original archives were retained before verified stopped disposable disks and redundant
copies were removed. The later retained-deadline handoff correction was not in this attempt.
The fixture correction passed 154 workload tests with 21 skips, 220 interop tests with eight
skips and 271 PR-31x restricted tests with one skip; root-only skips remain unexecuted.

The eighteenth attempt included the first-run configuration and retained-deadline corrections.
All four daemons passed FCP readiness before `operation-deadline-exceeded`; the shared error
label cannot distinguish a peer wait from a management request, so it cannot establish that
host bootstrap passed. All four stop receipts were captured, the synthetic sentinel matched,
cleanup was reported complete and the host confirmed guest stop. Across 166 memory samples,
minimum observed guest available memory exceeded 3.5 GiB. No content or restart result exists.
The diagnostic successor retains at most eight code locations from four fixed helper modules,
without traceback source lines, frame locals or absolute paths. This is private failure
diagnosis, not a trusted per-case acceptance witness, and does not increase operation deadlines.
At the eighteenth helper cutoff, complete protected discovery passed 519 tests with 74 skips,
restricted discovery passed 393 with one skip, and interop discovery passed 220 with eight
skips. The four certification self-tests passed 152, 247, 88 and 185 tests respectively.

The nineteenth attempt's retained code locations identify the first `fetch_direct()` call in
the content operation, ending in a socket timeout while awaiting an FCP frame. This call follows
all three two-sided relay waits and normal installation, worker binding and controller-bound
bootstrap of both signed Mail children. Those steps completed in the installed execution, but
their complete per-case causal records are still absent. No byte-checked remote result was obtained and no
role restart was reached. The configuration correction therefore passed the previously failing
bootstrap point; it did not resolve the content-path failure. All four stop receipts were captured,
the sentinel matched, cleanup was reported complete and host-observed guest stop completed.

`LocalRequestOnly` insertion is intended to write the shared CHK cache, but the existing storage
method can log a write failure and return. The retained wrapper excerpts contained neither of
the fixed storage-error messages; their absence in bounded excerpts does not rule out a failure.
The next driver therefore performs a byte-checked sender `DSOnly` read after local insertion,
before the recipient's unchanged `IgnoreDS` fetch. This control never preloads the recipient,
does not replace remote success and shares the existing 180-second operation deadline. A failed
local control stops the transfer rather than producing a passing result. No cache, routing,
guest or timeout limit was raised.

Future terminal diagnostics also retain at most 2 KiB from each of the four fixed observer FCP
logs. Safe descriptor reads reject unsafe leaves, replacement, excessive size and growth. The
same 15-second capture deadline and 64 KiB total private-output limit apply; controller records
and the sentinel take precedence. These private, non-atomic tails are not acceptance witnesses.
They cannot recover the unretained transcripts from attempts eighteen or nineteen. Their stopped
disks and verified redundant expansions were removed after retaining the available diagnostics.
Older expected-bundle copies were removed only after byte/identity verification and retention
of their unique files and complete path/type/mode inventories alongside the original archives.
The source-control and transcript changes passed 222 interop tests with eight skips, 401
restricted tests with one skip and the 152-test cross-version soak self-test.

A separate bounded, read-only administrator observation during that attempt followed an already
open role cgroup events descriptor through shutdown. It observed `populated=1`, followed by
`ENODEV` and an absent path; it did not observe `populated=0`. The stopped manager subsequently
cleared its invocation and cgroup properties. This demonstrates why missing-path success and a
post-stop manager query cannot supply the required retained-invocation cleanup witness. The
measurement remains private diagnostic evidence, not an accepted lifecycle case; the existing
cleanup gap remains open.

For the peer-call correction, all interop discovery passed 215 tests with eight skips, protected
discovery passed 485 with 74 skips, and restricted discovery passed 388 with one skip. The four
certification self-tests passed 152, 247, 88 and 185 tests. Root and transport skips remain
unexecuted installed checks. The candidate portable remains the startup-fixed source build;
this Python adapter change does not require rebuilding or relabeling the daemon product.

The subsequent wait audit found that the observer adapter constructed a fresh local deadline
after preparation, although the controller still enforced its original campaign deadline. The
corrected handoff carries that original monotonic deadline; the administrator cross-checks it
against retained authority, and late observer construction cannot grant a new local budget.
This is an offline timing correction, not an observed installed deadline-lifecycle pass.
Preparation's unbounded storage-child `waitpid` is also replaced with a finite initialization
wait capped by the original campaign deadline, followed by at most two seconds for exact-child
termination/reap. A timeout retains partial preparation and cannot authorize further work.
Real unprivileged fork tests cover success, failure and a stalled child; simulated uncertain
reap and clock cases remain offline tests. At this correction, protected discovery passed 518
tests with 74 skips, restricted discovery passed 393 with one skip, and interop discovery passed
219 with eight skips. These changes require a fresh installed attempt.

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

The suite-15 diagnostic demonstrated the disappearance transition that the former cleanup
path treated as quiescent without an exact terminal receipt. The replacement implementation
uses a fixed root manager `ExecStopPost` receipt: the helper must positively observe only itself
in the original role cgroup, no descendant cgroup, and unchanged process epoch and group identity.
A successful stop-post invocation alone is insufficient; systemd can reach that phase after a
kill timeout. The owner additionally requires matching start/stop identities, completed manager
state, and an absent original group or the same empty group. A replacement or missing receipt
retains reconciliation-required state. These checks have offline regressions but await installed
execution; the cleanup-race driver remains unimplemented.

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
headroom, controller demand and first-role startup demand. They establish no running four-role
memory observation or installed role-exhaustion result.

After exact role quiescence, extract only fixed bounded sentinels and necessary controller records
with existing safe descriptor readers. Reject symlinks, FIFOs, sockets, hardlinks, races and
unbounded growth. Retained QCOW2 does not preserve tmpfs after shutdown. A private diagnostic
snapshot is not a runtime restore format or continuation of the same epoch. Guest crashes may
make volatile evidence unavailable; record that limitation without manufacturing a snapshot.

Historical attempts' `cleanup=completed` remains a reported teardown result, not the contract's
exact-owned terminal witness. The new implementation persists a terminalizing campaign before
overall shutdown, preserving its generation and original deadline. Admission then rejects new
launches; ownership-only stop remains available. A replacement controller distinguishes initial
preparation from an interrupted launched campaign and fences the latter before reconciliation.
Ordinary role stop remains restartable and archives the prior exact stop receipt before issuing
a new role generation. Partial-launch cleanup preserves an explicitly never-launched prepared
role as distinct from a stopped invocation; its observer adapter accepts that result only when
it has no observed role epoch. Replies for observed roles must match that recorded epoch. Current and preceding receipt projections are retained with bounded
private diagnostics. These changes still require actual systemd, restart and loss validation.
Host-observed guest stop is a separate condition used for disposable disk cleanup; it does not
supply the missing per-case acceptance witnesses. The private snapshot explicitly does not
independently establish quiescence.

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

At helper `12d4eddc6344510a8dfa2acd1d620c88cec17576`, protected discovery ran 482 tests
with 74 skips; restricted discovery ran 382 with one QEMU-tool-availability skip. The protected
workload subset ran 117 with 21 skips; the interop workload adapter ran 26 with eight root-peer
transport skips. Root-only host skips remain unexecuted installed checks. The four certification
self-tests passed with 152, 247, 88 and 185 tests respectively. The FCP deadline regression uses
a real stalled socketpair; namespace/manager mocks elsewhere remain offline-only observations.

For the prospective launcher-policy revision, protected discovery passed 485 tests with 74
skips, restricted discovery passed 388 with one tool-availability skip, and the interop adapter
passed 26 with eight root-peer transport skips. The focused workload subset passed 120 with
21 skips; fixture/runner/evidence tests passed 67. Isolated PR-314 discovery exposed a missing
new dependency mock in the offline terminal-publication fixture; after correction all 61 tests
passed. The four certification self-tests again passed with 152, 247, 88 and 185 tests.
These results test implementation and policy binding only, not installed hostile/lifecycle cases.

The stop-receipt and terminal-fence changes passed protected discovery with 510 tests and 74
skips, restricted discovery with 389 tests and one skip, and interop discovery with 215 tests
and eight skips. The focused workload subset passed 145 with 21 skips; the new marker has 18
offline tests and evidence extraction has 26. Synthetic manager observations remain unit tests.

Earlier in this implementation, the Gradle wrapper completed
`:platform-devtools:installDist assembleCryptadDist`, candidate Mail staging/portable assembly,
and historical predecessor portable assembly. Existing compiler/ErrorProne warnings and Gradle
deprecation findings remain; task success does not establish analyzer cleanliness. No Java
behavior had been edited at that earlier cutoff. The subsequent wrapper startup ordering fix
passed all 28 focused startup, CLI and priority tests. `./gradlew test` then passed 17,406 tests
with zero failures/errors and ten skips: disabled benchmark, platform/provider preconditions,
and Windows-only paths. The JCE algorithm test is explicitly enabled only on Java 21–23 and
did not run on Java 25. Compiler analysis emitted 128 warnings in untouched code, including
BooleanLiteral, EffectivelyPrivate and ReferenceEquality findings; no touched-file compiler
warning was reported. Focused SonarLint reported no production-file findings and eight
informational static-import suggestions on unchanged test lines, none in the new regression.
No final-source hosted CI was dispatched.
None of these results grants installed workload acceptance.

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
