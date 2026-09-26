# Installed workload acceptance completion audit

This page records the PR-315 workload inventory, executable-path gaps, and the remaining
installed verification required for the finite four-role source-build profile.
**Implementation is incomplete; the latest passing TCG attempt, `7db8122b`
suite 108, passed eight positive, thirteen denial and `controller-restart` on one
source-bound guest. Its 22 case IDs do not complete the 45-case contract.**
The first three installed
attempts failed before role staging; the next
two failed network setup. The sixth and seventh prepared the fabric but timed out waiting for
controller readiness. The eighth observed readiness in a startup-only diagnostic. The ninth
through thirteenth reached first-role startup but failed daemon readiness; no four-role positive
run had completed at that point. The fourteenth reached both candidate daemons, then failed predecessor readiness.
The fifteenth reached all four daemons, then exposed an incorrect peer-wait helper call.
The sixteenth failed first-role wrapper bootstrap with a JVM illegal-instruction crash.
The seventeenth passed four-daemon readiness and two-sided peer connection waits, then failed
host bootstrap before app installation.
The eighteenth again reached all four daemons, then hit a bounded operation deadline; the
retained failure does not identify the expired operation, and no content retrieval completed.
The nineteenth reached recipient CHK retrieval after peer, signed AppHost and bootstrap checks,
then timed out waiting for the FCP fetch response. The twentieth lost the recipient HTTP
connection during normal Mail startup, with JVM fatal signals in the retained wrapper output.
It did not reach the new sender-local content control. The twenty-first reached content insertion
but expired while awaiting the sender's local insert response; its relay also recorded a JVM
segmentation fault. The twenty-second through twenty-fourth reached the same first local-only
insert and expired without a terminal insert frame. The full positive sequence then remained
incomplete. The twenty-fifth failed predecessor daemon readiness after both candidate roles
responded to FCP. The twenty-sixth failed sender daemon readiness after a JVM startup crash.
The twenty-seventh, in a separately identified macOS Docker translation profile, failed guest
boot before SSH readiness.
The twenty-eighth, on a new native x86 tank1 task root, failed during host source archiving before
allocating its VM.
The twenty-ninth passed four-role readiness, signed Mail bootstrap and the sender's local-only
CHK insertion and local byte control, then timed out waiting for the recipient's cross-node
fetch. Its diagnostics and stopped guest are retained privately. A subsequent isolated
three-node diagnostic identified a peer-selection defect and verified a narrow source fix;
that local result is not an installed acceptance witness.
The thirtieth, with the corrected native Linux product, completed the installed positive
aggregate: two byte-checked sender/recipient CHK transfers straddled a sender restart and
the signed Mail workers started. No individual v8 positive case has a complete trusted
record, and all denial and lifecycle cases remain unexecuted.
The thirty-first reran the same product with a fresh source-bound fixture and prospective
controller-kernel daemon epoch checks. Its positive aggregate also completed, including
the final four-role process sweep; individual v8 case coverage remains incomplete.
The thirty-second, adding actual Java PID-to-role network namespace identity checks, reached
four-role startup but failed relay FCP readiness after a wrapper JVM-start signal timeout.
The unchanged thirty-third attempt completed the positive aggregate with those checks.
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
Suite 81 used `workload-launcher-policy-v4` for its measured candidate-role
read/write pair. A separate KVM diagnostic exercised v5. The prospective
`workload-launcher-policy-v6` adds three more fixed role boundary
operations within the same TCG guest profile family. Its test-kit and TCG
results must be measured anew; historical v8 record interpretation remains
unchanged.

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

The twentieth attempt used helper `4b85d11281742503f5da06bfce40bded2ce5ef76`, with unchanged
products, JDK, CPU and VM resource profile. It passed four-daemon readiness and peer exchange
before the recipient HTTP connection closed during the normal Mail start request. Retained
wrapper output contains SIGILL and SIGSEGV reports; overlapping excerpts are not a reliable
count of distinct crashes. Their cause remains undiagnosed. All four FCP tails, stop receipts
and the matching sentinel were retained; cleanup and guest stop completed. The bounded evidence
record omitted detailed crash sections because routine logs had already consumed the output
budget. Those volatile details cannot be recovered after guest shutdown.

The follow-up evidence correction prioritizes crash headers and instruction/CPU sections after
controller records and the sentinel, ahead of FCP tails and routine wrapper logs. It preserves
the same 15-second deadline and 64 KiB output limit. A regression with crash records and flooded
routine logs verifies retention priority and explicit lower-priority omissions; all 38 focused
evidence tests pass. This is an evidence-retention fix, not a fix for the JVM failures.
After verified disposal of the stopped twentieth guest and redundant copies, task allocation
was 12,840,984,576 bytes and filesystem free space was 43,988,877,312 bytes. Original archives,
available diagnostics, reusable inputs and the current fixture remain retained under the
40 GiB task budget and 8 GiB free-space reserve.

The twenty-first attempt used helper `b9aab8c03b98b2886c738db10f790707b067d0ea` (tree
`93529a143b2bd1636e1b30260b44f5c6de47eed5`). Four daemon readiness checks and the normal
peer/AppHost/bootstrap sequence completed before the first content insertion. The retained FCP
tail confirms the sender's local-only insert request; the observer expired at the original
operation deadline while awaiting its response. Neither the sender-local read control nor the
recipient fetch ran. The relay fatal header reports SIGSEGV/SEGV_MAPERR in C1-compiled
`java.lang.CharacterData.of`. That observation does not establish the cause of the sender's
insert timeout or the earlier JVM failures. The pinned emulator binary identifies QEMU 10.0.13
(Debian `1:10.0.13+ds-0+deb13u1`) and matches the attempt's boot-closure identity.

Crash-first capture retained the fatal header and CPU line, but exposed a second diagnostic
defect: the instruction parser reported `captured` for a heading with no byte rows. JDK 25's
formatter permits indented and highlighted rows, which the earlier bare-address parser rejected.
The corrected reader accepts those fixed row forms, retains only normalized address/hex bytes
and a strictly numeric PC, and discards optional ASCII columns and adjacent sections. A heading
without byte rows is now `not-found`. Existing section, deadline and total-output caps remain.
The [OpenJDK 25 formatter](https://github.com/openjdk/jdk25u/blob/master/src/hotspot/share/runtime/os.cpp)
documents these row forms. A single unprivileged disposable process using the exact pinned JDK,
with core dumps disabled and bounded time/heap/output, confirmed that the corrected extractor
retains actual hex rows and the PC within the 2 KiB section limit. This is offline format
validation, not an installed workload case. All 83 PR-315 offline tests passed at this cutoff.
The exact rejected row from the twenty-first guest was not retained; the formatting correction
does not reconstruct those lost bytes or diagnose a JVM defect.

The twenty-first attempt captured all four current stop receipts and the matching sentinel,
completed cleanup and stopped the guest. Its 170 periodic memory samples observed a minimum
of 3,808,256,000 bytes available in the guest; the last observed role memory-event counters had
no OOM or OOM-kill events. Sampling is not continuous proof. Safe disposal retained the original
archive and available diagnostics while removing stopped disks and verified redundant copies.
After also retaining the unique files and reconstruction inventories for older expected bundles,
task allocation was 12,982,272,000 bytes and filesystem free space was 43,844,763,648 bytes.

A separate bounded, read-only administrator observation during that attempt followed an already
open role cgroup events descriptor through shutdown. It observed `populated=1`, followed by
`ENODEV` and an absent path; it did not observe `populated=0`. The stopped manager subsequently
cleared its invocation and cgroup properties. This demonstrates why missing-path success and a
post-stop manager query cannot supply the required retained-invocation cleanup witness. The
measurement remains private diagnostic evidence, not an accepted lifecycle case; the existing
cleanup gap remains open.

Attempts 22 and 23 reused the exact `beb9caa143010e5ce5edd0739c0bc60d745ca851`
helper tree and source-built two-product fixture. Both reached four-daemon readiness, peer
exchange, normal signed Mail AppHost startup and bootstrap, then expired while waiting for the
sender's first local-only FCP `ClientPut` response. Neither reached the new source-local
`ClientGet DSOnly=true` control, remote recipient fetch or role restart. Attempt 23's one-time
private sender thread diagnostic, taken during that wait, did not show an active insert stack;
it retained selected stack lines but not the complete thread dump. Its 161 guest-memory samples
had a minimum of 3,792,982,016 bytes available. Four current stop receipts, a matching sentinel,
reported cleanup and guest stop were retained. These observations do not locate the missing
insert callback or independently establish role quiescence.

Attempt 24 retained the same helper, products, JDK, `tcg-multi`/`qemu64`, 5632-MiB guest,
campaign and operation deadlines. Four daemons again reached readiness and the normal peer,
signed AppHost and bootstrap path completed. Its FCP tail records the sender's `ClientPut` with
no subsequent insert frame. At the predeclared 45-second nonresponse point, a single private
administrator diagnostic signaled only the exact owned sender JVM after checking its retained
invocation, role cgroup, namespaces, principal and executable digest. The bounded full-output
capture observed 84,048 bytes and a thread-dump header; dump completeness was not independently
established. At that snapshot FCP was reading the next message, its output queue was idle, the
CHK realtime starter was waiting for work and no active insert stack was observed. This does
not distinguish a request that failed before scheduling from a later missing callback or a
response observation defect. Fixed bounded node-log excerpts include peer-reference errors,
without a demonstrated link to the local-only insert.

Attempt 24's bounded fatal-log snapshot also retained two JVM `SIGSEGV` headers and corrected
instruction sections. Their recorded times precede the sender's `ClientPut`; the current sender
diagnostic identifies a different process epoch from its earlier fatal report. These crashes
show continuing emulator/JVM instability, but do not establish the cause of the later local
insert wait. The observer again expired at the original operation deadline. Its 175 guest-memory
samples observed at least 3,823,648,768 bytes available. Four current stop receipts, a matched
sentinel, reported cleanup and guest stop were captured. The private snapshot explicitly marks
independent quiescence unestablished, and none of the eight positive case witnesses passed.

After exact stopped-guest, backing and archive-reconstruction checks, the three attempts'
disposable disks and verified duplicate staging copies were removed while their original source
archives and unique private diagnostics stayed retained. After attempt 24, task allocation is
14,133,207,040 bytes. An unchanged next attempt requires a further 29,213,549,102-byte
reservation, projecting 43,346,756,142 bytes, or 397,083,182 bytes above the selected 40-GiB
task cap. Filesystem free space is 41,934,192,640 bytes against the 8-GiB reserve; effective
available host memory is 10,450,337,792 bytes against the 7-GiB VM budget plus 1-GiB host
reserve. Storage alone blocks another allocation. Remaining installed cases stay unexecuted or
inconclusive; no deadline, CPU, JDK, role memory or guest-size limit was changed to make room.

For a prospective unchanged twenty-fifth attempt, an audit found two obsolete JDK preparation
copies rather than deleting any distinct failed-attempt archive. The source expansion's 486
entries matched the retained original archive by type, file bytes and symlink targets; its 136
mode-only differences were inventoried privately. A separate prepared JDK tar was an exact
digest duplicate of the retained input tar and absent from the boot-file roster. After active
reference checks, those two generated copies were removed, reclaiming 458,571,776 allocated
bytes. The original archive, flattened runtime JDK, pinned closure, fixture and all 24 distinct
failure archives stayed retained. The next unchanged allocation then projected 42,888,450,606
bytes, 61,222,354 bytes below the 40-GiB cap; the 8-GiB free-space and host-memory reserves
passed. The runner repeated admission before allocating.

Attempt 25 used the same helper/product/JDK/CPU/resource tuple. It verified installation and
test kit before starting the campaign, prepared all four roles, and observed FCP readiness on
the two candidate roles. The predecessor never yielded FCP readiness within the fixed window;
its retained wrapper log reports that the wrapper's own JVM-start signal wait expired and that
it terminated that JVM. This identifies the immediate predecessor startup failure, without
establishing why startup was slow under the pinned guest. The relay was not observed started.
The positive driver reported
`workload-daemon-readiness-timeout`, with no content operation. Its private snapshot retained a
sender startup `SIGILL` report, but that earlier process failure does not establish why the
predecessor failed readiness. The controller recorded two node starts and two stops. Three
current stop receipts and a matching sentinel were captured; the relay receipt was
`unavailable-or-unsafe`, and independent quiescence remains unestablished. Reported cleanup and
guest stop completed. Its 104 guest-memory samples observed at least 4,487,254,016 bytes
available. The fixed sender-stall diagnostic did not trigger. This attempt supplies no completed
positive case or hostile/lifecycle witness.

After the stopped-ownership and backing checks, attempt 25's disposable disks, archive-verified
source expansion, duplicate boot closure and reconstructable expected-bundle expansion were
removed. Its distinct original source archive and private failure diagnostics remain retained.
The relay's retained controller state was prepared with no generation, manager invocation or
cgroup, consistent with no observed launch; the unavailable receipt still cannot prove
quiescence. Task allocation is now 14,106,800,128 bytes. Another unchanged attempt would project
43,320,349,230 bytes, exceeding the 40-GiB task cap by 370,676,270 bytes. Filesystem free space
is 41,957,908,480 bytes against the 8-GiB reserve; effective available host memory is
10,469,734,400 bytes against the 7-GiB plus 1-GiB memory reservation. Storage is the blocking
condition, so another guest must not be allocated without a separately verified safe reclaim or
a prospective budget decision.

A further task-wide audit retired two detached, task-owned historical source-build worktrees
only after verifying their exact Git commits and trees, reconstructable tracked files, portable
expansions, wrapper expansions and duplicate JARs. Unique problem reports, the two modified
checkout scripts and 8,226 unproven ignored build files were moved intact to private retention,
with old/new paths, hashes and a losslessly compressed complete inventory. Targeted
`git worktree remove` completed without force; original products, failed-attempt archives,
current fixture and reference inputs remained. The measured preflight for another unchanged
attempt then counted 13,713,506,304 allocated task bytes plus the conservative unchanged
29,213,549,102-byte reservation, leaving 22,617,554 bytes under 40 GiB. Filesystem free space
was 42,351,628,288 bytes and effective available host memory was 10,487,266,304 bytes; both
reserves passed. The runner repeated its own admission before allocating attempt 26.

Attempt 26 verified installation and test kit, prepared all four roles, then failed sender daemon
readiness before any node-start event. Its retained sender startup report records a JVM `SIGILL`
approximately five seconds into that process epoch. The observer reported
`workload-daemon-readiness-timeout` with the original experiment deadline exhausted; no peer,
app, content or restart action was observed. The private snapshot retained a matching sentinel
and a current sender stop receipt. The other three roles had no available safe stop receipt;
reported cleanup and guest stop do not turn those absences into independent quiescence proof.
Its 53 guest-memory samples observed at least 5,066,575,872 bytes available. The fixed sender
insert-stall diagnostic did not trigger. No positive, hostile or lifecycle case passed.

After exact stopped-owner, backing, boot-pin and archive checks, attempt 26's disposable disks
and verified duplicate expansions were removed. The original source archive and all unique
private diagnostics remain retained. The sender's captured stop receipt was checked against its
owned invocation; the other three roles remained prepared with no invocation or cgroup and no
observed launch. Independent overall quiescence is still unestablished. Final task allocation is
14,145,384,448 bytes. The next unchanged reservation is 29,208,196,898 bytes, projecting
43,353,581,346 bytes, or 403,908,386 bytes above the 40-GiB cap. Filesystem free space is
41,923,276,800 bytes and effective available host memory is 10,472,177,664 bytes, so their
8-GiB and 7-GiB-plus-1-GiB reserves pass. Further guest allocation is stopped under the
selected task cap; all remaining installed cases remain unexecuted or inconclusive.

### macOS transfer and separate startup diagnostic

The retained 26-attempt private task tree was copied from CT102 into the macOS workspace.
A checksum dry run found no differing files. A then-current `8e6fd35b898658a8a1c420cc6c64a664016abdb9`
fixture was prepared on CT102 from the same candidate, predecessor, JDK and signed Mail inputs,
then copied and strictly verified in an isolated Debian 13 amd64 Docker volume. Restoring the
original build-output permission bits was necessary because the macOS archive extraction had
removed group write permission from JARs; the verifier includes modes in its tool-tree digest.
The Git worktree remained clean. The focused PR-315 suite passed all 83 tests inside Linux;
its native macOS invocation was not a valid Linux test environment.

The macOS host has an arm64 CPU, so Docker translates the fixed x86_64 QEMU process. This is a
separately identified `pr315-mac-docker-translation-v1` diagnostic profile. Its prospective
task-wide cap was 96 GiB, including the retained macOS evidence copy, private Docker volume,
Docker image and next guest reservation; the Docker-root cap was 80 GiB. The 8 GiB filesystem
and 7 GiB plus 1 GiB memory reserves passed. The new attempt's 202 common boot-closure file
digests matched attempt 24, including its pinned QEMU binary and libraries. The source-built
products and JDK were unchanged.

Attempt 27 failed at guest boot. Under the existing 180-second SSH readiness window, the
translated QEMU guest reached only early Debian systemd startup; SSH banner exchanges timed out.
The guest and emulator stopped, and its complete stopped QCOW2 backing pair and failure
diagnostics were copied back to private macOS retention. A bytewise dry run found no copy
differences. This diagnostic cannot supply a workload witness or establish how the original
native x86 profile would behave. No boot timeout, guest size, CPU model or campaign deadline was
increased for it.

A separate single-node macOS diagnostic used the exact source-built candidate JAR with a local
Java 25 runtime, loopback FCP and no peers or Mail. Several synthetic
`ClientPut LocalRequestOnly=true` operations stalled after FCP accepted the request; a 120-second
attempt and shorter repetitions saw no response. A full live thread dump showed the FCP input
thread reading the next message, its output queue idle and CHK insert starters waiting. Minimal
insert DEBUG logs showed CHK encoding and block-set finalization without a started block request.
With scheduler DEBUG enabled, an equivalent synthetic operation received `URIGenerated`,
`PutFetchable` and `PutSuccessful` within milliseconds. A second non-debug `ClientPut` did not
release an already stalled first request. The timing-sensitive local behavior narrows the
investigation to insert scheduling or a preceding state transition. These local diagnostics
remain private and do not constitute installed acceptance.

A bounded read-only JVM Attach snapshot subsequently found two unfinished, ready CHK insert
items at priority 2, no running insert token, and an idle starter. An additional `wakeUp()`
did not clear the stall; a direct scheduler selection returned no block. Source inspection
identified the exact branch: `RandomGrabArray` counted an exclusion value of `-1` as eligible,
then `findNthValid()` required `== 0` when choosing among multiple eligible items. The insert
starter deliberately returns `-1` for an allowed insert. This mismatch stranded both the data
and metadata blocks for a small CHK put; DEBUG timing sometimes let the first block run while
the selector contained only one item, bypassing the faulty branch.

The source fix changes the final comparison to `<= 0`. A regression with two ready items and
negative exclusions failed before the change and passed afterward with the complete
`RandomGrabArrayTest` class. Two fresh, non-DEBUG local nodes then received `PutSuccessful`
using the rebuilt Java artifact. These are local behavioral checks, not installed witnesses.
An exact `c0964f057b46347575bed818d486a9054c9f27ac` Linux source build and fixture subsequently
passed strict verification. The remaining 37 hostile and lifecycle emitters are unaffected.

A read-only PVE storage check found the CT102 root filesystem still has room for another guest,
but its underlying shared `local-lvm` thin pool had about 22 GiB free against the unchanged
29.28-GB conservative next-attempt reservation. Increasing only CT102's 40-GiB task cap would
not fund that underlying reservation. No further native CT102 VM was allocated in this state.

### Native tank1 preparation and archive limit

The former 40-GiB task cap applied to the previous container agent; it is not a limit for this
workspace. A prospective 512-GiB task-wide budget now counts the retained macOS, Docker and
CT102 copies, a new tank1 copy and the next guest reservation. The task-owned tank1 dataset has
a 256-GiB quota; its runner root has a 224-GiB budget and a 16-GiB free-space reserve. The
shared PVE thin pool retains a separate 16-GiB minimum because the CT102 root still resides
there. One VM attempt is admitted at a time and capacity is rechecked before every allocation.

The healthy tank1 dataset was hot-mounted into CT102 at `/work/pr315-task` without stopping the
container. The original CT102 tree and macOS copy remain intact. Both retained reference QCOW2
files had no backing dependency and no QEMU was running before the copy. A checksum dry run found
no differences in the copied inputs or evidence; its only entries were the mount root's timestamp
and the verification output created in the source directory after the copy. The fixture in the
new root passed its full strict verification. The runner's `--probe` reported about 13.43 GB of
retained task allocation, a 29.21-GB next-attempt reservation and about 10.62 GB effective host
memory available, with no admission reason. It allocated no VM.

Attempt 28 repeated those admission checks and copied the fixed source, product and fixture to
the tank1 attempt directory. It failed at `source-archive`, before `guest.qcow2` creation; its
reported guest state remained stopped and no installed driver ran. The shared host-command
helper gives `tar -czf` 120 seconds by default. The retained archive was incomplete at about
285 MB when that bound expired. A separate bounded diagnostic archived the same exact source
snapshot to the same tank1 dataset in 267.421 seconds, producing a 425,189,755-byte archive.
This establishes a host preparation bound on the new storage, not a workload or guest timeout.

The prospective helper revision gives only `workload-positive` source archiving 420 seconds;
other reference modes retain 120 seconds. Guest SSH readiness, the original campaign deadline,
FCP operation deadlines, QEMU, CPU model, guest memory and role limits are unchanged. The new
helper source identity requires fresh fixture preparation and an installed rerun. Attempt 28
remains a failed preparation diagnostic, and all 45 installed workload cases remain without a
complete acceptance witness.

### Installed attempt 29 and cross-node routing defect

Attempt 29 used the unchanged native x86 `tcg-multi`/`qemu64`, four-vCPU, 5632-MiB guest
profile on the tank1 task root. Its copied reference, strict fixture, source archive, guest
boot, installation, four-daemon readiness and ordinary signed Mail bootstrap passed. The
sender's first `ClientPut LocalRequestOnly=true` emitted `URIGenerated`, `PutFetchable` and
`PutSuccessful`; a sender-side `DSOnly=true` control returned the exact inserted bytes. The
recipient then sent `ClientGet IgnoreDS=true` but received no terminal frame within the
predeclared 120-second operation limit. The driver failed and stopped the guest. All four
stop receipts were captured, but independent quiescence was not established. No complete
positive case was recorded, and the 37 hostile and lifecycle emitters remain unexecuted.

The same candidate JAR reproduced the stalled recipient fetch in a private, isolated
three-node loopback network without QEMU, nftables or AppHost. Peer status showed two-sided
connections. A read-only recipient fetch-scheduler snapshot found no pending CHK item after
the request had started; detailed logs showed its first `RequestSender` selecting the only
connected relay as the overall closest peer, then immediately finishing with
`ROUTE_NOT_FOUND`. This excludes the earlier insert-scheduler defect as the cause of this
particular local fetch failure. An experiment enabling sender
`node.writeLocalToDatastore` still timed out, so local datastore policy did not resolve it.

Source inspection found that `PeerRoutingSelector.updateBestTracking()` combined three
state-mutating calls with short-circuit `||`. When the first call selected a candidate as the
overall closest, it skipped the backed-off and not-backed-off trackers. The final selector
reads those trackers, so one eligible peer yielded `null`; multiple peers could select the
second closest instead. Existing unit expectations encoded that wrong behavior. After
correcting the tracker calls and expectations, 13 of 17 focused tests failed on the old
source and all 17 passed on the revised source. A fresh source-built local three-node run
then completed the same local-only CHK insertion, sender byte control and recipient
cross-node byte retrieval. This corroborates the defect and fix in an isolated network;
the revised product still requires an exact Linux build, fresh fixture and installed rerun.

### Native installed positive aggregate in attempt 30

The exact `4a924b8b7b039355ba01eb102d813d774689166a` Linux build passed the full Java
suite: 17,407 tests, ten skips, zero failures and zero errors. The focused PR-315 Linux
offline suite passed 83 tests. The new source/product-bound fixture passed strict verification.
A no-VM probe accepted the unchanged tank1 storage, host-memory and original
`tcg-multi`/`qemu64` profile. The first formal invocation refused the probe's already
existing output directory before allocating a VM; its files were preserved under a separate
`probe-30` path. After a fresh capacity check, the real attempt used a new `suite-30` output
directory without changing VM, guest, FCP or campaign limits.

The real attempt retained a guest report with exit code zero and `guestStopped=true`.
The installed driver reported four roles, two signed Mail workers, a new sender manager
epoch, and observed CHK content retrieval. Both sender `ClientPut` operations reached
`PutSuccessful`; sender-local controls and recipient cross-node `ClientGet` operations
returned `AllData`, and the driver compared their bytes before reporting success. The
positive aggregate is bound to the installed source/product identity by the runner, which
reported `installedPositiveExecuted=true`. Its eight individual positive case statuses
remain `inconclusive`: the required trusted per-case observations and host context have not
been emitted. All 26 denial and 11 lifecycle cases remain `not-executed`, so
`installedWorkloadAcceptanceSatisfied=false` and implementation coverage is incomplete.

The caller reported cleanup completed, all four current stop receipts were captured, and
the sender's pre-restart receipt was also captured. The retained fixed-file snapshot still
states `quiescenceIndependentlyEstablished=false`; neither the caller report nor the stopped
guest replaces independent proof. Its sentinel matched. Across 161 five-second samples,
minimum observed guest available memory was 3,780,231,168 bytes and the last sampled OOM
kill counters were zero; this is sampled diagnostic context, not continuous resource proof.
A predecessor HotSpot fatal file records `SIGILL` during this otherwise completed attempt.
Its reported problematic frame was a C1-compiled `ZipUtils.get32` method. Other retained
fatal summaries from attempts 13, 16, 21, 24-26 and 29 also name C1-compiled Java frames,
but the methods and signals differ. This pattern does not establish whether the cause is
QEMU, HotSpot or another guest fault; no VM, JDK or compiler profile was changed to obtain
the positive aggregate. The intermittent JVM failures remain open. The full stopped
attempt, including its same-attempt QCOW2 backing pair, was copied to the local private
retention directory and a recursive checksum dry run found no differences. No installed
hostile/lifecycle result or independent security review follows from this aggregate.

The next prospective observer revision pins the sole outer-namespace Java process from a
controller kernel sample after each role becomes FCP-ready. It checks the host PID, start
ticks, namespace PID vector and exact JDK executable on subsequent observations, requires
a new Java epoch after the intended sender restart, and samples all four roles again before
returning a positive aggregate. This addresses the attempt-30 gap where a service unit could
remain active while its JVM crashed or restarted internally. Linux interop tests exercise
same-manager JVM replacement, ambiguous process selection and the terminal all-role sweep.
The checks do not establish per-case process identity or turn any v8 case into `passed`.

Attempt 31 used helper source `9a231a35e36de8fb8e604d1232ea89e31328f9d9` and the
unchanged `4a924b8b7b039355ba01eb102d813d774689166a` candidate product. Its strict
fixture verification and separate no-VM admission probe passed. The original QEMU/JDK,
four-vCPU, 5632-MiB guest, operation bounds and workload policy remained selected. The
installed guest reported exit code zero and stopped; the positive aggregate again recorded
four roles, two signed Mail workers, a new sender manager epoch and byte-checked cross-node
retrieval before and after restart. The new daemon process epoch checks and final all-role
sample completed without failure. No fatal JVM file was found in this attempt. All current
stop receipts and the sender's prior receipt were captured, the sentinel matched, and the
caller reported cleanup completed. The fixed-file snapshot still states
`quiescenceIndependentlyEstablished=false`. The full stopped private evidence and same-attempt
QCOW2 backing pair were copied to local retention; a recursive checksum dry run found no
differences. The Linux interop offline suite passed 227 tests with eight skips, and the
focused PR-315 suite passed 83 tests. Attempt 31 therefore confirms the narrower process
epoch guard in one installed run, while all eight individual positive cases remain
`inconclusive` and the 37 denial/lifecycle cases remain `not-executed`.

A further prospective controller observation binds the fixed role namespace's nsfs device
and inode to the actual outer Java PID's `/proc/<pid>/ns/net` identity, sampled before and
after the process read. The adapter rejects a missing, ambiguous or mismatched daemon
namespace and retains the fixed cgroup identity alongside the process epoch. Linux focused
controller and adapter tests passed; the installed results appear below. These observations
are groundwork for genuine per-case actor
binding and are not themselves accepted case records.

Attempt 32 bound helper source `16403569775efb3bd3de8d85f5c16b04ac335a87` to the
unchanged candidate product and passed strict fixture/admission checks. Sender, recipient and
predecessor obtained FCP identities; relay service became active but never returned a complete
FCP identity within the original 180-second daemon readiness bound. The retained wrapper
excerpt shows its first JVM exceeded the wrapper's fixed startup-signal window and was
terminated, followed by a second JVM launch. The observer reported
`workload-daemon-readiness-timeout` with an immediate operation-deadline cause; no CHK request
was attempted. No HotSpot fatal file was captured and the relay's last sampled OOM-kill count
was zero. Cleanup was reported complete and the guest stopped. This does not establish a
namespace check failure or the root cause of intermittent startup delay.

Attempt 33 used the exact same source, fixture, product, guest profile and deadlines after a
fresh whole-task inventory and no-VM admission probe. It retained an exit-zero stopped guest
and `installedPositiveExecuted=true` aggregate with four roles, two signed Mail workers,
sender restart, and two byte-checked cross-node CHK transfers. Controller-observed daemon
process epochs and actual network namespace identities survived the final all-role sweep.
No fatal JVM file was captured; 172 five-second samples recorded at least 3,798,196,224 bytes
of guest available memory, with zero last-sampled OOM kills. The caller reported cleanup
completed, all current stop receipts and the sender's prior receipt were captured, and the
sentinel matched. Independent quiescence is still unestablished by the fixed-file snapshot.
The two stopped attempts and their same-attempt QCOW2 backing pairs were retained privately
and copied to local storage; recursive checksum dry runs found no differences. The successful
retry validates this narrower process/network binding in one installed run. It does not
resolve attempt 32's startup failure, complete any individual positive case record, or
execute the 37 hostile and lifecycle emitters.

The next prospective adapter revision projects its final four controller-kernel samples into
one fixed private role roster: installed UID/GID, actual daemon start tick, manager invocation,
boot ID, cgroup identity digest and actual role network namespace inode. The host runner
requires that roster's closed v8 principal shape and cross-checks the manager invocation,
cgroup and boot identity against separately extracted root-owned terminal controller records
and matching stop receipts after guest shutdown. Missing, malformed or substituted terminal
records cannot set the diagnostic `installedPositiveExecuted` flag. These observations are
still not per-case operation or denial witnesses, and the diagnostic flag does not imply
`installedWorkloadAcceptanceSatisfied`. At this prospective revision's preparation cutoff,
Linux focused adapter and PR-315 offline tests passed, while the roster path still awaited
installed execution.

A subsequent prospective host verifier uses that bound roster for exactly two v8 cases:
`installed-ready` repeats the fixed host installation/source/test-kit verification after
guest shutdown, and `four-role-start` uses the real final controller-kernel sample window.
Both are passed through the existing closed `pr314_acceptance.verify_attempts` contract with
the selected signed Mail digest and retained root terminal authority. The other six positive
cases remain inconclusive and all 37 hostile/lifecycle cases remain unexecuted; the runner
hard-codes full installed acceptance false for this incomplete implementation. Offline
synthetic records proved only that this narrow verifier path was reachable; attempt 35 below
provides the installed result.

Attempt 35 used helper source `21d004f0cc4de57bdbe7f573ae67c7b27ac5eabb`, the unchanged
source-built Linux product, and a fresh strict fixture. Task-wide storage and memory
admission passed before allocating the original `tcg-multi`/`qemu64`, four-vCPU, 5632-MiB
guest. The installed driver completed four roles, two normally signed Mail workers, both
byte-checked sender/recipient CHK transfers and a new sender manager and Java epoch. The
guest command exited zero and the emulator stopped. Afterward the host reverified the
installed source/test-kit/boot/product identity, checked the final controller-kernel roster
against root-owned terminal role and stop records, and called the fixed v8 verifier with
only `installed-ready` and `four-role-start` declared. It returned
`recordContractValid=true` and those two cases `passed`. The other six positive cases remain
`inconclusive`; 26 denial and 11 lifecycle cases remain `not-executed`, so the 45-case
`installedWorkloadAcceptanceSatisfied` verdict remains false.

The caller reported cleanup complete, all current stop receipts and the sender's prior
receipt were captured, and the synthetic sentinel matched. The fixed-file snapshot still
reports `quiescenceIndependentlyEstablished=false`; these two cases do not prove lifecycle
cleanup or any denial. No JVM fatal file was captured and 172 five-second resource samples
ended with zero OOM-kill counters. The stopped guest and same-attempt QCOW2 backing pair,
case record, and private diagnostics were copied to local retention and passed a recursive
checksum dry run. This installed observation is narrower than full workload acceptance and
does not replace original protected authority or independent security review.

The next prospective positive revision samples the current signed Mail worker again after
sender restart and binds its API PID hint to the controller's real nested-namespace worker
and Java descendant. It also retains a bounded start/end time for each administrator cgroup
sample, then requires all four current cgroup identities and positive memory, task and CPU
measurements to match the terminal role roster before attempting `signed-apphost-child` or
`kernel-resource-scope`. Missing, stale or mismatched observations leave those cases
inconclusive; the existing two installed case records remain separate. Linux offline tests
cover both the full four-case shape and evidence-substitution rejection. At that preparation
cutoff no installed result for these two additional cases existed; attempt 38 below supplies it.

Attempt 36 used the additional AppHost/resource emitter source with a fresh exact fixture,
but the sender JVM crashed with `SIGSEGV` in C1-compiled `Math.max` before FCP readiness.
The guest stopped after reported cleanup; no new case was credited. Its complete private
crash evidence and same-attempt QCOW2 backing pair were retained and copied locally.
This is another intermittent startup/JIT failure, not evidence that the new witness path
was exercised.

The next no-VM attempt-37 probe exposed a separate host admission problem before any guest
allocation: Python's task-wide allocated-block walk reached its existing 30-second deadline
after the retained input/evidence tree grew, even though the tank1 quota and free-space
reserves still passed. A read-only native `du` walk counted the same allocated blocks as the
old walk on a hardlink/symlink fixture and completed the real retained tree well within 30
seconds. The prospective Linux fast path retains a 30-second process deadline, counts every
hardlink, refuses malformed totals and checks `/proc/self/mountinfo` for any nested foreign
device before using `du -x`. Non-Linux behavior retains the original walk. The failed probe
directory is retained separately; fresh exact-source fixture and no-VM admission remain
required before another guest.

Subsequent unchanged no-VM probes showed that even the native `du` fallback could hit its
30-second bound intermittently on the growing ZFS tree; a direct diagnostic retained a
`TimeoutExpired` cause. A different probe completed admission, and formal attempt 37
allocated a VM, but its guest did not reach SSH readiness within the original 180-second
boot window. It stopped at `guest-boot` without any workload case execution; its stopped
private boot evidence and same-attempt disk pair were retained. This is separate from the
capacity-inventory failure.

The task root is itself a mounted, private ZFS filesystem. A prospective refinement first
rejects any nested foreign-device mount, then charges the entire mounted filesystem's
allocated usage from `statvfs` rather than walking retained files. On this dedicated mount,
that constant-time figure was conservative relative to the earlier complete `du` count;
it includes filesystem metadata and all retained task inputs. Non-mount Linux roots keep
the bounded hardlink-counting `du` path, and non-Linux roots keep the earlier Python walk.
No storage budget, free-space reserve, guest boot deadline or campaign deadline was raised.
The refinement needs a fresh exact-source fixture and no-VM admission before another guest.

Attempt 38 bound helper source `6a9472d2485436ceaf3d64780454fb466fc34047` to the
unchanged Linux product and passed strict fixture and no-VM admission checks. Mounted task
usage was charged conservatively without a repeated file-tree scan; no budget or guest
deadline changed. The guest passed four-daemon readiness, started two normally signed Mail
workers, performed byte-checked sender/recipient CHK transfers before and after sender
restart, and exited zero. The stopped host runner cross-checked the final role roster,
administrator cgroup sample windows, signed AppHost child identity, installation/source
identity and current stop receipts. The fixed v8 verifier returned
`recordContractValid=true` with `installed-ready`, `four-role-start`,
`signed-apphost-child` and `kernel-resource-scope` all `passed`. The other four positive
cases remain `inconclusive`; 26 denial and 11 lifecycle cases remain `not-executed`.
Full installed workload acceptance therefore remains false.

The caller reported cleanup complete, all current stop receipts and the sender's prior
receipt were captured, and the sentinel matched; independent quiescence remains
unestablished. Across 186 five-second samples, guest available memory stayed at or above
3,747,287,040 bytes and the last OOM-kill counters were zero. Private HotSpot fatal files
nevertheless showed two candidate-sender, one candidate-recipient and one relay JVM crashes,
all in varying C1-compiled JDK methods with `SIGILL` or `SIGSEGV`. The successful case records
refer to the actual final bound invocation epochs; they do not establish continuous JVM
stability or explain the earlier crashes. The full stopped attempt, including same-attempt
QCOW2 backing pair, four-case record and fatal diagnostics, was copied to local private
retention and passed a recursive checksum dry run. No denial/lifecycle result, original
protected authority or independent security review follows from this partial acceptance.

The next prospective positive revision adds fixed root-owned exchange audits for the
existing `connect-fcp` and `bootstrap-mail` controller methods. The controller records only
exact request/response hashes, current manager/cgroup/boot identity, actual monotonic
window and one served request; it never retains the Mail session token or a candidate URL.
The observer separately records hashes of the exact bytes it sent and received. After guest
shutdown the administrator snapshots the two fixed audit files and checks both sources
against the current role roster before producing independent v8 case commitments for
`own-management` and `dynamic-app-bootstrap`. An absent or mismatched audit leaves each
case inconclusive, and no new control method or arbitrary endpoint selector is introduced.
Linux protected and restricted offline tests cover fixed dispatch, digest projection and
tamper rejection. At this preparation cutoff installed execution was still required;
attempt 39 below supplies it.

Attempt 39 bound helper source `c39cf688e1e37336eacaf58fb41773118425f72c` to the
unchanged Linux product and passed strict fixture and no-VM admission. Its four installed
roles, two normally signed Mail workers, sender restart and byte-checked CHK transfers before
and after restart completed; the guest exited zero and the emulator stopped. The root
controller's fixed `connect-fcp` and `bootstrap-mail` audit digests matched the separately
received observer bytes and current sender manager/cgroup identity. The host produced
independent v8 commitments, and the verifier returned `recordContractValid=true` with six
positive cases `passed`: `installed-ready`, `four-role-start`, `signed-apphost-child`,
`own-management`, `dynamic-app-bootstrap` and `kernel-resource-scope`. The remaining two
positive cases, `fnp-content-retrieval` and `restart-durable-state`, stay `inconclusive`;
all 26 denial and 11 lifecycle cases remain `not-executed`. Full installed workload
acceptance remains false.

The caller reported cleanup complete, current stop receipts and the sender's prior receipt
were captured, and the sentinel matched; independent quiescence remains unestablished.
Across 215 five-second samples, minimum observed guest available memory was 3,775,909,888
bytes and the last OOM-kill counters were zero. A candidate-sender HotSpot fatal file still
recorded `SIGILL` in C1-compiled JDK `SHA5.lf_delta1`; the successful final invocation does
not explain that intermittent crash. The stopped private six-case record, exchange audits,
fatal diagnostic and same-attempt QCOW2 backing pair were copied locally and passed a
recursive checksum dry run. This is partial installed case coverage, not a protected release
or a 45-case acceptance result.

The next prospective positive path addresses `restart-durable-state`. Attempt-39 current
and prior sender stop receipts show different systemd cgroup identities across the real
restart. The old v8 pure verifier incorrectly required their digests to be equal, so it
could not accept the observed installed profile. The corrected rule requires stable
installed UID/GID, boot and role network namespace, and changed manager invocation, Java
start epoch and cgroup identity. Controller `observe` now hashes only the fixed synthetic
32-byte sender state sentinel, returns its actual deadline and sample time, and never
returns the sentinel bytes. The observer brackets its genuine stop/start transition with
before/after controller-kernel principal snapshots. The host will compare those values to
the independently captured current and archived prior stop receipts, terminal campaign
deadline and final sentinel hash before submitting a restart witness to v8. Missing or
mismatched evidence remains inconclusive. Focused Linux contract/controller/adapter tests
passed at that preparation cutoff; attempt 40 below supplies the installed result.

Attempt 40 bound helper source `ef225e727b12cbdf5ca86a0207b4f498860603d9` to the
unchanged Linux product and passed strict fixture and no-VM admission. Its four installed
roles, two normally signed Mail workers, and both byte-checked CHK transfers around sender
restart completed; the guest exited zero and the emulator stopped. The host matched actual
before/after controller-kernel principal and fixed state-sentinel digests to the archived
old and current sender stop receipts, unchanged campaign deadline and final root sentinel.
The v8 verifier returned `recordContractValid=true` and `restart-durable-state` `passed`,
bringing the installed positive total to seven. Only `fnp-content-retrieval` remains
`inconclusive` among positives. All 26 denial and 11 lifecycle cases remain
`not-executed`, so the 45-case acceptance verdict remains false.

The caller reported cleanup complete; all current receipts and the sender's archived prior
receipt were captured, and the sentinel matched. Independent quiescence is still not
established by the fixed-file snapshot. No JVM fatal file was captured during this attempt;
183 five-second samples observed at least 3,818,409,984 bytes of guest available memory
and zero last-sampled OOM kills. The stopped seven-case record, diagnostics and same-attempt
QCOW2 backing pair were copied to local private retention and passed a recursive checksum
dry run. This one clean run does not resolve prior intermittent HotSpot C1 crashes or
constitute a complete denial/lifecycle campaign.

The next prospective `fnp-content-retrieval` emitter keeps the same DROP policy and
four-role star topology, adding only six fixed named counters to the switch's already
approved FNP UDP rules. A new closed `observe-fnp` controller operation accepts only the
current recipient handle and durably brackets one content transfer with root-owned
before/after six-link counter snapshots. It cannot select a namespace, port, packet filter,
PID, executable or arbitrary operation. The observer's second public synthetic CHK payload
is derived from the pinned helper commit and a fresh operation ID, then byte-checked locally
at the sender and remotely at the recipient with `IgnoreDS=true`. After cleanup the host
will independently parse the fixed recipient FCP transcript tail, recompute the selected
payload and compare exact request/response digests, current recipient invocation, unchanged
ruleset/namespace identity and positive packet/byte deltas on all four directional links
needed for recipient-to-sender request and reverse data transfer. Only then can it compute
an independent v8 commitment. The current seven installed case records remain separate;
the eighth positive case has no installed witness yet. This is a separately identifiable
network-observer revision within the prospective workload profile, not a claim that prior
attempts had counter evidence.

Attempt 41 bound helper source `b33995343ab712bb76f650788468ca5bf089fe0f` to the
unchanged Linux product and passed fixture and no-VM admission. The guest exited zero after
four-role readiness, two normally signed Mail workers, sender restart and two byte-checked
cross-node CHK transfers. The stopped host runner again verified seven individual positive
v8 records; `fnp-content-retrieval` stayed `inconclusive` because the root-owned counter-pair
file was absent. All denial and lifecycle rows stayed `not-executed`. The caller reported
cleanup complete, four current stop receipts were captured, and independent quiescence was
not established. The complete stopped attempt and same-attempt QCOW2 backing pair were
retained locally and passed a recursive checksum comparison.

Attempt 42 repeated the same helper, product, fixture and VM profile after a fresh no-VM
admission. The bridge namespace contained all six named counters, and a read-only `nft -j`
query observed permitted FNP packet traffic on all six links. A separate read-only call to
the installed fixed counter reader reproduced the missing-pair cause: it queried the
namespace name `cryptad-role-switch` as a bridge table, while the installed rules define
the table `cryptad_switch`. The guest's positive sequence also failed after a recipient
JVM `SIGILL` in C1-compiled JDK code. Its report therefore provided no valid positive case
record; the result must not inherit attempt 41's seven passes. The caller reported cleanup
complete, four current stop receipts were captured, the emulator stopped, and the full
private attempt was copied locally with a recursive checksum match. The current source
correction uses a distinct fixed bridge-table constant in the reader and validates the
real table name independently in the offline test. It still needs installed rerun before
the eighth positive case can pass. Neither this diagnosis nor the read-only query explains
the intermittent JVM crashes.

Attempt 43 bound the corrected reader helper to the same product, prepared reference and
normally signed Mail fixture. Its no-VM admission passed, and a separate read-only call to
the installed fixed reader returned `pr315-fixed-fnp-counters` from the real bridge table.
The sender then crashed during startup with `SIGSEGV` in a C1-compiled Bouncy Castle method.
The guest reported a failed positive sequence and cleanup, four current stop receipts were
captured, and no individual positive case was established in this attempt. The emulator
stopped and its complete private evidence, including the same-attempt QCOW2 backing pair,
passed local recursive checksum comparison. The crash does not negate the isolated reader
diagnosis and does not establish the eighth case.

Attempt 44 reused the same exact helper, fixture, product and VM profile after fresh
task-wide storage and memory admission. Four roles and two signed Mail workers ran, both
byte-checked cross-node CHK transfers and the sender restart completed, and the guest exited
zero. Seven individual positive v8 cases passed again; `fnp-content-retrieval` remained
`inconclusive`. The observer supplied no `fnpCounterPair`, and the stopped host snapshot
reported its fixed root pair unavailable. No HotSpot fatal file was captured. The caller
reported cleanup complete and four current stop receipts were captured, but independent
quiescence remains unestablished. The stopped full attempt was retained locally and passed
recursive checksum comparison. Strings found by a read-only scan of its QCOW2 overlay
could also originate from the installed source and do not prove that a pair record existed.

The current diagnostic revision retains only a fixed stage, exception class, fixed error
code and bounded network failure class when the root `observe-fnp` method fails. The
administrator snapshots that private record only after reported cleanup. The observer
separately reports whether its fixed request failed or response binding failed. These
diagnostics cannot create a v8 case commitment or change a failing result. Native Linux
protected workload tests passed 164 with 21 skips, PR-315 restricted tests passed 92, and
the owning interop adapter tests passed 42 with eight skips. An installed run is still
required to locate the remaining failure and prove the eighth positive case.

Attempt 45 bound that diagnostic revision to the unchanged product and VM profile after
fresh no-VM admission. Four role services reached running state, but the positive sequence
failed and produced no individual passing case record. Its stopped root-private snapshot
captured an `observe-fnp` failure at `counter-read`, classified as
`NetworkBoundaryError` / `bounded_process_failed`; the fixed pair remained unavailable.
No HotSpot fatal file was captured. The caller reported cleanup complete, four current stop
receipts were retained, the emulator stopped, and the complete private attempt passed a
recursive local checksum comparison. The recorded class establishes that the fixed `nft`
command returned failure, but it lacks the command's stderr and cannot identify the kernel
or userspace reason. The next narrow diagnostic revision retains up to 512 bytes of stderr
only when the captured argv exactly matches the fixed counter-read command, inside the
root-private failure record. Other command stderr cannot enter this record, and the record
still cannot satisfy any v8 case. Native Linux protected workload tests passed 164 with 21
skips, and PR-315 restricted tests passed 92 after that schema extension. An installed
rerun remains required to identify and correct the command failure.

Attempt 46 bound the fixed-command stderr revision to the same pinned product, signed
fixture and VM profile after fresh no-VM admission. Four installed roles, two normally
signed Mail workers, both byte-checked CHK transfers and the sender restart completed;
the guest exited zero. Seven individual positive cases passed again, while
`fnp-content-retrieval` stayed `inconclusive`. The root-private controller diagnostic
captured `counter-read` / `bounded_process_failed` and nft netlink's `Operation not
permitted` response. The installed controller service's capability whitelist omits
`CAP_NET_ADMIN`; the administrator's read-only query succeeded against the same named
table. This establishes the permission mismatch for the failed counter read. One sender
HotSpot fatal file was also captured, so this run does not establish JVM stability.
The caller reported cleanup complete, four current stop receipts were captured, and the
emulator stopped. The complete attempt and its same-attempt QCOW2 backing pair were
copied locally and passed recursive checksum comparison; independent quiescence remains
unestablished by the snapshot.

The next prospective correction keeps the controller's existing capability whitelist.
The already trusted administrator test driver performs the two fixed counter reads through
an inherited per-attempt Unix seqpacket socket: the observer can request only `before`
then `after`, and the administrator binds each read to the current recipient manager,
campaign, cgroup and network namespace before durably saving the pair. The pair has a
distinct administrator-origin kind; the host rejects the older controller-origin kind,
requires both observer receipts and compares the selected CHK bytes, recipient FCP tail,
content time window, stable policy/namespace identity and four directional counter deltas.
The ineffective `observe-fnp` controller operation is removed. Offline native Linux
protected discovery passed 527 tests with 74 skips, restricted discovery passed 420
with one skip, and the owning interop adapter passed 42 with eight skips. These checks
do not establish an installed FNP case; a new exact-source fixture and full installed
rerun are required.

Attempts 47–49 used the same helper source `456d716fd22cd16c3efe5ed810a6534305408d64`,
the same signed fixture, product, JDK and `tcg-multi`/`qemu64` four-vCPU VM profile. Each
passed its own no-VM task-wide storage and memory admission. Attempts 47 and 48 did not
reach administrator counter sampling: sender readiness timed out after a JVM `SIGILL` in
C1-compiled JDK code in 47, and relay readiness timed out after a JVM `SIGSEGV` in a
different C1-compiled JDK method in 48. Both reported cleanup complete with four current
stop receipts and independently observed emulator stop, but neither yielded an individual
positive case. Their complete private evidence and same-attempt QCOW2 backing pairs were
copied locally and passed recursive checksum comparison. These crashes remain unexplained;
no QEMU, JDK, guest/host resource limit or deadline was changed for the next attempt.

Attempt 49 reached four-role readiness, started two normally signed Mail workers, completed
both byte-checked sender-to-recipient CHK transfers around the sender restart, and exited
zero. The administrator test driver durably captured the fixed six-link counter pair before
and after the second transfer. The observer's two responses matched that root pair; the
stopped host verifier matched recipient FCP bytes, selected payload, current invocation,
sample window, stable policy/namespace identity and positive packet/byte deltas on the
four directional links. All eight positive v8 rows, including `fnp-content-retrieval`,
returned `passed`. No HotSpot fatal file was captured in this attempt. The caller reported
cleanup complete, four current stop receipts and the sender's previous receipt were
retained, the emulator stopped, and the complete private attempt with its same-attempt
QCOW2 backing pair passed a recursive local checksum comparison. The fixed snapshot still
does not independently establish quiescence.

This is an installed eight-case positive result, not the complete 45-case workload
acceptance. The 26 denial and 11 lifecycle rows remain `not-executed`, and the suite
still reports `implementationCoverage=incomplete`,
`installedWorkloadAcceptanceSatisfied=false`, `finiteNativeAcceptance=false`,
`protectedExecutionEnabled=false` and `phaseComplete=false`. A read-only summary of locally
retained fatal snapshots through attempt 48 found 21 HotSpot fatal files across 17 attempts:
13 `SIGILL` and eight `SIGSEGV`, all reported in varying C1-compiled frames. This pattern
does not establish a QEMU or JDK root cause and is not a reason to relax a passing case.

The next prospective lifecycle revision exercises `cancellation` through the installed
administrator rather than relabeling the already quiescent positive cleanup. After the
observer captures its final four-role roster it leaves those exact roles running on a
successful positive sequence. The administrator separately verifies each active systemd
invocation, cgroup identity and populated state against that roster, records one fixed
cancellation trigger under the original campaign deadline, then executes the existing
fence, controller stop, role reconciliation and network teardown. It observes exact
stop receipts, inactive manager states and empty owned cgroups before producing a
terminal record. The host will accept this lifecycle case only when the independent
pretrigger record, retained terminal receipts, campaign deadline and stopped guest
agree; otherwise the case remains unexecuted or inconclusive without borrowing the
eight positive passes. Offline tests cover the active/terminal transition and reject
substituted receipts. Native Linux interop workload tests passed 43 with eight skips and
full restricted discovery passed 422 with one skip. Installed execution of this new
behavior is still required.

Attempts 50–52 bound helper source `a453d8046c69749ee109b43a9240d314b1d02f25` to
the unchanged signed Mail fixture, product, JDK and `tcg-multi`/`qemu64` four-vCPU profile.
Each passed its own no-VM task-wide storage and memory admission. Attempts 50 and 51 did
not reach an administrator cancellation trigger. Attempt 50 failed four-role readiness
after sender and predecessor JVM `SIGILL` crashes in different C1 methods; attempt 51
failed sender restart readiness after another C1 `SIGILL`. Both reported cleanup complete
with four current stop receipts and stopped emulators, but no case passed in either
attempt. Their complete private evidence and same-attempt QCOW2 backing pairs were
copied locally and passed recursive checksum comparisons.

Attempt 52 reached four-role readiness, started two normally signed Mail workers,
completed both byte-checked CHK transfers across the sender restart, and exited zero.
The observer left all four final invocations active after its positive observations.
The administrator independently matched their current manager and cgroup identities,
recorded a fixed cancellation intent before the original campaign deadline, fenced the
campaign and stopped the controller. Its terminal observation found no populated owned
cgroup or remaining descendant, and the host matched the resulting current stop receipts
and stopped guest to that pretrigger roster. The v8 verifier returned all eight positive
cases plus `cancellation` as individually `passed`. A sender HotSpot fatal file from an
earlier invocation was still captured; the passed cases bind only the later measured
invocation epochs and do not establish continuous JVM stability. The fixed-file volatile
snapshot itself still marks independent quiescence unestablished; the cancellation case
uses the separate administrator active/terminal observations and exact receipts. The
complete stopped attempt and same-attempt QCOW2 backing pair passed a recursive local
checksum comparison.

The suite remains `implementationCoverage=incomplete` and
`installedWorkloadAcceptanceSatisfied=false`: all 26 denial cases and ten other lifecycle
cases are still `not-executed`. A fresh read-only summary of locally retained fatal
snapshots through attempt 52 found 26 HotSpot fatal files across 20 attempts, 17
`SIGILL` and nine `SIGSEGV`, all reported at varying C1-compiled frames. That pattern
does not by itself establish the cause or permit changing a runtime profile to claim
the existing installed result.

The next prospective lifecycle revision adds a closed `controller-restart` scenario
selection to the same administrator test kit; the existing `cancellation` path remains
the default and a suite selects only one trigger. After a successful positive sequence
leaves four exact invocations running, the administrator records the current controller
invocation and role cgroups, issues one real `systemctl restart` for the installed
controller, then checks that the new controller invocation differs and its recovery
retains terminal role reconciliation. The host requires all four exact stop receipts,
`controller-reconciliation` stop reasons, empty cgroups, unchanged original campaign
deadline and stopped guest before emitting the v8 lifecycle case. Missing proof leaves
the case inconclusive, and no status is borrowed from attempt 52. Native Linux restricted
offline discovery passed 425 tests with one skip after this preparation; installed
execution remains required.

Attempt 53 selected the fixed `controller-restart` mode and passed exact-source fixture and
no-VM admission. Four roles and the administrator FNP pair reached the expected positive
path. The administrator observed a new controller InvocationID after the actual
`systemctl restart`, but final `reconcile()` rejected, so the guest exited nonzero and
the host correctly passed no case. The original stopped guest and same-attempt backing
pair were copied locally and passed recursive checksum comparison. Because cleanup was
not verified, the earlier volatile snapshot withheld role authority and stop records.

A separate task-owned forensic VM booted a byte-verified copy of the failed overlay,
leaving the original guest and backing disks untouched. The previous-boot systemd journal
showed all four roles stop and then receive new start jobs during the explicit controller
restart. Each original stop receipt matched its retained role identity, yet all four
authority records ended `reconciliation-required` after the attempted relaunch. This is
consistent with the documented [systemd `BindsTo=` restart propagation](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html).
The forensic VM was stopped; its reconstructable disk copy was removed after confirming
no retained QCOW depended on it. The bounded private unit journal and full original
failure evidence remain retained.

The corrected prospective trigger kills only the old controller main process, observes
all four `BindsTo` stops and exact stop receipts before issuing a fixed `systemctl start`
for the new controller. It still requires a changed controller InvocationID, original
campaign deadline, controller reconciliation stop reasons and terminally empty role
cgroups. A failed cleanup now captures only fixed root authority and partial stop-receipt
projections before shutdown; it does not read candidate state or claim quiescence.
Focused offline tests cover fixed kill/start commands, stopped-role preconditions,
administrator-origin trigger binding and root-only failed-cleanup capture. Full native
Linux restricted discovery passed 427 tests with one skip. This revised scenario remains
unexecuted in an installed VM.

Attempt 54 used that corrected exact-source helper, unchanged signed fixture, product,
JDK and `tcg-multi`/`qemu64` VM profile after fresh no-VM admission. Four roles reached
running state, but the observer failed sender restart readiness before the selected
controller-loss trigger. The guest exited nonzero; root cleanup was reported complete,
four current stop receipts and the stopped emulator were observed, and the FNP pair was
not available. Three captured HotSpot fatal files covered sender and recipient, with
`SIGILL`/`SIGSEGV` in different C1-compiled methods. No case passed in this attempt;
it cannot validate or refute the revised controller recovery. The complete stopped
attempt, including its same-attempt QCOW2 backing pair, was copied locally and passed a
recursive checksum comparison. Across all locally captured fatal snapshots through this
attempt there are 29 files in 21 attempts, 19 `SIGILL` and ten `SIGSEGV`, all reported
in C1-compiled frames; the count is incomplete where failed cleanup suppressed candidate
log capture. Repeating the same profile without an isolating JVM/QEMU diagnosis is not
a demonstrated fix. The revised lifecycle case still needs an installed rerun after
that separate diagnosis.

A separately identified JVM diagnostic used the pinned Temurin 25 from a stopped
successful guest and one byte-checked Java class that exercises SHA-512, regex, CRC,
reference queues and integer operations in four threads. Two fresh copies of the same
stopped guest overlay were booted sequentially with the pinned `qemu64`, four-vCPU QEMU
closure: one `tcg-multi`, one `tcg-single`. Each ran the fixed class for 120 seconds
with C1 tier selection and exited zero without a new HotSpot fatal file. The test class
and bounded results are retained privately; the disposable guest copies were removed
after stopping each emulator and checking that no retained QCOW depended on either.
These negative results do not reproduce or explain the intermittent installed C1
crashes and do not authorize pooling the `tcg-single` diagnostic with the installed
`tcg-multi` acceptance profile.

The next prospective denial cohort adds an exact-source signed `pr315-probe` app beside
Mail only in candidate-sender. Its reviewed worker runs through normal AppHost
installation and required bubblewrap, records only fixed process/namespace metadata,
attempts one bounded mount-namespace `unshare` syscall, and remains alive for controller
kernel observation. Fixture schema 4 binds its signed ZIP digest to the three exact
tracked source files; the ordinary app signature verifier accepts both Mail and probe
under a private two-key public registry. The production export excludes the probe source
tree as a test seam. After reported cleanup, the administrator's safe descriptor reader
projects only the fixed bounded app result and classifies it as candidate-origin,
not acceptance. A host-side active-target, signed child and kernel denial witness is
still needed before `namespace-mount-escape` or any other app-origin denial can pass.
The private staged and packed probe verified with `crypta-app validate --strict`,
`compat verify`, `sign`, `verify` and extracted-ZIP `verify`. Native Linux protected
discovery passed 527 tests with 74 skips, restricted discovery passed 430 with one
skip, and the owning interop workload tests passed 44 with eight skips. Installed
probe launch remains unexecuted at this preparation cutoff.

Attempts 55 and 56 used the same schema-4 helper source, distinct signed probe ZIP and
two-key trust registry, unchanged candidate product/JDK and original VM profile after
separate no-VM admissions. Attempt 55 stopped at sender readiness after another C1
`SIGILL`; the probe was not launched, cleanup was reported complete, and no case passed.
Attempt 56 reached four-role readiness and normally installed/started the signed probe
through AppHost. Its fixed candidate-origin file reported a real `unshare(CLONE_NEWNS)`
return of `-1`/`EPERM` with four namespace inode fields, and the safe root reader captured
that bounded result after cleanup. The observer then failed at sender restart because
its retained-app check still expected the exact inventory `['mail-prototype']`, while
this cohort correctly contained `['mail-prototype', 'pr315-probe']`. The guest exited
nonzero, so the host passed no positive, denial or lifecycle row; one predecessor JVM
fatal file was also captured. Both stopped attempts, including same-attempt QCOW2 backing
pairs, were copied locally and passed recursive checksum comparisons.

The narrow follow-up binds the restart inventory to the already admitted fixed app list,
restarts and reobserves the probe worker if AppHost did not keep it running, and has the
signed worker atomically replace its fixed bounded result after a new launch. This
preserves the Mail positive case and prevents a stale pre-restart probe file from being
used as a new child observation. No `namespace-mount-escape` case is emitted until a
host-side witness independently binds the current signed probe process, active outer
role target, syscall window and kernel denial. An exact-source signed ZIP and installed
rerun are still required.

Attempt 57 used a newly signed, source-matched probe ZIP with the same product/JDK and
VM profile after fresh no-VM admission. Four roles reached readiness and the signed
probe wrote its fixed `unshare-mount` `EPERM` result inside the real sender AppHost
boundary. During sender restart the two-app inventory check passed, but the probe's
current runtime was not running and its normal `POST /start` returned a non-success
status. The observer rejected the sequence as `workload-restart-probe-start-failed`;
the guest exited nonzero, cleanup was reported complete, four current stop receipts
were captured, and no case passed. No HotSpot fatal file was captured. The stopped
guest and same-attempt QCOW2 backing pair were copied locally with a recursive
checksum match.

A byte-verified forensic copy of this stopped disk was booted to look for the app
process log. It confirmed that the role's app install, data and run paths lived in
tmpfs and were absent after a reboot; the copy was stopped and removed after a
zero-dependent QCOW check, while the original failure disks remain retained. The
next narrow diagnostic revision preserves only a fixed HTTP status class from the
observer's failed `POST /start` and a bounded private AppHost process-log tail during
the original guest's post-cleanup, pre-shutdown snapshot. Neither diagnostic is an
acceptance witness. The app-origin denial rows remain `not-executed` until the actual
current signed child, active target and denied operation are independently bound.
Native Linux interop workload tests passed 45 with eight skips; full restricted
discovery passed 432 with one skip, including a real local process test that launched
the signed probe worker twice against one app data directory and verified atomic
replacement without emitting its token. The next installed run must identify the
bounded restart HTTP result and retain the ephemeral process-log tail before shutdown.

Attempt 58 used that bounded-diagnostic helper and the exact schema-4 signed probe cohort.
The recipient JVM crashed in C1 (`SIGSEGV` while compiling `ZipUtils.get16`) before
the signed probe could start. Recipient readiness expired; no positive, denial or
lifecycle case passed. The guest stopped after reported cleanup, and the full private
attempt was copied and checked locally. Repeating the same JVM profile without a
demonstrated correction would not establish the missing case, so this failure does not
justify changing QEMU, JDK, timeouts or workload limits.

The next implementation revision retains an immutable first AppHost probe result across
sender restart, and adds one closed administrator request while the first signed child
is still running. The root sampler verifies the installed probe tree against the
preparation's trusted tree, samples the current sender cgroup and process namespaces,
checks the sender role's durable-state digest before and after, and binds the fixed
candidate-origin `unshare` result to that live child. The observer durably checkpoints
the initial four-role target roster, controller process sample and matching root record
digest before later CHK or restart failures. After cleanup, the fixed descriptor reader
retains the three bounded records. The host's `namespace-mount-escape` builder checks
their exact identities, namespace inodes, syscall result, temporal order, signed fixture,
host transport and matching stop receipt before admitting the single denial contract row.
This path has passed offline tests only; it has no installed result yet and cannot set
the 45-case acceptance verdict. A malicious same-UID candidate could still try to alter
its app data result; stronger independent syscall witnessing remains necessary before
claiming adversarial resistance beyond the fixed signed source profile.

Attempt 59 used the newly signed probe bundle, schema-4 fixture bound to helper
`ae80895f1d674b90e8c253d363dc5d789cde4862`, unchanged candidate and predecessor
products, pinned JDK, and the original `tcg-multi/qemu64` four-vCPU VM. A fresh no-VM
preflight passed with 143,314,124,800 task-allocated bytes, a 29,217,091,904-byte
next reservation, and 131,563,782,144 bytes free on the task ZFS dataset. The PVE
thin-pool reserve and host-memory reserve also passed; no QEMU was active before
allocation. The guest booted and reached SSH, but the sender JVM later recorded one
`SIGSEGV` in C1-compiled `java.lang.Math.max(II)I` at compiled entry offset +2.
The observer expired waiting for sender readiness. Cleanup completed, the sender's
stop receipt was captured while the three unlaunched roles had no stop receipt,
and the guest stopped with exit code 1. The signed probe did not launch; the
root process record, observer checkpoint and first AppHost result were unavailable.
Thus no case passed in this attempt and
`namespace-mount-escape` remains `not-executed`. The stopped guest and backing QCOW,
plus the complete private attempt, were copied to the ignored local task directory;
recursive checksum comparison reported no differences. Original stopped disks and
private diagnostics remain retained on CT102. This is another C1 fatal in the pinned
profile, but it does not establish a QEMU or JDK root cause or justify relabeling
the profile. Further identical VM attempts are deferred pending a demonstrated fix
or a separately identified diagnostic profile.

Across the locally retained bounded fatal excerpts through attempt 59, 33 HotSpot
fatal files appear in 25 attempts: 20 `SIGILL` and 13 `SIGSEGV`. Every excerpt names a
C1-compiled Java frame. Of the 31 excerpts whose compiled-entry offset could be
parsed, 22 place the fault within eight bytes of that entry. This is a pattern in
the captured crashes, not a proof that TCG, HotSpot or a particular patch caused it.

An offline review after attempt 59 identified a separate future probe ambiguity:
Mail and the signed probe can each have inner PID 2 in distinct AppHost namespaces.
The administrator now matches the fixed probe's kernel PID and mount namespace inodes
as well as its inner PID, and reports probe-sampling failures separately from FNP
counter failures. A Linux regression with a same-PID Mail decoy passes. This source
revision has not been rerun in an installed guest.

The corrected helper `64fd1864519fa77cee8cdca58cbd1886422ad7c1` has a new
exact-source schema-4 private fixture using the same signed probe ZIP and pinned
product/JDK identities. Its manifest digest is retained privately. A no-VM runner
preflight returned the expected unexecuted exit 78 with no admission reasons:
147,688,783,872 task-allocated bytes, 29,217,608,075 bytes reserved for the next
attempt and 10,582,802,432 bytes of effective host memory. No guest was allocated
from this preflight. The repeated C1 startup failure is still unresolved.

A subsequent offline `observer-control` denial emitter uses the installed controller's
real peer-credential-checked Unix socket. In the schema-4 cohort, the observer sends
one fixed readiness byte; the root controller verifies its active systemd invocation
and cgroup, then returns a fixed readiness byte. Only then does the observer send a
single forbidden method with its already retained sender handle. The controller
returns its actual fixed denial, checks the same peer and target process epochs plus
the sender's active cgroup and durable-state digest, and writes a root-owned audit
containing only the fixed actor/target identities, times and request/response hashes.
The observer durably retains its pre-app four-role roster and matching transcript
hashes without storing the handle. After cleanup the safe reader captures both
fixed records; the host validates source/transport identity, the actual denied
response, causal order, matching stop receipt and unchanged sender state before
admitting this one denial row. A real Linux socketpair regression checks the
readiness barrier, including that the forbidden request follows it; malformed
requests and wrong peers still fail closed. Native Linux protected discovery passed
530 tests with 74 skips, restricted discovery passed 437 with one skip, and the
owning interop tests passed 48 with eight skips. These are offline checks only;
`observer-control` remains `not-executed` in installed evidence, and no positive
or complete acceptance verdict changes.

Attempt 60 used that source-bound signed schema-4 cohort, the unchanged candidate,
predecessor and JDK, and the original `tcg-multi/qemu64` profile after a new no-VM
admission. The root controller's fixed readiness/denial exchange and observer
checkpoint were both captured. Host transport verification, actual peer/target
process epochs, sender state, denial response and matching stop receipt passed the
single `observer-control` v8 contract row. Its private assessment has
`recordContractValid=true`, `observer-control=passed` and overall acceptance false.
The guest stopped with exit code 1 after reported cleanup, and all four current
role stop receipts plus the sender's prior receipt were captured. There was no
HotSpot fatal file in this attempt. The complete stopped attempt, including its
guest and backing QCOW, was copied to the ignored local task directory; recursive
checksum comparison found no difference and CT102 retains its originals.

The same attempt normally launched the signed probe: the first AppHost result
reported the fixed `unshare(CLONE_NEWNS)` `EPERM`, and the root administrator
independently captured its Python process and installed signed tree. The observer
had instead recorded the AppHost API PID, which in this installed launch was the
sandbox's inner PID 1; the actual Python child was inner PID 2 and its direct
descendant. The host correctly refused to equate these two process records, so
`namespace-mount-escape` remains `not-executed`. The follow-up binds the API PID
to the sandbox leader, then binds its unique same-namespace Python child using
the kernel parent PID and executable digest; the administrator retains the
leader alongside the child for independent host cross-checks. A hypothetical
in-memory projection of attempt 60 showed no second host-side mismatch, but it
is diagnostic only and did not alter the installed verdict.

After sender restart, the probe's normal `POST /start` returned HTTP 403. Source
inspection shows the Platform API bridge requires the current `formPassword` for
that mutating route and returns 403 for an invalid one. The observer refreshed
the Mail handle's host bootstrap password for the new sender epoch but kept the
probe handle's old copied password. The narrow fix copies the newly validated
password into the probe handle before its restart request; a focused regression
fails when the old password remains and passes with the epoch refresh. This
explains the observed status from the installed caller and bridge, but has not
yet been confirmed by another installed run. It does not change product code,
guest limits, timeout, QEMU profile or JDK.

Attempt 61 used the exact-source fixture for that narrow fix under the unchanged
`tcg-multi/qemu64` profile. The guest reached the signed probe and both independent
denial paths; host-verified `observer-control` and `namespace-mount-escape` each
passed their own v8 record contract, with real controller response, root process
and signed AppHost child binding, fixed `unshare` `EPERM`, active target and matching
stop receipt. Sender restart then expired before daemon readiness after a C1 `SIGILL`
in `LongArray.reduceInPlace` at compiled-entry offset +5. The guest exited 1,
reported cleanup complete, retained four stop receipts and did not pass the
positive aggregate or lifecycle row. Its complete stopped private attempt and
same-attempt QCOW pair were copied locally and compared recursively without
differences; CT102 originals remain. The refreshed host credential got past the
previous HTTP 403, but a C1 fatal again blocked positive completion. Neither
denial pass establishes general JVM stability.

Attempt 62 selected `controller-restart` using the *same* helper, signed fixture,
product/JDK and VM profile after a fresh no-VM capacity admission. It exited 0,
reported cleanup complete and stopped the guest. The nine-case positive/lifecycle
private assessment passed all eight positive v8 rows plus the real administrator
`controller-restart` trigger, new controller invocation, four role stop receipts
and zero remaining descendants. Separate host assessments for
`observer-control` and `namespace-mount-escape` each had `recordContractValid=true`
and a passed denial row. Thus this one source-bound installed attempt has 11
individual passes out of the fixed 45. Its public verdict still correctly keeps
`installedWorkloadAcceptanceSatisfied=false`, `finiteNativeAcceptance=false`,
`protectedExecutionEnabled=false` and `phaseComplete=false`. Two sender C1
`SIGSEGV` fatal files were captured during this guest run, in `StrictMath.ceil`
and `StringLatin1.lastIndexOf`; the final bound process epochs and terminal
receipts passed, but the fatal files mean startup reliability remains unresolved.
Complete private evidence and stopped guest/backing QCOW were copied locally and
passed recursive checksum comparison with CT102; the originals remain retained.
Across bounded fatal excerpts through attempt 62, 36 files in 27 attempts show
21 `SIGILL` and 15 `SIGSEGV`, all naming C1 frames; 25 of 34 parsed compiled-entry
offsets are within eight bytes. This still does not identify a QEMU or JDK root cause.

Attempt 63 deliberately reused the clean detached `fc691e7` helper and exact fixture
for `cancellation`, preserving attempt 62's source identity without rewriting the
active branch. It passed the two installed denial rows again but stopped before the
administrator cancellation trigger. The sender's first local-only CHK insert got
`PutFetchable` and `PutSuccessful` without `URI`, and no `URIGenerated` frame appeared
in the retained FCP tail. The observer correctly refused to invent a CHK reference;
the guest exited 1 after reported cleanup, and `cancellation` stayed
`not-executed`. One relay C1 `SIGSEGV` in `StrictMath.ceil` was also captured.
The stopped attempt and its guest/backing QCOW were copied locally and matched the
CT102 original by recursive checksum; both copies remain private.

Source inspection found a finite single-block insert ordering race: the transient
`SingleBlockInserter` queues `onEncode` on the main executor, then can deliver
terminal `onSuccess` on the current path before the queued URI callback runs.
A regression with a deliberately delayed executor failed on the old code with
only `onSuccess` observed, matching the missing-URI FCP shape. The narrow product
fix delivers the final key synchronously before terminal success for
nonpersistent inserts; persistent behavior and wire fields remain unchanged.
The same focused test passed after the fix. `SingleBlockInserter.java` produced
an empty SonarLint XML report, and the full Linux Gradle test run passed with
17,317 tests, zero failures/errors and ten skips across root and leaf JUnit XML.
This was initially an offline result; attempt 63 itself has no cancellation witness.

The fix was committed at `99cdda8f3731b68bf6409aa037ab586112de5ee3` and
built into a new candidate portable. Its packaged daemon identity check matched
that exact source commit. The first private tar had noncanonical member modes
and ownership and was rejected before any VM allocation. The repository's
portable archive normalizer corrected only archive metadata; the daemon jar
digest stayed `sha256:686079e31f004e097a9dc92a8f8ae17f6218b4b307cbe9b6ec3dc105770dfc89`.
The normalized archive was made owner-only, and a fresh schema-4 fixture with
the same historical predecessor, pinned JDK and normally signed Mail/probe
passed strict source, package and signature verification. No weakened archive
or unsigned bundle was admitted.

Attempt 64 used that new candidate under the original `tcg-multi/qemu64` profile
after inventory and a no-VM admission with no reasons. The full Java test
run had left an idle Gradle daemon and worker processes consuming CT102 memory;
the task-owned daemon was stopped normally, and effective available memory
returned above the unchanged VM plus host reserve before allocation. The guest
reached four-role connection setup, then an FCP connection closed during peer
waiting. The recipient and relay each had one C1 `SIGSEGV`, in
`CharacterData.of` and `Yarrow.getBytes` respectively. It stopped with exit 1
after reported cleanup; no case passed, and neither CHK nor `cancellation` was
executed on the new product. Its complete stopped guest/backing QCOW and private
diagnostics were copied locally and matched CT102 by recursive checksum; both
copies remain private. This attempt cannot confirm the URI fix in an installed
sequence. Across retained bounded fatal excerpts through attempt 64, 39 files
in 29 attempts show 21 `SIGILL` and 18 `SIGSEGV`, all naming C1 frames. The
intermittent C1 failure has no established QEMU/JDK root cause.

### Separate PVE KVM differential on the fixed candidate

The PVE host diagnostic used the same `99cdda8` source-built candidate, pinned
predecessor, JDK, signed fixture, `qemu64` CPU, four vCPUs, 5632-MiB guest and
byte-identical QEMU executable as attempt 64. Its only intended execution-profile
change was the accelerator: `kvm` on the isolated PVE host instead of the accepted
`tcg-multi` profile in CT102. QEMU used restricted user networking with a loopback-only
SSH forward. This profile is explicitly classified
`pve-kvm-differential-not-acceptance`; none of its observations can pass a v8 case
or replace the required TCG campaign.

The host retained the 224-GiB task allocation budget, 16-GiB filesystem reserve,
7-GiB guest/host memory budget and 1-GiB host-memory reserve. The task-private
admission adapter read host `MemAvailable` because the PVE root cgroup exposes no
`memory.current` or `memory.max`; it did not change those thresholds. Host-only
process adapters supplied a byte-identical task-local Git executable and SSH UID
lookup for the mapped CT user. The task-private QEMU library closure added resolved
libraries missing from the PVE host. Source and fixture verification passed after
these adapters; no PVE package, managed VM, CT configuration, LAN address or
persistent service was changed.

Diagnostic runs 01 and 02 failed before VM allocation at the boot-library snapshot
and source Git lookup respectively. Run 03 booted the KVM guest but timed out at SSH
readiness because the mapped UID had no host passwd entry. Run 04 reached the
installed positive driver and exited 1 after cleanup; guest stop and all four role
stop receipts were observed. Its first local CHK insert, sender-local byte control
and recipient cross-node byte fetch completed. After sender restart, the second
local insert and sender-local control also completed, but the recipient's second
`ClientGet` received no terminal response within its 120-second read. The private
observer records `TimeoutError` at `fetch_direct`, and the bounded FCP tails show
the two recipient `ClientGet` requests with a terminal `AllData` only for the first.
All four roles had zero new HotSpot fatal files in this one KVM guest. This narrows
the observed run-04 failure to the second cross-node fetch; it does not establish
whether KVM prevents the intermittent C1 failures seen under TCG.

The complete stopped run-04 guest, diagnostics and reference inputs were copied
into the ignored local private evidence directory and matched the CT102 originals
by recursive checksum. The task-private host plans, summaries, transports and
preflights were also retained locally. The original guest and backing QCOWs remain
retained on the task dataset. At that cutoff, no second KVM guest was allocated after the PVE host's
available memory fell below the unchanged next-run admission requirement. The
accepted-profile installed positive was still false at that cutoff; the full
45-case verdict remains false.

The installed observer previously started the second CHK immediately after the
sender's new daemon and AppHost epoch was established. It did not check whether
the restarted sender and relay had both returned to `CONNECTED`. The prospective
helper now waits for that existing link from both ends within the original
campaign deadline before sampling counters or issuing the second insert. It does
not add a peer, change the 120-second fetch timeout or treat peer status as
retrieval proof. Offline regressions confirm that an unconnected restarted peer
blocks the second CHK and that the check uses the current sender reference. No
installed run had exercised this helper revision at that cutoff. Later suites 66
and 68 completed the positive sequence with this check, while the run-04 timeout
remains unexplained. On CT102 Linux, the affected PR-314 driver, protected workload
and cross-version interop suites passed 71, 165 and 242 tests respectively; the
latter two retained 21 and eight root/environment skips. The same broader suites
were red on macOS because Linux `/proc`, peer-credential and cgroup semantics are
absent there and local loopback binds were sandboxed. The focused changed-file
interop suite passed 50 tests with nine skips on macOS.

A fresh schema-4 signed fixture was prepared and strictly verified on CT102 for
the new helper source while retaining the `99cdda8` product. A unique no-VM
preflight returned exit 78 with `prerequisites-present-not-executed` and no
reported reasons. Its task allocation plus next-attempt reservation was below
the 224-GiB task budget, and CT102 reported enough effective memory. A separate
PVE host `/proc/meminfo` read showed less than the same guest/host memory
requirement at that point. CT102's virtualized memory report is therefore not
sufficient physical-host admission for another guest; none was allocated. An
earlier preflight command reused an existing output directory and returned exit
2 without changing that retained directory. The unique run established the
actual source and capacity result, without executing any v8 case.

### Swap-authorized PVE KVM run 05

The operator then authorized another isolated PVE diagnostic using available swap
when physical `MemAvailable` fell below the original admission threshold. The
task-private run-05 guard retained the 5632-MiB guest, four vCPUs, pinned QEMU,
JDK, `qemu64` CPU, product `99cdda8`, 224-GiB task budget and 16-GiB filesystem
reserve. It separately measured physical memory, free swap and pressure, required
the 1-GiB physical host reserve plus 2 GiB spare swap, and never counted swap as
physical `MemAvailable`. This is a distinct
`pve-kvm-swap-authorized-differential-not-acceptance` profile. Two no-VM
preflights passed before guest allocation. A task-only pressure watcher initially
missed QEMU because the pinned executable ran through its private dynamic loader;
a corrected exact loader/executable/attempt matcher was started during boot and
observed the guest. Neither watcher terminated it. Across the sampled run, the
minimum physical available memory was about 2.19 GB, the minimum free swap about
10.96 GB, and the maximum ten-second full memory-pressure average 5.43 percent.
The original matcher gap is retained in private diagnostics.

Run 05 used the clean `31dae88` helper and freshly verified schema-4 fixture. It
reached the installed positive driver. The first CHK transfer and the new
post-restart two-sided peer check completed. The second local-only `ClientPut`
returned `PutFetchable` and `PutSuccessful` without a URI, and the observer
correctly refused to invent one. The sender wrapper recorded a missing generated
URI at `ClientPutBase.onSuccess`; four roles had no new HotSpot fatal file. The
guest exited 1, stopped, and retained four role stop receipts. The full stopped
guest and private diagnostics were copied locally and passed recursive checksum
comparison with CT102; host plans, preflights and pressure samples were copied
separately. This KVM run passes no v8 case and does not prove that swap makes the
original TCG profile reliable.

The candidate product's `SingleBlockInserter` bytecode was checked and contains
the earlier synchronous final-key callback fix. Separate pinned-product CT102
diagnostics completed 40 single-node and 30 three-node local CHK inserts across
sender restarts with a URI every time. Those negative reproductions do not explain
run 05. Source inspection found another concrete callback-ordering gap:
`MultiPutCompletionCallback` could complete a transient group without forwarding
the already-known key of its URI-generating `SingleBlockInserter`. A deterministic
regression failed on the old code with group success and no URI callback. The
prospective narrow change asks that generator for its latched key before group
success only when the transient group has not already received it; duplicate and
persistent policies remain unchanged. Focused aggregation and single-block tests
pass after the change. The subsequent full CT102 Linux `./gradlew test` passed
17,411 tests across root and leaf XML, with zero failures/errors and 15 skips.
The touched Java files had no compiler warning, and focused SonarLint reported
zero findings for the production file. The change cannot retroactively establish
the cause of run 05; the rebuilt candidate's installed observations appear below.

### Rebuilt product and latest-source installed attempts

The aggregator change was committed at `db2534044e9c5a4b12a7742e16a4ad42884fec7e`.
The resulting source-built portable was normalized and its packaged daemon
identity matched that commit. A new schema-4 fixture with the same pinned
predecessor, JDK and normally signed Mail/probe inputs passed strict verification.
The PVE private source clone initially retained the old `build/cryptad-dist`
copy: KVM run 06 stopped at `product-source-verification` before VM allocation.
The clone's product tree was replaced with the exact new build and host-side
product-source verification passed. Run 06 remains a retained setup failure.

KVM run 07 then completed the positive driver on the new source and product:
guest exit 0, four current stop receipts, no new JVM fatal files and a true
host-side positive-shape check. Its exact-task pressure monitor recorded no
termination action; minimum host physical available memory was about 4.16 GB
and minimum free swap about 8.08 GB. This remains the separate
`pve-kvm-swap-authorized-differential-not-acceptance` profile. Its stopped guest
and private evidence were copied locally and matched CT102 by recursive checksum.

The original CT102 `tcg-multi/qemu64` suite 65 used the same exact source,
product, fixture and deadlines. Its candidate-sender wrapper timed out waiting
for the JVM startup signal before the first daemon became ready. No HotSpot
fatal file was captured and no CHK ran. Guest exit 1 and stopped QEMU were
observed; only the sender's current stop receipt was captured. The PVE host
pressure monitor did not terminate QEMU. Its first watcher used the PVE mount
path and missed the CT-origin QEMU command path; a corrected watcher recognized
the exact process during the remaining run. The complete stopped failure was
copied locally and passed recursive checksum comparison. This single failure
does not establish whether CPU scheduling, JVM startup or wrapper timing was
causal.

Unchanged suite 66 passed the fixed TCG installed positive aggregate and eleven
individual v8 rows on one source-bound guest: all eight positives,
`observer-control`, `namespace-mount-escape` and a genuine administrator
`cancellation`. Its guest exited 0, four current stop receipts were captured,
and all four roles had zero new HotSpot fatal files. The corrected watcher saw
the exact QEMU from startup, took no termination action, and measured minimum
host physical available memory about 2.99 GB and free swap about 12.52 GB.
The complete stopped guest and evidence were copied locally and matched CT102
by recursive checksum. The assessment still correctly reports
`installedWorkloadAcceptanceSatisfied=false`.

The separate `controller-restart` scenario failed in suite 67 before its
trigger: relay daemon readiness expired after two relay HotSpot fatal files,
`SIGILL` in a C1-compiled `SHA5.lf_ch` frame and `SIGSEGV` in a JVM
stack-trace frame. It exited 1 with four current stop receipts and no passed
case. The stopped guest and private evidence were copied and checksum-verified.
Unchanged suite 68 then passed the positive aggregate and eleven individual
rows on one guest, including genuine administrator `controller-restart` in
place of `cancellation`. It exited 0 with four current stop receipts, no new
HotSpot fatal files and no pressure-monitor termination. Its private stopped
guest and host observations were copied locally and checksum-verified.

Suites 66 and 68 have identical trusted host identities. Taken as two separate
source-bound observations, they cover twelve distinct v8 case IDs: the same
eight positive and two denial cases, plus the two different lifecycle cases.
The verifier rejects duplicate case declarations across combined raw attempts,
so these full positive attempts are not rewritten or pooled into a synthetic
12-case acceptance record. All 24 other denial and nine other lifecycle IDs
still lack a `db25340` installed pass; the complete 45-case verdict remains
false. The intermittent TCG JVM startup/fatal behavior remains unexplained,
and neither the KVM result nor the host's available swap changes the selected
TCG profile or its fixed timeouts.

### Prospective runner-origin controller denial

The next `runner-control` emitter uses the actual `vmadmin` runner UID rather
than the observer's `cryptad-soak` controller socket identity. After a completed
positive sequence leaves the installed roles active, the administrator measures
the running controller systemd unit and sender role, then launches only the
fixed `systemctl --no-ask-password stop cryptad-workload-controller.service`
request as `vmadmin`. A bounded 2-KiB, 15-second reader captures the child's
actual policy response; excess output or timeout reaps only that child and
cannot produce an acceptance row. The administrator checks the actor PID/UID
epoch, the unchanged controller invocation/cgroup/process epoch and unchanged
sender state, then retains a root-owned private audit. After exact cleanup,
the safe reader checks its closed schema and bounded denial response. The host
verifier binds that audit to the positive result's principal roster, fixed
request, actual denied response, sender stop receipt and retained sentinel
before it can mark `runner-control` passed. Failure leaves this row unexecuted
or inconclusive; a successful forbidden stop or changed controller/sender epoch
fails the guest attempt rather than preserving a positive result.

At the implementation cutoff this was prospective source work. On CT102 Linux, PR-314
discovery passed 73 tests, PR-315 workload discovery passed 104, protected
workload discovery passed 165 with 21 skips, and cross-version interop
discovery passed 242 with eight skips. Offline tests also reject a forged runner
UID, altered target invocation, modified response and oversized child output.
The installed outcome is recorded below; offline results alone granted no case.

The emitter was committed at `d8d66e718ef4569a90af1bff95993a8790754e8d`.
Its fresh schema-4 fixture reused the verified `db25340` product and pinned
predecessor/JDK/signed Mail/probe bytes while binding the new helper source.
Original TCG suite 69 failed before the probe: relay readiness timed out after
one `SIGSEGV` in a C1-compiled JDK method. It exited 1 with four current stop
receipts, no runner-control audit and no passed case. The complete stopped
failure and host pressure records were copied locally and passed recursive
checksum comparison. No product, JDK, QEMU, CPU or timeout was changed.

Unchanged suite 70 completed on the original `tcg-multi/qemu64` profile. Its
host assessment passed all eight positives, `observer-control`,
`namespace-mount-escape`, the genuine administrator `cancellation`, and the
new `runner-control` denial on one guest. The fixed `vmadmin` systemd command
returned a nonzero authorization rejection; the root audit captured that
process UID/epoch, the actual response digest, matching active controller
invocation/cgroup and unchanged sender state. The host verifier bound it to
the exact source/fixture and sender stop receipt. Guest exit was 0, all four
current stop receipts were captured and no role had a new HotSpot fatal file.
The exact-QEMU host monitor took no termination action; minimum physical
available memory was about 5.12 GB and minimum free swap about 9.80 GB.
The complete stopped guest and private evidence were copied locally and
matched CT102 byte-for-byte by recursive checksum. Its public status remains
`implementation-incomplete` with `installedWorkloadAcceptanceSatisfied=false`.

After verifying complete local copies, the task-owned stopped guest and
backing QCOW copies for successful suites 66 and 68 were removed only from
CT102. A read-only scan of 95 QCOWs found no other guest depending on those
backing files; exact ownership, single-link status and zero task QEMU were
checked before deletion. Their CT102 reports and v8 evidence and the full
local private guest copies remain. Failed attempt disks were retained. The
task-private disposal audit records the exact paths and post-cleanup state.

### Prospective TCG host admission and suite 72

`cec96db` adds the versioned PVE TCG swap-admission receipt, exact-QEMU pidfd
monitor, prospective 21-group v9 ledger and a fixed test-kit candidate-role
`observer-private-read` probe. The probe and ledger passed offline checks but
cannot grant installed acceptance. The schema-4 fixture was rebuilt from the
same distinct candidate/predecessor products, pinned JDK and normally signed
Mail/probe bundles, now measured with `workload-launcher-policy-v3`.

Suite 71 was a no-VM preflight: the 224-GiB task cap, 16-GiB filesystem reserve,
7-GiB guest/host budget and PVE host swap policy passed. Retained allocation was
205,253,509,120 bytes and the next reservation 29,117,951,453 bytes. The
separately pinned PVE receipt and monitor readiness were then verified from
CT102 before allocating suite 72. An isolated no-VM monitor handshake had
previously shown that a watcher which never sees QEMU cannot yield a passing
completion receipt.

Suite 72 ran the original `tcg-multi/qemu64`, four-vCPU, 5632-MiB guest with
the same pinned QEMU/JDK/product bytes and the new host admission policy. It
failed while the candidate recipient awaited its first FCP `GetNode`: the
observer retained `workload-daemon-readiness-timeout` caused by an operation
deadline. The sender and recipient services had started; predecessor and relay
had not. Guest exit was 1, the guest stopped, root cleanup completed, the
retention sentinel matched, and the launched roles had current stop receipts.
No role had a captured HotSpot fatal file. Five-second sampling recorded no
candidate-role cgroup OOM event; its sampling cannot prove continuous absence
of pressure. The PVE watcher followed one exact task QEMU and finished without
terminating it. The new candidate-role probe was not reached, so no new denial
or positive case passed. The full failed guest and new fixture passed recursive
checksum comparison after copying into the ignored local task directory; the
separate host-admission and pressure records matched by SHA-256. The original
failed disks remain on CT102.

The readiness failure has no established root cause. The next source revision
adds a bounded `VM.command_line` and `Thread.print -l` capture for the single
kernel-measured JVM in the latest active role, before cleanup on this exact
failure code. Its raw output is private and capped; the public verdict remains
incomplete. This diagnostic has offline tests and has not yet run in a guest.

The `f590849` revision carried that diagnostic. Its new schema-4 fixture was
verified and archived locally; suite 73 passed no-VM task and PVE admission.
Suite 74 reached the disposable guest but failed during base installation,
before the controller or any workload role started. The guest exited 1 and
stopped; its PVE monitor finished normally. The retained error chain is
`restricted-native-execution-failed` from `restricted-native-boundary-rejected`.
The readiness-specific jcmd branch therefore did not run and no new workload
case passed. The complete failed guest, fixture and PVE records were copied
locally and passed byte checks; original failed QCOWs remain on CT102.

To narrow that installation failure without another guess, a temporary raw
image was made from the stopped suite 74 QCOW/backing under a full 24-GiB
capacity reservation. PVE attached and mounted only that task image read-only,
without journal replay. The retained native stage showed two fixed `probe`
operations: the first completed; the second had a manager invocation but no
completion output and produced its fixed reconciliation failure about 1.16
seconds after stage creation. Both diagnostic stdout/stderr files were empty.
The guest's persistent journal reported the second native unit exiting with
status 1. This places the failure after service start, but does not distinguish
the launcher's cgroup-membership check from its fixed output-roster check.
The bounded local forensic summary remains private. The task-only mount and
loop device were detached; the temporary raw copy was removed and audited.
The original suite 74 failed QCOWs and their checked local copies remain.

The next prospective source writes a closed private reason and counts at
those two actual post-run rejection branches, then captures only that small
record in the guest installation failure evidence. It leaves the denial
decision and production control interface unchanged. Offline regressions
exercise the fixed marker and reject extra fields; no installed result on this
revision exists yet.

That post-run diagnostic reached a new exact-source run. The `918b81a` fixture
was prepared, verified and copied locally. Suite 75 passed no-VM admission;
suite 76 ran with the same pinned TCG/QEMU/JDK/product/guest limits and the
versioned PVE host swap policy. It exited 0 and its host verifier again passed
the eight positive cases, `runner-control`, `observer-control`,
`namespace-mount-escape` and `cancellation`. All four current stop receipts
and the sentinel were retained; the host watcher completed without an action.
The new `observer-private-read` probe did not pass: the administrator caught a
`ValueError` before writing its root audit. This is still 12/45, not an
incremental 13-case pass. The predecessor also produced one captured HotSpot
`SIGSEGV` fatal file despite the completed positive sequence; this run does
not establish continuous JVM stability. The complete stopped guest, fixture
and PVE records passed byte checks after local private copying.

A second task-only read-only inspection of the stopped suite 76 disk showed
that the measured role probe source, root-owned request and observer-owned
32-byte canary existed. The administrator success audit was absent. The role
tmpfs containing ready/result records does not persist in the stopped QCOW,
so the exact failed comparison cannot be recovered from that disk. The
forensic summary remains private; loop/mount and temporary raw were removed,
with original failure evidence retained. The next prospective change splits
the final actor, invocation, target, result and timeline comparisons into
fixed error codes, and retains only a closed denial errno when available.
No installed result on that revision exists yet.

The `3a4ef89` revision completed as suite 78 on the same accepted TCG/QEMU,
JDK, product and guest limits with the versioned PVE host admission. The guest
exited 0 and stopped; the host verifier accepted all eight positive cases,
`runner-control`, `observer-control`, `namespace-mount-escape`, `cancellation`
and, for the first time, the actual candidate-role `observer-private-read`.
The latter bound a root-observed role process UID/start epoch, unchanged active
observer canary, actual `ENOENT` from the fixed open and matching current stop
receipt. Its v9 private case record has a distinct attack commitment. The
administrator root audit, sentinel, four current stop receipts and independent
host-QEMU monitor completion were captured. No role had a captured HotSpot
fatal file in this attempt. Complete guest, fixture and PVE records passed
byte checks after local copying. This is **13/45** on one source-bound guest,
not complete workload acceptance.

The next prospective fixed test-kit role probe performs a bounded write
attempt on the same existing observer canary after the proved read attempt.
The administrator checks the canary is unchanged, the same actor/invocation
remains active, and both operations have ordered times. Read and write obtain
separate fixed root audits and v9 host records. This changes the measured
launcher policy to `workload-launcher-policy-v4`; v3 installed observations
cannot be pooled into its final campaign. The v4 implementation has offline
tests but no installed case result yet.

That v4 source completed as suite 81. The guest exited 0 and stopped; its
host assessment passed the original eight positives, `runner-control`,
`observer-control`, `namespace-mount-escape`, `cancellation` and both fixed
`observer-private-read` and `observer-private-write` denials. The bounded
write attempt did not change the observer-owned canary. Its root audit and
separate v9 case record bind the same measured candidate process/manager
epoch and active canary as the read, with a distinct attack commitment.
All four current stop receipts, the retention sentinel and the exact QEMU
watch completion were captured; no HotSpot fatal file was captured in this
attempt. The complete stopped guest, fixture and host records passed local
byte checks. This is **14/45** on one source-bound guest, not complete workload
acceptance. After ownership, open-descriptor, 95-QCOW backing and complete
local-copy checks, only the CT102 disk duplicates for suites 72 and 78 were
released to maintain the unchanged 224-GiB task budget. Suite 72 failed
original bytes and suite 78 successful original bytes remain in their full
checked local copies with private offload audits.

The next prospective v5 role child also emits fixed false host PID/UID and
zero resource-counter claims. The administrator compares them with the current
installed process observer and cgroup-v2 measurements, captures before/after
role invocation and actor epoch, and writes separate bounded root audits.
The host verifier can mark `forged-runtime-identity` and `forged-counters`
only from those source-bound installed records. This path passed offline
tests before the accepted-profile TCG result recorded below.

The `846418c` v5 source first received a no-VM suite 83 PVE admission
rejection: I/O full PSI `avg10` was 21.94 percent against the unchanged
10-percent preflight ceiling. Suite 84 then booted the accepted TCG profile
but failed candidate-sender's first FCP readiness after a captured HotSpot
`SIGSEGV` in C1-compiled `Unsafe.getShortUnaligned`. A fresh suite 85 no-VM
admission passed. Suite 86 reached all four roles, but the sender's new JVM
failed its post-restart FCP readiness with a captured HotSpot `SIGILL` in
C1-compiled `SecP256R1Field.reduce32`. Both guest failures stopped, root
cleanup and task-QEMU monitor completion were retained, and neither reached
the v5 false-claim probes. Their complete private guests and PVE records
passed local byte checks. After confirming exact ownership, zero task QEMU
and open descriptors, and a 93-QCOW zero-dependency backing scan, only the
CT102 disk duplicates for stopped failed suites 69 and 86 were released.
Full exact-byte failure guests remain in the ignored local task directory.
These distinct C1 fault locations do not identify a cause or change the TCG
acceptance verdict.

PVE KVM diagnostic 08 then used the same `846418c` helper, candidate and
predecessor products, signed apps, pinned QEMU/JDK, `qemu64`, four vCPUs and
5632-MiB guest; only the accelerator and separately identified host transport
were KVM. Its source-bound no-VM preflight initially hit the unchanged 224-GiB
task cap, then passed after the verified duplicate cleanup. The guest exited
0, stopped and retained all four current role stop receipts, the sentinel,
and fixed root audits for `observer-private-read`, `observer-private-write`,
`forged-runtime-identity` and `forged-counters`. It captured no HotSpot fatal
file. The task-only KVM QEMU pressure monitor finished without action. The
complete guest and seven separate host records passed local byte checks.
Its result remains **differential diagnostic only**: it grants no v8/v9 TCG
case and does not establish the cause of the intermittent TCG JVM failures.
The prospective installed acceptance runner now rejects a non-TCG accelerator
before any case allocation; the separate direct KVM diagnostic produces only
private shape and failure observations.

The next prospective v6 role child also attempts a recipient-owned tmpfs
canary read, a bounded write to the installed read-only daemon package, and
a fixed cgroup migration. The administrator checks the active recipient
role, package digest and original service cgroup before and after; the host
requires separate source-bound v9 proofs for `sibling-data`,
`package-expectation` and `cgroup-migration`. Offline tests pass; the
source-bound v6 TCG result is recorded below.

PVE KVM diagnostic 09 used clean `f589bf3`, a newly measured schema-4 v6
fixture and the same pinned product/JDK/QEMU, `qemu64`, four-vCPU and
5632-MiB guest identities as the earlier differential. After a no-VM
224-GiB capacity block, it passed the unchanged budget and swap-pressure
checks following byte-verified release of KVM08's stopped duplicate disks.
The KVM09 guest exited 0 and stopped, kept four current role stop receipts,
matched the sentinel, and captured root audits for the previous four role
probes plus the new `sibling-data`, `package-expectation` and
`cgroup-migration` operations. The three actual denial errno values were
`ENOENT`, `EACCES` and `ENOENT`, respectively; the attacker opened none of
the targets or wrote bytes. Recipient invocation/cgroup/canary controls and
candidate daemon jar bytes stayed fixed; the package digest matched the
candidate fixture. No HotSpot fatal file was captured. The task-only QEMU
watcher completed without intervention. Complete guest and seven host
records passed local byte checks. The stopped KVM09 disk duplicates were
subsequently released only after their full local copies, 91-QCOW backing
scan, ownership, QEMU and file-descriptor checks passed. This is still
**KVM-only differential evidence** and grants no TCG case ID or 45-case
acceptance result.

The `fdcfe740` source adds a pre-allocation guard rejecting any non-TCG
accelerator in the formal case runner. Its schema-4 v6 fixture retained the
same candidate, predecessor, signed apps, pinned QEMU/JDK and original
`tcg-multi/qemu64`, four-vCPU, 5632-MiB guest profile. A fresh no-VM suite 87
passed with the expected exit 78. Suite 88 received a PVE preflight denial
because I/O full PSI exceeded the unchanged 10-percent ceiling; it allocated
no VM. After pressure subsided, suite 89 passed a new host swap-admission and
pidfd-watcher handshake, then ran the fixed installed sequence. Its guest
exited 0 and stopped. Host validation accepted all eight positive IDs, ten
denials (`observer-private-read`, `observer-private-write`, `sibling-data`,
`runner-control`, `observer-control`, `package-expectation`,
`forged-runtime-identity`, `namespace-mount-escape`, `cgroup-migration`,
`forged-counters`) and `cancellation`: **19/45** on one source-bound TCG
attempt. Four current role stop receipts, a matching retention sentinel and
completed exact-task QEMU monitoring were retained. The complete private
suite passed a recursive byte comparison with its Mac archive; both QCOW2
hashes matched independently. After guest stop, zero task QEMU/open file
descriptors and a 91-QCOW backing scan found no external dependents, only
suite 89's two remote disk duplicates were released. The full original bytes,
failure history, fixture and offload plan/completion receipts remain private
on Mac. The runner correctly reports `implementation-incomplete` and
`installedWorkloadAcceptanceSatisfied=false`; another 16 denial and ten
lifecycle IDs lack a current-source installed pass. `controller-restart` from
an older source is historical evidence only.

The subsequent documentation-only `45d8b914` source received a fresh schema-4
fixture and a no-VM suite 90 preflight. Suite 91 then ran the same accepted
TCG, product, JDK, signed-app and host-admission profile with the existing
`controller-restart` scenario. Its guest exited 0 and stopped; all eight
positive cases and the same ten denials passed, followed by a current-source
`controller-restart` pass: **19/45** on this separate source-bound guest.
The root administrator killed the old controller main process, observed all
four bound roles stop before requesting the new controller start, and retained
distinct old/new systemd invocation IDs, four stop receipts, zero populated
cgroups and zero remaining descendants. The sentinel matched, and the PVE
pidfd watcher completed without intervention. Suite 91's full private guest,
fixture and four host records passed byte checks on Mac. After a 89-QCOW
zero-dependency backing scan, stop/ownership/open-descriptor checks and
independent matching hashes for both disks, only its remote disk duplicates
were released; the complete local originals and audit receipts remain.
Suite 89's `cancellation` and suite 91's `controller-restart` cannot be
combined into one 20-case campaign because their helper source identities
differ. The post-suite-91 v9 record change below is another source revision
and needs fresh installed evidence.

The next prospective v9 private case record carries the administrator's
already checked child host/namespace PIDs and start epoch, UID/GID, boot ID,
namespace identities, role cgroup and systemd invocation, plus the actual
operation window and bounded active-target context for the seven currently
emitted candidate-role denials. It also compares the PID namespace across
the before/after root observations. This does not add a passed case or
authorize accepting a candidate claim as trusted identity. On native Linux,
86 owning runner, campaign, volatile-evidence and role-probe tests passed.
The seven enriched records were reconstructed from suite 89's retained real
root audits without granting a new installed verdict. A broader macOS test
invocation failed in Linux-specific descriptor snapshot fixtures; its result
is not substituted for the native Linux check.

The `7203dc73` prospective v7 policy adds a closed observer request for
`arbitrary-endpoint`. The actual observer UID asks the installed controller
to select one fixed disallowed sibling-FCP endpoint; the controller first
confirms the recipient's active FCP listener with bounded `ClientHello` /
`NodeHello` exchanges, invokes the existing connector boundary and retains
an independent root denial audit. No observer-supplied port, path, PID or
arbitrary method reaches production dispatch. The private volatile capture
ceiling is versioned at 96 KiB and remains below the host's fixed 256-KiB
transfer cap. Offline native Linux checks passed 101 restricted tests, 67
protected tests with one skip, 51 owning interop tests with eight skips, and
70 adjacent guest/driver/host-policy tests. These are implementation checks,
not installed acceptance.

Suite 92 passed the no-VM preflight with the expected exit 78. Suite 93 then
reached four-role readiness and the existing observer-control audit, but the
new observer request stopped before attacking the connector:
`workload-arbitrary-endpoint-premise-missing`. Source inspection and retained
diagnostics established that `stateDigest` is deliberately populated only
for the sender's fixed retention sentinel; recipient observations return
`None`. The new probe had incorrectly required a recipient state digest.
The guest exited 1 and stopped, cleanup was reported complete, and the PVE
task-QEMU watcher completed. No positive or new denial row passed on that
attempt. Its complete failure guest and four PVE host records passed local
byte checks; after zero QEMU/open descriptors and an 89-QCOW dependency scan,
only its two remote duplicate disks were released. Complete original bytes
and offload receipts remain private on Mac.

The next narrow correction removes only the nonexistent recipient sentinel
premise. Recipient validity still requires its current invocation, cgroup,
boot ID, running state and real FCP `NodeHello` controls before and after the
fixed connector rejection. The sender's actual sentinel remains required.
Native Linux reruns passed 77 restricted, 67 protected (one skip) and 51
interop tests (eight skips). A fresh accepted-profile TCG result is required
before `arbitrary-endpoint` or any positive case can pass on this corrected
source.

The corrected `b9647beb` helper received a fresh source-bound fixture.
Suite 94 passed no-VM preflight. Suite 95 then reached sender, recipient and
previous readiness, but relay bootstrap exited after a HotSpot `SIGSEGV` in
C1-compiled `sun.security.provider.SHA5.lf_sigma1`. Its wrapper reported an
invalid bootstrap result. Suite 96 passed a new no-VM preflight; suite 97
again reached three roles before relay bootstrap exited after a separate
HotSpot `SIGSEGV` in C1-compiled
`java.util.ImmutableCollections$SetN$SetNIterator.next`. Both failures
preceded the observer endpoint request, so neither tests it. The guests
exited 1 and stopped; the test kit reported cleanup complete, all four stop
receipts and the sentinel were retained, and the exact-task PVE watchers
completed. Full HotSpot files were copied privately before tmpfs shutdown.
Each complete failed guest and four host records passed Mac byte checks.
Only their stopped remote disk duplicates were released after independent
hashes, zero QEMU/open descriptors and 87-QCOW backing scans; original
failure bytes and offload receipts remain private. No QEMU, JDK, memory,
timeout or pressure threshold was changed to obtain a pass.

An isolated PVE KVM differential then used the same `b9647beb` source,
candidate/predecessor products, signed apps, pinned JDK/QEMU, `qemu64`, four
vCPUs and 5632-MiB guest; only the accelerator and separately identified
host transport were KVM. Its no-VM preflight, task-wide storage reserve,
swap/PSI admission and exact-QEMU PIDFD watcher passed. The guest reached
the positive role sequence and fixed role-probe audits, then exited 1 while
publishing the private volatile snapshot. The bounded failure receipt was
`restricted-workload-record-limit`: the v7 evidence ceiling was 96 KiB, but
the generic controller authority writer still capped every record at 64 KiB.
The diagnostic wrapper's secondary attempt to parse the empty volatile file
also failed; it is not the guest failure cause. From the stopped guest's
QCOW2, a temporary sparse raw copy was mounted with
`ro,noload,nodev,nosuid,noexec`. The root audit and observer checkpoint for
`arbitrary-endpoint` were both retained and byte-checked on Mac: the root
record contains pre/post active recipient FCP `NodeHello` controls and an
actual `sibling-fcp` connector rejection. This is **KVM-only diagnostic
proof**, never a TCG case pass or complete terminal acceptance result.
The loop/mount and reconstructed raw were removed after audit, and the
stopped remote QCOW duplicates were released after an 85-QCOW dependency
scan; full original guest and private forensic records remain on Mac.

The next narrow fix leaves the generic 64-KiB authority record limit and
control socket unchanged. Only the fixed root-owned PR-315 volatile file
uses a separate 96-KiB atomic, exclusive and fsynced private writer, still
below the host's existing 256-KiB transfer cap. Native Linux PR-314/315
driver, volatile-evidence, runner and fixture checks passed 142 tests,
including a new over-64-KiB exclusive-write regression. This corrected
source requires a fresh TCG run; the KVM differential does not grant an
installed workload verdict.

The `1a714f9d` source received a fresh fixture and passed no-VM suite 98.
Suite 99 started sender and recipient, but the recipient wrapper reported
14 seconds without CPU time and its first JVM timed out waiting for a startup signal; its
second JVM reached FProxy startup before the original FCP readiness deadline
expired. No HotSpot fatal file was captured. The guest exited 1 and stopped,
the new private volatile writer retained a 22.5-KiB record, cleanup and
four stop receipts completed, the sentinel matched, and the task-QEMU watcher
completed. Full failed guest and host records passed Mac byte checks; only
the stopped remote disk duplicates were released after an 85-QCOW
zero-dependency scan. Suite 100 passed a new no-VM preflight. Suite 101 was
rejected by PVE PSI admission before VM allocation and retains its separate
no-VM admission receipt.

After PSI recovered, suite 102 passed a fresh host admission and PIDFD
watcher handshake on the original `tcg-multi/qemu64`, four-vCPU,
5632-MiB guest with the same pinned candidate, predecessor, JDK, QEMU and
signed apps. The guest exited 0 and stopped. The host verifier accepted all
eight positive IDs, the ten previously proven denials plus the new
`arbitrary-endpoint`, and `cancellation`: **20/45**. The observer checkpoint
and independent root audit bind the same actor PID/start epoch, fixed request
and denial response; root captured real recipient `NodeHello` controls before
and after the disallowed connector call. Both records also match the
live-captured private copies and the v8/v9 host case files. The new writer
published 92,587 bytes of private volatile evidence under its 96-KiB cap.
Four current role stop receipts, a matching sentinel and completed exact
PVE watcher were retained; no HotSpot fatal was captured. The complete guest
and four host records passed Mac byte checks. Only suite 102's stopped remote
disk duplicates were released after independent hashes, zero task QEMU/open
descriptors and an 85-QCOW backing scan. Full original bytes and offload
receipts remain private. `implementationCoverage` is still incomplete and
`installedWorkloadAcceptanceSatisfied=false`; 15 denial and ten lifecycle
IDs lack a passing installed result on this helper. Historical
`controller-restart` belongs to another source and cannot be pooled with
suite 102.

The next prospective v8 policy adds two real candidate-origin network
denials, `sibling-fcp` and `sibling-http`. The installed sender role gains
only a fixed route to the recipient for observing its own filter; its inet
output and the switch bridge retain DROP policies, with no direct sibling
accept rule. Two named nft counters match only the fixed recipient address
and FCP/HTTP ports. The role child emits one bounded TCP attempt per
administrator trigger; root checks the actual role child and invocation,
the recipient's live FCP `NodeHello` or bounded HTTP HEAD before and after,
the exact counter delta for that case, and the other counter's unchanged
value. The host verifier additionally binds the root audit to current
sender/recipient stop receipts and the fixed v8/v9 case contracts. A
timeout or an unlistening target alone cannot pass. This revision raises
only the fixed private volatile snapshot limit to 128 KiB; the controller's
generic 64-KiB record limit and the host's 256-KiB transfer cap remain.
Native Linux checks passed 96 protected tests with one skip, 152 restricted
tests and 51 owning interop tests with eight skips. `nft --check` accepted
the generated sender, recipient and relay rule sets without applying them.
Suite 106 below supplies accepted-profile TCG witnesses for both network
denials; the preceding checks alone were prospective.

The source-bound `04a09267` KVM diagnostic 11 exercised the two new probes,
but is excluded from formal acceptance. The first formal TCG run, suite 104,
stopped before the network probes during ordinary signed Mail startup. Its
three candidate/predecessor HotSpot records report SIGILL in different C1
compiled Java methods. The guest stopped, and its complete failed attempt,
volatile records and host receipts were archived privately before two verified
remote duplicate disks were released. The same pinned source, products, JDK,
QEMU, guest size and admission profile passed the next formal TCG attempt,
suite 106. Its host assessment accepted eight positive cases, thirteen denial
cases including `sibling-fcp` and `sibling-http`, and `cancellation`: **22/45**.
Each network case used the actual sender role and live recipient FCP/HTTP
control, while its own exact nft DROP counter gained two packets (120 bytes)
and the other case counter stayed unchanged. The guest exited zero and stopped;
four role stop receipts, a matching sentinel, the live volatile capture and
completed PIDFD host watcher were retained. The 121,400-byte volatile record
was within its 128-KiB limit. A sender HotSpot SIGSEGV in C1-compiled
`sun.security.provider.SHA5.lf_delta0` was also captured and remains an
unresolved intermittent diagnostic, not a claim of JVM stability or an extra
acceptance row. The complete attempt passed recursive Mac byte comparison;
four PVE host records and both stopped disks matched independent SHA-256
checks. After zero task QEMU/open descriptors and an 83-QCOW backing scan,
only the two remote duplicate disks were released, with full Mac originals
and plan/completion receipts retained privately. The current source still
lacks thirteen denial and ten lifecycle installed passes; historical
`controller-restart` cannot be pooled with suite 106.

Subsequent source review found that the `04a09267` PVE preflight counted all
`MemAvailable` toward the 7-GiB requirement before checking the separate
1-GiB physical reserve. The corrected calculation reserves that 1 GiB first
and covers the remaining shortfall with swap above the 2-GiB swap reserve;
boundary tests now reject the old result. The task watcher also checks the
kernel executable inode against the copied loader and the exact fixed QEMU
drive argument, in addition to its PIDFD and start-epoch binding. Therefore
suite 106 remains a historical `04a09267` result and cannot be attributed to
the revised source. Suite 108 below exercises the correction on TCG.
Before another VM allocation, the mounted CT102 task dataset reported
211,724,271,616 allocated bytes; adding the unchanged 29,124,241,553-byte
reservation would exceed the 224-GiB task cap. The early stopped suite 33
success attempt had a complete Mac archive and passed a fresh recursive
checksum comparison. Independent SHA-256 checks matched its two remote disks;
the one-use cleanup plan found zero matching task QEMU processes, open
descriptors or external backing dependents among 81 QCOW images. Only those
two remote duplicate disks were removed. The Mac originals and private
plan/completion receipts remain, and the task dataset allocation fell to
208,757,587,584 bytes. A root-only historical forensic directory was made
enumerable to the mapped CT task group for capacity inventory, while its
three original records remain root-only and unreadable by CT102.

With a new `7db8122b` fixture prepared from the same pinned source-built
candidate/predecessor, JDK and normally signed Mail/probe inputs, suite 108
passed the corrected PVE admission and exact-loader PIDFD watcher. The
fixture and complete stopped attempt passed recursive Mac byte comparison;
four PVE host records and both stopped disks matched independent SHA-256
checks. The guest exited zero and stopped, with four role stop receipts and
the sentinel matched. The host assessment accepted eight positive cases,
thirteen denial cases and a fresh `controller-restart`: **22/45** on this
source. Its controller evidence identifies distinct before/after systemd
invocations and no populated role cgroups after the trigger. The 126,191-byte
volatile record remained within 128 KiB. A sender HotSpot SIGSEGV in a
different C1-compiled Java method was captured; no JVM root cause follows
from this pass. After confirming zero matching task QEMU processes, open
descriptors and external backing dependents across 81 QCOW images, only the
two remote duplicate disks were released. Full Mac originals and private
plan/completion receipts remain. `cancellation` was not run on `7db8122b`;
its passing suite 106 observation has a different source identity and is not
pooled into suite 108.

The next prospective resolver revision adds one measured candidate-role
`resolver-authority` read against a fixed 32-byte root canary in the installed
resolver's private state. The administrator starts and samples the real
`cryptad-restricted.service` before campaign preparation, then binds its
systemd invocation, main PID/start ticks, cgroup, boot ID, canary inode and
digest before and after the role syscall. The host checks that root audit
against the current candidate role epoch, fixed probe source, unrelated
sentinel and final stop receipt, and emits separate v8 and v9 case files.
Wrong actor, service epoch, canary, successful open and incomplete cleanup
cannot pass the offline checks. Native Linux PR-315 discovery passed 138
tests and PR-314 workload-driver discovery passed 42 after this change.
No accepted-profile TCG `resolver-authority` result exists for this source;
the source-bound suite 108 result remains historical.

The first resolver-source TCG attempt, `3d4fc2ef` suite 109, passed PVE
admission and the exact PIDFD watcher but failed the existing positive
sequence while restarting the sender. The observer's original operation
deadline expired; two retained sender HotSpot reports show SIGSEGV and
SIGILL in different C1-compiled Java methods. The resolver role syscall was
not reached, so no denial or `cancellation` case was credited. The guest
exited 1 and stopped; role cleanup completed, the sentinel matched and the
host watcher completed. The complete failed attempt and four PVE host records
passed Mac byte comparison, and both stopped disks matched independent
SHA-256 checks. After zero task QEMU/open descriptors and an 81-QCOW
zero-dependency scan, only the remote disk duplicates were released. The
complete failed Mac original, HotSpot records and offload receipts remain
private. The retained task dataset then used 211,372,053,984 bytes; another
unchanged 29,125,270,538-byte reservation would project 240,497,324,522
bytes, only 20,844,054 bytes below the 224-GiB cap. Another allocation must
re-inventory and may require further verified duplicate cleanup. A later
source revision adds the resolver probe to
the measured `workload-launcher-policy-v9` identity; suite 109's v8-policy
attempt remains historical and cannot be pooled with that revision.
Before the next VM, the already stopped successful suite 30 was checked
against its complete Mac original by recursive checksum and independent disk
SHA-256. A one-use 79-QCOW scan found zero task QEMU processes, open file
descriptors or external backing dependents. Only its two remote duplicate
disks were released; Mac originals and private plan/completion receipts
remain. PVE task dataset allocation fell to 208,413,494,016 bytes.

The `0d89f630` policy-v9 formal TCG suite 110 passed PVE admission and
watcher binding but again failed before the resolver syscall. Its sender
daemon readiness expired under the original operation deadline, and the
retained HotSpot report records SIGILL inside another C1-compiled Java base
method. The guest exited 1 and stopped; role cleanup, sentinel and PVE
watcher completion were retained. The complete failure and host records
passed Mac byte comparison, both disks matched independent SHA-256, and a
79-QCOW zero-dependency/no-open-descriptor scan preceded removal of only
the stopped remote duplicate disks. No positive, denial or lifecycle row
passed in suite 110. The repeated unrelated C1 crash frames do not establish
a product-source defect or justify changing the pinned QEMU/JDK/timeouts.

The separately identified `0d89f630` PVE KVM diagnostic 12 then used the
same source, candidate/predecessor, signed fixture and JDK on a 4-vCPU,
5632-MiB `qemu64` guest. It exited zero, stopped, retained four-role cleanup
and completed its exact-process pressure watcher. The actual candidate role
probe and root `resolver-authority` audit were captured; a private
host-side shape check bound the candidate and live resolver service to
distinct PID/start/systemd epochs and found the fixed v8 case contract
valid. No HotSpot fatal was captured. The 114,122-byte volatile record,
complete guest and host receipts passed Mac byte checks. After an independent
disk hash and 79-QCOW zero-dependency scan, only the two stopped remote
duplicates were released. **KVM diagnostic 12 is not a TCG acceptance
witness:** it cannot increase the accepted 45-case count or change the
false installed-acceptance verdict. The TCG-specific JVM failure remains
unresolved.

The next prospective output revision measures `workload-launcher-policy-v10`
and adds a closed `--case-group output-symlink` path. A fixed test-kit child
inside the candidate-sender service and role sandbox creates one symlink to
an existing 32-byte role-owned canary after an administrator barrier. The
administrator calls the actual bounded `runtime_snapshot.read_file`
descriptor collector, requires its fixed symlink rejection, and rechecks the
canary inode, timestamps and bytes. The root audit binds the candidate actor
and the collector process epochs to the operation, and the host verifier
requires the matching sender stop receipt before emitting v8/v9 private case
records. The selected public result can claim only `output-symlink` and does
not trigger a lifecycle fault. Native Linux checks passed 142 PR-315 tests,
23 PR-312 tests with one skip, 42 PR-314 workload-driver tests and 170
protected workload tests with 21 skips. No accepted-profile TCG output-symlink result
exists on this prospective source; other output attacks and the complete
campaign remain unimplemented.

The isolated `c13b0801` KVM diagnostic 13 ran this one output group on the
same pinned product/JDK/fixture family. Its guest exited zero and stopped;
the candidate-created symlink, valid canary, actual descriptor-reader
rejection and root audit were captured. A private poststop host check bound
the actor to its role invocation and the collector to its real process epoch,
and found the v8 case contract shape valid.

The diagnostic driver's final
summary step separately exited 1: it opened the PVE root-owned watcher
completion file after creation but before its mode changed from 0600 to 0444.
The original traceback and later completed watcher receipt are retained.
The guest, host receipts and both disks passed complete Mac byte comparison;
after an independent hash and 77-QCOW zero-dependency scan, only the remote
duplicate disks were released. KVM diagnostic 13 cannot set formal TCG
acceptance, and the original summary race must not be rewritten as success.

Formal TCG suite 111 on the same `c13b0801` source selected only
`output-symlink` and disabled lifecycle fault injection. Its guest exited 1
before the output barrier: the observer timed out at initial role readiness
after candidate sender and recipient startup, before predecessor launch.
The retained wrapper tails show both candidate nodes initialized, but the
original FCP readiness operation had no terminal success. No HotSpot fatal
or role cgroup OOM was captured. The output case remained `inconclusive`;
the other 44 rows were `not-executed`, and both installed verdict fields
stayed false.

Started roles were cleaned up, the sentinel matched and the
PVE watcher completed. The complete failed attempt, four host records and
both stopped disks matched Mac byte checks; a 77-QCOW zero-dependency scan
preceded removal of only the remote disk duplicates. The task dataset then
used 210,166,459,776 bytes. A subsequent offline correction preserves the
explicit `guest-operation-failed` status for selected-group failures; it has
not had an installed run. At the user's request, no suite after 111 was
started.

The post-111 prospective source now uses `workload-launcher-policy-v11` for
the output group's fixed four-role preparation. This group starts and binds
all four installed roles, then executes its actual descriptor-collector probe
without first requiring CHK transfer, Mail bootstrap or sender restart.
Its result explicitly records that content retrieval and positive restart
were not executed; the host checks the four role epochs, current stop
receipts, sentinel and output-specific root audit. This group cannot set
`installedPositiveExecuted`. The administrator writes a fixed probe-start
marker immediately before the output operation, so initial role-readiness
failure is classified as preparation failure on the new source rather than
mistaken for a completed probe. Suite 111 keeps its original historical
`inconclusive` record.

The PVE watcher now prepares each completion receipt privately, syncs it,
sets its final read-only mode and publishes the complete inode exclusively.
This closes the observed diagnostic-13 file-exists-before-readable race;
an existing receipt is never replaced. The host gives the ready receipt a
fixed five-second verification window before allocation; unreadable or
malformed publication then blocks the run. On failed role startup, the observer
requests a fixed administrator diagnostic before its role cleanup. The root
sampler binds the selected active role JVM, captures bounded `jcmd` output
and a bounded private FCP log tail, or records why either is unavailable.
The original readiness failure and campaign deadline remain authoritative.
An explicit `--role-readiness-measurement` path now runs the four real role
FCP readiness operations under the same installed profile and returns no
workload case credit. It gives the next separately identified TCG diagnostic
an actual role-start path; the older controller-only startup measurement
cannot reach the suite-111 failure point.
These changes have passed offline checks only and have no TCG installed
result. The default full-campaign entry now exits 78 before VM allocation
while any declared group lacks an emitter; explicit supported development
groups remain available. No suite after 111 had run when this v11 source was
frozen; the later resume is recorded separately.

The separately prepared prospective v12 output revision adds one isolated
`output-fifo` group. A measured candidate child creates the FIFO inside its
role sandbox after the administrator barrier. The root administrator observes
the active role and unchanged 32-byte canary, invokes the actual bounded
descriptor collector against the FIFO, verifies its immediate file-type
rejection and retains the role/collector epochs before shutdown. The host
checks this root audit, final stop receipts and guest stop before producing
the case's v8 and v9 private records. The group cannot claim positive or any
other denial case. Linux offline checks passed for the role, evidence and
host verifier paths; no v12 TCG installed result exists.

The following prospective v13 revision adds an isolated `output-hardlink`
group. The role child creates a second directory entry for the fixed canary;
the administrator proves the same inode now has exactly two links and the
canary's 32 bytes are unchanged. It calls the real bounded collector on the
attacking entry and requires its file-type/link-count rejection. The host
binds both entries, the live role and collector epochs, root audit, stop
receipt and guest stop. This group has offline checks only and does not
inherit any installed result from the earlier output groups.

The prospective v14 revision adds one isolated `output-flood` group. The
actual role child writes exactly 65,537 bytes to one fixed regular file.
The administrator byte-checks that object through the real descriptor
reader with a 65,537-byte bound, then invokes the same reader with the
case's 65,536-byte collection limit and requires rejection. The root and
host bind the file's owner, inode, size, digest, role and collector epochs,
unmodified canary, stop receipt and guest stop. No v14 TCG result exists.

The prospective v15 revision adds an isolated `output-replacement` group.
The candidate creates a fixed 32-byte file and waits at a second root
barrier. The actual descriptor collector pins that file; its measured
test-kit hook then releases the candidate to atomically replace the path
with a distinct fixed 32-byte inode. The collector must reject the changed
path after reading its pinned descriptor. Root and host checks bind both
inodes, exact A/B content digests, barrier order, role/collector epochs,
unchanged canary and terminal receipts. The hook is an optional local
callable in the descriptor reader; it does not add a production control
socket method. No v15 TCG result exists.

The prospective v16 `role-boundary` group uses a separate candidate probe
mode. After four real role starts, that mode performs only the observer
private read/write and the fixed sibling-data, package and cgroup operations.
The administrator binds the active canaries, candidate child, recipient
service, package and cgroups before and after those syscalls. Resolver,
network and false-identity operations are left to their own groups. The
host validates only the group's five exclusive IDs and exact stop receipts;
it does not claim a CHK/Mail positive result. No v16 TCG result exists.

The prospective v17 `authority` group starts four real roles and the
installed resolver, then exercises its fixed observer-control and active
endpoint refusals, a vmadmin runner-control attempt and a separate candidate
probe for false process/resource claims and resolver access. It does not
repeat the role-boundary file or sibling-network attacks. The host checks
the real actor and target epochs, root records and stop receipts for those
six implemented IDs. `hostile-app-origin`, `stale-handle` and `stale-pid-uid`
still need installed emitters, so the authority group remains incomplete.
No v17 TCG result exists.
In a network-disabled, read-only Debian Docker test container, the latest
focused source passed 157 PR-315, 45 PR-314 workload-driver, 23 PR-312
reference-VM, 11 interop snapshot and 54 interop workload tests (eight
interop workload skips). The
selected protected-workload file passed 69 tests with one skip after the
v11 policy change. These are offline checks, not installed results.
Broader read-only Docker discovery ran 494 restricted tests with one skip
and three errors, and 533 protected tests with 83 skips, two failures and
twelve errors. The restricted errors were a missing container
`/usr/bin/systemd-sysusers` and two temporary executables blocked by
the container's `noexec` tmpfs; those two specific tests passed when
rerun with executable tmpfs. The protected failures include unavailable
container tooling, read-only `build/`, and container `/proc`/cgroup
assumptions. This broad discovery is not a green gate and requires a
suitable disposable Linux environment before final-source acceptance.

For the `ae80895` source, native Linux protected discovery passed 527 tests with
74 skips, restricted discovery passed 435 with one skip, and the owning interop
workload tests passed 47 with eight skips. Full interop discovery ran 257 tests
with eight skips but had one import error and three packaged integration failures
from the existing package/environment and embedded-source mismatch; it is not a
green gate. The test suite validates the code path only. No final-source hosted CI,
independent security review or complete installed 45-case campaign has passed.

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

In the following tables, “positive path” identifies production actions reached by
`pr314_workload_driver.py` and `InstalledWorkloadAdapter.run_positive()`. The third
column names the evidence required for each row; suite 70 passed those eight rows.
The denial and lifecycle tables retain the missing installed emitters. Synthetic
verifier tests are not emitters.

| Positive ID | Existing path | Required evidence (passed in suite 70) |
| --- | --- | --- |
| `installed-ready` | Installation/test-kit checks in positive driver | Observed ready controller and exact installed before/after identity |
| `four-role-start` | Adapter starts four fixed role services | Trusted UID/GID, invocation, cgroup and namespace roster |
| `signed-apphost-child` | Signed Mail install/start and worker observation | Exact bundle and independently captured kernel child binding |
| `own-management` | Controller-bound FCP/HTTP descriptors | Per-operation request/control response and server invocation |
| `fnp-content-retrieval` | Relay topology and byte-checked content operation | Cross-node causal evidence excluding recipient preload/cache-only success |
| `dynamic-app-bootstrap` | Controller-verified Mail bootstrap | Current child/session/operation evidence captured independently |
| `kernel-resource-scope` | Controller kernel observation support | All four actual scoped cgroup measurements |
| `restart-durable-state` | Sender restart and app-inventory retention | Selected durable sentinel before/after, original deadline, both invocation epochs |

The denial rows below retain their fixed actor and target requirements.
`observer-private-read`, `observer-private-write`, `sibling-data`,
`runner-control`, `observer-control`, `arbitrary-endpoint`,
`package-expectation`, `forged-runtime-identity`,
`namespace-mount-escape`, `cgroup-migration`, `forged-counters`,
`sibling-fcp` and `sibling-http` have passing installed witnesses on
`7db8122b` suite 108; the other thirteen still lack passing installed
emitters. The actor column preserves the
contract; it must not be replaced with a root probe or a same-UID process outside the asserted
role/AppHost boundary.

| Denial ID | Actor | Fixed target and required executable probe |
| --- | --- | --- |
| `observer-private-read` | candidate | Existing observer canary; measured role process read and root/host audit passed in suite 78 |
| `observer-private-write` | candidate | Same active canary; measured role write attempt, unchanged bytes and independent root/host audit passed in suite 81 |
| `resolver-authority` | candidate | Prospective fixed role read against active installed resolver's root canary, with root/host process, file and stop checks; no installed result yet |
| `provider-authority` | app | Active synthetic provider fixture; normal signed AppHost child attempts authority access |
| `sibling-data` | candidate | Existing recipient sentinel; sender process attempts access |
| `sibling-fcp` | candidate | Suite 108 sender SYN, active recipient `NodeHello` controls and own named nft DROP delta passed TCG |
| `sibling-http` | candidate | Suite 108 sender SYN, active recipient HTTP HEAD controls and own named nft DROP delta passed TCG |
| `sibling-app` | app | Active recipient AppHost endpoint; sender AppHost probe |
| `host-network` | candidate | Active synthetic host canary; emitted probe and attributed filter evidence |
| `runner-control` | runner | Fixed vmadmin `systemctl` stop request against the active controller unit; policy denial and root/host audit passed in suite 70 |
| `observer-control` | observer | Installed system manager; valid disallowed control request |
| `arbitrary-endpoint` | observer | Active recipient FCP `NodeHello` controls and one fixed disallowed connector selection; root/observer/host checks passed on TCG suite 102 |
| `hostile-app-origin` | candidate | Active own app; valid request with hostile origin |
| `package-expectation` | candidate | Admitted immutable package/identity; actual fixed mutation attempt |
| `forged-runtime-identity` | candidate | Process observer; fixed false claim compared with independent kernel identity |
| `namespace-mount-escape` | app | Outer role boundary; bounded nested namespace/mount escape attempt |
| `cgroup-migration` | candidate | Existing fixed cgroup target; actual migration attempt and unchanged ownership |
| `resource-exhaustion` | app | Role resource cap; finite allocation/task probe and actual cgroup events |
| `output-symlink` | candidate | Prospective isolated role-created symlink to active canary, actual bounded descriptor collector, root/host epoch and stop checks; no installed result yet |
| `output-fifo` | candidate | Descriptor-based collector; role-created FIFO and bounded rejection |
| `output-hardlink` | candidate | Descriptor-based collector; actual multiply linked file |
| `output-replacement` | candidate | Descriptor-based collector; coordinated replacement during pinned read |
| `output-flood` | candidate | Descriptor-based collector; finite cap-exceeding growth/output |
| `stale-handle` | observer | Controller; retired handle against successor authority |
| `stale-pid-uid` | observer | Process observer; retired invocation versus actual new process |
| `forged-counters` | candidate | Kernel metrics; false candidate values versus actual cgroup measurements |

The lifecycle rows below retain their fixed triggers and terminal evidence.
`controller-restart` passed on `7db8122b` suite 108; `cancellation` passed on
`04a09267` suite 106. These are separate helper identities. The other nine
lifecycle IDs lack a source-bound TCG pass, and the eventual final source
requires all eleven again. Triggers must follow observed
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

Retain the ordinary Mail positive profile and the separately signed `pr315-probe`
cohort. Preparation and AppHost installation now admit both exact bundles; the
synthetic AppHost child has one installed mount-namespace denial witness. The
other app-origin denial operations still need fixed probe modes and installed
evidence. Do not modify either bundle after signing or label a candidate-UID
helper as an AppHost attack.

Use fixed bounded probe operations for file access, immutable-input mutation, namespace escape,
cgroup migration and output hazards. Capture the actual process epoch, UID, namespaces and
current role invocation before and after each operation. For app actors, also capture normal
AppHost parent/child and exact admitted bundle relationships. Administrator orchestration controls
only the declared disposable resources and cannot substitute for the asserted attack actor.

For network probes, keep DROP semantics. The six approved FNP links already have
named bridge counters; the denied scenarios still need fixed scenario-attributed
counters or an equivalent bounded kernel observer. Record the actual emitted probe,
exact ruleset/namespace identity, counter delta and causal interval, with an authorized active
target control before and after. A recipient loopback
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
v8 attempt has one role roster, so it cannot faithfully bind both pre-restart operations and
post-restart observations to different epochs. Its generic denial actor proof is UID-only;
the five passing denial emitters have additional fixed root audits. It also
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
denial from guest-wide OOM or loss of observation. Later positive attempts sampled
all four running role cgroups; no installed role-exhaustion result exists yet.

The next prospective TCG campaign uses `pve-tcg-swap-admission-v1` on the PVE host.
It preserves the 7-GiB guest/overhead/reserve budget, 1-GiB physical reserve and
2-GiB spare swap; only the observed physical shortfall can be covered by both
host and CT102 cgroup swap headroom. Host memory and I/O full-pressure preflight
ceilings are 5 and 10 percent. A root-owned, source-bound, 120-second host receipt
is required before VM allocation. The task-specific pressure watcher must be
ready first and must finish normally after the guest; it selects only the exact
suite QEMU and signals through a pidfd. This policy has offline tests but has
not yet produced installed acceptance evidence.

The new `observer-private-read` test-kit path stages a measured fixed Python
actor into the candidate sender's actual service cgroup and role sandbox. The
administrator creates an observer-owned canary, proves the observer can read it,
observes the role child and current invocation before triggering one bounded
open, then checks the child, target and stop receipt. Its fixed root audit is
copied into bounded private evidence and checked by the host. An absent path in
the candidate mount namespace is retained as the actual `ENOENT` result; it is
not relabelled `EACCES`. The v9 per-case record remains prospective until an
installed run validates this path. The 21-group v9 campaign ledger partitions
the unchanged 45 IDs and permits only bounded preparation-stage retries; its
offline structural result cannot set installed acceptance.
The runner now writes the same 21 exclusive declarations and accepts a closed
development `--case-group` selector. Selected public results project only
their owned case IDs and cannot set complete acceptance; unsupported emitters
return without a VM. This is scaffolding: the current guest driver still
runs its aggregate preparation/probes for supported groups, and the default
runner has not yet become a 21-group installed scheduler. Cross-group
preparation must be narrowed before final campaign execution.
A native CT102 `output-fifo` selection probe exited 78 with no guest
allocation, zero passed rows, and both installed verdict fields false.

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

For the fixed bridge-table correction, the independent table-name regression failed on
the old reader and passed on the corrected reader. Native Linux protected discovery passed
528 tests with 74 skips; the owning interop workload adapter passed 42 with eight skips;
and PR-31x restricted discovery passed 294 with one skip. Broader interop discovery ran
252 tests and retained four package/environment failures, including embedded source
mismatch against the pinned daemon product; it is not counted as green. macOS protected
discovery also remained red under its local socket sandbox, so installed Linux evidence
remains necessary. Root-only skips are still unexecuted checks.

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

For the insert-selector correction, the new two-item negative-exclusion regression failed on
the unmodified selector and passed after the one-line fix. The complete
`RandomGrabArrayTest` class passed. Two fresh, non-DEBUG local Java nodes then completed a
synthetic local-only CHK `ClientPut` with the rebuilt artifact. The full Java suite on CT102
passed 17,407 tests with ten skips, zero failures and zero errors. Focused `sonarlintFile`
analysis of the touched production file produced an empty Checkstyle report. A full macOS
Gradle run failed in unrelated workspace scanning and host-path/symlink tests; its outcome is
not substituted for the successful Linux run. The subsequent peer-selector correction passed
the full Linux Java suite and a complete installed positive aggregate as described above.
No 45-case installed workload campaign or hosted CI has run against the latest source.

| Assessment dimension | Audit verdict |
| --- | --- |
| `implementationCoverage` | Incomplete: the prospective branch has resolver, all five output emitters, the five-case role-boundary group and six existing authority emitters under v17 selected-group preparation. Three authority, other denial and lifecycle emitters and the default full scheduler remain absent. Historical `7db8122b` suite 108 passed eight positive, thirteen denial and `controller-restart` on one TCG guest; `cancellation` passed only on earlier `04a09267` |
| `installedPositiveExecuted` | False on the latest formal TCG suite 111; the prospective post-111 source has no installed run. Historical `7db8122b` suite 108 passed its eight-case positive aggregate. KVM diagnostics 12 and 13 are excluded |
| `installedWorkloadAcceptanceSatisfied` | False; no final-source 45-case TCG campaign passed. The best historical source-bound TCG suite has 22/45, and KVM diagnostics cannot raise that count |
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
