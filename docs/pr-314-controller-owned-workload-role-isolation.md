# Controller-owned workload role isolation

This branch implements a source-build workload adapter and an installed positive driver for the
existing four-role experiment. It is not yet a complete PR-314 remediation: installed hostile
drivers and the actual reference execution remain outstanding. Installed workload acceptance,
finite-native acceptance and original protected authority remain separate requirements.

## Source and evidence cutoff

The implementation starts from `develop` at
`45eb43d6654074df884f59415fa598c1cda93e36`, the squash merge of GitHub PR #1415
(project work item PR-313). GitHub reports that PR merged at `2026-09-22T04:28:18Z`;
its feature head was `90fc0323ff7b03202fd3f4f6f6114c68b3772819`.
The implementation branch is `feature/pr-314-controller-owned-workload-role-isolation`.

The current API requery found Java CI `35683706077` successful, including build,
interop-smoke and certification; extended/perf-smoke were skipped. Beta `35683705860`
passed its dry run and skipped `production-beta`. Restricted prerequisites `35683705861`
passed. These are hosted checks for the inspected PR-313 source, not installed workload
observations or tests executed by this development session.

The [PR-313 runbook](pr-313-installed-native-acceptance.md) retains its original 2026-09-16
17-case positive observation at helper `19983163e45e2cc55eaac10ee458c1177bd60286`, the
separate PR-312 product identity, the interrupted next guest, and the earlier unresolved
SIGILL/SIGSEGV. Its 65-case finite-native contract remains incomplete. The runner corrections
after that observation do not change its source identity or cutoff.

## Bounded prospective profile

The profile is `debian13-systemd257-workload-v1`, on the existing disposable Debian 13,
systemd 257, cgroup-v2 reference. It retains the explicit `qemu64` CPU and selected
`tcg-single` or `tcg-multi` accelerator without automatic fallback, four vCPUs and 5632 MiB.
The pinned reference records kernel `6.12.107+deb13-amd64`, systemd `257.13-1~deb13u1`,
bubblewrap `0.12.0-1~deb13u1` and Temurin `25.0.4.1+1`.

The bounded backend uses fixed per-role system-manager services and accounts, fixed namespace
setup, and controller-owned state under `/var/lib/cryptad-restricted-workload`. The roster is
`candidate-sender`, `candidate-recipient`, `previous`, and `relay-no-apps`. A smaller hostile
fixture does not establish the normal four-role topology. Source-built synthetic products are
eligible for local implementation testing, not historical-product authority.

Controller selections must bind original registration, exact packages/JDK/apps/configuration,
finite deadline and resource budgets, invocation generation, immutable mappings and writable
storage generation. No client command, namespace, PID, port, path or systemd-property selection
is admitted. The profile must reject an unsupported adapter before mutation.

## Audit and ownership matrix

| Execution or state | Existing component to reuse | Required workload treatment |
| --- | --- | --- |
| Original registration, approval and revocation | Restricted controller and original-provider admission | Controller-owned; never copied into role environment |
| Lease, journal, checkpoint, expected identities and canaries | Existing observer private root and historical readers | Observer-owned 0700; no role traversal or exposure |
| Main packaged daemons | `cross_version_runtime.Supervisor` | Fixed distinct role services; no same-UID launch fallback |
| AppHost descendants | Real signed app install and sandbox provider | Within role UID, namespaces and service cgroup; actual nesting must pass |
| Package/JDK/staged bundle | Product admission and exact installed closure | Read-only fixed role mapping; explicitly translated app-install path |
| Daemon config/data/cache/run/logs | Existing daemon configuration and persistence | Role-only writable storage; normalized config separate from expected config |
| Catalog transport and Java helpers | `federated_catalog_runtime` | Confine selected helpers or reject profile before execution |
| Scheduler Java/Node/browser tasks | `scheduler_pressure_runtime` | Confine every candidate-bearing task or reject profile |
| Recovery clones | `cross_version_recovery` | New retained role invocation with same deadline and durable app state |
| Historical adapters and Mail child inspection | Existing adapters and `two_node_demo` | Explicit adapter coverage; no arbitrary PID adoption or forged provenance |
| Finite package/app/CMS verification | Existing keyless native service | Retain separate resolver/native context and recipient-key boundary |
| Candidate outputs | Existing bounded collectors | Adversarial bytes; regular-file/link/race checks and bounded private retention |

The launch-site rows are obligations identified by the audit, not claims that every adapter is
implemented. Installed acceptance must enumerate the exact supported adapter set. Neither a Java
binary digest nor an app API's reported PID establishes the actual loaded product/app identity.

## Management and data connections

| Source | Destination | Required result |
| --- | --- | --- |
| Observer | Selected role's fixed FCP/HTTP/app management endpoint | Allowed through invocation-bound connector |
| Role daemon | Its own app and Platform API loopback endpoints | Allowed, preserving current bootstrap/session checks |
| Selected role | Approved peer FNP link | Allowed; actual cross-node content retrieval required |
| Candidate or app | Sibling FCP/HTTP/app endpoint | Denied against positively active server |
| Candidate or app | Observer, resolver, provider, baseline or host service | Denied against existing active target |
| Runner or observer | Arbitrary unit, namespace, PID or connector endpoint | Denied by server-side fixed selection |
| Candidate | Public Internet or metadata endpoint | No admitted route |

Different loopback ports are insufficient. Dynamic app listeners retain origin, nonce, session
and current-worker binding. A redirect cannot grant an arbitrary endpoint, and browser CORS is
not a server-side authorization proof. Unavailable listeners and client timeouts are not denials.

## Lifecycle and measurements

Each role needs controller-retained intent before launch, exact manager invocation and cgroup,
boot identity, process epoch, immutable input identities and absolute deadline. A lost reply
reconciles that exact invocation. It must not launch again or adopt a matching process name.
Revocation forbids new work while leaving exact owned termination available.

Cancellation, deadline, observer loss, controller restart and partial launch must stop scheduling,
terminate only the owned invocations, verify all descendants quiescent, then finalize bounded
output. No UID, port, mount or storage generation is reused while old descendants or recoverable
active records remain. Failure to prove quiescence retains reconciliation state.

Cgroup memory remains cgroup memory, not process RSS. Missing cross-UID metrics are unavailable,
not zero. Kernel observations, controller intent and candidate counters retain separate provenance.
A prospective collector/profile change requires fresh comparison eligibility; historical layout-2
same-UID results cannot be upgraded by replaying a checkpoint or changing its version.

## Separate acceptance contract

[`pr314_acceptance.py`](../tools/release-certification/restricted/pr314_acceptance.py) defines the
closed workload inventory and private driver-record verifier. It requires distinct role UIDs,
namespaces and invocations; real AppHost witness fields; control-side positive responses;
causal denial intervals; durable restart state; and terminal cgroup/descendant observations.
Unknown fields, duplicate attempts, omitted cases and stale identity prevent acceptance.

The verifier accepts records only through an administrator driver whose guest transport and
source identity have been independently measured. It is not a report-import or approval tool;
valid JSON, hashes and synthetic unit-test records do not authenticate execution. The module
provides a supporting contract, not proof that the workload backend runs.
The contract's unit tests exercise valid and hostile record shapes only.

| Dimension | Current evidence meaning |
| --- | --- |
| Role implementation and adapter coverage | Prospective implementation; audit obligations above |
| PR-313 finite-native acceptance | Separate 65-case contract; no complete installed run recorded |
| Workload isolation acceptance | No installed observations recorded |
| Actual operation/fault coverage | Contract cases are requirements, not executed attacks |
| Original protected authority | Not supplied by local synthetic provider context |
| Duration/resource comparison eligibility | No new baseline or long-soak claim |
| Cleanup and retained failure | Requires actual guest and role quiescence evidence |
| Phase 12 completeness | Unchanged; 49 mandatory assertions and historical 47 unresolved remain |

Protected authorize/start/checkpoint must retain the unsafe path's denial until all applicable
finite-native, workload, original-authority and reviewed deployment prerequisites are established.
No administrator JSON checkbox or self-digest supplies them.

## Implemented code path

The production extension is deliberately separate from the credential-bearing resolver:

| Component | Implemented responsibility |
| --- | --- |
| `restricted/workload_installation.py` | Explicit fixed-unit/account installation after immutable base closure verification; no protected enablement |
| `protected/restricted_workload_prepare.py` | Root-only source-build selection, existing archive/app admission, prospective configuration pins, immutable role staging and static account reservation |
| `protected/restricted_workload.py` | Retained campaign/role handles, operation/deadline checks, exact manager/cgroup observation, stop independent of current approval |
| `protected/restricted_workload_mark.py` | Fixed privileged `ExecStartPre` receipt binding the controller generation to the manager invocation before candidate execution |
| `protected/restricted_workload_launcher.py` | Empty-capability role identity, closed bwrap mappings, real packaged daemon invocation and original finite deadline |
| `protected/restricted_workload_network.py` | Four role namespaces plus isolated switch namespace; per-role and bridge UDP relay matrix; fixed connection descriptor transfer |
| `protected/restricted_workload_controller.py` | Observer-UID socket admission, fixed `{method, handle}` requests, finite request/watchdog budgets, semantic Mail bootstrap |
| `protected/restricted_workload_app.py` | Scoped kernel process/namespace/ancestry and current daemon listener binding, including Java's IPv4-mapped loopback sockets |
| `protected/restricted_workload_storage.py` | Pinned immutable input copies and bounded untrusted installed-app snapshots compared to exact admitted bytes |
| `interop/cross_version_workload.py` | Existing FCP parser, AppHandle route policy and journal; four-role relay connections, signed Mail child/bootstrap, CHK retrieval and daemon restart |

The initial selection accepts only source-built Cryptad products, Mail on the candidate roles,
and the app-free relay. Catalog, scheduler, composed-budget, recovery-clone, migration, historical
product and higher-level Mail consumer selections are unsupported implementation coverage. They
must not be routed into the historical observer's `Popen` or host-loopback client paths.
The existing plan still retains all mandatory scenario assertions; the positive driver writes
a partial journal and cannot report the whole experiment complete.

All four roles use fixed in-namespace FNP/FCP/HTTP ports `19400/19401/19402`. A selection's
`configDigest` must come from `configuration_identity(role, trustedKeysDigest)` in the preparation
module, and its producer must equal the existing installed `runner_identity()`, including the
immutable installation/dependency closure. Old loopback configuration pins cannot be reused.
The predecessor must have a distinct source and actual daemon JAR; repackaging current bytes does
not create a historical comparison.

Each role has a nondelegated 512-task, 1 GiB-memory, zero-swap, 100%-CPU service budget, and a
512 MiB/32768-inode tmpfs for all writable node state. Restarts retain that tmpfs; host-reboot
continuation is unsupported. Runtime is at most 3600 seconds and remains tied to the original
campaign deadline. The observer inactivity bound is 240 seconds, above the fixed 180-second FCP
transaction bound. Loss of the controller stops bound role services through systemd. Unknown or
replaced invocations retain reconciliation failure.

The role launcher permits AppHost's nested namespace construction; it does not copy the finite
native verifier's descendant-userns prohibition. Real AppHost nesting and hostile tmpfs/resource
exhaustion still need installed execution. The separate root sampler has `CAP_SYS_PTRACE` only to
satisfy cross-UID proc read checks, with ptrace, process-memory and perf-event syscalls denied.
Neither the observer nor candidate receives that capability. Root's fixed namespace setup and
the small controller/recorder remain part of the TCB.

The lifecycle reads the recursive `populated` state described by the
[Linux 6.12 cgroup-v2 interface](https://www.kernel.org/doc/html/v6.12/admin-guide/cgroup-v2.html).
It keeps manager invocation, cgroup identity and proc epochs separate; the
[proc interface](https://www.kernel.org/doc/html/latest/filesystems/proc.html) does not turn a
candidate-reported PID into ownership. Unit settings target
[systemd v257 execution semantics](https://github.com/systemd/systemd/blob/v257/man/systemd.exec.xml)
and still require checks against the exact installed Debian patches.

Preparation admits at most 512 MiB expanded package and 512 MiB JDK per role, plus bounded app
inputs. It reserves 12 GiB for staging/retained partial preparation and 4 GiB free-space headroom
by admission check; this is not a kernel filesystem quota or protection from unrelated writes.
Input/package bytes remain root-owned, outside the observer root. Failed app snapshots retain
their fixed reservation and reject retries; successful snapshots are removed after exact matching.
No static identity or retained campaign is automatically recycled.

## Executable test entry and remaining implementation work

The read-only prerequisite check is:

```bash
python3 tools/release-certification/restricted/pr314_workload_driver.py
```

Exit 78 means that the installed lane was not executed. In this development session it reported
missing administrator context, dedicated VM, fixed installation and measured test kit. The host
is a container; no workload services, accounts, namespace fabric or candidate daemon were installed
on it.

Inside a newly copied and admitted reference VM, first use the existing PR-313 base installation,
separate test-kit preparation and boot-closure verification. An administrator supplies the fixed
root-private `/root/pr314-workload-selection.json` with `plan`, `private`, and `authorization`.
Use two distinct source-built portable archives, a flattened exact JDK closure, and the normally
signed Mail bundle/public trust input. Produce the prospective config and installed runner pins
described above; do not change product bytes or invent source identities to satisfy the roster.
After independent source/test-kit checks, the explicit guest command is:

```bash
python3 /opt/cryptad-restricted-test-kit/tools/release-certification/restricted/pr314_workload_driver.py --execute
```

That driver invokes production preparation/installation code, drops the observer to `cryptad-soak`,
uses the existing private journal, executes the adapter's actual positive sequence, and requires
terminal owned cgroup quiescence before namespace teardown. It retains role tmpfs state and
private records for diagnostics. Its public result has fixed status fields only. The private
result labels the workload verdict incomplete because it does not execute the full hostile
contract. Neither this command nor a passing positive sequence is a protected approval.

Still required before calling PR-314 implementation complete:

- Executable installed drivers for all applicable hostile and lifecycle cases, including active
  sibling/admin canaries, real candidate/app-UID attacks, namespace/resource escape, late children,
  revocation, controller/observer loss, output races and retained invocation reuse.
- Complete private fixture preparation and host orchestration of that workload suite through the
  existing copied-reference/storage-budget transport.
- Actual installed validation and fixes derived from it, including effective service policy,
  cross-UID sampling, real AppHost nesting and truthful terminal resource retention.
- Reviewed admission of any future original-product/protected selection. The current source-build
  preparation rejects production-artifact comparison and does not bypass original artifact policy.

These are implementation and acceptance gaps, not renamed operations-only debt. No PR-313 finite
case was executed by the new driver, and none of the 45 workload cases has an installed passing
observation from this session.

## Resource inventory and execution limits

The initial read-only local inventory found no QEMU process, QEMU executable on PATH, or reference
images/attempt disks under accessible `/work`, `/tmp`, `/var/tmp`, `/opt` and `/home/codex`.
The host is LXC with UID1000 and systemd PID1; it is not the dedicated VM required by
`disposable_integration.prerequisites`. A subsequent administrator metadata-only inventory of
`/root` found no files with the inspected `.qcow2`, `.raw` or `.img` disk suffixes (zero allocated
bytes for those candidates). This bounded search does not erase or supersede historical evidence.
The last storage check found 57,067,704,320 bytes available on the root filesystem. No VM was
allocated or deleted, and no guest storage budget was consumed in this session.

Before every allocation, follow root `AGENTS.md`: inventory retained attempts and allocated blocks,
confirm stopped/disposable ownership before cleanup, then set one total task budget and minimum
free reserve. Reuse `pr313_acceptance_runner` storage admission and `pr313_boot_inputs` private
copied closure. Its 24 GiB guest-growth reserve and 256 MiB report reserve are admission estimates,
not filesystem quotas. Preserve failed/interrupted evidence and stop allocation if capacity fails.

New administrator drivers belong in the separate test kit and must be excluded by
`installation.TEST_SEAMS`. Their public output must use fixed allowlisted fields, excluding
private source/selection commitments, paths, identities, keys, topology, logs and guest images.

## Local verification on this branch

These results describe local tests of the uncommitted implementation, not installed acceptance.
Totals overlap because some self-tests include the same underlying test modules.

| Check | Result |
| --- | --- |
| Restricted Python discovery | 267 tests, 1 skipped, passed |
| Protected `test_restricted_*.py` discovery | 159 tests, 20 skipped, passed before the final preparation guard regression was added |
| New workload tests as root, including the final preparation guard | 87 tests, no skips, passed |
| Cross-version interop discovery | 206 tests, 8 skipped, passed |
| New observer adapter tests as root | 22 tests, no skips, passed |
| `cross-version-soak --self-test` | 152 tests, passed |
| `stable-maintenance --self-test` | 247 tests, passed |
| `stable-platform-api-1x --self-test` | 88 tests, passed |
| `phase-12-closeout --self-test` | 185 tests, passed |
| Catalog regressions | 24 tests, passed |
| Scheduler regressions | 19 tests, passed in each of two overlapping local invocations; numeric findings differ as described below |
| Mail regressions | 5 tests, passed |
| `:platform-devtools:installDist assembleCryptadDist` | Passed, 342 tasks: 307 executed, 35 up-to-date |
| `systemd-analyze verify` for both workload units | Passed static validation; no installed unit execution |
| Workload driver read-only prerequisite probe | Exit 78, installed execution not performed |

Root fixture tests include actual filesystem permission/link attacks and local socket descriptor
transfer/listener checks. Manager invocation and many fault cases use simulated manager state;
they are not real role-service, namespace or AppHost observations. No shared Java runtime source
changed and the full Java test suite was not run. The distribution build emitted 329 Error Prone
warnings across 117 untouched Java files, plus a Gradle deprecation warning; successful exit is
not a clean analyzer result.

The first scheduler invocation reported `runtime-reference-dispersion-exceeded` and
`runtime-regression-exceeded`, with `numericStatus=fail`. The second reported no numeric findings
and `numericStatus=within-reviewed-local-bounds`. Both reported `releaseEligible=false`, two
repetitions and one candidate execution. The invocations overlapped; the differing numeric
observations are retained without assigning an unverified cause. Neither establishes a fresh
performance baseline or release acceptance.

The subsequent review fixes require every installed app session refresh, including after restart,
to use the controller's `bootstrap-mail` exchange. Candidate-provided ordinary bootstrap origins
cannot skip current app/process/listener validation. A failed refresh clears the previous session.
Preparation explicitly sets traversal permissions and durable record permissions independently of
the administrator's umask; observer authority remains private. Both reported failures reproduced
before correction. The new preparation regression uses `umask 077` and real UID-dropped children
to initialize/read role storage, with product admission, service state and mounts supplied by
fixtures. It does not establish installed acceptance.

Review validation passed: 88 focused workload tests under root, 24 focused adapter tests under
root, 208 cross-version interop tests (8 skipped), and 161 protected tests under root (1 skipped).
These are subsequent local results, separate from the earlier verification table.

A further sampler review reproduced `pidfd_open()` returning `ProcessLookupError` for a reaped
child still listed in the sampled process roster. Observation now counts that race as
`exitedDuringSample`, alongside disappearing proc files, and still rechecks the exact manager
invocation afterward. Regression tests use real reaped children with fixture cgroup/manager state;
they also verify rejection of invocation replacement and propagation of permission failures.
Validation passed: 91 workload tests under root (no skips), 24 adapter tests (8 skipped), and
12 acceptance-contract tests. No installed systemd/network/AppHost execution was performed.

The later exit window, after process data is sampled but before pidfd readiness is checked, is
also covered. A distinct `ProcessExitedDuringSample` exception derives from `ProcessLookupError`,
so both roster consumers skip the exited entry; required app-process revalidation still rejects
its loss. A regression terminates and reaps a real child after pidfd acquisition and before the
readiness check, and verifies the final invocation check is retained. App-binding tests cover
unrelated helper exits, required process/ancestor exits during either pass, and ownership failures.
The subsequent checks passed: 95 workload tests under root without skips, 24 adapter tests with
8 skips, and 12 acceptance-contract tests. These remain local tests, not installed acceptance.

The subsequent PR review adds request-local handling of malformed role HTTP responses, including
`HTTPException` subclasses. A malformed bootstrap fails its own request without exiting the
controller and reconciling healthy siblings. Local TCP regressions exercise an invalid status
line and an oversized header, followed by a successful controller request.

The prospective acceptance contract is now `pr314-workload-roles-v2`. Each attempt requires
measured `principals` containing the observer UID, runner UID and exact four-role roster; all
six host accounts must be distinct. The start witness must match this context. Candidate/app
denial probes in this initial contract originate in `candidate-sender`; their actor UID must
match that role, while observer/runner denials must match their respective accounts. Legacy v1
records cannot satisfy v2. These checks bind host accounts only: the installed driver must still
measure the actual probe process and its app/role invocation. JSON context does not authenticate
execution. Review validation passed 96 workload tests under root and 15 contract tests.

Subsequent witness-binding fixes require the signed app invocation and management/bootstrap
server invocation to match `candidate-sender`; FNP retrieval binds its serving observation to
`candidate-recipient`. Lifecycle terminal rosters must equal the measured attempt roster,
including process epochs, accounts, invocations, cgroups and namespaces. A driver exercising a
new restart epoch must supply that epoch's measured context for its terminal attempt; it cannot
reuse stale context. Runtime JSON is checked as an object with object-valued runtime/sandbox
members before either bootstrap process-binding pass, so malformed JSON shapes fail only the
request. Local validation passed 97 workload tests under root and 19 contract tests. The current
driver still does not execute the complete installed hostile/lifecycle suite.

The next contract revision, `pr314-workload-roles-v3`, replaces unscoped aggregate resource
counters with exactly one measurement per owned role. Each measurement binds role, cgroup digest,
manager invocation, process epoch and boot identity to the attempt's measured principal roster;
duplicate, missing and unrelated groups reject. Restart evidence explicitly names
`candidate-sender` and binds its resulting invocation and epoch to that roster, in addition to
requiring a changed invocation/epoch, preserved state digest and unchanged deadline. Earlier
contract versions cannot satisfy this revised witness format. These checks establish record
consistency; actual measurements and causal restart execution remain installed-driver obligations.

Contract `pr314-workload-roles-v4` additionally binds the app witness to `admittedAppDigest` in
the independently supplied expected identity. The administrator driver must derive that value
from the authenticated selection's exact installed-app projection, not the observed installation.
Each attempt also carries measured denial targets keyed by its declared denial cases. A target
binds case, target kind, optional fixed workload role, service invocation, cgroup, boot identity,
control response and a case-specific probe digest committing to the endpoint/object and operation.
Witness targets must equal this context; role-backed targets also match the measured roster.
Sibling targets use `candidate-recipient`; own-app/input/outer-role/cgroup targets use
`candidate-sender`. Control-side targets cannot alias workload invocations or cgroups. Missing
targets, duplicate probe commitments across the entire assessment (including separate attempts),
and cross-case witness reuse reject. Context shape and
digest equality do not authenticate its measurements or execute an attack; those remain explicit
installed-driver obligations. Previous contract revisions cannot satisfy v4.

The next composed-budget work remains PR-309's import/fetch concurrency, timeout, cancellation,
retry and owner-terminal causality, followed by dependent window/store/restart/privacy cases.
Workload isolation does not close Mail lifecycle, migration, long-run or independent review.
