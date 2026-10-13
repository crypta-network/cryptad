# PR-317 namespace-bound composed-budget lifecycle

This runbook defines the bounded Phase 12 remediation that connects the composed app-network
budget workload to controller-owned roles and adds causal consumers for five lifecycle cases.

## Source, scope, and status

Implementation starts from merged PR-316 squash
`3a756199396ea74aeb9a1f85ae785c2f778d49ac`, tree
`943167d0895b2d4ad5a17ed216441da7eb2ad18e`, on
`feature/pr-317-namespace-bound-composed-budget-lifecycle`. The merged PR-316 feature head was
`08b2ac4f128a6cab561b4df38a05e17a576ab96f`; squash integration means literal feature-head
ancestry is not required. GitHub reported PR-316 merged on 2026-10-12 with its final Java CI,
CodeQL, restricted prerequisite, release-candidate dry-run, and SonarCloud checks successful.
The production publication job was skipped.

PR-317 implements code and local controlled validation. No Linux VM, cgroup-installed execution,
protected workflow, live node, publication, long soak, or independent security review was run
during implementation. A future installed result must bind the exact final source commit, fixture
manifest, product packages, runtime, role epochs, and retained private evidence. Until then the
installed directions are **not executed**, not failed and not passed.

The fixed composed-budget policy remains 31 mandatory cases. This slice adds consumers for:

```text
import-concurrency
fetch-concurrency
timeout
cancellation
retry
```

The following seven cases remain independently open:

```text
window-crossing
partial-rate-write
graph-store-unavailable
graceful-restart
abrupt-restart
diagnostics-unavailable
privacy
```

`fullAppBudgets` remains `not-observed`, and this work does not complete Phase 12.

## Reuse and gap matrix

| Boundary | Reused implementation | PR-317 addition or retained gap |
| --- | --- | --- |
| Native accounting | `AppNetworkBudgetService`, reservations, leases, fixed windows, nonrefundable durable charges | Exact `CONCURRENCY_LIMIT_REACHED` family/scope event; charging semantics unchanged |
| Owner lifecycle | Existing callback-owned terminal stage and normal-only deferred release | Snapshot v3 adds explicit normal and exceptional owner acknowledgment events |
| Isolation | Four fixed roles, opaque handles, systemd/cgroup epochs, namespace socket transfer, terminal receipts | Separate `pr317-namespace-bound-composed-budget-v1` execution class |
| Signed cohort | Normal bundle verification and AppHost install/start/session checks | Four exact synthetic budget bundles only on `candidate-sender`; other roles remain app-free |
| Worker binding | Controller kernel samples, cgroup and namespace identity, listener inode proof | Budget-specific AppHost plus non-Java `sleep` descendant binder; no Mail-JVM relabeling |
| HTTP/FCP transport | Controller-transferred fixed role sockets and no implicit reconnect | Spawned fixed clients, one socket/context per request, aggregate absolute deadlines |
| Evidence | Attachment v1/v2 legacy sequential routes and original journal binding | Private attachment v3 `causalCases`; public coverage schema stays version 1 |
| Installed cancellation | Safe client disconnect and controller-owned process cleanup | Disconnect is abandonment, not native owner cancellation; owner-cancelled installed direction remains unobserved |
| Privacy | Private role state, descriptor-based capture, closed public projections | PR-317 raw-record validator rejects sessions, insert URIs, private corpus, paths, and canaries |

The source audit found no charging, refund, or premature-release defect. It found missing causal
facts and installed drivers. No second limiter, scheduler, proxy, cancellation endpoint, or VM
framework was added.

## Fixed cohort and configuration

`pr317_budget_selection.py` creates a separate fixture contract. It does not extend historical
PR-315 or PR-316 fixture semantics. The selected app roster is:

| Role | Installed app IDs |
| --- | --- |
| `candidate-sender` | `feed-reader`, `budget-importer`, `budget-no-trust`, `budget-no-fetch` |
| `candidate-recipient` | none |
| `previous` | none |
| `relay-no-apps` | none |

These names identify disposable signed test subjects. In particular, the synthetic
`feed-reader` permissions do not change the shipped Feed Reader bundle or grant it new Trust Graph
authority.

The fixture contract binds bundle bytes, exact permissions, trusted-key registry, signed
synthetic statement, packaged products, JDK, verifier tree, driver/oracle/tool bytes, five case
IDs, failure policy, and normalized configuration. Its selection digest covers the complete
`budgetSelection`. The controller never accepts an app ID, URL, port, executable, PID, path,
budget value, or environment map from the observer.

The class-derived test configuration disables subscription scheduling and fixes finite rates. Its
concurrency values deliberately separate the two denial directions:

| Family | Per-app limit | Global limit |
| --- | ---: | ---: |
| Trust Graph import | 1 | 4 |
| Foreground content fetch | 2 | 1 |

An import holder therefore blocks a same-app direct-import contender at the app import family. A
different-app URI-import contender can reserve import capacity and then be blocked by the global
fetch family. Native tests separately cover app and global directions for both families.

## Controller-bound bootstrap and transport

`bootstrap-budget` is a fixed controller operation containing only the existing opaque role
handle. The controller derives all four app IDs from the retained selection, verifies each
installed tree, launch redirect, nonce, isolated origin, AppHost leader, signed non-Java worker,
listener, cgroup, namespaces, daemon epoch, and current session. It returns a fixed private app
context map plus the bounded, digest-verified synthetic statement bytes. Raw statement bytes are
used for owned FCP corpus setup and are not retained in causal or public results.

Every concurrent request runs in a spawn-created trusted observer process. Each client:

1. validates one immutable controller-issued app context;
2. obtains one new role-bound HTTP descriptor;
3. rechecks the role epoch on both sides of descriptor transfer;
4. waits at an explicit parent barrier;
5. applies one monotonic deadline to request send, response headers, and complete body reads; and
6. closes the descriptor and private management channel on every exit.

The client has no DNS, proxy, redirect, direct reconnect, local node process, host PID selector,
filesystem path, `Popen`, `killpg`, or signal-timer fallback. The operator runtime observation
route remains host/operator-only.

## Five causal consumers

| Case | Controlled/native proof | Installed driver | Current execution status |
| --- | --- | --- | --- |
| Import concurrency | Latch-controlled app and global denial; exact limiting family; no contender charge/work; recovery | Unpublished owned key holds URI import; same-app direct contender; delayed FCP fulfillment; recovery | Implemented; installed VM not executed |
| Fetch concurrency | Latch-controlled app and global denial; uncommitted import release; one fetch; retained holder charge | Different-app URI contender reserves import, hits global fetch holder, then recovers | Implemented; installed VM not executed |
| Timeout | Real owner callback distinguishes timeout, normal acknowledgment, exceptional acknowledgment, and release ordering | Short bounded attempt retains only a genuinely observed post-response owner tail; otherwise `not-observed` | Implemented; installed VM not executed |
| Cancellation | Causal reader accepts only authenticated cancelled request plus real normal owner tail; exceptional/missing tail fails | Client disconnect exercises abandonment and retained-capacity safety only | Consumer implemented; owner-cancelled installed direction remains unsupported/unobserved |
| Retry | Separate attempts, native IDs and charges; imported first result and duplicate retry; no refund or guessed result | First response is deliberately abandoned, native graph/history is observed, then one fixed retry runs | Implemented; installed VM not executed |

Owner-terminal acknowledgment is a fact used by timeout and cancellation. It is not a sixth case
and does not replace any mandatory case.

## Causal attachment v3

Attachment versions 1 and 2 and their legacy route ordering remain unchanged. Version 3 retains
all v2 bindings and `segments`, then adds at most five closed `causalCases`. Each row binds one
collector/node epoch, a contiguous native sequence window, every parent/import/fetch operation,
before/during/after valid diagnostics, reconstructed concurrency and reserved-rate holds, graph
counts, complete rate attribution, request outcome, owner outcome, retry relationship, and
unresolved/censored state.

The reader rejects:

- the wrong limiting family or scope;
- balanced counts without actual overlap;
- a missing during-hold snapshot;
- contender work or charging after denial;
- release before normal owner acknowledgment;
- exceptional or missing acknowledgment used as release credit;
- ring loss, invalid diagnostics, event gaps, or epoch substitution;
- unexplained concurrent rate changes; and
- retry ID reuse, child borrowing, refunds, or guessed first-attempt success.

Native snapshot version 3 adds only:

```text
CONCURRENCY_LIMIT_REACHED
FETCH_CANCEL_REQUESTED
FETCH_OWNER_TERMINATED
FETCH_OWNER_TERMINATION_FAILED
```

The first reports the actual saturated family, opaque limiting scope, held count, and denied
operation ID. `FETCH_CANCEL_REQUESTED` is emitted only after the existing runtime owner
cancellation API is invoked on timeout or thread interruption; a caller-authored outcome or HTTP
disconnect cannot substitute it. Normal acknowledgment is recorded before legacy `FETCH_FAILED` and deferred
releases. Exceptional acknowledgment records failure and retains uncertain holds. V1/v2 evidence
does not accept these new kinds. Runtime-pressure attachment v3 admits the new native snapshot
version and vocabulary without awarding any new pressure or full-budget claim; pressure v1/v2
remain closed.

## Runner, cleanup, and public output

`pr317_budget_runtime_runner.py` is a one-attempt host runner. It reuses the PR-316 copied-VM,
storage budget, PVE inventory, memory admission, host watcher, and retained terminal receipt
mechanics. It selects only the PR-317 execution class and has no case, campaign, key,
publication, or arbitrary-command selector.

The terminal order is:

```text
causal collection
 -> explicit owner result or unknown state
 -> controller-owned role stop
 -> private tmpfs capture
 -> four role receipts and guest stop
 -> private evidence revalidation
 -> identifier-free public projection
```

Role/process death can prove cleanup. It cannot fabricate an in-process owner callback. The public
projection contains fixed case codes, safe counts, an approved source identity, and false
completion flags. The private selection digest is used for validation but omitted from public
output. Public output never contains app sessions, worker/process tokens, insert keys, raw
statements, private
paths, command lines, or exception text.

## Local verification

The implementation uses Java 25+, `python3`, and the Gradle wrapper. Focused checks include:

```bash
./gradlew :platform-api:test

PYTHONPATH=tools/release-certification:tools/release-certification/restricted:tools/interop \
  python3 -m unittest discover -s tools/interop \
  -p 'test_cross_version_installed_budgets.py'

PYTHONPATH=tools/release-certification \
  python3 -m unittest discover \
  -s tools/release-certification/cryptad_certification/tests \
  -p 'test_composed_budget*.py'

PYTHONPATH=tools/release-certification:tools/release-certification/restricted:tools/interop \
  python3 -m unittest discover -s tools/release-certification/restricted \
  -p 'test_pr317_budget_*.py'

python3 -m unittest discover -s tools/release-certification/protected \
  -p 'test_pr317_protected_budget.py'
```

The protected discovery suite includes Linux/cgroup/socket tests that cannot execute completely on
macOS. A skipped or host-blocked test is reported as such; guards are not disabled.

## Compatibility and residual obligations

PR-317 does not change Platform API 1.0 membership, app-visible operator authority, wire formats,
persistent budget records, Trust Graph document formats, fixed-window accounting, graph
deduplication, release baselines, historical PR-315/316 results, or approved resource fingerprints.
The shared PR-314 driver remains at its enforced 5,000-line cap; PR-317 orchestration is in new
modules.

The next dependency-justified slice is PR-318: fixed-window and partial-store-failure evidence for
`window-crossing`, `partial-rate-write`, and `graph-store-unavailable`. Graceful/abrupt restart,
diagnostic unavailability, and complete privacy remain separate until their full contracts are
implemented and observed. Finite-native acceptance, original protected operations, installed Mail
evidence, independent review, baselines, and long-duration gates remain open.
