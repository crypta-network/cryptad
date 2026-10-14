# PR-319 composed-budget restart and diagnostics evidence

This runbook records bounded process restart and strict diagnostic failure observations for the existing composed-budget owner.

## Source and scope

The verified starting integration is PR-318 squash `9513287a4d8eeff51cd3431a0b03a13c77242564` on `develop`; GitHub reported PR #1420 merged at `2026-10-13T18:45:04Z`. Its replaced feature head is not an ancestry prerequisite. Work uses `feature/pr-319-composed-budget-restart-diagnostics`.

This slice owns `graceful-restart`, `abrupt-restart`, and `diagnostics-unavailable`. The fixed 31-case cohort, all 49 Phase 12 requirements, original experiment deadline, and historical assessment cutoffs remain intact. Process restart over the same mounted tmpfs is separate from guest reboot, power failure, exactly-once import, and native cancellation.

## Restart state ledger

| State | Restart oracle |
| --- | --- |
| Completed durable rate charge | The complete stored record survives under the same store and applicable window; death gives no refund. |
| Uncommitted in-memory rate reservation | Restart does not promote it into a durable charge. |
| Active process-local lease | Capacity belongs to its service instance; new capacity is usable only after exact old process death and role quiescence. |
| Unknown deferred owner termination | Old outcome remains unknown; process death is not normal owner acknowledgment. |
| Committed graph statement and metadata | Actual retained files supply the complete selected and unrelated control readback. Equal cardinality alone is insufficient. |
| In-flight or ambiguous graph attempt | Independent retained-file reconciliation may explain state; failed HTTP does not establish rollback. |
| Collector and operation IDs | Each collector is a new epoch; reused small IDs are distinct. |
| App principal and session | Rebootstrap retained signed installs against current controller, daemon, worker and listener bindings. |
| Experiment authorization | The original deadline and cohort remain unchanged; cleanup grants no restart permission. |

Full rate records and selected graph facts are compared before any chargeable recovery operation. A retained old minute is preserved until native lazy-window replacement; unchanged-window decrements fail. No whole-node-directory equality, clock change, quota rewrite, store repair, or bundle reinstall supplies continuity.

Fixture selection requires at least 70 seconds before the selected hour boundary: the runtime stops admitting work 60 seconds before that boundary, and the fixed start margin reserves another 10 seconds. Startup delays can still exhaust this window; the runtime rechecks the original cutoff and fails without moving the selected hour.

The authorized `maxSeconds` must equal the plan's `requestedSeconds`, with both set to an integer from 60 through 3,600. The selection digest binds `maxSeconds`; protected admission rejects a divergent duration before campaign creation or role startup. The host verifier checks the same identity against the prospective fixture.

The operation allowance must be at least 772 and at most 10,000. The minimum accounts for the four-role setup, two readiness attempts per start, bounded peer/native polling, initial app installation, 32-request exhaustion setup, all three restart variants, both diagnostic variants and final readback. Preparation, retained-fixture verification and protected admission enforce the same minimum before role startup. The selection digest binds `maxOperations` alongside `maxSeconds`, so changing the allowance invalidates the selected identity before campaign creation or role startup; further provider-readiness retries remain subject to the caller's finite operation cap and original deadline.

## Execution status

The bounded local implementation and verification are complete; installed acceptance is not executed. No installed VM, managed host allocation, live-node action, protected workflow, merge, or publication is authorized or claimed by this local task. Installed acceptance requires separately executed exact product/helper/selection bytes and original administrator and terminal records.

## Reuse and implementation

| Owner | Reused boundary | New executable behavior |
| --- | --- | --- |
| Native API and stores | Production `TrustGraphApiHandler`, `AppNetworkBudgetService`, real budget and graph file stores | Separate Java processes execute settled graceful/forced restart and a latch-observed interrupted URI owner. Complete records and graph facts are read before recovery work. |
| AppHost and controller | Signed four-app cohort, controller-derived sockets, normal retained installs and current capability checks | Fresh handles, host bootstrap, normal retained worker start and controller rebootstrap after each new role generation; no reinstall or permission approval. Root controller retains per-generation bootstrap originals. |
| Administrator test kit | Exact role locks, pidfds, cgroup/manager ownership, safe descriptor readers and stop helper | Fixed normal-exit observation, exact selected JVM SIGKILL, permission faults, original intent/stop records and complete bounded private readback. |
| Certification | Existing composed owner, journal, scoped runtime measurements and Phase 12 policy | Dedicated attachment v5 delegates cross-epoch and interval oracles to `composed_budget_restart_evidence.py`. Original installed matching remains a separate host step. |
| Host runner | PR-316/318 one-attempt copied-VM, PVE inventory, capacity and watcher admission | Separate prospective `pr319-composed-budget-restart-diagnostics-v1` selection, original private validation, terminal cleanup and allowlisted public projection. |

Production quota charging, refunds, leases, persistent formats, graph retention rules, Platform API 1.0 membership and native snapshot v4 are unchanged. Attachment v1–v4 consumers retain their original strict meanings; the storage `_ledger()` and `_holds()` are not relaxed for a crash. The installed adapter now recognizes the already selected PR-318 cohort as well as the new class, closing its previous early admission gap.

The fixed installed seed includes nonzero import counters, an exhausted unrelated app's import hour, a production subscription refresh in that app's separate family, a selected graph statement and a distinct synthetic unverified graph control. The latter follows normal native retention and explicitly retains `signatureVerified=false`; it supplies no signed-statement acceptance claim. Native tests use separate signed selected and control documents. Selected duplicate recovery may update its own metadata only when native duplicate outcomes explain it; unrelated graph metadata remains equal.

## Required variants and failure models

| Requirement | Mandatory installed variants | Local executed evidence |
| --- | --- | --- |
| `graceful-restart` | `settled-graceful` | Actual Java process exit, retained settled state, independent recovery charge; simple worker-only JVM restart is a negative control. |
| `abrupt-restart` | `settled-abrupt`, `inflight-abrupt` | Actual forced process death, retained files and observed active reservation/fetch prefix. The interrupted prefix stays censored. |
| `diagnostics-unavailable` | `enumeration-only`, `required-key-unreadable` | Actual POSIX permission faults plus malformed, identity mismatch, special member and bounded strict enumeration failures; valid empty, live transient holds and symlink behavior are separate controls. |

Installed normal shutdown uses the ordinary role-bound FCP `Shutdown` request. A fixed root test-kit watcher observes only the kernel-bound daemon through `PTRACE_SEIZE`/`PTRACE_EVENT_EXIT`. Graceful classification requires actual normal JVM exit zero, natural wrapper/manager completion, the effective stop profile and the exact trusted stop receipt. Manager success or disappearance alone is insufficient. Forced termination uses only that selected JVM's retained pidfd, preserves the original fault intent, observes death and reconciles the old role and descendants before a new start. Its exit status remains unknown when pidfd evidence supplies no wait status.

The permission test derives only the selected synthetic `feed-reader` scope. A probe drops to the actual role UID and opens a fresh descriptor to measure enumeration and exact-key access. Recovery restores access on the retained original inode and never copies old counter bytes. Path substitution, changed generation, old-owner survival or mount identity changes fail. Active permission faults cannot be combined with restart. Current manager semantics and Linux ptrace/permission support must be observed on the actual installed provider; macOS cannot establish them.

The operator route samples its event ring before strict diagnostics. The driver retains the first invalid response and performs a second actual sample to observe its newly recorded failure; it does not inject an event. `valid=false` with empty usage is unavailable durable usage. A missing HTTP response remains missing and cannot satisfy this variant. Only the diagnostics oracle admits that invalid middle interval; healthy accounting cases still reject it.

A ring is volatile. No release, request success, final old counter sample or normal owner acknowledgment is appended after abrupt death. Zero new leases describes only the new service. The actual last prefix, original stop/fault witness and independent post-restart readback remain separate. This does not prove cancellation, exactly-once import, arbitrary write cutpoints or power-loss durability.

The `inflight-abrupt` prefix must contain a started URI-import owner, its linked import reservation and admitted `FETCH_INVOKED` child, and live app/global import and fetch holds. Outstanding reservations alone cannot credit this variant; a terminal request or fetch outcome also prevents interrupted-owner credit.

## Original evidence and private retention

Each accepted installed phase binds native collector epoch and original app-to-scope mappings to root-read complete records. Native usage order is the production store's app/family sort order; scope numbers are never initialized to force equality. Original records retain actual minute/hour windows and all decision metadata. The selected real import hour and original campaign deadline do not move; a missed hour fails. Host UTC brackets cover every phase, including invalid `during`, and monotonic values remain in their original domains.

The host verifier independently checks administrator receipt order, actual daemon identities, archived stop receipts, unchanged boot/tmpfs mount ID and inode/device identity, root-retained controller bootstrap contexts and fresh workers. It compares graph metadata and all rate families, not just totals or graph cardinality. A self-consistent guest result paired with another original stop, fault, bootstrap or file sample rejects.

Each forced terminal receipt requires exactly one retained `fault-intent` for the same case, daemon, generation, manager invocation, boot, campaign, selection, deadline, data identity and fault start time. Its intended signal must match the terminal `SIGKILL`, and both monotonic times and receipt order must place the intent between the preceding snapshot and termination. Missing, duplicate, mismatched or reordered intent receipts reject the original history.

The intent and terminal receipt retain the exact same daemon sample. Comparison with the preceding snapshot uses PID, start time, executable digest and PID/network/mount/user namespace identities; RSS and thread count may change between those independent samples.

The bounded JSONL checkpoint stream is fsynced before transitions and includes interruptions and uncredited first invalid samples. Complete private files and original root diagnostics are captured through the existing safe fixed descriptor reader while tmpfs is still mounted. PR-319 uses a separate fixed 262 KiB root diagnostics writer/capture ceiling to retain complete originals; older classes keep their 64 KiB ceiling. The shared campaign source cap remains 5,000 lines; finite dispatch is extracted into a cohesive helper.

Terminal order is retained prefix, fixed transition, new observations, permission restoration, all-role stop and quiescence, private mounted-state capture, watcher/guest stop, original validation, then public projection. A retained guest disk cannot replace missing tmpfs or a lost native ring. Public output exposes censored variants explicitly and retains overall `incomplete` status when an owner tail is censored. It permits fixed cases/variants/reasons, safe counts and approved source identity only; phase, release and full-budget completion stay false. Plain, URL-encoded and Base64 private canaries reject public/error surfaces. Typed private graph/original records are never a general public-scan exception.

## Commands and verification

Run registered Java tasks sequentially with the wrapper and Java 25+:

```bash
./gradlew :platform-api:test :platform-trustgraph:test :bridge-http-runtime:test --continue
./gradlew :platform-devtools:installDist assembleCryptadDist
./gradlew --quiet sonarlintFile \
  -Psonarlint.file=platform-api/src/test/java/network/crypta/platform/api/TrustGraphProcessBudgetTest.java

PYTHONPATH=tools/release-certification python3 -m unittest discover \
  -s tools/release-certification/cryptad_certification/tests -p 'test_composed_budget*.py'
python3 -m unittest discover -s tools/interop -p 'test_cross_version_installed_restart_budgets.py'
PYTHONPATH=tools/release-certification:tools/release-certification/restricted:tools/release-certification/protected:tools/interop \
  python3 -m unittest discover -s tools/release-certification/restricted -p 'test_pr319*.py'
python3 -m unittest discover -s tools/interop -p 'test_cross_version_installed_budgets.py'
python3 -m unittest discover -s tools/release-certification/restricted -p 'test_pr318_storage_installed.py'
python3 -m unittest discover -s tools/release-certification/protected -p 'test_restricted_workload*.py'
python3 tools/release-certification/certify.py network-scale-soak --self-test
python3 tools/release-certification/certify.py cross-version-soak --self-test
python3 tools/release-certification/certify.py stable-maintenance --self-test
python3 tools/release-certification/certify.py phase-12-closeout --self-test
```

The real Java producer writes owner-only observations and separate parent-owned originals under `platform-api/build/test-results/pr319-native`. The Platform API test task declares that directory as an output and clears it before execution, so skipped or failed producers cannot leave earlier exports available to the Python integration. A filtered test run also replaces the entire export set; the integration rejects partial sets and skips when no producer files exist. The scoped integration uses the actual three process and six diagnostic exports unchanged. Its fixed expected 31-case inventory is a separate test fixture; it never generates expected pass objects from the implementation. The measurement reaches the existing journal and `maintenance-measurements` verifier with three local cases observed and 28 missing, original provenance unverified and runtime execution unobserved.

The host fixture preparer and actual one-attempt runner are usable entry points:

```bash
python3 tools/release-certification/restricted/pr319_restart_selection.py --help
python3 tools/release-certification/restricted/pr319_restart_runtime_runner.py --help
```

Their required arguments bind clean exact helper source, Linux products/JDK, signed bundles, synthetic statement, immutable selected hour, original host identity and task-wide disk/memory limits. This is preparation documentation, not VM allocation or execution authorization. Prior disposable VM inventory, retained failures, backing dependencies, free-space reserve, fresh PVE admission and watcher records remain mandatory. No VM or image copy was allocated during this local implementation.

Verification uses Microsoft OpenJDK 25.0.4.1. The complete Platform API suite passed 1,343 tests and Trust Graph passed 84 with zero skips. The new native slice is 13 tests with zero final skips. An earlier final-minute process attempt skipped three restart variants; a later genuine producer run established the positive traces. Schema/clock integration errors were corrected in producer source and rerun rather than by editing observed JSON. Earlier producer bytes and logs remain under the private build evidence roots.

HTTP bridge ran 135 tests with four failures. All four reproduced by exact test name and message in the verified `9513287a4d8eeff51cd3431a0b03a13c77242564` baseline checkout; their fixture trust bootstrap rejects the macOS ancestor path. The full result is not green. Supported developer-tool installation and distribution assembly passed. All three final focused SonarLint reports are empty after test-code refactors; the corrected Error Prone diagnostic probe emits no introduced warning. No full repository Java suite was run: production Java behavior and formats are unchanged, and the owning suites cover the added test sources.

The composed Python suite passed 78 tests, the new installed helper suite passed 24, and new restricted suites passed 34 with four Linux-only skips (two kernel-exit and two root/role UID access tests). Legacy installed clients passed 12 and PR-318 installed offline tests passed 19. The broad protected workload suite passed 193 with 35 skips after explicit local-socket access; the first sandboxed run had one failure and four socket/subprocess errors. Network-scale passed three tests after its blocked local HTTP test was rerun; cross-version passed 154 with 12 skips, maintenance passed 247, and final Phase 12 self-tests passed 185. These are offline/local checks, not installed VM acceptance.

Exact predecessor CI reads confirmed head `f636c0b185d15e3c7f1fe0581d09afe18d3f2c83`: [Java CI 38436776261](https://github.com/crypta-network/cryptad/actions/runs/38436776261), [Beta dry-run 38436776193](https://github.com/crypta-network/cryptad/actions/runs/38436776193) and [restricted prerequisite 38436776225](https://github.com/crypta-network/cryptad/actions/runs/38436776225) succeeded. Production Beta publication was skipped. They are predecessor observations, not CI for this change or installed execution results.

## Assessment and handoff

The fresh before/after assessments use explicit cutoff `2026-10-13T18:53:03Z` and disjoint private output roots. They retain 49 mandatory requirements, 47 unresolved and Phase 12 incomplete. The historical PR-318 cutoff `2026-10-13T09:39:26Z`, tracker, residual histories and earlier results remain unchanged. The prospective PR-319 disposition adds reviewed source/test paths and refreshes changed-source byte pins without changing accepted assertions, dimensions, owners, implementation states or original authorities. Eight inherited pin discrepancies verified against the exact starting integration remain visible.

Local native implementation progress is separate from installed acceptance. All five installed variants remain **not executed** here; Linux kernel/UID tests, exact packaged selection, original campaigns, resource approvals and terminal guest evidence are still needed. Complete privacy remains open, as do native owner cancellation in the installed lane, remaining PR-318 storage directions, earlier Mail/finite-native obligations, protected originals, independent review, resource baselines and long runs. `fullAppBudgets` is unobserved. Historical 45/45 workload completion does not transfer to these changed bytes.

The next bounded slice is tentatively PR-320: complete composed-budget privacy/export coverage and full-cohort admission while retaining every earlier missing cancellation, restart/storage and protected observation. This PR does not complete Phase 12.

Provider references: [Linux tmpfs lifetime](https://docs.kernel.org/filesystems/tmpfs.html), [systemd v257 kill procedure](https://raw.githubusercontent.com/systemd/systemd/v257/man/systemd.kill.xml), [systemd v257 service semantics](https://github.com/systemd/systemd/blob/v257/man/systemd.service.xml), and [Java 25 Files.move](https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/nio/file/Files.html#move(java.nio.file.Path,java.nio.file.Path,java.nio.file.CopyOption...)). Actual installed versions remain a provider observation; these references confer no deployment authority or stronger durability guarantee.
