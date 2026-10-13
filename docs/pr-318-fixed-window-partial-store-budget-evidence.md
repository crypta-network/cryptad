# Fixed-window and partial-store budget evidence

This runbook describes the three PR-318 budget requirements: `window-crossing`,
`partial-rate-write`, and `graph-store-unavailable`.

## Starting source and scope

Implementation starts at PR-317's verified squash on `develop`,
`b2ba948a9820d2c46f02f016ca75722151a8a11e`. Its tree,
`2ea15a5aa22f2fc53d7da4024ac3d55aa596104d`, equals the inspected PR-317 head
`af77940a91f0c961e88f529944e3d94183f76479`. GitHub reported PR #1419 merged
on October 13, 2026, at 09:19:53 UTC. The predecessor's successful CI checks
are predecessor evidence; the production Beta publication job was skipped.

The owning policy retains 31 budget requirements and 49 mandatory Phase 12
assertions. Graceful restart, abrupt restart, diagnostics unavailable, privacy,
and installed native cancellation retain their separate outstanding scope.
Local reopen tests do not close restart requirements. No original installed or
protected execution is supplied by this implementation request.

## Accounting oracle

Every rate identity includes opaque scope, family, window start and duration.
Import windows last 3,600 seconds; foreground/global fetch windows last 60 seconds.
Ordered import writes are app then global. Ordered URI fetch writes are app
foreground then global content fetch. Subscription writes remain app poll,
global poll, then global content fetch.

| Route and phase | Expected returned writes | Permissible persisted state | Transient capacity and graph | Recovery and evidence |
| --- | --- | --- | --- | --- |
| URI import reserves in W0, commits with W1 capacity | Both fetch families in their fetch minute; both import families in W1 | Fetch charges retained; import W1 replaces any stored W0 record | W0 pending holds release once; import concurrency encloses graph work and releases on close | Normal imported/duplicate verdict; controlled clock or separately observed real hour |
| URI import reserves W0, legitimate work consumes W1 | Fetch families plus every competing operation's acknowledged writes; no import charge for denied reservation | All legitimate charges retained; denial metadata may replace a record without an increment | Old pending holds release; no parse or graph attempt after denied commit; close releases owned concurrency | Separate later admitted request, under actual capacity; no quota reset |
| Direct acquisition or URI child acquisition fails at family N | Exactly families before N | Before-delegate model: prefix N−1. After-delegate model: prefix N. OS I/O alone: target N unknown until readback | Failed acquisition owns no new lease; URI outer reservation closes; no denied child fetch | Reopen real budget store; preserve prefix, restore access only, independently charge recovery |
| URI import commit fails at family N | Existing fetch charges plus import prefix N−1 | Import prefix N−1 or N according to actual readback; fetch unchanged | Original pending holds release once; concurrency stays until close; no parse or graph attempt | Cached denial does not write again; a new request pays its own charges |
| Direct/URI graph call fails before delegation | All required budget writes acknowledged | Selected graph unchanged only with proven cutpoint and complete private readback | Graph attempt has unknown native verdict; request fails; normal cleanup | File-backed controlled model or installed denial; restore access, reconcile, retry normally |
| Direct/URI graph delegate returns then decorator throws | All required budget writes acknowledged | Selected statement or duplicate metadata may have persisted; cardinality alone is insufficient | Native graph verdict unknown; failed response is not rollback | Reopen and compare canonical statement and metadata; successful retry is usually duplicate |
| Graph verdict returns, subsequent audit append fails | All required budget writes acknowledged | Graph result remains confirmed; audit outcome is separate | Failed request does not erase native imported/duplicate fact | Inspect audit independently and preserve original graph result |

`RATE_WRITE_ATTEMPT` records proposed count immediately before the owning store call.
`RATE_CHARGED` means that call returned. `RATE_WRITE_UNKNOWN` means it threw I/O;
it never asserts that no bytes changed. Decision-only writes have separate
`RATE_METADATA_WRITE_ATTEMPT`, `RATE_METADATA_WRITTEN`, and
`RATE_METADATA_WRITE_UNKNOWN` facts. These facts retain operation, family, opaque
scope and window identity and contain no paths or exception messages.

A trustworthy complete later read establishes reconciliation. Invalid diagnostics
remain unknown, never an empty zero-usage view. Healthy recovery is a separate
successful native operation with its own charges. No compensating decrement is
permitted. Authorized old-window replacement is not a refund.

## Evidence versions and limits

Native snapshot v4 adds only the five storage-write kinds above. Attachment v4
retains v3 lifecycle cases and adds a separate `storageCases` collection. Historical
v1/v2 order and the closed v3 five-case vocabulary remain unchanged. Current
producers must use v4 when forwarding v4 native events; filtering or renumbering
native events would destroy complete sequence attribution.

Controlled service clocks and actual recorder UTC remain distinct. A controlled
future-window test cannot establish elapsed installed time. Before/after-delegate
decorators use actual file stores but do not certify a particular post-rename OS
failure. Budget temp-and-replace and graph file-force/directory-force behavior have
different provider guarantees. Neither local tests nor reopen checks establish
host-crash or power-loss durability. This work introduces no WAL, cross-store
transaction, refund mechanism or production fault endpoint.

## Reuse and implementation

| Owner | Existing behavior reused | Added verification |
| --- | --- | --- |
| Budget service | Serialized decisions, fixed windows, reservation caching and ordered family writes | Passive correlated attempt/return/unknown events, including denial metadata; no accounting change |
| File-backed service tests | Before/after-delegate fault matrix for import, URI fetch and subscription families; existing import-hour tests | Exact attempted and acknowledged prefixes, unrelated records, independently charged recovery, W1 pending contention and close-before-commit |
| Trust handler and graph store | Real direct/URI routing, parser/signature checks, independent budget families, statement and audit stores | Thirty signed-statement handler executions, before/after graph ambiguity, duplicate metadata, audit failures, all composed write positions and six clock directions |
| Causal readers | Original operation/parent IDs, epochs, complete rate attribution and deferred owner semantics | Closed v4 storage reader; original Java exports consumed without rewriting time; strict owning journal admission |
| Installed roles | PR-317 signed cohort, fixed role connections, spawned HTTP clients, bounded FCP key fulfillment | Separate selected execution class and administrator-only fixed filesystem actions |
| Resource/authority boundary | Existing copied-VM runner, disk/PVE/memory admission, private capture and root terminal records | Exact fixture/selection/observed-time binding and original administrator receipt comparison; no new release authority |

`TrustGraphStorageBudgetTest` emits 26 private native trace files for the graph,
rate and clock cases. The four additional executions cover audit failures and
actual managed-directory obstruction. The Python reader verifies all 26 traces:
23 selected observations and three same-hour/minute/backward controls. These are
controlled native file-backed observations, not installed observations.

The native ring remains bounded at 4,096 events and performs no I/O. Complete
observations reject ring loss. The v4 reader distinguishes unavailable enumeration
from an empty valid rate view, checks window-specific reservation release and
every successful recovery's own charges, and binds graph reconciliation to the
selected statement fingerprint computed independently during fixture preparation by
the production parser. Installed wall and monotonic elapsed time must agree within
one second. Separate host UTC brackets verify the guest clock before and after the
workload and prove that the selected boundary elapsed in the host clock domain.
Private hashes and fingerprints are not public-safe data.

## Fixed installed procedure

No installed VM or protected operation was authorized or executed for this change.
The executable profile implements these representatives:

| Requirement | Installed representative | Missing installed directions |
| --- | --- | --- |
| `window-crossing` | Available-capacity URI import across its actual UTC hour | Contested current-hour capacity |
| `partial-rate-write` | Direct import: app family returns, global directory denies the later write | URI fetch admission, post-fetch import commit, and after-write ambiguity |
| `graph-store-unavailable` | Normally primed signed statement; direct duplicate update denied, reconciled and retried | Fresh insert, URI import and after-write ambiguity |

The profile retains PR-317's import concurrency of one per app. It cannot claim a
same-app competing operation. Controlled native tests cover the contested case
with an appropriate separate configuration. A future installed contested profile
requires a new prospective selection, not active quota mutation.

Prepare with a clean exact helper source, supported devtools/distribution outputs,
the four signed synthetic bundles, a signed statement and the existing approved
disposable image. The variables below are private operator inputs. Selecting them
does not authorize a VM allocation or change to another node.

```bash
python3 tools/release-certification/restricted/pr318_storage_selection.py \
  --source "$SOURCE" --output "$PREPARED_FIXTURES" \
  --candidate "$CANDIDATE_ARCHIVE" --previous "$PREVIOUS_ARCHIVE" \
  --java-home "$JAVA_HOME_25" \
  --feed-reader "$FEED_READER_BUNDLE" --budget-importer "$BUDGET_IMPORTER_BUNDLE" \
  --budget-no-trust "$BUDGET_NO_TRUST_BUNDLE" --budget-no-fetch "$BUDGET_NO_FETCH_BUNDLE" \
  --trusted-keys "$TRUSTED_KEYS" --statement "$SIGNED_SYNTHETIC_STATEMENT" \
  --candidate-commit "$CANDIDATE_COMMIT" --previous-commit "$PREVIOUS_COMMIT" \
  --jdk-digest "$JDK_DIGEST" --max-seconds 3600 --max-operations "$MAX_OPERATIONS" \
  --boundary-epoch-second "$BOUNDARY_EPOCH_SECOND"

python3 tools/release-certification/restricted/pr318_storage_runtime_runner.py \
  --probe --source "$SOURCE" --output "$ATTEMPT_OUTPUT" \
  --prepared-image "$PREPARED_IMAGE" --qemu-root "$QEMU_ROOT" --seed "$SEED" \
  --ssh-key "$SSH_KEY" --known-hosts "$KNOWN_HOSTS" \
  --prepared-fixtures "$PREPARED_FIXTURES" --storage-root "$TASK_STORAGE_ROOT" \
  --product-source-commit "$CANDIDATE_COMMIT" \
  --prepared-image-digest "$PREPARED_IMAGE_DIGEST" \
  --fixture-manifest-digest "$FIXTURE_MANIFEST_DIGEST" \
  --storage-budget-bytes "$STORAGE_BUDGET_BYTES" --min-free-bytes "$MINIMUM_FREE_BYTES" \
  --memory-budget-bytes "$MEMORY_BUDGET_BYTES" --min-host-memory-bytes "$MINIMUM_HOST_MEMORY_BYTES"
```

The probe does not allocate an attempt. The actual authorized attempt uses the
same runner arguments without `--probe`. Existing inventory, minimum free space,
task-wide storage budget, PVE pre/final inventory, memory and pressure requirements
remain mandatory. No VM inventory or allocation was performed during implementation.

The selected hour must be 60–3,600 seconds after selection. Record its UTC time
and the start time ten seconds earlier in the private plan before launch. Setup
must leave enough of the independently authorized campaign interval for that exact
hour and the original 45-second request/owner bounds. The collector observes the
actual import reservation in W0 before publishing the owned content key in W1.
Missing the interval or losing the bounded fetch yields not-observed evidence;
the runner never selects a later hour automatically. No clock is changed.

The trusted administrator derives two targets from the authenticated candidate
role layout: the global budget counter directory and graph statements directory.
It checks role tmpfs mount, UID, inode, device and modes; retains a restoration
descriptor; removes directory write access; and probes actual `EACCES` under the
daemon role UID. Existing records remain readable. It restores access only before
teardown, never old counter contents. Path substitution restores the retained inode
when safe but rejects completion. The observer receives no arbitrary path, chmod,
mount, shell or controller fault selector.

The host compares observer receipts against the separately captured administrator
record, original selection and final role generation. Verified fixture product,
runtime, tool, limit and time-plan identities must match the selected plan. The
window row's immutable time-plan fields must also match that selection, so a
self-consistent rehashed later-hour record is insufficient. Every row's graph target
must match the fixture's independently parsed document fingerprint; a guest-reported
replacement target is insufficient.

## Private retention

Native test exports use owner-only permissions on POSIX providers. Installed
observations and selected graph metadata remain in fixed private files. The bounded
`pr318-storage-attempts.private.jsonl` checkpoint stream retains original observations
before, during and after each attempt, including interruptions. It is fsynced,
limited to 4 MiB and captured before guest shutdown. Its typed parser rejects
credentials, duplicate keys and unknown record forms. Unknown samples remain null.

Public projections contain only fixed case/variant/status codes, limited counts,
approved source identity and evidence class. They report resilience-test outcome
separately from business-import outcome. Raw graphs, fingerprints, source URIs,
filesystem identities, private receipts and transcripts are excluded. The current
build workflow uploads typed CI facts and selected product files, not raw native
trace directories. A retained QCOW2 does not preserve vanished tmpfs evidence.

## Verification commands and results

```bash
./gradlew :platform-api:test :platform-trustgraph:test :bridge-http-runtime:test --continue
./gradlew :platform-devtools:installDist assembleCryptadDist

PYTHONPATH=tools/release-certification python3 -m unittest discover \
  -s tools/release-certification/cryptad_certification/tests -p 'test_composed_budget*.py'
python3 -m unittest discover -s tools/interop -p 'test_cross_version_installed_budgets.py'
python3 -m unittest discover -s tools/release-certification/restricted -p 'test_pr318_storage_installed.py'
python3 -m unittest discover -s tools/release-certification/restricted -p 'test_pr317*.py'
python3 -m unittest discover -s tools/release-certification/protected -p 'test_pr317_protected_budget.py'
python3 tools/release-certification/certify.py network-scale-soak --self-test
python3 tools/release-certification/certify.py cross-version-soak --self-test
python3 tools/release-certification/certify.py stable-maintenance --self-test
python3 tools/release-certification/certify.py phase-12-closeout --self-test
```

Java verification used Microsoft OpenJDK 25.0.4.1 and the wrapper. The complete
Platform API suite passed 1,330 tests and Trust Graph passed 84. All 30 new handler
executions passed. Bridge HTTP retained four pilot-fixture failures caused by
ancestor-symlink rejection. `installDist` and `assembleCryptadDist` completed.

The full `test` invocation initially had 93 failures. Its one task regression was
an old native-v3 assertion, corrected to v4. The final full retry after test cleanup
reported 91 failures across nine other modules; changing `TMPDIR` did not repair
the existing Gradle test-worker path behavior. Diagnoses include `/var` versus
`/private/var`, ancestor-link rejection and boundary scanners admitting historical
`.stversions` Java copies. Some launcher/bootstrap results remain separately
unresolved; this is not a green full suite. The root suite passed 13,753 tests with
ten skips. No predecessor test counts were used for these results.

Focused SonarLint reports for both changed production files and the new handler
test are empty. Introduced findings in the expanded budget test helper were fixed;
its thirteen preexisting findings remain documented separately from task exit status.

The focused Python checks passed 64 composed-budget tests, 15 new installed-path
offline tests, 30 predecessor restricted budget tests, seven protected budget tests,
12 installed-client tests, five scheduler-input tests and 24 runtime-pressure tests.
The relevant maintenance sealed-reader discovery passed 69 tests with 13 existing
environment skips. These are local tests, not original protected observations.

All four final certification self-tests passed: network-scale (three tests),
cross-version (154 tests, 12 skips), stable maintenance (247 tests), and Phase 12
closeout (185 tests). The first sandboxed network-scale invocation failed its local
socket test; the explicit local-socket rerun passed. Historical residual records
remain byte-for-byte unchanged in the final policy.

Broader role discovery ran 315 tests with 67 failures, 27 errors and 37 skips.
All 94 failure/error entries reproduced by name on the exact starting source:
Linux-only snapshot guards, unavailable macOS `O_PATH`, and fail-closed private
readers. Broad protected-workload discovery had one bounded helper startup error
and 35 skips among 193 tests. That helper passed separately on both baseline and
current source; the broad timing failure remains retained. Production guards were
not weakened to make macOS claim Linux isolation coverage.

## Phase 12 handoff

The fresh baseline and final repository assessments use the same cutoff,
`2026-10-13T09:39:26Z`: 49 mandatory requirements, 47 unresolved, Phase 12 incomplete.
The new source/test pins describe only the bounded implementation. The reviewed
implementation roster fingerprint was updated while preserving every accepted
assertion, dimension, authority, subject, prerequisite and implementation state.
Historical residual records, tracker bytes and assessments remain unchanged;
the current bounded remediation disposition is this runbook.

No installed or protected case, external security review, live-node behavior,
resource baseline approval or publication is claimed. The next slice is PR-319,
`composed-budget-restart-and-diagnostics-evidence`. Privacy, PR-317 installed native
cancellation, prior Mail/finite-native work and long-run obligations remain separate.

Provider references: [Java 25 Files.move](https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/nio/file/Files.html#move(java.nio.file.Path,java.nio.file.Path,java.nio.file.CopyOption...))
documents provider-dependent move failure states; [Linux fsync(2)](https://man7.org/linux/man-pages/man2/fsync.2.html)
distinguishes file synchronization from directory-entry synchronization. These
references grant no stronger durability guarantee than the actual owner code.
