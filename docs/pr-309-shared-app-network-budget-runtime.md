# PR-309 shared app-network-budget runtime

This runbook describes the composed Trust Graph accounting path, its bounded native observations,
and the finite shared-budget cohort needed for Phase 12 remediation.

## Source and scope

Implementation starts at merged PR-308 squash `e2d65ca9ab9c15f25369b50b8728a614161b6a9d`,
tree `ba2c046bc2b3330c00f200dc413ff215991ce0dc`, on
`feature/pr-309-complete-app-network-budget-runtime-cohort`. The predecessor feature head
`510753d3aa99af3a8f9d60478f90fc4e9faffba3` is historical; its checks cannot establish this
working tree's correctness. A `leumor` requery confirmed this exact base's Java run `34827128492`
completed successfully at `2026-09-14T09:44:18Z` and CodeQL run `34827127801` succeeded at
`2026-09-14T09:21:16Z`; develop still selected that integration. These checks describe only the base. Other base-associated checks include failed performance-smoke
run `34830858011`, renewal-ledger-retention run `34830732837`, and SonarCloud; the base is not
reported as universally green, and none of these checks validates the new working tree.
Exact final source and checks belong in the implementation report.

The selected scope is direct foreground fetch, subscription poll/manual refresh, direct and pasted
preview Trust Graph import, URI preview/import, and interference through their shared families.
Content insertion, native pending-key scheduling, generic Mail delivery and other app services are
outside this service. The graph remains node-local shared operator-curated state. Per-app quota
isolation does not create private graph databases.

Local synthetic preparation grants no protected dispatch, real-user graph mutation, public-network
insertion, production approval or release authority. Use disposable owned node roots, signed test
apps and normal app sessions. Trust Graph capabilities remain experimental with explicit opt-in;
Platform API 1.0 and Trust/Social v1 signatures retain their existing meanings.

## Audited reuse and gaps

| Boundary | Existing implementation reused | Additional proof required |
| --- | --- | --- |
| Admission | Authenticated principal, capability matrix, bounded content-key validation | Composed app-principal cases and absence of work before admission |
| Budget | Durable fixed windows, process-local reservations/leases and shared global families | Actual route-to-family linkage under interference and failures |
| Trust | Native parser, preview builder, signature verifier and local graph store | Parse, fingerprint and store verdicts linked to the charged request |
| Runtime | Bounded blocking content port and scheduler observations | Actual terminal state, cancellation uncertainty and restart reconciliation |
| Evidence | Bounded native ring and original pressure/baseline bindings | Narrow prospective composed facts; complete cohort remains independently defined |
| Certification | Existing budget/soak owners and immutable Phase 12 requirements | Original authenticated operational inputs, durations and remaining parent gates |

## Charging oracle

These expectations derive from the operation contract, not from observed totals. Each charged
family needs its scope, fixed-window identity and operation ID. A denied decision's metadata write
is not an allowed-work charge.

| Operation | Durable families | Concurrency families |
| --- | --- | --- |
| Foreground content fetch | App foreground minute; global content-fetch minute | App foreground; global content fetch |
| URI import/preview fetch stage | App foreground minute; global content-fetch minute | App foreground; global content fetch |
| Scheduled poll/manual refresh | App subscription hour; global subscription hour; global content-fetch minute | App subscription; global subscription; global content fetch |
| Direct import/pasted preview/import commit | App import hour; global import hour | App import; global import |

`CONTENT_FETCH_GLOBAL` is an internal aggregate, not an additional public request. Host Trust Graph
calls use `_cryptad_operator`; generic foreground host/reduced embeddings can be unbudgeted.
Operator observations do not establish app-principal coverage. Billing scope always comes from
trusted native authentication, never a caller's app-ID field.

| Route/stage/outcome | Fetch charge | Import charge | Graph effect |
| --- | --- | --- | --- |
| Authorization denied | None | None | None |
| Immediate invalid parameter or missing required port | None | None when rejected before reserve | None |
| Direct malformed statement after acquisition | None | Retained | Parser rejects |
| Pasted preview after commit | None | Retained, including later preview failure | No retained statements/anchors changed |
| Import reserve denied | No invocation | No allowed charge | None |
| URI invalid before fetch acquisition | None | Temporary hold released | None |
| Child fetch budget denied | No invocation | Uncommitted hold released | None |
| Fetch admitted then timeout, oversized body or invalid UTF-8 | Retained | Uncommitted hold released | None |
| URI import: bounded UTF-8 then malformed statement | Retained | Committed before parse; retained | Parser rejects |
| URI import: stale expected fingerprint | Retained | Committed before comparison; retained | No accepted store result |
| URI preview: malformed direct root | Retained | Root check precedes commit; no import charge | None |
| URI preview: valid root | Retained | Committed before preview construction | No retained statements/anchors changed |
| Valid URI import | Retained | Retained | Native store verdict |
| Repeated valid import | Each request charged | Each request charged | May deduplicate |

Pasted preview may summarize wrapper payloads that URI preview does not accept as a direct root.
Preview plus import are two requests. A preview fingerprint is neither a quota transfer nor an
exactly-once token. Invalid signature is a verification attribute: native stores may retain
unverified non-scoring evidence. Retention, deduplication, lifecycle and local scoring eligibility
must be assessed separately; no trust is granted merely by import.

## Reservation, failure and restart

The reservation owns import concurrency and pending rate capacity while the child fetch owns its
separate fetch lease. Commit removes the reservation's original-window pending hold, checks the
current window and writes durable import counts. Close releases process-local holds and never
refunds charged work. Repeated commit returns its cached decision, including denial; repeated close
cannot decrement capacity twice. Closing before the first commit makes commit unavailable.

Two-family import/fetch writes and three-family subscription writes are sequential. A failure
before write N leaves the preceding successful prefix. A failure reported after write N may also
leave N persisted although no successful charge event follows it. Neither path grants unapproved
work; neither rolls back a persisted prefix. Reservation commit failure retains concurrency until
close. Durable state uncertainty makes evidence incomplete, even if the public error is a safe 503.

The bounded getter also abandons ownership on timeout/interruption so a late successful result
can release its result bucket. This resource cleanup does not establish runtime task termination.

Deterministic native tests inject failures before and after each applicable write, reopen the real
file store and compare independently specified families. They also cover competing current-hour
imports, release of old-hour holds, cached commit denial, concurrent commit/close and recreation of
a service over persisted files. Service recreation establishes the storage/process-state contract;
it is not an abrupt packaged-daemon termination observation.

A client disconnect, response timeout, interrupted caller and actual runtime cessation are distinct.
The bounded native adapter now attaches an owner-terminal acknowledgment to timeout/interruption
failures. Foreground fetch leases and subscription reservations defer release until that acknowledgment
completes normally; runtime activity follows the same boundary. The URI request may finish failed
and release its unused import reservation while its child fetch still holds fetch concurrency.

`FETCH_TERMINATION_UNKNOWN` records the unresolved interval. Normal owner completion records child
`FETCH_FAILED` before deferred hold release. An absent callback or exceptionally completed
acknowledgment leaves capacity held conservatively until process termination. Legacy port failures
without an acknowledgment retain their existing port contract; they do not prove a real native
cancellation. The selected callback establishes the owner's terminal state, not disappearance of
every network packet. Late successful results after abandonment release their result buckets.

After ambiguous response, reconcile owned graph state and native observations before a retry,
which is a new charged request. Graph deduplication cannot refund previous retrieval/import charges.

The packaged harness stops only an owned quiescent test node. Its shutdown correction waits for
the wrapper, exact native JVM and authenticated synthetic workers through process-identity-bound
pidfds, rather than mistaking
wrapper exit for daemon exit. The earlier route run passed queue/support/log privacy checks and
graceful restart, then exposed a stale JVM after wrapper-only abrupt stop. Actors already observed absent count as absent; extant actors must match their pinned identities
and reach pidfd terminal state. The corrected final packaged rerun passed both tests; quiescent abrupt restart does not establish in-flight crash
accounting or a completed abrupt-restart consumer adapter.

After abrupt restart, the fixture checks persisted budget and graph bytes independently, then
restores the identical owned valid-content key/bytes using local-only FCP before a separately
charged duplicate retry. This procedure does not claim content-cache/datastore persistence.
HTTP waiting is bounded at 45 seconds for the native 30-second URI fetch timeout. Lost HTTP
requests retain bounded private graph/native reconciliation and remain failed runs.

Graceful stop and abrupt termination need separate packaged observations. On restart, same-window
rates and actual durable graph writes survive; process-local reservations/concurrency and collector
identities restart. The dead process receives no fabricated terminal event. Corrupt budget reads
fail closed rather than initialize fresh usage. Reinstall/rename is not a supported quota reset.

## Causal observation and privacy

`RuntimeWorkObservation` retains at most 4096 records. Native request handles establish parent/child
links to reservation and fetch operations; browser strings, adjacent timestamps and global last-ID
state are not correlation authority. Fixed request-start, parse/fingerprint, store-attempt/verdict,
fetch-terminal and request-terminal kinds supplement existing family hold/charge/release records.
`COMPOSED_CHILD` carries the child operation ID and the native parent ID in its numeric value.
Both reservation and fetch link to that parent. `PREVIEW_BUILT` means a preview was built; pasted
preview may include rejected candidate summaries and does not imply strict parsing succeeded.
Request terminal records follow reservation close. The underlying getter may remain uncertain.
Version 2 snapshots carry a process-local UUID collector epoch. Scope 1 is global, scope 2
is reserved for host/operator and scopes 3 or greater represent authenticated apps. Version 2
composed evidence rejects host scope 2, including outer-segment relabeling attempts. Historical
version 1 local-consistency scope semantics remain unchanged. IDs and opaque scope labels have meaning only within
that epoch; truncation, saturation, missing segments or unknown scope prevent complete coverage.

Recording is passive and accepts fixed labels/numeric metadata. It performs no file/network I/O
and grants no capacity. Raw URIs, statement bodies/signatures, issuer/subject keys, fingerprints,
source hashes, app data, private paths and exception text must not enter this journal. Scope mappings
and raw diagnostics stay private. Public projections are built from approved fields and synthetic
role/case identifiers rather than copying raw results and scanning afterward.

`diagnostics().valid=false` is unavailable state. Historical `snapshots()` may return an empty list
for unreadable records, so it cannot establish zero usage. Active-family counts count holds rather
than requests. Before/after totals alone are insufficient across window changes or competing apps.

## Finite cohort and evidence classes

The owning definition includes all six groups below. Callers cannot remove a failed case or define
completeness as all selected tests passing.

| Required group | Representative obligations |
| --- | --- |
| Authorization/validation | Missing trust/fetch capabilities, wrong/expired session, origin separation, parameter/key bounds |
| Import paths | Direct, pasted preview, URI preview/import; valid/malformed/mismatch/duplicate/native policy |
| Capacity | App/global import and fetch rate/concurrency; reservation-before-network; child-denial cleanup |
| Shared interference | Foreground/URI app family; subscription/global fetch; cross-app global gates; direct import exclusion |
| Failure/lifecycle | Timeout, size/encoding, partial writes, store unavailability, interruption, windows, retry/restart |
| Recovery/privacy | Useful recovery, released transient holds, unrelated state preservation, canaries on success/failure |

Native seams, owned packaged cache retrieval and original protected/network observations are
separate evidence classes. A port fixture does not prove the real network adapter; local content
retrieval does not prove cross-node propagation. A skipped packaged direction remains missing.
The complete finite cohort is not yet established merely by the native accounting additions.

The packaged direction must use the supported `:platform-devtools:installDist` and distribution
graph, normal signed fixture installation and real app sessions. Synthetic content belongs only in
owned isolated storage through the supported FCP/runtime path. Never pass arbitrary HTTP/file/LAN
URIs to Trust Graph import. Record the effective finite configuration, background schedule, windows,
process epoch and exact installed app/product subjects. A short-test profile is not default-profile
performance evidence. Remove only resources owned by that run.

The twelve remaining consumer case adapters are implementation gaps, not merely absent protected
operations: `import-concurrency`, `fetch-concurrency`, `timeout`, `cancellation`, `retry`,
`window-crossing`, `partial-rate-write`, `graph-store-unavailable`, `graceful-restart`,
`abrupt-restart`, `diagnostics-unavailable` and `privacy`. Deterministic native tests and packaged
restart/privacy checks can exercise portions of these behaviors without completing the owning
causal derivation. Therefore this implementation does not satisfy the complete PR-309 definition
of done or permit `fullAppBudgets` acceptance.

## Consumer and historical authority boundaries

The focused `composed_budget_evidence.py` original-journal attachment is schema 2. Its fixed policy
lists 31 cases; its current oracle recognizes 19 case types: nine direct/preview/URI outcomes, URI/UTF-8/size
rejections, authenticated capability denial, app/global import/fetch rate denial, and shared
foreground/subscription interference. Rate denial
requires the actual `RATE_LIMIT_REACHED` family/scope/window plus unchanged valid snapshots; a
legacy budget-denied event or caller case label cannot identify the exhausted owner. Recognition
support does not mean those cases were observed in a packaged run. Other required directions remain
missing. It checks closed bounded native segments, family/window/scope
snapshots, ordering, graph deltas and epoch/operation uniqueness. Its result identifies
`native-observation-local-consistency`, `originalAuthentication=not-established`,
`fullAppBudgets=not-observed` and `releaseEligible=false`.

Concurrency evidence must establish a hold interval for every applicable family and owning
operation. Each acquisition precedes the protected stages, each family release follows those
stages, and the aggregate budget release follows all family releases. Import holds cover parsing,
preview construction and graph-store results, plus the child fetch or admission denial while an
import reservation is active. Fetch holds cover invocation through native completion; their
release may legitimately precede subsequent import parsing. Balanced counts alone cannot establish
these boundaries. Premature release or late acquisition leaves the case unobserved.

Successful route evidence also requires each native processing stage exactly once and in order.
URI preview completes its fetch, parses the direct statement, commits import quota, then builds
the preview. URI import completes its fetch, commits import quota, parses, accepts the expected
fingerprint check, then attempts storage and records its result. Direct import has no fingerprint
stage; pasted preview requires preview construction after commit without a direct-statement parse
event. Missing, duplicate or reordered stages leave successful coverage unobserved even when
the response and durable accounting totals appear successful.

An original journal preselects closed `composedBudgetInputs` containing collector and configuration
digests. The latter binds the raw node configuration digest plus environment recipe. This is
separate from PR-308's unchanged effective-runtime configuration fingerprint. Caller-authored
attachment digests cannot replace those preselected plan bindings. Snapshot validation rejects
unexplained added/removed families, future windows and unknown scope zero.

Original-journal attachments bind root `collectorEpoch` and `nodeEpoch`; every contained segment
belongs to that collector. Each attachment is emitted before its owning process stops and must
match the journal's active node epoch. The owner unions coverage from one to eight unique process/
collector epochs without adding process-local counters across restarts. Historical attachment v1
remains local-consistency-only and cannot enter an original journal. Shared-family interference
requires actual owner calls, prescribed family/hold/snapshot changes and a later URI denial naming
the exhausted family; unrelated success records do not establish interference.

The existing cross-version journal accepts a bounded `composedBudgetEvidence` member and its
Phase 12 adapter can expose `composedBudgetCoverage` after the surrounding owner checks. Prospective
measurement v6 wraps its unchanged v2–v5 base through `composedBudgetBaseVersion`; terminal report v7
admits that wrapper explicitly. Pressure attachment v2 accepts the new fixed kinds and collector
epoch, while historical pressure v1 keeps its original closed vocabulary. This
reachable path does not manufacture original authentication or grant complete-budget coverage.
The attachment itself supplies no new signing root or protected execution authority.

Prospective composed-budget facts remain separate from PR-308 resource-baseline comparison.
Historical pressure v1, sealed measurement v4, PR-308 report v6/measurement v5 and their closed
component dispatch retain their meanings, including `fullAppBudgets=not-observed`. A changed
workload/app cohort or collector changes baseline applicability and needs later authorized
recollection/reapproval; equality checks and historic approval bytes cannot be relaxed.

A causal attachment must derive facts from original native segments and private snapshots, reject
wrong epoch/parent/product/cohort bindings, and retain missing required cases. Original producer
workflow/run/attempt/job/environment, package, roster, configuration and workload bindings remain
necessary for owning operational acceptance. Integrity verification precedes baseline approval
eligibility. An authentic budget fact grants no resource-bound or execution authority; terminal
collection after expiry grants no new execution authority.

The historical repository-only assessment remains 49 mandatory requirements, 47 unresolved and
`phaseComplete=false`. Its original IDs, cutoff and tracker bytes are unchanged. New implementation
dispositions and separately retained assessments must state their own source and fixed cutoff;
`--require-complete` must still reject the incomplete phase.

PR-310 remains provisionally the restricted protected-runtime worker and private resolver/key
isolation slice. Root-owned key files do not isolate secrets from an unrestricted-sudo workflow
account. This work neither provisions that boundary nor dispatches the blocked private lane.
Mail lifecycle, historical interoperability, original long-duration operations, minimum node/operation
counts, post-freeze/security/cleanup gates and independent review remain separate obligations.

## Validation status

After the supported distribution/tool build, the packaged driver is executable with:

```bash
PYTHONPATH=tools/interop:tools/release-certification \
python3 tools/interop/test_app_budgets_packaged.py
```

Its missing-prerequisite skip is not a passed packaged lane. The test uses the owned isolated node
profile, signed synthetic fixtures and local FCP content retrieval; it does not publish content to
public nodes.

The actual implementation validation includes these separately classified results:

| Check | Observed result and limit |
| --- | --- |
| `./gradlew spotlessApply` | Executed before shared Java verification |
| Initial `./gradlew test` | Failed on the old root observation test's immediate-cancel release assumption; the test now waits for native acknowledgment |
| `./gradlew :platform-devtools:installDist assembleCryptadDist test build` | Passed in 6m 38s after that correction; includes shared tests and supported distribution graph |
| Owning API/trust/HTTP focused verification | Passed; later final focused command completed in 35s |
| `:platform-api:test :platform-api:spotbugsMain :platform-devtools:installDist assembleCryptadDist` | Passed in 47s after observation-state synchronization fixes |
| Current JUnit XML inventory | 17,397 tests including six build-logic tests, zero failures/errors and ten skips; reports reflect the latest full/focused executions rather than one invented aggregate invocation |
| New native failure integration class | Eleven cases passed, zero skips; file stores and handler/native-port seam, not packaged network proof |
| Final packaged routes and shared families | Both tests passed in 264.743s with zero skips against the host-scope distribution; 13 route/rejection cases plus shared-family bindings, durable checks, privacy surfaces and exact owned-worker cleanup |
| Final `./gradlew test build assembleCryptadDist` | Passed in 5m 14s; final shared test/build/distribution verification |
| Final PR-306 packaged scheduler regression | Both tests passed in 510.420s with zero skips against final host-scope source; local repeatability used two references and one candidate, `numericStatus=within-reviewed-local-bounds`, no findings and `releaseEligible=false` |
| Final seven requested certification self-tests | Network-scale 3, cross-version 136, maintenance 247, Phase 12 185, content-profile 18, app-platform 2 and app-platform-docs 3 tests passed; no skips |
| Final API module rerun | Passed in 23s after the lost-store-acknowledgment regression was added |
| Host-scope API/analyzer/tools/distribution rerun | Passed in 69s after reserving collector scope 2 for host/operator |
| Composed/cross-version/maintenance self-tests | 22 composed, 136 cross-version, 24 projection and 247 maintenance tests passed |
| Phase 12 self-tests | 185 passed; original operational inputs remain absent |

The final scheduler command and certification regressions were executed against the final source:

```bash
PYTHONPATH=tools/interop:tools/release-certification \
python3 tools/interop/test_scheduler_pressure_packaged.py
python3 tools/release-certification/certify.py network-scale-soak --self-test
python3 tools/release-certification/certify.py cross-version-soak --self-test
python3 tools/release-certification/certify.py stable-maintenance --self-test
python3 tools/release-certification/certify.py phase-12-closeout --self-test
python3 tools/release-certification/certify.py stable-content-profile-review --self-test
python3 tools/release-certification/certify.py app-platform --self-test
python3 tools/release-certification/certify.py app-platform-docs --self-test
```

The scheduler's local numerical result does not grant approved production resource bounds. Final
process inspection found no owned PR-306/PR-309 runtime processes, and successful-run retention
markers were removed. These cleanup results concern the owned synthetic runs only.

The successful packaged route run observed three distinct process/collector epochs and accounted
for 12 owned app-worker exits across its restarts; the interference run accounted for four worker
exits. Already-absent workers remain verified absent rather than counted as unobserved. The run
used actual installed signed fixture principals, native stores and local FCP retrieval, including
the previously failing privacy/restart direction. It still leaves the twelve listed consumer
adapters incomplete and grants no original protected authentication.

The eleventh native failure case delegates a real file-store write and then injects a lost
acknowledgment. It reopens the persisted statement, observes an unknown store result, retries the
request and verifies deduplication with both requests charged. This native seam establishes neither
an actual packaged response-loss operation nor a completed retry consumer adapter.

The ten JUnit skips comprise an opt-in benchmark, two CHACHA parameter cases, a provider-availability
case, platform-specific file/native-thread checks and three Windows junction cases. Affected owning
module inventories contain no skips: API 1,282, Trust Graph 84, HTTP bridge 135, runtime node 97,
runtime SPI 31 and devtools 274 tests. Results do not establish protected execution, long-duration
soak, production baseline approval or full finite-cohort completion.

Fresh API SpotBugs initially found three stale-thread-state warnings in the new request context and
new external-monitor warnings in deferred-release methods. The narrow synchronization corrections
cleared those new findings on rerun. Five existing affected API findings remain: collaborator
exposure in budget/subscription services, singleton classification for the reusable no-op lease,
and external-monitor warnings for reservation commit/close. SPI also reports constructor-throw
warnings, including the new acknowledgment overload following the existing validated-constructor
pattern. The actual full-build compiler log contains no warning for changed tracked Java files;
retained Error Prone XML exports remain older and cannot establish fresh report cleanliness.
No fresh Sonar analysis or independent security review is claimed.

## Fixed-cutoff assessment disposition

A detached checkout of the actual base produced `build/pr309-phase12-base` at the unchanged
`2026-09-13T10:30:00Z` cutoff: 49 mandatory requirements, 47 unresolved, `phaseComplete=false`.
Verification with `--require-complete` returned the expected exit 2 with verified local consistency.
The unrefreshed intermediate `build/pr309-phase12-current` result recorded source drift and remains
retained separately rather than overwritten.

The reviewed mutable policy refresh updates exactly 20 existing source/test digest entries across
eight files and nine requirements. Removing those implementation digest fields yields the same
policy bytes as the base: assertions, states, requirement IDs, accepted scope, historical statements
and clocks are unchanged. The prospective runbook supplies the new implementation disposition;
no historic tracker or archived policy is rewritten.

`build/pr309-phase12-final` and the separately retained post-correction
`build/pr309-phase12-final-verified` and final host-scope successor
`build/pr309-phase12-final-source` evaluated and verified at the same cutoff with 49 mandatory requirements,
47 unresolved and the expected `--require-complete` rejection. Its tool digest binds the tool files
present at evaluation. Any later tooling correction requires a separately retained reassessment;
it cannot silently reuse that result. The final implementation report identifies the last applicable
assessment, package test results, outstanding directions and exact source identities.

The subsequent concurrency-interval review corrected the composed-budget verifier and added
premature-release regressions. Its separately retained assessment is
`build/pr309-phase12-review-hold-intervals`, evaluated at the same fixed cutoff against the corrected
tool source. It retains 49 mandatory requirements, 47 unresolved, and `phaseComplete=false`;
`--require-complete` verification rejects completion with exit 2. Earlier assessment artifacts
remain historical results bound to their own tool bytes.

The subsequent route-stage review requires complete ordered success stages, including URI preview
construction and URI import fingerprint acceptance. Its fixed-cutoff successor assessment is
`build/pr309-phase12-review-route-stages`; the 49 mandatory requirements and 47 unresolved
requirements remain unchanged, with `phaseComplete=false` and the expected `--require-complete`
exit 2. This successor binds the corrected verifier rather than reusing the earlier tool digest.

The wrapper-lineage review makes protected product-lineage admission compare schema 7 using its
underlying measurement version plus one, preserving the historical minimum report versions. One
mutable supervisor source digest is refreshed without changing assertions or requirement scope.
`build/pr309-phase12-review-wrapper-lineage` separately evaluates and verifies that correction at
the same cutoff: 49 mandatory requirements, 47 unresolved, `phaseComplete=false`, and the expected
`--require-complete` exit 2.
