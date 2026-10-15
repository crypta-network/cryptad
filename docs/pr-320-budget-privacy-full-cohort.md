# PR-320 budget privacy and full cohort integration

This work starts at integration commit `3ddb5e432ee357446a3f6cb2bfcc6b697b266148`.
PR #1421 was merged on 2026-10-14 at 05:31:49 UTC from amended feature head
`ef9d31cfd8a2bd51f70c7ef33794c8032dc20199`. The planning head is historical.
The initial checkout was clean. No installed VM or protected operation is authorized.

This branch implements the native privacy paths, finite installed drivers and original budget
consumer integration. Local verification is recorded below. Installed VM observations and
protected operations have not been executed; their original authority remains required.
The repository-only assessment at `2026-09-13T10:30:00Z` ran in
`build/pr320-assessment-before`: 49 mandatory requirements, 47 unresolved, Phase 12 incomplete.
The first attempt failed because the output parent did not exist; creating `build` and rerunning
produced the retained assessment. Historical policy and scope bytes remain authoritative.

## Frozen case and variant matrix

The cohort is exactly `composed_budget_evidence.REQUIRED_CASES`. A case name in a summary
is insufficient: the owning validator must recompute each native stream and applicable variant.
Native synthetic vectors, real local native execution, installed role execution and original
protected authentication are separate evidence classes. The starting gap column below remains an audit record. The implementation and execution columns
in the successor matrix distinguish the new paths from actual observations. Historical test
reports are not execution evidence for PR-320.

Owners used in this matrix:

- Route owner: `cryptad_certification/composed_budget_evidence.py`, native handlers in `platform-api`.
- Lifecycle owner: route owner's v3 causal cases, `cross_version_installed_budgets.py`, PR-317 originals.
- Storage owner: `composed_budget_storage_evidence.py`, `cross_version_installed_storage_budgets.py`, PR-318 administrator and originals.
- Restart owner: `composed_budget_restart_evidence.py`, `cross_version_installed_restart_budgets.py`, PR-319 administrator and originals.

| Fixed case | Required native behavior/business outcome | Existing producer/verifier and installed gap at start |
| --- | --- | --- |
| direct-valid | Direct signed document retained; successful import charged | Route owner; native handlers/tests exist; full campaign route adapter missing |
| direct-malformed | Charged admission, fixed parse failure, no graph mutation | Route owner; native handler tests exist; campaign adapter missing |
| pasted-preview-valid | Charged preview, useful parsed summary, no commit | Route owner; native handler tests exist; campaign adapter missing |
| uri-preview-valid | Import reservation and independent fetch charge; preview only | Route owner; native handler tests exist; campaign adapter missing |
| uri-preview-malformed | Independent fetch charge and safe parse failure | Route owner; native handler tests exist; campaign adapter missing |
| uri-valid | Independent fetch/import charges and retained signed graph | Route owner; native handler tests exist; campaign adapter missing |
| uri-malformed | Fetch remains charged; failed parsing never commits graph | Route owner; native handler tests exist; campaign adapter missing |
| uri-fingerprint-mismatch | Fetch charged; mismatch prevents graph commit | Route owner; native handler tests exist; campaign adapter missing |
| uri-duplicate | Independently charged retry; duplicate metadata explained | Route owner; retry driver exists; full route campaign missing |
| authorization-denied | Capability denial before sensitive producer/work | Router/capability tests; installed principal prerequisites exist; campaign case binding missing |
| app-import-rate | Exact app-family denial before fetch | Route owner; native tests; installed route campaign missing |
| global-import-rate | Exact global-family denial before fetch | Route owner; native tests; installed route campaign missing |
| import-concurrency | Real overlap, denying family, then successful recovery | Lifecycle owner; bounded installed driver exists, unexecuted here |
| app-fetch-rate | Import reservation released, exact app fetch denial | Route owner; native tests; installed route campaign missing |
| global-fetch-rate | Import reservation released, exact global fetch denial | Route owner; native tests; installed route campaign missing |
| fetch-concurrency | Real overlap, denying family, then successful recovery | Lifecycle owner; bounded installed driver exists, unexecuted here |
| shared-foreground | Foreground and URI work share content-global family | Route owner; native tests; installed campaign overlap binding missing |
| shared-subscription | Subscription and URI work share content-global family | Route owner; native tests; installed campaign overlap binding missing |
| invalid-uri | Rejection before runtime fetch with fixed error | Route owner; native tests; installed route campaign missing |
| invalid-utf8 | Charged fetched bytes rejected before parsing/store | Route owner; native tests; installed route campaign missing |
| oversized | Bounded fetched bytes rejected before parsing/store | Route owner; native tests; installed route campaign missing |
| timeout | Cancel requested; real owner ACK controls release; recovery | Lifecycle owner; installed positive depends on actual deferred termination, cannot fabricate it |
| cancellation | Owner cancellation, distinct from disconnect; ACK controls release | Lifecycle owner; native controlled port tests exist; installed driver only abandonment, propagation seam missing |
| retry | New independently charged owner and duplicate/recovery result | Lifecycle owner; runnable installed retry exists, unexecuted here |
| window-crossing | available-capacity and contested-capacity | Storage owner; available driver exists; contested accepting branch/driver missing |
| partial-rate-write | direct-readable-directory-denial, uri-child-write-denial, uri-import-commit-denial | Storage owner; direct driver exists; URI accepting branches/drivers missing |
| graph-store-unavailable | direct-readable-directory-denial, uri-readable-directory-denial | Storage owner; direct driver exists; URI accepting branch/driver missing |
| graceful-restart | settled-graceful: actual zero JVM exit and retained state | Restart owner; runnable driver/admin/verifier exists, unexecuted here |
| abrupt-restart | settled-abrupt and inflight-abrupt: original forced stop, retained state | Restart owner; both drivers exist, unexecuted here; in-flight business tail remains censored |
| diagnostics-unavailable | enumeration-only and required-key-unreadable | Restart owner; both drivers exist, unexecuted here; invalid is never zero/healthy |
| privacy | Actual sensitive stimulus, authorized private controls and useful real exports | No accepting case branch or complete producer/driver at start |

Storage controlled tests additionally cover direct/URI graph writes before/after delegation,
fresh/duplicate metadata, direct writes 1/2 and URI writes 1/2/3/4 before/after delegation,
available/contested/multiple-hour transitions and same-minute/same-hour/backward controls.
These controlled clock/decorator observations cannot be relabeled as actual OS write cutpoints.

Each selected run must freeze source/product/API, signed app cohort, workload/collector/configuration,
role/daemon/worker/collector epochs, time domains and phase boundaries before execution. Retain
attempts, failures, faults, readback and cleanup. A successful rerun cannot erase a contradictory
candidate result. Original controller/bootstrap, administrator and retained file records are
required for installed authentication. Missing original authority is distinct from a missing driver.

## Source-to-sink audit and ownership

| Surface | Intended classification | Starting finding and executable seam |
| --- | --- | --- |
| App response and graph/app-data store | Authorized private app data | Real native graph/file stores and handlers; prove stimulus with actual readback |
| App error/capability/audit | Fixed scoped metadata | Unknown first URL segment copied by `PlatformApiCapabilities.unknownAction` and `AppAuditLog.fallbackAction`; router test can reproduce |
| Native budget events | Fixed causal codes/numbers/opaque scope | Existing runtime snapshot builder; preserve useful counts, invalid diagnostics and complete epoch ranges |
| Operator runtime/graph diagnostics | Authorized private troubleshooting | Operator routes deny non-host before supplier; assert invocation counts; graph hashes remain private |
| Local support preview/JSON/digest | Reviewed local export | Real support builder is useful and count-only for graph; redactor echoes unsafe keys through `omittedFields` |
| Web Shell rendering/copy/download | Explicit local reviewed export | Actual JS exists; malformed pass/digest and cached export after failed regeneration need browser regression; no shell browser harness at start |
| HTTP host/session boundary | Privileged composition after authorization | Unregistered hostile Origin can fall through to host in `PlatformApiToadlet`; actual bridge denial must precede router |
| Daemon failed request logs | Fixed failure classification | Toadlet logs raw path/throwable and router logs raw exception causes; controlled failure can reproduce |
| Private checkpoints/originals | Bounded private verification | Existing fixed descriptor readers/PR-318/319 retention; never copy to public root |
| Public case/CI/site | Strict allowlisted facts | Shared scanner permits digest-shaped private correlations; new typed projection required, preserve allowed product/governance hashes |
| Successful/failed CI artifacts | Exact fresh public roster | `build.yml` uses typed singleton facts; `release-certification.yml` uploads broad output on `always()`, needs exact allowlist-root verification |

The native operator route is not a public artifact policy. Allowed private graph reads and local
support IDs/digests are not themselves leaks; their automatic publication would be. Preserve the
local support contract and emergency diagnostic capability. Server denial must precede sensitive
assembly. Missing/invalid exports and lost ring observations cannot establish privacy.

## Version and acceptance boundaries

Keep v1/v2 route attachments, v3 causal additions, v4 storage additions and v5's isolated restart
branch unchanged. V5 requires empty segments/causal/storage lists. Legacy journal union revalidates
original details, has eight attachments and one collector/configuration pair, and remains
`fullAppBudgets=not-observed`. A finite successor campaign must use exact bounded member references
and complete variants; it must not increase historical limits or union caller-supplied summaries.

Local consistency, actual installed observations and original protected budget acceptance remain
separate. No budget verdict grants release eligibility, resource baseline approval, long-runtime
coverage, Mail readiness, independent human security approval or Phase 12 completion. New workload,
cohort or collector bytes invalidate applicability to historical PR-308 resource baselines.

## Implemented privacy behavior

Unknown route names now produce closed action families in capability decisions and audit records.
Unsafe structural property names cannot echo through support omitted-field labels. Router and
HTTP bridge failure logs carry fixed classifications; host Origin admission runs before operator
composition. App-token content/import/preview requests register their actual launch-bound native
owner, and explicit stop or observed worker death propagates cancellation. Charges remain durable;
reservation release requires the genuine native callback. Disconnect or a test flag cannot release it.

The real native privacy test uses signed graph data, file stores, an actual URI fetch port, app data,
private operator readback, useful support counters and denial-before-composition counters. The
14 distinct sensitive purposes are retained only in private test originals. Web Shell verifies the
exact support wire digest, including numeric/escape lexemes, and invalidates export after failed
regeneration. Copy and download preserve verified wire bytes. Browser persistence remains empty.

The scanner bounds UTF-8/JSON/HTML/URL/Base64/Base64url decoding and private hash checks. It is
a check for the declared representations, not a classifier for arbitrary user secrets or encodings.
Safe summaries and typed public projections provide the primary boundary. Raw emergency operator
diagnostics remain private and authorized; local support metadata retains its reviewed contract.

PR-321 retains supported-platform and exact-source CI convergence. Required PR-320 budget drivers
and privacy paths stay in this work package. PR-322 finite-native installed acceptance, PR-330 full
system short integration and original protected operational observations remain independent.


## Full successor coverage matrix

The executable roster contains **31 cases and 42 mandatory variants**. Each installed driver uses
the same four signed apps and fixed candidate-sender, candidate-recipient, previous and relay roles.
Synthetic original vectors exercise actual budget validators; external authority is substituted in
those tests and cannot be reported as an original protected observation.

| Case | Mandatory variants | Native/local evidence | Installed driver | Original witness/verifier |
| --- | --- | --- | --- | --- |
| `direct-valid` | `native-route` | Native route/budget tests; synthetic finite-stream original vectors | routes: implemented, unexecuted | routes: owning validators exercised on synthetic originals; protected observations unexecuted |
| `direct-malformed` | `native-route` | Native route/budget tests; synthetic finite-stream original vectors | routes: implemented, unexecuted | routes: owning validators exercised on synthetic originals; protected observations unexecuted |
| `pasted-preview-valid` | `native-route` | Native route/budget tests; synthetic finite-stream original vectors | routes: implemented, unexecuted | routes: owning validators exercised on synthetic originals; protected observations unexecuted |
| `uri-preview-valid` | `native-route` | Native route/budget tests; synthetic finite-stream original vectors | routes: implemented, unexecuted | routes: owning validators exercised on synthetic originals; protected observations unexecuted |
| `uri-preview-malformed` | `native-route` | Native route/budget tests; synthetic finite-stream original vectors | routes: implemented, unexecuted | routes: owning validators exercised on synthetic originals; protected observations unexecuted |
| `uri-valid` | `native-route` | Native route/budget tests; synthetic finite-stream original vectors | routes: implemented, unexecuted | routes: owning validators exercised on synthetic originals; protected observations unexecuted |
| `uri-malformed` | `native-route` | Native route/budget tests; synthetic finite-stream original vectors | routes: implemented, unexecuted | routes: owning validators exercised on synthetic originals; protected observations unexecuted |
| `uri-fingerprint-mismatch` | `native-route` | Native route/budget tests; synthetic finite-stream original vectors | routes: implemented, unexecuted | routes: owning validators exercised on synthetic originals; protected observations unexecuted |
| `uri-duplicate` | `native-route` | Native route/budget tests; synthetic finite-stream original vectors | routes: implemented, unexecuted | routes: owning validators exercised on synthetic originals; protected observations unexecuted |
| `app-import-rate` | `native-route` | Native route/budget tests; synthetic finite-stream original vectors | routes: implemented, unexecuted | routes: owning validators exercised on synthetic originals; protected observations unexecuted |
| `global-import-rate` | `native-route` | Native route/budget tests; synthetic finite-stream original vectors | routes: implemented, unexecuted | routes: owning validators exercised on synthetic originals; protected observations unexecuted |
| `app-fetch-rate` | `native-route` | Native route/budget tests; synthetic finite-stream original vectors | routes: implemented, unexecuted | routes: owning validators exercised on synthetic originals; protected observations unexecuted |
| `global-fetch-rate` | `native-route` | Native route/budget tests; synthetic finite-stream original vectors | routes: implemented, unexecuted | routes: owning validators exercised on synthetic originals; protected observations unexecuted |
| `shared-foreground` | `native-route` | Native route/budget tests; synthetic finite-stream original vectors | routes: implemented, unexecuted | routes: owning validators exercised on synthetic originals; protected observations unexecuted |
| `shared-subscription` | `native-route` | Native route/budget tests; synthetic finite-stream original vectors | routes: implemented, unexecuted | routes: owning validators exercised on synthetic originals; protected observations unexecuted |
| `invalid-uri` | `native-route` | Native route/budget tests; synthetic finite-stream original vectors | routes: implemented, unexecuted | routes: owning validators exercised on synthetic originals; protected observations unexecuted |
| `invalid-utf8` | `native-route` | Native route/budget tests; synthetic finite-stream original vectors | routes: implemented, unexecuted | routes: owning validators exercised on synthetic originals; protected observations unexecuted |
| `oversized` | `native-route` | Native route/budget tests; synthetic finite-stream original vectors | routes: implemented, unexecuted | routes: owning validators exercised on synthetic originals; protected observations unexecuted |
| `authorization-denied` | `no-trust`, `no-fetch` | Native route/budget tests; synthetic finite-stream original vectors | routes: implemented, unexecuted | routes: owning validators exercised on synthetic originals; protected observations unexecuted |
| `import-concurrency` | `app`, `global` | Native route/budget tests; synthetic finite-stream original vectors | routes: implemented, unexecuted | routes: owning validators exercised on synthetic originals; protected observations unexecuted |
| `fetch-concurrency` | `app`, `global` | Native route/budget tests; synthetic finite-stream original vectors | routes: implemented, unexecuted | routes: owning validators exercised on synthetic originals; protected observations unexecuted |
| `timeout` | `deferred-normal-owner` | Native route/budget tests; synthetic finite-stream original vectors | routes: implemented, unexecuted | routes: owning validators exercised on synthetic originals; protected observations unexecuted |
| `cancellation` | `deferred-normal-owner` | Actual signed local workers and native callback tests; synthetic original vectors | owner: implemented, unexecuted | owner: owning validators exercised on synthetic originals; protected observations unexecuted |
| `retry` | `independently-charged` | Native route/budget tests; synthetic finite-stream original vectors | routes: implemented, unexecuted | routes: owning validators exercised on synthetic originals; protected observations unexecuted |
| `window-crossing` | `available-capacity`, `contested-capacity` | Controlled file/store and clock/cutpoint tests; synthetic original vectors | storage: implemented, unexecuted | storage: owning validators exercised on synthetic originals; protected observations unexecuted |
| `partial-rate-write` | `direct-readable-directory-denial`, `uri-child-write-denial`, `uri-import-commit-denial` | Controlled file/store and clock/cutpoint tests; synthetic original vectors | storage: implemented, unexecuted | storage: owning validators exercised on synthetic originals; protected observations unexecuted |
| `graph-store-unavailable` | `direct-readable-directory-denial`, `uri-readable-directory-denial` | Controlled file/store and clock/cutpoint tests; synthetic original vectors | storage: implemented, unexecuted | storage: owning validators exercised on synthetic originals; protected observations unexecuted |
| `graceful-restart` | `settled-graceful` | Separate JVM/file-store tests; synthetic original vectors | restart: implemented, unexecuted | restart: owning validators exercised on synthetic originals; protected observations unexecuted |
| `abrupt-restart` | `settled-abrupt`, `inflight-abrupt` | Separate JVM/file-store tests; synthetic original vectors | restart: implemented, unexecuted | restart: owning validators exercised on synthetic originals; protected observations unexecuted |
| `diagnostics-unavailable` | `enumeration-only`, `required-key-unreadable` | Separate JVM/file-store tests; synthetic original vectors | restart: implemented, unexecuted | restart: owning validators exercised on synthetic originals; protected observations unexecuted |
| `privacy` | `native`, `browser`, `public-artifacts` | Actual native file-backed test and Chromium export/recovery; synthetic original vectors | privacy: implemented, unexecuted | privacy: owning validators exercised on synthetic originals; protected observations unexecuted |


The family paths are:

- Routes: `tools/interop/cross_version_installed_route_budgets.py`, seven fixed profiles;
  `restricted/pr320_route_admin.py` and `pr320_route_runtime_evidence.py` match original bootstrap,
  native work/fetch/file counts, fixed scope probes, checkpoints and terminal receipts.
- Owner: `cross_version_installed_owner_budgets.py`, `pr320_owner_admin.py` and
  `pr320_owner_runtime_evidence.py` match the signed worker, launch, interpreter, root process death
  and native termination callback. Immediate acknowledgment cannot establish the deferred variant.
- Storage: `cross_version_installed_storage_budgets.py` with seven prospective selections,
  `pr320_storage_admin.py` and `pr320_storage_runtime_evidence.py` match exact quotas, cutpoints,
  real root file actions, partial writes, persistent readback and cleanup.
- Restart: `cross_version_installed_pr320_restart_budgets.py`, `pr320_restart_admin.py` and
  `pr320_restart_runtime_evidence.py` run the five existing restart directions under the common
  cohort. One complete v5 member retains all five; its old route/lifecycle/storage families stay empty.
- Privacy: `cross_version_installed_privacy_budgets.py`, `pr320_privacy_admin.py`,
  `pr320_privacy_browser_admin.py` and `pr320_privacy_runtime_evidence.py` require root native
  receipts, all thirteen authorization denials, actual session expiry and stale-worker death,
  the qualified Node/Chromium/package tree, actual app origin and empty persistence. Session expiry
  waits for the real expiration while the worker and daemon stay alive; a short deadline fails.
  `pr320_privacy_artifact_producer.py` produces and transfers the exact three public members,
  verifies job-summary bytes and commits member17 before journal finish.

No profile changes generic host loopback, manifest operator permissions, arbitrary file/namespace
selection, cancellation accounting or historical timeout defaults. Actual daemon/collector stdout
and stderr are retained with bounded EOF collection. Expected faults remain visible; failed collectors,
missing mandatory variants, interrupted cleanup or ring loss cannot become a complete campaign.

## Campaign and original custody

`composed_budget_journal_member.py` selects a finite private roster. Slots 00–06 contain route profiles,
07 owner cancellation,08–14 storage,15 the native privacy wrapper,16 browser,17 public artifacts and18
one full v5 restart member. Each journal reference binds exact raw bytes, selected producer/config/
collector identities and actual epochs. Legacy journal limits and output shape remain unchanged.

`composed_budget_campaign_evidence.py` recomputes every selected owner, all 42 variants, actual
per-profile workload digests and an aggregate map. Browser and artifact members must reference
exact native wrapper bytes in the same scope. Browser collector source and served script are separate
identities. Missing/substituted/replayed/failed members reject or remain incomplete. Censored restart
business tails remain censored even when the restart case itself is established.

A complete local campaign reports `complete-local` and `fullAppBudgets=not-observed`. Original
admission reauthenticates each original supervisor chain, selected raw input bytes, activation,
checkpoint, product provenance and retained root member. A sealed `OriginalBudgetCampaign`
capability grants only complete budget coverage. Consumer binding retains the exact selected plan
for every member, including collector/configuration/producer identities and planned variants. Copied JSON cannot create that capability.
Source-built protected observations use `original-protected-source-built-budget-cohort`; authenticated
release artifacts use `original-protected-budget-cohort`. Those classes remain distinct.

The source-owned `pr320_original_acquisition.py` and literal
`cryptad-pr320-original-acquisition.service` retain originals in the protected root domain. The unit
uses the host mount namespace because the existing preparer and PID1 role units share actual tmpfs
mounts. Existing controller/role isolation stays with their owning units. Immutable registrations,
fixed preparation/acquisition intents, exact installed source/kit/verifier trees, finite role commands,
monotonic deadlines, kernel process identity and stopped-service terminal authority bind custody.
This code is prepared for the qualified dedicated Debian 13/systemd 257 environment; it has not been
installed or executed here. Copying a VM capsule through an unprivileged host establishes local
consistency and cannot substitute for this original custody.

Prospective supervisor schema8 is a private additive terminal receipt over the historical report.
Schema9 is the public opaque receipt envelope: private plan/config/scope/checkpoint hashes remain
in the root store. Artifact/job/attestation verification precedes reopening those private originals.
Historical reports and attachment v1–v5 keep their meanings. No persistent or wire-format migration
is required for existing users.

Maintenance consumes the sealed capability after original measurement admission and preserves
historical rows in its additive schema7 wrapper. Network-scale consumes it separately from duration
and resource results. The `budget-campaign` Phase 12 adapter records the exact 31 budget cases while
keeping parent adapter/consumer dispositions partial and all 49 mandatory requirements intact.
It does not supply baseline review, 72-hour soak, Mail, independent providers/security review,
publication, activation or a release grant.

## Local execution record

The full wrapper build actually executed on this working source:

```sh
./gradlew spotlessApply build errorproneReport :platform-devtools:installDist assembleCryptadDist
```

It completed in 11m 50s: 17,498 JUnit cases, 0 failures/errors, 10 skips. The retained report facts are in
`build/pr320-local-report-facts.json`. SpotBugs reported 714 main and 191 test warnings, 0 analysis
errors and 2 missing classes; Error Prone reported 332 main and 130 test warnings, 0 errors. Existing
coverage was 0.72 against a non-blocking 0.80 threshold. Those findings remain for the owning work;
no task exit is treated as an empty analyzer report.

A later focused API/owner run actually executed after the cancellation-owner refactor:

```sh
./gradlew spotlessApply :platform-api:test :platform-api:errorproneReport sonarlintFile -Psonarlint.file=platform-api/src/main/java/network/crypta/platform/api/PlatformApiRequestOwner.java
```

It completed in 2m 35s; the new owner Sonar report is empty. The initial focused native run exposed
an interrupted audit write returning503 after genuine cancellation. The production fix preserves
one-shot owned interruption handling after the true callback. Its failed private attempt is retained.
The later `./gradlew assembleCryptadDist` completed in 2m 6s after this refactor
(`build/pr320-final-distribution.log`). The later `./gradlew distZipCryptad` completed in 40s;
its `lib/cryptad.jar` owner class exactly matches the final compiled owner bytes
(`build/pr320-distribution-owner-verification.json`). Earlier generated archives are historical
local outputs and are not the selected final portable ZIP.

Actual Chromium tests cover default support preview/copy/download, 1.0 and large-integer wire
preservation, recovery plan/execute/download and bad nested digest rejection. The harness uses
real shipped Web Shell HTML/JS/CSS and the native test export with an explicit intercepted local
transport. It does not establish installed namespace/browser provenance. Private outputs remain in
fresh `build/pr320-browser-private/attempt-*` directories. Installed browser execution remains pending.

Two packaged source-built distribution/signed-app cohort checks passed in 231.566s after correcting
an initial missing `PYTHONPATH` configuration. The composed suite passed 123 tests after original
receipt integration. Shared supervisor/protocol/worker/registration tests passed 58 tests. The public
supervisor projection additionally passed 3 isolated local root fixture tests; these do not install or
start a protected service. The final installed-tooling regression run passed 811 tests with 41 fixture skips
(`build/pr320-final-installed-regressions.log`). This includes source-contract, driver, capture,
cleanup and failure tests; it does not execute the installed VM or browser collectors. The exact-plan
capability regression passed 13 tests. The final combined original-chain, campaign, consumer, acquisition, worker, registration,
protocol and supervisor run passed 103 tests in 21.876s
(`build/pr320-final-original-and-worker.log`). It executes the real owning validators and original
chain checks with external artifact/attestation/product providers or OS boundaries substituted as
declared in each fixture. A broader shared-authority run passed 148 tests with four fixture skips
(`build/pr320-final-shared-authority-tests.log`).

Earlier broader offline checks passed: network-scale 3, cross-version 155, maintenance 247,
Phase 12 runtime 185 and release certification 50 tests. These are distinct from the Java suite and
from installed observations. The final installed driver tests include genuine OS prerequisites that
skip in this container; a skip grants no observation. The physically separated production/kit export
smoke passed three tests, and the combined export/privacy run passed 14 tests in 10.388s
(`build/pr320-final-export-and-privacy.log`). Fresh isolated children resolve all 17 profiles and
19 original members through actual exported owners, without checkout fallback. Missing or changed
kit helpers reject. Root ownership, installed identity and fixed-prefix providers are explicit offline
seams; this does not establish qualified-host execution, Java fixture materialization or systemd custody.

## Operational prerequisites and PR-321 handoff

Installed and original operations require separate explicit authorization, the qualified dedicated
host/VM, approved immutable installed source/kit/verifier/provider trees, signed synthetic fixtures,
original workflow/attestation authority and the retained failure/cleanup policy. Before any VM
allocation, apply the inventory, dependency, total disk budget and reserve rules in `AGENTS.md`.
No VM, workflow dispatch, upload, release, commit, push or merge was performed for this work.

PR-321 owns supported macOS/Windows/path regressions, exact-source CI execution and the remaining
inherited analyzer/source-pin drift. PR-320 owns the budget producers/drivers/consumer behavior
above and fixes its introduced failures here. PR-322 still owns broader finite-native installed
acceptance and protected enablement; PR-330 owns full-system short integration. Original resource
baselines/approvals, continuous soak, Mail, independent review, maintenance/publication/support
lifecycle and final Phase 12 completion remain separate requirements.


The protected preparation sequence uses the existing approved workflow with fixed `budget-prepare`
and `budget-collect` operations, followed by `authorize`, `start`, `checkpoint` and `finish` as
needed. Each request needs its own administrator registration for the exact original job and frozen
input scope. Preparation is asynchronous; authorization requires successful stopped preparation.
Start reauthenticates the original authorization and starts the fixed acquisition unit. A later job
may poll the same frozen source/bundle/configuration/input scope, while original start-job custody
remains independently retained. These are prepared workflow changes; no dispatch occurred.


## Source review and fixed-cutoff comparison

The successor inventory is version 6. The new budget implementation/test roster belongs only to
`p12-300-adapters` and `p12-300-consumers`; both declared states remain partial. Existing byte pins
for the touched shared runtime and assessment files are separately reviewed in `p12-295-origin`,
`p12-296-subjects`, `p12-296-federation`, `p12-300-72h`, `p12-303-reconciliation` and `p12-303-public`.
The additional runtime adapter does not alter their old product, subject, federation, duration,
reconciliation or public-observation rules. Untouched inherited source/owner-policy drift is retained.

The review verifies every mandatory ID, assertion, dimension, subject, prerequisite, applicability,
owner mapping, closure, residual, declared implementation state and historical file byte against the
starting inventory. The implementation roster and reviewed scope constant change prospectively;
accepted obligations and historical clocks stay fixed. The detailed local byte review is retained at
`build/pr320-source-pin-review.json`. This is an internal source review, not independent human
security approval or an operational authority.

At the identical cutoff `2026-09-13T10:30:00Z`, the reviewed assessment retains **49 mandatory
requirements and 47 unresolved**, with Phase 12 incomplete. The initial post-edit assessment showed
49 unresolved because affected dependent source pins had drifted. The narrow dependent review
restores the two previously satisfied repository reconciliation/public assertions; it supplies no
new operational acceptance. Budget adapter/consumer implementation dimensions remain unknown where
untouched inherited pins still differ: `cross_version_runtime.py`, `federated_catalog_runtime.py`
and the inherited PR-304 product-consumer integration test. PR-321 must reconcile those sources
against their owning semantics rather than mechanically resealing them.

Final source remains the uncommitted feature working tree based on
`3ddb5e432ee357446a3f6cb2bfcc6b697b266148`. The full build, focused checks and packaged artifacts
were produced locally from their recorded working revisions. They are not exact-source hosted CI
or observations of a published candidate. The final working-source manifest records changed/new
file hashes separately from Git HEAD; future original observations must select the actual reviewed
committed/installed source and exact product bytes.


The final export/acquisition/privacy run passed 35 tests in 10.761s, including the unprivileged
actor's read-only installed verifier and rejection of root custody in that context. The final
startup/export/acquisition run passed 46 tests in 10.302s (`build/pr320-final-start-export.log`).
The startup regression requires an actual selected unit process after asynchronous submission;
a queued/activating request with PID zero is insufficient. These are local source/OS-provider
fixtures, with no service execution. The final policy/public projection suite passed 89 tests,
and the reviewed policy/privacy/original suite passed 53 tests before the final byte refresh.

## Review regression corrections

The subsequent review confirmed five failures that the earlier focused tests missed. Host-origin
validation now derives HTTP/HTTPS from FProxy's actual SSL configuration. Relative browser targets
can therefore authorize matching HTTPS app mutations, while wrong schemes and ports are still
denied before routing or password checks. The historical PR-318 materializer retains its own tool
roster and does not require prospective campaign inputs.

Each prospective daemon invocation now exclusively creates `logs/stdio-<INVOCATION_ID>/` with its
own two streams and version-2 receipt. The launcher takes this generation from PID1 before clearing
its environment. Successive launches retain earlier bytes and receipts; an abrupt generation with
no terminal receipt stays incomplete. The privacy administrator reads the current invocation's
streams together with ordinary base logs, rejects ambiguous or foreign-generation output, and
binds the terminal receipt to the original observed manager invocation.

After admitting a selection and checking that the whole fixed role pool is stopped, the root
preparer writes only its owned `20-cryptad-workload-runtime.conf` under the four instance directories
in `/run/systemd/system`. Privacy receives `RuntimeMaxSec=7200`; subsequent profiles explicitly
restore 3600. Existing unrelated bytes and symlinks are rejected. Preparation reloads PID1 and
requires each unit's loaded `RuntimeMaxUSec` to match before launch. The hardened controller retains
its existing permissions. This allows the authentic one-hour browser session to expire after app
startup within a sufficiently long selected campaign; a short campaign still cannot claim expiry.
The subscription summary is collected while that original session is valid. The original expired
credential remains the negative control, including the later browser denials.

Review verification is local: all 97 HTTP bridge tests pass, and the final file-specific SonarLint
report has no findings. Error Prone reports have no findings in the touched HTTP production/test
files. The offline installed-tooling/export suite ran 170 tests with eight expected skips; separate
root-owned lifetime/preparation fixtures passed five tests with every PID1 command intercepted.
The composed-budget suite ran 112 tests with seven expected skips, and original-chain/admission/
consumer checks passed 18 tests. The final privacy/export checks were repeated after tightening
generation selection. Logs are retained at `build/pr320-review-*.log`. These fixes have not been
exercised against a live installed role, an actual one-hour expiry, or a VM. Earlier packaged
artifacts predate these corrections and must be rebuilt for any future installed observation.

The next integration review confirmed four additional defects. All seven route profiles now pin
the campaign journal, and their contract requires the resulting selected-source campaign inputs.
The regression calls each real route materializer and then protected selection recognition; it
also rejects an otherwise rehashed selection with the campaign commitments removed.

The privacy browser helper retains the fixed separate kit root for kit-local readers and uses
`/opt/cryptad-cross-version/current` for product contracts, process utilities and the collector CJS.
A fresh isolated child exercises the exact helper source against physical product/kit exports,
with only their fixed directory provider mapped to temporary fixtures. No parent's repository
imports are available. The packaged Web Shell reader now permits up to 512 KiB, since the actual
script exceeds its old 256 KiB ceiling; exact hashing, stable descriptors, ownership, and ZIP
member checks remain required. Its root-owned fixture uses the actual current script and rejects
an oversized or missing resource and a substituted archive symlink.

The prospective browser descriptor now carries `servedScriptDigest` independently of
`producerDigest`. Its selection pins the Web Shell resource as `webShellScript`; the schema and
code require this binding for browser members only. Prospective journal validation checks the
browser's served bytes against that digest, while original campaign admission additionally
requires agreement with the administrator's packaged-script receipt. A complete native/browser
journal with different collector and served-script hashes passes local recomputation; substituted
or missing served-script bindings fail. Historical attachments and their limits stay unchanged.

Support digest verification uses Web Crypto when available and a bounded SHA-256 implementation
otherwise. This preserves normal and recovery downloads on non-secure HTTP origins. The fallback
implements the [RFC 6234 SHA-256 algorithm](https://www.rfc-editor.org/rfc/rfc6234), and 18 vector
inputs match Node's independent SHA-256 across three crypto contexts, including Unicode, block
padding boundaries, a million bytes and the 2 MiB input ceiling. Chromium tests verify both secure
and non-secure origins with exact numeric/Unicode wire bytes, recovery downloads, digest rejection,
failed-refresh invalidation, and empty persistence. The non-secure test checks that Web Crypto is
actually absent; it does not claim clipboard availability on that origin.

The second review's local logs are `build/pr320-review2-*.log`. All 2,399 certification self-tests
passed in 918.787 seconds. The Web Shell's three resource tests passed; installed/export checks
ran 45 tests with one expected skip, covered separately by the passing root-owned package fixture.
The journal suite passed eight tests, including schema acceptance/rejection. The post-refresh
policy/integration suite passed 107 tests, and the same-cutoff assessment retains 49 mandatory
requirements, 47 unresolved, and Phase 12 incomplete. The Web Shell resource tests,
isolated export checks, protected-admission fixtures, and journal recomputation establish local
behavior only. No installed browser provider, live role, protected job, VM or publication has been
executed for these corrections. Earlier artifacts and original input commitments must be rebuilt
from the final committed source before any future installed observation.

The subsequent isolated-entry review reproduced a startup failure in both configured
`/usr/bin/python3 -I -S` services: the budget contract was imported before their trusted sibling
module path was initialized. The controller now imports that contract after its existing path
bootstrap. The launcher performs the same source-directory bootstrap at module entry, before
its sibling import, and no longer repeats it inside `main()`. Entry, UID, capability, cgroup,
installed-source, input-tree and deadline checks retain their existing behavior.

Two fresh-process regressions use the configured isolation flags with a hostile contract in the
working directory and `PYTHONPATH`. Direct entry invocations reach their argument guards without
an import traceback, and isolated module loading constructs all 84 role commands for the four
legacy/default and 17 prospective profiles. The workload/profile/export suite ran 135 tests with
five expected skips, and original-chain/admission/consumer checks passed 18 tests. These checks
exercise import startup and command construction; they do not start installed services or daemons.
The third review's retained logs are `build/pr320-review3-*.log`.

The next review reproduced two integration failures outside the previous focused checks. A single
300 KiB send on the driver's default Linux `SOCK_SEQPACKET` socketpair fails with `EMSGSIZE`, even
though such a privacy receipt fits its permitted serialized budget. Privacy replies now use a
versioned length/digest header followed by ordered 16 KiB payload chunks. The observer reassembles
the complete original JSON bytes and validates their length and SHA-256 before decoding. The 2 MiB
reply ceiling remains; one absolute deadline bounds the entire request/transfer, and incomplete,
reordered, corrupt, oversized or truncated packets cannot become an accepted receipt. Other
administrator methods retain their existing transport. Both private privacy endpoints must come
from the same reviewed kit revision; receipt contents and retained original formats are unchanged.

The downstream maintenance adapter now checks the historical measurement/report version
relationship against `budgetCampaignBaseVersion` when a schema-v8 campaign receipt wraps the
finish report. It preserves the direct historical version check for unwrapped reports and the
independent recomputation/product/lineage checks. The regression exercises actual owner validation
and authenticated lineage for measurement versions 2, 3 and 6, compares wrapped results with their
historical results, and rejects substituted base versions, products and measurements. Version 6
also verifies that the outer report's base version remains distinct from its measurement's own
composed-format base version.

Real socket tests drive the installed sampler and observer adapter with snapshot and browser
receipts larger than 300 KiB, preserve exact bytes through the 2 MiB ceiling and chunk boundaries,
and reject malformed or interrupted transfers. Budget errors and collector failures remain closed
after framing. The corrected workload-driver/privacy/export/original/maintenance adapter command
ran 210 tests with 23 expected skips. These local checks execute neither installed roles nor
protected operations. Fourth-review logs are retained at `build/pr320-review4-*.log`.

All 2,400 certification self-tests passed in 953.955 seconds after these fixes. The additional
maintenance-validation, baseline-consumer, supervisor-projection and privacy regression suite ran
23 tests with two expected skips. The reviewed source inventory preserves the 49 mandatory
requirements and immutable historical bytes; same-cutoff assessment recomputation still reports
47 unresolved and Phase 12 incomplete. These checks supply no live or protected observation.
