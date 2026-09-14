# Restricted worker and private resolver isolation — incomplete implementation

PR-310 adds an installed local controller, private maintenance adapters and a distinct native
verifier UID. **It does not yet satisfy the requested complete isolation boundary.** The runtime
observer and candidate workload still share a UID; new supervisor authorize/start/checkpoint
requests therefore reject. The mandatory installed service/UID positive lane has not executed.
This remains Phase 12 remediation, not Phase 13 or deployment approval.

## Source and audit

Work started from clean `develop` commit `570e36af184c6491d8f275840fccb67ab52c5a6f`, tree
`5d7e925f0338af5a4e7737c8ec097f40da4fbcd8`. Read-only GitHub inspection confirmed PR #1411's
final head `be01ae2cae76a7c65410be7d03244f16092d5984` and merge time
`2026-09-14T17:17:36Z`. The older embedded PR-body head was not used. At initial recheck,
merge CodeQL `34873866000` had succeeded and merge Java CI `34873867793` was in progress.
These checks identify the predecessor; they do not test this working tree.
The final recheck found merge Java CI `34873867793` completed successfully on that exact squash.

| Audited area | Reused owner | Change and remaining gap |
| --- | --- | --- |
| Private CMS | `maintenance_runtime_companion` | No crypto, recipient policy, five-member roster or freeze contract changes. |
| Native export/admission | `maintenance_runtime_metadata`, `app_subject_projection` | Fixed native bridge copies only mapped inputs and drops actual host UID before bwrap. Real installed positive execution remains unverified. |
| Private production/validation | `seal_private_freeze`, `original_context` | New fixed adapters call real owners; original verification and in-process capabilities remain required. |
| Installation | Fixed `/opt/cryptad-cross-version/current` | Manifest bundle, dependency inventory, isolated bootstrap, explicit install/verify/upgrade; current remains a real directory. |
| Request/retention | Existing original GitHub authentication | Fixed framed Unix socket, root registration, kernel UID check, original job check, durable intent/result; no runner paths or credentials. |
| Baseline and terminal | Existing PR-308 owners | Structured adapters preserve actual reviewer decisions, ordered attempts, expiry and stopped-run checks. Socket lifecycle integration remains unexecuted. |
| Workload observer | Existing `cryptad-soak` service | Bootstrap and hardening added; **candidate/observer UID and storage split is not implemented**. See the [specific gap map](pr310-workload-boundary-gap.md). |
| CI/conformance | Existing native PR-307 fixture | Disposable harness exists; current CI records prerequisites and does not run the mandatory VM lane. |

The initial inventory also found hosted `apt-get` packaging, hosted legacy cohort installation,
four fixed supervisor sudo operations, baseline prepare/approve sudo calls, fixed systemctl
show/start/stop, root activation/ledger writes, private CMS/selection reads and every native launch.
The two scoped supervisor/baseline workflows now call the installed client. The old hosted
selected-federation maintenance guards remain closed. No sudo wrapper was restored.

## Threat model and reference profile

The prospective reference is a dedicated Debian 13 Linux VM with systemd 257 and Python 3.13.
Development discovery observed Debian 13.7, systemd 257.13, Python 3.13.5, OpenSSL 3.5.7 and
OpenJDK 25.0.4.1. Those are observed tool versions, **not a tested VM image**. The development
account has unrestricted sudo; this host is not the restricted reference. The disposable probe
returns exit 78 here, without provisioning.

Trust includes the host kernel/service manager, out-of-band administrator, provisioned interpreter
and loader, reviewed immutable helper/dependency closure, original source authorities and required
credential issuers. Host root and hypervisor compromise are outside the claim. Treat runner code,
checkout/action/cache contents, artifacts, candidate Java, input JSON, filenames and child outputs
as potentially hostile. An administrator-controlled image and runner group are prerequisites;
no finite probe proves the absence of every escalation path.

| Principal | Intended access | Current limitation |
| --- | --- | --- |
| `cryptad-runner` | Local socket; an exact pre-registered method/handle; bounded safe output | One dedicated job at a time is required. Peer UID cannot distinguish concurrent jobs sharing that UID. |
| Root controller/resolver | Existing root-only private APIs; fixed lifecycle and original-provider reads | Parsing/crypto remain in the reviewed root TCB. This is not a fully reduced-privilege resolver. |
| `cryptad-native` | Fresh copied inputs, approved materialized JDK/tools, one bounded projection | Scoped selection legitimately enters its intended verifier. Covert-channel freedom is not claimed. |
| `cryptad-soak` | Tokenless observer and retained runtime inputs | Currently also launches candidate processes; new execution remains blocked. |
| `cryptad-workload` | Reserved distinct workload role | Full launch/storage integration is missing. Creating this account alone establishes nothing. |
| Collector | Existing retained terminal state and safe projection | Cannot launch new work or grant approval. |

The installer rejects shared/root role UIDs, privileged runner groups, permitted sudo,
unreviewed local Polkit rules, active runner capabilities, altered units/dependencies and missing
native namespace support. Dedicated runner-group/workflow restrictions must be configured outside
the evaluated job. This session did not inspect or change organization settings. No Docker,
containerd, LXD, KVM or hypervisor control socket may be available to the runner.

## Installation and immutable code

The implementation is in
[`tools/release-certification/restricted`](../tools/release-certification/restricted/installation.py).
Default preparation and verification do not create users or install services. Use a separately
reviewed clean committed checkout; local uncommitted changes cannot be an approved installation.

```bash
python3 -I -S tools/release-certification/restricted/installation.py plan \
  --source "$PWD" --output /tmp/cryptad-reviewed-bundle
python3 -I -S tools/release-certification/restricted/installation.py host-plan \
  --bundle-identity REVIEWED_MANIFEST_SHA256 > /tmp/cryptad-image-review.json
```

`REVIEWED_MANIFEST_SHA256` is the exact `bundleIdentity` returned by plan, not a product SHA.
An authorized administrator must review the bundle, dependency inventory, host configuration,
exclusive runner routing and original authority before separately installing the root-private
approval as `/etc/cryptad-certification/restricted-installation.json`. This is an explicit
administrative action, not a workflow step. No approval file or key was installed in this session.

On that approved disposable/reference host, the administrator executes:

```bash
python3 -I -S /tmp/cryptad-reviewed-bundle/tools/release-certification/restricted/installation.py \
  install --bundle /tmp/cryptad-reviewed-bundle
python3 -I -S /opt/cryptad-cross-version/current/tools/release-certification/restricted/installation.py verify
```

The actual sysusers/tmpfiles/socket/service manifests are bundled. Installation verifies and
creates version-addressed trees under `versions/<bundleIdentity>`, then a real `current` tree.
It installs units but does not start the socket or workload. The administrator alone starts
`cryptad-restricted.socket` after review. Never install the old supervisor sudoers grant for this
profile. Never install keys in an ordinary PR runner environment.

`-I -S` removes Python environment/user/site startup hooks; it cannot validate the interpreter
before that interpreter runs. The provisioned interpreter/loader is initial TCB. Bootstrap checks
the verifier bytes before import, then the complete helper source and approved runtime dependency
inventory before sensitive imports. Environment and inherited descriptors are reset. The inventory
includes fixed executables, Python and ELF/library trees, symlink targets and loader configuration.
Approved JDK/tool identities remain independently checked by existing native owners; raw distro JDK
symlink trees are not substitutes for the existing approved materialized JDK contract.

Service settings include no-new-privileges, private temporary/device views, read-only system/code,
bounded tasks/memory/CPU/I/O, no core dumps and an explicit capability set. Native `setpriv` removes
groups and all capabilities before bwrap. JVM JIT remains available; no memory-execute prohibition
is asserted. Effective settings must be verified on the actual supported VM.

## Registration, execution and output

The root-only installed
[`restricted_registration.py`](../tools/release-certification/protected/restricted_registration.py)
registers exact context and bounded input snapshots. It is not exposed through the socket.
The administrator supplies method, original workflow source/run/attempt/job, authorization and
collection intervals, and fixed configuration records. The helper binds its own installed version
and fixed runner UID and chooses the random handle. Its reservation/binding commands permit a
handle to be selected before the original job identity is known; reservation alone grants no work.

```bash
python3 -I -S /opt/cryptad-cross-version/current/tools/release-certification/protected/restricted_registration.py \
  --reserve maintenance-prepare
python3 -I -S /opt/cryptad-cross-version/current/tools/release-certification/protected/restricted_registration.py \
  --handle RESERVED_HANDLE --context /root/reviewed-context.json --inputs /root/reviewed-inputs
```

The context has exactly `method`, `context`, `notBefore`, `expiresAt`, `collectUntil` and
`configurationFiles`. The inner context contains `sourceCommit`, `runId`, `runAttempt` and `jobId`;
configuration files are an administrator-selected list under `/etc/cryptad-certification`.
Those workflow identities are checked against the provider before work; registration is not a
substitute for that check. Existing supervisor/baseline owner source-equality rules remain in
force; broader independent helper/workflow revision dispatch is not implemented by this patch.

Private original-provider access uses only the fixed root-private
`/etc/cryptad-certification/restricted-provider.json`, containing `token` and `expiresAt`.
The controller requires an expiry within one hour. Provisioning must supply a minimal read
credential through an existing trusted administrator/issuer channel; no new PAT or credential
authority is created. The runner's token and `GITHUB_*` environment never enter the service.
Existing PR-307 recipient/selection paths and root ownership checks remain unchanged.

Requests are length-prefixed JSON, maximum 256 bytes, with exactly `method` and a 64-hex `handle`.
Only fixed operation names and `collect` are accepted. Responses are bounded to 4 MiB. The serial
daemon admits only the fixed runner UID, rate-limits requests and uses the configured socket
backlog. Peer identity is combined with root registration and independent original GitHub job
verification. Actual baseline reviewer checks remain in the owning approval implementation.

| Method | Current route |
| --- | --- |
| `maintenance-prepare` | Authenticate selected originals, native generation under separate UID, seal five members once, retain exact freeze/descriptor/CMS. |
| `maintenance-validate` | Original outer/member authentication before decryption, private inner/native revalidation, ordinary maintenance engine under the real owning context. |
| `baseline-prepare`, `baseline-approve` | Existing proposal/reference/reviewer owners; positive socket integration not yet executed. |
| `supervisor-finish` | Existing original lineage and stopped terminal owner; positive socket integration not yet executed. |
| `supervisor-authorize`, `supervisor-start`, `supervisor-checkpoint` | Explicitly blocked by the missing workload/observer boundary. |
| `collect` | Existing exact completed result only; no execution, decryption, approval or deadline reset. |

Maintenance input filenames are fixed beneath `operations/<handle>/inputs`: `freeze.json`,
`package.tar.gz`, and `projection-origin.json` for preparation; validation additionally uses the
registered `manifest.json`, `runtime/` and the normal complete confined input set. Configuration,
manifest and tool paths are administrator-owned selection, never request fields. Output stays
within the private operation root. Native output cannot supply `_SEAL`, `AuthenticatedProducts`
or a serialized Python capability.

The controller writes and fsyncs intent before invoking an owner. Exact completed retries return
the retained result; interrupted intent does not rerun encryption or launch. Torn records stay
incomplete. Result-transfer failure leaves retained bytes for later collection. A receipt binds
the operation/helper/result but is not independently sufficient authority. Original supervisor
and baseline consumers first authenticate the original producer/member, then compare exact bytes
with the matching root-retained result for sources governed by the installed contract, and still
perform existing owning checks. Runner-reuploaded replacements cannot create an owning capability.

Public results are constructed by the operation owner. Private selection/cohort values, private
hashes, raw native output, private absolute paths, credentials and exception text are excluded.
Errors on the socket are fixed unavailable responses. The shared redaction scanner is secondary;
it does not make arbitrary native text safe. Ciphertext export/download integration into the
hosted maintenance workflow remains incomplete; those hosted guards are intentionally retained.

## Recovery, upgrades and removal

Retain `registration.json`, `intent.json`, `result.json`, existing baseline/reference ledgers and
activation records. Unknown or partly written state needs administrator investigation and cannot
be repaired by deleting roots or retrying under a new operation to obtain clean evidence. Terminal
collection does not reset execution or approval clocks. Per-operation `revoked.json` and the
monotonic version revocation history reject reuse.

`upgrade --bundle <reviewed-bundle>` requires the socket, controller and soak service stopped,
new separately approved bytes/dependencies and revocation of the previous helper. It retains
old trees and journals. Activation uses real-directory renames under an administrator lock;
an interruption between renames leaves the service unavailable and both trees retained. Recover
only after inspecting the exact approved identities. Rollback cannot erase recorded revocations.
This conservative stopped-host procedure does not silently change code underneath an operation.
Changed helper/dependency fingerprints require new applicable references and approval.

Safe removal is also an administrator operation: stop/disable the fixed socket and services,
verify their cgroups are empty, retain/reconcile all operation and security history, then remove
only the reviewed installed unit/code assets. Do not recursively delete evidence roots, recipient
keys or shared accounts to uninstall. No uninstallation was performed here.

## Verification and residual acceptance

The executable disposable harness refuses unsupported hosts and existing installations:

```bash
python3 tools/release-certification/restricted/disposable_integration.py --probe
# Only as authorized root inside a fresh disposable Debian 13/systemd 257 VM:
python3 tools/release-certification/restricted/disposable_integration.py \
  --disposable-vm --source /root/cryptad
```

The harness contains actual service/socket and UID denial probes, a hostile native helper, and
the real PR-307 CMS/native fixture with synthetic external-provider seams. Its positive worker is
test-harness-launched so no production bootstrap exposes those seams. Production-bootstrap
positive execution, baseline/terminal socket paths and the complete fault/adversarial matrix are
still missing verification. This session's exit-78 probe is **unexecuted**, not a passed isolation
lane. The new ordinary CI job reports that gap; it does not provide the required VM execution job.

The retained before assessment is `build/pr310-phase12-before`, cutoff
`2026-09-13T10:30:00Z`: 49 mandatory, 47 unresolved, `phaseComplete=false`. Updated assessments
retain that cutoff and scope. Mutable implementation source pins may be refreshed to current
bytes; historical tracker/policy/report bytes, assertions and requirement membership are not
changed. Artifact tests, local native fixtures, installed isolation, deployed host, original
protected observation, production approval and Phase 12 completion remain separate dimensions.

Actual local verification logs are retained in `build/pr310-verification`. They are local test
artifacts, not attested production evidence:

| Executed command | Result |
| --- | --- |
| `./gradlew :platform-devtools:installDist assembleCryptadDist` | Passed in 1m 5s; 342 tasks, 91 executed. |
| `./gradlew test` | Passed in 3m 40s; XML inventory 17,405 tests, zero failures/errors, 10 skips. |
| `certify.py stable-maintenance --self-test` | 247 passed. |
| `certify.py cross-version-soak --self-test` | 150 passed. |
| `certify.py stable-platform-api-1x --self-test` | 88 passed. |
| `certify.py phase-12-closeout --self-test` | Final 185 passed. Initial failures exposed changing source pins and an accidental historical tracker edit; the tracker was restored byte-for-byte, and only 14 mutable source digest entries were refreshed. |
| `python3 -m unittest discover -s tools/release-certification/protected -p 'test_*.py'` | 287 tests, zero failures/errors, 50 existing prerequisite skips. |
| `PYTHONPATH=tools/release-certification python3 -m unittest cryptad_certification.tests.test_pr307_product_consumer_integration` | One real CMS/native product-consumer fixture passed in 53.952s, no skips; not the installed multi-UID lane. |
| `python3 -m unittest discover -s tools/release-certification/restricted -p 'test_*.py'` | 13 passed; artifact/harness contracts only. |
| Focused PR-308/309 owner regressions | 74 composed/pressure/supervisor, 17 resource-budget, four sealed-measurement tests passed. Runtime/reference discovery ran 76 tests with 50 prerequisite skips. |
| `actionlint` on the three changed workflows; `systemd-analyze verify` on all three units | Passed syntax/configuration checks; no effective running-service claim. |
| Python compilation and relative-link/whitespace checks | Passed. |

The Gradle test log has 103 compiler warning diagnostics in unchanged sources/tests, plus Gradle
deprecation and JVM instrumentation notices. No new Java source was changed. No fresh SonarLint,
SonarCloud or independent security assessment is claimed. The native bridge and durable protocol
tests establish their specific local contracts; mocked authority seams do not count as actual
root/peer/provider isolation. The final fixed-cutoff successor assessment is separately retained
as `build/pr310-phase12-final`; `--require-complete` must reject it.

The twelve PR-309 consumer cases remain incomplete: import/fetch concurrency, timeout,
cancellation, retry, window crossing, partial rate write, graph store unavailable, graceful and
abrupt restart, diagnostics unavailable and privacy. `fullAppBudgets` remains not observed.
Mail lifecycle, independent review, migration/profile directions, long-run and publication
obligations remain open. PR-311's tentative budget work must not hide these PR-310 boundary gaps.

Mechanism references: [GitHub secure use](https://docs.github.com/en/actions/reference/security/secure-use),
[compromised runners](https://docs.github.com/en/actions/concepts/security/compromised-runners),
[Python isolated startup](https://docs.python.org/3/using/cmdline.html), and
[systemd credentials](https://systemd.io/CREDENTIALS/). These describe mechanisms, not approval of
this implementation. A protected environment is not OS isolation; neither DAC nor service
credentials protects secrets from actual host root.

## Review corrections: baseline workspace and stopped socket

Baseline prepare/approve now allocate their temporary workspace beneath the existing root-private
`/var/lib/cryptad-restricted/resolver` directory. Both entrypoints validate that directory's
ownership and permissions before use. The directory is already provisioned mode 0700 and covered
by the controller's narrow writable paths; `/run` remains read-only. Normal and exceptional owner
exit clean up the temporary workspace. A service crash can leave private scratch for administrator
reconciliation, as with the other resolver state.

Upgrade checks socket `ActiveState=inactive` and `SubState=dead` without requesting `MainPID`.
Both services still require those states and `MainPID=0`; missing state, a live PID, transitioning
units or a failed systemctl query reject the upgrade before version activation.

Two workspace regressions reach the prepare/approve owner configuration boundary and exercise
real private file creation and cleanup. Four upgrade regressions cover stopped socket acceptance
and rejection of active/transitioning sockets, nonzero or missing service PIDs, and query failure.
The disposable harness additionally checks real stopped-unit output and temporarily replaces only
the controller's ExecStart/Type to run the workspace regressions with its actual filesystem and
capability settings. The test verifies `/run` is still read-only and restores the original unit
configuration afterward. Upstream identity checks are test seams; these tests grant no approval.
This actual-unit lane remains unexecuted here (`dedicated-disposable-vm-required`); it is not a
production-bootstrap baseline approval or a completed full-upgrade integration test.

Review-fix verification: protected discovery ran 289 tests with no failures/errors and the same
50 prerequisite skips; restricted installation/harness discovery passed 17 tests; Phase 12
self-tests passed all 185 tests. Unit syntax and Python compilation passed. Four mutable baseline
implementation/test digest entries were refreshed without changing assertions or historical
files. The retained successor `build/pr310-phase12-review-systemd` uses the unchanged cutoff,
retains 47 unresolved requirements, and rejects `--require-complete` with exit 2.

## Review correction: native failure cleanup

The controller retains `CAP_KILL` so its existing bounded launcher can terminate the process group
it created after the native child changes host UID. The kernel capability is broader than that
group; the reviewed launcher limits the target to its own `Popen` process group and exposes no
caller-selected PID or signal operation. Native children still clear their bounding, effective,
permitted, inheritable and ambient capabilities. Installation verification now checks the exact
effective controller capability bounding set and rejects a missing cleanup capability or any
additional capability.

The disposable harness runs a new fixed native-cleanup probe using the controller's actual unit
settings and the normal native dispatch. A synthetic child records its unprivileged UID and zero
capabilities, then either times out or exceeds the output bound. The probe requires actual group
signaling, child reaping and return of the unit cgroup to its original membership before accepting
cleanup. It does not accept wrapper exit alone. The probe's temporary ExecStart override does not
change the unit's capability or filesystem restrictions.

Local review verification passed 20 installation/harness tests, nine native-boundary tests and
four bounded-process tests. Full protected discovery ran 289 tests with 50 prerequisite skips and
no failures/errors; its duplicate ZIP-member warning comes from the malformed-container fixture.
All 185 Phase 12 self-tests passed. Unit syntax, Python compilation and whitespace checks passed.
These checks do not execute the new
multi-UID controller-unit probe: the read-only harness probe still reports
`dedicated-disposable-vm-required`. Effective service cleanup remains an explicit unexecuted
verification requirement until that disposable lane runs. No host deployment or Phase 12
completion is established by this correction.

## Review correction: request-frame deadline

Receiving a request now has one five-second monotonic deadline shared by the length prefix and
payload. Each socket receive uses only the remaining budget; partial progress does not restart
the deadline. Expiry follows the existing unavailable-response and connection-close path before
any owner operation is invoked. The receiver restores the socket's prior timeout on both success
and failure. Client response reception explicitly retains a 900-second total budget to accommodate
the owning operation; the frame format and operation authorization are unchanged.

Regression coverage includes real local sockets with trickled prefix and payload bytes, a
controlled clock proving that prefix time consumes the payload budget, timeout restoration, and
the longer response budget. These tests establish local framing behavior, not deployed service
or multi-UID isolation.

## Review correction: retained-result revocation

Original-result admission now applies the same current operation and helper-bundle revocation
check as controller execution and collection, before reading the matching retained result.
Previously uploaded exact bytes therefore cannot bypass a later administrator revocation.
Missing, malformed or unreadable global revocation state fails closed. Any operation revocation
marker, including a dangling symlink, blocks admission. Revocations of unrelated operations or
helper bundles do not invalidate an otherwise matching result. Historical sources without a
matching restricted registration retain their existing historical scope.

Consumer-side regressions complete and admit a retained result, then independently revoke its
operation or bundle and require both original admission and collection to reject it. Additional
checks cover missing/invalid revocation state, unrelated revocations and a dangling marker.
These are durable-state tests with explicit original-authority and ownership seams, not installed
service-isolation evidence. Existing approval, native verification and original authentication
requirements remain in force.

## Review corrections: installed definitions and synthetic job identity

Install, verify and upgrade now share the same five-asset inventory: the three service/socket
units plus the sysusers and tmpfiles definitions. Verification compares installed bytes with the
approved bundle. Upgrade rejects differing account, directory or unit definitions before changing
revocation history or activating the new version; an administrator must review and replace them
while stopped. Missing installed definitions also fail closed. These checks do not automatically
apply account or directory migrations.

The disposable preparation fixture now indexes the job name by `maintenance-prepare`, matching
the worker's method-keyed policy. Its offline regression calls the real worker job-authentication
function with synthetic upstream responses and also rejects a changed source identity. Installed
asset tests cover missing/modified definitions and replacement requirements for a new bundle.
The actual disposable CMS/socket and service/UID integration lane remains unexecuted.

## Review corrections: baseline configuration closure and provisioning dependencies

Baseline registration requires an exact method-specific configuration roster. Prepare binds the
fixed preparation descriptor and every referenced campaign, policy, request and observation
bundle; approve binds its fixed original-proposal coordinates file. Missing and extra paths are
rejected. Execution rechecks the roster and digests, and each baseline owner configuration read
compares the bytes actually read with the registered identity. A change after preflight therefore
fails rather than supplying unregistered configuration to the owner. The binding context is
internal to the controller; original approval and retained-state authentication still apply.
Other operation owners retain their existing snapshot and activation contracts.

The dependency inventory now explicitly includes `systemd-sysusers` and `systemd-tmpfiles`, using
the existing exact-byte and resolved-symlink-target checks. Older approval inventories missing
either binary fail closed and require administrator review of a new inventory before installation.
No provisioning is performed by these offline regressions.

## Review correction: committed-object bundle provenance

Planning captures one commit identity and exports that commit's tree and raw blob objects through
Git, with replacement objects disabled. It no longer copies checkout bytes or uses index flags
as evidence of their identity. The existing clean-status precondition remains an operator check.
Executable modes come from the committed tree; blob object hashes are checked during export.
Symlinks, submodules and unsupported entries reject the plan and remove its partial output.
Checkout filters and archive attribute substitutions do not modify the exported source.

Regressions cover hidden `assume-unchanged` modifications, content/mode changes after the status
check, HEAD movement after revision capture, replacement blobs and committed symlinks. These
checks establish source-bundle provenance, not administrator approval or deployed isolation.
