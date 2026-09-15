# PR-310 workload isolation implementation gap

PR-310 does not yet separate the existing runtime observer from its candidate daemon processes.
The restricted controller therefore rejects supervisor authorize, start and checkpoint through its
new channel. This is an incomplete mandatory implementation requirement, not merely an unavailable
production observation. The installed observer bootstrap and service hardening do not close it.

The existing tokenless `cryptad-soak` observer launches candidate code under its own UID. Distinct
resolver/native-verifier isolation does not prevent that candidate from reaching observer-owned
runtime state. No host `CAP_SYS_PTRACE`, broader sudo grant or caller assertion enables this path.

## Prospective PR-311 dispositions

[PR-311 preparation](pr-311-observer-workload-isolation.md) moves new expected process identities
to observer control layout 2, updates all live runtime/scheduler readers, bounds catalog installed
file observations and native output, excludes synthetic test seams from new production bundles,
and repairs disposable controller/socket cleanup. Old run bytes remain historical. The daemon
still shares the observer UID, and the controller-owned workload launch/network/lifecycle adapter
is missing; these changes do not reopen restricted execution or establish installed acceptance.

## Required storage separation

The following are current paths relative to the selected experiment root, not a new approved
storage schema. A complete replacement must preserve exact original selection and recovery
semantics while separating writable workload data from retained observer authority.

| Current path or owner | Required treatment | Actual source |
| --- | --- | --- |
| `lease`, journal/checkpoint state, `runtime/owner.json` | Retain exclusively under observer control; candidate cannot replace ownership or execution history. | [Runtime observer](../tools/interop/cross_version_runtime.py), `validate`, `prepare`, `save_state`, `resume` |
| `runtime/runtime-state.json` | Retain observer-only. Contains process epochs, private operation state, canaries, admission observations and recovery state; it is not candidate input. | [Runtime observer](../tools/interop/cross_version_runtime.py), `save_state`, `resume` |
| Historical `runtime/<role>/node/run/process-identity.json`; new `runtime/control/processes/<role>.json` | New live readers/writer use observer control layout 2, without a node-file fallback. Historical files remain unchanged. Distinct-UID kernel observation and physical separation are still missing. | [Runtime observer](../tools/interop/cross_version_runtime.py), `start`, `sample_resources`; [scheduler observer](../tools/interop/scheduler_pressure_runtime.py), resource and measurement acquisition |
| `runtime/<role>/node/{config,data,cache,run,logs}` | Give only the selected workload the necessary writable subtree. Candidate-generated configuration, logs and process claims remain untrusted bounded inputs. | [Runtime observer](../tools/interop/cross_version_runtime.py), `prepare`, `start`, `resume` |
| `runtime/<role>/package`, staged apps and public trust registries | Expose exact admitted code and the scoped verification material needed by that workload. Candidate must not replace the observer's retained expected digests or another role's package/input set. | [Runtime observer](../tools/interop/cross_version_runtime.py), `prepare`; [catalog runtime](../tools/interop/federated_catalog_runtime.py) |
| Catalog `transport-operations.json` and operation intents | Keep observer-owned, separately from the catalog node and registry files modified by its lifecycle. | [Catalog runtime](../tools/interop/federated_catalog_runtime.py), `Journal`, `start`, `request`, registry selection |
| `/var/lib/cryptad-cross-version/selected` | Preserve authoritative exact input bindings and restrict candidate visibility to its explicitly required data. Do not make the selected root writable merely to permit traversal. | [Service](../tools/interop/cross_version_service.py), `load_selection`; [supervisor authority](../tools/release-certification/protected/cross_version_supervisor_authority.py), `selected_inputs` |
| `/var/lib/cryptad-cross-version-authority` and baseline/reference private stores | Preserve controller ownership, activation/deadline, original approval and revocation history. Neither candidate nor observer may rewrite root-owned authority. | [Supervisor authority](../tools/release-certification/protected/cross_version_supervisor_authority.py); [baseline approval](../tools/release-certification/protected/runtime_baseline_approval.py); [reference ledger](../tools/release-certification/protected/runtime_reference_ledger.py) |

Current private experiment roots require owner-only permissions. Adding traversal permissions or
changing all ownership checks to accept the current caller would weaken the existing contract.
Candidate files can contain symlinks, replacement races, restrictive modes and misleading process
identities; storage transfer must account for these without treating child output as authority.

## Required process integration

The launch inventory includes the packaged daemon in `cross_version_runtime.Supervisor.start`,
the catalog daemon and Java tools in `federated_catalog_runtime`, and the Java exporter and Node
driver in `scheduler_pressure_runtime`. A change to the first `Popen` alone does not establish a
complete boundary. Separate each candidate operation from observer-owned control, original
provider credentials, resolver material, unrelated sockets and sibling workload data.

The existing observer hashes `/proc/<pid>/exe`, verifies wrapper/JVM ancestry and checks start
epochs. Resource collection additionally reads process status and file-descriptor information in
`cross_version_budget`. A distinct host UID can deny these accesses. Giving the observer host-wide
ptrace authority would let it inspect resolver memory and is not an acceptable fix.

A future design must provide bounded process observation and cleanup for exactly the owned
workload while preserving the existing supervisor, cgroup, boot identity and terminal checks.
Namespace capabilities are a possible design input, not an implemented or tested guarantee here.
Changing PID namespaces can change the meaning of retained process IDs and external terminal
collection. Such a change requires an explicit compatible identity contract and real kernel tests.

## Evidence and reopening criteria

The installed source snapshot now requires administrator-approved source and dependency closure
verification. Its bundle and execution dependency closure contribute to the runner fingerprint;
an older baseline is not silently rewritten to describe this environment. Fixed baseline and
supervisor owner adapters preserve their original source, approval and lifecycle checks.

Reopen supervisor execution only after a real disposable installation runs the required positive
path under separate observer/workload UIDs, demonstrates denial of observer state and credential
access, and verifies exact restart, timeout, cancellation and stopped-terminal recovery. Mocked
systemd or UID tests do not satisfy that requirement. Historical PR-308/309 artifacts retain their
schemas and acceptance meaning. The twelve remaining PR-309 consumer cases and Phase 12
operational, review and publication obligations remain open.
