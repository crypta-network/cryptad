# PR-316 namespace-bound Mail runtime consumer

This document records the PR-316 implementation boundary, runnable installed lane, and evidence
that remains unexecuted.

## Source and claim boundary

PR-316 starts from the PR-315 squash merge `cef2b4bb31beeace910df3d0bda7622779812256`.
Its tree, `279947ea66ff1fda1967bc683bf86636e82cc37d`, matches the final PR-315 feature
head. The accepted frozen PR-315 implementation remains
`2aaf4af7aaad9bc6b6a4d5e1682a2eaafe890c4f` with source tree
`0e30df3ba7ac73aedd514553693393eca47bf1f2`. The squash relationship does not turn
new PR-316 bytes into the accepted 45-case product.

The new Mail result never sets installed workload acceptance, finite-native acceptance, original
protected authority, independent review, release eligibility, or Phase 12 completion. The PR-315
21-group and 45-case registry, validators, seal, campaign owner, and archived receipts are
unchanged.

## Reused boundaries and implemented gap

| Boundary | Reused owner | PR-316 behavior |
| --- | --- | --- |
| Mail operations | Existing Java Mail worker, broker, vault, app data, queue and fetch routes | Python retains only command/result framing and flow assertions. It does not parse Mail commands in the controller or implement mailbox or cryptographic behavior. |
| Common demonstration | `tools/mail-prototype/two_node_demo.py` | A trusted in-process transport seam separates common command/result and flow logic from standalone HTTP. Standalone literal-loopback and distinct-target validation are unchanged. |
| Installed HTTP | `InstalledWorkloadAdapter.connection()` and `_RoleHttp` | Every Mail POST obtains one fresh controller-provided role socket. The client accepts only the two Mail browser paths, validates HTTP status and response bounds, and closes the response, connection and descriptor on every path. |
| Controller | Existing `connect-http` and `bootstrap-mail` methods | No Mail RPC, arbitrary endpoint selector, observer listener, namespace path parameter or worker token was added. |
| Authentication | `InstalledAppHandle.refresh_session()` and native browser-session/origin checks | The installed client binds the current role invocation, verified worker, admitted app, origin, session and expiry. A deliberate worker or role restart discards the client context and uses a fresh controller bootstrap. |
| Broker lifetime | Existing four-request, 30-second, current-launch broker | Completed results remain consume-once. The client does not resubmit a mutation after a lost result; it reports a bounded uncertain outcome. |
| Durable send retry | Existing Mail `retry` command | Only a returned durable Mail operation is retried. The consumer never calls a generic queue mutation, constructs a queue identifier, reseals a message or repeats compose/confirm to hide uncertainty. |
| Installed topology | Existing candidate sender, candidate recipient, distinct predecessor and app-free relay | Candidate Mail roles may use identical textual API addresses because the controller role handle and transferred socket identify the service. The predecessor and relay do not need Mail behavior. |

`_FixedSocketHttpConnection` deliberately rejects `connect()`. Assigning the controller-provided
socket is the only way to send a request; a closed or failed descriptor cannot fall back to
`socket.create_connection()`. The transferred HTTP socket must have the exact
`127.0.0.1:19402` peer. Its timeout is the minimum remaining request and retained campaign budget.
The adapter rechecks the role invocation after the response closes before the result can be
credited. These choices follow Python's documented automatic `HTTPConnection.connect()` behavior
and Linux `SCM_RIGHTS`, `SO_PEERCRED`, `MSG_CTRUNC` and `MSG_CMSG_CLOEXEC` semantics.

## Mail lifecycle behavior

The common flow now checks duplicate rejection before restart and again after the worker restart.
The installed lane then performs a real recipient role/daemon restart over retained role tmpfs,
rebinds to the changed invocation and fresh app session, and requires the same reference to remain
a duplicate. A reverse-direction reply uses the same contact confirmation and manual CHK handoff.

Both datasets are checked before either initialization. Mail now reports the bounded
`initialization-recovery-required` status when the durable interrupted-initialization marker is
present. This read-only distinction exposes no account or key data and lets the consumer abort
before mutating either role. Initialization must subsequently return `recovery=normal` with no
`initializationRecoveryEpoch`; the consumer retains that second check as defense in depth.

A lost completed broker result remains uncertain because the broker has already consumed it.
`initialize`, contact import/approval, `confirm-send`, and `import-reference` are never issued a
second time automatically. If a durable operation or accepted inbox identity was not returned,
this implementation stops with uncertainty instead of inventing an identifier. Native state can
support a future separately reviewed reconciliation helper, but the absence of that helper does
not authorize replay.

## Installed execution path

`InstalledWorkloadAdapter.run_mail_lane()` implements the observer-side flow body without changing
`run_positive()` or a PR-315 campaign group. The
lane starts the finite roles, verifies their peer topology, installs the normal signed apps,
executes the real worker-owned Mail flow, performs worker and role restarts, and keeps the roles
under controller ownership for administrator reconciliation. Its public return contains fixed
outcome fields only. Session tokens,
origins, cards, fingerprints, plaintext, broker/message/operation/queue identifiers, CHKs, form
passwords and raw exceptions are not projected.

The fixed `pr316-installed-mail-runtime-v1` execution class is bound into the fixture authorization
and selection digest before root preparation or role mutation. The copied-VM wrapper, installed
guest and root driver accept that class only when no PR-315 group, lifecycle case, startup
measurement or retired-authority operation is selected. Root cleanup and volatile capture complete
before the private driver report can set `installedMailFlowObserved=true`.

The separate administrator entry uses two terminals. First, PVE root publishes the required host
admission and initial task inventory before the unprivileged CT runner starts:

```bash
# PVE root terminal.
python3 tools/release-certification/restricted/pr315_pve_host_admission.py \
  --suite suite-N --source-commit COMMIT
python3 tools/release-certification/restricted/pr316_pve_vm_inventory.py \
  --suite suite-N --source-commit COMMIT --phase pre

# CT terminal, unprivileged inside the approved task root. This waits at two markers.
python3 tools/release-certification/restricted/pr316_mail_runtime_runner.py \
  --source SOURCE --output OUTPUT --storage-root STORAGE_ROOT \
  --prepared-image PREPARED_IMAGE --prepared-fixtures PREPARED_FIXTURES \
  --qemu-root QEMU_ROOT --seed SEED --ssh-key SSH_KEY --known-hosts KNOWN_HOSTS \
  --product-source-commit COMMIT --prepared-image-digest DIGEST \
  --fixture-manifest-digest DIGEST --storage-budget-bytes BYTES \
  --min-free-bytes BYTES --memory-budget-bytes BYTES \
  --min-host-memory-bytes BYTES
```

After the runner writes `suite-N/awaiting-final-pve-inventory.private.json`, PVE root publishes the
second inventory. After all fixture, inventory, capacity and host-side attempt preparation passes,
the runner writes `suite-N/awaiting-pressure-watcher.private.json`; only then does PVE root publish
the launch-bound host admission and task inventory before starting the watcher in the background:

```bash
# PVE root terminal, after awaiting-final-pve-inventory.private.json appears.
python3 tools/release-certification/restricted/pr316_pve_vm_inventory.py \
  --suite suite-N --source-commit COMMIT --phase final

# PVE root terminal, after awaiting-pressure-watcher.private.json appears.
python3 tools/release-certification/restricted/pr315_pve_host_admission.py \
  --suite suite-N --source-commit COMMIT --phase launch
python3 tools/release-certification/restricted/pr316_pve_vm_inventory.py \
  --suite suite-N --source-commit COMMIT --phase launch

nohup python3 tools/release-certification/restricted/pr315_pve_pressure_watch.py \
  --suite suite-N --source-commit COMMIT \
  > /root/pr316-suite-N-pressure-watch.private.log 2>&1 < /dev/null &
```

The runner authenticates the watcher ready receipt at the final pre-QEMU boundary and then launches
the guest immediately. The same callback first requires distinct immutable launch-phase host
admission and PVE inventory receipts created after its marker. Memory, swap, pressure, absence of a
task QEMU, allocated task storage and the free-space reserve are therefore remeasured after host
preparation rather than inherited from earlier receipts. A fixture, final-inventory or capacity
failure therefore occurs before the watcher is requested. If QEMU does not appear within 30 seconds
after readiness, the watcher closes as `stopped-before-launch`. Before launch, the runner also
requires at least five seconds of that window to remain and rejects any already-published finished
receipt. It authenticates watcher termination before returning a post-ready failure. Reusing the
initial host-admission or `pre` inventory receipt cannot authorize allocation, and starting the
watcher before the second marker is unsupported.

The runner has no campaign, case-group, v10, history, protected-authority or retired-authority
options. Before each possible VM allocation it requires a fresh immutable PVE-root inventory
receipt showing no task QEMU and the actual allocated/available task storage. It also inventories
the CT-visible retained task storage, rejects any locally visible task QEMU, recomputes allocated
storage and required attempt size, checks the free-space reserve, validates host admission and
starts the existing pressure watcher. It runs one attempt and never automatically retries, deletes
or releases it.

The observer exclusively writes a bounded `0600` private causal record. It contains the synthetic
broker, operation, queue, CHK and replay identifiers needed to prove the actual association, plus
role/worker/browser-context commitments and ordered milestones. It never persists browser tokens,
passwords, message text, cards, fingerprints, approvals or raw exceptions. The host runner validates
that record against the post-cleanup driver result, exact source/product identity, guest stop,
watcher completion, retained sentinel and four terminal role stop receipts before producing the
closed identifier-free result.

No VM, public network, private user mail, protected workflow, production key or historical node was
authorized or used during implementation. The executable path is locally prepared and verified,
not an executed installed Mail observation.

## Verification and remaining work

Offline tests cover transport injection, duplicate JSON members, canonical Base64, read-only
recovery-marker rejection, uncertain mutation results, identical textual installed endpoints,
fixed path/status/framing failures, role-context drift, no implicit reconnect, the distinct Mail
selection and driver dispatch, causal association validation, terminal cleanup gating, host-runner
privacy projection and the absence of historical acceptance transfer. Existing Java broker and
Mail state tests remain the native authority. PR-316 adds only the bounded recovery-marker status;
it changes no crypto, quota or persistent format.

An actual installed result still requires executing this exact runner on an approved disposable
topology and retaining its private attempt. Full failed-collector/support-export privacy canaries,
independent security review, Mail key rotation, restore resume, the PR-309 budget consumers,
complete catalog/scheduler/recovery/migration/historical/protected inputs, the finite-native gate
and long soak remain separate Phase 12 work.
