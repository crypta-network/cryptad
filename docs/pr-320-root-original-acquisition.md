# PR-320 root original acquisition

The fixed PR-320 acquisition service retains budget originals inside the protected host's root domain and supplies a sealed custody object to the terminal supervisor.

The implementation is prepared code. No service installation, protected operation, daemon run, or VM run was performed to establish this document or its offline tests. Acquisition completion means that the original files were retained after actual cleanup; each component's original validator still determines which budget variants were observed.

## Required host and inputs

The existing four-role kit requires a dedicated disposable Debian 13 VM, systemd as PID 1, the approved installation at `/opt/cryptad-cross-version/current`, and the separately measured kit at `/opt/cryptad-restricted-test-kit`. The service runs on that protected host directly; it does not transfer authority from an unprivileged VM runner or accept a caller's report or capsule.

The installed source, dependencies, literal unit bytes, absence of unit overrides, registered inputs, original job, and activation remain separate checks. The restricted worker authenticates the original job before minting the private preparation or start intent. The acquisition service independently rechecks the root registration and input bytes; credentials are absent from its environment and retained reports.

Production code resolves only through the approved installed manifest. Helpers excluded from the production export resolve only through the fixed separate kit after its complete file roster, source commit, and every file hash pass. A sealed installed-source capability supplies these locations to the prospective fixture factory; it cannot select another directory or substitute an unregistered helper. The original consumer resolver admits exactly the five fixed component owners. The unprivileged
privacy actor has a separate read-only resolver through the public installed-source/dependency
identity and the same measured kit. It can validate local artifact omission without root; it cannot
construct original custody or call the root terminal collector.

The registered configuration is exactly `/etc/cryptad-certification/pr320-original-acquisition.json` with these fields:

| Field | Meaning |
| --- | --- |
| `schemaVersion` | Integer `1` |
| `kind` | `pr320-original-acquisition-selection` |
| `executionClass` | One exact entry in `pr320_budget_contract.PROSPECTIVE_EXECUTION_CLASSES` |
| `fixtureManifestDigest` | Bare SHA-256 of the prospective fixture manifest |
| `candidateCommit` | Exact candidate commit |
| `planDigest` | SHA-256 of the source factory's canonical plan |
| `verifierDigest` | Independently approved SHA-256 of the complete signed-app verifier tree |

The registered input roster contains only `fixture/`, `verifier/`, and the fixed `fixture-modes.private.json` file. The mode file maps every full registered relative member name, excluding itself, to its original approved mode. Fixture modes are `0600` or `0700`; verifier modes may also be `0644` or `0755` inside its private parent directory. Registration deliberately snapshots files as `0400`, so this explicit declaration is needed to reproduce the JDK and verifier tree identities.

The root factory copies those registered bytes to the existing class-specific `/root/cryptad/build/pr320-…` directory. It restores the declared modes and invokes the existing signer, statement, runtime, product, permission, and process-client validators. Both the independently registered `verifierDigest` and the fixture's verifier digest must match the actual verifier tree before Java executes.

## Preparation and acquisition

The implementation lives in [pr320_original_acquisition.py](../tools/release-certification/protected/pr320_original_acquisition.py). The one fixed unit is [cryptad-pr320-original-acquisition.service](../tools/release-certification/restricted/systemd/cryptad-pr320-original-acquisition.service).

| API | Owning operation | Behavior |
| --- | --- | --- |
| `prepare_owned()` | `budget-acquisition-prepare` | Writes an immutable root intent and starts asynchronous preparation. Returns only `status` and a UUID handle. |
| `collect_owned()` | `budget-acquisition-collect` | Returns only current state and the UUID handle. Preparation can be `running`, `prepared`, or `failed`; acquisition can be `running`, `complete`, or `failed`. A later authenticated job may collect the exact frozen source, bundle, configuration, and input scope. |
| `verify_prepared_selection(plan, private, authorization)` | Root supervisor selection read | Compares the selected JSON with the root's actual frozen source-factory result and original preparation bindings. Requires successful stopped preparation before authorization. |
| `begin_owned()` | `supervisor-start` or `budget-acquisition-begin` | Revalidates the prepared selection and registered inputs against the current activation, then starts acquisition. |
| `completed_owned(activation, plan, terminal=…)` | Stopped root supervisor | Reads the service's original files, verifies their bindings and owning consumers, and returns a sealed `OwnedAcquisitionCapture`. |
| `capture.members(activation, plan, terminal)` | Root terminal collector | Rechecks source, registration, revocation, activation, stopped service, original checkpoint commitments, and component originals before exposing the private member records. |

Preparation writes the authoritative root selection at `/var/lib/cryptad-cross-version-authority/pr320-original-acquisition/selection.json`. It also writes the driver's fixed `/root/pr314-workload-selection.json` mirror and the existing `cryptad-soak`-owned `STATE/selected` files. The service selection retains the historical schema and binds the new acquisition module's exact bytes as `serviceDigest`.

The later authorize and start jobs may differ from the preparation job. Their registered source, bundle, configuration, and raw input identities must match the frozen preparation; the original preparation job remains retained separately. Later collection jobs may also differ. The private acquisition start record retains the actual start job and its exact original registration, which are reverified before terminal custody is issued.

The hardened restricted worker never gains access to `/root` or new mount capabilities. Preparation runs in the fixed root service. That service must share PID 1's mount namespace: the existing preparer mounts shared role tmpfs, then starts controller and role units through PID 1. A separate filesystem namespace would hide the prepared mounts from those units. The service checks that actual namespace identity; the controller and four role units retain their existing isolation.

## Deadlines, originals, and custody

The fixed service forks one root child and polls it with `waitpid`. It uses the frozen monotonic deadline, sends `SIGTERM` through the driver's existing cleanup path on expiration, and allows a bounded cleanup grace before forced termination. This avoids conflicting with the existing kit's own `SIGALRM` timers. The restricted worker's 900-second request cap remains unchanged; long work belongs to the separate unit.

Acquisition calls the actual measured `pr314_workload_driver.execute(lifecycle_scenario='none', execution_class=…)`. The existing kit captures root originals after all four role stops, while their retained files and tmpfs still exist. The child reads that root capsule directly and retains it with the actor journal, original checkpoint, driver observation, and kernel clock report. It does not consume a requester-supplied originals JSON object.

The clock report kind is `pr320-root-native-original-report`. Its UTC samples come from the actual common host/role kernel and are bracketed by monotonic samples. It records the real boot identity, unit invocation, role kernel epochs, observation digest, checkpoint digest, plan digest, and activation digest. It does not assert a VM image identity or a guest stop that did not occur. Privacy readback, boundary-control, browser, and native event times must fall within that actual acquisition's corresponding UTC or monotonic bracket; a timestamp merely earlier than completion is insufficient.

Acquisition files are single-link root-owned files created exclusively, fsynced, and changed to `0400` under a private `0700` directory. Their completion record binds every retained file's exact size and digest, plus the start record, boot, invocation, and completion time. The bounded originals set is at most 40 MiB. A completion marker cannot admit an unsuccessful service exit, a failed or interrupted acquisition, a replaced checkpoint, an altered source or registered input, a revoked operation, or an unmatched activation.

`OwnedAcquisitionCapture` has a private constructor seal and immutable stored bytes. Serialized dictionaries cannot construct it. Its private member accessor also requires the real stopped-service `TerminalEvidence`; the terminal campaign collector must require both capabilities when staging original members.

Actor checkpoints retain their actual `partial` state where the finite budget driver uses it. Root role quiescence and cleanup are checked independently. No checkpoint is rewritten to claim full scenarios, a long soak, a protected product class, or an unobserved budget direction.

## Retention and verification

An existing selection, prepared fixture, acquisition intent, retained workload pool, or failed run is never automatically replaced or deleted. Reuse requires explicit task-owned reconciliation after the required originals have been retained. The unit has no restart policy or boot enablement target.

The acquisition and optional installed fixture-source seam preserve historical defaults. PR-318 still uses Git and the original source verifier unless it receives the separate sealed installed-source capability; all prospective wrappers default to the historical behavior. The old unprivileged copied-VM runners retain their local evidence meaning.

The offline tests are [test_pr320_original_acquisition.py](../tools/release-certification/protected/test_pr320_original_acquisition.py). They cover closed inputs, independent verifier identity, immutable descriptor reads, asynchronous intent behavior, original journal lineage, custody seals, actual owning component validators, and fixed service limits. Synthetic policy and terminal boundaries in these tests grant no operational authority.

Source closure must include the new acquisition module and unit, the changed PR-318 verifier, and all five prospective selection wrappers. Privacy member 17 additionally uses the separately owned fixed artifact producer and root capsule reader; its actual artifact bytes must be retained and checkpoint committed before terminal collection.

A start handoff waits up to 20 seconds for the asynchronous fixed unit to expose its actual MainPID
and selected cgroup. A queued request or an activating unit with PID zero cannot establish a
running observation. The bounded wait does not extend the frozen acquisition deadline.
