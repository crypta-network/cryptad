# App upgrade data migrations

This document describes the signed app-data migration contract used by app bundle updates.

## Scope

PR-249 adds an update-time contract for durable app-data schema changes. It lets a signed
`cryptad-app.properties` manifest declare the schema version expected by the bundle, bounded
migration steps from older schema versions, the migration entrypoint inside the signed bundle,
whether the step is rollback-compatible, and whether operator review is required before the update
can be staged.

This is separate from user-facing backup/restore portability. Operators use the dedicated
[app-data-backup-restore-portability.md](app-data-backup-restore-portability.md) routes and Web
Shell controls for long-term backup envelopes and cross-app restore planning. The snapshot
described here is internal, app-scoped, bounded by the existing app-data export/import limits, and
retained only while the update apply/rollback choreography needs it.

## Manifest properties

Migration metadata lives in `cryptad-app.properties`, so it is covered by the same bundle digest
and signature verification as the rest of the app metadata.

```properties
app.data.schema.current=2

app.data.schema.namespaces=ui-state
app.data.schema.namespace.ui-state.current=2

app.data.migrations=ui-state-v1-v2
app.data.migration.ui-state-v1-v2.namespace=ui-state
app.data.migration.ui-state-v1-v2.from=1
app.data.migration.ui-state-v1-v2.to=2
app.data.migration.ui-state-v1-v2.command=bin/migrate-feed-data.sh
app.data.migration.ui-state-v1-v2.rollbackCompatible=false
app.data.migration.ui-state-v1-v2.requiresStopped=true
app.data.migration.ui-state-v1-v2.description=Upgrade UI state to schema v2.
```

`app.data.schema.current` is the bundle's global durable app-data schema version. Namespace
properties are preferred when an app stores multiple independent schema families because the
durable app-data store tracks namespace schema versions.

Migration step ids are stable identifiers within the bundle. They must be deterministic,
single-line, and path-safe. Namespace names use the same safe identifier rules as app-data
namespaces. `from` and `to` are positive integers, and `to` must be greater than `from`.

`command` is a relative bundle path, not a shell command. Manifest validation rejects blank values,
absolute paths, traversal segments, Windows drive prefixes, escaped path separators, control
characters, and entries outside the signed bundle. The platform supplies migration mode and
version information through fixed environment variables rather than parsing command arguments.

Older manifests without `app.data.*` migration metadata remain valid. They represent an
undeclared schema contract. A schema-changing update from such a bundle can proceed only when no
durable data requires migration or when the target manifest declares a complete bounded path from
the current durable namespace schema to the target schema.

## Lifecycle

When an update is staged, `AppUpdateService` parses the candidate bundle manifest, compares it
with the installed manifest and current durable app-data namespace metadata, and builds a
path-free migration plan. Candidate and staged update summaries expose only safe fields such as:

```json
{
  "required": true,
  "status": "ready",
  "currentSchemaVersion": 1,
  "targetSchemaVersion": 2,
  "namespaces": [
    {
      "namespace": "ui-state",
      "from": 1,
      "to": 2,
      "stepId": "ui-state-v1-v2",
      "rollbackCompatible": false,
      "requiresStopped": true,
      "description": "Upgrade UI state to schema v2."
    }
  ],
  "operatorReviewRequired": true,
  "blockReason": null,
  "dryRunStatus": "passed",
  "snapshotStatus": null,
  "applyStatus": null
}
```

The summary intentionally omits filesystem paths, staging directories, command paths, process
tokens, browser session tokens, private insert URIs, raw command output, and raw app-data values.

The apply choreography for a schema-changing update is:

1. Stop the app when the caller requested restart choreography and the update is allowed to stop
   a running process.
2. Revalidate the staged candidate and update gates.
3. Re-verify the retained staged bundle against its signed sidecars and catalog entry before
   parsing the target manifest or running migration commands.
4. Rebuild the migration plan from current durable app-data metadata and rerun the staged-bundle
   dry-run when a migration is now required. Dry-run import validation uses the target manifest's
   `quota.data.bytes`, so quota-increasing updates are checked against the candidate contract
   before replacement.
5. Re-verify the retained staged bundle again after the dry-run and before installing it, so a
   migration entrypoint cannot mutate the staged tree after the signed-bundle check.
6. Begin an app-scoped app-data write barrier so browser sessions and app principals cannot write
   durable data that would be lost by the snapshot or replace-namespace import.
7. Create an internal app-data snapshot for the app.
8. Replace the immutable installed bundle.
9. Run migration entrypoints from the installed replacement bundle in `apply` mode. Each
   successful step imports its validated output and records durable namespace schema metadata before
   the next step starts.
10. Restart and health-check when requested.
11. Discard the internal snapshot after all post-apply checks pass and release the write barrier.

If migration apply or schema metadata recording fails after bundle replacement, the service asks
AppHost to roll back the bundle and then restores app data from the internal snapshot. If snapshot
restore fails after bundle rollback, public status uses a degraded reason such as
`app_data_restore_failed` without exposing raw data.

The write barrier is app-scoped, not namespace-scoped. The snapshot and rollback restore are
app-scoped, so writes to a non-migrated namespace during the apply window could otherwise be lost if
the update later rolls back. App-facing app-data writes fail with `app_data_migration_in_progress`
while the barrier is active. Internal migration imports and snapshot restore remain allowed so the
update lifecycle can finish or roll back.

## Migration execution

Migration entrypoints run as short-lived app-owned processes. The runner resolves each declared
command path inside the signed staged or installed bundle, rejects symlinks and unsafe traversal,
and executes only an executable file directly. Bundle validation checks that declared migration
commands are regular safe bundle files, but leaves host-dependent executable-bit checks to the
runner. Fresh installs and no-data updates can therefore accept signed migration contracts on
filesystems that do not preserve POSIX executable bits, while a required migration still fails
closed before bundle replacement if the local runner cannot launch the command directly. The runner
does not invoke a shell and does not parse a shell command string.

The runner clears inherited environment variables and provides only fixed migration environment
values. In addition to a minimal fixed tool path, migration commands receive:

```text
CRYPTA_APP_MIGRATION_MODE=dry-run|apply
CRYPTA_APP_MIGRATION_NAMESPACE=<namespace>
CRYPTA_APP_MIGRATION_FROM=<positive integer>
CRYPTA_APP_MIGRATION_TO=<positive integer>
CRYPTA_APP_MIGRATION_STEP_ID=<step id>
CRYPTA_APP_MIGRATION_INPUT=<temporary app-data export payload>
CRYPTA_APP_MIGRATION_OUTPUT=<temporary migrated app-data export payload>
```

The input and output paths are a scoped internal app-data channel, not Platform API routes and not
public summary fields. For each namespace step, the platform writes a bounded app-data export
payload for that namespace to `CRYPTA_APP_MIGRATION_INPUT`. The command must write a valid export
payload to `CRYPTA_APP_MIGRATION_OUTPUT`. Dry-run validates the output without committing it; apply
imports the output for that namespace before the platform records the signed schema migration.
Output that names another app, touches another namespace, omits namespace metadata, leaves records
at the old schema version, exceeds import limits, or is not valid app-data export JSON fails closed.

Migration stdout/stderr capture is bounded and is not exposed in public update summaries or
release reports. Missing execution support, unsafe entrypoints, non-zero exit codes, or timeouts
fail closed. A required migration is never silently marked successful when execution was skipped.
On supported Linux hosts, the local runner starts the signed entrypoint in a new process group with
`setsid`, tears that group down with `kill` before completing a step, and treats any surviving
process in the group as a failed migration. This prevents a fast-detached child from outliving the
bounded migration lifecycle or holding stdout/stderr open after the entrypoint exits. Hosts without
that enforceable process-group boundary fail closed before migration code runs.
The current local migration runner cannot enforce required AppHost sandbox providers, so
schema-changing updates whose target manifest sets `sandbox.required=true` for a sandboxed mode fail
closed with `app_data_migration_sandbox_unavailable` until an AppHost-backed migration launcher is
available.

## Blocking rules

Stable blocker and status values include:

| Value | Meaning |
| --- | --- |
| `not_required` | No durable app-data schema change requires a migration. |
| `ready` | A complete migration path exists and dry-run passed. |
| `missing_migration` / `app_data_migration_missing` | Durable app data exists but the target bundle does not declare a complete path. |
| `dry_run_failed` / `app_data_migration_dry_run_failed` | Dry-run failed before bundle replacement. |
| `backup_failed` / `app_data_snapshot_failed` | The internal app-data snapshot could not be created or exceeded configured limits. |
| `rollback_incompatible` / `app_data_migration_review_required` | The migration declares rollback compatibility risk and needs operator acknowledgement before staging. |
| `requires_stopped` / `app_data_migration_requires_stopped` | At least one signed step declares `requiresStopped=true`, so stage dry-run is blocked while the app is running. |
| `sandbox_unavailable` / `app_data_migration_sandbox_unavailable` | The target bundle requests an AppHost sandbox that the migration runner cannot enforce. |
| `failed` / `app_data_migration_apply_failed` | Apply failed after bundle replacement; bundle rollback and app-data restore are attempted. |
| `app_data_restore_failed` | Bundle rollback completed or was attempted, but app-data snapshot restore failed. |
| `app_data_migration_in_progress` | App-facing app-data writes are temporarily rejected while a schema-changing update holds the internal write barrier. |

Channel policy from production catalog channels remains independent. Migration acknowledgement
does not bypass signed catalog verification, stable/beta/nightly/deprecated channel policy,
trusted review receipt policy, Platform API compatibility checks, permission delta review, or
sandbox requirements.

## Reference apps

Feed Reader declares schema v2 with a `ui-state-v1-v2` migration step and
`bin/migrate-feed-data.sh`. Trust Graph Local RC declares schema v2 with a `ui-state-v1-v2`
migration step and `bin/migrate-preview-data.sh`. Both scripts support `dry-run` and `apply`
modes, validate the fixed environment variables, and print only generic status text. Both
first-party steps are rollback-incompatible because the updated apps may persist schema-v2 state
that older bundles do not accept after a bundle rollback.

## Redaction guarantees

Update summaries, Web Shell text, update history, app-platform smoke evidence, and release
certification reports must not contain raw app-data values, migration command paths, raw command
logs, private insert URIs, private keys, app process tokens, browser session tokens, form
passwords, catalog scratch paths, staged bundle paths, rollback paths, or AppHost filesystem
paths. Use schema versions, namespaces, step ids, booleans, counts, stable status strings, and
redacted error codes instead.
