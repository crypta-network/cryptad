# App update lifecycle

This document describes the v1 lifecycle for Cryptad AppHost app updates and rollback evidence.

## Scope

App updates are local AppHost bundle replacements. They are separate from CoreUpdater and do not
change peer protocols, core package downloads, or catalog trust roots. Durable app-data schemas can
change only through the signed app-data migration contract described below.

The v1 policy is:

| Step | Policy | Release evidence |
| --- | --- | --- |
| Detect | Catalog detail and listing responses compare the installed app version with the verified catalog entry. | `app-update.lifecycle` |
| Schedule | The background scheduler refreshes configured signed catalogs and checks installed apps. It delegates app checks to the same lifecycle service used by manual requests. | `app-update.scheduler` |
| Review | Web Shell and API callers can review signed catalog metadata, compatibility hints, publisher-advisory review notes, trusted review receipt decisions, changelog text, and permission deltas before acting. | `app-update.lifecycle` |
| Stage | Local and catalog-backed updates prepare a copied, verified staged bundle before AppHost mutates the installed bundle. | `app-update.lifecycle` |
| App-data migration | A candidate that changes durable app-data schema must declare a signed migration contract, pass dry-run before bundle replacement, and create an internal app-data snapshot before apply. | `app-update.data-migration-contract` |
| Apply | Applying an update is manual by default. The target app must be stopped unless an explicit restart request allows stop/start choreography. | `app-update.lifecycle` |
| Roll back | A successful update records the previous installed bundle as the durable rollback target. If replacement cannot complete, AppHost restores the previous bundle from a managed backup. | `app-update.rollback` |

Silent automatic update is not the default. The background scheduler can refresh configured signed
catalogs, including a live USK catalog source such as
`crypta:USK@.../cryptad-app-catalog.properties`, and discover candidates. Catalog refresh
preserves the last verified catalog when a later refresh fails. Scheduler-triggered app checks
delegate to `AppUpdateService.check(...)`. Applying an update requires an operator or explicit API
caller unless the operator selected a policy mode that allows automatic staging or apply. Manual
remains the default policy for every app.

For release evidence, manual remains the default.
Applying an update requires an operator or explicit API caller.
This remains true when the scheduler refreshes a live USK catalog before candidate discovery.

The update summary exposes scheduler state for clients. Scheduler summaries include enabled,
status, last check, next check, last result, last failure, failure count, and sanitized error code
metadata. They do not expose scheduler store paths, catalog scratch directories, staged bundle
paths, rollback paths, tokens, private insert URIs, or stack traces.

Host/operator requests can manage the local lifecycle after the HTTP bridge has enforced its
form-password guard. App principals remain default-deny and must carry the route capabilities
published by the Platform API contract. Catalog-backed update lifecycle mutations require both
`apps.manage` and `catalogs.manage` for app principals because `check`, `stage`, and `apply` can
refresh signed catalogs, prepare catalog install plans, or apply catalog-staged bundles.

Policy modes are explicit:

| Mode | Behavior |
| --- | --- |
| `manual` | Detect candidates and show review metadata. Do not stage or apply automatically. This is the default. |
| `stage` | Stage eligible verified candidates for later review. Do not apply automatically. |
| `apply_when_stopped` | Apply eligible candidates only when the app is already stopped and review gates allow it. Do not stop a running app to update it. |

Channel policy is separate from the mode. The default allowed channel set is `stable` only. A
candidate from `beta`, `nightly`, or `deprecated` can still be viewed, reviewed, and explicitly
staged by an operator when other gates allow it, but policy-driven staging/apply skips it unless the
local policy explicitly allows that channel. Deprecated entries are blocked from automatic
staging/apply even if a policy includes the deprecated channel; PR-248 surfaces replacement and
deprecation metadata but does not implement migration or replacement flows.

When channel policy excludes an otherwise newer candidate, the update summary keeps the candidate
visible with `channelPolicyAllowed=false`, `policyBlockReason=channel_policy_blocked`, and
`autoStageAllowed=false`. Update history records the same stable reason without exposing catalog
scratch paths, staged bundle paths, private insert URIs, tokens, or raw app data.

## App-data migration contract

When a candidate bundle declares `app.data.*` schema metadata, staging compares the target
contract with the installed manifest and current durable app-data namespace metadata. The update
summary includes a path-free `dataMigration` object with `required`, `status`,
`currentSchemaVersion`, `targetSchemaVersion`, namespace step summaries, rollback compatibility,
operator-review requirement, dry-run/snapshot/apply status, and a stable `blockReason` when the
update cannot proceed.

The migration plan never exposes command paths, staged bundle paths, AppHost paths, app process
tokens, browser-session tokens, private insert URIs, raw migration logs, or raw app-data values.
Web Shell renders only schema versions, namespaces, step ids, descriptions, status strings, and
risk flags.

Schema-changing updates fail closed:

- missing migration path blocks staging with `app_data_migration_missing`;
- rollback-incompatible migration steps block automatic apply and require explicit operator
  acknowledgement before staging;
- migration dry-run runs before bundle replacement and blocks staging with
  `app_data_migration_dry_run_failed` when it fails;
- signed steps with `requiresStopped=true` block stage dry-run with
  `app_data_migration_requires_stopped` while AppHost still reports the app running;
- required migrations for sandbox-requesting bundles fail closed with
  `app_data_migration_sandbox_unavailable` unless the migration launcher can enforce the AppHost
  sandbox boundary;
- apply creates an internal app-scoped app-data snapshot before bundle replacement;
- migration commands receive a scoped namespace export payload and must produce a validated
  migrated output payload before schema metadata is recorded;
- apply migration failure rolls back the bundle when possible and restores app data from the
  internal snapshot;
- snapshot restore failure is reported with `app_data_restore_failed` without raw data.

See [app-upgrade-data-migrations.md](app-upgrade-data-migrations.md) for the signed manifest
grammar, runner environment, snapshot limits, and PR-250 backup/restore non-goals.

## Candidate detection

Catalog responses expose two related values for installed apps:

- `versionDifferent` is true when the app is installed and the catalog version differs from the
  installed version.
- `updateAvailable` is true only when Cryptad can compare dotted numeric versions and the catalog
  version is newer. It is false for not-installed and equal-version entries, and unknown when either
  version is missing or comparison is ambiguous.

This keeps the UI honest: a changed catalog version can be shown for review even when the runtime
cannot prove that it is an upgrade.

## Review gates

The update review surface includes:

- signed catalog verification and signed bundle verification;
- artifact size and SHA-256 checks before extraction;
- manifest `app.id` and `app.version` consistency checks;
- production channel, support status, deprecation/replacement metadata, and security advisory
  references from the signed catalog;
- advisory Cryptad build compatibility and Platform API contract compatibility summaries;
- publisher-advisory catalog `review.status` and `review.note`;
- trusted review receipt status, reviewer key/display metadata, policy id/version, evidence
  digest/URI, receipt expiry, and receipt warnings when a catalog carries a receipt;
- changelog metadata when present;
- permission rationales and a permission delta with added, removed, and unchanged permissions.

Site Publisher uses the same update lifecycle as other catalog-installed apps: updates are
detected from signed catalog metadata, reviewed with permission deltas and review receipt status,
staged as verified bundles, and applied only under the configured app-update policy.

Catalog review metadata and compatibility metadata are review gates, not trust gates. They do not
replace signature verification. `review.status=reviewed` is a publisher claim unless a separate
review receipt verifies with a locally trusted reviewer key. A compatible newer candidate can still
be staged explicitly under the default review policy, but stricter review policies can require
operator acknowledgement or a trusted positive receipt before staging, updating, or policy-driven
apply.

App review policy is local node policy and is configured independently from update policy with
`cryptad.appreview.policyMode` or `CRYPTAD_APPREVIEW_POLICY_MODE`:

| Review policy mode | Install/update/apply behavior |
| --- | --- |
| `advisory` | Default. Show `reviewTrust`, but do not block manual install/update. |
| `warn_untrusted` | Manual install/update is allowed only when the API request or Web Shell form explicitly acknowledges missing, untrusted, expired, mismatched, or rejected review evidence. |
| `require_trusted_review` | Manual install/update is blocked unless `reviewTrust.status=trusted_reviewed`. |
| `require_trusted_review_for_apply_when_stopped` | Manual install/update can be acknowledged, but policy-driven `apply_when_stopped` requires `reviewTrust.status=trusted_reviewed`. |

Stable review-gate error codes include `app_review_missing`, `app_review_untrusted`,
`app_review_rejected`, `app_review_mismatch`, and `app_review_expired`. `trusted_rejected` is
trusted negative evidence and is never treated as a positive review.

## Apply policy

The default app-update policy is `manual`. The `apply_when_stopped` policy is available when an
operator wants eligible candidates applied by policy, but the app must already be installed and not
running before the update is applied. When review policy is
`require_trusted_review_for_apply_when_stopped` or `require_trusted_review`, policy-driven apply
also requires a trusted positive review receipt for the exact catalog artifact. Platform API routes
check runtime status before calling AppHost, and AppHost rechecks the live process table before any
installed-bundle mutation.

Policy summaries expose `allowedChannels`, `automaticStaging`, `automaticApply`, and
`deprecatedAutoUpdatesBlocked`. The Web Shell renders those fields in the app update lifecycle
details so operators can tell whether automation is stable-only or explicitly permits preview
channels.

The update source must already be a local staged directory or a catalog-managed temporary staged
directory. AppHost copies that stage under managed storage, verifies distribution sidecars when the
host policy requires signed bundles, parses the manifest, and rejects a manifest whose `app.id`
does not match the requested update target.

## Rollback scope

Rollback covers only the immutable installed bundle. During update, AppHost moves the existing
installed bundle to a managed backup path, moves the verified replacement into place, then records
the previous bundle under AppHost-managed rollback storage. If replacement cannot complete, AppHost
restores the previous bundle from the managed backup and also preserves any previous rollback
record.

When an operator or API caller invokes rollback, AppHost swaps the current installed bundle with
the durable rollback bundle. The app must be stopped for rollback just as it must be stopped for
update apply.

Rollback does not roll back:

- app data directories;
- app cache directories;
- app run directories;
- process logs;
- external files an app may have written outside AppHost-managed directories;
- catalog source state or scratch directories.

Data, cache, and run directories are intentionally preserved across successful updates. If a new
bundle changes durable Platform API app-data schema, the signed migration contract owns the
update-time migration path, operator acknowledgement, and downgrade risk summary. App-private files
outside the Platform API app-data store remain app-owned and outside this rollback snapshot.

Schema-changing app updates are the one app-data exception to the bundle-only rollback rule. During
that apply path, `AppUpdateService` creates a short-lived internal app-data snapshot before
replacing the bundle and restores it when migration apply or post-migration schema recording fails.
That snapshot is app-scoped, bounded by the app-data export/import limits, and is not exposed as a
user-facing backup or cross-app restore feature.

Vault records are also outside rollback snapshots. App-owned secrets, app-owned identities, shared
identity grants, and grant status changes are evaluated against the currently installed manifest
and current local grant state. Updating an app preserves app-owned vault material and active grants
only for vault capabilities still declared by the replacement manifest; removing a vault capability
marks matching grants inactive until operator review. Rollback restores the previous bundle, but it
does not restore old secret values or older grant decisions.

Uninstall is not a rollback operation. The v1 uninstall path revokes that app id's identity grants
and purges app-owned secret values so a later same-id reinstall cannot silently recover the previous
install's private configuration.

## Process health gate

The v1 health gate is conservative: an update is not applied while the app has a live process unless
the API caller explicitly sets `restart=true`. A normal running-app update receives a conflict
response and the installed bundle is left unchanged. A pending on-failure restart is canceled only
after an update has been accepted and the replacement bundle is installed.

When `healthCheck=process` is requested with restart behavior, Cryptad starts the app after bundle
replacement and treats a readable running status as the v1 health signal. If
`rollbackOnHealthFailure=true` is also set, AppHost restores the previous bundle when that process
health signal fails and a rollback record is available. Failure responses keep the health failure
and rollback failure distinct in update history.

This avoids replacing files beneath a running process and keeps rollback limited to durable bundle
state.

## Release certification

Release candidates require offline evidence for both app-update lifecycle behavior and rollback
scope:

- `app-update.lifecycle` proves the manual/stage/apply-when-stopped policy, candidate detection,
  review metadata, trusted review receipt decisions, permission delta, and compatibility checks are
  represented in source and tests.
- `app-update.scheduler` proves the background scheduler refreshes signed catalogs, checks
  installed apps through `AppUpdateService.check(...)`, records durable path-free state, applies
  failure backoff, and preserves the manual stable-only default policy.
- `app-update.rollback` proves durable installed-bundle backup/restore behavior and confirms data,
  cache, and run directories are outside rollback scope.
- `app-update.data-migration-contract` proves signed manifest schema/migration metadata,
  pre-update dry-run, app-scoped snapshot/restore, missing-path and rollback-incompatible blockers,
  path-free Platform API/Web Shell summaries, Feed Reader and Trust Graph Preview examples, and
  raw app-data/token/path/private-URI redaction.

The evidence is collected by `tools/release-certification/app_platform_smoke.py` and aggregated by
`tools/release-certification/release_certification.py`. It does not require a live node. Release
candidates fail when any required app-update evidence item is missing, failing, skipped, or
wrong-mode unless a release manager records a waiver.
