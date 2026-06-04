# App update lifecycle

This document describes the v1 lifecycle for Cryptad AppHost app updates and rollback evidence.

## Scope

App updates are local AppHost bundle replacements. They are separate from CoreUpdater and do not
change peer protocols, core package downloads, catalog trust roots, or app data formats.

The v1 policy is:

| Step | Policy | Release evidence |
| --- | --- | --- |
| Detect | Catalog detail and listing responses compare the installed app version with the verified catalog entry. | `app-update.lifecycle` |
| Schedule | The background scheduler refreshes configured signed catalogs and checks installed apps. It delegates app checks to the same lifecycle service used by manual requests. | `app-update.scheduler` |
| Review | Web Shell and API callers can review signed catalog metadata, compatibility hints, publisher-advisory review notes, trusted review receipt decisions, changelog text, and permission deltas before acting. | `app-update.lifecycle` |
| Stage | Local and catalog-backed updates prepare a copied, verified staged bundle before AppHost mutates the installed bundle. | `app-update.lifecycle` |
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
bundle changes its own data format, the app owns that migration and any app-level downgrade policy.

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

The evidence is collected by `tools/release-certification/app_platform_smoke.py` and aggregated by
`tools/release-certification/release_certification.py`. It does not require a live node. Release
candidates fail when any required app-update evidence item is missing, failing, skipped, or
wrong-mode unless a release manager records a waiver.
