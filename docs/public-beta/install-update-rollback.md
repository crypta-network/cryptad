# Public beta install, update, and rollback guide

Use this guide to distinguish daemon updates from app updates and to recover safely when a public
beta install, update, or rollback needs operator action.

## Scope

This page explains the public-beta workflow. Exact package names and commands belong to the release
artifact you are testing. Release managers should use
[../production-beta-release-pipeline.md](../production-beta-release-pipeline.md) and
[../production-beta-go-no-go-dashboard.md](../production-beta-go-no-go-dashboard.md) for release
evidence.

## Daemon update versus app update

| Update type | What changes | Trust check | Rollback shape |
| --- | --- | --- | --- |
| Daemon update | Cryptad node binaries, launcher, packaged runtime, service files, and bundled resources. | Release artifact verification and production beta release evidence. | Use the package manager, installer rollback, previous portable distribution, or support-guided daemon rollback. |
| App update | One installed app bundle from a signed app catalog. | Signed catalog, signed bundle, review policy, compatibility, security advisory, permission delta, and migration checks. | App rollback restores the immutable installed app bundle. It is not a general app-data restore. |
| Catalog update | Signed catalog metadata and app candidate revisions. | Catalog signature, trusted key policy, catalog id, digest, revision, advisory, and downgrade checks. | Explicit catalog rollback can select a previously verified revision. Mirrors cannot silently roll back bytes. |

## Verify production beta artifacts

Before updating the daemon:

1. Read the release notes and release artifact instructions.
2. Verify the artifact using the release-provided digest or signature process.
3. Confirm the release summary is not marked as fixture-only, non-release promotion evidence.
4. Back up app data for apps that store durable state.
5. Export a support bundle if you are already in a failing state.

Release certification and go/no-go dashboards are evidence records. They do not mean a real
production beta launch occurred unless the protected production pipeline, production signing,
live-node evidence, sandbox evidence, and go/no-go promotion all passed for that candidate.

## Choose catalog channels

Use `stable` for normal public-beta testing. Choose `beta` or `nightly` only when you intentionally
accept more frequent changes and a higher chance of broken app candidates.

Channel selection affects which catalog entries are eligible. It does not change the trust model:
catalogs still need signed metadata and trusted keys, and mirrors remain transport fallback only.

See [catalogs-and-apps.md](catalogs-and-apps.md) and
[../production-first-party-catalog-channels.md](../production-first-party-catalog-channels.md).

## App update scheduler

The default app-update policy is manual. Public beta does not silently auto-update third-party
apps. Other policies can stage eligible verified candidates or apply when the app is already
stopped, but they still pass the same gates.

Before applying an app update:

- review the signed catalog candidate;
- review the independent review status;
- review security advisory and denylist status;
- compare permission deltas;
- review app-service grant changes;
- run or inspect app-data migration dry-run output;
- create an app-data backup when the app stores durable state.

See [../app-update-lifecycle.md](../app-update-lifecycle.md) and
[../user-consent-and-permission-upgrade-ux.md](../user-consent-and-permission-upgrade-ux.md).

## Backup before update

Back up app data before:

- daemon rollback;
- app update with durable app-data schema changes;
- app-data migration;
- restore testing;
- support-guided recovery;
- uninstalling an app that owns durable state.

Backups and support evidence must stay metadata-only unless the operator intentionally handles the
backup payload outside public reports. See
[../app-data-backup-restore-portability.md](../app-data-backup-restore-portability.md).

## App-data migration dry-run

An update that changes app-data schema can require a migration dry-run and consent. The dry-run
should show schema versions, expected actions, counts, and status without raw app-data values. A
stale consent snapshot must fail closed.

See [../app-upgrade-data-migrations.md](../app-upgrade-data-migrations.md).

## Rollback paths

| Rollback | Use when | Safe first action |
| --- | --- | --- |
| App rollback | A newly applied app bundle fails launch, review, compatibility, or health checks. | Export a support bundle, then use Web Shell app rollback for the installed bundle. |
| Catalog rollback | A catalog revision is verified but operationally bad. | Inspect revision history, confirm the previous revision was verified, then perform explicit rollback. |
| Daemon rollback | The node package or launcher regresses. | Export support evidence, stop the daemon cleanly, preserve app-data backups, then use the package or release rollback path. |
| App-data restore | App-owned data is corrupt or a migration failed. | Preview restore conflicts and schema compatibility before commit. |

Do not repair app installs by editing internal directories. Use Web Shell, Platform API operator
routes, package-manager rollback, or maintainer-guided recovery.

## Support bundle after a failed update

After a failed update, a redacted support bundle is usually more useful before retries than after
multiple recovery attempts. Include catalog status, app update state, migration preview status,
backup/restore preview status, security advisory state, and redaction status. Do not paste raw
content or secrets publicly.

File failed install, update, migration, and rollback reports with `app-update-rollback.yml` through
[support-and-feedback.md](support-and-feedback.md). Check [known-issues.md](known-issues.md) first,
and include release id, app id/version, catalog channel, update phase, rollback result, migration
status, app-data backup status, support bundle digest, and redacted reproduction steps.

See [troubleshooting.md](troubleshooting.md),
[support-and-feedback.md](support-and-feedback.md), and
[../privacy-preserving-beta-diagnostics.md](../privacy-preserving-beta-diagnostics.md).
