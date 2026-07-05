# Public beta user and operator guide

Use this guide for the common public-beta workflow: install Cryptad, open Web Shell, install
first-party apps from a signed catalog, approve permissions, back up app data, and export redacted
support evidence.

## Scope

This guide is a high-level workflow. Packaging commands, artifact names, and OS integration can vary
by release. Use the release notes and artifacts for the exact package you are testing, then use the
source-of-truth docs linked from each section when you need details.

## Install and start Cryptad

1. Download the current public-beta release artifact from the release channel announced by the
   project.
2. Verify the artifact according to the release notes and
   [../production-beta-release-pipeline.md](../production-beta-release-pipeline.md).
3. Install or unpack the artifact for your OS.
4. Start Cryptad from the desktop launcher or service integration for that artifact.
5. Wait for the local node UI to open. If it does not open automatically, open the local Web Shell
   route shown by the launcher or service logs.

Do not copy release-manager local build paths, signing paths, private insert URIs, or support
bundle internals into public reports.

## Open Web Shell and check node status

Open Web Shell from the local node UI. The public-beta Web Shell is the operator entry point for
node status, catalog health, installed apps, permission review, app updates, app-data backup, and
support bundle export.

Check these areas first:

| Web Shell area | What to confirm | Detailed docs |
| --- | --- | --- |
| Node status | The node is reachable and not still starting. | [../operator-beta-dashboard.md](../operator-beta-dashboard.md) |
| Catalog health | Stable catalog source is verified, and mirrors are healthy or clearly marked fallback-only. | [catalogs-and-apps.md](catalogs-and-apps.md) |
| Installed apps | Installed apps show version, channel, review, security, and update state. | [../app-update-lifecycle.md](../app-update-lifecycle.md) |
| Support bundle | Preview metadata is redacted before export. | [support-and-feedback.md](support-and-feedback.md) and [../privacy-preserving-beta-diagnostics.md](../privacy-preserving-beta-diagnostics.md) |

## Add or verify the stable catalog

Use the catalog area in Web Shell to add or verify the stable first-party catalog described by the
release notes. A catalog is trusted because its metadata and signature verify against configured
trusted keys. Mirrors are transport fallbacks only; they are not trust authorities.

Before installing apps:

- Confirm the channel is `stable` unless you intentionally opted into `beta` or `nightly`.
- Confirm signature verification passes.
- Review source health and mirror health.
- Review catalog revision history if the catalog recently changed.
- Check for security advisories, denylist entries, and key-rotation status.

See [catalogs-and-apps.md](catalogs-and-apps.md),
[../app-catalogs.md](../app-catalogs.md), and
[../catalog-operations-and-mirrors.md](../catalog-operations-and-mirrors.md).

## Install a first-party app

Install first-party apps from signed catalog entries. The install flow should show the app id,
version, channel, publisher metadata, bundle signature status, review status, security advisory
state, and requested capabilities.

Use the default first-party path before installing third-party apps:

1. Pick an app from the stable first-party catalog.
2. Review the permission request and rationale.
3. Review optional and required service dependencies.
4. Approve only the grant bundle you understand.
5. Deny the install if the permission summary, review state, or security advisory is unclear.

See [../first-party-beta-catalog.md](../first-party-beta-catalog.md),
[../production-first-party-catalog-channels.md](../production-first-party-catalog-channels.md), and
[permissions-and-consent.md](permissions-and-consent.md).

## Review permissions and service grants

Public-beta apps use named capabilities. Some apps also request local app-service grants, such as
Trust Graph score annotations through an operator-approved provider. Consent is tied to a specific
snapshot of app metadata, permissions, service dependencies, and migration state.

When Web Shell asks for consent:

- Read the capability list and rationale.
- Compare permission deltas on update.
- Check whether a service dependency is optional or required.
- Check grant expiry, renewal, and revocation behavior.
- Review app-data migration consent before applying an update.
- Treat security advisory acknowledgement as a manual decision, not as a bypass.

See [permissions-and-consent.md](permissions-and-consent.md),
[../user-consent-and-permission-upgrade-ux.md](../user-consent-and-permission-upgrade-ux.md), and
[../app-permissions-and-audit.md](../app-permissions-and-audit.md).

## Update or rollback an app

App updates are separate from daemon updates. App updates come from signed catalog candidates and
pass catalog, bundle, review, compatibility, security advisory, permission delta, and migration
checks before apply.

Safe update path:

1. Back up app data when the app stores durable state.
2. Stage the update from a verified catalog revision.
3. Review permission deltas and service-grant changes.
4. Review app-data migration dry-run output.
5. Apply the update when the app is stopped or when the selected update policy allows it.
6. If the update fails, export a support bundle before retrying destructive recovery actions.
7. Use app rollback for the immutable installed bundle. Do not treat app rollback as a general
   mutable app-data restore.

See [install-update-rollback.md](install-update-rollback.md),
[../app-update-lifecycle.md](../app-update-lifecycle.md), and
[../app-upgrade-data-migrations.md](../app-upgrade-data-migrations.md).

## Back up or restore app data

Use Web Shell app-data backup controls before app updates, daemon rollback, migration testing, or
support-guided recovery. Backup and restore previews must remain metadata-only in support evidence.

Safe backup expectations:

- The backup is operator initiated.
- The preview reports app ids, schema versions, sizes, digests, and status.
- Raw app-data values and backup payloads are not printed into support bundles or release evidence.
- Restore preview should show conflicts before commit.
- Cross-app data access is not allowed.

See [../app-data-backup-restore-portability.md](../app-data-backup-restore-portability.md) and
[../operator-beta-dashboard.md](../operator-beta-dashboard.md).

## Export a privacy-preserving support bundle

Export a support bundle from Web Shell when a maintainer asks for operational evidence. Review the
preview before sharing.

Useful sections usually include:

- node and Web Shell status;
- catalog source, mirror, revision, and signature status;
- installed app ids, versions, channels, review status, update status, and security status;
- app-data backup/restore preview metadata;
- support action and recovery status;
- redaction booleans and finding counts.

Never paste raw support bundle internals publicly if they include private content. Do not paste
private insert URIs, tokens, form passwords, raw content, raw app data, raw social messages, raw
trust statements, raw profile/feed documents, raw FProxy HTML, or local absolute paths.

Public reports should start with support bundle digest, support bundle schema version, diagnostic
summary id, known issue id when relevant, and short redacted section summaries. Share raw bundle
files only if maintainers explicitly request a reviewed redacted bundle through an appropriate
channel. Raw app-data backups are not support bundles.

See [support-and-feedback.md](support-and-feedback.md),
[../privacy-preserving-beta-diagnostics.md](../privacy-preserving-beta-diagnostics.md), and
[security-reporting.md](security-reporting.md).

## Recover from common failures

Use [troubleshooting.md](troubleshooting.md) for symptom-specific steps. The safe default is:

1. Stop and read the Web Shell status before retrying.
2. Export redacted support evidence if the failure may need maintainer help.
3. Check [known-issues.md](known-issues.md), then file the specific issue form named in
   [support-and-feedback.md](support-and-feedback.md) if the issue is not already known.
4. Back up app data before update, rollback, migration, or restore operations.
5. Prefer explicit rollback or recovery actions over manual file edits.
6. Do not paste raw user content or local paths into public reports.
