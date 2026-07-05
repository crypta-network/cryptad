# Public beta troubleshooting

Use this guide to recover safely from common public-beta Web Shell, catalog, app install, update,
backup, sandbox, subscription, and support-bundle problems.

## Scope

Each item gives the meaning, safe first action, where to check in Web Shell, useful support bundle
metadata, what not to paste publicly, and source docs.

## Quick safety rules

- Export a redacted support bundle before repeated recovery attempts.
- Back up app data before app update, app rollback, app-data migration, daemon rollback, or restore.
- Do not paste secrets, raw content, raw app data, raw support bundles, or local absolute paths
  publicly.
- Prefer explicit Web Shell recovery actions and documented rollback routes over manual file edits.

## Symptoms

| Symptom | What it means | Safe first action | Web Shell check | Useful support bundle section | Do not paste publicly | Details |
| --- | --- | --- | --- | --- | --- | --- |
| Cannot open Web Shell | The local UI route is not reachable, the daemon is still starting, or the browser opened the wrong local URL. | Confirm the daemon is running, then retry the local UI route shown by the launcher or service logs. | Node status and runtime diagnostics. | Node status, listener status, launcher readiness metadata. | Form passwords, local service files, local paths, browser cookies. | [../operator-beta-dashboard.md](../operator-beta-dashboard.md) |
| Catalog not reachable | The primary catalog source cannot be fetched. | Retry refresh once, then inspect source health. | Catalog health. | Catalog source class, last refresh status, mirror fallback status. | Private insert URIs or raw catalog bytes. | [catalogs-and-apps.md](catalogs-and-apps.md) |
| Catalog mirror unhealthy | A fallback transport source failed or is stale. | Prefer the primary source when healthy; do not treat mirrors as trust authorities. | Mirror health and active source. | Mirror status, verified revision, fallback reason. | Mirror-local credentials or raw fetched bytes. | [../catalog-operations-and-mirrors.md](../catalog-operations-and-mirrors.md) |
| Catalog signature verification failed | Catalog bytes cannot be trusted for install or update. | Stop install/update, refresh from a known source, and report with redacted metadata. | Catalog signature and key status. | Catalog id, key id, revision, verification error code. | Raw signature bytes, private keys, private insert URIs. | [../app-catalogs.md](../app-catalogs.md) |
| App install failed | One of the catalog, bundle, review, compatibility, security, permission, or consent gates failed. | Read the failing gate and do not retry with weaker settings. | App install details and permission prompt. | App id, version, channel, failed gate, security/review status. | App tokens, raw request bodies, raw app data. | [../app-update-lifecycle.md](../app-update-lifecycle.md) |
| App update staged but not applied | The update is waiting for manual apply, app stop, consent, migration, or security acknowledgement. | Review permission delta, migration preview, and app state. | App updates panel. | Staged candidate metadata, policy, blockers, migration preview status. | Raw migration logs or app-data values. | [install-update-rollback.md](install-update-rollback.md) |
| App rollback needed | A newly applied app bundle is unhealthy or incompatible. | Export support evidence, then use app rollback. | App actions and update history. | Current version, previous verified version, health status, rollback result. | Rollback directory paths or raw process output. | [../app-update-lifecycle.md](../app-update-lifecycle.md) |
| Permission delta blocks update | The update requests new or changed capabilities. | Approve only if the rationale and app version are expected. | Permission delta prompt. | App id, old/new capability names, consent status. | Tokens, request bodies, private subject URIs. | [permissions-and-consent.md](permissions-and-consent.md) |
| Grant expired or revoked | An app-service dependency grant is no longer active. | Review provider, consumer, scope, and renewal request. | Service grants and dependency panel. | Provider id, consumer id, scope names, expiry/renewal status. | Provider app data, raw service request bodies, tokens. | [../app-service-discovery-and-grants.md](../app-service-discovery-and-grants.md) |
| Subscription stuck | The app-owned subscription scheduler is delayed, over budget, or waiting for source refresh. | Check network budget and subscription pressure before manual refresh. | Subscription recovery and app network budget. | Subscription id summary, status, budget counters, last attempt state. | Raw feed bodies, private source URIs, queue HTML. | [../feed-reader-reference-app.md](../feed-reader-reference-app.md) |
| App-data migration failed | The migration dry-run or commit failed validation or app execution. | Do not retry destructive steps; export support evidence and keep backups. | Migration preview and update details. | Schema versions, action counts, error code, backup metadata. | Raw app-data values, backup payloads, local store paths. | [../app-upgrade-data-migrations.md](../app-upgrade-data-migrations.md) |
| Backup restore failed | Restore preview or commit found incompatible schema, missing app, conflict, or corrupt backup metadata. | Keep the original backup, inspect preview conflicts, and avoid manual edits. | App-data backup/restore controls. | App ids, schema versions, digest, conflict summary, restore mode. | Backup payloads, raw app-data values, local paths. | [../app-data-backup-restore-portability.md](../app-data-backup-restore-portability.md) |
| Sandbox provider unavailable | The requested sandbox mode is unsupported or failed preflight on this host. | Treat restricted sandbox as unavailable unless Web Shell reports supported. | AppHost sandbox status. | Requested mode, support level, fail-closed status. | Bubblewrap paths, generated command lines, bind mount paths, app tokens. | [../apphost-runtime-hardening.md](../apphost-runtime-hardening.md) |
| Security advisory blocks update | A signed advisory warns or denies the candidate. | Do not bypass denylist; read safe replacement guidance. | App security status and advisory card. | Advisory id, action, affected app id/version, acknowledgement status. | Raw incident artifacts, private keys, raw catalog bytes. | [security-reporting.md](security-reporting.md) |
| Support bundle export needed | Maintainers need redacted operational metadata. | Preview the bundle, export locally, and share only through the requested private channel when needed. | Support bundle panel. | Redaction booleans, node status, catalog/app/update summaries. | Raw support bundle bodies, raw content, raw app data, tokens, local paths. | [../privacy-preserving-beta-diagnostics.md](../privacy-preserving-beta-diagnostics.md) |

## When to report

Use a public issue only for redacted beta support, documentation, or developer workflow problems.
Use [security-reporting.md](security-reporting.md) for suspected vulnerabilities, private report
channels, advisory behavior, denylist behavior, and support-bundle redaction expectations.
