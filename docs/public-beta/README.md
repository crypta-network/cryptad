# Public beta onboarding

Use this front door to find the public-beta path for installing Cryptad, using first-party apps,
building third-party apps, legacy plugin migration, reporting security issues, and checking release
readiness without reading daemon internals.

## Start here

| Role or task | Start with | Source-of-truth follow-up |
| --- | --- | --- |
| I am a beta user/operator | [user-guide.md](user-guide.md) | [../operator-beta-dashboard.md](../operator-beta-dashboard.md) and [../privacy-preserving-beta-diagnostics.md](../privacy-preserving-beta-diagnostics.md) |
| I am installing or updating Cryptad | [install-update-rollback.md](install-update-rollback.md) | [../production-beta-release-pipeline.md](../production-beta-release-pipeline.md) and [../app-update-lifecycle.md](../app-update-lifecycle.md) |
| I am installing first-party apps | [catalogs-and-apps.md](catalogs-and-apps.md) | [../app-catalogs.md](../app-catalogs.md), [../first-party-beta-catalog.md](../first-party-beta-catalog.md), and [../production-first-party-catalog-channels.md](../production-first-party-catalog-channels.md) |
| I am backing up or restoring app data | [user-guide.md](user-guide.md#back-up-or-restore-app-data) | [../app-data-backup-restore-portability.md](../app-data-backup-restore-portability.md) |
| I need support or want to file beta feedback | [support-and-feedback.md](support-and-feedback.md) | [triage-taxonomy.md](triage-taxonomy.md), [known-issues.md](known-issues.md), and [feedback-to-backlog.md](feedback-to-backlog.md) |
| I am troubleshooting a problem | [troubleshooting.md](troubleshooting.md) | [../operator-rc-recovery-and-support-workflow.md](../operator-rc-recovery-and-support-workflow.md) |
| I am reporting a security issue | [security-reporting.md](security-reporting.md) | [../SECURITY.md](../SECURITY.md) and [../production-security-response-runbook.md](../production-security-response-runbook.md) |
| I am a third-party app developer | [developer-quickstart.md](developer-quickstart.md) | [../third-party-developer-beta-program.md](../third-party-developer-beta-program.md) and [../developer-beta-toolkit.md](../developer-beta-toolkit.md) |
| I am submitting an app for review | [app-submission-walkthrough.md](app-submission-walkthrough.md) | [../app-store-submission-and-review-workflow.md](../app-store-submission-and-review-workflow.md) |
| I am a former plugin author | [legacy-plugin-authors.md](legacy-plugin-authors.md) | [../legacy-plugin-migration-cookbook.md](../legacy-plugin-migration-cookbook.md) and [../legacy-plugin-freeze-policy.md](../legacy-plugin-freeze-policy.md) |
| I am a reviewer/release manager | [app-submission-walkthrough.md](app-submission-walkthrough.md#reviewer-and-release-manager-path) | [../production-beta-go-no-go-dashboard.md](../production-beta-go-no-go-dashboard.md) and [../release-certification.md](../release-certification.md) |

## User/operator path

1. Install and start Cryptad from the current release artifact.
2. Open Web Shell at the local node UI.
3. Check node and catalog status before installing apps.
4. Add or verify the stable first-party catalog.
5. Install a first-party app from signed catalog metadata.
6. Review the permission request, service grants, and any migration consent.
7. Back up app data before material updates.
8. Export a privacy-preserving support bundle when support asks for evidence.
9. File structured feedback with safe fields from [support-and-feedback.md](support-and-feedback.md)
   when the issue needs maintainer triage.
10. Use explicit rollback or recovery actions when an update, catalog refresh, or migration fails.

The full path is in [user-guide.md](user-guide.md).

## Developer path

1. Install the `crypta-app` developer CLI.
2. Create a `hello-stable` app or adapt the checked-in sample.
3. Run strict tests, UI lint, and Platform API compatibility checks.
4. Generate local development keys, sign the bundle, verify it, and pack a deterministic ZIP.
5. Create, verify, and pre-review a submission package.
6. Hand the package to public beta intake.
7. Respond to reviewer feedback, then stage a beta catalog candidate after a reviewed or allowed
   caution decision.

The copyable command path is in [developer-quickstart.md](developer-quickstart.md). The review
flow is in [app-submission-walkthrough.md](app-submission-walkthrough.md).

## Limitations

The public beta does not promise stable 1.0 product status. It also does not restore old plugin
compatibility or legacy social/mail protocols.

- Trust Graph Local RC is local advisory trust only. It is not global WebOfTrust, routing policy,
  global moderation, a crawler, or legacy WoT compatibility.
- Social Inbox RC is a local threaded social/message reference app. It is not Freemail,
  Freetalk/Sone compatibility, encrypted mail transport, global moderation, or a daemon-core social
  store.
- FProxy browse, content rendering, content filter, startup/recovery, diagnostics, and explicit
  fallback routes remain retained where the legacy-retirement docs say they remain retained.
- Legacy admin is maintenance-only.

Read [trust-social-limitations.md](trust-social-limitations.md) before testing Trust Graph or Social
Inbox.

## Safety

Do not paste secrets or raw user content into public issues, chat, docs, release artifacts, support
tickets, or app submissions. This includes private insert URIs, private keys, seed phrases, app
tokens, browser session tokens, form passwords, cookies, authorization headers, raw FProxy HTML,
raw support bundles, raw social messages, raw trust statements, raw profile/feed documents, raw app
data values, and local absolute paths.

Support bundles are local until you explicitly export them. They are designed to report metadata,
counts, statuses, versions, digests, and redaction booleans rather than private content. See
[support-and-feedback.md](support-and-feedback.md), [known-issues.md](known-issues.md),
[triage-taxonomy.md](triage-taxonomy.md), [security-reporting.md](security-reporting.md), and
[../privacy-preserving-beta-diagnostics.md](../privacy-preserving-beta-diagnostics.md).
