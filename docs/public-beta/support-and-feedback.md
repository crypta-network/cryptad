# Public beta support and feedback loop

Public beta feedback is handled as a redaction-safe operations loop. Reports should give
maintainers enough structure to reproduce, triage, and verify a fix without exposing private
content, keys, tokens, local file layout, app data, or support bundle internals.

## Loop

1. Observe the issue in Web Shell, a first-party app, the developer CLI, or the local operator
   recovery surface.
2. Check [known-issues.md](known-issues.md) for an existing `knownIssueId`.
3. Collect a privacy-preserving diagnostic summary. Start with the digest, schema version, status
   counters, redaction status, and section summaries from
   [../privacy-preserving-beta-diagnostics.md](../privacy-preserving-beta-diagnostics.md).
4. Export a support bundle locally only if needed. Review the preview before sharing anything.
5. File the most specific structured issue form with safe metadata and redacted reproduction steps.
6. Maintainers run the redaction check, reproduction check, and taxonomy assignment from
   [feedback-to-backlog.md](feedback-to-backlog.md).
7. Maintainers either answer the support request, match or create a known issue, escalate privately
   for security, or create a backlog candidate.
8. Fixed or waived items are summarized in the next
   [beta release notes template](../templates/beta-release-notes.md).
9. The next beta candidate verifies the known issue, backlog item, or support action through
   release certification and the production beta go/no-go dashboard.

## Choose a form

| Situation | Public form |
| --- | --- |
| General install, Web Shell, catalog, app, permission, backup, or docs support | `public-beta-support.yml` |
| First-party app behavior in queue-manager, publisher, site-publisher, profile-publisher, feed-reader, trust-graph, or social-inbox | `app-specific-feedback.yml` |
| Catalog refresh, mirror, source health, signature, channel, or rollback incident | `catalog-incident.yml` |
| App install, update, migration, or rollback failure | `app-update-rollback.yml` |
| Support bundle preview, digest, schema, redaction, or export problem | `support-bundle-diagnostics.yml` |
| Developer docs, devtools, CLI, lint, compatibility, or workflow feedback | `developer-beta-feedback.yml` or `app-platform-beta-feedback.yml` |
| Third-party app submission feedback | `app-submission-beta.yml` |
| App review appeal or resubmission | `app-review-appeal.yml` |
| Platform API compatibility issue | `platform-api-compatibility.yml` |
| Legacy plugin migration question | `plugin-migration-feedback.yml` |
| Suspected security issue | `security-advisory-intake.yml` handoff, then the private path in [security-reporting.md](security-reporting.md) |

## Safe fields to include

Include only values that are already public, redacted, or digest-only:

- `app_id`
- `app_version`
- `catalog_id`
- `catalog_channel`
- `release_id`
- node build or commit
- `platform_api_contract_version`
- `support_bundle_digest`
- `support_bundle_schema_version`
- `diagnostic_summary_id`
- `consent_audit_event_id` when relevant
- `operator_recovery_action_id` when relevant
- `known_issue_id` when relevant
- redacted reproduction steps
- expected behavior
- actual behavior
- redacted status codes, evidence IDs, counters, and section names
- safe screenshots only when they contain no secrets, raw private content, private app data, or local paths

Support bundles are local-only until an operator chooses to share them. Public reports should start
with the digest, schema version, diagnostic summary ID, redaction status, and short section
summaries. A maintainer may request a reviewed redacted bundle after checking the public metadata,
but the operator must review the bundle first. App-data backups are not support bundles and must
not be attached to public issues.

## Material to exclude

Do not include any of the following in public issues, screenshots, release notes, support replies,
or backlog records:

- private insert URI
- private keys
- reviewer private keys
- app signing private keys
- browser session tokens
- app tokens
- AppHost process tokens
- authorization headers
- cookies
- form passwords
- seed phrases
- raw fetched content
- raw feed bodies
- raw profile documents
- raw trust statements
- raw social messages
- raw app data values
- raw support bundle files unless explicitly requested and verified redacted
- raw request or response bodies
- absolute local paths
- unredacted stack traces containing paths or secrets
- raw app-data backup files
- private identity material

If a support bundle contains raw content, secrets, app-data backups, private URIs, or absolute local
paths, do not attach it. File a `support-bundle-diagnostics.yml` report with the digest, schema
version, diagnostic summary ID, redaction status, and a description of the redaction concern.

## Triage expectations

Maintainers assign labels from [triage-taxonomy.md](triage-taxonomy.md), then record the outcome in
one of four places:

- support response: the issue is answered without a code or docs change;
- known issue: [known-issues.md](known-issues.md) receives or references a `knownIssueId`;
- backlog candidate: [feedback-to-backlog.md](feedback-to-backlog.md) records the category, next
  beta verification, and release-note requirement;
- security handoff: [security-reporting.md](security-reporting.md) and [../SECURITY.md](../SECURITY.md)
  are used instead of public issue details.

Release certification checks the support feedback loop with these evidence IDs:

- `public-beta.support-feedback-loop`
- `public-beta.support-feedback-docs`
- `public-beta.issue-templates`
- `public-beta.triage-taxonomy`
- `public-beta.known-issues-tracker`
- `public-beta.feedback-to-backlog`
- `public-beta.release-notes-template`
- `public-beta.support-bundle-guidance`
- `public-beta.security-reporting-handoff`
- `public-beta.app-specific-feedback`
- `public-beta.catalog-incident-feedback`
- `public-beta.redaction-fixtures`
