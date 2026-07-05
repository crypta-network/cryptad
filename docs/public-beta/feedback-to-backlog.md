# Feedback to backlog workflow

This workflow tells maintainers how to turn public beta feedback into support actions, known
issues, backlog candidates, release blockers, release notes, and next-beta verification without
storing private material.

## Steps

1. Intake: choose the most specific issue form and verify the required metadata is present.
2. Redaction check: confirm the public report contains no private insert URIs, keys, tokens,
   authorization headers, cookies, form passwords, raw content, raw app data, raw support bundles,
   raw request or response bodies, stack traces with local paths, or app-data backup files.
3. Reproduction check: confirm the report has redacted reproduction steps, expected behavior, actual
   behavior, release ID, Cryptad version, app or catalog metadata when relevant, and digest-only
   support evidence when relevant.
4. Triage category: assign labels from [triage-taxonomy.md](triage-taxonomy.md).
5. Known issue matching: match an existing `knownIssueId` in [known-issues.md](known-issues.md) or
   create a new redaction-safe entry.
6. Support response: answer the issue when a workaround, docs pointer, or operator recovery action
   resolves it.
7. Security escalation: move suspected vulnerabilities, advisory or denylist events, key compromise
   reports, and support-bundle redaction failures to [security-reporting.md](security-reporting.md)
   and [../SECURITY.md](../SECURITY.md). Do not request exploit details in public.
8. Developer or app-review escalation: route third-party submission, reviewer, appeal,
   compatibility, and plugin migration items to the corresponding public beta template and review
   workflow.
9. Release blocker decision: mark `severity/blocker` when the issue affects production beta
   promotion, redaction safety, catalog trust, security response, app update safety, or required
   support evidence.
10. Backlog candidate creation: record a safe placeholder or tracker link. The backlog item must
    reference the public issue number, taxonomy labels, `knownIssueId` when present, safe evidence
    IDs, and next beta verification criteria.
11. Next beta verification: define the doc, test, release-certification evidence, or manual support
    verification that closes the loop.
12. Release notes entry: summarize fixed issues, known issues, support guidance, security handoffs,
    app compatibility notes, waivers, and upgrade warnings in
    [../templates/beta-release-notes.md](../templates/beta-release-notes.md).
13. Closure criteria: close the public issue only after the support answer, known issue entry,
    backlog candidate, release-note entry, or security handoff is recorded.

## Safe examples

### Catalog cannot refresh

Use `catalog-incident.yml`. Collect catalog ID, catalog channel, catalog source class, mirror ID if
available, revision or edition, signature verification status, health status, rollback attempted,
support bundle digest, and a redacted error code. Do not ask for a private insert URI.

### App update failed

Use `app-update-rollback.yml`. Collect app ID, current app version, target app version, catalog
channel, update phase, rollback result, migration status, app-data backup status, support bundle
digest, expected behavior, and actual behavior.

### Subscription stuck

Use `app-specific-feedback.yml`. Collect app ID, app version, catalog channel, redacted
subscription ID, operation attempted, expected result, actual result, support bundle digest, and
redacted reproduction steps. Do not include feed bodies or fetched content.

### Trust Graph import warning

Use `app-specific-feedback.yml` with `trust-graph`. Include the trust/social document profile ID
only if it is already public-safe or redacted. Include warning code, digest, expected result, and
actual result. Do not include raw trust statements.

### Social Inbox rendering issue

Use `app-specific-feedback.yml` with `social-inbox`. Include app version, catalog channel, redacted
subscription or conversation identifier, expected rendering, actual rendering, and support digest.
Do not include raw social messages.

### Third-party app compatibility report

Use `platform-api-compatibility.yml` or `developer-beta-feedback.yml`. Include app ID, app version,
Platform API contract version, tested compatibility range, verifier evidence ID, and redacted
runtime behavior.

### Legacy plugin author migration question

Use `plugin-migration-feedback.yml`. Include plugin category, legacy surfaces used, proposed app
platform replacement, stable-baseline need, and safe blockers. Do not include legacy plugin export
bodies.

### Support bundle redaction concern

Use `support-bundle-diagnostics.yml`. Include digest, schema version, diagnostic summary ID,
redaction status, affected section name, and operator-reviewed description. Do not attach the raw
bundle.

### Suspected security advisory

Use `security-advisory-intake.yml` only to classify the handoff, then follow the private workflow in
[security-reporting.md](security-reporting.md) and [../SECURITY.md](../SECURITY.md). Do not post
exploit details, proof of concept payloads, keys, tokens, private URIs, or raw logs publicly.
