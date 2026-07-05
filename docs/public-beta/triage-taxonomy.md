# Public beta triage taxonomy

Use these labels and categories for public beta support, app feedback, catalog incidents, developer
feedback, compatibility issues, security handoffs, known issues, backlog candidates, and beta
release notes. The taxonomy is deterministic so release certification and the go/no-go dashboard can
verify feedback-loop coverage without reading private issue bodies.

## Area labels

- `area/catalog`: catalog source, catalog channel, mirror, signature, health, rollback, or catalog
  operation incident.
- `area/app-update`: app install, staging, update, migration, rollback, or denylist gate.
- `area/app-data`: app-data backup, restore, portability, migration state, quota, or storage issue.
- `area/app-service-grants`: permission consent, service grant, dependency grant, or grant-bundle
  issue.
- `area/trust-graph`: Trust Graph Local RC warning, import, export, trust score, or local advisory
  trust issue.
- `area/social-inbox`: Social Inbox RC rendering, subscription, threading, or local message issue.
- `area/feed-reader`: feed-reader app behavior, feed subscription, or sanitized feed metadata issue.
- `area/profile-publisher`: profile-publisher app behavior or generated profile metadata issue.
- `area/platform-api`: Platform API contract, compatibility window, deprecation, or verifier issue.
- `area/third-party-review`: app submission, review receipt, appeal, resubmission, or reviewer
  workflow issue.
- `area/security-advisory`: private security report handoff, advisory event, denylist event, or key
  compromise coordination.
- `area/legacy-plugin-migration`: legacy plugin migration question, unsupported legacy surface, or
  app-platform replacement pattern.
- `area/docs`: documentation, onboarding, template, release note, or troubleshooting issue.
- `area/support-bundle`: support bundle preview, digest, schema version, redaction, export, or
  diagnostic summary issue.

## Severity labels

- `severity/blocker`: prevents production beta promotion, app install/update safety, catalog trust,
  security response, or redaction safety.
- `severity/high`: materially affects beta users, app developers, or release managers and needs
  next-beta attention.
- `severity/medium`: has a workaround or affects a narrower beta workflow.
- `severity/low`: docs polish, minor ergonomics, or low-risk clarification.

## Status labels

- `status/needs-redaction`: maintainers need safer evidence, a rewritten summary, or private handoff.
- `status/needs-repro`: maintainers need deterministic reproduction steps or a safe diagnostic
  summary.
- `status/known-issue`: issue is matched to a `knownIssueId`.
- `status/backlog-candidate`: issue should become tracked backlog work.
- `status/fixed-next-beta`: fix is expected in the next beta release notes and verification pass.
- `status/waiver-requested`: release manager has requested a documented waiver.

## Privacy labels

- `privacy/redaction-required`: report must be reviewed for secrets, raw content, local paths, or
  unsafe support material before deeper triage.
- `privacy/redaction-passed`: public issue metadata, known issue record, release note entry, or
  backlog record passed redaction review.

## Triage rule

Every public beta feedback item should have one area label, one severity label, one status label,
and one privacy label before it is cited in [known-issues.md](known-issues.md),
[feedback-to-backlog.md](feedback-to-backlog.md), or
[../templates/beta-release-notes.md](../templates/beta-release-notes.md).
