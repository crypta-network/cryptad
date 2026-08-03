# Public beta security reporting

Use this guide to report suspected vulnerabilities, understand advisories and denylists, and share
support evidence without leaking private material.

## Report suspected vulnerabilities

Start with the reporting boundary in [../SECURITY.md](../SECURITY.md). Source path:
`docs/SECURITY.md`. This repository does not currently publish a Crypta-specific private reporting
endpoint. Use [support-and-feedback.md](support-and-feedback.md) only for public-safe support
reports. Do not open a public issue for a vulnerability that could identify users, reveal private
content, bypass app/catalog trust, expose tokens, or weaken redaction. Do not send sensitive
details to the inherited Freenet address as though it were a Crypta endpoint.

If a maintainer provides an approved protected Crypta channel out of band, include:

- Cryptad build or release tag;
- OS and package type;
- affected app id/version or catalog id when relevant;
- high-level impact;
- minimal reproduction steps using placeholders;
- redacted support bundle metadata if requested;
- whether the issue affects signed catalogs, signed bundles, app review receipts, Web Shell,
  Platform API permissions, AppHost, support bundles, or release evidence.

Do not include exploit details in public issue titles, public comments, screenshots, or logs.

## Public or private path

| Situation | Safe path |
| --- | --- |
| Public bug report with no security impact | Public issue form from [support-and-feedback.md](support-and-feedback.md). |
| Sensitive security report | Use the public form only to request a redacted handoff. Share details only after a maintainer supplies an approved protected Crypta channel out of band. |
| Security advisory or denylist event | Protected Crypta channel when configured, then public-safe release notes after authorization. |
| Reviewer key compromise | Protected Crypta channel when configured and reviewer-key compromise runbook evidence. |
| Catalog signing key compromise | Protected Crypta channel when configured and signed catalog replacement guidance. |
| App signing key compromise | Protected Crypta channel when configured, denylist or advisory metadata, and replacement app guidance. |
| Support bundle redaction failure | `security-advisory-intake.yml` for a public-safe handoff request; do not attach private details. |

## What not to include

Never paste:

- private insert URIs;
- private keys or seed phrases;
- reviewer private keys;
- app process tokens or browser session tokens;
- form passwords, cookies, or authorization headers;
- raw support bundles;
- raw fetched content;
- raw app-data values or backup payloads;
- raw social messages;
- raw trust statements;
- raw profile or feed documents;
- raw FProxy HTML;
- local absolute paths;
- release secrets or CI secret values.

Use placeholders such as `<redacted>`, `<catalog-key>`, `<app-id>`, `<token-redacted>`, and
`<summary-only>` where a value would be sensitive.

## Advisories and denylists

Public beta app security response uses signed catalog metadata, security advisories, version
denylists, review receipt revocation, reviewer-key lifecycle, replacement guidance, and security
release notes.

- Denylisted versions fail closed for install, update, stage, apply, and automatic policy apply.
- Warning advisories require manual acknowledgement.
- Acknowledgement does not bypass signatures, review policy, compatibility, migration, service
  dependency, digest, or channel checks.
- Emergency replacement apps or catalog updates are communicated through signed metadata and
  release notes.

See [../production-security-response-runbook.md](../production-security-response-runbook.md),
[../ecosystem-security-advisories.md](../ecosystem-security-advisories.md), and
[../templates/security-release-notes.md](../templates/security-release-notes.md).

## Support bundle redaction expectations

Default support bundles are local until the operator exports them. They should include metadata,
counts, statuses, versions, digests, and redaction booleans. They should exclude raw content, raw
app data, private insert URIs, app or browser tokens, form passwords, identity material, local
paths, and legacy plaintext diagnostic bodies.

Before sharing a bundle:

1. Preview the redaction summary.
2. Confirm redaction status is passing.
3. Share only after a maintainer identifies an approved protected Crypta channel. If none is
   configured, retain the bundle locally and share only a redacted handoff request.
4. Keep the original export available in case maintainers ask for additional redacted metadata.

See [support-and-feedback.md](support-and-feedback.md) and
[../privacy-preserving-beta-diagnostics.md](../privacy-preserving-beta-diagnostics.md).

## Stable 1.0 authenticated case lifecycle

The public handoff does not create a vulnerability case. An approved protected intake converts a
private report into an opaque `sv-…` identity, protected acknowledgement, and append-only case
ledger. Acknowledgement and triage deadlines come from the reviewed Stable vulnerability policy;
critical acknowledgement and triage are due within four hours and cannot be extended.

Triage records exact severity (`low`, `moderate`, `high`, or `critical`), confidence,
exploitability, urgency, affected builds/packages/apps/contracts/profiles/keys, and every deadline.
Extensions require a protected, digest-bound authorization issued before the old deadline.
Anonymous reports remain actionable. Reporter silence does not permit maintainers to ignore
confirmed impact.

The public-beta issue taxonomy retains the established `severity/medium` label. It is a
non-authoritative routing estimate. Protected PR-288 triage explicitly normalizes that estimate to
the closed `moderate` case severity; a public label never sets or lowers the authenticated
classification.

Confirmed remediation enters the existing Stable backport and maintenance/security-hotfix paths.
Disclosure remains separate: exact released bytes and any catalog, updater, lifecycle, reviewer,
or key actions must be authenticated before exact public advisory bytes and targets can be
authorized. A CVE, GHSA, OSV, or vendor id is optional and never grants authorization. Public
reporter credit is opt-in and bound to the exact authorized text.

See the complete [Stable 1.0 vulnerability intake and coordinated-disclosure
runbook](../stable-1.0-vulnerability-intake-and-coordinated-disclosure-operations.md). It also
defines what operators see after disclosure, how exact publication is observed, and why closure
waits for post-release checks and every applicable follow-up.

## Public support template

Use public GitHub issue templates only for redacted support or documentation issues. The templates
under `../../.github/ISSUE_TEMPLATE/` ask for summary evidence and confirmation that secrets and raw
content are not included. `security-advisory-intake.yml` is a handoff-only public form and must not
request exploit details. If a report may be security-sensitive, request a redacted handoff and wait
for a maintainer to provide an approved protected Crypta channel. The repository currently
publishes no Crypta-specific private endpoint.
