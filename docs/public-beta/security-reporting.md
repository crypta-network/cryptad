# Public beta security reporting

Use this guide to report suspected vulnerabilities, understand advisories and denylists, and share
support evidence without leaking private material.

## Report suspected vulnerabilities

Start with [../SECURITY.md](../SECURITY.md). Source path: `docs/SECURITY.md`. Use
[support-and-feedback.md](support-and-feedback.md) only for public-safe support reports. Do not open
a public issue for a vulnerability that could identify users, reveal private content, bypass
app/catalog trust, expose tokens, or weaken redaction.

When reporting privately, include:

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
| Private security report | Private workflow in [../SECURITY.md](../SECURITY.md). |
| Security advisory or denylist event | Private security workflow, then public-safe release notes when approved. |
| Reviewer key compromise | Private security workflow and reviewer-key compromise runbook evidence. |
| Catalog signing key compromise | Private security workflow and signed catalog replacement guidance. |
| App signing key compromise | Private security workflow, denylist or advisory metadata, and replacement app guidance. |
| Support bundle redaction failure | `security-advisory-intake.yml` for public-safe handoff, then private details in [../SECURITY.md](../SECURITY.md). |

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
3. Share only through the requested private support channel when the report is security-sensitive.
4. Keep the original export available in case maintainers ask for additional redacted metadata.

See [support-and-feedback.md](support-and-feedback.md) and
[../privacy-preserving-beta-diagnostics.md](../privacy-preserving-beta-diagnostics.md).

## Public support template

Use public GitHub issue templates only for redacted support or documentation issues. The templates
under `../../.github/ISSUE_TEMPLATE/` ask for summary evidence and confirmation that secrets and raw
content are not included. `security-advisory-intake.yml` is a handoff-only public form and must not
request exploit details. If a report may be security-sensitive, use the private security path in
[../SECURITY.md](../SECURITY.md) instead.
