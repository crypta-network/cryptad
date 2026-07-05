# Public beta catalogs and first-party apps

Use this guide to understand stable, beta, and nightly app catalogs, catalog mirrors, catalog
health, first-party app install, security advisories, denylists, and rollback.

## Scope

This is the user-facing summary. The signed catalog format and operator routes are defined in
[../app-catalogs.md](../app-catalogs.md),
[../first-party-beta-catalog.md](../first-party-beta-catalog.md),
[../production-first-party-catalog-channels.md](../production-first-party-catalog-channels.md), and
[../catalog-operations-and-mirrors.md](../catalog-operations-and-mirrors.md).

## Channels

| Channel | Intended use | What to expect |
| --- | --- | --- |
| `stable` | Normal public-beta testing and first-party app onboarding. | Stricter review policy, slower changes, and the safest default. |
| `beta` | Candidate testing before stable promotion. | Reviewed or allowed caution candidates can appear before stable eligibility. |
| `nightly` | Maintainer or advanced tester validation. | Frequent changes and a higher chance of broken candidates. |

A beta catalog candidate is not automatic stable promotion. Stable catalog inclusion requires the
stricter review policy for that channel.

## Trust model

Catalog trust comes from signed catalog metadata and trusted keys. A primary source and its mirrors
can transport catalog bytes, but transport does not create trust. Every refresh still verifies:

- source URI policy;
- catalog id;
- signature;
- trusted catalog key;
- digest and revision;
- stale or downgrade prevention;
- security advisory and denylist metadata;
- key-rotation status.

Mirrors are transport fallback only. Do not treat a mirror as a separate authority.

## Catalog health

Web Shell catalog health should tell you whether the primary source and mirrors are reachable,
fresh, verified, and safe to use. An unhealthy mirror does not mean the catalog is untrusted if the
primary source is healthy and signed metadata verifies. A signature verification failure is
different: it means the bytes cannot be trusted for install or update.

Check:

- last successful refresh;
- active source;
- mirror fallback status;
- current verified revision;
- rollback candidates;
- catalog signing-key rotation state;
- security advisory refresh state.

Report catalog incidents with `catalog-incident.yml` through
[support-and-feedback.md](support-and-feedback.md). Include catalog id, channel, source class,
mirror id when relevant, revision or edition, signature verification status, health status,
rollback attempted, redacted error code, and support bundle digest. Do not include private insert
URIs.

## App review states

| State | User-facing meaning |
| --- | --- |
| `reviewed` | A trusted reviewer receipt supports the candidate for the policy being used. |
| `caution` | A trusted reviewer receipt allows testing with warnings. Web Shell should show the warning before install or update. |
| `rejected` | The candidate should not enter the stable catalog. Rejected candidates are not install approvals. |
| missing or publisher advisory only | The app may be blocked or warned depending on the configured review policy. |

Publisher advisory catalog fields are not independent reviewer trust.

## Security advisories and denylists

Signed catalog metadata can warn about vulnerable versions or denylist exact app versions.

- `denylist` blocks install, update, stage, apply, and automatic policy apply.
- `warn` requires manual acknowledgement for the specific security decision.
- Acknowledgement does not bypass signatures, review policy, compatibility, channel, migration,
  service dependency, or digest checks.
- Emergency replacement guidance is communicated through signed catalog/advisory metadata and
  security release notes, not by asking users to paste secrets.

See [../ecosystem-security-advisories.md](../ecosystem-security-advisories.md) and
[security-reporting.md](security-reporting.md).

## Catalog rollback and key rotation

Catalog rollback is explicit operator action to a previously verified revision. Mirror fallback
must not silently roll back to older bytes. Key rotation status should be visible before a catalog
source is trusted for install or update.

Use rollback when a verified revision is operationally bad, not when signature verification fails.
For signature failures, stop and use troubleshooting or support guidance. Link the incident to
[known-issues.md](known-issues.md) when maintainers assign a `knownIssueId`, and cite only digest
and summary fields from [../privacy-preserving-beta-diagnostics.md](../privacy-preserving-beta-diagnostics.md).
