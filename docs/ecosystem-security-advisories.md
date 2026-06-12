# Ecosystem security advisories

This document describes how signed app catalogs, local review governance, update gates, Web Shell,
developer tooling, and release certification handle app security advisories and review revocation.

## Scope

The security advisory layer is a local app distribution response mechanism. It does not add global
moderation, content blocking, peer-selection policy, routing policy, a network advisory crawler,
legacy plugin compatibility, or automatic app uninstall.

The response layer covers:

- signed catalog-level advisory records in `catalog.version=4`;
- exact `{appId, version}` denylist records;
- review receipt fingerprints and local receipt revocation;
- reviewer-key compromise through the existing `status=revoked` lifecycle;
- install, update, stage, apply, and scheduler security gates;
- Web Shell warnings and safe uninstall guidance;
- release-certification evidence and redaction checks.

## Catalog schema

Catalog-level security policy is part of the signed catalog bytes. A catalog that carries this
policy uses `catalog.version=4`:

```properties
catalog.version=4
catalog.securityAdvisories=CRYPTA-2026-0001
catalog.securityAdvisory.CRYPTA-2026-0001.uri=https://example.invalid/advisories/CRYPTA-2026-0001
catalog.securityAdvisory.CRYPTA-2026-0001.title=Social Inbox 0.1.0 vulnerable draft handling
catalog.securityAdvisory.CRYPTA-2026-0001.severity=critical
catalog.securityAdvisory.CRYPTA-2026-0001.status=active
catalog.securityAdvisory.CRYPTA-2026-0001.action=denylist
catalog.securityAdvisory.CRYPTA-2026-0001.summary=Upgrade to a reviewed replacement version.
catalog.securityAdvisory.CRYPTA-2026-0001.publishedAt=2026-06-11T00:00:00Z
catalog.securityAdvisory.CRYPTA-2026-0001.updatedAt=2026-06-11T00:00:00Z
catalog.securityAdvisory.CRYPTA-2026-0001.replacementAppId=social-inbox
catalog.securityAdvisory.CRYPTA-2026-0001.safeUninstallGuidance=Export app data before uninstalling this vulnerable version.

catalog.securityDenylist=deny-social-inbox-0-1-0
catalog.securityDenylist.deny-social-inbox-0-1-0.appId=social-inbox
catalog.securityDenylist.deny-social-inbox-0-1-0.version=0.1.0
catalog.securityDenylist.deny-social-inbox-0-1-0.advisoryId=CRYPTA-2026-0001
catalog.securityDenylist.deny-social-inbox-0-1-0.reason=Known vulnerable release; update or uninstall.
catalog.securityDenylist.deny-social-inbox-0-1-0.replacementAppId=social-inbox
catalog.securityDenylist.deny-social-inbox-0-1-0.safeUninstallGuidance=Use app-data export before removal.
```

Entry-level `app.<id>.securityAdvisory.*` references still work. They are display references for
one catalog entry. Catalog-level advisory records and denylist entries are the enforceable policy.

The parser is strict:

- advisory IDs and denylist IDs are bounded safe tokens;
- title, summary, reason, and safe-uninstall guidance are bounded single-line text;
- severity is one of `low`, `medium`, `high`, or `critical`;
- status is one of `active`, `resolved`, or `withdrawn`;
- action is one of `inform`, `warn`, `block_install`, `block_update`, or `denylist`;
- duplicate IDs fail closed;
- denylist entries must reference a catalog-level advisory ID;
- v1, v2, and v3 catalogs remain compatible only when they omit v4-only fields;
- v1, v2, or v3 catalogs that include v4-only security-policy fields fail closed.

The first implementation uses exact app-version matching. It does not implement version ranges.

## Security actions

Cryptad reduces catalog policy to a redacted `securityDecision` object in catalog summaries,
install/update checks, update candidates, staged update summaries, and operator dashboard summaries.
The object contains status, action, severity, advisory IDs, acknowledgement requirements, block
flags, replacement app id, safe uninstall guidance, and bounded warning text.

| Action | Manual install | Manual update/stage/apply | Automation |
| --- | --- | --- | --- |
| `inform` | Allowed. | Allowed. | Allowed. |
| `warn` | Requires `securityAcknowledged=true`. | Requires `securityAcknowledged=true`. | Blocked unless a future explicit policy allows warning-level automation. |
| `block_install` | Blocked. | Allowed unless another action blocks update. | Install automation is blocked. |
| `block_update` | Allowed unless another action blocks install. | Blocked. | Staging and apply are blocked. |
| `denylist` | Blocked. | Blocked. | Staging and apply are blocked. |

`denylist` is strongest. `securityAcknowledged=true` can acknowledge only warning-level decisions.
It cannot bypass denylist, block actions, signed catalog verification, artifact digest checks,
signed bundle verification, app review policy, production channel policy, app-data migration gates,
service dependency gates, or Platform API compatibility gates.

Resolved or withdrawn advisories can remain visible for operator context. They do not block unless
an active exact-version denylist entry still applies.

## Installed vulnerable apps

Installed app summaries can include `installedSecurityDecision` when any trusted configured catalog
denylists the installed `{appId, version}`. Web Shell shows the installed vulnerable version, the
advisory IDs, severity, action, replacement guidance, and safe uninstall guidance.

Cryptad does not automatically uninstall a vulnerable app and does not silently migrate to a
replacement app. Operators should export app data before deleting an app when the guidance says to
do so. Replacement app ids are guidance only.

## Review receipt revocation

Review receipt revocation is local governance and is separate from reviewer-key revocation. A
receipt can be revoked by its stable `fingerprintSha256`, which covers the canonical receipt
payload plus detached signature metadata and value.

Registry version 3 extends trusted reviewer keys with revocation entries:

```properties
trusted.reviewers.version=3
review.revocations=receipt-1
review.revocation.receipt-1.receiptFingerprintSha256=<sha256>
review.revocation.receipt-1.appId=social-inbox
review.revocation.receipt-1.appVersion=0.1.0
review.revocation.receipt-1.bundleSha256=<bundle-sha256>
review.revocation.receipt-1.reviewerKeyId=crypta-first-party-review-2026q2
review.revocation.receipt-1.revokedAt=2026-06-11T00:00:00Z
review.revocation.receipt-1.reason=Receipt revoked after advisory CRYPTA-2026-0001.
```

A revoked receipt verifies as `revoked_receipt`. It is not treated as `trusted_reviewed`,
`trusted_caution`, or `trusted_rejected`. Review policy treats it as fail-closed evidence for
manual install/update and policy apply.

## Reviewer-key compromise

Reviewer-key compromise uses the existing lifecycle status:

```properties
reviewer.1.status=revoked
reviewer.1.revoked.at=2026-06-11T00:00:00Z
reviewer.1.revocation.reason=Compromised reviewer key; rotate to crypta-first-party-review-2026q3.
```

Receipts signed by a revoked reviewer key fail as `revoked_reviewer`, including historical
receipts. Web Shell review governance shows revoked reviewer keys and revocation warnings. CLI
inspection reports lifecycle status and receipt revocation counts without printing raw public key
bytes, private keys, raw signatures, registry paths, receipt contents, or local evidence paths.

## Developer tooling

`crypta-app catalog create` can author catalog-level security policy using repeated semicolon
`key=value` specs:

```bash
crypta-app catalog create \
  --security-advisory-record 'id=CRYPTA-2026-0001;uri=https://example.invalid/advisories/CRYPTA-2026-0001;title=Social Inbox 0.1.0 vulnerable draft handling;severity=critical;status=active;action=denylist;summary=Upgrade to a reviewed replacement version.;publishedAt=2026-06-11T00:00:00Z;updatedAt=2026-06-11T00:00:00Z;replacementAppId=social-inbox;safeUninstallGuidance=Export app data before uninstalling this vulnerable version.' \
  --security-denylist-entry 'id=deny-social-inbox-0-1-0;appId=social-inbox;version=0.1.0;advisoryId=CRYPTA-2026-0001;reason=Known vulnerable release; update or uninstall.;replacementAppId=social-inbox;safeUninstallGuidance=Use app-data export before removal.'
```

`crypta-app review verify` prints the redacted receipt fingerprint. `crypta-app review fingerprint`
prints the receipt fingerprint, payload digest, and reviewer id. `crypta-app review keys inspect`
and `verify-lifecycle` include receipt revocation counts.

CLI output may include advisory IDs, app IDs, versions, statuses, counts, fingerprints, and hashes.
It must not print private keys, raw public key bytes, raw signatures, tokens, private insert URIs,
local registry paths, raw fetched content, request bodies, or app-data backup payloads.

## Release certification

Release candidates require the Phase 9 matrix row
`ecosystem-security-advisory-and-revocation` and the gate
`ecosystem.security-advisory-revocation`. The deterministic evidence IDs are:

```text
catalog.security-advisories
catalog.version-denylist
app-review.receipt-revocation
app-review.reviewer-key-compromise-flow
app-update.security-denylist-gates
web-shell.security-advisory-trust-warnings
ecosystem-security.advisory-revocation-redaction
```

The evidence proves strict v4 parser/writer behavior, exact version denylist enforcement, warning
acknowledgement behavior, install/update/stage/apply/scheduler gates, receipt revocation,
revoked-reviewer fail-closed behavior, Web Shell warnings, safe uninstall guidance, and redaction.

Reports must not contain raw signatures, raw public keys, private keys, private insert URIs,
tokens, request bodies, raw fetched content, app-data backup payloads, local filesystem paths,
catalog scratch paths, or staged bundle paths.
