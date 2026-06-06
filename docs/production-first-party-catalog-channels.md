# Production first-party catalog channels

PR-248 promotes the first-party app catalog from a beta-only flow to a production release-candidate
channel model. The supported signed catalog entry channels are:

| Channel | Use | Default automation |
| --- | --- | --- |
| `stable` | Production-safe first-party releases. | Allowed by default. |
| `beta` | Operator-selected preview releases. | Blocked unless app-update policy explicitly allows beta. |
| `nightly` | High-churn release-job and tester builds. | Blocked unless app-update policy explicitly allows nightly. |
| `deprecated` | Retired entries retained for operator guidance and replacement metadata. | Always blocked from ordinary automatic staging/apply. |

Stable is the default for production browsing and automation. The first-party beta catalog remains
available, but beta/nightly/deprecated entries must not be automatically mixed into a stable-only
selection.

## Catalog schema

Production channel metadata is authenticated by `catalog.version=3` signed catalog bytes. It is
strictly parsed and deterministically written:

```properties
catalog.version=3
app.<id>.channel=stable|beta|nightly|deprecated
app.<id>.minimumCryptaVersion=<semver-or-build-version>
app.<id>.maximumCryptaVersion=<semver-or-build-version>
app.<id>.support.status=supported|maintenance|experimental|deprecated|unsupported
app.<id>.deprecation.status=none|deprecated|retired
app.<id>.deprecation.message=<single-line operator-facing text>
app.<id>.replacementAppId=<normalized-app-id>
app.<id>.securityAdvisories=CRYPTA-2026-0001
app.<id>.securityAdvisory.CRYPTA-2026-0001.uri=https://example.invalid/advisories/CRYPTA-2026-0001
```

Existing v1 and v2 catalogs remain compatible. When they omit production-channel fields, Cryptad
defaults the entry to `channel=stable`, `support.status=supported`, `deprecation.status=none`, no
replacement app id, and no security advisories. A v1 or v2 catalog that declares v3-only fields is
rejected by the strict parser instead of being partially accepted.

`replacementAppId` uses the same normalized app-id validation as catalog entries. Security
advisory URIs use the same safe metadata URI policy as homepage, source, changelog, and screenshot
metadata.

## API and Web Shell

Catalog APIs expose channel metadata through `GET /api/v1/app-catalogs`,
`GET /api/v1/app-catalogs/recommended`, `GET /api/v1/app-catalogs/{catalogId}/apps`, and
`GET /api/v1/app-catalogs/{catalogId}/apps/{appId}`. Catalog app summaries include:

```json
{
  "channel": "stable",
  "supportStatus": "supported",
  "compatibility": {
    "minimumCryptaVersion": "1481",
    "maximumCryptaVersion": "1499"
  },
  "deprecation": {
    "status": "none",
    "message": null,
    "replacementAppId": null
  },
  "securityAdvisories": [
    {
      "id": "CRYPTA-2026-0001",
      "uri": "https://example.invalid/advisories/CRYPTA-2026-0001"
    }
  ]
}
```

Recommended catalog summaries also expose `defaultEntryChannel=stable` and
`availableEntryChannels=["stable","beta","nightly","deprecated"]` for production selectors.

The Web Shell Apps page provides a catalog-channel selector with a stable default. It filters
catalog app cards by selected channel, displays distinct badges for beta, nightly, and deprecated
entries, and shows support status, deprecation status/message, replacement app id, and security
advisory links when present. Deprecated entries are shown as operator guidance and do not render as
ordinary install/update buttons.

## Update policy

App update policy includes `allowedChannels`. The default allowed channel set is `stable` only.
Manual operator actions may still view and explicitly stage non-stable entries when review and
compatibility gates allow them, but background policy-driven staging/apply filters candidates
through channel policy first.

If a candidate is excluded by channel policy, the candidate remains visible with:

```json
{
  "channelPolicyAllowed": false,
  "policyBlockReason": "channel_policy_blocked",
  "autoStageAllowed": false
}
```

Deprecated entries are blocked from automatic staging/apply even if a policy includes
`deprecated`. PR-248 only surfaces deprecation and replacement metadata; it does not implement
app-data migration, backup/restore, advisory denylist enforcement, or automated replacement flows.
PR-249 app-data migration acknowledgement is an additional update gate only; it does not override
`allowedChannels`, `channel_policy_blocked`, signed catalog verification, trusted review receipt
policy, or deprecated-entry automation blocking.

## Release certification

Release candidates require `catalog.production-channels` evidence. The check is deterministic and
offline-friendly. It verifies:

- schema v3 parser/writer/descriptor support for stable, beta, nightly, and deprecated metadata;
- default stable-only automation and `channel_policy_blocked` status for excluded candidates;
- deprecated entries expose replacement/deprecation metadata and are not ordinary automatic update
  candidates;
- API and Web Shell response/rendering support for channel metadata;
- signed catalog verification and trusted review receipt verification remain mandatory;
- release reports redact private insert URIs, tokens, private keys, raw fetched content, raw app
  data, catalog scratch paths, staged bundle paths, and absolute local paths.

Live-network beta certification remains separate. The production-channel evidence row is a Phase 9
release-candidate gate and does not require a live node.
