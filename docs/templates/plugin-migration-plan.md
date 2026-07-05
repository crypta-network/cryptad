# Plugin migration plan template

Use this template when a submitted app replaces legacy plugin behavior.

## Summary

Use these exact field names in the submitted migration plan, then expand each section below:

```text
legacyPluginId
newAppId
stateClasses
manifestCapabilities
appDataNamespaces
contentSubscriptions
identityGrants
appServiceDependencies
migrationSteps
backupRestorePolicy
reviewEvidence
redactionPolicy
knownNonGoals
```

- `legacyPluginId`:
- `newAppId`:
- `migrationOwner`:
- `targetStability`: `stable` or `experimental`
- `legacyBehaviorSummary`:
- `publicBetaSupportStatus`: `supported`, `unsupported`, or `future-work`

## State classes

List each legacy state class and the public-beta destination.

| State class | Destination | Automatic migration | Notes |
| --- | --- | --- | --- |
| Public content | Content profile or public read URI summary | yes/no | |
| Local config | App-data namespace | yes/no | |
| App data | App-data namespace and schema version | yes/no | |
| Identity/secrets | AppVault grant | no private export | |
| Subscriptions | Content subscriptions | yes/no | |
| Trust statements | Trust Graph Local RC import | yes/no | |
| Messages | App data or future app design | yes/no | |
| Diagnostics | Summary/digest only | yes/no | |

## Manifest capabilities

List requested capabilities and the smallest reviewed reason for each.

| Capability | Required or optional | Reason |
| --- | --- | --- |
| `platform.contract.read` | required | Read the local Platform API contract for compatibility checks. |

## App-data namespaces

| Namespace | Current schema | Records | Migration steps | Backup/restore behavior |
| --- | --- | --- | --- | --- |
| `ui-state` | `1` | UI preferences and safe summaries | additive | included |

## Content subscriptions

| Subscription purpose | Source kind | Budget behavior | Stored summary |
| --- | --- | --- | --- |
| Example public source follow | public USK source | shared app-network budget | digest and status only |

## Identity grants

| Grant | Purpose | Private material export |
| --- | --- | --- |
| `vault.identities.use` | Bounded signing for public documents | never |

## App-service dependencies

| Provider | Service | Scope | Context | Dependency kind | Degrade behavior |
| --- | --- | --- | --- | --- | --- |
| `trust-graph` | `trust.score` | `score.read` | `message-author` | optional | disable feature |

## Migration steps

1. Inventory legacy state and side effects.
2. Run dry-run import and report counts, digests, skipped classes, and warnings.
3. Create backup/export before destructive migration.
4. Apply additive app-data migrations.
5. Request operator consent for any app-service grant delta.
6. Verify restored state after backup/restore.
7. Record unsupported or manual-only state classes.

## Backup and restore policy

State whether app data participates in app-data backup/restore. List restore prerequisites,
unsupported cases, and whether migration can be retried after restore.

## Review evidence

- manifest validation:
- API compatibility:
- UI lint:
- permission rationale:
- app-data schema notes:
- backup/restore notes:
- security notes:
- content format profile notes:
- app-service dependency notes:
- redaction scan:

## Redaction policy

Artifacts and support evidence must include only safe ids, counts, digests, status labels,
capability names, service ids, schema versions, and redaction booleans. They must not include
private insert URIs, private keys, app tokens, browser session tokens, cookies, form passwords,
raw plugin state, raw social messages, raw trust statements, raw profile/feed documents, raw
app-data values, raw signatures, local paths, raw FProxy HTML, or raw support bundles.

## Known non-goals

List every old plugin behavior that is not migrated automatically, including old plugin ABI/FCP
compatibility, protocol compatibility, daemon-core hooks, ambient localhost RPC, raw FProxy
scraping, private-key export, and unbounded crawling.
