# First-party app beta quality pass

This page defines the beta usability bar for Crypta first-party apps. It is the release-manager and
operator entry point for the PR-275 first-party beta readiness checks.

Release certification evidence id: `first-party-app.beta-quality-pass`.

The canonical machine-readable source is
`tools/release-certification/first-party-app-beta-readiness.json`. That file is checked against
`tools/release-certification/first-party-app-maintenance-policy.json`, the staged manifests, static
UI assets, app READMEs, and the release docs. Missing metadata, missing static UI assets, or
redaction failures keep production beta in a no-go state.

## Readiness contract

Each first-party app must declare and show:

- app identity and purpose summary;
- empty state for no data or no configured source;
- bounded error state that avoids raw daemon exceptions;
- retry action and operator recovery action;
- visible permission rationale plus manifest `permissions.rationale.*` metadata;
- app-data backup, export, import, and migration status;
- support metadata owned by `crypta-core`;
- ARIA live status region and keyboard-accessible controls;
- design-system classes and local static assets only;
- diagnostic copy marked `redacted-summary-only`.

These checks are first-party release readiness checks. They do not replace the third-party
submission queue, reviewer assignment, caution/rejected states, or third-party developer beta
program requirements.

Content-format profile checks are separate PR-276 evidence. Apps that publish, fetch, or import
profile, feed, trust, social message, or social outbox documents should display concise
format-profile metadata from `CryptaPlatform.contentFormats`, but the detailed profile table,
canonicalization rules, version policy, and release evidence live in
[trust-social-content-format-profiles.md](trust-social-content-format-profiles.md).

These content profiles are Crypta app ecosystem profiles. They are not compatibility promises for
legacy WoT, Freetalk, Sone, Freemail, or any old plugin ABI/protocol.

## App coverage

| App | Beta support level | App-data and backup status | Migration dry-run | Scope notes |
| --- | --- | --- | --- | --- |
| `queue-manager` | `core` | Stateless; backup/export/import are `not-applicable`. | `not-applicable` | Queue read/control UI for operator queue recovery. |
| `publisher` | `core` | Stateless; backup/export/import are `not-applicable`. | `not-applicable` | Insert queue workflow with redacted publish summaries. |
| `site-publisher` | `maintained` | Private schema-1 literal drafts; guarded additive import and private export/restore. | `supported` for selected Sharesite conversion preview | Existing site/file inserts plus explicit new-CHK text publication. |
| `profile-publisher` | `maintained` | Durable limited draft/history state; operator-supported export/import. | `not-applicable` | Backup/export never exports vault private identity material. |
| `feed-reader` | `maintained` | Durable feed list, read state, subscription summary, and draft metadata; export/import supported. | `supported` for `ui-state-v1-v2` | Diagnostics must not include raw fetched content. |
| `trust-graph` | `local-rc` | Durable UI-local state; operator-supported export/import. | `supported` for `ui-state-v1-v2` | Local trust only, not global truth, not global WoT, not moderation, not a crawler. |
| `social-inbox` | `local-rc` | Durable sources, read state, social summaries, and drafts; operator-supported export/import. | `additive-not-required` under schema 1 | Not Freemail/Freetalk/Sone protocol compatibility and not encrypted mail transport. |

## Operator behavior

The first screen of each staged app must explain what the app does before the operator performs a
destructive, publishing, grant, or migration action. Empty states describe the next safe action.
Error states show bounded categories such as fetch failure, validation failure, grant unavailable,
service grant inactive, or retry-after/backoff status. They do not display raw stack traces, raw
queue HTML, raw fetched documents, raw messages, raw profile documents, raw trust statements, raw
app-data values, browser session tokens, app-service bearer tokens, private insert URIs, private
keys, vault identity material, or absolute local paths.

Every app offers a retry action for its common failure path. Recovery actions point operators to
the existing RC recovery and support workflow instead of creating app-specific unsafe routes.

## App-data and migration affordances

Stateless apps explicitly say backup/export/import are not applicable because they store no durable
local app state. This is different from unsupported backup; there is nothing app-owned to export.

Site Publisher's [Sharesite pilot](real-legacy-plugin-migration-pilot.md) previews a converted
private package before committing one complete draft dataset. Its migration dry-run status refers
to that import preview, not to an update-time schema transformation. An already installed version
requires normal signed update review and consent for the additional permissions.

Apps with durable app data show the declared schema version when safe, the export/import status,
and whether migration dry-run is available. Feed Reader and Trust Graph declare `ui-state-v1-v2`
migrations and expose dry-run support. Social Inbox uses additive schema-1 beta records and says
that update-time migration is not currently required. Profile Publisher stores bounded profile
draft/history state, but AppVault identity secrets remain vault-scoped and non-exportable.

Backup/export is app-data portability. It is not vault secret export and it does not export vault
private identity material, private keys, seeds, app-service tokens, browser session tokens, private
insert URIs, raw fetched content, raw messages, raw trust signatures, app bundles, or local paths.

## Permission rationale

Every non-trivial manifest permission must have a `permissions.rationale.<permission>` entry and
visible UI disclosure. Rationale text explains the operator workflow enabled by the permission, for
example reading queue state, creating insert jobs, fetching bounded content, writing app-owned
state, using AppVault for bounded signing, or requesting Trust Graph service grants.

Permission rationale changes are material consent changes. Update consent must show added
permissions and changed rationales before install or update can proceed.

## Diagnostics and support

First-party app diagnostics are `redacted-summary-only`. Support metadata may include:

- app id and version;
- catalog channel;
- API target stability and tested contract range;
- app-data schema version;
- last operation status category;
- retry-after or backoff category;
- support action id;
- redaction policy marker.

Support metadata must not include raw fetched content, raw social messages, raw profile documents,
raw trust signatures, private insert URIs, private keys, vault identity material, app-service
bearer tokens, browser session tokens, absolute local paths, or raw app-data values.

Operator support bundle guidance stays in
[operator-rc-recovery-and-support-workflow.md](operator-rc-recovery-and-support-workflow.md).

## Release evidence

The unified `certify.py app-platform` collector validates `first-party-app.beta-quality-pass`
offline. Production beta mode requires the evidence id and treats missing evidence as a blocker.
Redaction findings are unwaivable blockers. Copy-only or wording polish warnings may be shown by
the go/no-go dashboard, but they must be visible in the first-party beta quality domain.

The `certify.py production-beta` pipeline copies a sanitized readiness input below its
engine-native `artifacts/legacy/inputs/` directory. The `certify.py go-no-go` component summarizes
the first-party app beta quality risk separately from first-party maintenance policy and catalog
signing risk.

Run deterministic checks with:

```bash
python3 tools/release-certification/certify.py app-platform --self-test
python3 tools/release-certification/certify.py release-certification --self-test
python3 tools/release-certification/certify.py go-no-go --self-test
python3 tools/release-certification/certify.py production-beta --self-test
```
