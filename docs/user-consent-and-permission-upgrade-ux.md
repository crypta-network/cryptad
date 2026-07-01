# User consent and permission upgrade UX

This document describes the unified operator consent layer for app install, app update,
app-service grant, and app-data migration decisions.

## Scope

Consent applies when an app operation would change material trust, permission, support, security,
service, or data-handling state. It gives Web Shell and host/operator API clients one preview and
decision flow instead of separate prompts for every subsystem.

Consent covers:

- new app installation from a signed catalog;
- catalog-backed app updates;
- permission additions and changed permission rationales;
- Platform API target stability and experimental capability acceptance changes;
- third-party review, reviewer-key, receipt, and trust-status changes;
- catalog channel, support level, deprecation, and replacement metadata;
- catalog security advisories, denylist decisions, and revoked review receipts;
- app-service dependency bundles and grant renewal or revalidation;
- app-data schema migration plans and backup-before-update recommendations;
- Trust Graph import preview commits with material local score impact;
- automatic update gating when material review is required;
- audit records for approve, reject, defer, and expired decisions.

The consent layer is a local operator policy surface. It does not change bundle signatures, catalog
signatures, review receipt verification, app sandboxing, AppHost process launch, peer protocols, or
the app-facing Platform API contract.

## Consent Preview

Operators review a deterministic consent snapshot before a material operation. A snapshot includes
the action, app id, candidate version and digest when available, catalog id/source/channel, risk
level, blocking reasons, grouped human-readable sections, and a snapshot digest.

The snapshot digest binds the decision to the exact preview. Mutating routes that require consent
must receive the same consent request id and digest that Web Shell approved. If the candidate,
catalog entry, review receipt, permission set, service grant, security policy, or migration plan
changes after preview, the mutation rejects the stale approval and asks the operator to refresh the
preview. This stale consent protection prevents an operator decision from authorizing a later,
different candidate.

Approved consent requests are single-use and process-local. The platform consumes an approval after
one successful digest check, and unconsumed approvals expire from the in-memory decision cache after
15 minutes so an old request id cannot be replayed if the same snapshot digest appears later.

Snapshots and audit records are redacted summaries. They must not include private insert URIs,
private keys, bearer tokens, browser session tokens, authorization headers, raw fetched content,
raw app data, backup payloads, vault secret material, or host-local filesystem paths.

## Install Consent

Install preview summarizes the candidate app before the bundle is installed:

- app id, name, version, and bundle digest;
- catalog id, source, channel, first-party or third-party status, support level, and maintenance
  owner;
- review status, reviewer-key status, receipt fingerprint, submission id, and submission digest
  when available;
- stable, beta, nightly, deprecated, replacement, and deprecation metadata;
- security advisory status and blocking security decisions;
- required permissions with declared rationales;
- Platform API target stability, target API range, and experimental acceptance flag;
- sandbox requirement;
- app-data schema, migration, and backup declarations;
- app-service dependencies and requested grant bundles;
- explicit risk level and blocking reasons.

Install mutations can proceed without a consent approval only when the preview has no material or
blocking findings. Denylisted candidates and non-overridable security blocks remain blocked even
when an operator tries to approve the snapshot.

## Update Consent

Update preview compares the installed app with the candidate bundle or catalog entry. It shows:

- old and new app versions;
- old and new bundle digests;
- added and removed permissions;
- changed permission rationales when available;
- stable-to-experimental target changes, target API range changes, and experimental acceptance
  changes;
- reviewer changes, review status changes, receipt changes, caution decisions, and revoked
  receipts;
- channel changes, support degradation, deprecation, and replacement app suggestions;
- new security advisories, denylisted candidates, and vulnerable installed versions;
- app-data schema migration from and to versions, dry-run status, rollback compatibility, and
  backup recommendation or requirement;
- new service dependencies, changed provider descriptors, and grants requiring renewal or
  revalidation;
- whether the update is eligible for automatic staging or apply.

The update route validates the approved snapshot before staging a candidate. Review, security, and
migration acknowledgements are derived from the verified consent approval so Web Shell does not
need to present separate raw acknowledgement checkboxes for the same operation.

## Permission Delta

Permission changes are grouped by added, removed, and changed rationale. Added permissions and
expanded rationales are material because they alter what the app can request from the local node.
Removed permissions are still visible so operators can verify that an update reduces authority, but
they do not normally block automatic policy by themselves.

Permission rationales are display text, not grants. Runtime authorization still comes from the
signed manifest and the authenticated app principal.

For first-party apps, `first-party-app.beta-quality-pass` verifies that every non-trivial
permission has manifest rationale metadata and visible UI copy before production beta. Install and
update consent should surface changed first-party rationale text alongside permission deltas,
support metadata, app-data backup/export/import status, migration dry-run status, and
`redacted-summary-only` diagnostics posture. Backup/export consent must still say that vault
private identity material is not exported.

## API Stability Change

Platform API stability changes are material when an update moves from the stable baseline to
experimental target stability, widens accepted experimental capability use, or changes the declared
target API range in a way the operator should review. This keeps Platform API 1.0 stable-baseline
expectations visible before operators accept an update that depends on experimental app-facing
behavior.

## Review And Trust Delta

Review and trust findings summarize the current trusted review status without exposing raw receipt
payloads or raw key material. The consent preview highlights reviewer changes, receipt fingerprint
changes, `caution` review results, receipt revocations, reviewer-key lifecycle degradation, and
publisher-advisory-only review metadata.

A revoked review receipt or revoked reviewer key is treated as a high-risk or blocking condition
according to local policy. The preview should fail closed for operations that cannot be made safe
with an operator acknowledgement.

## Service Grants

App-service dependency grant bundles use the same consent language as install and update. A
service-grant preview explains:

- the requesting app;
- the provider app and service;
- service id, capability, scopes, contexts, and feature name;
- whether the dependency is required or optional;
- expiry and renewal behavior when present;
- audit impact and revocation behavior;
- provider descriptor revalidation state.

Approving, renewing, rejecting, or deferring a grant bundle writes a consent audit event. Approval
does not create ambient localhost trust; the app still needs the authenticated principal,
`app.services.call`, and an active grant record for invocation.

Social Inbox uses this path for the optional Trust Graph `trust.score` dependency. Installing or
updating Social Inbox exposes the requested `trust-annotations` bundle in the install/update
preview. Grant approval, renewal, or provider descriptor revalidation must bind to the current
snapshot digest. Revoked, expired, stale, or revalidation-required grants leave Social Inbox in a
neutral unscored state; they do not authorize a fallback to direct Trust Graph routes.

## App-Data Migration And Backup

App-data migration findings summarize metadata only:

- current and target schema versions;
- migration path or platform migration status;
- dry-run status when available;
- whether a backup exists;
- whether backup-before-update is recommended or required;
- rollback compatibility;
- known data-loss risk and blocking migration errors.

When a migration requires operator review, rollback compatibility is missing, or backup is required
but absent, the update cannot be silently applied by scheduler policy. The preview must never show
raw app-data values, backup contents, migration logs, command paths, process tokens, or private
content identifiers.

Social Inbox beta hardening is currently additive within schema-1 `ui-state` and `social`
namespaces so installed schema-1 data can update without launching a migration process. A future
Social Inbox schema bump must use the same consent preview, backup-before-update recommendation,
snapshot digest binding, and stale approval rejection as other app-data migrations. Trust Graph
Local RC UI-state migrations use the same mechanism for app-owned UI data; platform trust graph
anchors and statements remain platform service state, not raw app-data payloads.

## Trust Graph Import Consent

Trust Graph import preview commit uses the unified consent language when a preview reports material
risk, such as accepted statements that also contain duplicate issuers, conflicts,
revoked/deprecated/expired candidates, oversized input warnings, or repeated high-risk source
warnings. The consent snapshot includes bounded source summaries, candidate and rejection counts,
duplicate issuer counts, conflict counts, approximate score impact, and whether raw content was
discarded. The mutation must reject a stale approval if the preview digest no longer matches the
import commit request.

The consent record and audit event must remain path-free and summary-only. They must not include
raw fetched content, raw trust statement bodies, raw Social Inbox messages, raw app data, backup
payloads, private insert URIs, bearer tokens, browser session tokens, raw signatures, private keys,
or absolute local paths.

## Security, Deprecation, And Replacement

Catalog security, deprecation, and replacement metadata is visible before install and update.

Rules:

- denylisted candidates are not installable, stageable, applyable, or auto-updatable;
- warning-level advisories require explicit consent before manual install or update;
- revoked receipts and reviewer-key compromise states fail closed or require blocking warnings
  according to local policy;
- deprecated apps show replacement information when the catalog provides it;
- security advisory text is summarized and redacted.

Consent approval can acknowledge warning-level metadata. It cannot override denylist or
non-overridable block decisions.

## Auto-Update Gating

Automatic update policy must not bypass material consent. Scheduler-driven staging or apply is
blocked when a candidate introduces:

- new permissions or expanded permission rationale;
- required app-service dependency grants or provider revalidation;
- app-data migration with backup required or operator review required;
- stable-to-experimental Platform API target changes;
- newly accepted experimental capabilities;
- review caution, revoked receipt, reviewer-key degradation, or receipt changes;
- stable-to-beta, nightly, or deprecated channel movement;
- support degradation, deprecation, or replacement metadata;
- new security advisories;
- denylist or other non-overridable catalog security blocks.

The scheduler surfaces pending consent state through update summaries instead of silently applying
the candidate.

## Audit Records

Every consent approve, reject, defer, or expiry decision records:

- decision id;
- consent request id;
- local operator marker or actor identity when available;
- app id;
- action type;
- decision status;
- timestamp;
- consent snapshot digest;
- material risk summary.

Audit records are safe summaries. They redact tokens, private URI forms, raw content, raw app data,
backup payloads, vault secret material, and host-local paths. Audit records must be useful for
support and release evidence without becoming a secret-bearing log.

## API Surface

The consent routes are host/operator routes under the local Platform API transport. App principals
do not receive ambient authority to approve their own install, update, service-grant, or migration
decisions.

The current route family includes preview and decision endpoints for install, catalog update, app
update, service grants, approve, reject, defer, and audit listing. Clients should always fetch a
fresh preview immediately before asking the operator for approval and should submit the returned
request id plus snapshot digest with the mutation.

## Web Shell UX

Web Shell renders consent previews as grouped sections with concise labels. It does not dump raw
manifest JSON. The install, update, and service-grant buttons fetch a preview when needed, show the
material findings, and then submit the approved request id and snapshot digest with the original
mutation.

If the mutation reports a stale approval, Web Shell asks the operator to refresh the preview. The
operator can approve the new snapshot, reject the decision, or leave the candidate pending.

## Release Evidence

Release certification records this work as `app-platform.user-consent-flow`. The deterministic
smoke evidence checks that the consent model, route wiring, auto-update gating, audit redaction,
stale snapshot protection, Web Shell UI, docs, and tests are present without requiring a live
Crypta node.

## Non-Goals

This layer is reused by Trust Graph and Social Inbox beta hardening, but it does not turn Trust
Graph into global Web of Trust, make Social Inbox compatible with Freetalk/Sone/Freemail, add a
public remote app store, replace signed catalog verification, bypass review receipt validation,
weaken denylist decisions, expose raw app data to operators, or make automatic updates the default.
