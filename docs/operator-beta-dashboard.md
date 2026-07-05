# Operator Beta Dashboard

The operator beta dashboard is a local host/operator-only surface for checking whether the app
platform is ready for public beta use. PR-257 keeps this route as compatibility evidence while
the Web Shell now presents the RC workflow documented in
[operator-rc-recovery-and-support-workflow.md](operator-rc-recovery-and-support-workflow.md).

Public-beta users and operators should start with
[public-beta/user-guide.md](public-beta/user-guide.md) and
[public-beta/troubleshooting.md](public-beta/troubleshooting.md). This page remains the detailed
Web Shell dashboard, support-bundle, and operator recovery source of truth.

It is exposed through the Web Shell and the internal operator route family:

- `GET /api/v1/operator/rc-dashboard`
- `GET /api/v1/operator/beta-dashboard`
- `GET /api/v1/operator/recovery/actions`
- `POST /api/v1/operator/recovery/plan`
- `POST /api/v1/operator/recovery/execute`
- `GET /api/v1/operator/network-budgets`
- `GET /api/v1/operator/support-bundle/preview`
- `GET /api/v1/operator/support-bundle`
- `POST /api/v1/operator/app-data/backups` with `appId=<app-id>`
- `POST /api/v1/operator/app-data/backups` with `scope=all`
- `POST /api/v1/operator/app-data/restore/plan`
- `POST /api/v1/operator/app-data/restore`
- `POST /api/v1/operator/subscriptions/{appId}/{subscriptionId}/refresh`
- `POST /api/v1/operator/subscriptions/{appId}/{subscriptionId}/pause`
- `POST /api/v1/operator/subscriptions/{appId}/{subscriptionId}/resume`
- `POST /api/v1/operator/subscriptions/{appId}/{subscriptionId}/reset-backoff`
- `POST /api/v1/operator/subscriptions/{appId}/{subscriptionId}/reschedule-now`

These routes are not part of the app-facing Platform API contract. App principals must not call
them, and app compatibility descriptors should not depend on them. Mutating subscription recovery
actions require the normal local form-password bridge when they are reached through legacy HTTP.
App-data backup export is also a `POST` route, not a `GET`, so the bridge applies the same
form-password guard before returning a raw user backup payload.

Default support-bundle exports use the versioned privacy-preserving diagnostics schema documented
in [privacy-preserving-beta-diagnostics.md](privacy-preserving-beta-diagnostics.md). The bundle is
generated locally, is not uploaded automatically, and excludes raw content, raw app data, private
insert URIs, tokens, identity material, local paths, and legacy plaintext diagnostics bodies.

## Dashboard Contents

The dashboard is intentionally a summary and recovery surface, not a replacement for the app
contract or release certification reports.

| Evidence id | Dashboard behavior |
| --- | --- |
| `operator-beta.dashboard` | Shows one generated-at snapshot with overall status, summary counts, catalogs, apps, subscriptions, Trust Graph Local RC state, app-service grants, legacy-admin usage, diagnostics availability, warnings, and safe recovery actions. |
| `operator-beta.catalog-health` | Shows configured catalog source kind, redacted source display, trusted-key state, last fetch status, last successful refresh, app count, and a refresh action. It may show a digest for correlation, but it must not expose private insert URIs or local catalog paths. |
| `operator-beta.app-update-recovery` | Shows installed app state, signed-bundle status, sandbox and quota warnings, update candidate/staged/rollback state, and safe lifecycle actions such as start, stop, check, stage, apply, rollback, and log review. Destructive uninstall is not advertised in the beta dashboard. |
| `operator-beta.subscription-recovery` | Shows all durable content subscriptions to the host operator with redacted source display, digest, status, last success/failure, next due time, failure count, and refresh/pause/resume actions. It must not expose raw fetched content or app-private request bodies. |
| `operator-beta.trust-review-warnings` | Shows Trust Graph Local RC as local operator-curated trust state only, not global truth, moderation, blocking, routing policy, or legacy Web of Trust compatibility, and surfaces app-review/update warnings that need operator attention. |
| `operator-beta.app-data-quota-warnings` | Summarizes app-data and AppHost quota warnings using counts, booleans, and status labels instead of raw app data values. |
| `operator-beta.app-data-backup-restore` | Shows sensitive app-data backup, restore preview, restore commit, all-app backup, and export-before-delete controls without displaying raw backup record values in ordinary dashboard panels. |
| `operator-beta.support-bundle-redaction` | Exports a redacted support bundle for issue triage. |
| `operator-beta.web-shell` | Pins the Web Shell panel, refresh controls, support-bundle export/copy controls, read-only hints, and recovery-action submit handling. |

## Beta Compatibility and RC Recovery

The beta dashboard route remains a read-only compatibility alias for older operator tooling and
for the `operator-beta.*` release evidence. The RC dashboard composes the same summary data with
typed recovery actions and support-bundle preview metadata. Web Shell loads the RC route first and
falls back to the beta route only with a visible compatibility note.

The RC workflow adds these deterministic evidence ids:

- `operator-rc.dashboard`
- `operator-rc.recovery-plan-execute`
- `operator-rc.catalog-repair`
- `operator-rc.app-reinstall-rollback`
- `operator-rc.export-before-uninstall`
- `operator-rc.subscription-recovery`
- `operator-rc.app-service-grant-recovery`
- `operator-rc.trust-graph-recovery`
- `operator-rc.network-budget-visibility`
- `operator-rc.support-bundle-wizard`
- `operator-rc.redaction`

See the RC workflow guide for the closed `OperatorRecoveryActionId` list, typed target model,
plan-before-execute semantics, destructive confirmation requirements, and unavailable reset
limitations.

## Recovery Actions

Recovery actions are intentionally narrow:

- Catalog recovery refreshes a configured catalog through the existing catalog route.
- RC catalog repair can also reverify catalog metadata and add a recommended first-party source
  only through existing catalog-manager APIs. It does not silently switch stable operators to beta,
  nightly, or deprecated channels.
- App recovery delegates to existing app lifecycle and app-update routes. Stage/apply/rollback keep
  the existing update policy and running-app guards. RC reinstall is represented as unavailable
  until a dedicated verified catalog reinstall API exists; rollback stays scoped to the immutable
  installed bundle and does not bypass migration, security, review, dependency, catalog-signature,
  signed-bundle, digest, or running-app gates.
- Subscription recovery uses the operator wrapper around the shared content-subscription service.
  It does not grant apps authority over other apps' subscriptions.
- Subscription status wording may include `queue_pressure`, `runtime_unavailable`, `backoff`, and
  `budget_exhausted`. These are diagnostic statuses only; budget exhaustion and queue pressure do
  not expose queue HTML, fetched content, source documents, or raw daemon exception text.
  `reset-backoff` and `reschedule-now` are metadata-only actions; `refresh` still consumes the
  PR-256 content-subscription and content-fetch budgets.
- App-data backup and restore uses the durable app-data backup layer. Backups are sensitive user
  data, restore plans are metadata-only, and destructive `replaceNamespace`, `replaceApp`, and
  export-before-delete steps require explicit operator confirmation. RC export-before-uninstall
  returns its backup payload only as the explicit sensitive action response and keeps it out of
  support bundles.
- App-service grant and bundle recovery delegates to the app-service coordinator. Expired grants
  remain non-authorizing until renewal succeeds, and provider descriptor drift remains fail-closed
  until operator renewal or revalidation succeeds.
- Trust Graph lifecycle actions, when exposed from the dashboard or Web Shell, update only local
  statement policy such as `active`, `deprecated`, or `revoked`. They are not global revocation,
  content removal, app blocking, routing policy, or legacy Web of Trust compatibility. RC export
  is metadata-only by default. Reset and audit-clear plans are blocked until tested store clear
  methods exist.
- Network-budget visibility exposes app id, operation, window, usage, limit, active leases, and
  next availability only. It does not reset budgets.
- Support-bundle export is read-only.

The dashboard should prefer "unavailable" or warning cards when optional services are missing. A
missing optional service should not prevent the rest of the dashboard from rendering.

Trust Graph dashboard text must stay explicit about scope. A Trust Graph panel may show local
anchors, imported public signed statement counts, lifecycle counts, score evidence bounds, and
redacted source metadata. It must not imply network crawling, global reputation, moderation,
blocking, routing decisions, or compatibility with old WebOfTrust, Freetalk, Sone, or Freemail
data and plugin APIs.

## Support Bundle Redaction

Support bundles are redacted but should still be reviewed by the operator before sharing. They are
designed for support triage and release evidence, not for publishing raw diagnostics.

The bundle must exclude or redact:

- form passwords, app process tokens, browser-session tokens, cookies, authorization headers, and
  other credentials;
- raw request bodies, raw fetched content, raw feed bodies, raw social message bodies, and raw Trust
  Graph documents;
- raw app-data backup payloads and raw app-data values;
- private insert URIs, private identity material, seeds, recovery phrases, private keys, and
  signatures;
- local absolute paths, catalog scratch paths, staged bundle paths, rollback paths, source paths,
  directory paths, command lines, and raw command bodies.

Safe support-bundle content includes route names, app ids, catalog ids, evidence ids, capability
names, status labels, booleans, counts, byte sizes, timestamps, warning codes, digests, and redacted
source displays.

PR-277 records this boundary under `app-platform.privacy-preserving-beta-diagnostics`. The Web
Shell shows redaction status, omitted-field count, and support-bundle digest before copy/download.

## Certification Boundary

Release certification remains the source of truth for promotion. The dashboard helps the operator
find and recover beta issues on a local node, while release certification records deterministic
source, docs, and fixture evidence. Certification for this surface is recorded under the
`operator-beta-ux-and-recovery` ecosystem matrix row and the `operator-beta.*` evidence ids above,
including `operator-beta.app-data-backup-restore`. The RC workflow is recorded separately under
the `operator-rc-recovery-and-support-workflow` ecosystem matrix row, the
`ecosystem.operator-rc-recovery` gate, and the `operator-rc.*` evidence ids. The app-data
portability layer also records `app-data.backup-restore-portability`; see
[app-data-backup-restore-portability.md](app-data-backup-restore-portability.md).

The dashboard does not introduce a public app store, full Web of Trust, global trust propagation,
global moderation or blocking, live-network requirement for normal PR evidence, generic
HTTP/HTTPS crawler, generic filesystem access, generic app database API, new sandbox provider, new
update policy, or any FNP/FCP/wire protocol change.
