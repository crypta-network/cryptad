# Operator RC Recovery and Support Workflow

The operator RC recovery workflow is a host/operator-only Web Shell surface for recovering a
local node's app platform state without asking the operator to know raw Platform API routes or read
daemon logs. It builds on the beta dashboard data, but adds typed recovery plans, explicit
confirmation, support-bundle preview metadata, Trust Graph Local RC recovery summaries, and
network-budget visibility.

The route family is intentionally excluded from the app-facing Platform API compatibility
contract. App principals must be denied before any dashboard, recovery plan, support bundle,
cross-app subscription inventory, grant inventory, app-data backup payload, Trust Graph operator
state, or network-budget snapshot is assembled.

## Routes

The RC surface uses these internal operator routes:

| Route | Behavior |
| --- | --- |
| `GET /api/v1/operator/rc-dashboard` | RC dashboard alias that includes the beta-dashboard snapshot, typed recovery action metadata, network-budget snapshots, and support-bundle preview route metadata. |
| `GET /api/v1/operator/beta-dashboard` | Compatibility route for the older beta dashboard. Web Shell loads the RC dashboard first and falls back to this route only when the RC route is unavailable. |
| `GET /api/v1/operator/recovery/actions` | Closed action-id catalog for the Web Shell recovery controls. It does not return arbitrary server-provided paths. |
| `POST /api/v1/operator/recovery/plan` | Builds a bounded `OperatorRecoveryPlan` for one known `OperatorRecoveryActionId` and returns an opaque one-time `planToken`. |
| `POST /api/v1/operator/recovery/execute` | Executes only a previously planned known action shape when the request echoes the matching `planToken`. Destructive actions also require `confirm=true` and the action-specific confirmation phrase. |
| `GET /api/v1/operator/network-budgets` | Safe app-network budget snapshots: app id, operation, window, usage, limit, active leases, and next availability. |
| `GET /api/v1/operator/support-bundle/preview` | Support-bundle wizard metadata: kind, included sections, omitted fields, redaction checks, and recent recovery context. |
| `GET /api/v1/operator/support-bundle` | Privacy-preserving support bundle. It includes safe recovery plan/result summaries, lifecycle counts, redaction metadata, and digest fields, not raw backup payloads, raw Trust Graph statements, raw app data, private insert URIs, tokens, identity material, local paths, or legacy plaintext diagnostics. |
| `POST /api/v1/operator/subscriptions/{appId}/{subscriptionId}/reset-backoff` | Metadata-only stuck-subscription recovery wrapper. It does not fetch content. |
| `POST /api/v1/operator/subscriptions/{appId}/{subscriptionId}/reschedule-now` | Metadata-only due-time recovery wrapper. It does not fetch content. |

The existing operator app-data backup/restore and subscription `refresh`, `pause`, and `resume`
routes remain available for compatibility. Mutating operator routes pass through the legacy local
form-password bridge when reached through legacy HTTP.

## Typed Plans

Every RC action uses an allowlisted `OperatorRecoveryActionId` and a typed target:

- catalog actions target `catalogId`;
- app actions target `appId`;
- subscription actions target `appId` plus `subscriptionId`;
- app-service grant recovery targets `grantId`;
- app-service bundle recovery targets `bundleId`;
- support and network-budget actions do not accept arbitrary paths or commands.

The server validates the action id, target fields, preconditions, current service availability,
destructive status, and confirmation before it mutates state. Requests cannot provide a method/path
pair to proxy arbitrary routes.

The plan token is scoped to the exact action id and typed target that produced it. If a client
changes the target, omits the token, or reuses a consumed token, execution fails before dispatch.
The token is an operator request credential for this local workflow and must not be copied into
support bundles, release evidence, audit events, or ordinary dashboard panels.

The default support bundle follows
[privacy-preserving-beta-diagnostics.md](privacy-preserving-beta-diagnostics.md). It remains local
until the operator explicitly copies or downloads the JSON, and Web Shell disables export when the
bundle reports redaction failure.
Public beta support reports should start with the digest and summary workflow in
[public-beta/support-and-feedback.md](public-beta/support-and-feedback.md), not raw bundle uploads.

`operator-rc.recovery-plan-execute` release evidence checks this plan-before-execute behavior,
unknown-action rejection, destructive confirmation, form-password coverage, and route-proxy
rejection.

## Recovery Actions

The RC action catalog includes:

| Evidence id | Action coverage |
| --- | --- |
| `operator-rc.dashboard` | RC dashboard shape, Web Shell RC-first load, beta compatibility fallback, and app-principal denial. |
| `operator-rc.catalog-repair` | `catalog.refresh`, `catalog.reverify`, and `catalog.repair-first-party-source`. These delegate to existing signed-catalog APIs and keep PR-248 channel policy, signed catalog verification, security advisory gates, and review gates intact. The repair action can add a known recommended source only through existing catalog APIs; it does not silently switch stable users to beta, nightly, or deprecated channels. |
| `operator-rc.app-reinstall-rollback` | `app.check-update`, `app.stage-update`, `app.apply-update`, `app.rollback`, `app.reinstall-from-catalog`, `app.stop`, and `app.start`. Rollback delegates to the existing app-update rollback service and shows running-app guards. Reinstall is represented as unavailable until a dedicated verified catalog reinstall API exists; the plan blocks instead of bypassing catalog, review, security, dependency, migration, signed-bundle, or digest gates. |
| `operator-rc.export-before-uninstall` | `app.export-before-uninstall` sequences app-data backup creation before uninstall, records the current daemon version in the backup manifest, then clears the same app-update, subscription, and app-service state as the normal app DELETE route while preserving durable app-data. If uninstall or post-uninstall cleanup fails after backup creation, the result is `partial` and still returns the generated backup payload as the explicit sensitive action response. The backup payload is excluded from support bundles, dashboards, audit events, and release evidence. |
| `operator-rc.subscription-recovery` | `subscription.refresh`, `subscription.pause`, `subscription.resume`, `subscription.reset-backoff`, `subscription.reschedule-now`, and `subscription.delete`. Reset and reschedule mutate only subscription metadata. Refresh still fetches content through the shared subscription service and consumes PR-256 network budgets. Queue-pressure skips do not consume fetch budget. |
| `operator-rc.app-service-grant-recovery` | `app-service.grant-revoke`, `app-service.bundle-renew`, `app-service.bundle-revalidate`, and `app-service.bundle-reject`. These use existing app-service coordinator APIs. Expired grants remain non-authorizing until renewal succeeds, and descriptor drift remains fail-closed until operator renewal or revalidation. |
| `operator-rc.trust-graph-recovery` | `trust-graph.export-summary`, `trust-graph.recompute-summary`, `trust-graph.reset-local-state`, and `trust-graph.clear-audit`. Export and recompute are metadata-only. Reset and clear-audit plans are blocked/unavailable because the current Trust Graph stores do not expose tested clear-all methods. |
| `operator-rc.network-budget-visibility` | `network-budget.view` exposes safe budget counters only. It does not add a broad budget reset action. |
| `operator-rc.support-bundle-wizard` | `support-bundle.preview` and `support-bundle.export` back the Web Shell wizard. Operators preview redaction metadata and included sections before copy or download. |
| `operator-rc.redaction` | RC responses, audits, support bundles, Web Shell ordinary panels, and release evidence stay path-free and payload-free. |

## Web Shell Workflow

Web Shell presents the surface as "Operator RC Recovery". It loads
`/api/v1/operator/rc-dashboard` first and falls back to `/api/v1/operator/beta-dashboard` with a
visible compatibility note. The recovery controls are grouped by catalog, app lifecycle,
subscriptions, app-service grants, Trust Graph Local RC, network budgets, and support bundle.

Operators must request a plan before executing an action. Destructive cards show a confirmation
checkbox and the server-supplied confirmation phrase. The client posts only action ids and typed
form parameters to fixed recovery endpoints; it does not submit arbitrary server-provided paths.

The Web Shell does not persist support bundles, app-data backups, Trust Graph exports, tokens, or
raw response bodies in browser storage. Ordinary panels render summaries, preconditions, warnings,
and step status, not raw JSON dumps.

## Support Bundles

Support bundles are `crypta-operator-support-bundle` documents with an explicit support bundle
version, redaction metadata, included sections, omitted fields, and recent recovery context. They
are designed for issue triage and release evidence. They still require operator review before
sharing.

Support bundles must exclude or redact:

- form passwords, app tokens, browser session tokens, cookies, authorization headers, and private
  keys;
- recovery `planToken` values;
- private insert URIs, private identity material, seed phrases, recovery phrases, and raw
  signatures;
- raw request bodies, raw fetched content, raw queue HTML, raw feed bodies, raw social-message
  bodies, raw app-service invocation request/response bodies, and raw Trust Graph statement
  bodies;
- raw app-data values and raw app-data backup payloads, including export-before-uninstall
  backups;
- local filesystem paths, catalog scratch paths, staging paths, rollback paths, source paths,
  command lines, and process environments.

Safe support content includes action ids, route names, app ids, catalog ids, bundle ids, grant ids,
evidence ids, status labels, timestamps, counts, byte sizes, limits, digests, warning codes, and
redacted source displays.

Security incident intake follows the production response runbook in
[production-security-response-runbook.md](production-security-response-runbook.md). Incident
artifacts may include advisory ids, app ids, versions, catalog key ids, reviewer key ids, receipt
fingerprints, digest summaries, and bounded operator guidance. They must not include raw catalog
payloads, raw fetched content, raw app data, raw support bundle payloads, private insert URIs,
private keys, bearer/session/app tokens, authorization headers, command lines containing secrets,
CI secret values, or absolute local paths. The `production-security.response-runbook` evidence and
`operator-rc.redaction` evidence prove these constraints for release certification.
The multi-node beta soak support-bundle drill records the same constraints after failed update,
subscription-pressure, and advisory scenarios; see
[multi-node-beta-soak-and-upgrade-drill.md](multi-node-beta-soak-and-upgrade-drill.md).

## First-party app support actions

First-party app UI recovery actions should point operators back to this workflow instead of
inventing app-specific diagnostic exports. The PR-275 readiness evidence
`first-party-app.beta-quality-pass` checks that each first-party app exposes a support/recovery
action, support metadata, and `redacted-summary-only` diagnostic copy.

Safe first-party app support metadata includes app id, app version, catalog channel, API target
stability, app-data schema version when declared, last operation status category, retry/backoff
category, support action id, and the redaction policy marker. It must not include raw fetched
content, raw messages, raw profile documents, raw trust signatures, vault private identity
material, app-service tokens, browser-session tokens, private insert URIs, raw app-data values, or
local paths.

## Trust Graph Scope

Trust Graph Local RC recovery is local operator-curated trust only. It is not global truth, not
moderation, not routing policy, not blocking policy, not node-to-node trust propagation, and not
legacy Web of Trust compatibility. Export summaries may contain scope metadata, anchor summaries,
statement counts, lifecycle counts, audit counts, and bounded subject summaries. They must not
contain raw statement JSON, raw signatures, private identity material, raw fetched content, or
local store paths.

Reset and audit-clear actions intentionally plan as unavailable until tested store APIs exist. Do
not treat a blocked reset plan as a failed recovery; it is the safe result for this RC.

## Non-Goals

The RC workflow does not add arbitrary shell commands, a generic route proxy, remote support
upload, support-ticket creation, automatic uninstall of vulnerable apps, automatic stop-update-
restart choreography, broad network-budget reset, global Web of Trust, moderation/blocking/routing
policy, Freetalk/Sone/Freemail compatibility, legacy plugin runtime restoration, FProxy browse
removal, content-filter removal, startup wizard removal, backup encryption redesign, app-data
migration redesign, network crawling, or FNP/FCP protocol changes.

## Certification

Release certification records the RC workflow under the
`operator-rc-recovery-and-support-workflow` matrix row and the `ecosystem.operator-rc-recovery`
gate. The deterministic `operator-rc.*` evidence ids listed above check host/operator-only route
enforcement, app-principal denial, closed action-id dispatch, plan-before-execute behavior,
destructive confirmation, recovery action coverage, Web Shell controls, support-bundle wizard
behavior, and redaction.

The older `operator-beta.*` evidence and `operator-beta-ux-and-recovery` row remain as
compatibility evidence for the beta route and dashboard fallback.

## Stable build lifecycle status

The operator dashboard and support bundle include the local `coreSupportLifecycle` projection.
It contains only the running build/status, support deadlines, nullable current and recommended
builds, bounded advisory/reason ids, replacement or recovery guidance, descriptor edition/digest,
verification time, and stale/unknown warnings. A recovery-only revocation of the current tip shows
no invented current or replacement build. It never includes the raw descriptor, update URI,
private insertion material, tokens, local paths, identity material, or raw advisory/support
content.

`recommendedBuild` is optional upgrade guidance. A fully supported superseded build remains
`supported-maintenance` and does not acquire a `requiredReplacementBuild`; that field is reserved
for authenticated policy-required guidance from `security-fixes-only`, `deprecated`,
`end-of-support`, or `revoked`. If a future-effective descriptor is staged locally, the dashboard
does not expose its changed guidance early. It preserves an already-effective predecessor
revocation and its bounded recovery path, or reports ordinary support state as unknown until the
descriptor activates.

Unknown and stale lifecycle state are not reported as supported. `end-of-support` and `revoked`
are critical operator states, but recovery remains non-destructive: the workflow does not shut down
the node, delete data, uninstall apps, disable FProxy browse, or claim an update completed merely
because a download was requested. Web Shell treats the lifecycle read as best-effort: a transient
failure renders lifecycle status as unknown without disabling a successful core-updater panel.
Installer and store actions are reauthorized against the daemon's current package selection and
effective lifecycle state when the process is launched, so a stale form cannot consume a
superseded or revoked target. See [Stable 1.0 support lifecycle and deprecation
governance](stable-1.0-support-lifecycle-and-deprecation-governance.md).
PR-277 adds `app-platform.privacy-preserving-beta-diagnostics` and the
`privacy-preserving-diagnostics-risk` row so release certification can block production beta when
support-bundle schema, preview/export, safe lifecycle summaries, or redaction fixtures regress.
PR-281 adds separate `public-beta.support-feedback-loop` evidence for issue-template routing,
known issues, release notes, and digest-first support guidance.
