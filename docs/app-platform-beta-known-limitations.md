# App platform beta known limitations

This page records conservative limits and safety boundaries for the Crypta app ecosystem beta.

## General beta limits

- This is an app ecosystem beta, not a public production app store.
- First-party beta catalog support does not imply automatic app installation.
- First-party beta readiness means the staged first-party app has empty/error/retry/recovery UI,
  permission rationale, support metadata, app-data status, accessibility markers, and
  `redacted-summary-only` diagnostics. It does not make Local RC apps globally authoritative or
  turn stateless apps into durable app-data apps.
- Recommended catalog metadata is an onboarding hint, not ranking, endorsement, or trust by itself.
- Developer tooling supports offline and dry-run publication planning. Explicit live USK
  publication depends on existing content and queue mechanisms plus the operator's localhost node
  and secure private insert URI configuration.
- `crypta-app dev`, `crypta-app test`, release self-tests, and docs certification do not depend on
  the public Crypta network.
- The beta does not require Docker, Node.js, npm, external network access, signing secrets, or
  public Crypta network access for its offline tests.
- PR-246 live-network beta certification is an explicit release-manager step. It is not part of
  normal PR or nightly evidence, and it should use disposable fixture catalog keys unless the
  release manager is intentionally publishing the candidate first-party beta catalog.
- Required live-network beta certification fails unless the configured expected catalog signing
  key id matches the public `signatureKeyId` observed from the node's verified catalog summary.
- Live-network beta app-facing steps authenticate with per-app browser sessions minted from the
  configured static app bootstraps. A missing or stale bootstrap session fails required mode rather
  than falling back to host/operator authority.
- The beta does not modify FNP, FCP, wire protocol, or Hyphanet/Freenet network compatibility
  behavior.
- FProxy browse remains retained.
- The trust/social content format profiles are app ecosystem document profiles for first-party
  apps and future third-party apps. They are not Platform API 1.0 stable baseline route guarantees,
  not legacy plugin compatibility, and not a generic content signing or crawling framework.

These content profiles are Crypta app ecosystem profiles. They are not compatibility promises for
legacy WoT, Freetalk, Sone, Freemail, or any old plugin ABI/protocol.

## Security boundaries

- App UI origin isolation is based on app-owned origins and browser sessions. It is not permission
  to bypass server-side Platform API capability checks, and it is not an AppHost child-process
  sandbox.
- Static app UI CSP is a browser defense for local bundled assets. It does not replace process
  sandboxing, signed bundle verification, AppHost launch-token checks, or Platform API
  authorization.
- Browser app sessions are local browser credentials for static UI calls. Do not treat them as
  long-lived secrets, do not persist them in app local storage, and do not confuse them with
  AppHost process tokens.
- AppHost process tokens must never be exposed through bootstrap JSON, Web Shell state, app UI,
  release evidence, logs, diagnostics, or bug reports.
- AppVault protects app-owned identity and secret material through bounded routes. It does not
  expose private keys, seed material, or raw signing keys to apps.
- `vault.identities.create` creates app-owned identity material. `vault.identities.use` permits
  bounded signing operations such as profile-document or trust-statement signing without exporting
  private material.
- `content.fetch` is bounded Crypta-content fetch. It is not arbitrary HTTP, LAN, local file, or
  loopback fetch.
- `content.subscribe` is bounded durable USK subscription metadata for app-owned feeds. It is not
  a generic crawler, not arbitrary HTTP/HTTPS fetch support, and not a generic app data store.
  Subscription evidence and summaries must not include raw fetched content, queue HTML, private
  keys, browser-session tokens, app process tokens, form passwords, private insert URIs, or
  absolute paths.
- Platform API v18 applies shared app/global network budgets to foreground content fetch,
  subscription refresh/polling, and Trust Graph import-by-URI. Budget exhaustion or queue pressure
  should surface as bounded status/retry metadata, not raw daemon exceptions.
- `app.data.read` and `app.data.write` expose bounded app-owned durable state. They are not a
  filesystem API, database engine, browser storage replacement for secrets, or AppVault bypass.
  Apps can read and write only their own records, and evidence must summarize counts, bytes,
  schema versions, hashes, and booleans instead of raw values.
- App-generated document insert stages bytes under Cryptad control. It must not expose absolute
  staging paths, local source paths, raw request bodies, raw profile/feed/trust documents, or
  private insert URIs.
- Trust Graph Local RC has durable local backend storage for anchors and imported public
  statements, but it remains local RC scope. It is not full Web of Trust, old plugin
  compatibility, global moderation, routing policy, peer selection, or a background crawler.
- The [legacy plugin freeze policy](legacy-plugin-freeze-policy.md) and
  [legacy plugin migration guide](legacy-plugin-migration-guide.md) document the app-platform path,
  but they do not restore old plugin ABI compatibility, old FCP plugin command compatibility, or
  old plugin API shims.
- Social Inbox RC is a threaded reference app outside daemon core and legacy plugin APIs. Its
  `crypta.social.message.v1` route is bounded social-message signing only; local threads,
  channel filters, search, and read state operate over bounded summaries. It is not a generic
  browser signing API, full WoT, Freetalk, Sone, Freemail, encrypted mail transport, moderation,
  crawler, daemon-core message storage, or a network protocol change.
- Review governance uses local trust configuration plus a local tamper-evident transparency log.
  It is not a global public transparency log.
- Sandbox provider support depends on platform and provider availability. Linux bubblewrap support
  can provide an enforced provider on supported systems, but the docs and evidence must not claim
  hard isolation beyond the implemented provider status, tests, quotas, and runtime checks. The
  current bubblewrap provider enforces filesystem containment for the installed bundle and
  AppHost-managed mutable directories; it does not enforce CPU, memory, or network isolation.

## Update and rollback limits

- Background scheduler behavior is policy-driven.
- Manual update policy detects candidates but does not stage or apply automatically.
- `stage` may stage eligible verified candidates according to policy.
- `apply_when_stopped` may apply only when the app is already stopped and catalog, bundle, review,
  compatibility, permission-delta, and health gates pass.
- Permission additions should block unattended apply unless the current implementation explicitly
  supports a stricter approved path.
- Rollback restores the immutable installed bundle. It does not promise to roll back app data,
  cache, run state, external network state, or every user-visible app state.
- Schema-changing Platform API app-data updates are the narrow exception: the update lifecycle
  creates a short-lived internal app-scoped snapshot before migration apply and restores it when a
  migration or post-migration check fails. That snapshot is not a user-facing backup/restore
  feature and does not cover AppVault records or app-private files outside the durable app-data
  store.
- Health checks and rollback records are safety mechanisms, not a guarantee that every update
  failure can be undone.

## Review and catalog limits

- Signed catalog, signed bundle, artifact digest, review receipt, and reviewer trust are separate
  layers.
- A valid catalog signature authenticates catalog bytes and publisher metadata only.
- A valid bundle signature authenticates the extracted app bundle payload only.
- A review receipt is independent reviewer evidence. It is trusted only when it verifies against
  local trusted reviewer-key configuration and policy.
- A catalog listing a reviewer key must not automatically establish local reviewer trust unless the
  local implementation explicitly configures that key as trusted.
- Publisher-advisory `review.status` and `review.note` fields do not replace trusted review
  receipts.
- Unknown, revoked, expired, retired, missing, or mismatched reviewer states must be displayed
  honestly and must not be rendered as trusted positive review.
- `crypta:` catalog transport is not a trust boundary. Catalog bytes, catalog signatures, app
  artifacts, artifact digests, bundle signatures, review receipts, reviewer key lifecycle state,
  and permission/API compatibility still need their own checks.
- Live-network beta certification proves only that signed catalog sidecars can be validated,
  queued through a localhost node, and optionally fetched back from the configured public source.
  It does not prove global propagation, public reputation, app safety beyond the signed
  catalog/bundle/review gates, or deletion of published bytes.
- Live synthetic content may remain retrievable and may not be deletable once inserted. Use fixture
  catalog sources such as `crypta:USK@<catalog-key>/cryptad-app-catalog.properties`, immutable
  artifact placeholders such as `crypta:CHK@<artifact-key>`, and a private insert URI supplied
  only through environment-variable or protected-file indirection.
- Lifecycle cleanup deletes only apps installed by that certification run. Prepared nodes with
  existing first-party apps should use disposable certification app ids for lifecycle rehearsals.

## Data handling and redaction

Do not paste or commit:

- Private signing keys or reviewer private keys.
- Seed phrases, recovery phrases, or private identity material.
- Private insert URIs.
- Browser session tokens, app process tokens, form passwords, authorization headers, cookies, or
  request bodies.
- Raw feed bodies, raw social message bodies, raw fetched social documents, raw trust documents
  from real users, raw profile documents, raw signatures, or raw receipt signatures.
- Local absolute paths, catalog scratch paths, staging paths, rollback backup paths, or host private
  configuration paths unless they are already redacted.
- Real keys, production secrets, or user content in fixture certification examples, issue reports,
  or release evidence.

Safe placeholders include:

```text
<redacted>
<token-redacted>
/abs/path/outside/repo/dev-private.der
crypta:CHK@<artifact-key>
crypta:USK@<catalog-key>/cryptad-app-catalog.properties
```

Release certification and issue templates should record statuses, relative repo paths, digests,
app ids, capability names, evidence ids, public fixture URIs, and redacted summaries instead of
raw payloads.

## Operator RC recovery limitations

The [Operator RC recovery workflow](operator-rc-recovery-and-support-workflow.md) and
[Operator beta dashboard](operator-beta-dashboard.md) are local recovery and support surfaces, not
app-facing Platform API contracts. Apps cannot use the operator routes, and compatibility checks
must continue to use the app-facing contract snapshot. Recovery actions delegate to existing
catalog, app-update, app lifecycle, app-data, app-service, Trust Graph, and content-subscription
services; they do not bypass catalog channel policy, signed catalog verification, signed bundle
verification, digest verification, review policy, security advisory gates, migration gates,
dependency/grant gates, running-app update guards, app ownership boundaries, network-budget policy,
or form-password checks.

RC recovery is intentionally typed and incomplete where no safe primitive exists:

- `app.reinstall-from-catalog` plans as unavailable until a dedicated verified catalog reinstall
  API exists.
- `trust-graph.reset-local-state` and `trust-graph.clear-audit` plan as unavailable until the
  Trust Graph stores expose tested clear-all methods.
- Network-budget visibility is read-only. There is no broad operator budget reset action.
- The workflow does not do automatic stop-update-restart choreography. Operators must review plans
  and confirmation phrases before destructive execution.

Support bundles are redacted release/support summaries. They still need operator review before
sharing, and they must not include raw request bodies, raw fetched content, private insert URIs,
tokens, local paths, app-private values, raw app-data backup payloads, app-service invocation
request/response bodies, or Trust Graph document bodies/signatures.

## Non-goals

The beta does not introduce a live public app store, a normal PR/nightly live-network dependency,
global transparency log, full Web of Trust, old plugin ABI compatibility, old FCP plugin command
compatibility, generic crawling, arbitrary HTTP/HTTPS fetching, a generic filesystem or database
API for apps, Freetalk/Sone/Freemail compatibility, encrypted mail delivery, daemon-core social or
mail protocols, legacy plugin runtime restoration, FProxy browse removal, content-filter removal,
startup wizard/security recovery removal, new sandbox provider, new update scheduler policy, or
any FNP/FCP/wire protocol change.
