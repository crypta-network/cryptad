# App permissions and audit

This document describes how Cryptad authorizes app-originated Platform API requests and records
recent app decisions.

## Scope

The app permission boundary applies to local AppHost child processes that authenticate with their
current launch token and to app-owned static browser UIs that authenticate with browser app
sessions. It is separate from AppHost sandbox status. Permission checks do not add containers, WASM
isolation, seccomp, chroot, FCP changes, wire-protocol changes, or persistent compliance-grade
audit storage.

Host/operator Web Shell requests keep the existing local-admin model. They do not need app
permissions, and they are not recorded in the app audit log.

## Process token authentication

Every AppHost launch receives a fresh opaque `CRYPTAD_APP_TOKEN` in the child process environment.
The token is valid only while that specific app run is currently tracked as live. Blank, unknown,
stopped, or stale tokens do not authenticate. Restarting an app creates a new token; the old token
stops working.

An app process can present the token to Platform API v1 with either header:

```text
X-Crypta-App-Token: <token>
Authorization: Bearer <token>
```

`X-Crypta-App-Token` is the explicit app-token header: blank, unknown, stopped, or stale values
fail authentication with `401 invalid_app_token`. `Authorization: Bearer` is opportunistic for
clients that already use Bearer token plumbing. If the Bearer value matches a live app token, the
request becomes an app principal; otherwise it remains a normal host/operator request so unrelated
Bearer credentials from proxies or shared client configuration do not break existing management
flows.

Tokens are not read from query parameters. Static app UI bootstrap JSON, Web Shell bootstrap JSON,
app summaries, runtime status, process-log responses, audit entries, diagnostic strings, and
`toString()` output must not expose raw launch tokens.

## Browser session authentication

Installed static app UIs prefer a per-app loopback browser origin and fetch
`/.well-known/cryptad-bootstrap.json` from that origin. The legacy
`/apps/{appId}/.well-known/cryptad-bootstrap.json` route remains as an explicit same-origin
fallback. The bootstrap contains an opaque `browserSessionToken`, `browserSessionExpiresAt`, UI
origin metadata, and the Platform API root the app should call. It does not contain
`CRYPTAD_APP_TOKEN`, a raw process launch token, local-admin `formPassword`, filesystem paths,
signing keys, or trusted-key material.

On isolated origins, bootstrap `GET` must also include the short-lived launch proof minted by the
admin/Web Shell compatibility launch route:

```text
X-Crypta-App-Bootstrap-Nonce: <short-lived-launch-proof>
```

App summaries may publish public `uiUrl` and `uiOrigin` metadata, but they do not publish this
proof. A caller that only knows another app's loopback port cannot mint that app's browser-session
token.

Browser apps present the token to Platform API v1 with:

```text
X-Crypta-App-Session: <token>
```

The session is bound to one installed static app, its manifest permissions, the expected browser
origin, and the origin mode. Blank, unknown, expired, uninstalled-app, non-static-app, or stale
manifest sessions fail with `401 invalid_app_browser_session`. Isolated-loopback sessions also
require an `Origin` header matching the session origin and an active registered app UI origin for
that app. A mismatch fails with `403 origin_mismatch`. The raw browser session token is not
recorded in audit, diagnostics, summaries, logs, errors, or `toString()` output.

The Platform API accepts cross-origin app-browser requests only from currently registered app UI
origins. CORS responses never use wildcard origins, never allow cookies or local-admin
credentials, and do not allow `X-Crypta-App-Token` through app-browser preflight. Requests from a
registered app origin without `X-Crypta-App-Session` fail as app-browser authentication failures
and do not fall back to host/operator Web Shell authentication.

The `crypta-app dev` beta mock server intentionally mirrors the browser-session header shape for
local template development: bootstrap returns a mock browser session, and mock `/api/v1/...` routes
return `401 invalid_app_browser_session` when the `X-Crypta-App-Session` value is missing or wrong.
That local session is not a real AppHost process token and does not install or authorize an app on
a live node. See [developer-beta-toolkit.md](developer-beta-toolkit.md).

## App principals

When a process token authenticates, the Platform API receives a token-free app principal:

- app id;
- manifest-declared permissions;
- authentication source `APP_TOKEN`.

When a browser session authenticates, the Platform API receives a token-free app browser principal:

- app id;
- manifest-declared permissions bound to the verified browser session;
- expected browser origin and origin mode;
- authentication source `APP_BROWSER_SESSION`.

Neither principal carries the raw credential. The permission list is immutable and sorted before the
router checks it.

## Capability checks

App principals are denied by default. A request must match the endpoint descriptors published in
the Platform API compatibility contract, and the app principal must include every required
capability. The runtime authorization path reads the same descriptors that
`GET /api/v1/platform/contract` publishes, so app-facing contract metadata and the permission
matrix cannot drift as separate lists. A valid app token or browser session without the required
capability receives `403 Forbidden`. An invalid or stale app token receives
`401 invalid_app_token`; an invalid or stale browser session receives `401 invalid_app_browser_session`.

The current capabilities are intentionally conservative:

| Capability | Example covered routes |
| --- | --- |
| `node.read` | `GET /api/v1/node/**` |
| `connectivity.read` | `GET /api/v1/connectivity` |
| `queue.read` | `GET /api/v1/queue/**` |
| `queue.write` | queue download creation, request mutation, cleanup |
| `content.fetch` | `POST /api/v1/content/fetch` bounded app content fetches, without insert, queue mutation, or local path authority |
| `content.subscribe` | `/api/v1/content/subscriptions` app-owned USK subscription metadata and controls; create/refresh also require `content.fetch` |
| `content.insert` | local file/directory insert routes, together with `queue.write` |
| `content.insert.app-document` | app-generated document inserts without local source-path authority, together with `queue.write` |
| `peers.read` | `GET /api/v1/peers/**` |
| `peers.write` | peer add, settings, note, removal |
| `config.read` | `GET /api/v1/config` |
| `config.write` | config overrides and persist |
| `security.read` | `GET /api/v1/security-levels/**` |
| `security.write` | network and physical threat-level mutations |
| `trust.read` | read local Trust Graph Preview status, anchors, subjects, statement summaries, scores, and bounded evidence |
| `trust.write` | import bounded trust statements and add/remove local trust anchors |
| `updates.read` | `GET /api/v1/updates/**` |
| `updates.write` | core update download trigger |
| `wizard.read` | `GET /api/v1/wizard/**` |
| `wizard.write` | first-time wizard apply |
| `alerts.read` | `GET /api/v1/alerts` |
| `alerts.write` | alert dismiss |
| `diagnostics.read` | `GET /api/v1/diagnostics` |
| `apps.read` | app inventory, runtime, logs, permissions, audit reads |
| `apps.manage` | app install, start, stop, local staged-directory update, rollback, uninstall |
| `catalogs.read` | catalog and catalog-app reads |
| `catalogs.manage` | catalog add/remove/refresh, catalog app install/update, and catalog-backed app update check/stage/apply |
| `platform.contract.read` | `GET /api/v1/platform/contract` contract snapshot reads |
| `app.data.read` | read the caller app's durable app-data status, namespace metadata, records, and bounded exports |
| `app.data.write` | create, replace, delete, import, clear, and record schema metadata for the caller app's durable app data |
| `vault.secrets.read` | read app-granted vault secret metadata and values |
| `vault.secrets.write` | create, update, rotate, or delete app-owned vault secrets |
| `vault.identities.read` | read app-granted identity metadata and public identity material |
| `vault.identities.create` | create app-owned identities, including `POST /api/v1/app-vault/identities` for browser-safe Profile Publisher setup |
| `vault.identities.use` | use an app-granted identity without exporting private identity material; the profile-document route combines this with `vault.identities.read` |
| `vault.identities.manage` | manage app-owned identities and app grants for shared identities |

Capability descriptors, endpoint descriptors, and stability levels are described in
[platform-api-contract.md](platform-api-contract.md). `app.permissions` remains the authoritative
grant request; manifest `api.*` compatibility metadata is advisory verifier and review input.

The app secret and identity vault has additional lifecycle and redaction rules because it handles
local secret values and identity private material. See
[app-secret-and-identity-vault.md](app-secret-and-identity-vault.md) for app-owned versus shared
identities, process/browser restrictions, local at-rest limitations, update/rollback/uninstall
grant behavior, and future content/social/mail extension points.

Site Publisher, the first content reference app, requests only the capabilities needed for its
implemented publishing flow. A basic local-site publishing flow needs `content.insert` to submit
content, `queue.write` to create insert requests, and `queue.read` to display queue progress.

Profile Publisher is the first identity-profile reference app. Its implemented flow can request
`vault.identities.read`, `vault.identities.create`, and `vault.identities.use` alongside
`content.insert.app-document`, `queue.write`, `queue.read`, `app.data.read`, and
`app.data.write`. It uses the app-vault profile-document route for identity-bound profile signing,
the app-data API for bounded drafts and publish summaries, and
`POST /api/v1/queue/inserts/app-document` for app-generated document insertion without local
source-path authority. It should not request `content.insert`, `vault.identities.manage`, or
`vault.secrets.*` unless a later feature needs those broader capabilities.

Feed Reader is the first content-subscription reference app. Its read flow uses `content.fetch`
for on-demand `POST /api/v1/content/fetch` rendering and `content.subscribe` for durable USK
subscription metadata under `/api/v1/content/subscriptions`. Create and refresh actions need both
capabilities because a subscription is a durable background fetch grant. The scheduler stores only
path-free metadata such as status, due times, sanitized resolved URI, last seen edition, digest,
byte length, failures, and update count; it does not persist raw fetched content and does not
parse or expose queue HTML. Feed Reader should not request `content.insert` or local source-path
authority. Its publishing flow can combine `content.insert.app-document`, `queue.write`, and
`queue.read` to publish generated feed documents and display queue progress. It uses
`app.data.read` and `app.data.write` for bounded app-owned source lists, selected subscription ids,
read-state metadata, and safe draft fields. Audit and release
evidence for this route must keep raw feed bodies, raw fetched content, raw request bodies,
private insert URIs, app process tokens, browser-session tokens, form passwords, queue HTML, and
local paths out of persisted output.

Trust Graph Preview is the local trust-service reference app. Score/status reads require
`trust.read`; imports and local anchor changes require `trust.write`; bounded trust-statement
signing also requires `vault.identities.read` and `vault.identities.use`. URI import additionally
requires `content.fetch`; trust-statement subscription management uses `content.subscribe` and the
same `content.fetch` grant for create/refresh that content subscriptions require. Publication uses
`content.insert.app-document` and `queue.write`. `trust.write` covers import and anchor management
only; it does not publish anchors automatically, export private identity material, grant moderation
authority, or apply scores to content blocking.

Trust Graph Preview also has a bounded redacted trust graph audit route:

```text
GET /api/v1/trust-graph/audit
```

It requires `trust.read` and returns local mutation/exchange summaries such as anchor changes,
imports, URI imports, local publication imports, subscription actions when available, and rejected
imports. Trust graph audit entries may include app id, event type, document fingerprint, payload
hash, issuer fingerprint, subject kind, redacted/hash URI summaries, source type, verification
status, and stable status codes. They must not include raw trust documents, raw fetched content,
raw request bodies, signature values, private insert URIs, private keys, app process tokens,
browser-session tokens, form passwords, daemon exception text, or absolute local paths.

The Trust Graph Preview app also uses `app.data.read` and `app.data.write` for UI-local draft
values, selected filters, and redacted import summaries. Those permissions are separate from the
platform trust graph backend, which persists public anchors and imported public statements as local
platform service state.

## Audit trail

The Platform API records app-originated allowed and denied authorization decisions in a bounded
process-local audit log. The default bound is the most recent 512 events per router instance. When
the log is full, the oldest entries are dropped.

Each event records:

- timestamp;
- app id;
- request method;
- endpoint family;
- route/action label;
- required capability names;
- authentication source (`APP_TOKEN` or `APP_BROWSER_SESSION`);
- decision;
- HTTP status;
- short reason code.

Audit entries do not record raw launch tokens, browser session tokens, full query strings, request
bodies, form passwords, local filesystem paths, or large payloads. The log is useful for operator
visibility and debugging; it is not durable evidence storage.

## Operator surfaces

The Apps API exposes declared permissions and recent audit data:

```text
GET /api/v1/apps/{appId}/permissions
GET /api/v1/apps/{appId}/audit
```

Installed app summaries also include a small audit object and a retained denied-count snapshot.
The Web Shell displays declared permissions, recent app-originated audit events, and denied-call
counts on installed app cards. Audit entries include the auth source so operators can distinguish
AppHost process-token calls from browser-session calls.

Vault metadata is not part of the app-readable summary contract. App principals only receive vault
availability in installed-app summaries; secret names, identity grant details, and vault audit
targets remain behind the vault-specific capabilities and host/operator views.

Installed app summaries and runtime status also include quota status for AppHost-managed data,
cache, and process-log resources. Those quota fields are operator visibility and lifecycle
enforcement data; they do not grant app principals any additional Platform API capability and they
must remain free of launch tokens, browser session tokens, command lines, and local filesystem
paths.
