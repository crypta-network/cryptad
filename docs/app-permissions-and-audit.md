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
| `content.insert` | local file/directory insert routes, together with `queue.write` |
| `peers.read` | `GET /api/v1/peers/**` |
| `peers.write` | peer add, settings, note, removal |
| `config.read` | `GET /api/v1/config` |
| `config.write` | config overrides and persist |
| `security.read` | `GET /api/v1/security-levels/**` |
| `security.write` | network and physical threat-level mutations |
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
| `vault.secrets.read` | read app-granted vault secret metadata and values |
| `vault.secrets.write` | create, update, rotate, or delete app-owned vault secrets |
| `vault.identities.read` | read app-granted identity metadata and public identity material |
| `vault.identities.create` | create app-owned identities |
| `vault.identities.use` | use an app-granted identity without exporting private identity material |
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
Identity-profile publishing should request `vault.identities.read` or `vault.identities.use` only
when an implemented app can use an operator-granted identity without exporting private material.

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
