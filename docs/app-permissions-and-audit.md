# App permissions and audit

This document describes how Cryptad authorizes app-originated Platform API requests and records
recent app decisions.

## Scope

The app permission boundary applies to local AppHost child processes that authenticate with their
current launch token and to app-owned static browser UIs that authenticate with browser app
sessions. It is separate from AppHost sandbox status. Permission checks do not add containers, WASM
isolation, seccomp, chroot, browser origin isolation, FCP changes, wire-protocol changes, or
persistent compliance-grade audit storage.

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

Installed static app UIs fetch `/apps/{appId}/.well-known/cryptad-bootstrap.json` after the normal
full-access check for app-owned UI routes. The bootstrap contains an opaque `browserSessionToken`
and a `browserSessionExpiresAt` timestamp. It does not contain `CRYPTAD_APP_TOKEN`, a raw process
launch token, local-admin `formPassword`, filesystem paths, signing keys, or trusted-key material.

Browser apps present the token to Platform API v1 with:

```text
X-Crypta-App-Session: <token>
```

The session is bound to one installed static app and its manifest permissions. Blank, unknown,
expired, uninstalled-app, non-static-app, or stale manifest sessions fail with
`401 invalid_app_browser_session`. The raw browser session token is not recorded in audit,
diagnostics, summaries, logs, errors, or `toString()` output.

## App principals

When a process token authenticates, the Platform API receives a token-free app principal:

- app id;
- manifest-declared permissions;
- authentication source `APP_TOKEN`.

When a browser session authenticates, the Platform API receives a token-free app browser principal:

- app id;
- manifest-declared permissions bound to the verified browser session;
- authentication source `APP_BROWSER_SESSION`.

Neither principal carries the raw credential. The permission list is immutable and sorted before the
router checks it.

## Capability checks

App principals are denied by default. A request must match the central route-to-capability matrix,
and the app principal must include every required capability. A valid app token or browser session
without the required capability receives `403 Forbidden`. An invalid or stale app token receives
`401 invalid_app_token`; an invalid or stale browser session receives
`401 invalid_app_browser_session`.

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
| `apps.manage` | app install, start, stop, update, uninstall |
| `catalogs.read` | catalog and catalog-app reads |
| `catalogs.manage` | catalog add/remove/refresh and catalog app install/update |

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

Installed app summaries and runtime status also include quota status for AppHost-managed data,
cache, and process-log resources. Those quota fields are operator visibility and lifecycle
enforcement data; they do not grant app principals any additional Platform API capability and they
must remain free of launch tokens, browser session tokens, command lines, and local filesystem
paths.
