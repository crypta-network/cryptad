# App-owned static UI

This document describes how installed AppHost bundles declare and serve app-owned browser UI.
Static app UIs prefer isolated per-app loopback origins, while the legacy `/apps/{appId}/` route
remains as a compatibility and diagnostics fallback.

## Scope

App-owned static UI is a local browser surface for installed apps. Static app pages receive a
browser-scoped app session for Platform API calls, and the server authorizes those calls with the
installed app's manifest permissions. The preferred Phase 6 path serves each static app from a
distinct loopback-only browser origin such as `http://127.0.0.1:<appUiPort>/`. This does not add
process sandboxing, container execution, network isolation, or remote protocol changes. The
[`CryptaPlatform` JavaScript SDK](platform-sdk-js.md) is a browser convenience wrapper around
bootstrap and Platform API calls; permission enforcement remains server-side.

The route serves immutable files from the installed app bundle only. It does not serve app data,
cache, run directories, catalog scratch directories, or caller staging paths.

Static apps should vendor the canonical Crypta UI design-system assets under
`static/crypta-ui/` and load them before app-specific CSS. The design system is a small local
asset set, not a hosted framework. `crypta-app ui lint` can check the staged bundle offline for
design-system adoption, CSP-compatible local resources, SDK/bootstrap ordering, permission
disclosure, and basic accessibility before the app is signed or cataloged. See
[app-ui-design-system.md](app-ui-design-system.md) for the asset list, `cr-*` classes, and warning
versus failure policy.

## Manifest fields

App manifests can declare a UI mode:

```properties
app.ui.mode=none|shell-panel|static
app.ui.entry=...
```

The manifest schema remains version `1`. The mode is optional for compatibility:

| Manifest values | Normalized mode | Behavior |
| --- | --- | --- |
| No `app.ui.entry` | `none` | The app has no browser UI. |
| No `app.ui.mode`, absolute `app.ui.entry` | `shell-panel` | Existing shell deep links keep working. |
| No `app.ui.mode`, relative `app.ui.entry` | `static` | The entry is treated as a bundle-relative static UI file. |
| `app.ui.mode=none` | `none` | `app.ui.entry` must be absent or blank. |
| `app.ui.mode=shell-panel` | `shell-panel` | `app.ui.entry` must be an absolute same-origin local path such as `/app/node/#queue`. |
| `app.ui.mode=static` | `static` | `app.ui.entry` must be a normalized relative bundle path such as `static/index.html`. |

External URLs are not supported. Static entries reject absolute paths, Windows drive-prefix paths,
empty segments, `.`, `..`, backslashes after normalization, reserved distribution sidecars, ISO
control characters, and path segments with colons.

## Isolated app origins

For static apps, Cryptad allocates a distinct loopback listener per installed app when isolation is
available. The Web Shell and Platform API remain on the local admin origin, for example:

```text
http://127.0.0.1:<adminPort>/app/node/
http://127.0.0.1:<adminPort>/api/v1/
```

Each static app UI opens on its own local origin:

```text
http://127.0.0.1:<appUiPort>/
http://127.0.0.1:<anotherAppUiPort>/
```

App UI listeners bind only to loopback addresses and do not listen on wildcard or LAN-visible
interfaces. Distinct ports create distinct browser origins; apps do not share one app-UI origin.

An isolated app origin serves:

```text
GET /                         -> app entry or canonical entry-directory redirect
GET /static/...               -> installed bundle static assets
GET /.well-known/cryptad-bootstrap.json -> dynamic bootstrap JSON
HEAD variants for those paths
```

The same installed-bundle confinement, traversal rejection, content-type mapping, no-store dynamic
bootstrap policy, and static UI security headers apply on isolated origins.
The bootstrap `GET` additionally requires a short-lived launch proof minted by the admin/Web Shell
route and echoed by the SDK as `X-Crypta-App-Bootstrap-Nonce`. This keeps public app-origin route
metadata from being enough for another local caller to mint an app browser-session token. Static
assets remain readable from the app origin without that proof so the browser can load the page.

## Compatibility route behavior

The legacy HTTP admin adapter still mounts static app UI compatibility paths such as:

```text
/apps/{appId}/
/apps/{appId}/static/...
/apps/{appId}/.well-known/cryptad-bootstrap.json
```

The compatibility route stays same-origin by default, even when an isolated origin is active.
`GET /apps/{appId}` still redirects to `/apps/{appId}/` first, and the fallback root then serves a
root entry directly or redirects to the static entry directory. Web Shell opens the isolated path
only after the browser can read a token-free origin probe from the per-app loopback listener; that
explicit launch request receives the short-lived bootstrap nonce in the isolated URL fragment.
Static asset paths under `/apps/{appId}/static/...` remain available as an explicit same-origin
fallback for compatibility and diagnostics.

When isolation is unavailable or an operator opens the explicit fallback path, a static entry at
the bundle root can be served directly from `/apps/{appId}/`. For nested entries such as
`static/index.html`, the fallback root redirects to the entry directory, such as
`/apps/{appId}/static/`. That preserves the browser base URL, so a page can use normal references
such as `./app.js` and `../shared.js`. Explicit paths such as `/apps/{appId}/static/app.js` still
resolve as bundle-relative paths. All served targets must resolve to regular files inside the
immutable installed bundle root.

To preserve the browser base URL for nested entries, Platform API summaries publish `uiUrl` at the
entry directory when needed. With an isolated binding, `uiUrl` is an absolute app-origin URL such
as `http://127.0.0.1:<appUiPort>/static/`. Without isolation, fallback summaries use the legacy
same-origin path such as `/apps/{appId}/static/`.
The isolated `uiUrl` is public route metadata, not a bearer credential and not the complete launch
handshake. Web Shell opens isolated apps through the same-origin compatibility launch path so the
admin adapter can mint a fresh bootstrap nonce before the browser reaches the isolated origin.

Only installed apps with `uiMode=static` are served. Missing app ids, non-static apps, missing
files, and directories return not found responses. Malformed paths, traversal attempts, encoded
traversal, encoded path separators, symlink escapes, and reparse-point escapes are rejected before
files are read.

Content types are deterministic and do not depend on the host operating system. The route maps
HTML, CSS, JavaScript (`.js` and `.mjs`), JSON, WebAssembly, SVG, PNG, JPEG, GIF, WebP, and ICO to
browser-appropriate MIME types. Unknown extensions fall back to `application/octet-stream` and are
paired with `X-Content-Type-Options: nosniff`.

Static UI responses include conservative headers:

```text
Content-Security-Policy: default-src 'self'; script-src 'self'; base-uri 'none'; object-src 'none'; form-action 'self'; frame-ancestors 'self'
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
```

If JavaScript is disabled for the legacy admin UI, Cryptad changes the app UI CSP to
`script-src 'none'` for the same response.

Isolated app-origin responses keep scripts local to the app origin and add `connect-src` for the
admin Platform API root supplied in bootstrap. They do not allow remote scripts, objects, embeds,
or `base` rewriting. Frame ancestry is limited to the Web Shell/admin origin when embedding is
enabled by the host response.

The same CSP model means static app bundles should avoid remote stylesheets, CDN scripts, inline
scripts, inline event handlers, `javascript:` URLs, dynamic code evaluation, and browser storage
for app/session credential material. The browser SDK keeps app browser-session credentials in
memory; app-owned UI files must not reference AppHost launch-token names or the local admin form
password.

App-owned UI uses stable URLs across reinstall and update operations. Responses are therefore sent
with non-public no-cache headers instead of the legacy admin adapter's long-lived static cache
policy.
The stable URL is a browser route guarantee only; update rollback is scoped to the immutable
installed bundle and does not roll back app data, cache, or browser-visible app state. See
[app-update-lifecycle.md](app-update-lifecycle.md).

Static browser UI does not receive `CRYPTAD_APP_TOKEN` and cannot authenticate as the app process.
Instead, app-owned bootstrap issues a browser session token for `X-Crypta-App-Session`. Platform
API requests with that header become app browser principals and use the same central capability
matrix as process app tokens.

Vault secret values remain process-only by default. Static browser UI may list granted identity
metadata and submit token-free grant requests through the browser-safe vault routes, but it should
not read raw app secrets, private identity material, AppHost launch tokens, or local vault files.
The browser SDK exposes only metadata/request helpers for `crypta.vault.identities.*` and
`crypta.vault.grants.*`; process apps use the Platform API directly with their launch token for
secret read/write and identity-use operations. See
[app-secret-and-identity-vault.md](app-secret-and-identity-vault.md).

## First-party app bootstrap

On an isolated app origin, static app UIs fetch bootstrap from their current origin:

```text
GET /.well-known/cryptad-bootstrap.json
X-Crypta-App-Bootstrap-Nonce: <short-lived-launch-proof>
```

The same-origin compatibility route can also return a fallback bootstrap for explicit fallback UI
loading:

```text
GET /apps/{appId}/.well-known/cryptad-bootstrap.json
```

The host builds this JSON dynamically. The isolated app origin serves it without exposing local
admin form passwords; the same-origin compatibility route still applies the normal full-access
check used by legacy app UI assets. The path is reserved by the host; it is not read from the
installed bundle.

The current payload is deliberately small:

```json
{
  "appId": "queue-manager",
  "name": "Queue Manager",
  "uiRoot": "/apps/queue-manager/",
  "assetRoot": "/apps/queue-manager/static/",
  "platformApiRoot": "/api/v1/",
  "shellRoot": "/app/node/",
  "uiOrigin": null,
  "uiOriginMode": "same-origin-fallback",
  "uiOriginStatus": "fallback",
  "sameOriginFallbackUrl": "/apps/queue-manager/",
  "browserSessionToken": "<opaque-browser-session-token>",
  "browserSessionExpiresAt": "2026-04-28T12:00:00Z"
}
```

For isolated app origins, `uiRoot`, `assetRoot`, `platformApiRoot`, and `shellRoot` are absolute
local URLs. For example:

```json
{
  "appId": "queue-manager",
  "uiRoot": "http://127.0.0.1:12345/",
  "assetRoot": "http://127.0.0.1:12345/static/",
  "platformApiRoot": "http://127.0.0.1:8888/api/v1/",
  "shellRoot": "http://127.0.0.1:8888/app/node/",
  "uiOrigin": "http://127.0.0.1:12345",
  "uiOriginMode": "isolated-loopback",
  "uiOriginStatus": "active",
  "sameOriginFallbackUrl": "/apps/queue-manager/",
  "browserSessionToken": "<opaque-browser-session-token>",
  "browserSessionExpiresAt": "2026-04-28T12:00:00Z"
}
```

`browserSessionToken` is an opaque bearer value generated by the node for the installed static app.
It is bound to the app id, the installed manifest permissions, the expected browser origin, the
origin mode, the issue time, and an absolute expiry. The current in-memory implementation uses a
one-hour lifetime and rejects blank, unknown, expired, uninstalled-app, non-static-app, or stale
manifest sessions. Isolated-loopback sessions also reject missing-origin or mismatched-origin
Platform API calls.

Static app UIs send the token as:

```text
X-Crypta-App-Session: <opaque-browser-session-token>
```

The bootstrap does not expose `CRYPTAD_APP_TOKEN`, AppHost launch tokens, signing keys, trusted-key
material, installed-bundle filesystem paths, data/cache/run paths, catalog scratch paths, or the
legacy local-admin `formPassword`. The browser session token is not an AppHost process launch
token, and apps must not persist it in local storage or session storage. The
[Platform JavaScript SDK](platform-sdk-js.md) keeps it in memory and adds `X-Crypta-App-Session` to
Platform API calls.

## Platform API CORS

The Platform API remains on the local admin origin. Isolated app UIs call it cross-origin through
restricted CORS and `X-Crypta-App-Session`.

Only active registered app UI origins are allowed. Cryptad does not return
`Access-Control-Allow-Origin: *`, does not allow credentials or cookies for app UI origins, and
does not allow app process-token headers through CORS preflight. Allowed app-browser request
headers are limited to:

```text
X-Crypta-App-Session
Content-Type
Accept
```

Actual app-origin requests must carry `Origin` matching the verified browser session. A session for
one app cannot authenticate another app's origin. Requests from a registered app origin without
`X-Crypta-App-Session` fail with `401 invalid_app_browser_session` and do not fall back to
host/operator Web Shell authentication. Requests with a mismatched origin fail with
`403 origin_mismatch`.

Queue Manager and legacy Publisher are also the primary replacements for the legacy queue and
insert admin pages in the current retirement map. Site Publisher is the first content reference app
for new app-platform publishing flows. It shares content-insert capabilities with legacy Publisher,
but it is documented as a reference app rather than as the legacy insert-page compatibility
surface. The full map is maintained in [legacy-retirement-plan.md](legacy-retirement-plan.md).

## Platform API summary fields

Installed app summaries expose UI metadata:

```json
{
  "appId": "demo-app",
  "name": "Demo App",
  "version": "1.0.0",
  "uiMode": "static",
  "uiEntry": "static/index.html",
  "uiUrl": "http://127.0.0.1:12345/static/",
  "uiOrigin": "http://127.0.0.1:12345",
  "uiOriginMode": "isolated-loopback",
  "uiOriginStatus": "active",
  "sameOriginFallbackUrl": "/apps/demo-app/",
  "running": false
}
```

Shell-panel apps preserve their existing local route:

```json
{
  "uiMode": "shell-panel",
  "uiEntry": "/app/node/#queue",
  "uiUrl": "/app/node/#queue"
}
```

Apps without a UI use `uiMode=none`, `uiEntry=null`, and `uiUrl=null`.

Runtime hardening APIs are separate from the app summary:

```text
GET /api/v1/apps/{appId}/runtime
GET /api/v1/apps/{appId}/logs?maxBytes=65536
GET /api/v1/apps/{appId}/permissions
GET /api/v1/apps/{appId}/audit
```

The runtime endpoint reports process state, PID, start time, last exit metadata, restart attempt
counts, quota status for AppHost-managed data/cache/log resources, runtime warnings, and
process-log availability. It also reports process sandbox status such as `supportLevel` and
`provider`; that status is separate from browser origin isolation. The logs endpoint returns a
bounded, token-redacted tail of the app's combined stdout/stderr log. Neither endpoint exposes
`CRYPTAD_APP_TOKEN` or absolute installed/data/cache/run filesystem paths.

The Web Shell uses those endpoints for operator visibility. Static app UIs must not treat the
runtime endpoint as proof of app-level health; it is process status only.

The permissions and audit endpoints expose manifest-declared permissions, recent app-originated
Platform API decisions, and retained denied-call counts. Audit entries distinguish process-token
requests from browser-session requests with an auth-source label. They are bounded and
process-local, and they omit launch tokens, browser session tokens, query strings, request bodies,
form passwords, and filesystem paths.

## Examples

Static UI bundle:

```properties
manifest.version=1
app.id=queue-manager
app.name=Queue Manager
app.version=1.0.0
app.exec=bin/launch.sh
app.ui.mode=static
app.ui.entry=static/index.html
app.permissions=queue.read,queue.write
quota.data.bytes=0
quota.cache.bytes=0
```

First-party Publisher bundle:

```properties
manifest.version=1
app.id=publisher
app.name=Publisher
app.version=1.0.0
app.exec=bin/launch.sh
app.ui.mode=static
app.ui.entry=static/index.html
app.permissions=queue.read,queue.write,content.insert
quota.data.bytes=0
quota.cache.bytes=0
```

First content reference app bundle:

```properties
manifest.version=1
app.id=site-publisher
app.name=Site Publisher
app.version=1.0.0
app.exec=bin/site-publisher.sh
app.ui.mode=static
app.ui.entry=static/index.html
app.permissions=queue.read,queue.write,content.insert
quota.data.bytes=0
quota.cache.bytes=0
```

Site Publisher needs `content.insert` to submit operator-selected local site content to the insert
pipeline, `queue.write` to create the resulting insert requests, and `queue.read` to show publish
progress. It does not request vault identity capabilities; identity-backed profile publishing
remains future work until a browser-safe grant flow can use identity metadata without exporting
private material.

Transitional shell-panel bundle:

```properties
manifest.version=1
app.id=legacy-queue-panel
app.name=Legacy Queue Panel
app.version=1.0.0
app.exec=bin/launch.sh
app.ui.mode=shell-panel
app.ui.entry=/app/node/#queue
```
