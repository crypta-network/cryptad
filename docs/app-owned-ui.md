# App-owned static UI

This document describes how installed AppHost bundles declare and serve app-owned browser UI under
`/apps/{appId}/`.

## Scope

App-owned static UI is a local browser surface for installed apps. It does not add sandboxing,
container execution, browser-scoped app sessions, or remote protocol changes. The
[`CryptaPlatform` JavaScript SDK](platform-sdk-js.md) is only a browser convenience wrapper around
the existing bootstrap and Platform API calls; permission enforcement remains server-side.

The route serves immutable files from the installed app bundle only. It does not serve app data,
cache, run directories, catalog scratch directories, or caller staging paths.

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

## Static route behavior

The legacy HTTP admin adapter mounts static app UI at app-owned paths such as:

```text
/apps/{appId}/
/apps/{appId}/static/...
/apps/{appId}/.well-known/cryptad-bootstrap.json
```

`GET /apps/{appId}/` serves the app's declared static `app.ui.entry` when that entry lives at the
bundle root. `HEAD` returns the same headers without a body. `GET /apps/{appId}` redirects to
`/apps/{appId}/`.

For nested entries such as `static/index.html`, `GET /apps/{appId}/` redirects to the entry
directory, such as `/apps/{appId}/static/`. That preserves the browser base URL, so a page can use
normal references such as `./app.js` and `../shared.js`. Explicit paths such as
`/apps/{appId}/static/app.js` still resolve as bundle-relative paths. All served targets must
resolve to regular files inside the immutable installed bundle root.

To preserve the browser base URL for nested entries, Platform API summaries publish `uiUrl` at the
entry directory when needed. For `app.ui.entry=static/index.html`, `uiUrl` is
`/apps/{appId}/static/`.

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

App-owned UI uses stable URLs across reinstall and update operations. Responses are therefore sent
with non-public no-cache headers instead of the legacy admin adapter's long-lived static cache
policy.

The route remains same-origin with the local admin UI and Platform API. Static browser UI does not
receive `CRYPTAD_APP_TOKEN` and cannot authenticate as the app process in this model. App
permission enforcement and audit apply to process-originated Platform API calls that present the
launch token. Stronger browser isolation remains later platform work. Until that exists, install
static UI bundles only from sources trusted to run JavaScript in the local admin origin.

## First-party app bootstrap

First-party static app UIs can fetch:

```text
GET /apps/{appId}/.well-known/cryptad-bootstrap.json
```

The legacy HTTP admin adapter builds this JSON dynamically after the same full-access check used by
app UI assets. The path is reserved by the host; it is not read from the installed bundle.

The current payload is deliberately small:

```json
{
  "appId": "queue-manager",
  "name": "Queue Manager",
  "uiRoot": "/apps/queue-manager/",
  "assetRoot": "/apps/queue-manager/static/",
  "platformApiRoot": "/api/v1/",
  "shellRoot": "/app/node/",
  "formPassword": "<local-admin-form-password>"
}
```

`formPassword` is the existing local-admin mutation guard accepted by the legacy Platform API
bridge. Static first-party UIs add it as a form field when they submit mutating `/api/v1/` requests,
the same way the Web Shell does. Read-only requests do not need it.

The bootstrap does not expose `CRYPTAD_APP_TOKEN`, AppHost launch tokens, signing keys, trusted-key
material, installed-bundle filesystem paths, data/cache/run paths, or catalog scratch paths. It is
not an app permission token. The [Platform JavaScript SDK](platform-sdk-js.md) consumes this
bootstrap as route metadata and as the source of the existing `formPassword` mutation guard.
Browser-issued app sessions and stronger app isolation remain later platform work.

Queue Manager and Publisher are also the primary replacements for the legacy queue and insert
admin pages in the current retirement map. The full map is maintained in
[legacy-retirement-plan.md](legacy-retirement-plan.md).

## Platform API summary fields

Installed app summaries expose UI metadata:

```json
{
  "appId": "demo-app",
  "name": "Demo App",
  "version": "1.0.0",
  "uiMode": "static",
  "uiEntry": "static/index.html",
  "uiUrl": "/apps/demo-app/static/",
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
counts, and process-log availability. The logs endpoint returns a bounded, token-redacted tail of
the app's combined stdout/stderr log. Neither endpoint exposes `CRYPTAD_APP_TOKEN` or absolute
installed/data/cache/run filesystem paths.

The Web Shell uses those endpoints for operator visibility. Static app UIs must not treat the
runtime endpoint as proof of app-level health; it is process status only.

The permissions and audit endpoints expose manifest-declared permissions, recent app-originated
Platform API decisions, and retained denied-call counts. Audit entries are bounded and
process-local, and they omit tokens, query strings, request bodies, form passwords, and filesystem
paths.

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
```

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
