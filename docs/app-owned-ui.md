# App-owned static UI

This document describes how installed AppHost bundles declare and serve app-owned browser UI under
`/apps/{appId}/`.

## Scope

App-owned static UI is a local browser surface for installed apps. It does not add permission
enforcement, a JavaScript SDK, sandboxing, container execution, or remote protocol changes.

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

The route remains same-origin with the local admin UI and Platform API. Permission enforcement,
stronger isolation, and audit logging belong to later platform work.

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

## Examples

Static UI bundle:

```properties
manifest.version=1
app.id=demo-app
app.name=Demo App
app.version=1.0.0
app.exec=bin/launch.sh
app.ui.mode=static
app.ui.entry=static/index.html
app.permissions=network.access
```

Shell-panel bundle:

```properties
manifest.version=1
app.id=queue-manager
app.name=Queue Manager
app.version=1.0.0
app.exec=bin/launch.sh
app.ui.mode=shell-panel
app.ui.entry=/app/node/#queue
```
