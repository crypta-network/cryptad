# Platform API Surface

This page documents the current local Platform API v1, Web Shell, app catalog, and app-owned UI
surfaces.

## Scope

Platform API v1 is mounted at `/api/v1/`. The current transport-facing entrypoint is the legacy
HTTP admin bridge in `:adapter-http-legacy-admin`, which converts legacy requests into
`PlatformApiRequest` objects and delegates routing to `:platform-api`.

The API is a local/internal control plane for the daemon and first-party shell. It is not yet a
declared stable remote public API.

Web Shell v1 is mounted separately at `/app/node/`. Its static assets are served beneath
`/app/node/static/`, and its bootstrap payload points the browser at the Platform API root.

Installed apps with static browser UI are mounted separately at `/apps/{appId}/`. The Platform API
continues to own the JSON lifecycle/control plane under `/api/v1/apps`; it only publishes
`uiMode`, `uiEntry`, and `uiUrl` so shells can open the correct app UI route.

Static first-party app UIs use `/apps/{appId}/.well-known/cryptad-bootstrap.json` for route
metadata and the existing local-admin form password needed by mutating Platform API calls. That
bootstrap is served by the app UI route, not by `/api/v1/apps`, and it does not expose
`CRYPTAD_APP_TOKEN` or AppHost filesystem paths.

The [Platform JavaScript SDK](platform-sdk-js.md) is a browser convenience layer over that
bootstrap and the same-origin Platform API. It does not create a new authority boundary; server-side
Platform API permission checks and app-origin audit remain authoritative.

## Response contract

The router emits JSON responses. Successful reads generally return `200 OK`; create-style
operations such as queueing a direct download or installing a local app can return `201 Created`.

Errors use one JSON shape:

```json
{"error":{"code":"...","message":"..."}}
```

Current error handling uses HTTP-style status codes:

| Status | Current use |
| --- | --- |
| `400 Bad Request` | Malformed paths, malformed percent-encoding, or invalid query/form values. |
| `403 Forbidden` | The legacy bridge rejects a caller without full access. |
| `404 Not Found` | Unknown routes or missing resources. |
| `405 Method Not Allowed` | A known route was called with the wrong method; the response includes `Allow`. |
| `409 Conflict` | Stateful conflicts, confirmation requirements, or temporarily unavailable control paths. |
| `500 Internal Server Error` | Unexpected failures after routing. |

Mutating routes still rely on the legacy admin bridge for full-access checks and the form-password
guard. Current Web Shell mutations submit URL-encoded form data.

## Endpoint families

The table lists the current family-level surface. It avoids documenting every minor query
parameter; check the handler and tests when adding or changing a specific contract.

| Family | Current surface |
| --- | --- |
| Node | `GET /api/v1/node/greeting` and `GET /api/v1/node/reference` expose read-only node metadata and node-reference export. |
| Connectivity | `GET /api/v1/connectivity` exposes the current connectivity snapshot. |
| Queue | `GET /api/v1/queue` exposes the queue snapshot. The family also covers count and key-export views, direct downloads, local file/directory inserts, request removal/restart/priority changes, and finished upload/download cleanup. |
| Peers | `GET /api/v1/peers` exposes raw peer lists or the shell summary view. The family also covers peer add, lookup, settings updates, private-note updates, and removal. |
| Config | `GET /api/v1/config` exports config snapshots. `POST` actions apply overrides and persist the current config. |
| Security levels | `GET /api/v1/security-levels` exposes threat-level state. The family also covers network warning lookup and current network/physical threat-level mutations, with confirmation-heavy flows still falling back to legacy pages when required. |
| Updates | `GET /api/v1/updates/core` reports core-updater availability. `POST /api/v1/updates/core/download` triggers the current package download flow. |
| Wizard/welcome | `GET /api/v1/wizard/first-time` exposes the detached first-time setup snapshot. `POST /api/v1/wizard/first-time/apply` submits the shell-native onboarding/reset model. There is no separate `/welcome` Platform API family in Phase 3; welcome-page fallback behavior remains on the legacy/admin side. |
| Alerts | `GET /api/v1/alerts` lists current alerts. `POST /api/v1/alerts/{alertId}/dismiss` dismisses one alert by detached identifier. |
| Diagnostics | `GET /api/v1/diagnostics` exposes the ordered diagnostic snapshot and plain-text export. When served through the legacy HTTP bridge, it also includes process-local `legacyAdmin.surfaces[]` counters for legacy admin retirement planning. |
| Apps | `GET /api/v1/apps` lists installed apps when `AppHost` is wired into the router. The family also covers local staged-bundle install, app lookup, start, stop, update, uninstall, token-free runtime status at `GET /api/v1/apps/{appId}/runtime`, and bounded token-redacted process logs at `GET /api/v1/apps/{appId}/logs`. |
| App catalogs | `GET /api/v1/app-catalogs` lists configured signed catalogs when catalog support is wired into the router. The family also covers source add/remove, refresh, catalog app listing/detail, and install/update from a verified catalog artifact. |

## Web Shell relationship

The Web Shell uses the Platform API for node management, queue control, peer control, alerts,
diagnostics, config, updater, security levels, wizard, and installed-app lifecycle work. The
repo-owned Publisher and Queue Manager apps now use the same Platform API from their own static
routes under `/apps/publisher/` and `/apps/queue-manager/`.

The shell currently includes these first-party panels and surfaces:

- Overview and connectivity snapshots.
- Alert queue and diagnostics.
- Installed apps and signed catalog app discovery.
- Security levels, updater state, config controls, and first-time wizard controls.
- Peer control plane.
- Publisher and Queue Manager open as independent first-party app UIs when installed.
- Publisher local file/directory insert workflow and queue control remain available in the shell as
  fallback operator panels.
- Legacy links for pages that remain fallback or debug surfaces.
- Replaced legacy admin pages are not primary shell navigation targets; their current retirement
  state is tracked in [legacy-retirement-plan.md](legacy-retirement-plan.md).

The shell is hosted by `:adapter-http-legacy-admin`, but its route constants, HTML template, CSS,
JavaScript, and bootstrap model are owned by `:platform-web-shell`.

## Legacy HTTP and FCP relationship

Platform API v1 does not replace legacy HTTP or FCP in the current platform work.

Legacy HTTP remains the current transport and authentication boundary for `/api/v1/` and
`/app/node/`. The shared admin shell, admin toadlets, updater actions, and fallback pages remain in
`:adapter-http-legacy-admin`; concrete browse/FProxy routes remain in
`:adapter-http-legacy-browse`; concrete runtime HTTP bindings remain in `:bridge-http-runtime`.

FCP remains a separate compatibility and automation protocol. The detached FCP protocol surface is
owned by `:adapter-fcp`, and runtime bindings are owned by `:bridge-fcp-runtime`. The Platform API
does not own FCP routing or compatibility behavior.

The maintained boundary docs are [fcp-boundary.md](fcp-boundary.md) and
[legacy-http-boundary.md](legacy-http-boundary.md).
