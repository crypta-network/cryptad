# Platform API Surface

This page documents the current local Platform API v1 and Web Shell surfaces after Phase 3.

## Scope

Platform API v1 is mounted at `/api/v1/`. The current transport-facing entrypoint is the legacy
HTTP admin bridge in `:adapter-http-legacy-admin`, which converts legacy requests into
`PlatformApiRequest` objects and delegates routing to `:platform-api`.

The API is a local/internal control plane for the daemon and first-party shell. It is not yet a
declared stable remote public API.

Web Shell v1 is mounted separately at `/app/node/`. Its static assets are served beneath
`/app/node/static/`, and its bootstrap payload points the browser at the Platform API root.

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
| Diagnostics | `GET /api/v1/diagnostics` exposes the ordered diagnostic snapshot and plain-text export. |
| Apps | `GET /api/v1/apps` lists installed apps when `AppHost` is wired into the router. The family also covers local staged-bundle install, app lookup, start, stop, update, and uninstall. |

## Web Shell relationship

The Web Shell uses the Platform API for node management, queue control, peer control, alerts,
diagnostics, config, updater, security levels, wizard, installed-app lifecycle work, and the
Publisher/Queue Manager first-party app surfaces.

The shell currently includes these first-party panels and surfaces:

- Overview and connectivity snapshots.
- Alert queue and diagnostics.
- Installed apps.
- Security levels, updater state, config controls, and first-time wizard controls.
- Peer control plane.
- Publisher local file/directory insert workflow.
- Queue control plane.
- Legacy links for pages that remain fallback or debug surfaces.

The shell is hosted by `:adapter-http-legacy-admin`, but its route constants, HTML template, CSS,
JavaScript, and bootstrap model are owned by `:platform-web-shell`.

## Legacy HTTP and FCP relationship

Platform API v1 does not replace legacy HTTP or FCP in Phase 3.

Legacy HTTP remains the current transport and authentication boundary for `/api/v1/` and
`/app/node/`. The shared admin shell, admin toadlets, updater actions, and fallback pages remain in
`:adapter-http-legacy-admin`; concrete browse/FProxy routes remain in
`:adapter-http-legacy-browse`; concrete runtime HTTP bindings remain in `:bridge-http-runtime`.

FCP remains a separate compatibility and automation protocol. The detached FCP protocol surface is
owned by `:adapter-fcp`, and runtime bindings are owned by `:bridge-fcp-runtime`. The Platform API
does not own FCP routing or compatibility behavior.

The maintained boundary docs are [fcp-boundary.md](fcp-boundary.md) and
[legacy-http-boundary.md](legacy-http-boundary.md).
