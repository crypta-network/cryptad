# Platform API Surface

This page documents the current local Platform API v1, Web Shell, app catalog, and app-owned UI
surfaces.

## Scope

Platform API v1 is mounted at `/api/v1/`. The current transport-facing entrypoint is the legacy
HTTP admin bridge in `:adapter-http-legacy-admin`, which converts legacy requests into
`PlatformApiRequest` objects and delegates routing to `:platform-api`. The URL version is separate
from the integer compatibility contract version described in
[platform-api-contract.md](platform-api-contract.md).

The API is a local/internal control plane for the daemon and first-party shell. It is not yet a
declared stable remote public API.

Web Shell v1 is mounted separately at `/app/node/`. Its static assets are served beneath
`/app/node/static/`, and its bootstrap payload points the browser at the Platform API root.

Installed apps with static browser UI prefer isolated per-app loopback origins, with
`/apps/{appId}/` retained as a compatibility route. The Platform API continues to own the JSON
lifecycle/control plane under `/api/v1/apps`; it publishes `uiMode`, `uiEntry`, `uiUrl`,
`uiOrigin`, `uiOriginMode`, `uiOriginStatus`, and `sameOriginFallbackUrl` so shells can open the
correct app UI route.

Static first-party app UIs use `/.well-known/cryptad-bootstrap.json` on their app origin for route
metadata, origin metadata, and an opaque browser app session token for Platform API calls. The
compatibility `/apps/{appId}/.well-known/cryptad-bootstrap.json` path can return fallback
bootstrap metadata. Bootstrap is served by the app UI route, not by `/api/v1/apps`, and it does not
expose `CRYPTAD_APP_TOKEN`, local-admin `formPassword`, or AppHost filesystem paths.

The [Platform JavaScript SDK](platform-sdk-js.md) is a browser convenience layer over that
bootstrap and Platform API calls. It does not create the authority boundary; server-side Platform
API permission checks, origin-bound browser sessions, restricted CORS, and app-origin audit remain
authoritative.

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
| `401 Unauthorized` | App-token or app browser-session authentication failed because a supplied credential is invalid, blank, stale, or unavailable. |
| `403 Forbidden` | The legacy bridge rejects a caller without full access. |
| `404 Not Found` | Unknown routes or missing resources. |
| `405 Method Not Allowed` | A known route was called with the wrong method; the response includes `Allow`. |
| `409 Conflict` | Stateful conflicts, confirmation requirements, or temporarily unavailable control paths. |
| `500 Internal Server Error` | Unexpected failures after routing. |

Host/operator mutating routes still rely on the legacy admin bridge for full-access checks and the
form-password guard. Current Web Shell mutations submit URL-encoded form data.

App processes can authenticate with the per-launch `CRYPTAD_APP_TOKEN` injected by AppHost. The
legacy HTTP bridge accepts the token in `X-Crypta-App-Token`; it also accepts Bearer credentials in
the `Authorization` header only when the Bearer value verifies as a live app token. Query parameters
are ignored for token authentication, and unrelated Bearer credentials remain host/operator
requests. Authenticated app requests are checked against manifest-declared capabilities before
routing and are denied by default. See [app-permissions-and-audit.md](app-permissions-and-audit.md)
for the matrix and audit model.

Static app-owned browser UI authenticates with `X-Crypta-App-Session`, which carries the opaque
browser session token from app UI bootstrap. Browser app sessions are bound to one installed static
app and its manifest permissions; they are not AppHost process launch tokens and do not grant
host/operator authority.

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
| Apps | `GET /api/v1/apps` lists installed apps when `AppHost` is wired into the router, including path-free quota usage, effective limits, process-log size/limit metadata, sandbox status, app-owned UI metadata, and recent audit summary data. Sandbox status reports the requested mode, required flag, provider, active flag, warnings, and support level such as `none`, `best-effort`, `unsupported`, or `enforced`; it does not expose wrapper command lines, executable paths, or launch tokens. The family also covers local staged-bundle install, app lookup, start, stop, update, uninstall, declared permissions at `GET /api/v1/apps/{appId}/permissions`, recent app audit at `GET /api/v1/apps/{appId}/audit`, token-free runtime status at `GET /api/v1/apps/{appId}/runtime`, and bounded token-redacted process logs at `GET /api/v1/apps/{appId}/logs`. Contract version 2 adds app-update lifecycle routes under `GET /api/v1/apps/{appId}/updates` plus `check`, `stage`, `apply`, `rollback`, and policy read/write subroutes; those summaries are path-free and token-free and keep app bundle rollback separate from app data/cache state. |
| App catalogs | `GET /api/v1/app-catalogs` lists configured signed catalogs when catalog support is wired into the router. The family also covers source add/remove, refresh, catalog app listing/detail, install/update from a verified catalog artifact, and app-store metadata for install/update review. |
| Platform contract | `GET /api/v1/platform/contract` exposes the deterministic Platform API compatibility contract. App principals need `platform.contract.read`; host/operator requests use the existing local-admin model. |

## App catalog response metadata

Catalog app listing and detail responses expose signed-catalog metadata for the Web Shell Apps
section. The response shape includes the existing app id, name, version, summary, bundle metadata,
installed state, running state, and installed version. It also includes optional store metadata
when a metadata-capable catalog entry provides it:

- `homepage`, `source`, `license`, and `categories`.
- Legacy publisher-advisory `review.status` and `review.note`.
- `reviewTrust`, the node-local trusted review receipt decision. It includes stable `status`,
  booleans for `trusted`, `positive`, `requiresAcknowledgement`, `blocksInstall`,
  `blocksUpdate`, and `blocksPolicyApply`, reviewer key/display metadata, policy id/version,
  review/expiry timestamps, optional evidence digest/URI, and warnings.
- `permissionRationales`, keyed by normalized permission name.
- `compatibility.minimumCryptaVersion`, the current comparable Cryptad build/version string,
  advisory status, and whether the comparison is satisfied when it can be evaluated.
- `apiCompatibility`, including the current Platform API contract version, the app's optional
  minimum and maximum-tested contract versions, status, optional capabilities, and verifier
  warnings.
- `screenshots` as URI strings.
- `changelog.summary` and `changelog.uri`.
- Installed-vs-catalog version-difference fields and an advisory `updateAvailable` summary. A
  version mismatch is reported separately through `versionDifferent`; `updateAvailable` is `true`
  only when the catalog version compares newer than the installed version and is `null` when
  ordering cannot be evaluated safely.
- `permissionDelta` for install/update review, with added, removed, and unchanged permissions.

Example review fields:

```json
{
  "review": {
    "status": "reviewed",
    "note": "Publisher advisory note"
  },
  "reviewTrust": {
    "status": "trusted_reviewed",
    "trusted": true,
    "positive": true,
    "requiresAcknowledgement": false,
    "blocksInstall": false,
    "blocksUpdate": false,
    "blocksPolicyApply": false,
    "reviewerKeyId": "crypta-first-party-review",
    "reviewerDisplayName": "Crypta First-Party Review",
    "policyId": "crypta-app-review-v1",
    "policyVersion": "1",
    "reviewedAt": "2026-04-21T18:25:00Z",
    "expiresAt": null,
    "evidenceSha256": "<optional-lowercase-hex-sha256>",
    "evidenceUri": "crypta:CHK@...",
    "warnings": []
  }
}
```

Signed catalog verification authenticates catalog bytes and publisher metadata; it does not
authenticate independent review evidence. `review.status=reviewed` remains advisory unless
`reviewTrust.status=trusted_reviewed` verifies a receipt for the same app id, version, artifact
digest, and size with a configured trusted reviewer key. Cryptad build compatibility and Platform
API contract compatibility metadata are advisory in this PR and do not block install/update by
themselves when version comparison is unavailable or ambiguous.

The API must not expose trusted-key material, catalog scratch paths, verified staging directories,
AppHost filesystem paths, reviewer public key bytes, reviewer private key material, receipt file
paths, app browser session tokens, or AppHost process tokens through catalog responses. Screenshot
fields are URL metadata for the operator; the Web Shell should show them as links or behind an
explicit preview control rather than silently fetching arbitrary remote images.

Install/update APIs use local review policy to decide whether `reviewTrust` blocks or requires
acknowledgement. `advisory` is backward-compatible with old catalogs. `warn_untrusted` requires an
explicit `reviewAcknowledged=true` request flag for missing, untrusted, expired, mismatched, or
rejected review evidence. `require_trusted_review` blocks manual install/update unless the receipt
is trusted and positive. Policy-driven update apply also honors `blocksPolicyApply`. Stable review
gate error codes include `app_review_missing`, `app_review_untrusted`, `app_review_rejected`,
`app_review_mismatch`, and `app_review_expired`.

## Web Shell relationship

The Web Shell uses the Platform API for node management, queue control, peer control, alerts,
diagnostics, config, updater, security levels, wizard, and installed-app lifecycle work. The
repo-owned Publisher and Queue Manager apps now use the same Platform API from their own static
routes under `/apps/publisher/` and `/apps/queue-manager/`.

The shell currently includes these first-party panels and surfaces:

- Overview and connectivity snapshots.
- Alert queue and diagnostics.
- Installed apps and signed catalog app discovery, including catalog detail review before
  install/update.
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
