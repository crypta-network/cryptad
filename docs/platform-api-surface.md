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
| Content | `POST /api/v1/content/fetch` lets an app principal with `content.fetch` request one bounded content document for app-owned workflows such as feed reading. It accepts form-encoded `uri`, optional `maxBytes`, `timeoutMillis`, `format=text\|base64`, and `purpose`, with daemon-enforced 256 KiB/30 second defaults and 1 MiB/60 second hard caps. App principals may fetch only `CHK@`, `SSK@`, `USK@`, `KSK@`, or matching `crypta:` content-key forms, with the key-type prefix accepted case-insensitively; `file:`, `http:`, `https:`, loopback, LAN, and local-path sources are rejected before the runtime fetch port is called. Contract v8 adds app-scoped durable subscriptions under `/api/v1/content/subscriptions`: `GET` list/read and `POST` create/refresh/pause/resume plus `DELETE` delete. All subscription routes require an app principal and `content.subscribe`; create and refresh also require `content.fetch`. Subscription sources are USK-only (`USK@...` or `crypta:USK@...`) and reject local paths, relative paths, query strings, fragments, whitespace, multiline text, `CHK@`, `SSK@`, `KSK@`, and arbitrary HTTP/HTTPS URLs. The scheduler stores metadata only: status, due times, sanitized resolved URI, last seen edition, digest, byte length, failures, and update count. It never persists raw fetched content. Queue pressure is recorded with stable runtime signals as path-free metadata such as `queue_pressure` or `runtime_unavailable`; no queue HTML is parsed or exposed. Content routes do not grant local file-path access, queue mutation, catalog authority, app-vault access, generic crawler behavior, or arbitrary HTTP/HTTPS fetching. Audit records, error diagnostics, and certification evidence must not include raw feed bodies, raw fetched content, raw request bodies, private insert URIs, app process tokens, browser-session tokens, form passwords, queue HTML, or local paths. |
| App data | Contract v9 adds bounded durable app-owned state under `/api/v1/app-data`. App principals need `app.data.read` for status, namespace metadata, record reads, record lists, and bounded exports. They need `app.data.write` for record create/replace/delete, namespace clear, schema migration metadata, and bounded imports. Routes are scoped to the authenticated app id and never accept host filesystem paths or another target app id. Values are returned only to the owning app through read/export calls; list responses expose summaries with byte counts and SHA-256 digests. The file-backed store is host-managed rather than app-writable, but store-level caps apply even when manifest data quota is absent or zero, and positive `quota.data.bytes` is enforced when available. This route family is not a generic filesystem API, database engine, browser storage for secrets, or AppVault bypass. Evidence must use route names, capability labels, counts, byte sizes, schema versions, booleans, and digests instead of raw values. See [app-data-store.md](app-data-store.md). |
| App services | Contract v12 adds `/api/v1/app-services` for local service discovery, grant request/list, host/operator approve/revoke, redacted audit, and mediated invocation. App principals need `app.services.read` for discovery and grant visibility and `app.services.call` for grant request, self-revoke, and invocation. Invocation also checks at call time that the consumer still declares `app.services.call`, the provider is installed, the provider manifest still advertises the service, and an active grant matches consumer/provider/service/scope/context. The first provider is Trust Graph Preview's `trust.score` platform adapter for `score.read`. This family is not generic RPC, not remote discovery, and not a localhost proxy. Evidence must not include provider app data, Trust Graph store files, raw statement bodies, raw request bodies, private insert URIs, identity secrets, tokens, form passwords, or local paths. See [app-service-discovery-and-grants.md](app-service-discovery-and-grants.md). |
| Operator | `/api/v1/operator/beta-dashboard`, `/api/v1/operator/support-bundle`, and `/api/v1/operator/subscriptions/{appId}/{subscriptionId}/refresh\|pause\|resume` are host/operator-only routes for the local beta dashboard and support bundle. They are intentionally excluded from the app-facing Platform API contract, and app principals must be denied. The support bundle is redacted and path-free, and subscription recovery delegates to the shared content-subscription service without granting apps cross-app authority. See [operator-beta-dashboard.md](operator-beta-dashboard.md). |
| Trust graph | Contract v7 adds the local Trust Graph Preview route family. `GET /api/v1/trust-graph/status`, `anchors`, `subjects`, `statements`, and `score` require `trust.read`; `POST /api/v1/trust-graph/import`, `POST /api/v1/trust-graph/anchors`, and `DELETE /api/v1/trust-graph/anchors/{fingerprint}` require `trust.write`. Contract v10 adds `POST /api/v1/trust-graph/import-uri` with `trust.write` plus `content.fetch` and `GET /api/v1/trust-graph/audit` with `trust.read`. The full runtime uses a durable local file-backed store for anchors, imported normalized public statements, and redacted trust audit entries, while reduced embeddings may inject the in-memory store. The service imports bounded `crypta.trust.statement.v1` documents, manages local anchors, verifies AppVault preview signatures when issuer public keys are present, and scores direct anchor evidence with a deterministic confidence-weighted average. Unverified imports are retained as non-contributing evidence. It is not full WoT, old plugin compatibility, moderation, background crawling, routing policy, peer selection, or a protocol change. Audit and evidence must not include raw trust document bodies from real users, raw fetched content, raw request bodies, raw signatures, private insert URIs, private identity material, tokens, form passwords, or local paths. |
| Queue | `GET /api/v1/queue` exposes the queue snapshot. The family also covers count and key-export views, direct downloads, local file/directory inserts, app-generated document inserts at `POST /api/v1/queue/inserts/app-document`, request removal/restart/priority changes, and finished upload/download cleanup. Local file/directory inserts require `content.insert` plus `queue.write`. App-generated document inserts require the narrower `content.insert.app-document` plus `queue.write`, accept generated document content instead of a local file path, and must keep raw request bodies, private insert URIs, signatures, and absolute staging paths out of certification evidence. |
| Peers | `GET /api/v1/peers` exposes raw peer lists or the shell summary view. The family also covers peer add, lookup, settings updates, private-note updates, and removal. |
| Config | `GET /api/v1/config` exports config snapshots. `POST` actions apply overrides and persist the current config. |
| Security levels | `GET /api/v1/security-levels` exposes threat-level state. The family also covers network warning lookup and current network/physical threat-level mutations, with confirmation-heavy flows still falling back to legacy pages when required. |
| Updates | `GET /api/v1/updates/core` reports core-updater availability. `POST /api/v1/updates/core/download` triggers the current package download flow. |
| Wizard/welcome | `GET /api/v1/wizard/first-time` exposes the detached first-time setup snapshot. `POST /api/v1/wizard/first-time/apply` submits the shell-native onboarding/reset model. There is no separate `/welcome` Platform API family in Phase 3; welcome-page fallback behavior remains on the legacy/admin side. |
| Alerts | `GET /api/v1/alerts` lists current alerts. `POST /api/v1/alerts/{alertId}/dismiss` dismisses one alert by detached identifier. |
| Diagnostics | `GET /api/v1/diagnostics` exposes the ordered diagnostic snapshot and plain-text export. When served through the legacy HTTP bridge, it also includes process-local `legacyAdmin.surfaces[]` counters for legacy admin retirement planning. |
| Apps | `GET /api/v1/apps` lists installed apps when `AppHost` is wired into the router, including path-free quota usage, effective limits, process-log size/limit metadata, sandbox status, app-owned UI metadata, and recent audit summary data. Sandbox status reports the requested mode, required flag, provider, active flag, warnings, and support level such as `none`, `best-effort`, `unsupported`, or `enforced`; it does not expose wrapper command lines, executable paths, or launch tokens. The family also covers local staged-bundle install, app lookup, start, stop, update, uninstall, declared permissions at `GET /api/v1/apps/{appId}/permissions`, recent app audit at `GET /api/v1/apps/{appId}/audit`, token-free runtime status at `GET /api/v1/apps/{appId}/runtime`, and bounded token-redacted process logs at `GET /api/v1/apps/{appId}/logs`. `DELETE /api/v1/apps/{appId}` removes app data by default; operators can pass `preserveData=true` to keep the app-owned persistent data directory and durable app-data records while removing the immutable bundle, cache, run state, and rollback state. Contract version 2 adds app-update lifecycle routes under `GET /api/v1/apps/{appId}/updates` plus `check`, `stage`, `apply`, `rollback`, and policy read/write subroutes; those summaries are path-free and token-free, include background scheduler state, expose candidate channel/support/deprecation/advisory metadata, expose policy `allowedChannels`, and keep app bundle rollback separate from app data/cache state. |
| App catalogs | `GET /api/v1/app-catalogs` lists configured signed catalogs when catalog support is wired into the router. `GET /api/v1/app-catalogs/recommended` exposes operator-visible recommended catalogs such as the first-party beta catalog plus production-safe `defaultEntryChannel=stable` and available entry channels. `POST /api/v1/app-catalogs/recommended/{catalogId}/add` adds one through the same verified source path. The family also covers source add/remove, refresh, catalog app listing/detail, install/update from a verified catalog artifact, and app-store metadata for install/update review. Catalog app summaries include signed production channel metadata (`channel`, `supportStatus`, `deprecation`, `securityAdvisories`, `minimumCryptaVersion`, and `maximumCryptaVersion`) without exposing private insert URIs, catalog scratch paths, staged bundle paths, tokens, private keys, raw fetched content, or raw app data. |
| Platform contract | `GET /api/v1/platform/contract` exposes the deterministic Platform API compatibility contract. App principals need `platform.contract.read`; host/operator requests use the existing local-admin model. |
| App vault | Secret and identity vault routes use `vault.secrets.read`, `vault.secrets.write`, `vault.identities.read`, `vault.identities.create`, `vault.identities.use`, and `vault.identities.manage` when the vault endpoint family is wired. `POST /api/v1/app-vault/identities` creates app-owned identities for authorized app process or browser principals without returning private material. `POST /api/v1/app-vault/identities/{identityId}/profile-document` uses an identity the app can see and use to create a profile document without exporting the private key. `POST /api/v1/app-vault/identities/{identityId}/trust-statement` requires `trust.write`, `vault.identities.read`, and `vault.identities.use` and signs only the bounded trust statement payload. Contract v11 adds `POST /api/v1/app-vault/identities/{identityId}/social-message` with `vault.identities.read` and `vault.identities.use`; it signs only bounded `crypta.social.message.v1` plain-text messages, fixes the signing domain, and is not a generic browser signing API. Vault responses and audit entries must remain token-free, path-free, and free of raw secret values, identity private material, request bodies, private keys, raw message bodies, raw fetched social documents, and raw signatures. See [app-secret-and-identity-vault.md](app-secret-and-identity-vault.md) and [social-inbox-reference-app.md](social-inbox-reference-app.md). |

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
repo-owned Queue Manager, Publisher, Site Publisher, Profile Publisher, Social Inbox Preview, Feed
Reader, and Trust Graph Preview apps use the same Platform API from their own static routes under
`/apps/queue-manager/`, `/apps/publisher/`, `/apps/site-publisher/`,
`/apps/profile-publisher/`, `/apps/social-inbox/`, `/apps/feed-reader/`, and
`/apps/trust-graph/`.

The shell currently includes these first-party panels and surfaces:

- Overview and connectivity snapshots.
- Alert queue and diagnostics.
- Installed apps and signed catalog app discovery, including catalog detail review before
  install/update.
- Security levels, updater state, config controls, and first-time wizard controls.
- Peer control plane.
- Queue Manager, Publisher, Site Publisher, Profile Publisher, Social Inbox Preview, Feed Reader,
  and Trust Graph Preview open as independent first-party app UIs when installed.
- Publisher local file/directory insert workflow and queue control remain available in the shell as
  fallback operator panels.
- Legacy links for retained or pending tools that remain legitimate legacy entry points.
- Replaced legacy admin pages are not primary shell navigation targets. The first removal wave now
  returns replacement responses for selected canonical admin URLs instead of rendering the old
  pages by default; the current state and wave list are tracked in
  [legacy-retirement-plan.md](legacy-retirement-plan.md).

The shell is hosted by `:adapter-http-legacy-admin`, but its route constants, HTML template, CSS,
JavaScript, and bootstrap model are owned by `:platform-web-shell`.

## Legacy HTTP and FCP relationship

Platform API v1 does not replace legacy HTTP or FCP in the current platform work.

Legacy HTTP remains the current transport and authentication boundary for `/api/v1/`,
`/app/node/`, and `/apps/{appId}/`. The shared admin shell, retained and pending admin toadlets,
updater actions that are not in the current removal wave, and replacement-response gate remain in
`:adapter-http-legacy-admin`; concrete browse/FProxy routes remain in
`:adapter-http-legacy-browse`; concrete runtime HTTP bindings remain in `:bridge-http-runtime`.
Wave-1 admin URLs return `303 See Other` for safe reads or `410 Gone` for mutating requests with a
same-origin replacement link when the replacement UI is reachable for the current request. If the
replacement app is not installed, FProxy JavaScript is disabled, or Web Shell is not the advertised
primary UI, the legacy fallback remains reachable and diagnostics record fallback rendering. FProxy
browse remains retained and is not owned by Platform API v1.

FCP remains a separate compatibility and automation protocol. The detached FCP protocol surface is
owned by `:adapter-fcp`, and runtime bindings are owned by `:bridge-fcp-runtime`. The Platform API
does not own FCP routing or compatibility behavior.

The maintained boundary docs are [fcp-boundary.md](fcp-boundary.md) and
[legacy-http-boundary.md](legacy-http-boundary.md).
