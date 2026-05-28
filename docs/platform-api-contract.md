# Platform API compatibility contract

The Platform API compatibility contract is the deterministic app-facing description of the current
Platform API v1 surface. It is separate from the URL version in `/api/v1/`: the URL version names
the transport route family, while the integer contract version is what app manifests, catalog
metadata, developer tooling, and release certification compare.

The current app-facing values are:

```text
apiVersion=v1
contractVersion=11
```

The contract does not change Platform API behavior. It publishes metadata that answers which
routes/actions exist, which manifest capabilities app principals need, and whether capabilities or
endpoints are stable, experimental, deprecated, scheduled for removal, or internal.

## Public snapshot

The current node exposes the contract at:

```text
GET /api/v1/platform/contract
```

Host/operator requests use the existing local-admin model. App process and browser principals can
read the endpoint only when their manifest grants:

```text
platform.contract.read
```

The response shape is:

```json
{
  "contract": {
    "apiVersion": "v1",
    "contractVersion": 11,
    "generatedBy": "cryptad",
    "stabilityPolicy": "...",
    "capabilities": [],
    "endpoints": []
  }
}
```

The snapshot is deterministic and excludes raw app process tokens, browser session tokens,
bootstrap nonces, form passwords, request bodies, query strings, filesystem paths, sandbox command
lines, environment variables, private keys, and private insert URIs.

The developer beta toolkit uses the same contract metadata in `crypta-app test` and
`crypta-app compat verify`. Scaffolded beta templates declare conservative `api.minimumVersion` and
`api.maximumTestedVersion` values, and catalog entry generation copies the manifest compatibility
metadata into descriptor output. See [developer-beta-toolkit.md](developer-beta-toolkit.md).

## Descriptor fields

Capability descriptors contain:

- `name`
- `stability`
- `sinceContractVersion`
- optional `deprecation`
- short `description`

Endpoint descriptors contain:

- route family, HTTP method, and route template relative to `/api/v1`
- audit/authorization action label
- required manifest capabilities
- whether host/operator bypass is allowed through the existing local-admin model
- whether app process and app browser principals can call the route
- stability level, first contract version, optional deprecation/removal metadata, and description

The runtime app authorization path reads the same endpoint descriptors that the snapshot publishes,
so the contract and route-to-capability policy do not maintain separate route lists.

## Stability levels

| Stability | Meaning |
| --- | --- |
| `stable` | Covered by the current Platform API compatibility contract. |
| `experimental` | Available for explicit adopters, but may change in a later contract. |
| `deprecated` | Still callable, but app authors should migrate away. |
| `scheduled-for-removal` | Still callable now, with planned removal metadata. |
| `internal` | Not app-facing; developer tooling treats app use as an error. |

Contract version 2 adds the installed-app update lifecycle endpoints under
`/apps/{appId}/updates`. Contract version 3 adds the app vault and identity vault descriptors.
Contract version 4 adds the first-party catalog onboarding routes under
`/app-catalogs/recommended`. Contract version 5 adds profile-publishing support for app-owned
static UIs:

| Route | Required app capabilities | Purpose |
| --- | --- | --- |
| `POST /api/v1/app-vault/identities` | `vault.identities.create` | Create an app-owned identity from a browser-safe app principal or app process principal without returning private identity material. |
| `POST /api/v1/app-vault/identities/{identityId}/profile-document` | `vault.identities.read`, `vault.identities.use` | Ask Cryptad to produce a profile document for an identity the app can see and use, without exporting private keys or recording raw signatures in evidence. |
| `POST /api/v1/queue/inserts/app-document` | `content.insert.app-document`, `queue.write` | Queue an app-generated document insert without requiring or authorizing a local source path in the request. |

`POST /api/v1/app-vault/identities` keeps `sinceContractVersion=3` because app-process
identity creation was introduced with the app-vault contract. Contract version 5 expands that
same descriptor to browser app principals for app-owned identity creation; the complete browser
profile-publishing workflow still requires the v5 profile-document and app-document routes.

Existing version 1 capabilities and endpoints remain stable, and their descriptors keep
`sinceContractVersion=1` so tooling can distinguish old and newly introduced surface area.

Contract version 6 adds bounded content fetch support for static feed apps:

| Route | Required app capabilities | Purpose |
| --- | --- | --- |
| `POST /api/v1/content/fetch` | `content.fetch` | Fetch a bounded Crypta content document for an app workflow such as feed reading without granting queue mutation or local file-path authority. |

The v6 fetch descriptor is separate from insert permissions. `content.fetch` lets the app ask the
local node to retrieve a specific content URI through the Platform API; it does not grant
`content.insert`, `content.insert.app-document`, `queue.write`, catalog management, vault access,
or local filesystem access. Certification evidence for this route must record only sanitized fetch
metadata and must exclude raw feed bodies, raw request bodies, private insert URIs, app process
tokens, app browser-session tokens, form passwords, and local paths.

`POST /api/v1/content/fetch` accepts `application/x-www-form-urlencoded` parameters. `uri` is
required and must be a Crypta/Freenet content key in `CHK@...`, `SSK@...`, `USK@...`, `KSK@...`,
`crypta:CHK@...`, `crypta:SSK@...`, `crypta:USK@...`, or `crypta:KSK@...` form, with the key-type
prefix accepted case-insensitively. Optional `maxBytes`, `timeoutMillis`, `format`, and `purpose`
values are bounded by the daemon: the default byte cap is 262144, the hard byte cap is 1048576, the
default timeout is 30000 milliseconds, and the hard timeout is 60000 milliseconds. `format=text`
returns UTF-8 `contentText`; `format=base64` returns `contentBase64`. App principals cannot use this
route for `file:`, `http:`, `https:`, loopback, LAN, or absolute local-path fetches.

Contract version 7 adds the local Trust Graph Preview service and the bounded AppVault
trust-statement signing route:

| Route | Required app capabilities | Purpose |
| --- | --- | --- |
| `GET /api/v1/trust-graph/status` | `trust.read` | Read local preview service status and document type metadata. |
| `GET /api/v1/trust-graph/anchors` | `trust.read` | List local trust anchors. |
| `POST /api/v1/trust-graph/anchors` | `trust.write` | Add or replace one local trust anchor. |
| `DELETE /api/v1/trust-graph/anchors/{fingerprint}` | `trust.write` | Remove one local trust anchor. |
| `POST /api/v1/trust-graph/import` | `trust.write` | Import one bounded `crypta.trust.statement.v1` document into the local preview store and record whether its AppVault preview signature verifies. |
| `GET /api/v1/trust-graph/subjects` | `trust.read` | List subjects that have imported trust statement evidence. |
| `GET /api/v1/trust-graph/statements` | `trust.read` | List redacted trust statement summaries with optional filters. |
| `GET /api/v1/trust-graph/score` | `trust.read` | Query a deterministic local score and optional bounded evidence for one subject/context. |
| `POST /api/v1/app-vault/identities/{identityId}/trust-statement` | `trust.write`, `vault.identities.read`, `vault.identities.use` | Ask AppVault to sign one bounded trust statement payload without exporting private identity material. |

`trust.read` lets an app read local trust preview scores and evidence; it does not grant import,
anchor mutation, queue access, vault access, catalog access, moderation authority, or content
blocking. `trust.write` lets an app import trust statements and manage local anchors; it does not
publish anything automatically, export private identity material, or create a global trust policy.

The preview service is intentionally not a full Web of Trust implementation and does not provide
old WebOfTrust plugin compatibility. Trust anchors are local, imported statements are
persisted locally, non-contributing until anchored, and the scorer uses direct local anchors with a simple
confidence-weighted average. No FNP/FCP/wire protocol, routing, datastore, peer-management, or
FProxy browse behavior changes are part of contract v7. See
[trust-graph-preview.md](trust-graph-preview.md).

Contract version 8 adds app-owned, durable, bounded USK content subscriptions under
`/api/v1/content/subscriptions`:

| Route | Required app capabilities | Purpose |
| --- | --- | --- |
| `GET /api/v1/content/subscriptions` | `content.subscribe` | List the caller app's safe subscription metadata. |
| `POST /api/v1/content/subscriptions` | `content.subscribe`, `content.fetch` | Create one bounded USK subscription for the caller app. |
| `GET /api/v1/content/subscriptions/{subscriptionId}` | `content.subscribe` | Read one subscription owned by the caller app. |
| `POST /api/v1/content/subscriptions/{subscriptionId}/refresh` | `content.subscribe`, `content.fetch` | Trigger one bounded foreground refresh of the caller app's subscription. |
| `POST /api/v1/content/subscriptions/{subscriptionId}/pause` | `content.subscribe` | Pause background polling for one caller-owned subscription. |
| `POST /api/v1/content/subscriptions/{subscriptionId}/resume` | `content.subscribe` | Resume background polling and make the subscription due. |
| `DELETE /api/v1/content/subscriptions/{subscriptionId}` | `content.subscribe` | Delete one caller-owned subscription. |

All subscription routes require an app process or app browser principal. Host/operator principals
do not implicitly bypass app scoping for these routes. If an operator-facing subscription console
is needed later, it must be a separate API that names the target app explicitly.

Background subscriptions are intentionally narrower than foreground content fetches. They accept
only `USK@...` and `crypta:USK@...` source URIs, reject local paths, relative paths, query strings,
fragments, whitespace, multiline text, `file:`, `http:`, `https:`, `CHK@`, `SSK@`, and `KSK@`,
and normalize only the safe runtime fetch URI for the bounded `ContentFetchPort`. Creation and
manual refresh require both `content.subscribe` and `content.fetch` because each subscription is a
durable background fetch grant. The background scheduler must also skip apps that are no longer
installed or no longer declare both capabilities.

Subscription summaries are metadata only. They may include the app-owned `sourceUri`, sanitized
`lastSeenResolvedUri`, `lastSeenEdition`, `contentSha256`, byte length, timestamps, status,
failure count, stable error code, update count, and short message. They must not include raw
fetched content, raw request bodies, browser-session tokens, app process tokens, form passwords,
private insert URIs, private keys, absolute staging paths, store root paths, queue HTML, or raw
daemon exception messages. The scheduler records queue pressure with stable runtime signals, not
by parsing legacy queue HTML; when pressure is clear, it records safe statuses such as
`queue_pressure` or `runtime_unavailable`. This is not a generic crawler and does not add
arbitrary HTTP/HTTPS fetch support.

Contract version 9 adds bounded durable app-owned data under `/api/v1/app-data`:

| Route | Required app capabilities | Purpose |
| --- | --- | --- |
| `GET /api/v1/app-data/status` | `app.data.read` | Read the caller app's record count, namespace count, stored bytes, effective caps, quota status, and sanitized warnings. |
| `GET /api/v1/app-data/namespaces` | `app.data.read` | List namespace metadata for the caller app. |
| `GET /api/v1/app-data/namespaces/{namespace}` | `app.data.read` | Read one namespace and its bounded schema migration history. |
| `POST /api/v1/app-data/namespaces/{namespace}/schema` | `app.data.write` | Record a schema-version update or migration summary without executing app-provided code. |
| `DELETE /api/v1/app-data/namespaces/{namespace}` | `app.data.write` | Clear one caller-owned namespace. |
| `GET /api/v1/app-data/records` | `app.data.read` | List bounded record summaries with optional namespace, limit, and cursor filters. |
| `GET /api/v1/app-data/records/{namespace}/{key}` | `app.data.read` | Read one caller-owned record with metadata and bounded value output. |
| `POST /api/v1/app-data/records` | `app.data.write` | Create or replace one bounded caller-owned record. |
| `DELETE /api/v1/app-data/records/{namespace}/{key}` | `app.data.write` | Delete one caller-owned record. |
| `GET /api/v1/app-data/export` | `app.data.read` | Export bounded caller-owned data as a structured JSON payload with base64 values. |
| `POST /api/v1/app-data/import` | `app.data.write` | Import a bounded app-data export in merge or replace-namespace mode. |

All app-data routes require app principals and scope records to
`request.principal().appId()`. Apps never name a host filesystem path or another app id when
accessing records. Namespace and key identifiers are normalized and bounded; record values are
stored under hashed key directories in the file-backed store rather than raw logical path segments.

`app.data.read` grants reads of the caller app's status, namespace metadata, record values, and
bounded exports. `app.data.write` grants create, replace, delete, import, clear, and schema
metadata updates for the caller app only. Store-level caps remain positive even when the manifest
omits `quota.data.bytes` or sets it to zero; positive manifest data quotas are also enforced when
an installed app can be described.

The app-data store is not AppVault, not secret storage, not a generic filesystem API, and not a
database engine. Certification evidence must summarize counts, byte sizes, schema versions, caps,
digests, booleans, and sanitized error codes. It must not include raw app-data values, raw request
bodies, store roots, app data directories, staging paths, private insert URIs, private keys, app
process tokens, browser-session tokens, form passwords, or raw vault secret material. See
[app-data-store.md](app-data-store.md).

Contract version 10 adds durable Trust Graph Preview exchange and audit routes:

| Route | Required app capabilities | Purpose |
| --- | --- | --- |
| `POST /api/v1/trust-graph/import-uri` | `trust.write`, `content.fetch` | Fetch bounded Crypta content by URI, parse one `crypta.trust.statement.v1` document, persist the normalized public statement in the local trust graph store, and return a redacted import summary. |
| `GET /api/v1/trust-graph/audit` | `trust.read` | Read bounded redacted local trust graph mutation and exchange audit entries. |

The existing v7 trust routes remain compatible. Runtime embeddings can still inject an in-memory
store for tests, but the full HTTP runtime wires a shared file-backed trust graph store under the
platform-owned AppHost data tree. The store persists local anchors, imported public statements,
redacted source metadata, and enough public document data to score after restart. It does not
persist raw request bodies, raw fetched content outside normalized trust statement records,
private insert URIs, private identity material, browser-session tokens, form passwords, absolute
paths, or raw signatures.

Contract version 11 adds bounded Social Inbox Preview message signing:

| Route | Required app capabilities | Purpose |
| --- | --- | --- |
| `POST /api/v1/app-vault/identities/{identityId}/social-message` | `vault.identities.read`, `vault.identities.use` | Ask AppVault to sign one bounded `crypta.social.message.v1` plain-text message document for an app-visible identity without exposing a generic browser signing API. |

The social-message route fixes the signing purpose to `crypta.social.message.v1`, uses the server
clock for `createdAt`, bounds subject, body, tags, profile URI, reply metadata, and total canonical
payload bytes, and rejects caller-supplied signing domains, raw payload bytes, or arbitrary signing
purposes. The response contains the public signed document and verification metadata only. It must
not include private key material, private identity material, local vault paths, browser-session
tokens, app process tokens, raw request bodies, domain-separated payload bytes, or private insert
URIs.

This route exists so `apps/social-inbox` can demonstrate a social/mail-like migration spike using
AppVault identity, content insert/fetch/subscriptions, durable app data, and Trust Graph Preview
annotations outside daemon core. It is not full WoT, old plugin ABI compatibility, Freetalk, Sone,
Freemail, encrypted mail transport, a moderation system, a daemon-core message protocol, or a
network protocol change. See [social-inbox-reference-app.md](social-inbox-reference-app.md).

The app secret and identity vault capability names are also part of the app permission vocabulary:
`vault.secrets.read`, `vault.secrets.write`, `vault.identities.read`,
`vault.identities.create`, `vault.identities.use`, and `vault.identities.manage`. They are
documented in [app-secret-and-identity-vault.md](app-secret-and-identity-vault.md). Developer
tooling recognizes those names for manifest validation and UI permission disclosure. Runtime route
authorization still depends on the endpoint descriptors exposed by the node's selected contract
snapshot.

Catalog-backed update lifecycle mutations preserve the catalog capability boundary for app
principals. App principals need `apps.manage` plus `catalogs.manage` for update `check`, `stage`,
and `apply` actions because those routes can refresh signed catalogs, prepare catalog install
plans, or apply catalog-staged bundles. Host/operator calls keep the existing local-management
bypass.

Recommended catalog onboarding follows the catalog capability boundary. Reading recommendations
requires `catalogs.read`; adding a recommendation through
`/app-catalogs/recommended/{catalogId}/add` requires `catalogs.manage` and still uses the verified
signed-catalog add path.

App-update summaries also include scheduler metadata for background catalog refresh and app update
checks. The scheduler fields are path-free and token-free: they expose enabled/status, last and
next check timestamps, result, failure count, sanitized error code, and a short message. The
scheduler does not add new app-facing routes and does not change the default `manual` update
policy.

## App manifest metadata

App manifests may declare optional API compatibility metadata:

```properties
api.minimumVersion=1
api.maximumTestedVersion=1
api.optionalCapabilities=alerts.read,diagnostics.read
api.experimentalCapabilitiesAccepted=false
```

Missing fields remain valid for old apps. `app.permissions` remains the authoritative capability
grant request; `api.optionalCapabilities` is advisory metadata for verification and review.

`api.minimumVersion` means the app expects at least that Platform API contract version.
`api.maximumTestedVersion` means the app was tested up to that contract version. A local node below
the minimum is incompatible. A local node above the maximum-tested version is a warning by default
and a failure in strict verification.

## Catalog metadata

Signed catalogs can mirror or summarize app API compatibility with optional entry fields:

```properties
app.<id>.api.minimumVersion=1
app.<id>.api.maximumTestedVersion=1
app.<id>.api.optionalCapabilities=alerts.read,diagnostics.read
app.<id>.api.experimentalCapabilitiesAccepted=false
```

Bundle manifest metadata remains authoritative for the app artifact. Catalog metadata is display
and review input. Developer tooling flags catalog-vs-bundle API metadata mismatches and permission
mismatches so catalog authors can fix them before signing. Old catalogs without API metadata still
parse and display an `unknown` advisory API compatibility status.

## Developer tooling

Create an offline snapshot:

```bash
crypta-app api snapshot --output build/platform-api-contract.json
```

Verify a staged bundle against the built-in current contract:

```bash
crypta-app compat verify --bundle-dir path/to/staged-app
```

Verify against an explicit target snapshot:

```bash
crypta-app compat verify \
  --bundle-dir path/to/staged-app \
  --contract build/platform-api-contract.json
```

Verify a catalog entry descriptor and referenced bundle:

```bash
crypta-app compat verify \
  --catalog-entry descriptor.properties \
  --contract build/platform-api-contract.json
```

`crypta-app validate --strict` also runs compatibility checks against the current contract.
Malformed `api.*` metadata is always a hard failure. Unknown future capability names,
experimental capability use without `api.experimentalCapabilitiesAccepted=true`, deprecated or
scheduled capabilities, a target above `api.maximumTestedVersion`, and catalog-vs-bundle metadata
mismatches are warnings by default and failures with `--strict`.

## Platform API and Web Shell display

Installed app summaries and catalog app summaries include an `apiCompatibility` object:

```json
{
  "minimumVersion": 1,
  "maximumTestedVersion": 2,
  "currentVersion": 2,
  "optionalCapabilities": [],
  "experimentalCapabilitiesAccepted": false,
  "declared": true,
  "status": "compatible",
  "warnings": []
}
```

Status values are `compatible`, `below_minimum`, `newer_than_tested`, `unknown`, and
`incompatible`. The Web Shell shows the status, current contract version, app minimum version,
maximum-tested version, optional capabilities, and warnings in app/catalog review cards.

## Release certification

`tools/release-certification/app_platform_smoke.py` now emits required
`platform-api.contract` evidence. It generates a contract snapshot with `crypta-app api snapshot`,
records descriptor counts and non-stable entries, and runs offline `crypta-app compat verify`
checks for first-party staged apps and the generated sample app. Profile publishing also has
separate release evidence: `app-platform.identity-profile-publish` for the profile-document route,
`app-platform.generated-document-insert` for the app-generated document insert route, and
`reference-app.profile-publisher` for the first-party Profile Publisher bundle. Networked content
has separate release evidence: `app-platform.content-fetch` for `POST /api/v1/content/fetch`,
`app-platform.content-subscriptions` for the v8 subscription routes,
`network-content.subscription-scheduler` for deterministic bounded scheduler behavior, and
`reference-app.feed-reader` plus `reference-app.feed-reader-subscriptions` for the first-party
Feed Reader bundle. Social Inbox Preview has separate evidence:
`app-platform.social-message-signing` for the bounded v11 AppVault social-message route,
`reference-app.social-inbox`, `reference-app.social-inbox-signed-message`,
`reference-app.social-inbox-subscriptions`, `reference-app.social-inbox-app-data`,
`reference-app.social-inbox-trust-annotations`, and `migration.social-mail-preview`. Trust Graph Preview has
separate evidence: `reference-app.trust-graph` for the first-party app,
`app-platform.trust-graph-preview` for the v7 trust routes and SDK helpers, and
`app-platform.trust-statement-signing` for the bounded AppVault signing route and redaction checks.

In release-candidate mode, missing contract evidence, snapshot generation failure, descriptor
parse failure, or strict compatibility verifier failure blocks promotion unless an explicit
release-manager waiver is recorded in the aggregate certification report.
