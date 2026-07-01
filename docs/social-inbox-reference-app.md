# Social Inbox RC reference app

Social Inbox RC is a first-party static AppHost bundle under `apps/social-inbox`. It demonstrates
local message-threading, reply, subscription, and read-state workflows outside daemon core and
legacy plugin surfaces.

The app composes existing platform surfaces with bounded Platform API v11 signing and v12
app-service grants:

```text
AppVault identity + signed profile/message documents
+ content insert/fetch/subscribe
+ durable app data with an additive signed schema-1 namespace contract
+ local thread, channel, search, read-state, filter, and export UI
+ Trust Graph Local RC score annotations through app-service grants
= Social Inbox RC reference layer outside the daemon
```

This is a reference app, not a production social network, mail protocol, full WoT implementation,
old plugin ABI compatibility, WebOfTrust plugin compatibility layer, Freetalk/Sone/Freemail
compatibility layer, encrypted mail transport, moderation system, daemon-core message store,
daemon-core message protocol, crawler, or network protocol change.

For broader legacy plugin categories and migration recipes, see
[legacy-plugin-migration-guide.md](legacy-plugin-migration-guide.md).

## App metadata

```text
app.id=social-inbox
app.name=Social Inbox RC
api.minimumVersion=16
api.maximumTestedVersion=23
api.targetStability=experimental
api.experimentalCapabilitiesAccepted=true
app.data.schema.current=1
app.data.schema.namespaces=ui-state,social
app.data.schema.namespace.ui-state.current=1
app.data.schema.namespace.social.current=1
```

The app id remains `social-inbox` so installed app ownership and durable app-data namespaces stay
stable across the Preview-to-RC promotion.

The app declares these permissions:

| Permission | Rationale |
| --- | --- |
| `vault.identities.read` | Lists app-visible public identity metadata for the selected social signing identity. |
| `vault.identities.create` | Creates an app-owned Social Inbox identity without exporting private key material. |
| `vault.identities.use` | Calls bounded AppVault signing routes for profile and social message documents. |
| `content.fetch` | Fetches bounded social outbox JSON selected by the user or a subscription. |
| `content.subscribe` | Manages durable app-owned USK social source subscriptions. |
| `content.insert.app-document` | Publishes generated outbox snapshots without local source-path authority. |
| `queue.read` | Displays safe upload queue summaries for generated outbox publication. |
| `queue.write` | Queues generated outbox document inserts. |
| `app.data.read` | Restores bounded sources, summaries, drafts, imported message summaries, UI filters, and message read state used for thread actions. |
| `app.data.write` | Saves bounded app-owned Social Inbox state under the additive schema-1 record contract. |
| `app.services.read` | Discovers the local Trust Score Service descriptor and caller-visible grant state. |
| `app.services.call` | Requests and invokes an approved local `trust.score` service grant. |

The signed manifest also declares a transparent service request:

```text
app.services.requests=trust-score
app.service-request.trust-score.provider=trust-graph
app.service-request.trust-score.service=trust.score
app.service-request.trust-score.scopes=score.read
app.service-request.trust-score.contexts=message-author
```

This metadata is visible to operators and catalog review, but it does not auto-approve a grant.

## Identity and profile metadata

The app uses AppVault app-owned identities. The browser UI can list and create identity records,
but it sees only public metadata such as identity id, public fingerprint, display label, and public
verification material. It never receives private key material, seed material, encrypted vault
envelopes, or local vault paths.

Profile metadata is optional. The app reuses the bounded profile-document route through the SDK so
authors can prepare a signed public profile document or attach a public profile URI to messages.
Imported messages may show an author label, a bounded fingerprint summary, and a validated public
Crypta profile URI as a copyable app-controlled value. The app does not fetch profile documents
automatically and does not store raw profile documents. Social Inbox does not duplicate the Profile
Publisher app; it keeps profile handling to the minimum needed to link author metadata to social
messages.

## Signed social message document

Platform API contract v11 adds:

```text
POST /api/v1/app-vault/identities/{identityId}/social-message
```

The route is a browser-safe bounded signing route, not a generic browser signing API. It fixes the
signing domain to:

```text
crypta.social.message.v1
```

The app cannot choose another domain, cannot submit arbitrary canonical bytes, and cannot request
general-purpose AppVault signing from browser JavaScript. The route uses the server clock for
`createdAt`, validates field sizes, requires `format=text/plain`, and produces domain-separated
signatures over deterministic canonical JSON for this public document shape:

```json
{
  "type": "crypta.social.message.v1",
  "message": {
    "appId": "social-inbox",
    "identityId": "<app-owned-identity-id>",
    "authorFingerprint": "<public-fingerprint>",
    "authorLabel": "optional display label",
    "profileUri": "crypta:USK@<public-profile-key>/profile/1/profile.json",
    "messageId": "msg-<payload-hash>",
    "createdAt": "2026-05-27T00:00:00Z",
    "channel": "general",
    "subject": "bounded subject",
    "body": "bounded plain text body",
    "format": "text/plain",
    "replyTo": "optional msg-<sha256> parent message id",
    "recipientFingerprint": "optional public recipient fingerprint",
    "tags": ["bounded", "tags"]
  },
  "signature": {
    "algorithm": "Ed25519",
    "domain": "crypta.social.message.v1",
    "payloadHash": "<sha256-hex>",
    "publicKeyFingerprint": "<public-fingerprint>",
    "publicKeyBase64": "<public-verification-key>",
    "signatureBase64": "<public-signature-bytes>"
  }
}
```

When importing remote outboxes, the app rejects messages whose `messageId` is not the route-style
`msg-<sha256>` value recomputed from the canonical public message payload without the `messageId`
field. Read-state keys are accepted only for that safe generated shape, so imported content cannot
choose object-prototype names or collide with another signed payload's identifier.

RC threading uses the existing signed `message.replyTo` field. A reply links only to another safe
`msg-<sha256>` id in the imported or local message set. Missing parents become local thread roots,
and cycle detection breaks malformed reply graphs before rendering. The UI caps rendered thread
depth and total message counts, sorts pinned threads first, then by the most recent message
timestamp, and sorts replies by timestamp and message id.

The signing response contains public verification material only. Release evidence and logs must not
include raw request bodies, raw message bodies, raw signatures, private identity material,
browser-session tokens, app process tokens, local vault paths, or private insert URIs.

## Outbox publication

Social Inbox keeps signed local messages in memory while composing an outbox snapshot. Publication
uses the generated app-document insert route through the SDK:

```text
POST /api/v1/queue/inserts/app-document
```

The generated outbox document is bounded JSON:

```json
{
  "type": "crypta.social.outbox.v1",
  "appId": "social-inbox",
  "generatedAt": "2026-05-27T00:00:00Z",
  "profileUri": "crypta:USK@<public-profile-key>/profile/1/profile.json",
  "sourceLabel": "Social Inbox RC",
  "messages": []
}
```

The user may enter an insert URI for a publication action. The app passes that value to the insert
route for that request only. It stores only safe summaries in `social/outbox-summary`: identifier,
target filename, content type, message count, redacted public source URI summary when supplied,
public source URI SHA-256, queue request id, document SHA-256, and status. It does not persist
private insert URIs or raw source URIs in app data, browser storage, release evidence, logs, or docs
examples.

## Sources and subscriptions

The app follows remote social sources with durable content subscriptions from Platform API v8 and
bounded content fetch from Platform API v6. Sources must be `USK@...` or `crypta:USK@...` social
outbox URIs. App data stores source labels, subscription ids, URI summaries/hashes, status, last
checked time, last seen edition, update count, and bounded backoff or error summary. The raw
source URI is passed to the subscription/fetch request path only and is not copied into
`social/sources`.

Platform API v18 budgets foreground fetches, manual subscription refreshes, scheduler polls, and
Trust Graph import-by-URI work. Social Inbox inherits those shared app/global limits and is not a
crawler. Refresh-all is capped by the app's source limit and requests subscription refreshes
sequentially. Queue pressure may delay polls without consuming budget, and budget exhaustion records
safe `budget_exhausted`/retry metadata rather than raw daemon exceptions. The UI surfaces queue
pressure, runtime unavailable, backoff, budget exhausted, and stale source states without hiding,
archiving, moderating, or blocking messages.

Manual import fetches the current resolved source using `content.fetch`, parses only bounded JSON
objects with `type=crypta.social.outbox.v1`, and imports only bounded signed
`crypta.social.message.v1` entries. Unsupported document types, unsupported message formats,
oversized documents, malformed signatures, and unknown dangerous shapes are rejected.

Imported app data stores normalized message summaries rather than raw fetched documents. The
summary includes bounded subject, bounded body preview, body SHA-256, source metadata, author
fingerprint, public profile URI, signature SHA-256, timestamps, and import time. Imported messages
must pass bounded field validation and Ed25519 verification against the signed
`crypta.social.message.v1` canonical payload before Trust Graph annotations are queried. Release
evidence must redact raw fetched content and raw message bodies.

When the same safe `messageId` appears from multiple sources, dedupe keeps the verified canonical
message summary and preserves bounded source summaries such as source id, label, URI hash,
first-import time, last-seen time, and seen count. It must not store raw fetched documents, raw
source URIs, raw signatures, or full raw message bodies.

Changing the local channel filter or search query does not fetch network content. Channel names are
bounded and malformed values fall back to `general`. Search runs only over already imported bounded
summaries such as subject, author label, fingerprint summary, channel, tags, body preview, and
source label.

## Durable app data

Social Inbox uses the durable app data API for app-owned state:

```text
ui-state/social-inbox
social/sources
social/outbox-summary
social/imported-message-index
social/read-state
social/drafts
social/local-filters
```

`ui-state/social-inbox` stores bounded UI selections such as channel and read/archive filters.
`social/read-state` tracks message read/unread, pin/archive state, and last viewed timestamp keyed
by validated `msg-<sha256>` message ids. Thread-level read/unread/archive/pin actions are derived
from those validated message records, so PR-252 does not add a separate durable thread record.
`social/sources` tracks safe subscription metadata, source URI summaries, and source URI hashes,
not raw source URIs. `social/imported-message-index` stores capped message summaries.
`social/drafts` stores a draft body only when the user explicitly selects the draft checkbox, and
the draft remains bounded.

The signed manifest declares `ui-state` at schema 1 and `social` at schema 1. The beta hardening
records for local filters, read state, redacted export metadata, and source pause state are additive
schema-1 records so existing Social Inbox RC installs can update without launching a local migration
process. Social Inbox does not currently declare `social-v1-v2`; that migration remains deferred
until the production migration runner can prove executable process containment. A future schema bump
must use the unified update consent preview, snapshot digest binding, stale approval rejection, and
backup-before-update flow before replacing the installed bundle.

These records must not contain private identity material, private insert URIs, browser-session
tokens, app process tokens, raw fetched documents, raw signatures, local paths, or generic secrets.

## Local filters and export

Source pause/resume is a local subscription control. Pausing a source stops refresh requests for
that source until the user resumes it, and the app preserves the paused state in app-owned data.
Blocking a source locally and muting an author locally are UI filters only. They do not publish
moderation metadata, modify the network, revoke trust statements, or change what other nodes see.

Social Inbox persists local filters in `social/local-filters` as bounded author and source keys.
The UI still keeps the underlying imported summaries available for backup/restore and for an
operator who later unmutes or unblocks the source. Release evidence must summarize muted author
counts and blocked source counts without exposing raw source URIs, raw profile bodies, or raw
message bodies.

Message export is bounded and redacted. The app can export visible message summaries, a thread
summary, or one selected message summary. Export payloads include app id, schema version, export
kind, message count, source/app/schema metadata, body preview and body SHA-256, profile URI
summary, trust annotation summary, and local filter counts. They do not include private material,
raw signatures, raw fetched source documents, raw message bodies, bearer tokens, browser session
tokens, private insert URIs, raw app data dumps, or absolute local paths.

## Trust Score Service Dependency

For each message author fingerprint, the app queries Trust Graph Local RC through the app-services
API:

```text
POST /api/v1/app-services/trust-graph/services/trust.score/invoke
subjectKind=identity
context=message-author
scope=score.read
```

The app first calls `CryptaPlatform.services.get("trust-graph", "trust.score")` and
`CryptaPlatform.services.grants.list()` to show whether the service is discovered and whether its
grant is missing, pending, active, revoked, expired, inactive, or revalidation-required. The signed
manifest declares the dependency as optional:

```properties
app.service-request.trust-score.dependency.kind=optional
app.service-request.trust-score.dependency.required=false
app.service-request.trust-score.dependency.featureId=trust-score-annotations
app.service-request.trust-score.dependency.featureName=Trust score annotations
app.service-request.trust-score.dependency.degradeBehavior=disable-feature
app.service-request.trust-score.dependency.minServiceVersion=1
app.service-request.trust-score.dependency.maxServiceVersion=1
app.service-request.trust-score.dependency.grantBundle=trust-annotations
app.service-request.trust-score.dependency.grantExpiresAfter=PT720H
```

The request button calls `CryptaPlatform.services.bundles.request(...)`, creating or reusing a
pending `trust-annotations` bundle that the operator must approve in Web Shell. Bundle approval
revalidates the signed consumer manifest and current Trust Graph provider descriptor before it
activates the grant. After approval, author annotations use
`CryptaPlatform.services.invoke("trust-graph", "trust.score", ...)`.

Pending, rejected, revoked, expired, inactive, missing, revalidation-required, or
no-longer-authorized grants are rendered as neutral unavailable states such as
`Trust score unavailable / grant required`, `Trust score unavailable / grant expired`, or
`Trust score unavailable / grant requires operator revalidation`. The app must not fall back to
`CryptaPlatform.trust.score` or direct Trust Graph routes after revocation or revalidation failure.
The result is rendered as annotations only. Scores and evidence counts are displayed when
available. Missing or failed trust evidence is shown as a neutral/unscored badge. The app still
shows unscored and untrusted messages; Trust Graph annotations are not a moderation decision, not
content hiding, and not daemon routing policy. Trust score values do not hide, archive, sort by
policy, block replies, trigger network fetches, or change subscription behavior.

## Beta readiness

Social Inbox RC participates in `first-party-app.beta-quality-pass`. The staged UI must show an
empty sources/messages state, bounded subscription/message/import/trust-score errors, retry
refresh/resubscribe/reload-score actions, visible permission rationales, app-data export/import
status, additive schema-1 migration status, support metadata, an ARIA live status region,
design-system classes, and `redacted-summary-only` diagnostics. The UI and docs must keep the
scope visible: Social Inbox RC is not Freemail/Freetalk/Sone protocol compatibility, not encrypted
mail transport, not a full WoT, and not a daemon-core social or mail protocol.

## Release evidence

Deterministic offline evidence for Social Inbox includes these ids:

```text
app-platform.social-message-signing
reference-app.social-inbox
reference-app.social-inbox-signed-message
reference-app.social-inbox-subscriptions
reference-app.social-inbox-app-data
reference-app.social-inbox-trust-annotations
reference-app.social-inbox-service-grant
reference-app.social-inbox-service-dependency
reference-app.social-inbox-rc-threading
app-platform.trust-social-beta-hardening
network-scale.subscription-budget
network-scale.queue-pressure-backoff
network-scale.social-inbox-multi-source-soak
network-scale.redaction
network-scale.rc-soak-summary
app-services.registry
app-services.grants
app-services.dependency-graph
app-services.grant-bundles
app-services.grant-expiry-renewal
app-services.provider-revalidation
app-services.trust-score-provider
app-services.web-shell
app-services.redaction
app-services.dependency-redaction
migration.social-mail-preview
```

Evidence must verify the app exists and stages, preserves `app.id=social-inbox`, declares its
permissions, uses the SDK and design system, signs messages through the bounded AppVault
social-message route, publishes generated outbox documents, manages durable USK subscriptions,
persists only safe bounded app data, builds local threads from `replyTo`, supports channel
filtering and bounded local search, persists read/unread state, renders safe author/profile
metadata, supports source pause/resume, local mute/block filters, and bounded redacted message
export, requests the `trust-annotations` bundle, uses a mediated Trust Score Service grant for
message-author scores, verifies expiry/revocation/provider-revalidation failure, and documents the
additive schema-1 beta data boundary and deferred executable migration requirement.

Evidence must not include raw message bodies, raw fetched content, raw request bodies, queue HTML,
raw signatures, private insert URIs, private keys, private identity material, browser-session
tokens, app process tokens, form passwords, local staging paths, absolute local paths, or local
vault paths.
