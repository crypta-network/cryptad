# Social Inbox Preview reference app

Social Inbox Preview is a first-party static AppHost bundle under `apps/social-inbox`. It
demonstrates that social/mail-like functionality can move outside the daemon, out of daemon core
and legacy plugin surfaces, and into an out-of-process app-platform reference app.

The app composes existing platform surfaces with bounded Platform API v11 signing and v12
app-service grants:

```text
AppVault identity + signed profile/message documents
+ content insert/fetch/subscribe
+ durable app data
+ Trust Graph Preview score annotations through app-service grants
= social/mail-like reference layer outside the daemon
```

This is a migration spike, not a production social network, mail protocol, full WoT
implementation, old plugin ABI compatibility, WebOfTrust plugin compatibility layer,
Freetalk/Sone/Freemail compatibility layer, encrypted mail transport, moderation system,
daemon-core message store, daemon-core message protocol, or network protocol changes.

For broader legacy plugin categories and migration recipes, see
[legacy-plugin-migration-guide.md](legacy-plugin-migration-guide.md).

## App metadata

```text
app.id=social-inbox
app.name=Social Inbox Preview
api.minimumVersion=12
api.maximumTestedVersion=14
api.experimentalCapabilitiesAccepted=true
```

The app declares these permissions:

| Permission | Rationale |
| --- | --- |
| `vault.identities.read` | Lists app-visible public identity metadata for the selected social signing identity. |
| `vault.identities.create` | Creates an app-owned preview identity without exporting private key material. |
| `vault.identities.use` | Calls bounded AppVault signing routes for profile and social message documents. |
| `content.fetch` | Fetches bounded social outbox JSON selected by the user or a subscription. |
| `content.subscribe` | Manages durable app-owned USK social source subscriptions. |
| `content.insert.app-document` | Publishes generated outbox snapshots without local source-path authority. |
| `queue.read` | Displays safe upload queue summaries for generated outbox publication. |
| `queue.write` | Queues generated outbox document inserts. |
| `app.data.read` | Restores bounded sources, summaries, drafts, imported message summaries, and read state. |
| `app.data.write` | Saves bounded app-owned Social Inbox state. |
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
Social Inbox does not duplicate the Profile Publisher app; it keeps profile handling to the
minimum needed to link author metadata to social messages.

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
    "replyTo": "optional message id or URI",
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
  "sourceLabel": "Social Inbox Preview",
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
check, last seen edition, update count, and bounded backoff or error summary. The raw source URI is
passed to the subscription/fetch request path only and is not copied into `social/sources`.

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

## Durable app data

Social Inbox uses the durable app data API for app-owned state:

```text
ui-state/social-inbox
social/sources
social/outbox-summary
social/imported-message-index
social/read-state
social/drafts
```

`social/read-state` tracks read/unread, pinned, archived/hidden, and last viewed timestamp keyed by
validated `msg-<sha256>` message ids.
`social/sources` tracks safe subscription metadata, source URI summaries, and source URI hashes,
not raw source URIs. `social/imported-message-index` stores capped message summaries.
`social/drafts` stores a draft body only when the user explicitly selects the draft checkbox, and
the draft remains bounded.

These records must not contain private identity material, private insert URIs, browser-session
tokens, app process tokens, raw fetched documents, raw signatures, local paths, or generic secrets.

## Trust Score Service Grant

For each message author fingerprint, the app queries Trust Graph Preview through the v12
app-services API:

```text
POST /api/v1/app-services/trust-graph/services/trust.score/invoke
subjectKind=identity
context=message-author
scope=score.read
```

The app first calls `CryptaPlatform.services.get("trust-graph", "trust.score")` and
`CryptaPlatform.services.grants.list()` to show whether the service is discovered and whether its
grant is missing, pending, active, revoked, or inactive. The request button calls
`CryptaPlatform.services.grants.request(...)`, creating a pending grant that the operator must
approve in Web Shell. After approval, author annotations use
`CryptaPlatform.services.invoke("trust-graph", "trust.score", ...)`.

Pending, revoked, inactive, missing, or no-longer-authorized grants are rendered as neutral
`Trust score unavailable / grant required` states. The app must not fall back to
`CryptaPlatform.trust.score` or direct Trust Graph routes after revocation. The result is rendered
as a preview annotation. Scores and evidence counts are displayed when available. Missing or failed
trust evidence is shown as a neutral/unscored badge. The app still shows unscored and untrusted
messages; Trust Graph annotations are not a moderation decision, not content hiding, and not daemon
routing policy.

## Release evidence

PR-242 adds deterministic offline evidence for these ids:

```text
app-platform.social-message-signing
reference-app.social-inbox
reference-app.social-inbox-signed-message
reference-app.social-inbox-subscriptions
reference-app.social-inbox-app-data
reference-app.social-inbox-trust-annotations
reference-app.social-inbox-service-grant
app-services.registry
app-services.grants
app-services.trust-score-provider
app-services.web-shell
app-services.redaction
migration.social-mail-preview
```

Evidence must verify the app exists and stages, declares its permissions, uses the SDK and design
system, signs messages through the bounded AppVault social-message route, publishes generated
outbox documents, manages durable USK subscriptions, persists only safe bounded app data, requests
and uses a mediated Trust Score Service grant for message-author scores, verifies revocation
failure, and documents the migration boundary.

Evidence must not include raw message bodies, raw fetched content, raw request bodies, raw
signatures, private insert URIs, private keys, private identity material, browser-session tokens,
app process tokens, form passwords, local staging paths, or local vault paths.
