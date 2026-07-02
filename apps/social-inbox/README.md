# Social Inbox RC

`apps/social-inbox` stages a first-party static AppHost bundle that demonstrates local
message-threading, reply, subscription, read-state, and Trust Graph annotation workflows outside
daemon core and legacy plugin surfaces. The app id remains `social-inbox`; the RC display name is
`Social Inbox RC`.

The reference app combines AppVault identities, bounded signed social-message documents, generated
app-document inserts, content fetch/subscriptions, durable app data, local channel filtering and
bounded search, safe author profile links, and an operator-approved Trust Graph Local RC Trust
Score Service grant. It is not a production social network, mail protocol, full WoT
implementation, Freetalk/Sone/Freemail compatibility layer, encrypted mail transport, moderation
service, daemon message store, daemon-core social protocol, or crawler.

## Build

Stage the static AppHost bundle:

```bash
./gradlew :apps:social-inbox:stageApp
```

The staged bundle is written to:

```text
apps/social-inbox/build/cryptad-app/social-inbox
```

Sign and verify with the same inputs used by the other first-party apps:

```bash
./gradlew :apps:social-inbox:signApp
./gradlew :apps:social-inbox:verifyApp
```

The root first-party aggregate tasks also include this app:

```bash
./gradlew stageFirstPartyApps
./gradlew signFirstPartyApps
./gradlew verifyFirstPartyApps
```

## Runtime Surface

The app requires Platform API contract 12 because it uses the bounded browser-safe social-message
signing route and the local app-service grant routes:

```text
POST /api/v1/app-vault/identities/{identityId}/social-message
GET /api/v1/app-services
POST /api/v1/app-services/grants
POST /api/v1/app-services/trust-graph/services/trust.score/invoke
```

The route fixes the signing domain to `crypta.social.message.v1`; the browser app cannot choose an
arbitrary signing purpose or submit arbitrary bytes to sign. Responses contain public verification
material and signed document fields only, never private key material or local vault paths.

The app declares these permissions:

```text
vault.identities.read
vault.identities.create
vault.identities.use
content.fetch
content.subscribe
content.insert.app-document
queue.read
queue.write
app.data.read
app.data.write
app.services.read
app.services.call
```

The signed manifest also declares a transparent service request for Trust Graph Local RC's
`trust.score` service with `score.read` in the `message-author` context. The request does not
approve access by itself; Web Shell must approve the grant before score annotations can run. If the
grant is missing, pending, revoked, or inactive, the UI keeps messages visible and shows a neutral
trust-score unavailable state.

## Content format profiles

Social Inbox uses `CryptaPlatform.contentFormats.profileDocument`,
`CryptaPlatform.contentFormats.socialMessage`, and `CryptaPlatform.contentFormats.socialOutbox`.
Social messages use `crypta.social.message.v1` and signed bytes consisting of the signing domain,
one newline, and canonical message JSON. Outbox snapshots use `crypta.social.outbox.v1`,
`application/vnd.crypta.social.outbox+json`, `social-outbox.json`, and bounded signed-message
entries. Imports reject malformed documents, unsupported versions, deprecated versions according
to profile policy, oversized documents, unsupported message formats, and
signature/canonicalization mismatches without persisting raw fetched documents, raw message bodies,
raw profile documents, raw signatures, private insert URIs, tokens, raw app-data values, or local
paths.

These content profiles are Crypta app ecosystem profiles. They are not compatibility promises for
legacy WoT, Freetalk, Sone, Freemail, or any old plugin ABI/protocol.

## Durable State

Social Inbox RC stores bounded app-owned records through the app data API:

```text
ui-state/social-inbox
social/sources
social/outbox-summary
social/imported-message-index
social/read-state
social/drafts
```

The app stores safe summaries, source URI summaries/hashes, subscription metadata, UI filters,
message read state used for thread-level actions, and explicitly saved bounded drafts. It does not persist private
insert URIs, raw source URIs, private identity material, browser-session tokens, raw fetched
documents, raw profile documents, or raw signature values. Imported messages are normalized before
storage, verified against the signed `crypta.social.message.v1` canonical payload, and fetched
documents are parsed only as bounded JSON `crypta.social.outbox.v1` snapshots. Threading is local:
`replyTo` links are validated as safe `msg-<sha256>` ids, malformed parents become roots, and
cycles are broken before rendering.

The signed manifest declares the existing `ui-state` and `social` namespaces at schema 1. PR-252
keeps the new thread, filter, and source-summary fields additive under that schema because the
current production app-update migration runner still fails closed before executing signed
migration commands. Do not add Social Inbox update-time migration metadata until that runner can
execute migrations for installed apps without blocking updates.

## App-data backup scope

Operator app-data backups for `social-inbox` include the durable records listed above: UI
selection state, channel/read/archive filters, bounded source summaries/hashes, subscription
metadata, outbox summaries, imported-message index summaries, message read state that drives
thread actions, and
explicitly saved drafts. Treat exported backups as sensitive user data because saved drafts, source
summaries, author relationships, and read state can reveal private social context.

Backups do not include AppVault private identity material, vault private identity material, raw
source URIs, private insert URIs, raw fetched documents, raw signatures, browser-session tokens,
app-service tokens, app-service grant tokens, Trust Graph service grant state, app bundle files, or
local paths. Restoring a backup rehydrates Social Inbox UI state and drafts; Trust Graph service
access still depends on the target node's current operator-approved grant state.

## Tests

```bash
./gradlew :apps:social-inbox:test
```

## Beta readiness

- Current beta support level: `local-rc`, owned by `crypta-core`, with
  `app.beta.readiness=ready`.
- Empty/error/retry states: the staged UI shows an empty sources/messages state, bounded
  subscription/message/import/trust-score failure states, and retry refresh/resubscribe/reload
  score actions.
- App-data backup/export/import status: operator-supported for durable source summaries, imported
  message indexes, read state, filters, outbox summaries, and explicitly saved drafts. Trust Graph
  service grants and AppVault identity material are outside this app-data backup.
- Migration dry-run status: `additive-not-required` for schema 1 social records; future
  non-additive schema changes must add migration metadata before update.
- Permission rationale summary: vault identity, content subscription/fetch/insert, queue,
  app-data, and optional Trust Graph score grant permissions each have manifest rationale and
  visible disclosure.
- Support/recovery path: the recovery action points operators to resubscribe, refresh Trust Graph
  score grants, export/import app data, and RC recovery support guidance.
- Diagnostic redaction promise: diagnostics are `redacted-summary-only` and do not expose raw
  messages, identity material, private insert URIs, app-service tokens, browser-session tokens, raw
  app-data values, or local paths.
- Known limitations: Social Inbox RC is not Freemail/Freetalk/Sone protocol compatibility, not
  encrypted mail transport, not a full WoT, and not a daemon-core social or mail protocol.
