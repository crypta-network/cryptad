# Social Inbox Preview

`apps/social-inbox` stages a first-party static AppHost bundle that demonstrates a
social/mail-like migration path outside the daemon core and legacy plugin surface. The app id is
`social-inbox` and the displayed name is `Social Inbox Preview`.

The preview combines AppVault identities, bounded signed social-message documents, generated
app-document inserts, content fetch/subscriptions, durable app data, and Trust Graph Preview
annotations. It is not a production social network, mail protocol, full WoT implementation,
Freetalk/Sone/Freemail compatibility layer, encrypted mail transport, moderation service, or daemon
message store.

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

The app requires Platform API contract 11 because it uses the bounded browser-safe social-message
signing route:

```text
POST /api/v1/app-vault/identities/{identityId}/social-message
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
trust.read
```

## Durable State

Social Inbox Preview stores bounded app-owned records through the app data API:

```text
ui-state/social-inbox
social/sources
social/outbox-summary
social/imported-message-index
social/read-state
social/drafts
```

The app stores safe summaries, source URI summaries/hashes, subscription metadata, read state, and
explicitly saved bounded drafts. It does not persist private insert URIs, raw source URIs, private
identity material, browser-session tokens, raw fetched documents, or raw signature values. Imported
messages are normalized before storage, verified against the signed
`crypta.social.message.v1` canonical payload, and fetched documents are parsed only as bounded JSON
`crypta.social.outbox.v1` snapshots.

## Tests

```bash
./gradlew :apps:social-inbox:test
```
