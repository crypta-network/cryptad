# Feed Reader reference app

This page describes the first-party Feed Reader reference app and the Platform API v6 content-fetch
surface it exercises.

## Scope

Feed Reader is a first-party static AppHost bundle under `apps/feed-reader`. It demonstrates a
feed-reading and feed-publishing workflow on top of the browser SDK, app-owned UI bootstrap,
bounded content fetches, generated-document inserts, signed first-party catalog metadata, and
release-certification evidence.

The app is not a generic crawler, a catalog fetcher, or a vault/identity app. It should not request
local source-path authority, app-vault permissions, catalog management, or host/operator
credentials.

## Required capabilities

Feed Reader declares these app permissions:

| Permission | Use |
| --- | --- |
| `content.fetch` | Fetch one bounded feed document through `POST /api/v1/content/fetch`. |
| `content.insert.app-document` | Publish generated feed documents without local source-path authority. |
| `queue.write` | Create the generated-document insert request for publishing. |
| `queue.read` | Display upload queue progress after publication. |

`content.fetch` is fetch-only. It does not imply `content.insert`, `queue.write`,
`catalogs.read`, `catalogs.manage`, or any `vault.*` permission.

## SDK flow

The static UI should use the SDK helpers rather than building Platform API forms directly:

```js
await CryptaPlatform.bootstrap.load({ appId: "feed-reader" });

const fetched = await CryptaPlatform.feed.fetchSnapshot({
  uri: feedUri,
  maxBytes: 262144,
  timeoutMillis: 30000,
});

const feed = fetched.snapshot;

await CryptaPlatform.feed.publishSnapshot({
  insertUri,
  identifier,
  snapshot: feedDocument,
});
```

`CryptaPlatform.feed.fetchSnapshot` wraps `POST /api/v1/content/fetch` and parses the canonical
feed snapshot JSON returned by the bounded fetch route. The reference app fetches text first so it
can render canonical snapshots, RSS/Atom entries, or plain text feed previews through the same
bounded route.
`CryptaPlatform.feed.publishSnapshot` wraps the app-generated document insert route. The app can use
`CryptaPlatform.queue.snapshot({ page: "uploads" })` after publication to render local queue
progress.

## Catalog metadata

First-party catalog descriptors for Feed Reader should include explicit categories, review
metadata, API compatibility metadata, and permission rationales:

```properties
app.id=feed-reader
name=Feed Reader & Publisher
permissions=content.fetch,content.insert.app-document,queue.read,queue.write
categories=reader,publishing,content
review.status=reviewed
review.note=First-party feed reference app.
permissions.rationale.content.fetch=Fetches subscribed feed documents through the bounded content fetch route.
permissions.rationale.content.insert.app-document=Queues generated feed documents without local source-path authority.
permissions.rationale.queue.write=Creates generated feed publication inserts.
permissions.rationale.queue.read=Displays publication progress from the local transfer queue.
api.minimumVersion=6
api.maximumTestedVersion=6
api.experimentalCapabilitiesAccepted=false
```

The signed bundle manifest remains authoritative for permissions. Catalog permission rationales
are operator review metadata; they do not grant capabilities.

## Release evidence

Release certification records two required evidence ids for this workflow:

| Evidence id | Required proof |
| --- | --- |
| `app-platform.content-fetch` | `POST /api/v1/content/fetch` is documented, capability-gated by `content.fetch`, represented in the Platform API contract, and covered by redaction evidence. |
| `reference-app.feed-reader` | Feed Reader exists as a first-party static app, declares the expected permissions, uses SDK feed helpers, and publishes generated feed documents without local source-path authority. |

Evidence and reports must not include raw feed bodies, raw request bodies, private insert URIs, app
process tokens, browser-session tokens, form passwords, or local paths.
