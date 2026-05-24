# Feed Reader reference app

This page describes the first-party Feed Reader reference app and the Platform API v8
content-subscription surface it exercises.

## Scope

Feed Reader is a first-party static AppHost bundle under `apps/feed-reader`. It demonstrates a
feed-reading and feed-publishing workflow on top of the browser SDK, app-owned UI bootstrap,
durable USK subscription metadata, bounded content fetches, generated-document inserts, signed
first-party catalog metadata, and release-certification evidence.

The app is not a generic crawler, an arbitrary HTTP/HTTPS fetcher, a catalog fetcher, or a
vault/identity app. It should not request local source-path authority, app-vault permissions,
catalog management, or host/operator credentials.

## Required capabilities

Feed Reader declares these app permissions:

| Permission | Use |
| --- | --- |
| `content.fetch` | Fetch one bounded feed document through `POST /api/v1/content/fetch`, including on-demand rendering of a subscribed feed's current resolved URI. |
| `content.subscribe` | Register and manage app-owned bounded USK subscriptions through `/api/v1/content/subscriptions`. |
| `content.insert.app-document` | Publish generated feed documents without local source-path authority. |
| `queue.write` | Create the generated-document insert request for publishing. |
| `queue.read` | Display upload queue progress after publication. |

`content.fetch` is fetch-only. `content.subscribe` grants subscription metadata and controls, not
raw fetched content storage. Creating or refreshing a subscription requires both capabilities
because the subscription is a durable background fetch grant. Neither capability implies
`content.insert`, `queue.write`, `catalogs.read`, `catalogs.manage`, or any `vault.*` permission.

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

const { subscription } = await CryptaPlatform.content.subscriptions.create({
  uri: "USK@example/feed/0/feed.json",
  label: "Example feed",
  pollIntervalSeconds: 1800,
  maxBytes: 262144,
  timeoutMillis: 30000,
});

await CryptaPlatform.content.subscriptions.refresh(subscription.subscriptionId);

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
`CryptaPlatform.content.subscriptions.*` wraps `/api/v1/content/subscriptions` and lets the app
create, list, inspect, refresh, pause, resume, and delete its own USK subscriptions. Subscription
sources are limited to `USK@...` and `crypta:USK@...`. The app displays scheduler status, last
check, last seen edition, update count, and stable errors from subscription metadata. When
`lastSeenResolvedUri` changes, the app may fetch and render that current document on demand with
the existing content/fetch or feed helpers.
`CryptaPlatform.feed.publishSnapshot` wraps the app-generated document insert route. The app can use
`CryptaPlatform.queue.snapshot({ page: "uploads" })` after publication to render local queue
progress.

The previous browser-tab-only follow timer is not the durable path. The reference app uses the
platform scheduler when `CryptaPlatform.content.subscriptions` is available; any manual fetch path
is only a local fallback for environments without the v8 helper.

## Catalog metadata

First-party catalog descriptors for Feed Reader should include explicit categories, review
metadata, API compatibility metadata, and permission rationales:

```properties
app.id=feed-reader
name=Feed Reader & Publisher
permissions=content.fetch,content.subscribe,content.insert.app-document,queue.read,queue.write
categories=reader,publishing,content
review.status=reviewed
review.note=First-party feed reference app.
permissions.rationale.content.fetch=Fetches subscribed feed documents through the bounded content fetch route.
permissions.rationale.content.subscribe=Registers bounded USK feed subscriptions with the platform scheduler and stores metadata only.
permissions.rationale.content.insert.app-document=Queues generated feed documents without local source-path authority.
permissions.rationale.queue.write=Creates generated feed publication inserts.
permissions.rationale.queue.read=Displays publication progress from the local transfer queue.
api.minimumVersion=8
api.maximumTestedVersion=8
api.experimentalCapabilitiesAccepted=false
```

The signed bundle manifest remains authoritative for permissions. Catalog permission rationales
are operator review metadata; they do not grant capabilities.

## Release evidence

Release certification records these required evidence ids for this workflow:

| Evidence id | Required proof |
| --- | --- |
| `app-platform.content-fetch` | `POST /api/v1/content/fetch` is documented, capability-gated by `content.fetch`, represented in the Platform API contract, and covered by redaction evidence. |
| `app-platform.content-subscriptions` | `/api/v1/content/subscriptions` is documented, capability-gated by `content.subscribe` plus `content.fetch` for create/refresh, app-principal scoped, represented in contract v8, and covered by redaction evidence. |
| `network-content.subscription-scheduler` | The background scheduler has deterministic offline evidence for bounded due checks, per-app/global/per-tick limits, backoff, dedupe, queue pressure handling with no queue HTML parsing, and path-free durable metadata. |
| `reference-app.feed-reader` | Feed Reader exists as a first-party static app, declares the expected permissions, uses SDK feed helpers, and publishes generated feed documents without local source-path authority. |
| `reference-app.feed-reader-subscriptions` | Feed Reader declares `content.subscribe`, requires API v8, uses platform subscription helpers, and no longer relies on a tab-local follow loop as the durable follow path. |

Evidence and reports must not include raw feed bodies, raw fetched content, raw request bodies,
private insert URIs, app process tokens, browser-session tokens, form passwords, private keys,
absolute staging paths, store root paths, queue HTML, or local paths. Subscription state is
metadata only and is not a generic app data store.
