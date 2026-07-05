# Social inbox migration example

This example maps Freetalk/Sone-like social or forum behavior to Social Inbox RC patterns without
Freetalk or Sone protocol compatibility.

## Recommended shape

| Area | Migration choice |
| --- | --- |
| UI | App-owned static UI for local threads, source management, filters, and read state. |
| Identity | AppVault app-owned identity for profile and social-message signing. |
| Documents | `crypta.social.message.v1`, `crypta.social.outbox.v1`, and optional `crypta.profile.v1`. |
| Subscriptions | Budgeted content subscriptions for explicit public social outbox sources. |
| App data | Source summaries, imported-message summaries, drafts, read/unread/archive/pin state, and filters. |
| Trust | Optional `trust.score` grant for advisory author annotations. |

## Manifest outline

```properties
app.id=app-id.example
api.targetStability=experimental
api.experimentalCapabilitiesAccepted=true
app.permissions=vault.identities.read,vault.identities.create,vault.identities.use,content.fetch,content.subscribe,content.insert.app-document,queue.read,queue.write,app.data.read,app.data.write,app.services.read,app.services.call
app.data.schema.current=1
app.data.schema.namespaces=ui-state,social
app.services.requests=trust-score
app.service-request.trust-score.provider=trust-graph
app.service-request.trust-score.service=trust.score
app.service-request.trust-score.scopes=score.read
app.service-request.trust-score.contexts=message-author
app.service-request.trust-score.dependency.kind=optional
app.service-request.trust-score.dependency.degradeBehavior=disable-feature
```

## Migration notes

- Store only summaries and digests for imported social documents.
- Keep message bodies in app data only when they are part of the app's own local state model.
- Keep support bundles to message counts, source digests, schema versions, and redaction status.
- A revoked or expired Trust Graph grant disables annotations and leaves messages visible.
- No daemon-core message store, global moderation, raw FProxy scraping, or old plugin protocol
  compatibility is provided.
