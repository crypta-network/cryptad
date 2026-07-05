# Future Mail app pattern

This example is a design outline for Freemail-like authors. It does not implement Freemail,
encrypted mail transport, or Freemail protocol compatibility.

## Public-beta stance

Future Mail should be an out-of-process app or app-service. It is not implemented in PR-279. It
should keep message body storage in app data, identities and keys behind AppVault grants, and any
local service calls behind declared app-service dependencies and operator-approved grant bundles.

Social Inbox RC can inform thread and message-list UX, but it is not a mail protocol
implementation.

## Manifest outline

```properties
app.id=mail-pattern.example
app.name=Future Mail Pattern Example
api.targetStability=experimental
api.experimentalCapabilitiesAccepted=true
app.permissions=vault.identities.read,vault.identities.use,content.fetch,content.subscribe,app.data.read,app.data.write,app.services.read,app.services.call
app.data.schema.current=1
app.data.schema.namespaces=mail-ui,mail-store
app.services.requests=trust-score
app.service-request.trust-score.provider=trust-graph
app.service-request.trust-score.service=trust.score
app.service-request.trust-score.scopes=score.read
app.service-request.trust-score.contexts=message-author
app.service-request.trust-score.dependency.kind=optional
app.service-request.trust-score.dependency.degradeBehavior=disable-feature
```

## Required review notes

- threat model and privacy rationale;
- message storage schema and retention bounds;
- identity/AppVault grant use;
- backup/restore and migration behavior;
- subscription or polling budget behavior;
- optional service dependency and degrade behavior;
- redaction policy for diagnostics and support.

Encrypted mail transport, address exchange, delivery semantics, and compatibility with any legacy
mail plugin protocol are future work and are not implemented by PR-279.
