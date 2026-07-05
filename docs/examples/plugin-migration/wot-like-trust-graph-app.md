# WoT-like trust graph app migration

This example maps a WebOfTrust-like plugin to Trust Graph Local RC without old WebOfTrust plugin
API compatibility.

## Recommended shape

| Area | Migration choice |
| --- | --- |
| App role | Trust app or Trust Graph Local RC contributor. |
| Consumer role | Optional app-service consumer of `trust-graph` / `trust.score`. |
| Content profile | `crypta.trust.statement.v1`. |
| App data | UI drafts, import previews, filter state, and redacted import summaries only. |
| AppVault | App-owned identity and bounded trust-statement signing. |
| Review path | Experimental app review with threat model, trust-statement profile notes, app-data schema, grant rationale, and redaction scan. |

## Consumer manifest outline

```properties
app.id=app-id.example
api.targetStability=experimental
api.experimentalCapabilitiesAccepted=true
app.permissions=app.services.read,app.services.call,app.data.read,app.data.write
app.services.requests=trust-score
app.service-request.trust-score.provider=trust-graph
app.service-request.trust-score.service=trust.score
app.service-request.trust-score.scopes=score.read
app.service-request.trust-score.contexts=profile
app.service-request.trust-score.dependency.kind=optional
app.service-request.trust-score.dependency.degradeBehavior=disable-feature
app.service-request.trust-score.dependency.grantBundle=trust-annotations
```

## Safe migration artifact

```json
{
  "legacyPluginId": "weboftrust-like.example",
  "newAppId": "app-id.example",
  "stateClasses": ["public-trust-statements", "local-ui-state", "operator-anchors"],
  "appDataNamespaces": ["ui-state", "imports"],
  "contentSubscriptions": ["crypta:USK@<example-public-read-key>/trust/1/trust.json"],
  "appServiceDependencies": ["trust-graph:trust.score:score.read:profile"],
  "reviewEvidence": ["api-compatibility", "ui-lint", "redaction-scan"],
  "redactionPolicy": "summaries, digests, statement counts, and grant status only",
  "knownNonGoals": ["old WebOfTrust API", "global moderation", "routing policy"]
}
```

The safe URI is a placeholder public read key. Do not include private insert URIs, raw trust
statements, signatures, or private identity material in migration artifacts.
