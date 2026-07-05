# App-service grant migration example

This example shows a migrated app consuming an optional local service through Platform API
app-service grants.

## Trust score dependency

```properties
app.services.requests=trust-score
app.service-request.trust-score.provider=trust-graph
app.service-request.trust-score.service=trust.score
app.service-request.trust-score.scopes=score.read
app.service-request.trust-score.contexts=message-author
app.service-request.trust-score.purpose=Annotate local author summaries with Trust Graph Local RC scores.
app.service-request.trust-score.dependency.kind=optional
app.service-request.trust-score.dependency.required=false
app.service-request.trust-score.dependency.featureId=trust-score-annotations
app.service-request.trust-score.dependency.featureName=Trust score annotations
app.service-request.trust-score.dependency.reason=Show advisory local trust context after operator approval.
app.service-request.trust-score.dependency.degradeBehavior=disable-feature
app.service-request.trust-score.dependency.minServiceVersion=1
app.service-request.trust-score.dependency.maxServiceVersion=1
app.service-request.trust-score.dependency.grantBundle=trust-annotations
app.service-request.trust-score.dependency.grantExpiresAfter=PT720H
```

## Runtime behavior

| Event | App behavior |
| --- | --- |
| Provider unavailable | Show the feature as unavailable. Do not call localhost directly. |
| Grant pending | Request bundle review and keep the feature disabled. |
| Grant revoked or expired | Stop invoking the service. Do not create a direct fallback. |
| Provider descriptor changed | Treat the grant as revalidation-required until the operator renews it. |
| Support bundle generated | Include provider id, service id, scope, context, and status only. No tokens or request bodies. |

App-service calls are mediated by the authenticated app principal, declared capabilities, current
provider descriptor, active grant, scope, and context at invocation time.
