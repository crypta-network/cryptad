# App-service discovery and grants

Contract v12 adds a local app-service layer for narrowly scoped app-to-app workflows. The platform,
not arbitrary app localhost servers, mediates discovery, grant approval, invocation, audit, and
revocation.

The first proving path is:

```text
Trust Graph Preview advertises trust.score
Social Inbox Preview requests score.read for message-author
the operator approves the grant in Web Shell
Social Inbox invokes trust.score through /api/v1/app-services
revocation makes future invocations fail
```

This is not generic RPC, not a daemon plugin ABI, not remote service discovery, and not a localhost
proxy. There is no ambient localhost trust: apps do not receive ambient access to each other's run
directories, data stores, cache directories, launch tokens, private identity material, or provider
process ports.

## Provider descriptors

Providers declare optional service metadata in their signed `cryptad-app.properties` manifest.
The core manifest parser continues to ignore unknown keys; app-services code parses only the
`app.services.*` properties from installed signed manifests.

Trust Graph Preview declares:

```properties
app.services.provides=trust-score
app.service.trust-score.id=trust.score
app.service.trust-score.name=Trust Score Service
app.service.trust-score.version=1
app.service.trust-score.kind=platform-adapter
app.service.trust-score.adapter=trust-graph.score
app.service.trust-score.scopes=score.read
app.service.trust-score.contexts=message-author,profile
app.service.trust-score.description=Returns a local redacted Trust Graph Preview score summary for an app-provided public subject.
```

`trust-score` is only a path-safe manifest alias. `trust.score` is the public service id used by
discovery, grants, and invocation. `kind=platform-adapter` means the service dispatches to a
registered platform adapter. It does not forward HTTP traffic to a provider app port.

Public descriptors expose provider app id/name/version, service id/name/version, kind, adapter,
scopes, supported contexts, description, stability, and availability. They must not expose
installed paths, data directories, cache directories, process tokens, private keys, raw stores, or
raw app data.

## Consumer requests

Consumers can declare intended service requests in their signed manifest for operator visibility:

```properties
app.services.requests=trust-score
app.service-request.trust-score.provider=trust-graph
app.service-request.trust-score.service=trust.score
app.service-request.trust-score.scopes=score.read
app.service-request.trust-score.contexts=message-author
app.service-request.trust-score.purpose=Annotate Social Inbox message authors using the local Trust Graph Preview score service.
```

Request metadata is transparent intent, not authorization. It does not create or approve a grant.
The consumer still needs `app.services.read` for discovery and grant visibility, and
`app.services.call` for grant request, self-revoke, and invocation routes.

## Grant Lifecycle

Grant records are bounded, deterministic, and safe to serialize in operator-facing JSON. They
record:

- `grantId`
- `consumerAppId`
- `providerAppId`
- `serviceId`
- scopes and contexts
- purpose
- status: `pending`, `active`, `revoked`, `inactive`, or `expired`
- created, updated, approved, revoked, and last-used timestamps
- use count
- optional token fingerprint

PR-243 does not issue raw service bearer tokens. The authenticated app principal plus active grant
record is the access boundary.

Grant behavior is default-deny:

- a consumer app can request a grant, which starts as `pending`;
- apps cannot approve their own grants;
- the host/operator approves or revokes grants in Web Shell;
- apps can list their own consumer grants;
- host/operator can list all grants and redacted audit events;
- revocation takes effect on the next invocation attempt;
- if an app is uninstalled or app state is cleared, related grants become inactive.

Invocation requires all of:

- authenticated app principal;
- consumer manifest still includes `app.services.call`;
- provider app is installed;
- provider manifest still advertises the service;
- active grant exists for consumer/provider/service/scope/context;
- invocation payload passes the adapter's bounded validation.

## Platform API

Routes live under `/api/v1/app-services`:

| Route | App capability or principal | Purpose |
| --- | --- | --- |
| `GET /api/v1/app-services` | `app.services.read` | List public service descriptors and visible request metadata. |
| `GET /api/v1/app-services/{providerAppId}/services` | `app.services.read` | List one provider's advertised services. |
| `GET /api/v1/app-services/{providerAppId}/services/{serviceId}` | `app.services.read` | Read one descriptor. |
| `GET /api/v1/app-services/grants` | `app.services.read` | List caller-visible grants. |
| `POST /api/v1/app-services/grants` | `app.services.call` | Request a pending grant. |
| `POST /api/v1/app-services/grants/{grantId}/approve` | host/operator only | Approve a grant. |
| `POST /api/v1/app-services/grants/{grantId}/revoke` | `app.services.call` for consumer self-revoke; host/operator for any grant | Revoke a grant. |
| `GET /api/v1/app-services/audit` | host/operator only | List redacted audit events. |
| `POST /api/v1/app-services/{providerAppId}/services/{serviceId}/invoke` | `app.services.call` | Invoke a registered adapter through an active grant. |

The Trust Score Service invocation accepts:

```text
subjectKind=identity
subjectUri=crypta:identity:example
context=message-author
scope=score.read
```

The response envelope includes provider app id, service id, grant id, status, invocation timestamp,
and a redacted score result. The result contains a subject URI hash instead of the raw subject URI
and does not include raw Trust Graph statement bodies, raw signatures, store paths, private
identity material, request bodies, tokens, or private insert URIs.

## SDK

Browser apps use `CryptaPlatform.services`:

```js
await CryptaPlatform.services.list();
await CryptaPlatform.services.get("trust-graph", "trust.score");
await CryptaPlatform.services.grants.list();
await CryptaPlatform.services.grants.request({
  providerAppId: "trust-graph",
  serviceId: "trust.score",
  scopes: ["score.read"],
  contexts: ["message-author"],
  purpose: "Annotate message authors.",
});
await CryptaPlatform.services.invoke("trust-graph", "trust.score", {
  subjectKind: "identity",
  subjectUri: "crypta:identity:example",
  context: "message-author",
  scope: "score.read",
});
```

The SDK wraps Platform API routes with form-encoded requests and keeps the app browser session in
memory. It does not log request bodies, cache raw service tokens, expose local paths, or call
provider app ports.

## Operator UI

Web Shell's installed apps view shows:

- advertised service descriptors;
- manifest-declared requests;
- pending, active, revoked, inactive, and expired grants;
- consumer and provider app ids;
- service id, scopes, contexts, purpose, timestamps, last used time, and use count;
- redacted audit event type, reason code, status, and subject hash.

Operators can approve pending grants and revoke pending or active grants. The UI must not display
raw app launch tokens, raw service bearer tokens, private insert URIs, private keys, raw Trust
Graph statement bodies, raw request bodies, or absolute local store paths.

## Reference Apps

Trust Graph Preview provides `trust.score` as a preview-only local service. It is not complete WoT,
not a moderation system, and not a compatibility bridge for old WebOfTrust, Freetalk, Sone, or
Freemail plugin APIs.

Social Inbox Preview declares the service request, requests an operator-approved grant, invokes the
service only through `CryptaPlatform.services.invoke(...)`, and renders a neutral unavailable state
when the grant is missing, pending, revoked, or inactive. It must not fall back to
`CryptaPlatform.trust.score` when the grant boundary denies access.

## Security and Evidence

Release evidence should prove descriptor parsing, pending grant creation, host/operator approval,
successful invocation, revoked invocation failure, Web Shell approve/revoke UI, SDK helpers, and
redaction. Evidence must use safe identifiers, counts, booleans, hashes, route names, and reason
codes. It must not include raw provider app data, Trust Graph store files, raw statement bodies,
raw signatures, raw request bodies, browser-session tokens, app process tokens, form passwords,
private keys, private identity material, private insert URIs, or absolute local paths.
