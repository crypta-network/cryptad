# Trust Graph Local RC

This document describes the first-party Trust Graph local release-candidate service. The file name
is retained for compatibility with older links that referred to the Trust Graph Preview.

Trust Graph Local RC is a bounded local trust service for one Cryptad node. It lets an operator
curate local anchors, import public signed trust statements, attach local lifecycle policy, and ask
for deterministic direct-anchor scores. It does not crawl the network, publish trust policy to other
nodes, moderate content, block apps or messages, change routing, or claim legacy WebOfTrust,
Freetalk, Sone, or Freemail compatibility.

## Scope and non-goals

The RC service has these release boundaries:

| Boundary | Meaning |
| --- | --- |
| Local anchors only | Scores can use only issuers that the local operator or an authorized local app anchored on this node. |
| Imported public statements only | The store accepts bounded public `crypta.trust.statement.v1` documents from paste, URI import, app-generated publication, or content-subscription flows. |
| No crawling | Trust Graph does not discover statements by walking the network. Durable subscriptions remain owned by the content-subscription layer. |
| No global moderation or blocking | Scores are advisory local annotations. They do not hide content, block apps, mutate feeds, or enforce catalog policy. |
| No routing decisions | Scores never change peer selection, request routing, FProxy browse behavior, content filters, or daemon-core protocols. |
| No legacy compatibility promise | The service does not implement old WebOfTrust plugin APIs, `FCPPluginMessage`, PluginTalker, Freetalk, Sone, Freemail, or old WoT data formats. |

Trust Graph Local RC does not by itself add Social Inbox message threading, ecosystem advisory or
denylist policy, operator RC recovery workflows, or final ecosystem RC certification. Later
release-candidate evidence composes Trust Graph with app-service dependency bundles, Social Inbox
RC threading, network-scale soak, operator RC recovery, and the
`ecosystem.rc-certification` gate. The final gate is documented in
[ecosystem-rc-certification-gate.md](ecosystem-rc-certification-gate.md), and Trust Graph remains
limited to the local RC trust-service scope described here.

## Components

- `:platform-trustgraph` owns the bounded statement model, strict JSON parser, deterministic
  canonical payload writer, fingerprints, local anchors, lifecycle records, durable file-backed
  store, redacted trust audit events, in-memory test store, and direct-anchor scorer.
- `:platform-api` exposes the local `/api/v1/trust-graph/*` route family, `trust.read` and
  `trust.write` capability checks, trust exchange and audit routes, lifecycle management routes,
  app-service discovery/grant routes for the read-only `trust.score` service, and the bounded
  AppVault signing route `POST /api/v1/app-vault/identities/{identityId}/trust-statement`.
- `:platform-sdk-js` exposes `CryptaPlatform.trust.*`,
  `CryptaPlatform.trust.exchange.*`, and
  `CryptaPlatform.vault.identities.createTrustStatement(...)` helpers. SDK helpers are transport
  convenience only; server-side Platform API capability checks remain authoritative.
- `apps:trust-graph` stages the static Trust Graph app with SDK, backend status, URI import,
  statement lifecycle controls, publication, subscription, redacted audit, UI-local app-data state,
  and design-system assets.

## Durable local backend

The runtime wires a shared file-backed trust graph store under platform-owned AppHost state. It
persists local trust anchors, normalized public trust statements, local lifecycle records, redacted
source metadata, and bounded redacted trust audit events across process restart. Reduced
embeddings and unit tests may still inject the in-memory store.

The durable store records canonical public `crypta.trust.statement.v1` documents rather than raw
request bodies or raw fetched content. Statement metadata is bounded and redacted:

- `sourceType`, such as `local-import`, `content-fetch`, `subscription`, or `app-generated`;
- redacted URI kind, such as `crypta-usk`, `crypta-ssk`, `file`, or `unknown`;
- optional sanitized `subscriptionId` and `sourceLabel`;
- imported and last-seen timestamps;
- document fingerprint, payload hash, and signature verification status.

Imports are idempotent by canonical statement fingerprint. Re-importing the same statement updates
safe source and last-seen metadata, but it must not clear a local `deprecated` or `revoked`
lifecycle record. Listing order is deterministic, and retention caps bound anchors, statements,
audit entries, evidence rows, lifecycle notes, source labels, and stored document bytes. Corrupt
persisted entries are ignored safely without exposing local paths or raw document data.

App data remains separate. The Trust Graph app uses app data only for UI-local drafts, filters, and
redacted import summaries. Trust anchors, imported statements, lifecycle records, source metadata,
and scoring state are platform trust graph service state, not app-data backup records.

The staged Trust Graph app declares an app-data migration contract for the UI-local
`ui-state/preview-state` record. Its `ui-state-v1-v2` step points at
`bin/migrate-preview-data.sh`, supports `dry-run` and `apply` modes, validates only fixed
migration environment variables, and is marked rollback-incompatible because schema-v2 UI state is
not guaranteed to be readable by the previous UI bundle. This migration example does not expand
Trust Graph scope into global Web of Trust behavior.

## Trust statement format

Trust statements are public JSON documents with this root type:

```json
{
  "type": "crypta.trust.statement.v1",
  "payload": {
    "issuer": {
      "identityId": "local-or-public-id",
      "publicKeyFingerprint": "...",
      "publicKeyBase64": "optional-x509-public-key",
      "profileUri": "USK@.../profile.json"
    },
    "subject": {
      "kind": "profile",
      "uri": "USK@.../profile.json",
      "fingerprint": "optional-stable-subject-fingerprint"
    },
    "context": "profile",
    "score": 50,
    "confidence": 80,
    "reason": "short bounded text",
    "tags": ["example"],
    "issuedAt": "2026-05-16T00:00:00Z",
    "expiresAt": "2026-11-16T00:00:00Z"
  },
  "signature": {
    "algorithm": "app-vault-ed25519-preview",
    "domain": "crypta.trust.statement.v1",
    "value": "base64-signature-or-preview-signature"
  }
}
```

The parser rejects unknown fields. Subject kind must be one of `profile`, `feed`, `app`,
`identity`, or `uri`. Context must be one of `general`, `profile`, `feed-source`, `app-review`, or
`message-author`. Score is an integer from `-100` to `100`; confidence is an integer from `0` to
`100`. Reason text and tags are bounded and sanitized. `issuedAt` is an ISO-8601 instant; the
signing route generates it server-side. `expiresAt` is optional and must be later than `issuedAt`.
AppVault-created statements include the issuer's public verification key in
`issuer.publicKeyBase64`; imports without a matching key and valid signature are retained only as
non-contributing evidence.

The signed byte sequence is deterministic:

```text
crypta.trust.statement.v1
<canonical-payload-json>
```

Canonical payload JSON has stable field order and stable whitespace. Unknown fields are rejected
before signing or import so apps cannot smuggle unreviewed fields into signatures.

## Lifecycle policy

Lifecycle records are local operator policy, not universal revocation truth. They are keyed by the
canonical statement fingerprint and stored separately from the public statement body.

| Lifecycle state | Scoring behavior | Operator meaning |
| --- | --- | --- |
| `active` | May contribute if every other scoring rule passes. | The local node has no lifecycle policy excluding the statement. |
| `deprecated` | Does not contribute. | The local operator prefers a replacement, updated context, or retired evidence. |
| `revoked` | Does not contribute. | The local operator has explicitly withdrawn local reliance on this statement. |
| `expired` | Does not contribute. | The statement's own `expiresAt` is in the past; this is derived from the statement, not a lifecycle record. |

Lifecycle records include a bounded reason code, sanitized note, optional sanitized replacement URI
summary, created and updated timestamps, optional bounded actor app id, and source such as
`operator`, `app`, or `imported-metadata`. API responses and audit entries expose only lifecycle
summaries. They do not include raw statement JSON, raw signatures, private insert URIs, tokens, or
absolute store paths.

## Local scoring

The scorer is deterministic and intentionally narrow. A statement contributes only when all of
these conditions are true:

- the issuer fingerprint is a local anchor;
- the statement signature is locally verified;
- the statement has not expired;
- confidence is greater than zero;
- lifecycle status is `active`;
- the subject kind, subject URI, and context match the score request.

Statements do not contribute when the issuer is unanchored, the signature is unverified, the
statement is expired, confidence is zero, or lifecycle status is `deprecated` or `revoked`.
Subject/context scores are confidence-weighted averages of contributing direct statements. No
contributing evidence returns `unknown` with score `0` and confidence `0`.

Score explanations are bounded. Evidence rows use stable reason codes such as `unanchored`,
`unverified`, `expired`, `zero-confidence`, `deprecated`, and `revoked`. Rows also expose safe
booleans and status fields such as issuer fingerprint, score, confidence, signature verification,
anchor match, expiry state, lifecycle status, contribution state, and non-contribution reason
codes. Evidence never includes raw statement bodies, raw fetched content, raw signature values,
private insert URIs, private keys, tokens, app-data backup payloads, absolute paths, or unbounded
human text.

`includeEvidence=true` must not create an unbounded response. The status route exposes the current
evidence row limit, statement retention limit, audit retention limit, and lifecycle contribution
rules. Score responses include an `evidenceTruncated` flag or equivalent when matching evidence
exceeds the configured row limit.

## Platform API

The status route returns path-free RC metadata. It should identify `mode=local-rc`, the scope
booleans listed above, the direct-local-anchor scoring method, lifecycle contribution rules, and
store limits without exposing filesystem paths, tokens, private material, or raw statement bodies.

Trust Graph capabilities:

| Capability | Purpose |
| --- | --- |
| `trust.read` | Read local trust status, anchors, subjects, statement summaries, lifecycle summaries, scores, and bounded evidence. |
| `trust.write` | Import trust statements, add or remove local anchors, and mutate local statement lifecycle records. |

Trust routes:

```text
GET  /api/v1/trust-graph/status
GET  /api/v1/trust-graph/anchors
POST /api/v1/trust-graph/anchors
DELETE /api/v1/trust-graph/anchors/{fingerprint}
POST /api/v1/trust-graph/anchors/{fingerprint}/deprecate
POST /api/v1/trust-graph/anchors/{fingerprint}/revoke
POST /api/v1/trust-graph/anchors/{fingerprint}/reactivate
POST /api/v1/trust-graph/import-preview
POST /api/v1/trust-graph/import-preview-uri
POST /api/v1/trust-graph/import
POST /api/v1/trust-graph/import-uri
GET  /api/v1/trust-graph/audit
GET  /api/v1/trust-graph/subjects
GET  /api/v1/trust-graph/statements
GET  /api/v1/trust-graph/statements/{fingerprint}
POST /api/v1/trust-graph/statements/{fingerprint}/deprecate
POST /api/v1/trust-graph/statements/{fingerprint}/revoke
POST /api/v1/trust-graph/statements/{fingerprint}/reactivate
GET  /api/v1/trust-graph/score
```

Contract v10 added the bounded exchange routes `POST /api/v1/trust-graph/import-uri` and
`GET /api/v1/trust-graph/audit`. Contract v15 keeps those routes and adds local lifecycle
management for imported statements. Contract v22 adds the beta hardening preview routes,
`POST /api/v1/trust-graph/import-preview` for pasted documents and
`POST /api/v1/trust-graph/import-preview-uri` for content URI previews, plus local anchor
lifecycle routes.

`POST /api/v1/trust-graph/import-preview` is the beta import preview stage. It requires
`trust.write` for pasted `document` previews and consumes Trust Graph import budget before parsing
candidate statements. URI previews use
`POST /api/v1/trust-graph/import-preview-uri`, whose descriptor requires both `trust.write` and
`content.fetch` before any fetch occurs; they consume Trust Graph import budget before fetching and
the shared content-fetch budget before fetched content is previewed. Both routes parse candidate
statements, compare them against local statement fingerprints and issuer/subject/context keys, and
return only path-free summaries. The preview includes source URI kind, redacted source label,
candidate statement count, accepted count, rejected count, duplicate count, duplicate issuer count,
conflict count, revoked/deprecated/expired count, approximate score impact, material-risk status,
warnings, and limits. Candidate summaries are capped and include fingerprints, subject kind, subject
URI hash, score/confidence, signature verification state, duplicate issuer status, conflict status,
lifecycle status, and expiry state. The preview sets `rawContentDiscarded=true`; release artifacts
and support bundles must not include raw fetched content, raw statement bodies, raw signatures,
private insert URIs, raw app data, tokens, or absolute local paths.

Preview does not mutate the store. A later commit must submit the same document or URI through the
normal import path, consume Trust Graph import budget again, and use the unified consent snapshot
when the preview reports material risk. Duplicate statement ids/digests are idempotent. Duplicate
issuers are summarized deterministically by issuer, subject kind, subject URI, and context, and
conflicting issuer/subject statements are reported as bounded conflict summaries rather than raw
document dumps.

`POST /api/v1/trust-graph/import` accepts form-encoded `document`, optional `sourceUri`, optional
`sourceLabel`, and safe source metadata. It validates size, parses
`crypta.trust.statement.v1`, stores a redacted summary, records whether the signature verifies
against the issuer public key, and returns an import summary without raw private data.

`POST /api/v1/trust-graph/import-uri` accepts a Crypta content URI, optional `sourceLabel`, and an
optional byte cap bounded by trust graph configuration. It uses the same content fetch rules as the
content API, rejects oversized content before parsing, stores only the normalized public trust
statement and redacted source metadata, and never returns raw fetched content. Private insert URIs
must not be stored or exposed.

Platform API v18 adds import budgets. Direct `import` consumes Trust Graph import budget before
parsing a document. `import-preview` consumes the same budget before parsing pasted preview
candidates. `import-preview-uri` and `import-uri` consume both Trust Graph import budget and the
shared content-fetch budget family before fetched content can be previewed or reach the store. If
import budget is exhausted, URI paths do not fetch. If content-fetch budget is exhausted, they do
not preview or import. Safe failures use stable codes such as
`trust_graph_import_budget_exhausted` and `content_fetch_budget_exhausted`.

Local anchor lifecycle routes let an authorized local app or host/operator deprecate, revoke, or
reactivate an anchor by public fingerprint. These are local operator choices, not global truth.
Only active anchors contribute to direct-anchor scores. Deprecated and revoked anchors remain
listed with lifecycle state, update time, and reason code so recovery and support flows can explain
why scores changed without exposing private material.

`GET /api/v1/trust-graph/score` accepts `subjectKind`, `subjectUri`, `context`, and optional
`includeEvidence=true`. The direct route requires `trust.read`. Apps can import statements, manage
anchors, or mutate lifecycle records only when their manifest grants `trust.write`.

Other apps should call scores through the platform-mediated `trust.score` app-service. That
service uses operator-reviewed grant bundles plus active app-service grants, and it requires
`app.services.read`, `app.services.call`, and an active non-expired grant. It is read-only:
app-service consumers cannot import statements, manage anchors, deprecate, revoke, or reactivate
statements through `trust.score`.

The signed Trust Graph manifest advertises:

```text
app.services.provides=trust-score
app.service.trust-score.id=trust.score
app.service.trust-score.name=Trust Score Service
app.service.trust-score.version=1
app.service.trust-score.kind=platform-adapter
app.service.trust-score.adapter=trust-graph.score
app.service.trust-score.scopes=score.read
app.service.trust-score.contexts=message-author,profile
```

Invocation is not a proxy to a Trust Graph app localhost server. The platform dispatches to the
built-in `trust-graph.score` adapter, checks the consumer manifest and active grant at call time,
and returns only a redacted score summary and subject URI hash. Bundle approval and invocation
match provider app id, service id, version `1`, scope `score.read`, context such as
`message-author`, kind `platform-adapter`, and adapter `trust-graph.score`. If a provider update
changes those descriptor fields incompatibly, the grant becomes `revalidation-required` until the
operator explicitly renews or revalidates the bundle. App-service score output must be no more
permissive than direct score output and must preserve evidence limits.

Trust statement subscription management uses the content subscription routes through SDK trust
exchange helpers. This avoids a Trust Graph crawler and keeps subscription ownership, restart
durability, refresh, pause, resume, delete, queue-pressure backoff, and network budget semantics in
the content subscription service.

The bounded signing route is:

```text
POST /api/v1/app-vault/identities/{identityId}/trust-statement
```

It requires `vault.identities.read`, `vault.identities.use`, and `trust.write`. It signs only the
bounded trust statement payload with AppVault. It returns public identity metadata, a payload hash,
the fixed domain, and the public trust statement. It does not export private keys, seed material,
vault paths, raw process tokens, browser session tokens, form passwords, or generic signing access.

## Reference app

`apps:trust-graph` preserves `app.id=trust-graph`. The visible app name may say Trust Graph Local
RC, but compatibility depends on the stable app id. The app declares the trust, content, vault,
queue, and app-data permissions needed for local statement import, publication, subscription,
anchor management, scoring, lifecycle controls, and UI-local state.

The app must keep a persistent warning visible: Trust Graph is local trust only, not global truth,
not moderation, not blocking, not routing policy, and not legacy WoT/Freetalk/Sone/Freemail
compatibility. Its status panel should render the RC scope and limits from
`GET /api/v1/trust-graph/status`. Statement lists should show lifecycle state. Score results
should show bounded contribution status and non-contribution reason codes.

The static app can create or select an app-owned trust identity, ask AppVault to create a bounded
statement, publish it as `application/vnd.crypta.trust+json` with target filename `trust.json`,
import the locally generated public statement into the durable backend, fetch/import selected
Crypta trust documents by URI, manage content subscriptions for trust statement URIs, manage local
anchors, manage local lifecycle records, query scores, show recent queue state, and show redacted
trust audit entries. It uses `CryptaPlatform.data.records.getJson` and `putJson` only for
UI-local state: draft form values, selected filters, and redacted import summaries.

The import UI must preview before committing source fetches or pasted statements. It shows grouped
counts for duplicate statements, duplicate issuers, conflicts, revoked/deprecated/expired
statements, source budget warnings, and approximate score impact. The UI also exposes path-free
anchor lifecycle controls, audit summaries, app-data backup/export/import controls, and a local
scope warning that local anchors are operator choices for this node only.

The app uses SDK helpers rather than hard-coded `/api/v1/` URLs. URI previews call
`CryptaPlatform.trust.previewImport({ uri, ... })`, which fetches through the Trust Graph import
budget and discards the fetched body server-side after producing a redacted candidate summary. The
browser stores only the URI, display label, and previewed `documentFingerprint`; commit calls
`CryptaPlatform.trust.exchange.fetchAndImport({ uri, expectedDocumentFingerprint, ... })`, and the
Platform API rejects the commit with `trust_import_preview_stale` if a mutable source resolves to a
different document. URI fetch/import does not display raw fetched bodies. Pasted statement JSON is
rendered only as text when the operator deliberately imports pasted content. Publication and audit
summaries avoid private insert URIs, private identity material, raw signatures, tokens, and local
paths. Browser persistent storage must not be used for private data, raw statements, app-service
tokens, or app-data backup payloads.

## Redaction

Model `toString()` output, API errors, trust audit entries, authorization audit entries, UI errors,
support bundles, release evidence, and developer-tooling reports must not include raw trust
statement bodies from real users, raw request bodies, raw fetched content, private insert URIs,
queue HTML, private keys, seed material, app process tokens, browser-session tokens, form passwords,
absolute local paths, raw app-data backup payloads, or raw signatures. Release-certification evidence should
use route names, capability labels, booleans, counts, fixture hashes, lifecycle status labels,
reason codes, and redacted summaries. Durable UI-local app-data evidence should similarly use
counts and summary fields instead of raw trust statements, private insert URIs, or raw form bodies.
