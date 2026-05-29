# Trust Graph Preview

Trust Graph Preview is a first-party reference app and local Platform API preview service for
bounded trust statements. It demonstrates that a future WoT-like trust layer can live outside the
daemon and network core while using AppHost, AppVault, app-owned browser sessions, content fetch,
generated document inserts, signed catalog metadata, review receipts, and release-certification
evidence.

It is not a full Web of Trust implementation. It does not implement the old WebOfTrust plugin,
`FCPPluginMessage`, PluginTalker compatibility, global moderation, automatic blocking, global
network crawling, daemon-core identity sharing, FNP/FCP/wire protocol changes, routing changes,
datastore changes, peer-management changes, or FProxy browse removal.

## Components

- `:platform-trustgraph` owns the bounded statement model, strict JSON parser, deterministic
  canonical payload writer, fingerprints, local anchors, durable file-backed preview store,
  redacted trust audit events, in-memory test store, and preview scorer.
- `:platform-api` exposes contract v7 `trust.read` and `trust.write` compatibility routes,
  contract v10 trust exchange and audit routes, the local `/api/v1/trust-graph/*` route family,
  contract v12 app-service discovery/grant routes for the local `trust.score` service, and the
  bounded AppVault signing route `POST /api/v1/app-vault/identities/{identityId}/trust-statement`.
- `:platform-sdk-js` exposes `CryptaPlatform.trust.*`, `CryptaPlatform.trust.exchange.*`, and
  `CryptaPlatform.vault.identities.createTrustStatement(...)` helpers.
- `apps:trust-graph` stages the static Trust Graph Preview reference app with SDK, durable
  backend status, URI import, publication, subscription, redacted audit, UI-local app-data state,
  and design-system assets.

## Durable Local Backend

The runtime wires a shared file-backed trust graph store under the platform-owned AppHost data
tree. It persists local trust anchors, normalized public trust statements, redacted source
metadata, and bounded redacted trust audit events across process restart. Reduced embeddings and
unit tests may still inject the in-memory store.

The durable store records canonical public `crypta.trust.statement.v1` documents rather than raw
request bodies or raw fetched content. Statement metadata is bounded and redacted: source type,
optional source URI summary/hash, source label, imported/updated timestamps, document fingerprint,
payload hash, and signature verification status. Imports are idempotent by document fingerprint,
listing order is deterministic, and retention caps bound anchors, statements, audit entries, and
stored document bytes. Corrupt persisted entries are ignored safely without exposing local paths or
raw document data.

App data remains separate. The Trust Graph Preview app uses app data only for UI-local drafts,
filters, and redacted import summaries; it is not the trust graph backend.

## Trust Statement Format

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

## Local Scoring

The preview scorer is deliberately simple:

- only statements from local trust anchors contribute to the final score;
- contributing statements must also have a locally verified AppVault preview signature;
- imported non-anchor statements are retained as evidence but marked non-contributing;
- imported statements without issuer public key material, with a mismatched fingerprint, or with an
  invalid signature are retained as unverified, non-contributing evidence;
- expired statements are ignored for score but may appear as expired evidence;
- subject/context scores are confidence-weighted averages of contributing direct statements;
- no contributing evidence returns `unknown` with score `0` and confidence `0`;
- evidence rows are bounded, and normal evidence does not include raw trust document bodies.

Trust anchors are local state. Adding an anchor does not publish anything and does not make the
issuer globally trusted for other nodes or apps. Imported statements remain untrusted until their
issuer fingerprint is anchored locally, and unverified imports still do not contribute after an
anchor is added.

## Platform API

Contract v7 adds the original local trust graph routes:

| Capability | Purpose |
| --- | --- |
| `trust.read` | Read local trust status, anchors, subjects, statement summaries, scores, and bounded evidence. |
| `trust.write` | Import trust statements and add/remove local trust anchors. |

Trust routes:

```text
GET  /api/v1/trust-graph/status
GET  /api/v1/trust-graph/anchors
POST /api/v1/trust-graph/anchors
DELETE /api/v1/trust-graph/anchors/{fingerprint}
POST /api/v1/trust-graph/import
GET  /api/v1/trust-graph/subjects
GET  /api/v1/trust-graph/statements
GET  /api/v1/trust-graph/score
```

Contract v10 adds durable exchange and audit routes:

| Route | Required app capabilities | Purpose |
| --- | --- | --- |
| `POST /api/v1/trust-graph/import-uri` | `trust.write`, `content.fetch` | Fetch bounded Crypta content by URI, parse it as one trust statement, persist it, and return a redacted import summary. |
| `GET /api/v1/trust-graph/audit` | `trust.read` | Return a bounded list of redacted trust graph mutation/exchange audit events. |

`POST /api/v1/trust-graph/import` accepts form-encoded `document`, optional `sourceUri`, and
optional `sourceLabel`. It validates size, parses `crypta.trust.statement.v1`, stores a redacted
summary, records whether the signature verifies against the issuer public key, and returns an
import summary without raw private data.

`GET /api/v1/trust-graph/score` accepts `subjectKind`, `subjectUri`, `context`, and optional
`includeEvidence=true`. First-party Trust Graph UI uses this direct route for its own preview
screen. Other apps should not use this route for the v12 service proving path; they use the
platform-mediated `trust.score` service with `app.services.read`, `app.services.call`, and an active
operator-approved grant. Apps can import statements or manage anchors only when their manifest
grants `trust.write`.

Other apps need operator-approved app-service grants before they can call `trust.score`.

Contract v12 advertises the local Trust Score Service from the signed Trust Graph manifest:

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

The service is preview-only and not complete WoT. Invocation is not a proxy to a Trust Graph app
localhost server. The platform dispatches to a built-in `trust-graph.score` adapter, checks the
consumer manifest and active grant at call time, and returns only a redacted score summary and
subject URI hash.

`POST /api/v1/trust-graph/import-uri` accepts a Crypta content URI, optional `sourceLabel`, and an
optional byte cap bounded by the trust graph configuration. It uses the same content fetch rules as
the content API, rejects oversized content before parsing, stores only the normalized public trust
statement and redacted source metadata, and never returns raw fetched content.

Trust statement subscription management uses the contract v8 content subscription routes through
SDK trust exchange helpers. This avoids a separate crawler and keeps subscription ownership,
restart durability, refresh, pause, resume, and delete semantics in the content subscription
service.

The bounded signing route is:

```text
POST /api/v1/app-vault/identities/{identityId}/trust-statement
```

It requires `vault.identities.read`, `vault.identities.use`, and `trust.write`. It signs only the
bounded trust statement payload with AppVault. It returns public identity metadata, a payload hash,
the fixed domain, and the public trust statement. It does not export private keys, seed material,
vault paths, raw process tokens, browser session tokens, form passwords, or generic signing access.

## Reference App

`apps:trust-graph` declares API minimum v10 and maximum tested v12, with:

```text
trust.read,trust.write,content.fetch,content.subscribe,content.insert.app-document,queue.read,
queue.write,vault.identities.read,vault.identities.create,vault.identities.use,app.data.read,
app.data.write
```

The static app can create or select an app-owned trust identity, ask AppVault to create a bounded
statement, publish it as `application/vnd.crypta.trust+json` with target filename `trust.json`,
import the locally generated public statement into the durable backend, fetch/import selected
Crypta trust documents by URI, manage content subscriptions for trust statement URIs, manage local
anchors, query scores, show recent queue state, and show redacted trust audit entries. It uses
`CryptaPlatform.data.records.getJson` and `putJson` only for UI-local state: draft form values,
selected filters, and redacted import summaries.

The app uses SDK helpers rather than hard-coded `/api/v1/` URLs. URI fetch/import does not display
raw fetched bodies. Pasted statement JSON is rendered only as text when the operator deliberately
imports pasted content. Publication and audit summaries avoid private insert URIs, private identity
material, raw signatures, tokens, and local paths.

## Redaction

Model `toString()` output, API errors, trust audit entries, authorization audit entries, UI errors,
release evidence, and developer-tooling reports must not include raw trust statement bodies from
real users, raw request bodies, raw fetched content, private insert URIs, private keys, seed
material, app process tokens, browser-session tokens, form passwords, absolute local paths, or raw
signatures. Release-certification evidence should use route names, capability labels, booleans,
counts, fixture hashes, and redacted summaries. Durable UI-local app-data evidence should similarly
use counts and summary fields instead of raw trust statements, private insert URIs, or raw form
bodies.
