# Trust Graph Preview

Trust Graph Preview is a first-party reference app and local Platform API preview service for
bounded trust statements. It demonstrates that a future WoT-like trust layer can live outside the
daemon and network core while using AppHost, AppVault, app-owned browser sessions, content fetch,
generated document inserts, signed catalog metadata, review receipts, and release-certification
evidence.

It is not a full Web of Trust implementation. It does not implement the old WebOfTrust plugin,
`FCPPluginMessage`, PluginTalker compatibility, global moderation, automatic blocking, durable
background crawling, daemon-core identity sharing, FNP/FCP/wire protocol changes, routing changes,
datastore changes, peer-management changes, or FProxy browse removal.

## Components

- `:platform-trustgraph` owns the bounded statement model, strict JSON parser, deterministic
  canonical payload writer, fingerprints, in-memory store, local anchors, and preview scorer.
- `:platform-api` exposes contract v7 `trust.read` and `trust.write` capabilities, the local
  `/api/v1/trust-graph/*` route family, and the bounded AppVault signing route
  `POST /api/v1/app-vault/identities/{identityId}/trust-statement`.
- `:platform-sdk-js` exposes `CryptaPlatform.trust.*` helpers and
  `CryptaPlatform.vault.identities.createTrustStatement(...)`.
- `apps:trust-graph` stages the static Trust Graph Preview reference app with SDK and design-system
  assets.

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

Contract v7 adds:

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

`POST /api/v1/trust-graph/import` accepts form-encoded `document`, optional `sourceUri`, and
optional `sourceLabel`. It validates size, parses `crypta.trust.statement.v1`, stores a redacted
summary, records whether the signature verifies against the issuer public key, and returns an
import summary without raw private data.

`GET /api/v1/trust-graph/score` accepts `subjectKind`, `subjectUri`, `context`, and optional
`includeEvidence=true`. Other apps can query scores only when their manifest grants `trust.read`.
Apps can import statements or manage anchors only when their manifest grants `trust.write`.

The bounded signing route is:

```text
POST /api/v1/app-vault/identities/{identityId}/trust-statement
```

It requires `vault.identities.read`, `vault.identities.use`, and `trust.write`. It signs only the
bounded trust statement payload with AppVault. It returns public identity metadata, a payload hash,
the fixed domain, and the public trust statement. It does not export private keys, seed material,
vault paths, raw process tokens, browser session tokens, form passwords, or generic signing access.

## Reference App

`apps:trust-graph` declares API v7 and:

```text
trust.read,trust.write,content.fetch,content.insert.app-document,queue.read,queue.write,
vault.identities.read,vault.identities.create,vault.identities.use
```

The static app can create or select an app-owned trust identity, create a bounded statement, sign it
through AppVault, publish it as `application/vnd.crypta.trust+json` with target filename
`trust.json`, fetch/import selected Crypta trust documents, manage local anchors, query scores, and
show recent queue state. It renders imported and fetched fields as text, uses SDK helpers, uses the
design-system assets, and does not store app tokens or browser-session tokens in browser storage.

## Redaction

Model `toString()` output, API errors, audit entries, diagnostics, UI errors, release evidence, and
developer-tooling reports must not include raw trust document bodies from real users, raw request
bodies, private keys, seed material, app process tokens, browser-session tokens, form passwords,
absolute local paths, or raw signatures. Release-certification evidence should use route names,
capability labels, booleans, counts, fixture hashes, and redacted summaries.
