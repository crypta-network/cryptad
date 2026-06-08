# Trust Graph Local RC

`apps/trust-graph` stages a first-party static AppHost bundle for operating the bounded local Trust
Graph release-candidate service. The bundle is named `Trust Graph Local RC` and uses app id
`trust-graph`.

The service is local trust only. It is operator-curated local evidence, not global truth,
moderation, blocking, routing policy, peer selection, network crawling, or automatic content
filtering. It does not promise legacy WoT, Freetalk, Sone, Freemail, or old WebOfTrust plugin
compatibility. Trust anchors and lifecycle records are local to the node and are not published
automatically.

The signed manifest advertises a bounded local `trust.score` service named Trust Score Service.
Other apps can invoke it only through the Platform API app-services layer after an
operator-approved read-only grant; the app does not expose lifecycle mutation powers or an
arbitrary localhost server for score access.

## Stage

```bash
./gradlew :apps:trust-graph:stageApp
```

The staged bundle is written to:

```text
apps/trust-graph/build/cryptad-app/trust-graph
```

## Sign

```bash
./gradlew :apps:trust-graph:signApp \
  -PcryptadAppSigningKeyId=<key-id> \
  -PcryptadAppSigningPrivateKeyBase64=<base64-private-key>
```

You can also provide `CRYPTAD_APP_SIGNING_KEY_ID` and
`CRYPTAD_APP_SIGNING_PRIVATE_KEY_BASE64`, or provide a private key file through
`-PcryptadAppSigningPrivateKeyFile` / `CRYPTAD_APP_SIGNING_PRIVATE_KEY_FILE`.

## Verify

```bash
./gradlew :apps:trust-graph:verifyApp \
  -PcryptadAppSigningKeyId=<key-id> \
  -PcryptadAppSigningPublicKeyBase64=<base64-public-key>
```

You can also provide `CRYPTAD_APP_SIGNING_PUBLIC_KEY_BASE64`, or provide a public key file through
`-PcryptadAppSigningPublicKeyFile` / `CRYPTAD_APP_SIGNING_PUBLIC_KEY_FILE`.

## Bundle Contents

The staged static bundle contains:

```text
cryptad-app.properties
bin/trust-graph.sh
static/index.html
static/app.css
static/app.js
static/crypta-platform.js
static/crypta-ui/crypta-ui-tokens.css
static/crypta-ui/crypta-ui.css
static/crypta-ui/crypta-ui-components.js
```

The launcher script is a minimal long-running process for AppHost lifecycle tests. The browser UI
loads only local design-system assets and the staged `crypta-platform.js` SDK.

## Permissions

- `trust.read` reads local RC scope, anchor summaries, imported statements, lifecycle state, and
  bounded scores.
- `trust.write` imports bounded trust statements, adds/removes local trust anchors, and applies
  local lifecycle policy when the Platform API exposes lifecycle routes.
- `content.fetch` fetches a statement document through the bounded trust import helper.
- `content.subscribe` manages trust statement content subscriptions.
- `content.insert.app-document` queues a generated trust statement document for insertion.
- `queue.read` previews queue status for generated trust statement inserts.
- `queue.write` creates generated trust statement insert jobs.
- `vault.identities.read` lists visible identity metadata for trust statement authors.
- `vault.identities.create` requests app-owned identities for trust statements.
- `vault.identities.use` asks the vault to create trust statement payloads without exposing private
  signing secrets to the browser UI.
- `app.data.read` restores UI-local drafts, selected filters, and redacted import summaries.
- `app.data.write` saves bounded UI-local RC state only.

The bounded AppVault route is `app-vault/identities/{identityId}/trust-statement`; it signs only
the trust statement payload and does not export private key material.

## Trust Score Service

Trust Graph Local RC advertises this service metadata in `cryptad-app.properties`:

```properties
app.services.provides=trust-score
app.service.trust-score.id=trust.score
app.service.trust-score.kind=platform-adapter
app.service.trust-score.adapter=trust-graph.score
app.service.trust-score.scopes=score.read
app.service.trust-score.contexts=message-author,profile
```

The platform adapter calls the existing local Trust Graph score implementation and returns a
redacted score summary with a subject URI hash. It does not return raw trust statement bodies,
raw signatures, local store paths, private identity material, or private insert URIs.

Score explanations are bounded. Evidence rows report public issuer fingerprints, public score and
confidence values, verification status, lifecycle status when present, contribution flags, and
stable non-contribution reason codes. Deprecated, revoked, expired, unverified, unanchored, or
zero-confidence statements must not silently contribute to scores.

## Statement Lifecycle

The UI shows lifecycle status from the statement API when available. Local lifecycle controls call
SDK lifecycle helpers only when the current Platform API contract exposes them. Lifecycle changes
are local operator policy, not universal revocation truth and not a network propagation mechanism.

Lifecycle states shown by the UI are:

- `active`: eligible to contribute only when the issuer is a local anchor, the signature verifies,
  the statement is not expired, and confidence is non-zero.
- `deprecated`: retained for local history and explanation, but not score-contributing.
- `revoked`: retained for local history and explanation, but not score-contributing.

## Durable Backend and Exchange

Trust anchors and imported public trust statements are stored by the platform trust graph backend,
not in this app's app-data namespace. The app-data store remains UI-local state for drafts and
redacted summaries.

The RC exchange workflow uses existing Crypta content APIs. URI import fetches bounded content and
persists only the normalized public trust statement plus redacted source metadata such as source
type, URI kind, subscription id when present, sanitized source label, import time, and last-seen
time. Publication uses AppVault to create the public statement, queues it through generated
app-document insertion, and imports the local public statement summary into the durable trust graph
store. Subscriptions use the content subscription scheduler and do not crawl the network globally.

## App-data backup scope

Operator app-data backups for `trust-graph` include only the app's `ui-state` durable app-data
record: UI-local draft choices, selected filters when present, source-kind import state, and
redacted recent import summaries. Treat exported backups as sensitive user data because drafts and
import summaries can reveal what trust material the operator is reviewing.

Backups do not include platform trust graph backend state such as anchors, imported public trust
statements, scores, or service-provider state. They also exclude content subscriptions, AppVault
identity material, vault private identity material, private signing secrets, raw statement bodies,
raw signatures, private insert URIs, app-service tokens, app-service grant state, app bundle files,
tokens, and local paths. Restoring a backup rehydrates the browser UI RC state only; trust
anchors and imported statements must already exist on the target node or be restored through their
platform-specific flows.

## Browser Safety

The UI persists draft form values, selected filters, and redacted import summaries through
app-data. Fetched statement bodies are not displayed during URI imports, and pasted trust statement
JSON is rendered only as text when the operator deliberately imports pasted content. Queue and
publication summaries avoid private insert URIs. The UI does not use persistent browser storage,
direct Platform API URLs, external scripts, untrusted HTML insertion, app launch credentials,
private signing secrets, tokens, raw signatures, or local file paths.

Run the staged bundle test with:

```bash
./gradlew :apps:trust-graph:test
```
