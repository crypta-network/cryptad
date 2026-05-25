# Trust Graph Preview

`apps/trust-graph` stages a first-party static AppHost bundle for previewing the planned trust
graph SDK surface. The bundle is named `Trust Graph Preview` and uses app id `trust-graph`.
It is not full WoT, old WebOfTrust plugin compatibility, moderation, or automatic content
blocking. Trust anchors are local to the node and are not published automatically.

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

- `trust.read` reads local trust graph status, anchor summaries, imported statements, and scores.
- `trust.write` imports bounded trust statements and adds/removes local trust anchors.
- `content.fetch` fetches a statement document through the bounded content fetch helper.
- `content.insert.app-document` queues a generated trust statement document for insertion.
- `queue.read` previews queue status for generated trust statement inserts.
- `queue.write` creates generated trust statement insert jobs.
- `vault.identities.read` lists visible identity metadata for trust statement authors.
- `vault.identities.create` requests app-owned identities for trust statements.
- `vault.identities.use` asks the vault to create trust statement payloads without exposing private
  signing secrets to the browser UI.
- `app.data.read` restores UI-local drafts, selected filters, and redacted import summaries.
- `app.data.write` saves bounded UI-local preview state without making the trust backend durable.

The bounded AppVault route is `app-vault/identities/{identityId}/trust-statement`; it signs only
the trust statement payload and does not export private key material.

## Browser Safety

The UI persists draft form values, selected filters, and redacted import summaries through
app-data. Fetched statement text, raw trust documents, status results, and queue previews are not
stored as durable backend trust state. The UI does not use persistent browser storage, direct
Platform API URLs, external scripts, untrusted HTML insertion, app launch credentials, private
signing secrets, or local file paths.

Run the staged bundle test with:

```bash
./gradlew :apps:trust-graph:test
```
