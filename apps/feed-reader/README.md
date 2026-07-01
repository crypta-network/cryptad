# Feed Reader & Publisher App

`apps/feed-reader` stages a first-party static AppHost bundle for reading and publishing feed
snapshots through the Platform API browser SDK.

The app persists feed sources, selected subscription ids, read-state metadata, and safe publish
draft fields through the durable app-data API. Fetched snapshots, queue summaries, and publication
results stay bounded in the UI and are not written to browser storage. The app does not use
external scripts, direct Platform API URLs, form-password credentials, or AppHost launch tokens.

Build the staged bundle with:

```bash
./gradlew :apps:feed-reader:stageApp
```

`stageApp` stays unsigned by default. Add signed-bundle sidecars with:

```bash
./gradlew :apps:feed-reader:signApp \
  -PcryptadAppSigningKeyId=dev-local \
  -PcryptadAppSigningPrivateKeyFile=/abs/path/to/dev-app-signing-private.pem
```

Verify the signed staged bundle with:

```bash
./gradlew :apps:feed-reader:verifyApp \
  -PcryptadAppSigningKeyId=dev-local \
  -PcryptadAppSigningPublicKeyFile=/abs/path/to/dev-app-signing-public.pem
```

The staged output is written to:

```text
apps/feed-reader/build/cryptad-app/feed-reader
```

The staged bundle contains:

```text
cryptad-app.properties
bin/feed-reader.sh
static/index.html
static/app.js
static/app.css
static/crypta-platform.js
static/crypta-ui/crypta-ui-tokens.css
static/crypta-ui/crypta-ui.css
static/crypta-ui/crypta-ui-components.js
cryptad-app.digests          # after signApp
cryptad-app.signature        # after signApp
```

Feed Reader & Publisher declares:

- `content.fetch` to fetch canonical feed snapshots, RSS/Atom text, or plain text previews for
  configured Crypta content-key sources.
- `content.subscribe` to register bounded USK subscriptions with the platform scheduler and store
  safe metadata only.
- `content.insert.app-document` to publish generated feed snapshots without local source-path
  authority.
- `queue.read` to show upload queue progress for published snapshots.
- `queue.write` to create publish queue requests.
- `app.data.read` to restore the app-owned feed list and reader state.
- `app.data.write` to save bounded feed, subscription, read-state, and draft metadata.

The manifest requires Platform API contract v9 because the reference app depends on durable content
subscription helpers and durable app-data records for reader state, and it is tested through the
current v10 contract.

## App-data backup scope

Operator app-data backups for `feed-reader` include the app's `ui-state` durable app-data record:
feed source labels and content-key URIs, selected source and subscription ids, bounded read/fetch
summaries, and safe publisher draft fields. Treat exported backups as sensitive user data because
feed sources, read state, and drafts reveal reading and publishing intent.

Backups do not include fetched feed bodies, queue artifacts, content subscription scheduler
internals beyond ids or summaries already represented in app-data, vault private identity
material, vault identities or keys, private insert URIs, form passwords, app-service tokens,
browser-session tokens, app bundle files, or local paths. Restoring a backup brings back configured
sources, read state, and draft metadata; platform subscription records may need to be recreated or
reconciled if they are not present on the target node.

Run focused validation with:

```bash
./gradlew :apps:feed-reader:test
```

See [docs/app-distribution.md](../../docs/app-distribution.md) for signing inputs and the shared
first-party app workflow.

## Beta readiness

- Current beta support level: `maintained`, owned by `crypta-core`, with
  `app.beta.readiness=ready`.
- Empty/error/retry states: the staged UI shows an empty feed-source/subscription state, bounded
  fetch/subscription failure states, and retry refresh/resubscribe actions.
- App-data backup/export/import status: supported for durable `ui-state` feed source, selected
  subscription, read-state, fetch-summary, and draft metadata. Exported backups remain sensitive
  user data.
- Migration dry-run status: supported for the `ui-state-v1-v2` migration command before applying
  an update.
- Permission rationale summary: content fetch, content subscription, generated app-document
  insert, queue, and app-data permissions each have manifest rationale and visible disclosure.
- Support/recovery path: the recovery action points operators to resubscribe, refresh, app-data
  export/import, and RC recovery support guidance.
- Diagnostic redaction promise: diagnostics are `redacted-summary-only` and do not include raw
  fetched content, raw feed bodies, private insert URIs, tokens, raw app-data values, or local
  paths.
- Known limitations: platform subscription records may need to be recreated or reconciled after
  restoring app data onto another node.
