# Feed Reader & Publisher App

`apps/feed-reader` stages a first-party static AppHost bundle for reading and publishing feed
snapshots through the Platform API browser SDK.

The app keeps feed sources, fetched snapshots, draft entries, queue summaries, and recent publish
results in memory for the open browser tab only. It does not use persistent browser storage,
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

The manifest targets Platform API contract v8 because the reference app depends on durable
content subscription helpers for USK follow behavior. Run focused validation with:

```bash
./gradlew :apps:feed-reader:test
```

See [docs/app-distribution.md](../../docs/app-distribution.md) for signing inputs and the shared
first-party app workflow.
