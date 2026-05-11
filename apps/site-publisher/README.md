# Site Publisher App

`apps/site-publisher` stages the first repo-owned content reference AppHost bundle.

Site Publisher is separate from the legacy Publisher app. Publisher remains the compatibility
replacement for legacy insert admin pages, while Site Publisher demonstrates a normal user-facing
content workflow on the app-platform stack: isolated static UI, local design-system assets, the
browser SDK, explicit content-publishing permissions, catalog metadata, review evidence, and update
certification.

Build the staged bundle with:

```bash
./gradlew :apps:site-publisher:stageApp
```

`stageApp` stays unsigned by default. Add the local signed-bundle sidecars with:

```bash
./gradlew :apps:site-publisher:signApp \
  -PcryptadAppSigningKeyId=dev-local \
  -PcryptadAppSigningPrivateKeyFile=/abs/path/to/dev-app-signing-private.pem
```

Verify the signed staged bundle with:

```bash
./gradlew :apps:site-publisher:verifyApp \
  -PcryptadAppSigningKeyId=dev-local \
  -PcryptadAppSigningPublicKeyFile=/abs/path/to/dev-app-signing-public.pem
```

The staged output is written to:

```text
apps/site-publisher/build/cryptad-app/site-publisher
```

The staged bundle contains:

```text
cryptad-app.properties
bin/site-publisher.sh
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

Site Publisher declares:

- `content.insert` to submit operator-selected local files and directories to the insert pipeline.
- `queue.write` to create the resulting insert requests.
- `queue.read` to show upload queue progress.

The browser UI does not read local files directly, does not use persistent browser storage, and
does not request vault identity capabilities. Identity-backed site/profile publishing remains
future work until an app can request an operator grant and use identity metadata without exposing
private identity material.

Run focused validation with:

```bash
./gradlew :apps:site-publisher:test
```

See [docs/app-distribution.md](../../docs/app-distribution.md) for signing inputs and the shared
first-party app workflow, and [docs/app-catalogs.md](../../docs/app-catalogs.md) for local signed
catalog metadata.
