# Profile Publisher App

`apps/profile-publisher` stages a first-party profile-publishing AppHost bundle.

Profile Publisher is a static app-owned browser UI that uses the browser SDK, the local Crypta UI
design-system assets, the app-vault identity permission vocabulary, and the durable app-data API.
Draft profile data, the selected identity id, the last published profile URI, and bounded publish
history summaries persist in app-owned records. Signed preview state and private identity material
do not leave AppVault.

Build the staged bundle with:

```bash
./gradlew :apps:profile-publisher:stageApp
```

`stageApp` stays unsigned by default. Add the local signed-bundle sidecars with:

```bash
./gradlew :apps:profile-publisher:signApp \
  -PcryptadAppSigningKeyId=dev-local \
  -PcryptadAppSigningPrivateKeyFile=/abs/path/to/dev-app-signing-private.pem
```

Verify the signed staged bundle with:

```bash
./gradlew :apps:profile-publisher:verifyApp \
  -PcryptadAppSigningKeyId=dev-local \
  -PcryptadAppSigningPublicKeyFile=/abs/path/to/dev-app-signing-public.pem
```

The staged output is written to:

```text
apps/profile-publisher/build/cryptad-app/profile-publisher
```

The staged bundle contains:

```text
cryptad-app.properties
bin/profile-publisher.sh
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

Profile Publisher declares:

- `vault.identities.read` to list identity metadata and visible grants.
- `vault.identities.create` to request app-owned profile signing identities.
- `vault.identities.use` to request domain-separated profile document signatures.
- `content.insert.app-document` to queue node-side app-document inserts without local source-path
  authority.
- `queue.write` to create the insert request.
- `queue.read` to show upload queue progress.
- `app.data.read` to restore the app-owned profile draft and publish summaries.
- `app.data.write` to save bounded draft and publish-history state.

The manifest targets Platform API contract v9 because Profile Publisher now combines the
profile-document and app-document insert routes with durable app-data records. It also sets
`api.experimentalCapabilitiesAccepted=true`; the current app-vault identity capabilities remain
experimental even though the app keeps the operation narrow and first-party reviewed.

The browser UI does not use persistent browser storage, cookies, external resources, browser file
inputs, or direct local file reads. Profile documents are built from bounded app-owned form state,
signed through the browser-safe profile-document vault route, and submitted to the app-generated
document insert route without exposing launch tokens, browser-session tokens, private identity
material, or server-side staging paths. The app-data record stores drafts and publish summaries
only; secrets, seeds, private keys, and identity material remain in AppVault.

Run focused validation with:

```bash
./gradlew :apps:profile-publisher:test
```

See [docs/app-distribution.md](../../docs/app-distribution.md) for signing inputs and the shared
first-party app workflow, [docs/app-ui-design-system.md](../../docs/app-ui-design-system.md) for
static UI rules, and [docs/app-secret-and-identity-vault.md](../../docs/app-secret-and-identity-vault.md)
for app-vault identity boundaries.
