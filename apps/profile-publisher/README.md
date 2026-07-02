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

The manifest requires Platform API contract v9 because Profile Publisher combines the
profile-document and app-document insert routes with durable app-data records, and it is tested
through the current v10 contract. It also sets `api.targetStability=experimental` and
`api.experimentalCapabilitiesAccepted=true`; the current app-vault identity capabilities remain
experimental even though the app keeps the operation narrow and first-party reviewed.

The browser UI does not use persistent browser storage, cookies, external resources, browser file
inputs, or direct local file reads. Profile documents are built from bounded app-owned form state,
signed through the browser-safe profile-document vault route, and submitted to the app-generated
document insert route without exposing launch tokens, browser-session tokens, private identity
material, or server-side staging paths. The app-data record stores drafts and publish summaries
only; secrets, seeds, private keys, and identity material remain in AppVault.

## Content format profile

Profile Publisher uses `CryptaPlatform.contentFormats.profileDocument` for the
`crypta.profile.v1` schema, `application/vnd.crypta.profile+json` content type, `profile.json`
default filename, `profile.publish.v1` signing purpose, and profile byte bounds. Unknown profile
request fields are rejected before signing, and release evidence must not include raw signed
profile documents, raw signatures, private insert URIs, private keys, tokens, raw app-data values,
or local paths.

These content profiles are Crypta app ecosystem profiles. They are not compatibility promises for
legacy WoT, Freetalk, Sone, Freemail, or any old plugin ABI/protocol.

## App-data backup scope

Operator app-data backups for `profile-publisher` include only the app's durable app-data record in
the `profile-draft` namespace: bounded profile draft fields, the selected identity id, the last
published profile URI, and recent publish/action summaries. Treat exported backups as sensitive
user data because profile drafts, selected identities, and profile URIs can identify the operator.

Backups do not include AppVault private identity material, vault private identity material, seeds,
private keys, signed preview state, launch tokens, browser-session tokens, app-service tokens,
queue internals, app bundle files, or local paths.
Restoring a backup rehydrates the draft and publish summaries; identity signing authority still
depends on the target node's AppVault state.

Run focused validation with:

```bash
./gradlew :apps:profile-publisher:test
```

See [docs/app-distribution.md](../../docs/app-distribution.md) for signing inputs and the shared
first-party app workflow, [docs/app-ui-design-system.md](../../docs/app-ui-design-system.md) for
static UI rules, and [docs/app-secret-and-identity-vault.md](../../docs/app-secret-and-identity-vault.md)
for app-vault identity boundaries.

## Beta readiness

- Current beta support level: `maintained`, owned by `crypta-core`, with
  `app.beta.readiness=ready`.
- Empty/error/retry states: the staged UI shows an empty profile draft/identity grant state,
  bounded vault grant and publish failure states, and retry/re-request-grant actions.
- App-data backup/export/import status: supported for bounded `profile-draft` records such as
  draft fields, selected identity id, last published URI summary, and publish-history summaries.
  Backup/export does not export AppVault secrets.
- Migration dry-run status: `not-applicable` for schema 1 profile draft state.
- Permission rationale summary: AppVault identity, generated app-document insert, queue, and
  app-data permissions each have manifest rationale and visible disclosure.
- Support/recovery path: the recovery action points operators to grant refresh, publish retry,
  app-data export/import, and RC recovery support guidance.
- Diagnostic redaction promise: diagnostics are `redacted-summary-only` and do not expose identity
  material, private keys, signed profile bodies, private insert URIs, tokens, raw app-data values,
  or local paths.
- Known limitations: restoring app data rehydrates drafts and summaries only; identity signing
  authority still depends on the target node's AppVault state and vault private identity material
  remains non-exportable.
