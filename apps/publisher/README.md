# Publisher App

`apps/publisher` stages the first repo-owned Publisher AppHost bundle for PR-191.

Build the staged bundle with:

```bash
./gradlew :apps:publisher:stageApp
```

`stageApp` stays unsigned by default. Add the PR-192 local sidecars with:

```bash
./gradlew :apps:publisher:signApp \
  -PcryptadAppSigningKeyId=dev-local \
  -PcryptadAppSigningPrivateKeyFile=/abs/path/to/dev-app-signing-private.pem
```

Verify the signed staged bundle with:

```bash
./gradlew :apps:publisher:verifyApp \
  -PcryptadAppSigningKeyId=dev-local \
  -PcryptadAppSigningPublicKeyFile=/abs/path/to/dev-app-signing-public.pem
```

The staged output is written to:

```text
apps/publisher/build/cryptad-app/publisher
```

The staged bundle contains:

```text
cryptad-app.properties
bin/publisher.sh
static/index.html
static/app.js
static/app.css
cryptad-app.digests          # after signApp
cryptad-app.signature        # after signApp
```

Install it through the existing Platform API by passing the absolute staged directory path:

For the default production-like path, start the node with the matching trusted public key
configured, for example `CRYPTAD_APPHOST_TRUSTED_KEY_ID=dev-local` plus
`CRYPTAD_APPHOST_TRUSTED_PUBLIC_KEY_FILE=/abs/path/to/dev-app-signing-public.pem`. Use
`CRYPTAD_APPHOST_ALLOW_UNSIGNED=true` only for explicit local development/testing of unsigned
bundles.

```bash
curl -X POST \
  --data-urlencode "formPassword=<token>" \
  --data-urlencode "stagedDir=/abs/path/to/apps/publisher/build/cryptad-app/publisher" \
  http://127.0.0.1:<port>/api/v1/apps/install
```

Start and stop it through the existing app-management routes:

```bash
curl -X POST --data-urlencode "formPassword=<token>" \
  http://127.0.0.1:<port>/api/v1/apps/publisher/start

curl -X POST --data-urlencode "formPassword=<token>" \
  http://127.0.0.1:<port>/api/v1/apps/publisher/stop
```

The bundle intentionally stays narrow in PR-198:

- Local signed staged bundles and catalog-backed installs use the shared first-party app workflow.
- The primary UI lives under `/apps/publisher/static/`.
- `static/index.html` fetches `/apps/publisher/.well-known/cryptad-bootstrap.json` before calling
  Platform API v1, then uses `platformApiRoot` plus the in-memory browser app session for
  publisher queue actions.
- The launcher is a POSIX shell script; Windows-specific first-party app launch packaging remains deferred.

See [docs/app-distribution.md](../../docs/app-distribution.md) for the exact signing inputs and the shared first-party app workflow.

## Beta readiness

- Current beta support level: `core`, owned by `crypta-core`, with `app.beta.readiness=ready`.
- Empty/error/retry states: the staged UI shows an empty document-staging state, a bounded publish
  failure state, and retry/re-stage actions.
- App-data backup/export/import status: stateless. Backup, export, import, and migration dry-run
  are `not-applicable` because Publisher stores no durable local app state.
- Migration dry-run status: `not-applicable`.
- Permission rationale summary: content insert and queue permissions explain document publication,
  insert queue creation, and queue progress display.
- Support/recovery path: the recovery action points operators to failed publish job support and
  the RC recovery workflow.
- Diagnostic redaction promise: diagnostics are `redacted-summary-only` and summarize local paths
  and insert results without exposing private insert URIs, tokens, raw content, or local paths.
- Known limitations: this app remains a narrow insert workflow and does not persist drafts or
  publish history.
