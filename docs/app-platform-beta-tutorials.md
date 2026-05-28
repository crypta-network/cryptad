# App platform beta tutorials

Use these offline-first tutorials to create, test, sign, pack, catalog, and review a beta app
without reading Cryptad internals.

## Prerequisites

Run from the repository root with Java 25 or newer. The flows use the Gradle wrapper and the
installed `crypta-app` launcher:

```bash
./gradlew :platform-devtools:installDist
export CRYPTA_APP="$PWD/platform-devtools/build/install/crypta-app/bin/crypta-app"
"$CRYPTA_APP" --help
```

Keep local development keys outside the repository. The examples below use `$HOME/.crypta-dev/keys`
and URI-safe placeholder Crypta URIs such as `crypta:CHK@...` and
`crypta:USK@.../cryptad-app-catalog.properties`. They are placeholders, not usable public network
keys.

## Tutorial 1: static app from template

Create a minimal static app bundle:

```bash
"$CRYPTA_APP" init \
  --dir build/dev-apps/hello-crypta \
  --template static-basic \
  --app-id hello-crypta \
  --name "Hello Crypta" \
  --version 0.1.0
```

Run the local development server:

```bash
"$CRYPTA_APP" dev --bundle-dir build/dev-apps/hello-crypta
```

`crypta-app dev` binds to `127.0.0.1` by default and uses mock Platform API fixtures. It does not
talk to the public Crypta network, install the app into AppHost, fetch signed catalogs, or prove
live-node permission grants. Use `--fixture-dir` for custom mock JSON fixtures and
`--allow-non-loopback` only for deliberate local-network testing.

In another terminal, run the offline test suite:

```bash
"$CRYPTA_APP" test \
  --bundle-dir build/dev-apps/hello-crypta \
  --strict \
  --json build/dev-apps/hello-crypta-test.json
```

The JSON report uses deterministic, path-redacted output suitable for beta submissions and release
evidence.

## Tutorial 2: queue dashboard or publisher template

Create a queue-dashboard app with the template's default queue capabilities:

```bash
"$CRYPTA_APP" init \
  --dir build/dev-apps/queue-dashboard \
  --template queue-dashboard \
  --app-id queue-dashboard \
  --name "Queue Dashboard" \
  --version 0.1.0
```

The `queue-dashboard` template declares `queue.read` and `queue.write`. Add any extra capability
deliberately with repeated `--permission <capability>` options and update the visible permission
rationale before signing.

Create a publisher app instead when you want a content-insert example:

```bash
"$CRYPTA_APP" init \
  --dir build/dev-apps/local-publisher \
  --template publisher \
  --app-id local-publisher \
  --name "Local Publisher" \
  --version 0.1.0
```

The `publisher` template declares `content.insert`, `queue.read`, and `queue.write`.

Run strict offline checks:

```bash
"$CRYPTA_APP" test \
  --bundle-dir build/dev-apps/queue-dashboard \
  --strict \
  --json build/dev-apps/queue-dashboard-test.json
```

`crypta-app test` runs the app developer checks without network access. It covers staged bundle
validation, manifest and Platform API compatibility checks, static asset safety, UI lint for static
bundles, API compatibility output, and a dev-server smoke check when the bundle can be served by the
mock loopback server.

## Tutorial 3: sign, pack, catalog, and offline USK publication plan

Generate separate local development keys for bundle and catalog signing:

```bash
mkdir -p "$HOME/.crypta-dev/keys"

"$CRYPTA_APP" keys generate \
  --key-id dev-local-bundle \
  --private-key-file "$HOME/.crypta-dev/keys/dev-local-bundle-private.der" \
  --public-key-file "$HOME/.crypta-dev/keys/dev-local-bundle-public.der" \
  --trusted-keys-file "$HOME/.crypta-dev/keys/trusted-app-keys.properties" \
  --overwrite

"$CRYPTA_APP" keys generate \
  --key-id dev-local-catalog \
  --private-key-file "$HOME/.crypta-dev/keys/dev-local-catalog-private.der" \
  --public-key-file "$HOME/.crypta-dev/keys/dev-local-catalog-public.der" \
  --overwrite
```

Sign and verify the staged bundle:

```bash
"$CRYPTA_APP" sign \
  --bundle-dir build/dev-apps/queue-dashboard \
  --key-id dev-local-bundle \
  --private-key-file "$HOME/.crypta-dev/keys/dev-local-bundle-private.der"

"$CRYPTA_APP" verify \
  --bundle-dir build/dev-apps/queue-dashboard \
  --trusted-keys-file "$HOME/.crypta-dev/keys/trusted-app-keys.properties"
```

Pack the signed staged bundle:

```bash
mkdir -p dist/apps dist/catalog

"$CRYPTA_APP" pack \
  --bundle-dir build/dev-apps/queue-dashboard \
  --output dist/apps/queue-dashboard-0.1.0.zip \
  --overwrite
```

Create a catalog entry descriptor. The `crypta:CHK@...` value is a placeholder for the public
immutable artifact URI returned by a reviewed insertion workflow:

```bash
"$CRYPTA_APP" catalog entry \
  --bundle-dir build/dev-apps/queue-dashboard \
  --artifact dist/apps/queue-dashboard-0.1.0.zip \
  --bundle-uri "crypta:CHK@..." \
  --output dist/catalog/queue-dashboard-entry.properties \
  --summary "Inspect and manage local transfer queue state." \
  --homepage "https://example.invalid/apps/queue-dashboard" \
  --source "https://example.invalid/src/queue-dashboard" \
  --license "MIT" \
  --category productivity \
  --minimum-crypta-version 1481 \
  --permission-rationale "queue.read=Reads local queue state." \
  --permission-rationale "queue.write=Cancels or reprioritizes selected queue entries." \
  --strict \
  --overwrite
```

Create, sign, and verify the catalog:

```bash
"$CRYPTA_APP" catalog create \
  --catalog-file dist/catalog/cryptad-app-catalog.properties \
  --catalog-id dev-queue-dashboard \
  --name "Development Queue Dashboard Catalog" \
  --entry dist/catalog/queue-dashboard-entry.properties \
  --overwrite

"$CRYPTA_APP" catalog sign \
  --catalog-file dist/catalog/cryptad-app-catalog.properties \
  --key-id dev-local-catalog \
  --private-key-file "$HOME/.crypta-dev/keys/dev-local-catalog-private.der"

"$CRYPTA_APP" catalog verify \
  --catalog-file dist/catalog/cryptad-app-catalog.properties \
  --trusted-key-id dev-local-catalog \
  --trusted-public-key-file "$HOME/.crypta-dev/keys/dev-local-catalog-public.der"
```

Write an offline Crypta USK publication plan:

```bash
"$CRYPTA_APP" publish-usk \
  --catalog-file dist/catalog/cryptad-app-catalog.properties \
  --catalog-signature-file dist/catalog/cryptad-app-catalog.signature \
  --catalog-source "crypta:USK@.../cryptad-app-catalog.properties" \
  --output dist/catalog/publish-plan.md \
  --dry-run
```

`crypta-app publish-usk --dry-run` writes a plan. It does not insert catalog bytes, signature
bytes, or app ZIP artifacts into the public Crypta network. Live insertion remains a separate
reviewed release/operator workflow that uses the existing content and queue mechanisms:

```bash
"$CRYPTA_APP" publish-usk --live \
  --catalog-file dist/catalog/cryptad-app-catalog.properties \
  --catalog-signature-file dist/catalog/cryptad-app-catalog.signature \
  --catalog-source "crypta:USK@.../cryptad-app-catalog.properties" \
  --private-insert-uri-env CRYPTAD_FIRST_PARTY_CATALOG_INSERT_URI \
  --node-base-url http://127.0.0.1:8888/api/v1 \
  --form-password-env CRYPTAD_CERT_FORM_PASSWORD \
  --trusted-key-id dev-local-catalog \
  --trusted-public-key-file "$HOME/.crypta-dev/keys/dev-local-catalog-public.der" \
  --output dist/catalog/live-publication-summary.json
```

The live command verifies the signed catalog locally before insertion. It publishes
`cryptad-app-catalog.signature` as the sibling sidecar at the same USK edition as
`cryptad-app-catalog.properties`, and its output is sanitized for release evidence. Keep the
private insert URI, form password, and private signing keys out of shell history, logs, and
uploaded artifacts.

## Tutorial 4: reference app map

The first-party apps are reference points for the beta. Their current manifests declare these key
capabilities:

| App | Demonstrates | Key capabilities |
| --- | --- | --- |
| Queue Manager | Queue read/write and operator queue flow. | `queue.read`, `queue.write` |
| Publisher | Content insert workflow. | `content.insert`, `queue.read`, `queue.write` |
| Site Publisher | Static site publishing pattern. | `content.insert`, `queue.read`, `queue.write` |
| Profile Publisher | AppVault identity, bounded profile document signing, durable draft state, and app-generated document insert. | `vault.identities.read`, `vault.identities.create`, `vault.identities.use`, `content.insert.app-document`, `app.data.read`, `app.data.write`, `queue.read`, `queue.write` |
| Social Inbox Preview | Social/mail-like migration spike with bounded `crypta.social.message.v1` signing, generated outbox inserts, durable USK sources, app data, and Trust Graph annotations. | `vault.identities.read`, `vault.identities.create`, `vault.identities.use`, `content.fetch`, `content.subscribe`, `content.insert.app-document`, `app.data.read`, `app.data.write`, `trust.read`, `queue.read`, `queue.write` |
| Feed Reader & Publisher | Durable USK subscription metadata, durable reader state, bounded content fetch, and feed snapshot publish. | `content.fetch`, `content.subscribe`, `content.insert.app-document`, `app.data.read`, `app.data.write`, `queue.read`, `queue.write` |
| Trust Graph Preview | Durable local trust graph backend, URI import, redacted audit, content subscription management, score, sign, and publish preview. | `trust.read`, `trust.write`, `content.fetch`, `content.subscribe`, `content.insert.app-document`, `vault.identities.read`, `vault.identities.create`, `vault.identities.use`, `app.data.read`, `app.data.write`, `queue.read`, `queue.write` |

Release evidence for the Feed Reader path includes `network-content.subscription-scheduler`,
which proves deterministic scheduler ticks, conservative limits, dedupe, backoff, and redacted
metadata.

Use the detailed docs before copying a reference pattern:

- [feed-reader-reference-app.md](feed-reader-reference-app.md)
- [social-inbox-reference-app.md](social-inbox-reference-app.md)
- [trust-graph-preview.md](trust-graph-preview.md)
- [app-data-store.md](app-data-store.md)
- [app-secret-and-identity-vault.md](app-secret-and-identity-vault.md)
- [platform-api-contract.md](platform-api-contract.md)

## Tutorial 5: Web Shell onboarding path

The first-party beta catalog appears in Web Shell as a recommended catalog when the runtime or
package configuration provides the catalog source and trusted key hint. Recommended catalog means
"available for explicit operator onboarding." It is not automatic app installation.

The high-level operator flow is:

1. Open the Web Shell Apps area.
2. Inspect the recommended first-party beta catalog entry.
3. Confirm the catalog source and trusted catalog key configuration.
4. Add the catalog recommendation.
5. Refresh the signed catalog source.
6. Inspect each app entry, permissions, review trust, API compatibility, and version delta.
7. Install or update individual apps explicitly.

These checks still apply:

- The catalog source signature and trusted catalog key must verify.
- Signed bundle verification and artifact SHA-256 checks remain separate from catalog trust.
- App review trust and reviewer governance still apply; a review receipt is independent evidence.
- Reviewer trust follows the reviewer key lifecycle and local transparency log records described in
  the governance docs; a catalog listing does not make an unknown reviewer locally trusted.
- Platform API compatibility and permission-delta gates still apply.
- The background update scheduler policy governs check, stage, and apply behavior.
- Manual policy detects candidates but does not stage or apply updates automatically.
- Rollback is a bounded safety mechanism after an update is staged or applied; it is not a promise
  that every app state can be restored.
- The ecosystem certification matrix records this docs/tutorial evidence for release managers.
- FProxy browse remains retained; Web Shell catalog onboarding does not remove legacy browse routes.

See [first-party-beta-catalog.md](first-party-beta-catalog.md),
[app-catalogs.md](app-catalogs.md), [app-review-governance.md](app-review-governance.md), and
[app-update-lifecycle.md](app-update-lifecycle.md).
