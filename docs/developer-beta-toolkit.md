# Developer beta toolkit

This guide describes the developer beta toolkit workflow for building, testing, signing,
cataloging, and dry-run publishing a standalone Crypta app bundle.

## Scope

Use this page with a current `crypta-app` launcher built from `:platform-devtools`. Older launchers
may expose only the base commands documented in [app-dev-cli.md](app-dev-cli.md). Run
`crypta-app --help` and the subcommand help before relying on beta flags in automation.

The beta toolkit is for developer-owned app bundles outside the first-party `apps/*` Gradle
projects. It can scaffold a queue dashboard template, run a mock development server, execute
offline strict checks, generate local signing keys, sign and pack bundles, create and sign catalogs,
and prepare a dry-run USK publication plan. It does not make unsigned bundles trusted, bypass
catalog verification, or turn a mock development server into a live daemon install path.

## Install the toolkit

Build the installed CLI launcher with Gradle:

```bash
./gradlew :platform-devtools:installDist
```

Use the generated launcher directly from the install distribution:

```bash
platform-devtools/build/install/crypta-app/bin/crypta-app --help
```

On Windows, use the matching `crypta-app.bat` under the generated `bin` directory.

The examples below assume the launcher directory is on `PATH`:

```bash
export PATH="$PWD/platform-devtools/build/install/crypta-app/bin:$PATH"
```

## Create a queue dashboard app

Scaffold a standalone staged bundle with the queue dashboard template:

```bash
crypta-app init \
  --dir build/dev-apps/queue-dashboard \
  --template queue-dashboard \
  --app-id queue-dashboard \
  --name "Queue Dashboard" \
  --version 0.1.0 \
  --permission queue.read \
  --permission queue.write
```

The output is a staged app bundle directory, not a Gradle subproject. The template should create the
app manifest, launch files, browser assets, SDK copy, and local design-system assets under the
bundle directory. Keep generated work under `build/` or `dist/` unless you intentionally want to
check in source files.

The signed manifest remains authoritative for app id, version, launch behavior, UI mode, requested
permissions, and Platform API compatibility metadata. Catalog metadata can add display and review
context, but it does not replace the bundle manifest.

## Run the mock development server

Start the beta development server against the staged bundle:

```bash
crypta-app dev --bundle-dir build/dev-apps/queue-dashboard
```

The development server is a mock app-authoring surface. It is useful for iterating on static UI,
template assets, local SDK wiring, and fixture-backed queue views. It is not the real Cryptad
daemon, does not install the app into AppHost, does not fetch signed catalogs, and does not prove
that a live node will grant the same permissions.

For Trust Graph Preview-style apps, the mock server exposes deterministic local fixtures for
`GET /api/v1/trust-graph/status`, `GET /api/v1/trust-graph/anchors`,
`POST /api/v1/trust-graph/anchors`, `DELETE /api/v1/trust-graph/anchors/{fingerprint}`,
`POST /api/v1/trust-graph/import`, `GET /api/v1/trust-graph/score`, bounded
`POST /api/v1/content/fetch`, and
`POST /api/v1/app-vault/identities/{identityId}/trust-statement`. Those responses are fixtures for
offline UI work; they do not verify live network trust, global reputation, old WebOfTrust plugin
compatibility, or moderation behavior.

Use a real daemon when testing install, update, AppHost lifecycle, catalog refresh, browser session
issuance, audit behavior, review policy, or Crypta network fetch/insert behavior. Live daemon
install and update still go through signed bundle and signed catalog verification as described in
[app-catalogs.md](app-catalogs.md) and [app-update-lifecycle.md](app-update-lifecycle.md).

## Run strict checks

Run the beta test wrapper in strict mode:

```bash
crypta-app test --bundle-dir build/dev-apps/queue-dashboard --strict
```

Strict mode should be treated as the pre-signing gate. It is expected to include bundle validation,
Platform API compatibility verification, and static UI lint checks. For static UI bundles, the UI
lint checks cover local-resource rules, SDK/bootstrap ordering, obvious CSP mistakes, accessibility
basics, permission disclosure, and design-system adoption. The base checks are documented in
[app-ui-design-system.md](app-ui-design-system.md).

You can also run the base commands directly when you need narrower feedback:

```bash
crypta-app ui lint --bundle-dir build/dev-apps/queue-dashboard --strict
crypta-app validate --bundle-dir build/dev-apps/queue-dashboard --strict
crypta-app compat verify --bundle-dir build/dev-apps/queue-dashboard --strict
```

Do not sign or catalog a bundle that fails strict checks. A warning promoted to an error usually
means the bundle is relying on an unknown permission, stale compatibility metadata, missing
permission disclosure, remote UI resource, or unsupported design-system pattern.

## Generate local keys

Generate local development key pairs outside the repository:

```bash
mkdir -p "$HOME/.crypta-dev/keys"
crypta-app keys generate \
  --key-id dev-local-bundle \
  --private-key-file "$HOME/.crypta-dev/keys/dev-local-bundle-private.der" \
  --public-key-file "$HOME/.crypta-dev/keys/dev-local-bundle-public.der" \
  --trusted-keys-file "$HOME/.crypta-dev/keys/trusted-app-keys.properties" \
  --overwrite
crypta-app keys generate \
  --key-id dev-local-catalog \
  --private-key-file "$HOME/.crypta-dev/keys/dev-local-catalog-private.der" \
  --public-key-file "$HOME/.crypta-dev/keys/dev-local-catalog-public.der" \
  --overwrite
```

Use different key ids for different trust roles when possible:

| Role | Example key id | What it signs |
| --- | --- | --- |
| Bundle publisher | `dev-local-bundle` | `cryptad-app.digests` through `cryptad-app.signature`. |
| Catalog publisher | `dev-local-catalog` | `cryptad-app-catalog.properties` through `cryptad-app-catalog.signature`. |
| Reviewer | `dev-review` | Independent review receipt payload bytes provisioned through the review-key registry. |

Local development keys are not production keys. Do not commit private keys, reviewer private keys,
trusted-key registries containing private material, private insert URIs, or generated secrets.

## Sign, pack, and verify the bundle

Sign the staged bundle:

```bash
crypta-app sign \
  --bundle-dir build/dev-apps/queue-dashboard \
  --key-id dev-local-bundle \
  --private-key-file "$HOME/.crypta-dev/keys/dev-local-bundle-private.der"
```

The bundle signature authenticates the bundle payload. It writes the root sidecars
`cryptad-app.digests` and `cryptad-app.signature`. The digest sidecar includes the manifest and
regular bundle files and excludes reserved distribution sidecars.

Pack the signed bundle as a catalog artifact:

```bash
mkdir -p dist/apps
crypta-app pack \
  --bundle-dir build/dev-apps/queue-dashboard \
  --output dist/apps/queue-dashboard-0.1.0.zip \
  --overwrite
```

Verify the signed staged bundle with the trusted public key:

```bash
crypta-app verify \
  --bundle-dir build/dev-apps/queue-dashboard \
  --trusted-keys-file "$HOME/.crypta-dev/keys/trusted-app-keys.properties"
```

Packing does not make an unsigned or invalid bundle trusted. The runtime catalog install path still
verifies artifact size, artifact SHA-256, extracted bundle signature, and manifest id/version before
AppHost receives the bundle.

## Create a catalog entry descriptor

Create an entry descriptor for the packed artifact:

```bash
mkdir -p dist/catalog
crypta-app catalog entry \
  --bundle-dir build/dev-apps/queue-dashboard \
  --output dist/catalog/queue-dashboard-entry.properties \
  --artifact dist/apps/queue-dashboard-0.1.0.zip \
  --bundle-uri "crypta:CHK@..." \
  --summary "Inspect and manage local transfer queue state." \
  --homepage "https://example.invalid/apps/queue-dashboard" \
  --source "https://example.invalid/src/queue-dashboard" \
  --license "MIT" \
  --category productivity \
  --minimum-crypta-version 1481 \
  --permission-rationale "queue.read=Reads local queue state." \
  --permission-rationale "queue.write=Cancels or reprioritizes selected queue entries." \
  --overwrite
```

The descriptor is authoring input for `catalog create`; it is not the app manifest and is not the
signed catalog. It should name the exact ZIP artifact so the catalog writer can compute the public
artifact size and lowercase SHA-256 digest from the bytes that will be distributed.

If the beta `catalog entry` helper is not available in your launcher, write the descriptor manually
using the shape in [app-dev-cli.md](app-dev-cli.md#catalog-descriptor-and-flow):

```properties
artifact.path=/abs/path/to/dist/apps/queue-dashboard-0.1.0.zip
bundle.uri=crypta:CHK@...
summary=Inspect and manage local transfer queue state.
name=Queue Dashboard
version=0.1.0
permissions=queue.read,queue.write
app.id=queue-dashboard
homepage=https://example.invalid/apps/queue-dashboard
source=https://example.invalid/src/queue-dashboard
license=MIT
categories=productivity
permissions.rationale.queue.read=Reads local queue state.
permissions.rationale.queue.write=Cancels or reprioritizes selected queue entries.
api.minimumVersion=1
api.maximumTestedVersion=1
api.experimentalCapabilitiesAccepted=false
```

Catalog entry metadata is for operator display, compatibility hints, and review context. Permission
rationales do not grant capabilities. URI fields do not fetch automatically in the Web Shell unless
the operator takes an explicit action.

Feed-style apps that use Platform API v8 subscriptions should declare `content.subscribe` for
`/api/v1/content/subscriptions` and `content.fetch` for `POST /api/v1/content/fetch`. Use SDK feed
and subscription helpers such as `CryptaPlatform.content.subscriptions.*`,
`CryptaPlatform.feed.fetchSnapshot`, and `CryptaPlatform.feed.publishSnapshot`. If the app also
publishes generated feed documents, add
`content.insert.app-document`, `queue.write`, and `queue.read` with permission rationales. Do not
write raw feed bodies, raw request bodies, private insert URIs, app/browser tokens, form passwords,
or local paths into catalog descriptors, mock fixtures, UI lint JSON, or release evidence.

## Optional review receipt

A review receipt is independent reviewer evidence. It is not the bundle signature and not the
catalog signature. Create one before catalog creation when your policy requires review evidence:

```bash
crypta-app review sign \
  --catalog-entry dist/catalog/queue-dashboard-entry.properties \
  --receipt-file dist/catalog/queue-dashboard-review.properties \
  --reviewer-key-id dev-review \
  --reviewer-private-key-file /abs/path/outside/repo/dev-review-private.der \
  --policy-id crypta-app-review-v1 \
  --policy-version 1 \
  --status reviewed \
  --note "Reviewed for local beta testing." \
  --overwrite
```

Verify it with a trusted reviewer-key registry:

```bash
crypta-app review verify \
  --catalog-entry dist/catalog/queue-dashboard-entry.properties \
  --receipt-file dist/catalog/queue-dashboard-review.properties \
  --trusted-reviewer-keys-file /abs/path/outside/repo/trusted-reviewers.properties
```

The receipt binds a reviewer decision to the app id, app version, artifact digest, artifact size,
reviewer policy, reviewer key id, timestamps, and optional evidence. A trusted `rejected` receipt
is still not a positive review. Publisher-advisory `review.status=reviewed` is not the same thing
as a trusted review receipt.

## Create, sign, and verify the catalog

Create the catalog properties file:

```bash
crypta-app catalog create \
  --catalog-file dist/catalog/cryptad-app-catalog.properties \
  --catalog-id dev-queue-dashboard \
  --name "Development Queue Dashboard" \
  --entry dist/catalog/queue-dashboard-entry.properties \
  --review-receipt dist/catalog/queue-dashboard-review.properties \
  --overwrite
```

Sign the exact catalog bytes:

```bash
crypta-app catalog sign \
  --catalog-file dist/catalog/cryptad-app-catalog.properties \
  --key-id dev-local-catalog \
  --private-key-file "$HOME/.crypta-dev/keys/dev-local-catalog-private.der"
```

Verify the catalog and sibling signature:

```bash
crypta-app catalog verify \
  --catalog-file dist/catalog/cryptad-app-catalog.properties \
  --trusted-key-id dev-local-catalog \
  --trusted-public-key-file "$HOME/.crypta-dev/keys/dev-local-catalog-public.der"
```

The catalog signature authenticates the exact bytes of
`dist/catalog/cryptad-app-catalog.properties`. Do not sort, rewrite, or reformat that file after
signing. A valid catalog signature authenticates catalog bytes and publisher metadata only; it does
not authenticate the extracted app payload, does not grant Platform API permissions, and does not
make reviewer claims trusted.

## Dry-run USK publication

Prepare a dry-run catalog publication plan:

```bash
crypta-app publish-usk \
  --catalog-file dist/catalog/cryptad-app-catalog.properties \
  --catalog-signature-file dist/catalog/cryptad-app-catalog.signature \
  --catalog-source "crypta:USK@.../apps/dev-queue-dashboard/cryptad-app-catalog.properties" \
  --output dist/catalog/publish-plan.md \
  --dry-run
```

Dry-run mode must not insert catalog bytes, signature bytes, or app artifacts into Crypta. Treat it
as a plan and validation step: it should confirm which files would be published, which USK path
would be used, which public source URI operators would add, and whether the catalog and signature
sidecar files are present and parse.

Live insertion is different. A live publish uses an insert-capable key, contacts a real localhost
daemon, consumes network resources, and may make the catalog source discoverable to anyone who
knows the corresponding public URI. The release/operator form is explicit:

```bash
crypta-app publish-usk --live \
  --catalog-file dist/catalog/cryptad-app-catalog.properties \
  --catalog-signature-file dist/catalog/cryptad-app-catalog.signature \
  --catalog-source "crypta:USK@.../apps/dev-queue-dashboard/cryptad-app-catalog.properties" \
  --private-insert-uri-env CRYPTAD_FIRST_PARTY_CATALOG_INSERT_URI \
  --node-base-url http://127.0.0.1:8888/api/v1 \
  --form-password-env CRYPTAD_CERT_FORM_PASSWORD \
  --trusted-keys-file "$HOME/.crypta-dev/keys/trusted-app-keys.properties" \
  --output dist/catalog/live-publication-summary.json
```

The private insert URI and form password must come from an environment variable or protected file,
not from a positional argument. Live mode publishes `cryptad-app-catalog.properties` and the
`cryptad-app-catalog.signature` sibling at the same USK path and edition, then writes a sanitized
summary. The summary may include the public `crypta:USK@.../cryptad-app-catalog.properties`
source, digest values, catalog id, signing key id, and queue status, but it must not include private
insert URIs, private keys, form passwords, tokens, raw request bodies, or absolute staging paths.
The private insert URI must be the matching private USK directory insert URI for the configured
public source parent. For example,
`crypta:USK@PUBLIC.../catalog/42/cryptad-app-catalog.properties` is inserted from the secure
private USK root for the same `catalog/42` parent path, supplied only through the env/file option.
Because the queue insert path reads staged disk files after the request is queued, the CLI retains
the two public sidecar files until the live insert has finished consuming them. `--verify-live-fetch`
proves the currently fetched public catalog and signature match the local signed files, but it is not
treated as proof that the queued insert has consumed the staged directory.

## Runtime trust model

Keep the beta toolkit boundaries explicit:

| Boundary | What it means | What it does not mean |
| --- | --- | --- |
| Mock dev server | Local fixture-backed UI and SDK iteration. | Real daemon install, real AppHost launch, live catalog refresh, or network insertion. |
| Real daemon | Runtime Platform API, AppHost lifecycle, browser-session issuance, audit, catalog refresh, and Crypta transport. | Automatic trust in unsigned bundles or untrusted catalogs. |
| Dry-run publish | Local validation and publication plan. | Live insertion or public availability. |
| Live insertion | Bytes are submitted to Crypta through a real insert path. | Catalog or bundle trust; signatures still verify locally. |
| Catalog signature | Authenticates catalog properties bytes and publisher metadata. | Bundle payload trust or reviewer trust. |
| Bundle signature | Authenticates the staged app payload through digest and signature sidecars. | Catalog publisher trust or reviewer approval. |
| Review receipt | Authenticates independent reviewer evidence with a trusted reviewer key. | App signing authority, catalog signing authority, or permission grant. |
| `crypta:` URI | Transport location for catalog sidecars or immutable CHK artifacts. | Trust boundary. Signatures, sizes, and digests remain mandatory. |

Catalog sources may use `crypta:` USK/SSK paths for catalog sidecars or CHK companion forms for
immutable catalog bytes. App ZIP artifacts published through catalogs must use supported artifact
URI forms documented in [app-catalogs.md](app-catalogs.md#source-and-artifact-fetching). A
`crypta:CHK@...` artifact URI is only a byte transport. The runtime still enforces the catalog
declared size and SHA-256 before extracting and verifying the signed bundle.

## Process tokens and browser sessions

AppHost launch tokens and app browser sessions are separate credentials.

An AppHost process receives a fresh `CRYPTAD_APP_TOKEN` at launch. Process-originated Platform API
requests authenticate with that token and then pass the central capability matrix. The token must
not appear in browser bootstrap JSON, logs, diagnostics, catalog responses, audit entries, or
operator-facing errors.

An app-owned static UI receives a short-lived browser session through the app bootstrap route and
uses it as `X-Crypta-App-Session`. The browser session is origin-bound to the installed app UI and
is not an AppHost process token. The browser SDK keeps it in memory and must not persist it to
`localStorage`, `sessionStorage`, cookies, or catalog metadata.

A valid process token or browser session is still not enough by itself. The requested route must
allow the app principal and the signed manifest must declare the required capability. Missing
capability returns an authorization failure even when authentication succeeds.

## UI lint and design-system expectations

Static app UI should use local bundle assets only. Load the browser SDK from
`./crypta-platform.js` and the design-system assets from `./crypta-ui/`. Do not add CDN CSS,
remote JavaScript, third-party font loads, or silent screenshot/image fetches from catalog
metadata.

`crypta-app test --strict` and `crypta-app ui lint --strict` should fail static UI bundles that
violate the local-resource model, omit permission disclosure, drift from SDK/bootstrap ordering, or
depend on unsupported design-system patterns. The lint is an offline developer gate. Runtime
authorization, token handling, and catalog verification still happen server-side.

## API compatibility

Bundle manifests should declare Platform API compatibility metadata:

```properties
api.minimumVersion=1
api.maximumTestedVersion=1
api.experimentalCapabilitiesAccepted=false
```

Stable-only templates such as `queue-dashboard` and `publisher` keep experimental capability
acceptance disabled. The `vault-profile` template enables
`api.experimentalCapabilitiesAccepted=true` because its default `vault.*` permissions exercise
experimental app-vault capabilities.

Run compatibility checks before signing:

```bash
crypta-app api snapshot --output build/platform-api-contract.json
crypta-app compat verify \
  --bundle-dir build/dev-apps/queue-dashboard \
  --contract build/platform-api-contract.json \
  --strict
crypta-app compat verify \
  --catalog-entry dist/catalog/queue-dashboard-entry.properties \
  --contract build/platform-api-contract.json \
  --strict
```

The verifier checks declared API versions, optional and experimental capability use, deprecated or
scheduled capabilities, and catalog descriptor mismatches against the referenced bundle. Warnings
become failures with `--strict`.

## Related docs

- [app-platform-developer-portal.md](app-platform-developer-portal.md) is the app ecosystem beta
  entry point.
- [app-platform-beta-tutorials.md](app-platform-beta-tutorials.md) gives copyable offline beta
  tutorials.
- [app-platform-beta-known-limitations.md](app-platform-beta-known-limitations.md) records beta
  limits and safety boundaries.
- [app-platform-beta-program.md](app-platform-beta-program.md) covers app submission, feedback, and
  release closeout.
- [app-dev-cli.md](app-dev-cli.md) documents the base standalone CLI workflow.
- [app-distribution.md](app-distribution.md) documents signed bundle sidecars and runtime trusted
  key inputs.
- [app-catalogs.md](app-catalogs.md) documents catalog format, source transport, artifact
  verification, and review trust.
- [first-party-beta-catalog.md](first-party-beta-catalog.md) covers first-party catalog
  publication and Web Shell onboarding.
- [app-ui-design-system.md](app-ui-design-system.md) documents static UI assets and offline lint.
- [platform-sdk-js.md](platform-sdk-js.md) documents the browser SDK and browser session handling.
- [app-permissions-and-audit.md](app-permissions-and-audit.md) documents process principals,
  browser principals, permission checks, and audit redaction.
- [platform-api-contract.md](platform-api-contract.md) documents API compatibility snapshots and
  verifier behavior.
