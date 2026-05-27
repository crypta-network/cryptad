# Developer app CLI

This document describes the `crypta-app` command for scaffolding, validating, signing, packing,
and cataloging standalone AppHost bundles.

## Scope

Use `crypta-app` for developer-owned bundles that live outside the first-party `apps/*` Gradle
projects. The command works on a staged bundle directory containing `cryptad-app.properties`,
launch files, and optional `static/` assets. The scaffold is a standalone staged bundle directory,
not a new Gradle subproject.

The signing, packing, validation, and catalog commands are offline filesystem tooling. The beta
toolkit adds a local mock development server for static app UI iteration, but it is not hot reload
and it is not a daemon-side install command. Install and update flows still go through the Platform
API or signed catalog source handling described in [app-catalogs.md](app-catalogs.md).

First-party repo apps can keep using their existing Gradle tasks. See
[First-party Gradle workflow](#first-party-gradle-workflow).

For the beta sidecar workflow, including `init --template queue-dashboard`, the mock development
server, strict beta test wrapper, local key generation, `publish-usk --dry-run`, and the explicit
`publish-usk --live` release/operator path, see [developer-beta-toolkit.md](developer-beta-toolkit.md).
For the full beta portal and submission path, see
[app-platform-developer-portal.md](app-platform-developer-portal.md).

## Build and run the command

`crypta-app` is delivered by the `:platform-devtools` application plugin. Build an installed
launcher with:

```bash
./gradlew :platform-devtools:installDist
```

The generated script is under the `installDist` output, typically:

```bash
platform-devtools/build/install/crypta-app/bin/crypta-app --help
```

On Windows, use the matching `crypta-app.bat` launcher from the generated `bin` directory.

You can also run the application plugin task directly while iterating:

```bash
./gradlew :platform-devtools:run --args='--help'
./gradlew :platform-devtools:run --args='validate --bundle-dir build/dev-apps/hello-queue'
```

## Scaffold a staged bundle

Command shape:

```bash
crypta-app init \
  --dir <staged-dir> \
  --app-id <app-id> \
  --name <display-name> \
  --version <version> \
  [--template static-basic|queue-dashboard|publisher|vault-profile] \
  [--ui-mode static|shell-panel|none] \
  [--permission <capability>] \
  [--overwrite]
```

Example:

```bash
crypta-app init \
  --dir build/dev-apps/hello-queue \
  --app-id hello-queue \
  --name "Hello Queue" \
  --version 0.1.0 \
  --ui-mode static \
  --permission queue.read \
  --permission queue.write
```

Repeat `--permission` for each Platform API capability the app needs. Current capability names are
listed in [app-permissions-and-audit.md](app-permissions-and-audit.md). The developer tooling also
recognizes the app-vault capability names `vault.secrets.read`, `vault.secrets.write`,
`vault.identities.read`, `vault.identities.create`, `vault.identities.use`, and
`vault.identities.manage`; see [app-secret-and-identity-vault.md](app-secret-and-identity-vault.md)
before requesting them. It also recognizes Trust Graph Preview capabilities `trust.read` and
`trust.write`; see [trust-graph-preview.md](trust-graph-preview.md) before using them. Use
`--overwrite` only when you deliberately want to replace an existing
scaffolded directory.

The `static` scaffold is expected to produce a bundle shaped like:

```text
build/dev-apps/hello-queue/
  cryptad-app.properties
  bin/start.sh
  static/index.html
  static/app.js
  static/app.css
  static/crypta-platform.js
  static/crypta-ui/crypta-ui-tokens.css
  static/crypta-ui/crypta-ui.css
  static/crypta-ui/crypta-ui-components.js
```

When the browser SDK resource is available, the static template copies or vendors it as
`static/crypta-platform.js`. Static pages should load it with `./crypta-platform.js`; see
[platform-sdk-js.md](platform-sdk-js.md). The static template also copies the canonical Crypta UI
design-system assets under `static/crypta-ui/` and links the token stylesheet, base stylesheet, and
app stylesheet in that order. See [app-ui-design-system.md](app-ui-design-system.md) for the
supported `cr-*` vocabulary, local-resource rules, and permission-disclosure guidance. If the
scaffold is created with `--ui-mode none`, no browser UI is declared. If it uses
`--ui-mode shell-panel`, the manifest points at a shell-panel entry instead of an app-owned static
route.

`--template` defaults to `static-basic`, which preserves the minimal static scaffold. The beta
templates `queue-dashboard`, `publisher`, and `vault-profile` are static-only examples that vendor
the same SDK and design-system assets, declare the permissions they demonstrate, and include visible
permission disclosure. They are intended as staged bundles for app authors, not new Gradle
subprojects. The `publisher` template uses the same `sourcePath`, `insertUri`, and `identifier`
form fields accepted by `/api/v1/queue/inserts/file`; it does not read local files through browser
file inputs. The `vault-profile` template sets `api.experimentalCapabilitiesAccepted=true` because
the current vault capabilities are experimental. See
[developer-beta-toolkit.md](developer-beta-toolkit.md) for the complete mock-dev, offline-test,
signing, catalog, and dry-run publication flow.

A static scaffold should produce a manifest with fields like:

```properties
manifest.version=1
app.id=hello-queue
app.name=Hello Queue
app.version=0.1.0
app.exec=bin/start.sh
app.ui.mode=static
app.ui.entry=static/index.html
sandbox.mode=none
sandbox.required=false
app.permissions=queue.read,queue.write
api.minimumVersion=1
api.maximumTestedVersion=1
api.experimentalCapabilitiesAccepted=false
quota.data.bytes=0
quota.cache.bytes=0
app.restart.policy=never
app.restart.maxAttempts=0
app.restart.backoff.ms=0
```

The manifest is part of the signed payload. Change app id, version, executable path, UI fields, or
permissions before signing, then validate again.

## Validate, sign, pack, and verify

Validate the staged bundle before signing:

```bash
crypta-app validate --bundle-dir build/dev-apps/hello-queue
```

Add `--strict` when unknown manifest permissions, compatibility warnings, or
newer-than-tested contract targets should fail the command instead of producing a warning. Strict
validation also runs the static UI linter for `app.ui.mode=static` bundles.

Run the UI linter directly while iterating on app-owned static UI:

```bash
crypta-app ui lint --bundle-dir build/dev-apps/hello-queue
crypta-app ui lint --bundle-dir build/dev-apps/hello-queue --strict
crypta-app ui lint \
  --bundle-dir build/dev-apps/hello-queue \
  --strict \
  --json build/dev-apps/hello-queue-ui-lint.json
```

`crypta-app ui lint` is offline. It checks the staged static UI for local-resource compatibility,
obvious CSP violations, SDK/bootstrap ordering, accessibility basics, permission disclosure, and
design-system adoption. JSON output uses bundle-relative paths so reports can be archived without
developer-specific local paths.

When a static app declares vault capabilities, `crypta-app init` writes the same names into the
visible permission disclosure and `crypta-app ui lint --strict` checks that the disclosure still
matches `app.permissions`. Keep the disclosure path-free and value-free: show capability names and
operator-facing rationale, not secret values, identity private keys, seed phrases, or recovery
phrases.

Sign it with a local development key:

```bash
crypta-app sign \
  --bundle-dir build/dev-apps/hello-queue \
  --key-id dev-local \
  --private-key-file /abs/path/to/dev-app-signing-private.pem
```

This writes `cryptad-app.digests` and `cryptad-app.signature` beside
`cryptad-app.properties`. Keep private keys outside the repository. Prefer `--private-key-file` or
the CLI's environment-variable key input over putting private key bytes on the shell command line.

Pack the signed staged bundle for catalog distribution:

```bash
mkdir -p dist/apps
crypta-app pack \
  --bundle-dir build/dev-apps/hello-queue \
  --output dist/apps/hello-queue-0.1.0.zip \
  --overwrite
```

`crypta-app pack` writes catalog-compatible ZIP artifacts. It rejects bundles with more than 4096
regular-file entries, because the catalog install/update path uses the same entry cap before
extracting artifacts.

Verify the signed staged bundle with the matching trusted public key:

```bash
crypta-app verify \
  --bundle-dir build/dev-apps/hello-queue \
  --trusted-key-id dev-local \
  --trusted-public-key-file /abs/path/to/dev-app-signing-public.pem
```

The catalog install path verifies the catalog signature, the ZIP artifact size and SHA-256, and the
extracted bundle signature before AppHost installs or updates the app. Packing an unsigned bundle
does not make it trusted.

## API compatibility checks

Generate the current offline Platform API compatibility snapshot:

```bash
crypta-app api snapshot --output build/platform-api-contract.json
```

Verify a staged bundle against the built-in current contract:

```bash
crypta-app compat verify --bundle-dir build/dev-apps/hello-queue
```

Verify against an explicit target contract, such as a release-candidate snapshot:

```bash
crypta-app compat verify \
  --bundle-dir build/dev-apps/hello-queue \
  --contract build/platform-api-contract.json
```

The verifier checks unknown manifest permissions, unknown optional capabilities, malformed
`api.*` metadata, app-declared minimum contract versions above the target, target contract versions
above the app's maximum-tested version, experimental capability use without
`api.experimentalCapabilitiesAccepted=true`, and deprecated or scheduled capabilities. It also
checks catalog entry descriptors against the referenced bundle when `--catalog-entry` is used.
Warnings become failures with `--strict`.

## Catalog descriptor and flow

`crypta-app catalog create` can build a `cryptad-app-catalog.properties` file from one or more app
entry descriptors. A descriptor is CLI input, not the installed app manifest and not the generated
catalog entry. It points at a local ZIP artifact so the catalog writer can compute the public
catalog size and SHA-256 fields from the exact bytes:

```properties
# catalog-entry.properties
artifact.path=/abs/path/to/dist/apps/hello-queue-0.1.0.zip
bundle.uri=https://example.invalid/apps/hello-queue-0.1.0.zip
summary=Example static UI that reads the local queue.
name=Hello Queue
version=0.1.0
permissions=queue.read,queue.write
app.id=hello-queue
homepage=https://example.invalid/apps/hello-queue
source=https://example.invalid/src/hello-queue
license=MIT
categories=productivity,network
minimumCryptaVersion=1481
review.status=reviewed
review.note=Reviewed for local operator safety.
permissions.rationale.queue.read=Reads the local transfer queue.
permissions.rationale.queue.write=Lets the app cancel or reprioritize requests.
screenshot.1=https://example.invalid/assets/hello-queue-1.png
changelog.summary=Adds queue retry controls.
changelog.uri=https://example.invalid/apps/hello-queue-0.1.0-changelog.txt
api.minimumVersion=1
api.maximumTestedVersion=1
api.optionalCapabilities=alerts.read,diagnostics.read
api.experimentalCapabilitiesAccepted=false
```

A Site Publisher local catalog descriptor should include explicit permission rationales:

```properties
artifact.path=/abs/path/to/dist/apps/site-publisher-1.0.0.zip
bundle.uri=file:/abs/path/to/dist/apps/site-publisher-1.0.0.zip
summary=Reference app for publishing a local static site through Crypta.
name=Site Publisher
version=1.0.0
permissions=queue.read,queue.write,content.insert
app.id=site-publisher
homepage=https://example.invalid/apps/site-publisher
source=https://example.invalid/src/site-publisher
license=GPL-3.0-only
categories=publishing,content
review.status=reviewed
review.note=First-party content reference app.
permissions.rationale.content.insert=Submits selected local site content to the insert pipeline.
permissions.rationale.queue.write=Creates insert requests for the publish operation.
permissions.rationale.queue.read=Displays publish progress from the local transfer queue.
changelog.summary=Adds the first content reference app.
api.minimumVersion=3
api.maximumTestedVersion=10
api.experimentalCapabilitiesAccepted=false
```

Do not include `vault.identities.*` permissions for Site Publisher. Profile Publisher owns the
identity-profile reference flow. A Profile Publisher catalog descriptor should include the
route-specific vault and generated-document rationale:

```properties
artifact.path=/abs/path/to/dist/apps/profile-publisher-1.0.0.zip
bundle.uri=file:/abs/path/to/dist/apps/profile-publisher-1.0.0.zip
summary=Reference app for publishing an identity-bound profile document.
name=Profile Publisher
version=1.0.0
permissions=queue.read,queue.write,content.insert.app-document,vault.identities.read,vault.identities.create,vault.identities.use,app.data.read,app.data.write
app.id=profile-publisher
homepage=https://example.invalid/apps/profile-publisher
source=https://example.invalid/src/profile-publisher
license=GPL-3.0-only
categories=publishing,identity
review.status=reviewed
review.note=First-party profile reference app.
permissions.rationale.vault.identities.create=Creates an app-owned profile identity without exporting private material.
permissions.rationale.vault.identities.use=Uses the profile-document route for identity-bound profile publishing.
permissions.rationale.content.insert.app-document=Queues the generated profile document through app-document insert without local source-path authority.
permissions.rationale.queue.write=Creates the generated document insert request.
permissions.rationale.queue.read=Displays publish progress from the local transfer queue.
permissions.rationale.app.data.read=Restores bounded profile drafts and publish summaries.
permissions.rationale.app.data.write=Saves bounded profile drafts and publish summaries.
changelog.summary=Adds the first identity-profile reference app.
api.minimumVersion=9
api.maximumTestedVersion=10
api.experimentalCapabilitiesAccepted=true
```

Do not include tokens, form passwords, private insert URIs, raw request bodies, private keys,
signatures, or absolute staging paths in descriptor notes, generated catalog metadata, or release
evidence.

A Feed Reader catalog descriptor should include the content-subscription, content-fetch, durable
app-data, generated-document publication permissions, and minimum-v9, tested-through-v10 API
compatibility metadata:

```properties
artifact.path=/abs/path/to/dist/apps/feed-reader-1.0.0.zip
bundle.uri=file:/abs/path/to/dist/apps/feed-reader-1.0.0.zip
summary=Reference app for reading and publishing feed documents through Crypta.
name=Feed Reader & Publisher
version=1.0.0
permissions=content.fetch,content.subscribe,content.insert.app-document,queue.read,queue.write,app.data.read,app.data.write
app.id=feed-reader
homepage=https://example.invalid/apps/feed-reader
source=https://example.invalid/src/feed-reader
license=GPL-3.0-only
categories=reader,publishing,content
review.status=reviewed
review.note=First-party feed reference app.
permissions.rationale.content.fetch=Fetches subscribed feed documents through POST /api/v1/content/fetch without local source-path authority.
permissions.rationale.content.subscribe=Registers bounded USK subscriptions with the platform scheduler and stores metadata only.
permissions.rationale.content.insert.app-document=Queues generated feed documents through app-document insert.
permissions.rationale.queue.write=Creates generated feed publication inserts.
permissions.rationale.queue.read=Displays publication progress from the local transfer queue.
permissions.rationale.app.data.read=Restores the app-owned feed list, selected subscriptions, read state, and safe draft metadata.
permissions.rationale.app.data.write=Saves bounded app-owned reader state through the durable app-data API.
changelog.summary=Adds the first feed reader and publisher reference app.
api.minimumVersion=9
api.maximumTestedVersion=10
api.experimentalCapabilitiesAccepted=false
```

Feed Reader evidence must not include raw feed bodies, raw fetched content, raw request bodies,
private insert URIs, app process tokens, browser-session tokens, form passwords, queue HTML, or
local paths.

Only `artifact.path`, `bundle.uri`, and `summary` are required. The writer derives the catalog app
id and version from the ZIP artifact's root `cryptad-app.properties`; descriptor `app.id` and
`version` values are optional consistency checks and must match the artifact manifest. The `name`
and `permissions` fields can override the display metadata and permission hints written to the
catalog.

Descriptors can also author optional app-store metadata:

| Descriptor property | Generated catalog property |
| --- | --- |
| `homepage` | `app.<id>.homepage` |
| `source` | `app.<id>.source` |
| `license` | `app.<id>.license` |
| `categories` | `app.<id>.categories` |
| `minimumCryptaVersion` | `app.<id>.minimumCryptaVersion` |
| `review.status` | `app.<id>.review.status` |
| `review.note` | `app.<id>.review.note` |
| `permissions.rationale.<permission>` | `app.<id>.permissions.rationale.<permission>` |
| `screenshot.N` | `app.<id>.screenshot.N` |
| `changelog.summary` | `app.<id>.changelog.summary` |
| `changelog.uri` | `app.<id>.changelog.uri` |
| `api.minimumVersion` | `app.<id>.api.minimumVersion` |
| `api.maximumTestedVersion` | `app.<id>.api.maximumTestedVersion` |
| `api.optionalCapabilities` | `app.<id>.api.optionalCapabilities` |
| `api.experimentalCapabilitiesAccepted` | `app.<id>.api.experimentalCapabilitiesAccepted` |

These fields are optional. A descriptor and artifact with no app-store metadata and no API
compatibility metadata generate a minimal `catalog.version=1` catalog. Descriptors that include
any app-store metadata, or descriptors/artifacts that declare API compatibility metadata, generate
`catalog.version=2` so strict v1 catalog consumers reject the expanded schema cleanly instead of
accepting unknown fields.
`homepage`, `source`, `screenshot.N`, and `changelog.uri` are URI metadata for operator display.
`review.status` and `review.note` are advisory and do not replace signed catalog or signed bundle
verification. `minimumCryptaVersion` is advisory and does not block install/update by itself;
integer Cryptad build labels are the comparable form used by Platform API responses. Permission
rationales explain declared permissions; they do not grant capabilities.

API compatibility metadata is advisory. The signed bundle manifest remains authoritative for the
app artifact, and catalog-vs-bundle mismatches are reported by `crypta-app compat verify`.

Independent review receipts are separate from descriptor `review.status` and `review.note`. A
receipt signs a canonical payload that binds the reviewer decision to the descriptor's app id,
version, artifact SHA-256, artifact size, reviewer policy, reviewer key id, review timestamps, and
optional evidence metadata. The receipt is later embedded into the signed catalog with
`--review-receipt`, but the catalog signature does not make the receipt trusted by itself.

`artifact.path` is local authoring input and is not written to the public catalog. Do not change
the ZIP after creating the catalog; the generated catalog records its size and lowercase SHA-256
digest.

`bundle.uri` is the public ZIP artifact location written into the signed catalog entry. Current
catalog entries can use `file:`, `https:`, or loopback `http:` artifact URIs. `crypta:` catalog
sources are supported by the runtime catalog refresh flow, but `bundle.uri=crypta:...` is rejected
unless `platform-appcatalog` adds explicit Crypta artifact fetching. Keep Crypta keys for the
catalog properties and catalog signature sidecars, not for app bundle artifacts.

Create and verify an independent app review receipt before signing the catalog:

```bash
crypta-app review sign \
  --catalog-entry catalog-entry.properties \
  --receipt-file review-receipt.properties \
  --reviewer-key-id crypta-first-party-review \
  --reviewer-private-key-file /abs/path/to/reviewer-private.pem \
  --policy-id crypta-app-review-v1 \
  --policy-version 1 \
  --status reviewed \
  --evidence-file review-evidence.json \
  --overwrite

crypta-app review verify \
  --catalog-entry catalog-entry.properties \
  --receipt-file review-receipt.properties \
  --trusted-reviewer-keys-file /abs/path/to/trusted-reviewers.properties
```

Reviewer private keys are local reviewer material, not app or catalog signing keys. Do not commit
them. The trusted reviewer keys file is distinct from the AppHost trusted app-key file:

```properties
trusted.reviewers.version=1
reviewer.1.id=crypta-first-party-review
reviewer.1.algorithm=Ed25519
reviewer.1.public.key.base64=<X.509 Ed25519 public key bytes>
reviewer.1.display.name=Crypta First-Party Review
reviewer.1.policy.id=crypta-app-review-v1
```

Registry version 1 remains supported and treats keys as active with no explicit validity window.
For governed review workflows, prefer registry version 2 so the local trust root records
policy-version constraints and reviewer key lifecycle state:

```properties
trusted.reviewers.version=2
reviewer.1.id=crypta-first-party-review-2026q2
reviewer.1.algorithm=Ed25519
reviewer.1.public.key.base64=<X.509 Ed25519 public key bytes>
reviewer.1.display.name=Crypta First-Party Review Q2 2026
reviewer.1.policy.id=crypta-app-review
reviewer.1.policy.version=1
reviewer.1.status=active
reviewer.1.valid.from=2026-04-01T00:00:00Z
reviewer.1.valid.until=2026-07-01T00:00:00Z
```

Inspect, migrate, and validate reviewer registries with:

```bash
crypta-app review keys inspect \
  --trusted-reviewer-keys-file trusted-reviewers.properties

crypta-app review keys migrate \
  --trusted-reviewer-keys-file trusted-reviewers-v1.properties \
  --output trusted-reviewers-v2.properties

crypta-app review keys verify-lifecycle \
  --trusted-reviewer-keys-file trusted-reviewers.properties
```

Verify a local review transparency log with:

```bash
crypta-app review transparency verify \
  --log-file review-transparency-log.jsonl
```

These commands print redacted summaries. They do not print reviewer private keys, raw public key
bytes, raw receipt signatures, local evidence contents, app browser sessions, AppHost process
tokens, or local transparency-store paths.

`review sign` accepts `--reviewer-private-key-base64`, `--reviewer-private-key-file`, or
`--reviewer-private-key-env`. `--evidence-file` records the file's SHA-256 in the receipt; use
`--evidence-sha256` when the evidence digest was computed elsewhere. Verification fails closed for
app id/version mismatches, artifact digest or size mismatches, unknown reviewer keys,
retired/revoked/out-of-window reviewer keys, policy id/version mismatches, expired receipts,
invalid signatures, malformed fields, and unsupported algorithms. A verified `rejected` receipt is
trusted evidence but is not a positive review.

Create the catalog properties file after the receipt exists:

```bash
crypta-app catalog create \
  --catalog-file dist/catalog/cryptad-app-catalog.properties \
  --catalog-id dev \
  --name "Development Apps" \
  --entry catalog-entry.properties \
  --review-receipt review-receipt.properties
```

Sign the exact catalog bytes:

```bash
crypta-app catalog sign \
  --catalog-file dist/catalog/cryptad-app-catalog.properties \
  --key-id dev-local \
  --private-key-file /abs/path/to/dev-app-signing-private.pem
```

Verify the catalog and sibling signature:

```bash
crypta-app catalog verify \
  --catalog-file dist/catalog/cryptad-app-catalog.properties \
  --trusted-key-id dev-local \
  --trusted-public-key-file /abs/path/to/dev-app-signing-public.pem
```

The sign command writes `cryptad-app-catalog.signature` beside
`cryptad-app-catalog.properties`. Do not rewrite, sort, or reformat the catalog after signing.

`crypta-app` does not publish catalogs or signatures to Crypta. To offer a public
catalog-over-Crypta source, create and sign the catalog locally, then publish
`cryptad-app-catalog.properties` and `cryptad-app-catalog.signature` with the existing Crypta
publishing workflow. Runtime catalog sources can reference a path-like USK/SSK catalog location
with sibling signature sidecar, or the CHK v1 companion form
`crypta:CHK@<catalog-key>?signature=CHK@<signature-key>`.

## First-party Gradle workflow

The developer CLI is for standalone bundle directories. First-party apps in this repository already
have Gradle staging tasks that wire the same signing and verification libraries into the app
projects:

```bash
./gradlew :apps:queue-manager:stageApp
./gradlew :apps:queue-manager:signApp
./gradlew :apps:queue-manager:verifyApp

./gradlew :apps:publisher:stageApp
./gradlew :apps:publisher:signApp
./gradlew :apps:publisher:verifyApp

./gradlew :apps:site-publisher:stageApp
./gradlew :apps:site-publisher:signApp
./gradlew :apps:site-publisher:verifyApp

./gradlew :apps:profile-publisher:stageApp
./gradlew :apps:profile-publisher:signApp
./gradlew :apps:profile-publisher:verifyApp

./gradlew :apps:feed-reader:stageApp
./gradlew :apps:feed-reader:signApp
./gradlew :apps:feed-reader:verifyApp

./gradlew :apps:trust-graph:stageApp
./gradlew :apps:trust-graph:signApp
./gradlew :apps:trust-graph:verifyApp
```

Those `signApp` and `verifyApp` tasks still require the signing inputs documented in
[app-distribution.md](app-distribution.md). Use the root `stageFirstPartyApps`,
`signFirstPartyApps`, and `verifyFirstPartyApps` tasks when you need to process all first-party
apps together.

## First-party beta catalog publication

The public beta catalog for first-party apps reuses the existing Gradle and `crypta-app` tooling.
Maintainers should keep generated artifacts under `build/` or `dist/` and keep private signing and
review keys outside the repository.

1. Stage, sign, and verify the first-party bundles:

   ```bash
   ./gradlew stageFirstPartyApps
   ./gradlew signFirstPartyApps
   ./gradlew verifyFirstPartyApps
   ./gradlew :platform-devtools:installDist
   ```

2. Pack `queue-manager`, `publisher`, `site-publisher`, `profile-publisher`, `feed-reader`, and
   `trust-graph` with
   `crypta-app pack`. Insert each ZIP into Crypta as an immutable CHK artifact through the
   maintainer publishing workflow.

3. Write catalog descriptors whose public artifact location is the returned CHK:

   ```properties
   artifact.path=<path-to-queue-manager.zip>
   bundle.uri=crypta:CHK@...
   summary=Manage local Crypta transfer queues.
   name=Queue Manager
   permissions=queue.read,queue.write
   permissions.rationale.queue.read=Reads local transfer queue state.
   api.minimumVersion=1
   api.maximumTestedVersion=10
   review.status=reviewed
   changelog.summary=First public beta catalog entry.
   ```

4. Create, sign, and verify the catalog with `crypta-app catalog create`, `crypta-app catalog
   sign`, and `crypta-app catalog verify`. Run `crypta-app publish-usk --dry-run` for the
   deterministic plan, then use `crypta-app publish-usk --live` from the release/operator
   environment to publish `cryptad-app-catalog.properties` and the sibling
   `cryptad-app-catalog.signature` at the same USK edition. The private insert URI must be the
   matching private USK directory insert URI for the configured public source parent. The CLI
   retains the staged public sidecars until the live queue has consumed them and records only a
   path-free warning in the summary; `--verify-live-fetch` verifies the currently fetchable public
   bytes, but it does not authorize deleting disk-backed staging.

5. Configure runtime onboarding with `CRYPTAD_FIRST_PARTY_CATALOG_SOURCE` and
   `CRYPTAD_FIRST_PARTY_CATALOG_TRUSTED_CATALOG_KEY_ID`, plus the normal `CRYPTAD_APPHOST_*`
   trusted public key settings. The legacy `CRYPTAD_FIRST_PARTY_CATALOG_TRUSTED_KEY_ID` alias is
   still accepted for older packaging. Operators add the catalog through Web Shell or
   `POST /api/v1/app-catalogs/recommended/crypta-first-party-beta/add`; apps are not installed
   until the operator confirms an install/update for each entry.

See [first-party-beta-catalog.md](first-party-beta-catalog.md) for the full maintainer and
operator flow.

## Related docs

- [app-platform-developer-portal.md](app-platform-developer-portal.md) is the app ecosystem beta
  entry point.
- [app-platform-beta-tutorials.md](app-platform-beta-tutorials.md) gives copyable offline beta
  tutorials.
- [developer-beta-toolkit.md](developer-beta-toolkit.md) gives the beta toolkit walkthrough for
  queue-dashboard scaffolding, mock dev runs, strict tests, key generation, signing, cataloging,
  and dry-run USK publication.
- [first-party-beta-catalog.md](first-party-beta-catalog.md) covers first-party catalog publication
  and Web Shell onboarding.
- [app-distribution.md](app-distribution.md) describes the signed bundle sidecars, manifest fields,
  and first-party Gradle tasks.
- [app-ui-design-system.md](app-ui-design-system.md) describes canonical app UI assets and
  `crypta-app ui lint`.
- [app-catalogs.md](app-catalogs.md) describes the runtime catalog format, verification order, and
  Platform API install/update flow.
- [platform-sdk-js.md](platform-sdk-js.md) describes the browser SDK used by app-owned static UI.
- [app-permissions-and-audit.md](app-permissions-and-audit.md) lists the current Platform API
  capability names.
- [platform-api-contract.md](platform-api-contract.md) explains contract versions, stability
  levels, manifest `api.*` fields, and offline compatibility verification.
