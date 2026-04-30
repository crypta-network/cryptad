# Developer app CLI

This document describes the `crypta-app` command for scaffolding, validating, signing, packing,
and cataloging standalone AppHost bundles.

## Scope

Use `crypta-app` for developer-owned bundles that live outside the first-party `apps/*` Gradle
projects. The command works on a staged bundle directory containing `cryptad-app.properties`,
launch files, and optional `static/` assets. The scaffold is a standalone staged bundle directory,
not a new Gradle subproject.

The CLI is offline filesystem tooling. It does not provide hot reload or a daemon-side install
command. Install and update flows still go through the Platform API or signed catalog source
handling described in [app-catalogs.md](app-catalogs.md).

First-party repo apps can keep using their existing Gradle tasks. See
[First-party Gradle workflow](#first-party-gradle-workflow).

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
listed in [app-permissions-and-audit.md](app-permissions-and-audit.md). Use `--overwrite` only when
you deliberately want to replace an existing scaffolded directory.

The `static` scaffold is expected to produce a bundle shaped like:

```text
build/dev-apps/hello-queue/
  cryptad-app.properties
  bin/start.sh
  static/index.html
  static/app.js
  static/app.css
  static/crypta-platform.js
```

When the browser SDK resource is available, the static template copies or vendors it as
`static/crypta-platform.js`. Static pages should load it with `./crypta-platform.js`; see
[platform-sdk-js.md](platform-sdk-js.md). If the scaffold is created with `--ui-mode none`, no
browser UI is declared. If it uses `--ui-mode shell-panel`, the manifest points at a shell-panel
entry instead of an app-owned static route.

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

Add `--strict` when unknown manifest permissions should fail the command instead of producing a
warning.

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
```

Only `artifact.path`, `bundle.uri`, and `summary` are required. The writer derives the catalog app
id and version from the ZIP artifact's root `cryptad-app.properties`; descriptor `app.id` and
`version` values are optional consistency checks and must match the artifact manifest. The `name`
and `permissions` fields can override the display metadata and permission hints written to the
catalog.

Descriptors can also author optional v1 app-store metadata:

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

These fields are optional and backward compatible. `homepage`, `source`, `screenshot.N`, and
`changelog.uri` are URI metadata for operator display. `review.status` and `review.note` are
advisory and do not replace signed catalog or signed bundle verification. `minimumCryptaVersion`
is advisory and does not block install/update by itself; integer Cryptad build labels are the
comparable form used by Platform API responses. Permission rationales explain declared permissions;
they do not grant capabilities.

`artifact.path` is local authoring input and is not written to the public catalog. Do not change
the ZIP after creating the catalog; the generated catalog records its size and lowercase SHA-256
digest.

Create the catalog properties file:

```bash
crypta-app catalog create \
  --catalog-file dist/catalog/cryptad-app-catalog.properties \
  --catalog-id dev \
  --name "Development Apps" \
  --entry catalog-entry.properties
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
```

Those `signApp` and `verifyApp` tasks still require the signing inputs documented in
[app-distribution.md](app-distribution.md). Use the root `stageFirstPartyApps`,
`signFirstPartyApps`, and `verifyFirstPartyApps` tasks when you need to process both first-party
apps together.

## Related docs

- [app-distribution.md](app-distribution.md) describes the signed bundle sidecars, manifest fields,
  and first-party Gradle tasks.
- [app-catalogs.md](app-catalogs.md) describes the runtime catalog format, verification order, and
  Platform API install/update flow.
- [platform-sdk-js.md](platform-sdk-js.md) describes the browser SDK used by app-owned static UI.
- [app-permissions-and-audit.md](app-permissions-and-audit.md) lists the current Platform API
  capability names.
