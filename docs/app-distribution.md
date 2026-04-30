# Signed App Distribution

This document describes Cryptad's local signed staged app bundle workflow for first-party AppHost apps.

## Scope

This page covers the local signed bundle sidecars and Gradle tasks used to stage, sign, and verify
first-party AppHost apps. PR-194 treats staging, signing, and verification as Phase 3 release gates;
see [phase-3-platform-primacy-closeout.md](phase-3-platform-primacy-closeout.md) and
[cryptad-release-workflow-and-runbook.md](cryptad-release-workflow-and-runbook.md).

Related but documented elsewhere:

- Developer CLI workflow for standalone staged bundles: [app-dev-cli.md](app-dev-cli.md)
- Signed catalog sources and remote/local catalog artifact install/update:
  [app-catalogs.md](app-catalogs.md)
- App-owned static UI routing for installed bundles: [app-owned-ui.md](app-owned-ui.md)
- Browser SDK helpers for app-owned static UI: [platform-sdk-js.md](platform-sdk-js.md)
- Catalog distribution over Crypta keys, browser-side bundle uploads, and app sandboxing remain
  future platform work.

## Bundle Files

`stageApp` still produces an unsigned staged bundle by default. Signing adds two UTF-8 sidecars at the bundle root:

```text
cryptad-app.properties
bin/<launcher>.sh
static/...
cryptad-app.digests
cryptad-app.signature
```

The sidecars follow the PR-192 local distribution format:

- `cryptad-app.digests`
  - `digest.version=1`
  - `digest.algorithm=SHA-256`
  - `file.<N>.path=<normalized relative path>`
  - `file.<N>.sha256=<lowercase hex sha256>`
- `cryptad-app.signature`
  - `signature.version=1`
  - `signature.algorithm=Ed25519`
  - `signature.key.id=<stable key id>`
  - `signature.payload=cryptad-app.digests`
  - `signature.value.base64=<base64 Ed25519 signature over the exact digest sidecar bytes>`

The digest includes `cryptad-app.properties` and regular bundle files. It excludes reserved
distribution sidecars such as `cryptad-app.digests`, `cryptad-app.signature`,
`cryptad-app.catalog`, and `cryptad-app.catalog.signature`.

## UI Manifest Fields

App bundles can declare browser UI ownership with `app.ui.mode` and `app.ui.entry`.

```properties
app.ui.mode=none|shell-panel|static
app.ui.entry=static/index.html
```

The mode is optional for compatibility. Missing `app.ui.entry` means `none`; an absolute local
entry such as `/app/node/#queue` infers `shell-panel`; a relative entry such as
`static/index.html` infers `static`. Static entries are normalized relative paths inside the
signed bundle and are validated during structure checks. They must not point at reserved
distribution sidecars, absolute paths, traversal segments, Windows drive prefixes, empty segments,
colons, or control characters. Existing shell-panel entries remain valid.

The repo-owned Queue Manager and Publisher bundles use `app.ui.mode=static` and
`app.ui.entry=static/index.html`, so installed copies open under `/apps/queue-manager/static/` and
`/apps/publisher/static/`.

See [app-owned-ui.md](app-owned-ui.md) for the `/apps/{appId}/` route contract, first-party
bootstrap JSON, static asset security boundary, and API summary fields. See
[platform-sdk-js.md](platform-sdk-js.md) for the staged browser SDK used by first-party static UI
bundles.

## Sandbox Manifest Fields

App bundles can declare the requested AppHost sandbox mode:

```properties
sandbox.mode=none|restricted-process|wasm-preview
sandbox.required=false
```

Both fields are optional. Missing `sandbox.mode` defaults to `none`, and missing
`sandbox.required` defaults to `false`. Unknown modes and malformed booleans fail manifest
validation before a bundle is installed or launched.

The `restricted-process` mode currently maps to AppHost's best-effort restricted local process
provider. It preserves the existing sanitized environment, explicit working directory, and
app-scoped mutable directories, but it is not a hard OS sandbox. The `wasm-preview` mode is reserved
for a future provider and is unsupported by the default runtime.

## Quota Manifest Fields

App bundles can declare data and cache quota metadata:

```properties
quota.data.bytes=0
quota.cache.bytes=0
```

Both fields are optional non-negative byte counts. AppHost enforces a data or cache quota only when
the value is positive. A missing field and an explicit `0` both mean unlimited or no explicit app
quota. This preserves compatibility with the first-party Queue Manager and Publisher staged
manifests, which currently declare `quota.data.bytes=0` and
`quota.cache.bytes=0`.

Quota enforcement is scoped to AppHost-managed app data and cache directories. It does not apply to
the immutable installed bundle, catalog scratch space, daemon datastore files, or arbitrary host
paths. AppHost measures regular files without following symlinks and reports path-free warnings
when a scan is incomplete. If a positive quota is active for that area, incomplete measurement blocks
launch and automatic restart because AppHost cannot enforce the quota from a partial byte count.
Runtime status and app summaries include measured data/cache usage, effective limits, over-limit
flags, process-log size/limit metadata, and warning text that is safe for operator display.

Process-log size is controlled by host policy rather than signed manifest metadata. AppHost keeps
`process.log` bounded on a best-effort basis at lifecycle and status checkpoints while preserving
the tail of the file for diagnostics. AppHost may retain a small additional redaction overlap beyond
the displayed process-log limit so bounded log reads can still redact tokens and known AppHost paths
when the display tail begins inside a sensitive value.

## Runtime Manifest Fields

App bundles can declare a minimal restart policy:

```properties
app.restart.policy=never|on-failure
app.restart.maxAttempts=0
app.restart.backoff.ms=0
```

All fields are optional. The default policy is `never`, with no automatic restart attempts. When a
bundle opts in to `on-failure`, AppHost restarts only after a non-zero process exit, only within the
current daemon session, and only up to `app.restart.maxAttempts`. Explicit operator stop suppresses
automatic restart. Each restart receives a fresh `CRYPTAD_APP_TOKEN`.

`app.restart.maxAttempts` and `app.restart.backoff.ms` must be non-negative integers. AppHost does
not persist restart state across daemon restarts and does not run app-provided health checks.

See [apphost-runtime-hardening.md](apphost-runtime-hardening.md) for the process boundary, runtime
status, process-log tailing, token redaction, and remaining sandbox limitations.

## Developer CLI

`crypta-app` is the developer-facing CLI for standalone AppHost bundles. It is delivered by the
`:platform-devtools` application plugin and can be installed locally with:

```bash
./gradlew :platform-devtools:installDist
```

Use it when an app should be scaffolded, signed, packed, or cataloged outside the first-party
`apps/*` Gradle projects:

```bash
crypta-app init \
  --dir build/dev-apps/hello-queue \
  --app-id hello-queue \
  --name "Hello Queue" \
  --version 0.1.0 \
  --ui-mode static \
  --permission queue.read

crypta-app validate --bundle-dir build/dev-apps/hello-queue
crypta-app sign \
  --bundle-dir build/dev-apps/hello-queue \
  --key-id dev-local \
  --private-key-file /abs/path/to/dev-app-signing-private.pem
crypta-app pack \
  --bundle-dir build/dev-apps/hello-queue \
  --output dist/apps/hello-queue-0.1.0.zip \
  --overwrite
crypta-app verify \
  --bundle-dir build/dev-apps/hello-queue \
  --trusted-key-id dev-local \
  --trusted-public-key-file /abs/path/to/dev-app-signing-public.pem
```

`crypta-app init` creates a standalone staged bundle directory, not a new Gradle subproject. The
static template copies or vendors the browser SDK as `static/crypta-platform.js` when that resource
is available. See [app-dev-cli.md](app-dev-cli.md) for the full scaffold, pack, and catalog flow.

The CLI does not replace the first-party Gradle workflow. Queue Manager and Publisher can keep
using `:apps:queue-manager` and `:apps:publisher` `stageApp`, `signApp`, and `verifyApp` tasks.

## Catalog Store Metadata

Signed bundle manifests remain the source for installed app id, version, launch settings, UI
entry, sandbox mode, quota metadata, and declared permissions. Signed catalogs can add optional
store metadata around those bundles so the Web Shell can show a richer install/update review
surface.

Catalog entry descriptors accepted by `crypta-app catalog create` can include `homepage`,
`source`, `license`, `categories`, `minimumCryptaVersion`, `review.status`, `review.note`,
`permissions.rationale.<permission>`, `screenshot.N`, `changelog.summary`, and `changelog.uri`.
The generated catalog writes those fields under `app.<id>.*` and uses `catalog.version=2`.
Descriptors without store metadata continue to generate minimal `catalog.version=1` catalogs.

These fields are display and review metadata. The catalog signature still authenticates the exact
catalog bytes, and the app bundle signature still authenticates the bundle payload. Review notes,
permission rationales, screenshot URLs, changelog URLs, and compatibility hints do not grant trust
or bypass AppHost verification.

## Gradle Tasks

Per app:

- `:apps:queue-manager:stageApp`
- `:apps:queue-manager:signApp`
- `:apps:queue-manager:verifyApp`
- `:apps:publisher:stageApp`
- `:apps:publisher:signApp`
- `:apps:publisher:verifyApp`

Root convenience tasks:

- `stageFirstPartyApps`
- `signFirstPartyApps`
- `verifyFirstPartyApps`

`stageApp` remains unsigned on purpose. Use `signApp` when you need a signed local bundle, and `verifyApp` to re-digest and verify a signed staged bundle with the configured public key.

## Signing Inputs

Use Gradle properties or environment variables. The same inputs work for both first-party app projects and the root convenience tasks.

| Purpose | Gradle property | Environment variable | Notes |
| --- | --- | --- | --- |
| Stable signing key id | `cryptadAppSigningKeyId` | `CRYPTAD_APP_SIGNING_KEY_ID` | Required for `signApp` and `verifyApp`. |
| Private key bytes | `cryptadAppSigningPrivateKeyBase64` | `CRYPTAD_APP_SIGNING_PRIVATE_KEY_BASE64` | Required for `signApp`. Base64-encoded PKCS#8 Ed25519 private key bytes. |
| Private key file | `cryptadAppSigningPrivateKeyFile` | `CRYPTAD_APP_SIGNING_PRIVATE_KEY_FILE` | Alternative to `*PrivateKeyBase64`. File may contain PEM, Base64 text, or raw DER bytes. |
| Public key bytes | `cryptadAppSigningPublicKeyBase64` | `CRYPTAD_APP_SIGNING_PUBLIC_KEY_BASE64` | Required for `verifyApp`. Base64-encoded X.509 Ed25519 public key bytes. |
| Public key file | `cryptadAppSigningPublicKeyFile` | `CRYPTAD_APP_SIGNING_PUBLIC_KEY_FILE` | Alternative to `*PublicKeyBase64`. File may contain PEM, Base64 text, or raw DER bytes. |

For private keys, prefer `CRYPTAD_APP_SIGNING_PRIVATE_KEY_BASE64` or
`cryptadAppSigningPrivateKeyFile`. Avoid putting base64 private key material directly on the shell
command line with `-PcryptadAppSigningPrivateKeyBase64=...`.

## Runtime Trust Inputs

Production-facing AppHost installs and updates reject unsigned bundles by default. To install a
signed staged bundle through the live node, start the node with either direct trusted-key inputs or
 a trusted-keys properties file.

| Purpose | System property | Environment variable | Notes |
| --- | --- | --- | --- |
| Trusted key id | `cryptad.apphost.trustedKeyId` | `CRYPTAD_APPHOST_TRUSTED_KEY_ID` | Pairs with a direct trusted public key. |
| Trusted public key bytes | `cryptad.apphost.trustedPublicKeyBase64` | `CRYPTAD_APPHOST_TRUSTED_PUBLIC_KEY_BASE64` | Base64-encoded X.509 Ed25519 public key bytes. |
| Trusted public key file | `cryptad.apphost.trustedPublicKeyFile` | `CRYPTAD_APPHOST_TRUSTED_PUBLIC_KEY_FILE` | File may contain PEM, Base64 text, or raw DER bytes. |
| Trusted keys file | `cryptad.apphost.trustedKeysFile` | `CRYPTAD_APPHOST_TRUSTED_KEYS_FILE` | Properties file with `trusted.keys.version=1` plus `key.<n>.id`, `key.<n>.algorithm`, and `key.<n>.public.key.base64`. |
| Development-only unsigned installs | `cryptad.apphost.allowUnsigned=true` | `CRYPTAD_APPHOST_ALLOW_UNSIGNED=true` | Explicit escape hatch for local development and tests. Do not enable in production. |

Example trusted-keys file:

```text
trusted.keys.version=1
key.0.id=dev-local
key.0.algorithm=Ed25519
key.0.public.key.base64=<base64-x509-public-key>
```

## Local Workflow

Stage an unsigned bundle:

```bash
./gradlew :apps:queue-manager:stageApp
```

Sign it with a local development key pair:

```bash
./gradlew :apps:queue-manager:signApp \
  -PcryptadAppSigningKeyId=dev-local \
  -PcryptadAppSigningPrivateKeyFile=/abs/path/to/dev-app-signing-private.pem
```

Verify it with the matching public key:

```bash
./gradlew :apps:queue-manager:verifyApp \
  -PcryptadAppSigningKeyId=dev-local \
  -PcryptadAppSigningPublicKeyFile=/abs/path/to/dev-app-signing-public.pem
```

Stage, sign, and verify both first-party apps:

```bash
./gradlew \
  stageFirstPartyApps \
  signFirstPartyApps \
  verifyFirstPartyApps \
  -PcryptadAppSigningKeyId=dev-local \
  -PcryptadAppSigningPrivateKeyFile=/abs/path/to/dev-app-signing-private.pem \
  -PcryptadAppSigningPublicKeyFile=/abs/path/to/dev-app-signing-public.pem
```

To install the signed bundle through the running node, export the matching trusted public key
before starting Cryptad:

```bash
export CRYPTAD_APPHOST_TRUSTED_KEY_ID=dev-local
export CRYPTAD_APPHOST_TRUSTED_PUBLIC_KEY_FILE=/abs/path/to/dev-app-signing-public.pem
```

If you deliberately want to test unsigned local bundles against a live node, opt in explicitly:

```bash
export CRYPTAD_APPHOST_ALLOW_UNSIGNED=true
```

## Key Handling

Do not commit production private keys, keystores, exported PKCS#8 private keys, or long-lived test secrets to this repository.

Preferred local patterns:

- Keep signing keys outside the repo and pass file paths with `-P...File=...`.
- Keep trusted public keys outside the repo and pass them through environment variables or a local
  trusted-keys file outside the checkout.
- Use environment variables for short-lived automation when file-based secrets are not practical.
- Label local development keys clearly as non-production.

## Future Work

Catalog distribution over Crypta keys, public catalog governance, background app-update
scheduling, remote screenshot proxying, and app sandboxing remain later platform work. Signed
bundles now carry the manifest metadata and staged browser assets needed by app-owned static UI
routes.
