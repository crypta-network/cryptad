# Signed App Distribution

This document describes Cryptad's local signed staged app bundle workflow for first-party AppHost apps.

## Scope

PR-192 adds signed local bundle sidecars and Gradle tasks for staging, signing, and verifying first-party apps.

Out of scope in this PR:

- Remote catalog fetching
- Remote bundle downloads
- Public app store UI
- Browser-side bundle uploads
- App proxying and app-owned static serving

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

The digest includes `cryptad-app.properties` and regular bundle files. It excludes distribution sidecars such as `cryptad-app.digests`, `cryptad-app.signature`, and reserved future catalog sidecars.

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

Remote catalog fetching, remote bundle downloads, and public catalog management are deferred to later PRs. PR-192 only establishes signed local bundle files and Gradle-side signing and verification hooks.
