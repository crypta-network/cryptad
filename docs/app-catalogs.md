# Signed app catalogs

This document describes Cryptad's signed app catalog format and the local install/update flow.

## Scope

Signed app catalogs are a Phase 4 app-platform control plane. They do not change peer protocols,
wire formats, application sandboxing, or AppHost process launching. A catalog only tells the local
node where to fetch a signed app bundle ZIP and which digest, size, app id, and version to expect.

The runtime verifies data in this order:

1. `cryptad-app-catalog.signature` over the exact bytes of `cryptad-app-catalog.properties`.
2. The catalog entry's ZIP artifact size and lowercase SHA-256 digest.
3. The extracted bundle's existing `cryptad-app.digests` and `cryptad-app.signature` through
   `AppBundleVerifier`.
4. The extracted manifest `app.id` and `app.version` against the catalog entry.

## Catalog files

A catalog source points at `cryptad-app-catalog.properties`. The matching signature is read from
the sibling file `cryptad-app-catalog.signature`.

Catalog properties use a deterministic `key=value` text sidecar:

```properties
catalog.version=1
catalog.id=core
catalog.name=Crypta Core Apps
catalog.generatedAt=2026-04-21T18:22:40Z
catalog.entries=queue-manager,publisher

app.queue-manager.id=queue-manager
app.queue-manager.name=Queue Manager
app.queue-manager.version=1.0.0
app.queue-manager.summary=Manage local Crypta transfer queues.
app.queue-manager.bundle.uri=https://example.invalid/apps/queue-manager-1.0.0.zip
app.queue-manager.bundle.sha256=<lowercase-hex-sha256-of-zip>
app.queue-manager.bundle.size.bytes=12345
app.queue-manager.bundle.type=zip
app.queue-manager.permissions=queue.read,queue.write
```

The parser rejects duplicate keys, missing required fields, unsupported versions, unsupported
artifact types, invalid app ids, blank names or versions, invalid SHA-256 text, negative sizes,
unsafe artifact URIs, duplicate entries, and unknown properties.

## Catalog signatures

Catalog signatures use Ed25519 and the same trusted-key registry shape as signed app bundles:

```properties
catalog.signature.version=1
catalog.signature.algorithm=Ed25519
catalog.signature.key.id=<trusted-key-id>
catalog.signature.payload=cryptad-app-catalog.properties
catalog.signature.value.base64=<base64-signature-over-exact-catalog-properties-bytes>
```

The signature payload is the exact catalog-properties byte stream. Do not rewrite, sort, or
re-serialize the catalog after signing.

## Trusted keys

Catalog verification reuses the trusted app key configuration already used for signed bundles:

| Setting | Environment variable |
| --- | --- |
| `cryptad.apphost.trustedKeysFile` | `CRYPTAD_APPHOST_TRUSTED_KEYS_FILE` |
| `cryptad.apphost.trustedKeyId` | `CRYPTAD_APPHOST_TRUSTED_KEY_ID` |
| `cryptad.apphost.trustedPublicKeyBase64` | `CRYPTAD_APPHOST_TRUSTED_PUBLIC_KEY_BASE64` |
| `cryptad.apphost.trustedPublicKeyFile` | `CRYPTAD_APPHOST_TRUSTED_PUBLIC_KEY_FILE` |

Unsigned catalogs are rejected. The local unsigned-bundle development bypass does not make remote
catalogs or catalog artifacts trusted.

## Source and artifact fetching

Supported catalog sources:

- Absolute local paths or `file:` URIs to `cryptad-app-catalog.properties`.
- `https:` URIs.
- `http:` URIs only for loopback hosts such as `localhost` or `127.0.0.1`.

Remote fetches use the JDK HTTP client with finite timeouts, no automatic redirects, and size caps
for catalog, signature, and artifact downloads. Artifact bytes are written to catalog-owned scratch
storage, checked against the catalog size and SHA-256, then extracted into a separate staging
directory. The extractor rejects absolute ZIP paths, `..`, Windows drive prefixes, backslash path
separators, duplicate normalized entries, and rootless bundles.

## Platform API flow

Operators can manage catalogs through Platform API v1:

```text
GET    /api/v1/app-catalogs
POST   /api/v1/app-catalogs/add?source=<uri-or-path>
DELETE /api/v1/app-catalogs/{catalogId}
POST   /api/v1/app-catalogs/{catalogId}/refresh
GET    /api/v1/app-catalogs/{catalogId}/apps
GET    /api/v1/app-catalogs/{catalogId}/apps/{appId}
POST   /api/v1/app-catalogs/{catalogId}/apps/{appId}/install
POST   /api/v1/app-catalogs/{catalogId}/apps/{appId}/update
```

Install and update endpoints prepare a verified temporary staged bundle, then delegate to
`AppHost.installFromDirectory(...)` or `AppHost.updateFromDirectory(...)`. Existing local
`/api/v1/apps/install?stagedDir=...` and `/api/v1/apps/{appId}/update?stagedDir=...` flows are
unchanged.

## Future work

This PR does not add app-owned `/apps/{appId}/` static UI proxying, permission enforcement,
container or WASM sandboxing, public app-store governance, or background app update scheduling.
