# Durable app data store

This document describes the bounded app-owned data store exposed through Platform API contract v9.

## Scope

The durable app data store is for app-owned user state that should survive daemon restarts, app
updates, and live catalog refreshes. Typical records include Feed Reader source lists, Profile
Publisher drafts, publish summaries, selected subscription ids, UI filters, and redacted import
summaries.

The store is not a filesystem API, database engine, cache, crawler, or secret vault. Apps must not
store private identity material, seed material, private keys, private insert URIs, browser session
tokens, AppHost process tokens, form passwords, or raw vault secrets in app-data records. Use
[app-secret-and-identity-vault.md](app-secret-and-identity-vault.md) for secrets and identity
material.

## Capabilities

Apps must declare explicit app-data capabilities in `app.permissions`:

| Capability | Grants |
| --- | --- |
| `app.data.read` | Read the caller app's status, namespace metadata, records, and bounded exports. |
| `app.data.write` | Create, replace, delete, import, clear, and record schema migration metadata for the caller app's own records. |

All app-data routes require an app process principal or app browser-session principal. Host/operator
requests are not an app-data bypass. The route implementation derives the app id from the
authenticated principal, so an app cannot name or access another app's records through the API.

The file-backed daemon store lives in host-managed app-platform storage, not inside the
`CRYPTAD_APP_DATA_DIR` tree that an app process can mutate directly. Apps access durable records
only through the Platform API and SDK. Operator uninstall choices still control cleanup:
`preserveData=true` keeps both the app-visible persistent data directory and the host-managed
durable app-data records.

## Routes

The route family is mounted under `/api/v1/app-data`:

| Method and route | Capability | Result |
| --- | --- | --- |
| `GET /api/v1/app-data/status` | `app.data.read` | App id, record count, namespace count, stored bytes, effective caps, quota status, and warnings. |
| `GET /api/v1/app-data/namespaces` | `app.data.read` | Namespace metadata summaries. |
| `GET /api/v1/app-data/namespaces/{namespace}` | `app.data.read` | One namespace plus bounded migration history. |
| `POST /api/v1/app-data/namespaces/{namespace}/schema` | `app.data.write` | Records a schema-version update or migration summary. |
| `DELETE /api/v1/app-data/namespaces/{namespace}` | `app.data.write` | Deletes all records and metadata for that namespace. |
| `GET /api/v1/app-data/records` | `app.data.read` | Bounded record summaries, optionally filtered by `namespace`, `limit`, and `cursor`. |
| `GET /api/v1/app-data/records/{namespace}/{key}` | `app.data.read` | One record with metadata and a bounded value representation. |
| `POST /api/v1/app-data/records` | `app.data.write` | Creates or replaces one record. |
| `DELETE /api/v1/app-data/records/{namespace}/{key}` | `app.data.write` | Deletes one record. |
| `GET /api/v1/app-data/export` | `app.data.read` | Bounded JSON export payload with base64 record values. |
| `POST /api/v1/app-data/import` | `app.data.write` | Imports a bounded export payload in `merge` or `replaceNamespace` mode. |

Mutations use `application/x-www-form-urlencoded` form parameters. The router does not accept host
filesystem paths, arbitrary JSON request bodies, or unbounded raw request bodies for this route
family.

## Records

Records are scoped by app id, namespace, and key. Namespaces and keys are logical identifiers, not
filesystem paths. Namespaces use a safe segment pattern and a 64-character maximum. Keys are also
bounded and path-safe as logical identifiers; on disk the key is hashed before it becomes part of a
directory name.

`POST /api/v1/app-data/records` accepts:

| Field | Meaning |
| --- | --- |
| `namespace` | Required app-owned namespace. |
| `key` | Required logical record key. |
| `schemaVersion` | Required positive integer. |
| `contentType` | Optional bounded content type. Defaults to text, JSON, or binary depending on the value field. |
| `valueBase64` | Base64 bytes for binary records. |
| `valueText` | Text value for UTF-8 records. |
| `valueJson` | JSON value submitted as text and stored as UTF-8 bytes. |
| `ifMatchSha256` | Optional optimistic concurrency guard. |

Exactly one value field must be supplied. List responses include record summaries only: key,
content type, schema version, byte size, SHA-256 digest, and timestamps. They do not include raw
values. Read responses return the value to the owning app as `valueBase64` and, for text or JSON
content types, `valueText`.

## Schema metadata

Apps own their record schemas. The platform records metadata only; it does not execute app-provided
migration code.

Use:

```text
POST /api/v1/app-data/namespaces/{namespace}/schema
```

with `fromSchemaVersion`, `toSchemaVersion`, and optional `summary`. Downgrades are rejected.
Namespace metadata includes the current schema version, timestamps, and bounded migration history.
The app is responsible for transforming its own records before or after it records the migration.

## Quotas and limits

The store always enforces positive platform-level caps:

| Setting | Default |
| --- | --- |
| `cryptad.appData.maxRecordBytes` | `262144` |
| `cryptad.appData.maxRecordsPerApp` | `4096` |
| `cryptad.appData.maxNamespacesPerApp` | `64` |
| `cryptad.appData.maxExportBytes` | `778240` |
| `cryptad.appData.maxImportBytes` | `778240` |

When an installed manifest has a positive `quota.data.bytes`, app-data writes and imports also
respect the app's data quota. Manifest-quota checks reserve space for the store's metadata files
as well as value bytes, so metadata-only schema updates and zero-length records still need quota
headroom. The file-backed store is outside the app-visible data directory, so quota checks add the
current durable app-data usage to the AppHost data usage before accepting a write or import. If the
manifest omits the quota or sets it to zero, the platform caps still apply.
Quota errors use stable codes such as `app_data_quota_exceeded` and must not include store roots,
app data directories, staging paths, or other host filesystem details.

## Export and import

`GET /api/v1/app-data/export` returns a bounded export envelope for the authenticated app. The
payload includes an export version, optional app id, namespace metadata, record summaries, and
base64 record values. Use the optional `namespace` query parameter to export one namespace.

`POST /api/v1/app-data/import` accepts `payloadBase64` and optional `mode`. Export responses use
URL-safe base64 without padding for `payloadBase64` so the SDK can round-trip default-sized
exports through the URL-encoded Platform API bridge; import also accepts standard base64 payloads.

| Mode | Behavior |
| --- | --- |
| `merge` | Adds or replaces records from the payload without clearing unrelated namespaces. |
| `replaceNamespace` | Clears each imported namespace before importing that namespace's records. |

Import rejects payloads that name a different app id. It also rejects unsupported export versions,
oversized payloads, invalid identifiers, and payloads that would exceed record, namespace, record
count, import, or data-quota limits.

## Browser SDK

Static browser apps should use `CryptaPlatform.data` helpers:

```js
await CryptaPlatform.bootstrap.load({ appId: "feed-reader" });

await CryptaPlatform.data.records.putJson({
  namespace: "ui-state",
  key: "reader-state",
  schemaVersion: 1,
  value: {
    selectedSubscriptionId,
    sourceCount,
  },
});

const state = await CryptaPlatform.data.records.getJson("ui-state", "reader-state");
const status = await CryptaPlatform.data.status();
const namespaces = await CryptaPlatform.data.namespaces.list();
```

The SDK exposes:

```text
CryptaPlatform.data.status()
CryptaPlatform.data.namespaces.list()
CryptaPlatform.data.namespaces.get(namespace)
CryptaPlatform.data.namespaces.migrate(namespace, options)
CryptaPlatform.data.namespaces.clear(namespace)
CryptaPlatform.data.records.list(options)
CryptaPlatform.data.records.get(namespace, key)
CryptaPlatform.data.records.put(options)
CryptaPlatform.data.records.putJson(options)
CryptaPlatform.data.records.getJson(namespace, key)
CryptaPlatform.data.records.remove(namespace, key)
CryptaPlatform.data.export(options)
CryptaPlatform.data.import(payload, options)
```

The SDK keeps browser session tokens in memory only and does not use `localStorage` or
`sessionStorage` for durable app state.

## Uninstall behavior

Default app uninstall removes the immutable bundle and host-owned data, cache, and run state.
Operators can request data preservation with `preserveData=true` on app uninstall. Preserve-data
uninstall removes the immutable bundle, cache, run state, rollback state, and runtime bookkeeping
while leaving the persistent data directory and durable app-data records for a future reinstall or
migration.

## Redaction rules

API errors, audit events, diagnostics, release evidence, and model `toString()` output must not
include store root paths, app data directories, temporary paths, raw request bodies, private insert
URIs, private keys, seed material, raw vault secrets, form passwords, app process tokens, or browser
session tokens.

Release evidence should use route names, capability labels, record counts, namespace counts, byte
counts, schema versions, booleans, sanitized error codes, and digests. It must not include raw
app-data values unless the owning app receives them through the app-data read API.
