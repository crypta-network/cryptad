# Site Publisher App

`apps/site-publisher` stages the first repo-owned content reference AppHost bundle.

Site Publisher is separate from the legacy Publisher app. Publisher remains the compatibility
replacement for legacy insert admin pages, while Site Publisher demonstrates a normal user-facing
content workflow on the app-platform stack: isolated static UI, local design-system assets, the
browser SDK, explicit content-publishing permissions, catalog metadata, review evidence, and update
certification.

Build the staged bundle with:

```bash
./gradlew :apps:site-publisher:stageApp
```

`stageApp` stays unsigned by default. Add the local signed-bundle sidecars with:

```bash
./gradlew :apps:site-publisher:signApp \
  -PcryptadAppSigningKeyId=dev-local \
  -PcryptadAppSigningPrivateKeyFile=/abs/path/to/dev-app-signing-private.pem
```

Verify the signed staged bundle with:

```bash
./gradlew :apps:site-publisher:verifyApp \
  -PcryptadAppSigningKeyId=dev-local \
  -PcryptadAppSigningPublicKeyFile=/abs/path/to/dev-app-signing-public.pem
```

The staged output is written to:

```text
apps/site-publisher/build/cryptad-app/site-publisher
```

The staged bundle contains:

```text
cryptad-app.properties
bin/site-publisher.sh
static/index.html
static/app.js
static/drafts.js
static/app.css
static/crypta-platform.js
static/crypta-ui/crypta-ui-tokens.css
static/crypta-ui/crypta-ui.css
static/crypta-ui/crypta-ui-components.js
cryptad-app.digests          # after signApp
cryptad-app.signature        # after signApp
```

Site Publisher declares:

- `content.insert` to submit operator-selected local files and directories to the insert pipeline.
- `queue.write` to create the resulting insert requests.
- `queue.read` to show upload queue progress.
- `app.data.read` and `app.data.write` to read and commit private durable draft changes.
- `content.insert.app-document` to publish literal UTF-8 text to a new CHK address.

The directory/file forms send operator-selected paths. The draft importer reads only an explicitly
selected converted JSON package or private target backup. It does not use persistent browser storage and
does not request vault identity capabilities. Identity-backed site/profile publishing remains
future work until an app can request an operator grant and use identity metadata without exposing
private identity material.

Run focused validation with:

```bash
./gradlew :apps:site-publisher:test
```

See [docs/app-distribution.md](../../docs/app-distribution.md) for signing inputs and the shared
first-party app workflow, and [docs/app-catalogs.md](../../docs/app-catalogs.md) for local signed
catalog metadata.

## Beta readiness

- Current beta support level: `maintained`, owned by `crypta-core`, with
  `app.beta.readiness=ready`.
- Empty/error/retry states: the staged UI shows an empty site-source state, bounded invalid
  bundle/path/metadata errors, and retry validation/publish actions.
- App-data status: `durable-limited`; the `sharesite-drafts` namespace has schema 1 and one bounded
  `dataset` record. Backup/export/import use private user-data copies with `encryption.mode=none`.
- Migration preview status: `supported` for explicitly selected active Sharesite pastebin records.
  This does not claim entire-plugin migration or authentic operator migration evidence.
- Permission rationale summary: content insert and queue permissions explain site publication,
  insert queue creation, and progress display.
- Support/recovery path: the recovery action points operators to failed site insert support and
  the RC recovery workflow.
- Diagnostic redaction promise: diagnostics are `redacted-summary-only` and do not include raw
  bundle paths, private insert URIs, tokens, raw content, or local paths.
- Known limitations: identity-backed site publishing remains out of scope until the app can use
  bounded operator grants without exposing private identity material.

## Sharesite plain-text migration

Use [the real legacy migration runbook](../../docs/real-legacy-plugin-migration-pilot.md) to create
an offline private conversion package from a stopped, consistent Sharesite snapshot. Never open the
raw legacy database in the browser or upload it to a node. The old plugin runtime remains absent.

Site Publisher uses independent app version `3.1`, newer than the previous stateless `3` bundle.
Other app versions and the daemon integer build are unchanged. Catalog/submission descriptors use
the verified bundle manifest version, and the normal update path must review the permission delta.

Install or update the signed Site Publisher bundle through normal catalog review, stable baseline
admission, and explicit permission consent. The app targets stable baseline `1.0`, has minimum
contract `9` for its stable data capabilities, and declares maximum tested contract `24`. Guarded
writes additionally require a daemon exposing `status.sharesiteWriteGuard=1`; the UI checks that
marker before sending any draft write, including previews. Older daemons ignore unknown form
parameters, so capability presence alone is insufficient.

The draft controls provide this workflow:

1. Download and retain a private target backup separately from the source snapshot. A browser
   download is not encrypted and cannot enforce your destination's filesystem permissions; choose
   an owner-only local directory and restrict access before retaining it.
2. Select the converted package, acknowledge backup readiness, and inspect the selected literal
   pages and exclusion counts. Review the private target binding and acknowledge the exact preview.
3. Commit the reviewed local change. The app adds an isolated import dataset without overwriting
   existing drafts. Exact completed replays are no-ops; altered operation identities are rejected.
4. Refresh or restart the app to read durable drafts. Select a draft, edit its literal text, preview
   the save, and commit. HTML and URL-looking text render through text nodes, not active markup.
5. Separately approve publication of a saved draft. The SDK generates the exact UTF-8 bytes with
   `contentType=text/plain; charset=utf-8`, `targetFilename=draft.txt`, and `insertUri=CHK@` through
   the existing generated-document route. Import and saving never publish.

The generated-document route limits each text to 65,536 UTF-8 bytes. The pilot limits one import to
16 pages, its operation ledger to 32 entries, and the whole dataset JSON to 196,608 bytes. The
1,048,576-byte manifest quota reserves room for record and namespace metadata and private
export/base64 overhead within the existing platform caps. Quotas are checked before commit.
Original imported text, including CRLF line endings and empty strings, is preserved exactly.
Editing through a browser textarea uses LF line endings; review that explicit edit before saving.

Undo removes only one unchanged import. Each operation retains a private canonical digest of its
original draft array; later edits block automatic undo and require manual recovery. A private
restore is additive and refuses divergent existing drafts or operation records. It does not perform
a whole-app destructive restore. The node binds preview to the exact proposed bytes, current data,
verified target bundle and permissions, and app update barriers. A stale preview requires a new
review.

Bundle rollback is independent of data undo. Returning to an older stateless Site Publisher bundle
keeps durable records but that older UI cannot display them; reinstall the approved draft-capable
version or recover from the private backup. Source data and old-node recovery remain separately
owned by the legacy operator. Do not disable the old writer until an explicit cutover decision.

Old insert keys are never imported. A public read reference may remain private historical metadata;
it conveys no write authority. Textile, CSS, activelinks, scheduling, deleted pages, and same-USK
continuity are excluded. New publication creates a new CHK address. Cancelling a queue request or
undoing local data cannot guarantee removal of content already inserted into the network.
