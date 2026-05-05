# Signed app catalogs

This document describes Cryptad's signed app catalog format and the local install/update flow.

## Scope

Signed app catalogs are a Phase 5 app-platform control plane. They do not change peer protocols,
wire formats, application sandboxing, or AppHost process launching. A catalog tells the local node
where to fetch a signed app bundle ZIP and which digest, size, app id, and version to expect. It
can also carry optional app-store display metadata for review, compatibility, source, license,
permissions, screenshots, and changelog links.

The runtime verifies data in this order:

1. `cryptad-app-catalog.signature` over the exact bytes of `cryptad-app-catalog.properties`.
2. The catalog entry's ZIP artifact size and lowercase SHA-256 digest.
3. The extracted bundle's existing `cryptad-app.digests` and `cryptad-app.signature` through
   `AppBundleVerifier`.
4. The extracted manifest `app.id` and `app.version` against the catalog entry.
5. If present, the app review receipt signature over canonical receipt payload bytes, using the
   node's separate trusted reviewer-key registry.

These are separate trust layers. The catalog signature authenticates catalog bytes and publisher
metadata. The artifact digest binds one catalog entry to one downloaded ZIP. The bundle signature
authenticates the extracted app bundle. A review receipt signature independently authenticates
review evidence from a reviewer key that the local node trusts for app review. Legacy
`review.status` and `review.note` catalog metadata remains publisher-advisory only.

## Catalog files

A catalog source points at `cryptad-app-catalog.properties`. The matching signature is read from
the sibling file `cryptad-app-catalog.signature`.

Catalog properties use a deterministic `key=value` text sidecar:

```properties
catalog.version=2
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
app.queue-manager.homepage=https://example.invalid/apps/queue-manager
app.queue-manager.source=https://example.invalid/src/queue-manager
app.queue-manager.license=MIT
app.queue-manager.categories=productivity,network
app.queue-manager.minimumCryptaVersion=1481
app.queue-manager.review.status=reviewed
app.queue-manager.review.note=Reviewed for local operator safety.
app.queue-manager.permissions.rationale.queue.read=Reads the local transfer queue.
app.queue-manager.permissions.rationale.queue.write=Lets the app cancel or reprioritize requests.
app.queue-manager.screenshot.1=https://example.invalid/assets/queue-manager-1.png
app.queue-manager.changelog.summary=Adds queue retry controls.
app.queue-manager.changelog.uri=https://example.invalid/apps/queue-manager-1.0.0-changelog.txt
app.queue-manager.api.minimumVersion=1
app.queue-manager.api.maximumTestedVersion=1
app.queue-manager.api.optionalCapabilities=alerts.read,diagnostics.read
app.queue-manager.api.experimentalCapabilitiesAccepted=false
app.queue-manager.review.receipt.version=1
app.queue-manager.review.receipt.app.id=queue-manager
app.queue-manager.review.receipt.app.version=1.0.0
app.queue-manager.review.receipt.artifact.sha256=<lowercase-hex-sha256-of-zip>
app.queue-manager.review.receipt.artifact.size=12345
app.queue-manager.review.receipt.policy.id=crypta-app-review-v1
app.queue-manager.review.receipt.policy.version=1
app.queue-manager.review.receipt.status=reviewed
app.queue-manager.review.receipt.reviewer.key.id=crypta-first-party-review
app.queue-manager.review.receipt.reviewed.at=2026-04-21T18:25:00Z
app.queue-manager.review.receipt.evidence.sha256=<optional-lowercase-hex-sha256>
app.queue-manager.review.receipt.evidence.uri=crypta:CHK@...
app.queue-manager.review.receipt.note=Reviewed against the first-party app policy.
app.queue-manager.review.receipt.signature.algorithm=Ed25519
app.queue-manager.review.receipt.signature.value.base64=<base64-signature-over-canonical-payload>
```

The parser rejects duplicate keys, missing required fields, unsupported versions, unsupported
artifact types, invalid app ids, blank names or versions, invalid SHA-256 text, negative sizes,
unsafe artifact URIs, duplicate entries, and unknown properties.

`catalog.version=1` is the minimal signed-catalog schema and contains only the required app,
artifact, and permission fields. `catalog.version=2` adds the optional app-store and API
compatibility metadata fields shown above. Current Cryptad nodes parse both versions. Older strict
v1 nodes reject v2 catalogs rather than silently accepting unknown metadata fields.

Minimal v1 catalogs that only provide the required fields still parse and install unchanged. The
app-store metadata fields remain optional within the v2 schema.

## App-store metadata

Catalog entries can include these optional fields:

| Catalog property | Meaning |
| --- | --- |
| `app.<id>.homepage` | Operator-facing homepage URI. |
| `app.<id>.source` | Source repository or source archive URI. |
| `app.<id>.license` | Single-line license label, such as `MIT` or `GPL-3.0-or-later`. |
| `app.<id>.categories` | Comma-separated category labels, normalized and deduplicated for display. |
| `app.<id>.minimumCryptaVersion` | Advisory minimum Cryptad build/version string. Integer build numbers are the comparable form used by Platform API responses. |
| `app.<id>.review.status` | Advisory human review state. Supported values are `unreviewed`, `reviewed`, `caution`, and `rejected`. |
| `app.<id>.review.note` | Single-line advisory review note for operators. |
| `app.<id>.permissions.rationale.<permission>` | Explanation for a declared permission, keyed by the normalized permission name. |
| `app.<id>.screenshot.N` | Screenshot URI metadata, where `N` is a positive deterministic index. |
| `app.<id>.changelog.summary` | Single-line summary of changes for the catalog version. |
| `app.<id>.changelog.uri` | URI for full changelog text or release notes. |
| `app.<id>.api.minimumVersion` | Advisory minimum Platform API compatibility contract version. |
| `app.<id>.api.maximumTestedVersion` | Advisory maximum Platform API compatibility contract version tested by the app author. |
| `app.<id>.api.optionalCapabilities` | Advisory comma-separated optional capability names used for verifier and review warnings. |
| `app.<id>.api.experimentalCapabilitiesAccepted` | Whether the app author explicitly accepts experimental capability use. |
| `app.<id>.review.receipt.*` | Optional independently signed review receipt. See [Trusted review receipts](#trusted-review-receipts). |

URI fields are metadata only. The Web Shell should show screenshot URIs as links or behind an
operator-explicit preview control; it should not silently auto-fetch arbitrary remote images from a
catalog entry. `minimumCryptaVersion` is advisory and should not block install/update by itself
when comparison is unavailable or ambiguous. Catalog compatibility summaries compare numeric
Cryptad build labels when possible and compare API compatibility metadata against the current
Platform API contract version.

Platform API contract metadata is also advisory in catalogs. The signed bundle manifest remains
authoritative for the app artifact. Developer tooling flags catalog-vs-bundle API metadata
mismatches and permission mismatches before signing; old catalogs without API metadata still parse
and display an `unknown` API compatibility status.

Permission rationales explain why the catalog version declares a permission. They do not grant
permissions and do not replace the signed bundle manifest's permission list or server-side
Platform API authorization checks.

## Trusted review receipts

Catalog entries may carry an inline review receipt under `app.<id>.review.receipt.*`. The receipt
is still part of the signed catalog bytes, but it is not trusted merely because the catalog signer
included it. Cryptad verifies the receipt separately with a node-local trusted reviewer key. This
lets the Web Shell and Platform API distinguish a publisher claim such as
`review.status=reviewed` from a trusted reviewer receipt that binds a reviewer decision to the
exact app artifact.

The signed receipt payload contains:

| Receipt property | Meaning |
| --- | --- |
| `review.receipt.version` | Receipt schema version. Current value is `1`. |
| `review.receipt.app.id` | App id that must match the catalog entry. |
| `review.receipt.app.version` | App version that must match the catalog entry. |
| `review.receipt.artifact.sha256` | Lowercase SHA-256 that must match `app.<id>.bundle.sha256`. |
| `review.receipt.artifact.size` | Artifact size that must match `app.<id>.bundle.size.bytes`. |
| `review.receipt.bundle.key.id` | Optional signed-bundle key id recorded by the reviewer. |
| `review.receipt.policy.id` | Reviewer policy id, for example `crypta-app-review-v1`. |
| `review.receipt.policy.version` | Reviewer policy version. |
| `review.receipt.status` | Reviewer decision: `reviewed`, `caution`, or `rejected`. |
| `review.receipt.reviewer.key.id` | Reviewer key id looked up in the local reviewer trust registry. |
| `review.receipt.reviewed.at` | Strict ISO-8601 review instant. |
| `review.receipt.expires.at` | Optional strict ISO-8601 expiry instant. Expired receipts are untrusted. |
| `review.receipt.evidence.sha256` | Optional evidence digest. |
| `review.receipt.evidence.uri` | Optional `https:` or `crypta:` evidence URI. |
| `review.receipt.note` | Optional bounded single-line reviewer note. |
| `review.receipt.signature.algorithm` | Current value is `Ed25519`. |
| `review.receipt.signature.value.base64` | Signature over canonical receipt payload bytes. The signature fields are not signed. |

Canonicalization is deterministic: receipt payload fields are serialized in the fixed receipt
order, bounded strings must be single-line, and the signature sidecar is excluded from the bytes
being signed. Tampering with the app id, version, artifact digest, size, reviewer status, evidence
fields, policy fields, timestamps, or reviewer key id invalidates the receipt. A `rejected`
receipt can be trusted evidence, but it is not a positive review and must not be rendered as
"safe" or "reviewed".

Trusted reviewer keys are configured separately from app and catalog signing keys:

| Setting | Environment variable |
| --- | --- |
| `cryptad.appreview.trustedReviewerKeysFile` | `CRYPTAD_APPREVIEW_TRUSTED_REVIEWER_KEYS_FILE` |
| `cryptad.appreview.trustedReviewerKeyId` | `CRYPTAD_APPREVIEW_TRUSTED_REVIEWER_KEY_ID` |
| `cryptad.appreview.trustedReviewerPublicKeyBase64` | `CRYPTAD_APPREVIEW_TRUSTED_REVIEWER_PUBLIC_KEY_BASE64` |
| `cryptad.appreview.trustedReviewerPublicKeyFile` | `CRYPTAD_APPREVIEW_TRUSTED_REVIEWER_PUBLIC_KEY_FILE` |

Trusted reviewer keys files use their own registry shape:

```properties
trusted.reviewers.version=1
reviewer.1.id=crypta-first-party-review
reviewer.1.algorithm=Ed25519
reviewer.1.public.key.base64=<X.509 Ed25519 public key bytes>
reviewer.1.display.name=Crypta First-Party Review
reviewer.1.policy.id=crypta-app-review-v1
```

Unknown algorithms, duplicate key ids, malformed public keys, and incomplete entries fail closed.
Platform API and Web Shell responses expose reviewer key ids, display names, policy ids, timestamps,
evidence metadata, and warnings; they do not expose reviewer public key bytes, private key material,
local receipt paths, scratch paths, staging paths, app browser tokens, or AppHost process tokens.

Review policy is local operator policy, not catalog metadata. Configure it with
`cryptad.appreview.policyMode` or `CRYPTAD_APPREVIEW_POLICY_MODE`:

| Mode | Behavior |
| --- | --- |
| `advisory` | Default. Show trusted/untrusted review status, but do not block manual install/update. |
| `warn_untrusted` | Allow manual install/update only after explicit acknowledgement for missing, untrusted, expired, mismatched, or rejected receipts. |
| `require_trusted_review` | Block manual install/update unless a trusted positive receipt exists. |
| `require_trusted_review_for_apply_when_stopped` | Require a trusted positive receipt for policy-driven apply-when-stopped updates; manual install/update can still proceed after acknowledgement. |

Stable review-trust statuses include `trusted_reviewed`, `trusted_caution`, `trusted_rejected`,
`missing_receipt`, `unknown_reviewer`, `invalid_signature`, `artifact_mismatch`, `app_mismatch`,
`expired`, `publisher_claim_only`, and `not_configured`.

## Developer CLI catalog flow

For standalone developer apps, `crypta-app catalog create` can generate
`cryptad-app-catalog.properties` from one or more app entry descriptors. The descriptor is CLI
input; the generated catalog still uses the runtime format shown above. The descriptor names the
local ZIP artifact to inspect and the public URI that should be written to the catalog.

Descriptor shape:

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

Only `artifact.path`, `bundle.uri`, and `summary` are required. The writer derives the catalog app
id and version from the artifact's root `cryptad-app.properties`; descriptor `app.id` and `version`
values are optional consistency checks and must match the artifact manifest. The `name` and
`permissions` fields can override the display metadata and permission hints written to the catalog.
Optional descriptor metadata uses the same names as catalog metadata without the `app.<id>.`
prefix. The writer computes `bundle.sha256` and `bundle.size.bytes` from the local artifact bytes.
A descriptor and artifact with no app-store metadata and no API compatibility metadata produce
`catalog.version=1`; descriptors that include app-store metadata, or descriptors/artifacts that
declare API compatibility metadata, produce `catalog.version=2`.

Create, sign, and verify a catalog with:

```bash
crypta-app catalog create \
  --catalog-file dist/catalog/cryptad-app-catalog.properties \
  --catalog-id dev \
  --name "Development Apps" \
  --entry catalog-entry.properties \
  --review-receipt review-receipt.properties

crypta-app catalog sign \
  --catalog-file dist/catalog/cryptad-app-catalog.properties \
  --key-id dev-local \
  --private-key-file /abs/path/to/dev-app-signing-private.pem

crypta-app catalog verify \
  --catalog-file dist/catalog/cryptad-app-catalog.properties \
  --trusted-key-id dev-local \
  --trusted-public-key-file /abs/path/to/dev-app-signing-public.pem
```

The catalog signature authenticates the exact bytes of `cryptad-app-catalog.properties`. Do not
rewrite, sort, or reformat the catalog after signing. See
[app-dev-cli.md](app-dev-cli.md) for the full standalone app CLI workflow.

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
- `crypta:` URIs for public catalog-over-Crypta sources.

`crypta:` catalog sources use these forms:

- Mutable/path-like catalog keys:
  `crypta:USK@<catalog-key>/<catalog-path>/cryptad-app-catalog.properties` or
  `crypta:SSK@<catalog-key>/<catalog-path>/cryptad-app-catalog.properties`.
  The signature sidecar is the sibling
  `crypta:USK@<catalog-key>/<catalog-path>/cryptad-app-catalog.signature` or
  `crypta:SSK@<catalog-key>/<catalog-path>/cryptad-app-catalog.signature`.
- Immutable CHK v1 catalogs:
  `crypta:CHK@<catalog-key>?signature=CHK@<signature-key>`. The catalog CHK contains
  `cryptad-app-catalog.properties` bytes, and the `signature` companion CHK contains the matching
  `cryptad-app-catalog.signature` bytes.

`crypta:` is a catalog transport, not a trust boundary. The catalog signature must still verify
against a configured trusted catalog key. Install and update flows still verify the catalog entry's
artifact size and SHA-256, then verify the extracted signed bundle before AppHost receives it.

Remote fetches use the JDK HTTP client with finite timeouts, no automatic redirects, and size caps
for catalog, signature, and artifact downloads. Artifact bytes are written to catalog-owned scratch
storage, checked against the catalog size and SHA-256, then extracted into a separate staging
directory. The extractor rejects artifacts with more than 4096 ZIP entries, absolute ZIP paths,
`..`, Windows drive prefixes, backslash path separators, duplicate normalized entries, and rootless
bundles. It drops macOS archive metadata entries such as `__MACOSX/**` and AppleDouble `._*` files
before signed-bundle verification, so those files are not installed as app payload.

Current catalog support accepts `crypta:` for catalog sources only. Catalog entry artifact URIs
still use `file:`, `https:`, or loopback `http:` sources. A catalog entry with
`app.<id>.bundle.uri=crypta:...` is rejected with a stable unsupported artifact URI scheme error
unless `platform-appcatalog` adds explicit Crypta artifact fetching in a later change.

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

Refresh failures update the catalog source's last-attempt and last-failure status, but they do not
replace or delete the last successfully verified catalog sidecars. Catalog listing, detail,
install, and update operations continue to use the last verified catalog until a later refresh
verifies a replacement. Already installed apps are not removed or rolled back because a catalog
refresh failed.

Install and update endpoints prepare a verified temporary staged bundle, then delegate to
`AppHost.installFromDirectory(...)` or `AppHost.updateFromDirectory(...)`. Existing local
`/api/v1/apps/install?stagedDir=...` and `/api/v1/apps/{appId}/update?stagedDir=...` flows are
unchanged. Update apply remains explicit: catalog refresh and listing can detect candidates, but
the operator or API caller still chooses when to apply the update, and AppHost applies it only when
the target app is stopped.

Catalog-installed apps use the same manifest UI contract as local staged apps. If the verified
bundle declares `app.ui.mode=static` and a relative `app.ui.entry`, Cryptad serves the installed
bundle UI at `/apps/{appId}/`. Existing shell-panel entries such as `/app/node/#queue` still open
through their declared local route. Catalog-installed bundles also use the same data/cache quota
semantics as local staged apps: missing or `0` quota fields are unlimited, and positive values are
enforced only for AppHost-managed app data/cache directories. See
[app-owned-ui.md](app-owned-ui.md) for the static UI route and security boundary.

Catalog app listing and detail responses expose optional store metadata, installed/running state,
installed version, catalog version, advisory version-difference/update information, API
compatibility summaries, permission rationales, and permission deltas for install/update review.
Responses include both the legacy advisory `review` object and the locally evaluated
`reviewTrust` object. `reviewTrust.status` records the stable receipt decision, `trusted` records
whether the receipt signature verified with a configured reviewer key, and `positive` is true only
for `trusted_reviewed`. Review policy flags such as `requiresAcknowledgement`, `blocksInstall`,
`blocksUpdate`, and `blocksPolicyApply` explain whether the local node will allow, warn, or block a
catalog install/update/apply operation. Responses do not expose trusted-key material, reviewer
public key bytes, catalog scratch paths, verified staging directories, receipt file paths, browser
session tokens, or AppHost process tokens.

The Web Shell Apps section uses the same API to show catalog details before install or update:
catalog signature/source state, artifact digest and bundle verification status when available,
publisher advisory review status and note, trusted review receipt status, reviewer key/display
metadata, policy id/version, evidence metadata, expiry, warnings, source/homepage/license/category
metadata, permission explanations, installed-vs-catalog version difference, advisory compatibility
hints, and changelog metadata when present. Web Shell wording must distinguish "signed by catalog
publisher" from "reviewed by trusted reviewer". See
[app-update-lifecycle.md](app-update-lifecycle.md) for candidate detection, manual apply,
permission-delta review, and rollback scope.

## Future work

Manifest permissions are enforced for app-process Platform API calls as described in
[app-permissions-and-audit.md](app-permissions-and-audit.md). Public app-store governance,
silent automatic update policy, Crypta artifact fetching, and remote screenshot proxying remain
future work. Catalog-backed candidate detection and explicit apply are implemented; silent
auto-update is not the default.
