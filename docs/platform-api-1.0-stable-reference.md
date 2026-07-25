# Platform API 1.0 Stable Reference

This document is the developer-facing reference for the Platform API 1.0 stable baseline. It
describes the third-party app surface covered by stable compatibility guarantees. The full
contract snapshot remains available through `crypta-app api snapshot` and
`GET /api/v1/platform/contract`; this page lists only the `stableBaseline.name=1.0` members.

The stable baseline is separate from the integer compatibility contract version. The current
contract version records when descriptors were added or changed. The stable baseline name records
which descriptors are part of the Platform API 1.0 app-facing compatibility promise.
Platform API 1.0 membership is frozen at contract version 19. The current app-facing contract
version is 23. Later contract versions may add experimental or future baseline surface, but they
must not change `stableBaseline.name=1.0` membership unless the project intentionally defines a
new stable baseline.

## Stability Terms

`stable` means app-facing Platform API 1.0 surface. Stable baseline capabilities and routes remain
available to apps that declare `api.targetStability=stable`.

`experimental` means app-facing but not covered by the Platform API 1.0 stable guarantee. Apps may
use experimental capabilities only when they declare `api.targetStability=experimental` and
`api.experimentalCapabilitiesAccepted=true`.

`internal` means daemon implementation API. Third-party apps cannot declare internal capabilities.

`operator-only` means host or Web Shell operator API. Third-party apps cannot declare operator-only
capabilities, even when `api.targetStability=experimental`.

`deprecated` remains available and remains part of the stable compatibility promise while warning
during compatibility verification.

`scheduled-for-removal` remains available during its migration window and remains part of the
stable compatibility promise until an approved future baseline and release policy allow removal.

## Manifest Choice

A stable-only third-party app should declare:

```properties
api.minimumVersion=1
api.maximumTestedVersion=23
api.targetStability=stable
api.experimentalCapabilitiesAccepted=false
```

An app that knowingly uses experimental app-facing API should declare:

```properties
api.minimumVersion=1
api.maximumTestedVersion=23
api.targetStability=experimental
api.experimentalCapabilitiesAccepted=true
```

Legacy manifests that omit `api.targetStability` remain readable. The compatibility metadata model
treats the effective target as `experimental`, records that the field was not declared, and emits
`api_target_stability_missing` when explicit API compatibility metadata is otherwise present.

## Stable Baseline Counts

The Platform API 1.0 stable baseline contains 9 capabilities and 32 endpoints.

Release certification also checks the stable endpoint required-capability sets, action labels, and
app-principal access flags. A stable endpoint that changes required capabilities, changes the
authorization/audit action label, drops app process/browser access, or changes method/route
identity is treated as a stable breaking change.

## Stable Capabilities

- `app.data.read`
- `app.data.write`
- `content.fetch`
- `content.insert`
- `content.insert.app-document`
- `content.subscribe`
- `platform.contract.read`
- `queue.read`
- `queue.write`

## Stable Endpoints

- `DELETE /app-data/namespaces/{namespace}`
- `DELETE /app-data/records/{namespace}/{key}`
- `DELETE /content/subscriptions/{subscriptionId}`
- `GET /app-data/export`
- `GET /app-data/namespaces`
- `GET /app-data/namespaces/{namespace}`
- `GET /app-data/records`
- `GET /app-data/records/{namespace}/{key}`
- `GET /app-data/status`
- `GET /content/subscriptions`
- `GET /content/subscriptions/{subscriptionId}`
- `GET /platform/contract`
- `GET /queue`
- `GET /queue/count`
- `GET /queue/keys`
- `POST /app-data/import`
- `POST /app-data/namespaces/{namespace}/schema`
- `POST /app-data/records`
- `POST /content/fetch`
- `POST /content/subscriptions`
- `POST /content/subscriptions/{subscriptionId}/pause`
- `POST /content/subscriptions/{subscriptionId}/refresh`
- `POST /content/subscriptions/{subscriptionId}/resume`
- `POST /queue/cleanup/downloads`
- `POST /queue/cleanup/uploads`
- `POST /queue/downloads`
- `POST /queue/inserts/app-document`
- `POST /queue/inserts/directory`
- `POST /queue/inserts/file`
- `POST /queue/requests/priority`
- `POST /queue/requests/remove`
- `POST /queue/requests/restart`

## Exclusions

The stable baseline intentionally excludes app-vault, identity-vault, app-service, and Trust Graph
Local RC capabilities and routes. Those surfaces remain available in the full contract with their
own stability labels, but third-party apps must not treat them as Platform API 1.0 stable.

Host-only and operator-only routes may still be visible in localhost contract snapshots for audit
or Web Shell wiring, but they are not part of the third-party stable baseline and compatibility
verification rejects app declarations that rely on them.

The current snapshot also records the operator-only, read-only
`GET /api/v1/updates/support-lifecycle` route without advancing the app-facing contract version.
It exposes the locally verified Stable 1.0 build-support state for the Web Shell and operator
diagnostics. It does not change the frozen Platform API 1.0 version 19 membership and is not an
app capability. Its public-safe projection includes nullable current/recommended/replacement build
fields and bounded `recoveryGuidance`; a recovery-only revocation of the chain tip therefore does
not invent a safe build.

## Submission Review Enforcement

Third-party app-store pre-review uses this same baseline. A submission whose manifest declares
`api.targetStability=stable` must use only the stable capabilities and endpoints listed above.
Experimental app-facing capabilities require `api.targetStability=experimental` and
`api.experimentalCapabilitiesAccepted=true`. Internal, host-only, and operator-only capabilities
fail pre-review for third-party submissions.

See [app-store-submission-and-review-workflow.md](app-store-submission-and-review-workflow.md) for
the submission package format, automated pre-review report, and reviewer decision workflow. See
[platform-api-compatibility-support-window.md](platform-api-compatibility-support-window.md) for
the beta support-window policy, experimental opt-in consequences, deprecation windows, and release
certification behavior for stable baseline regressions.

## Previous Snapshot Comparison

Release managers compare the current contract against the previous production beta contract
snapshot before promotion. The canonical baseline snapshot lives under
`docs/platform-api/contracts/platform-api-1.0-baseline.json`; production release artifacts also
write `platform-api-contract-current.json`, `platform-api-contract-previous.json`, and
`platform-api-stable-diff.json`. Those artifacts are redacted metadata only.

Stable apps can reproduce the app-author side of the check with:

```bash
crypta-app api snapshot --output build/platform-api-contract.json
crypta-app api policy --contract build/platform-api-contract.json
crypta-app compat verify \
  --bundle-dir . \
  --contract build/platform-api-contract.json \
  --target-stability stable \
  --strict
```

## Stable 1.0 release baseline

The canonical Stable RC freeze records `platform-api-current-contract.json`,
`platform-api-stable-diff.json`, the Platform API 1.0 baseline identity, and their digests beside
the deterministic product archive. Stable GA re-authenticates those files and requires the GA
payload to retain the same API snapshot. Promotion cannot add, remove, graduate, deprecate, or
otherwise change Platform API 1.0 membership.

After verified publication, `stable-1.0-maintenance-baseline.json` becomes the release-comparison
anchor for the GA build. Future maintenance and hotfix candidates compare their current contract,
stable surface, access flags, required capabilities, action labels, and support-window metadata
against that baseline. Any API change needed before GA must return to the Stable RC refreeze path.
