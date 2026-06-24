# Platform API 1.0 Stable Reference

This document is the developer-facing reference for the Platform API 1.0 stable baseline. It
describes the third-party app surface covered by stable compatibility guarantees. The full
contract snapshot remains available through `crypta-app api snapshot` and
`GET /api/v1/platform/contract`; this page lists only the `stableBaseline.name=1.0` members.

The stable baseline is separate from the integer compatibility contract version. The current
contract version records when descriptors were added or changed. The stable baseline name records
which descriptors are part of the Platform API 1.0 app-facing compatibility promise.
Platform API 1.0 membership is frozen at contract version 19. Later contract versions may add
experimental or future baseline surface, but they must not change `stableBaseline.name=1.0`
membership unless the project intentionally defines a new stable baseline.

## Stability Terms

`stable` means app-facing Platform API 1.0 surface. Stable baseline capabilities and routes remain
available to apps that declare `api.targetStability=stable`.

`experimental` means app-facing but not covered by the Platform API 1.0 stable guarantee. Apps may
use experimental capabilities only when they declare `api.targetStability=experimental` and
`api.experimentalCapabilitiesAccepted=true`.

`internal` means daemon implementation API. Third-party apps cannot declare internal capabilities.

`operator-only` means host or Web Shell operator API. Third-party apps cannot declare operator-only
capabilities, even when `api.targetStability=experimental`.

`deprecated` remains available but should warn during compatibility verification.
`scheduled-for-removal` remains available during its migration window but is excluded from new
stable target use.

## Manifest Choice

A stable-only third-party app should declare:

```properties
api.minimumVersion=1
api.maximumTestedVersion=19
api.targetStability=stable
api.experimentalCapabilitiesAccepted=false
```

An app that knowingly uses experimental app-facing API should declare:

```properties
api.minimumVersion=1
api.maximumTestedVersion=19
api.targetStability=experimental
api.experimentalCapabilitiesAccepted=true
```

Legacy manifests that omit `api.targetStability` remain readable. The compatibility metadata model
treats the effective target as `experimental`, records that the field was not declared, and emits
`api_target_stability_missing` when explicit API compatibility metadata is otherwise present.

## Stable Baseline Counts

The Platform API 1.0 stable baseline contains 9 capabilities and 32 endpoints.

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
