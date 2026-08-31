# Signed app catalogs

This document describes Cryptad's signed app catalog format and the local install/update flow.

Public-beta users should start with the catalog onboarding summary in
[public-beta/catalogs-and-apps.md](public-beta/catalogs-and-apps.md). This document remains the
signed catalog source of truth.

## Scope

Signed app catalogs are a Phase 5 app-platform control plane. They do not change peer protocols,
wire formats, application sandboxing, or AppHost process launching. A catalog tells the local node
where to fetch a signed app bundle ZIP and which digest, size, app id, and version to expect. It
can also carry optional app-store display metadata for review, compatibility, source, license,
permissions, screenshots, changelog links, production catalog channels, support status,
deprecation/replacement hints, first-party maintenance policy metadata, third-party submission
review metadata, security advisory references, and catalog-level security response policy.

The runtime verifies data in this order:

1. `cryptad-app-catalog.signature` over the exact bytes of `cryptad-app-catalog.properties`.
2. The catalog entry's ZIP artifact size and lowercase SHA-256 digest.
3. The extracted bundle's existing `cryptad-app.digests` and `cryptad-app.signature` through
   `AppBundleVerifier`.
4. The extracted manifest `app.id` and `app.version` against the catalog entry.
5. If present, the app review receipt signature over canonical receipt payload bytes, using the
   node's separate trusted reviewer-key registry.
6. If present, the catalog-level security decision for the exact app version.

These are separate trust layers. The catalog signature authenticates catalog bytes and publisher
metadata. The artifact digest binds one catalog entry to one downloaded ZIP. The bundle signature
authenticates the extracted app bundle. A review receipt signature independently authenticates
review evidence from a reviewer key that the local node trusts for app review. Legacy
`review.status` and `review.note` catalog metadata remains publisher-advisory only.

Catalog-level security policy starts at `catalog.version=4`. It can define signed advisory records
and exact app-version denylist entries. Those records are enforceable: denylisted versions cannot
be installed, updated, staged, applied, or applied by automatic policy, and warning-level
advisories require the independent `securityAcknowledged=true` acknowledgement for manual
install/update. See [ecosystem-security-advisories.md](ecosystem-security-advisories.md).
Production incident handling for advisory publication, denylist propagation, catalog signing-key
rotation, emergency replacement apps, and release notes is covered by
[production-security-response-runbook.md](production-security-response-runbook.md). Production
source operations for a primary source plus mirrors, transport fallback, verified revision history,
explicit rollback, key-rotation status, and emergency advisory refresh are covered by
[catalog-operations-and-mirrors.md](catalog-operations-and-mirrors.md).
Stable 1.0 role-separated key governance and network-primary publication are covered by
[stable-1.0-catalog-publication-and-key-ceremony.md](stable-1.0-catalog-publication-and-key-ceremony.md).

The host/operator consent layer groups catalog trust metadata into one install or update preview
before a material mutation. Permission rationales, review receipt state, reviewer-key lifecycle,
channel/support changes, deprecation and replacement notices, security advisories, app-service
dependencies, and app-data migration declarations are summarized with a snapshot digest. Manual
install/update mutations that require consent must carry an approval for that exact digest; stale
approvals are rejected. See
[user-consent-and-permission-upgrade-ux.md](user-consent-and-permission-upgrade-ux.md).

For third-party app authors, `crypta-app catalog entry` can generate the descriptor input for
`catalog create`, `crypta-app publish-usk --dry-run` can produce an offline publication checklist,
and `crypta-app publish-usk --live` can publish a verified signed catalog through a configured
localhost node. Those helpers do not change the runtime trust layers described here; they only
reduce hand-authored descriptor, publication-plan, and live-publication mistakes. See
[developer-beta-toolkit.md](developer-beta-toolkit.md).

## Catalog files

A catalog source points at `cryptad-app-catalog.properties`. The matching signature is read from
the sibling file `cryptad-app-catalog.signature`.

Catalog properties use a deterministic `key=value` text sidecar:

```properties
catalog.version=5
catalog.id=core
catalog.name=Crypta Core Apps
catalog.generatedAt=2026-04-21T18:22:40Z
catalog.entries=queue-manager,publisher,site-publisher,profile-publisher,social-inbox,feed-reader,trust-graph

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
app.queue-manager.channel=stable
app.queue-manager.minimumCryptaVersion=1481
app.queue-manager.maximumCryptaVersion=1499
app.queue-manager.support.status=supported
app.queue-manager.deprecation.status=none
app.queue-manager.securityAdvisories=CRYPTA-2026-0001
app.queue-manager.securityAdvisory.CRYPTA-2026-0001.uri=https://example.invalid/advisories/CRYPTA-2026-0001
app.queue-manager.maintenance.owner=crypta-core
app.queue-manager.maintenance.ownerUri=https://example.invalid/crypta/owners/core
app.queue-manager.maintenance.supportLevel=core
app.queue-manager.maintenance.dataSchemaPolicy=stateless
app.queue-manager.maintenance.migrationPolicy=none
app.queue-manager.maintenance.backupRestore=not-applicable
app.queue-manager.maintenance.securityPolicy=catalog-advisories
app.queue-manager.maintenance.deprecationPolicy=none
app.queue-manager.maintenance.supportUri=https://example.invalid/crypta/apps/queue-manager/support
app.queue-manager.review.status=reviewed
app.queue-manager.review.note=Reviewed for local operator safety.
app.queue-manager.permissions.rationale.queue.read=Reads the local transfer queue.
app.queue-manager.permissions.rationale.queue.write=Lets the app cancel or reprioritize requests.
app.queue-manager.screenshot.1=https://example.invalid/assets/queue-manager-1.png
app.queue-manager.changelog.summary=Adds queue retry controls.
app.queue-manager.changelog.uri=https://example.invalid/apps/queue-manager-1.0.0-changelog.txt
app.queue-manager.api.minimumVersion=1
app.queue-manager.api.maximumTestedVersion=23
app.queue-manager.api.targetStability=stable
app.queue-manager.api.experimentalCapabilitiesAccepted=false

app.site-publisher.id=site-publisher
app.site-publisher.name=Site Publisher
app.site-publisher.version=1.0.0
app.site-publisher.summary=Reference app for publishing a local static site through Crypta.
app.site-publisher.bundle.uri=https://example.invalid/apps/site-publisher-1.0.0.zip
app.site-publisher.bundle.sha256=<lowercase-hex-sha256-of-zip>
app.site-publisher.bundle.size.bytes=12345
app.site-publisher.bundle.type=zip
app.site-publisher.permissions=queue.read,queue.write,content.insert
app.site-publisher.homepage=https://example.invalid/apps/site-publisher
app.site-publisher.source=https://example.invalid/src/site-publisher
app.site-publisher.license=GPL-3.0-only
app.site-publisher.categories=publishing,content
app.site-publisher.review.status=reviewed
app.site-publisher.review.note=First-party content reference app.
app.site-publisher.permissions.rationale.content.insert=Submits selected local site content to the insert pipeline.
app.site-publisher.permissions.rationale.queue.write=Creates insert requests for the publish operation.
app.site-publisher.permissions.rationale.queue.read=Displays publish progress from the local transfer queue.
app.site-publisher.changelog.summary=Adds the first content reference app.
app.site-publisher.api.minimumVersion=3
app.site-publisher.api.maximumTestedVersion=23
app.site-publisher.api.targetStability=stable
app.site-publisher.api.experimentalCapabilitiesAccepted=false

app.profile-publisher.id=profile-publisher
app.profile-publisher.name=Profile Publisher
app.profile-publisher.version=1.0.0
app.profile-publisher.summary=Reference app for publishing an identity-bound profile document.
app.profile-publisher.bundle.uri=https://example.invalid/apps/profile-publisher-1.0.0.zip
app.profile-publisher.bundle.sha256=<lowercase-hex-sha256-of-zip>
app.profile-publisher.bundle.size.bytes=12345
app.profile-publisher.bundle.type=zip
app.profile-publisher.permissions=queue.read,queue.write,content.insert.app-document,vault.identities.read,vault.identities.create,vault.identities.use,app.data.read,app.data.write
app.profile-publisher.homepage=https://example.invalid/apps/profile-publisher
app.profile-publisher.source=https://example.invalid/src/profile-publisher
app.profile-publisher.license=GPL-3.0-only
app.profile-publisher.categories=publishing,identity
app.profile-publisher.review.status=reviewed
app.profile-publisher.review.note=First-party profile reference app.
app.profile-publisher.permissions.rationale.vault.identities.create=Creates an app-owned profile identity without exporting private material.
app.profile-publisher.permissions.rationale.vault.identities.use=Asks Cryptad to produce the profile document for the selected identity.
app.profile-publisher.permissions.rationale.content.insert.app-document=Submits the generated profile document to the insert pipeline without local source-path authority.
app.profile-publisher.permissions.rationale.queue.write=Creates the generated document insert request.
app.profile-publisher.permissions.rationale.queue.read=Displays publish progress from the local transfer queue.
app.profile-publisher.permissions.rationale.app.data.read=Restores bounded profile drafts and publish summaries.
app.profile-publisher.permissions.rationale.app.data.write=Saves bounded profile drafts and publish summaries.
app.profile-publisher.changelog.summary=Adds the first identity-profile reference app.
app.profile-publisher.api.minimumVersion=9
app.profile-publisher.api.maximumTestedVersion=23
app.profile-publisher.api.targetStability=experimental
app.profile-publisher.api.experimentalCapabilitiesAccepted=true

app.social-inbox.id=social-inbox
app.social-inbox.name=Social Inbox RC
app.social-inbox.version=1.0.0
app.social-inbox.summary=Reference app for local threaded social inbox workflows outside daemon core.
app.social-inbox.bundle.uri=https://example.invalid/apps/social-inbox-1.0.0.zip
app.social-inbox.bundle.sha256=<lowercase-hex-sha256-of-zip>
app.social-inbox.bundle.size.bytes=12345
app.social-inbox.bundle.type=zip
app.social-inbox.permissions=vault.identities.read,vault.identities.create,vault.identities.use,content.fetch,content.subscribe,content.insert.app-document,queue.read,queue.write,app.data.read,app.data.write,app.services.read,app.services.call
app.social-inbox.homepage=https://example.invalid/apps/social-inbox
app.social-inbox.source=https://example.invalid/src/social-inbox
app.social-inbox.license=GPL-3.0-only
app.social-inbox.categories=social,identity,reference
app.social-inbox.review.status=reviewed
app.social-inbox.review.note=First-party Social Inbox RC reference app; local threading and Trust Graph annotations only, not full WoT, plugin compatibility, Freetalk/Sone/Freemail, encrypted mail, crawler, or daemon-core protocol.
app.social-inbox.permissions.rationale.vault.identities.read=Lists public metadata for app-owned social signing identities.
app.social-inbox.permissions.rationale.vault.identities.create=Creates an app-owned Social Inbox identity without exporting private material.
app.social-inbox.permissions.rationale.vault.identities.use=Uses bounded social-message and profile-document routes without exposing generic browser signing.
app.social-inbox.permissions.rationale.content.fetch=Fetches bounded social outbox JSON selected by the user or a subscription.
app.social-inbox.permissions.rationale.content.subscribe=Manages durable USK social source subscriptions without global crawling.
app.social-inbox.permissions.rationale.content.insert.app-document=Publishes generated social outbox snapshots without local source-path authority.
app.social-inbox.permissions.rationale.queue.write=Creates generated social outbox publication inserts.
app.social-inbox.permissions.rationale.queue.read=Displays safe upload queue summaries.
app.social-inbox.permissions.rationale.app.data.read=Restores bounded sources, imported-message summaries, channel filters, message read-state-derived thread actions, outbox summaries, and explicit drafts.
app.social-inbox.permissions.rationale.app.data.write=Saves bounded Social Inbox RC state without private insert URIs, raw fetched documents, or private identity material.
app.social-inbox.permissions.rationale.app.services.read=Discovers local app-service descriptors and caller-visible grant state.
app.social-inbox.permissions.rationale.app.services.call=Requests and invokes an operator-approved Trust Graph score service grant.
app.social-inbox.services.requests=trust-score
app.social-inbox.service-request.trust-score.provider=trust-graph
app.social-inbox.service-request.trust-score.service=trust.score
app.social-inbox.service-request.trust-score.scopes=score.read
app.social-inbox.service-request.trust-score.contexts=message-author
app.social-inbox.service-request.trust-score.purpose=Annotate Social Inbox message authors using the local Trust Graph Local RC score service.
app.social-inbox.changelog.summary=Adds the Social Inbox RC threaded reference app.
app.social-inbox.api.minimumVersion=16
app.social-inbox.api.maximumTestedVersion=23
app.social-inbox.api.targetStability=experimental
app.social-inbox.api.experimentalCapabilitiesAccepted=true

app.feed-reader.id=feed-reader
app.feed-reader.name=Feed Reader & Publisher
app.feed-reader.version=1.0.0
app.feed-reader.summary=Reference app for reading and publishing feed documents through Crypta.
app.feed-reader.bundle.uri=https://example.invalid/apps/feed-reader-1.0.0.zip
app.feed-reader.bundle.sha256=<lowercase-hex-sha256-of-zip>
app.feed-reader.bundle.size.bytes=12345
app.feed-reader.bundle.type=zip
app.feed-reader.permissions=content.fetch,content.subscribe,content.insert.app-document,queue.read,queue.write,app.data.read,app.data.write
app.feed-reader.homepage=https://example.invalid/apps/feed-reader
app.feed-reader.source=https://example.invalid/src/feed-reader
app.feed-reader.license=GPL-3.0-only
app.feed-reader.categories=reader,publishing,content
app.feed-reader.review.status=reviewed
app.feed-reader.review.note=First-party feed reference app.
app.feed-reader.permissions.rationale.content.fetch=Fetches subscribed feed documents through the bounded content fetch route.
app.feed-reader.permissions.rationale.content.subscribe=Registers bounded USK feed subscriptions with the platform scheduler and stores metadata only.
app.feed-reader.permissions.rationale.content.insert.app-document=Submits generated feed documents to the insert pipeline without local source-path authority.
app.feed-reader.permissions.rationale.queue.write=Creates generated feed publication inserts.
app.feed-reader.permissions.rationale.queue.read=Displays publication progress from the local transfer queue.
app.feed-reader.permissions.rationale.app.data.read=Restores the app-owned feed list, selected subscriptions, read state, and safe draft metadata.
app.feed-reader.permissions.rationale.app.data.write=Saves bounded app-owned reader state through the durable app-data API.
app.feed-reader.changelog.summary=Adds the first feed reader and publisher reference app.
app.feed-reader.api.minimumVersion=9
app.feed-reader.api.maximumTestedVersion=23
app.feed-reader.api.targetStability=stable
app.feed-reader.api.experimentalCapabilitiesAccepted=false

app.trust-graph.id=trust-graph
app.trust-graph.name=Trust Graph Local RC
app.trust-graph.version=1.0.0
app.trust-graph.summary=Reference app for durable local trust statements, anchors, exchange, audit, and preview scoring.
app.trust-graph.bundle.uri=https://example.invalid/apps/trust-graph-1.0.0.zip
app.trust-graph.bundle.sha256=<lowercase-hex-sha256-of-zip>
app.trust-graph.bundle.size.bytes=12345
app.trust-graph.bundle.type=zip
app.trust-graph.permissions=trust.read,trust.write,content.fetch,content.subscribe,content.insert.app-document,queue.read,queue.write,vault.identities.read,vault.identities.create,vault.identities.use,app.data.read,app.data.write
app.trust-graph.homepage=https://example.invalid/apps/trust-graph
app.trust-graph.source=https://example.invalid/src/trust-graph
app.trust-graph.license=GPL-3.0-only
app.trust-graph.categories=identity,trust,preview
app.trust-graph.review.status=reviewed
app.trust-graph.review.note=First-party local trust graph preview; not full WoT or moderation.
app.trust-graph.permissions.rationale.trust.read=Reads local trust graph scores, evidence, and redacted audit entries for preview queries.
app.trust-graph.permissions.rationale.trust.write=Imports local trust statements and manages local trust anchors.
app.trust-graph.permissions.rationale.vault.identities.create=Creates an app-owned trust identity without exporting private material.
app.trust-graph.permissions.rationale.vault.identities.use=Uses the bounded trust-statement route to sign trust statements.
app.trust-graph.permissions.rationale.content.fetch=Fetches bounded Crypta trust documents selected by the user.
app.trust-graph.permissions.rationale.content.subscribe=Manages trust statement content subscriptions without global crawling.
app.trust-graph.permissions.rationale.content.insert.app-document=Publishes generated trust statements as Crypta content.
app.trust-graph.permissions.rationale.queue.write=Creates generated trust statement publication inserts.
app.trust-graph.permissions.rationale.queue.read=Displays publication progress from the local transfer queue.
app.trust-graph.permissions.rationale.app.data.read=Restores UI-local drafts, selected filters, and redacted import summaries.
app.trust-graph.permissions.rationale.app.data.write=Saves bounded UI-local preview state separately from the trust backend.
app.trust-graph.services.provides=trust-score
app.trust-graph.service.trust-score.id=trust.score
app.trust-graph.service.trust-score.name=Trust Score Service
app.trust-graph.service.trust-score.version=1
app.trust-graph.service.trust-score.kind=platform-adapter
app.trust-graph.service.trust-score.adapter=trust-graph.score
app.trust-graph.service.trust-score.scopes=score.read
app.trust-graph.service.trust-score.contexts=message-author,profile
app.trust-graph.service.trust-score.description=Returns a bounded local RC Trust Graph score summary for an app-provided public subject.
app.trust-graph.changelog.summary=Adds the local Trust Graph Local RC reference app.
app.trust-graph.api.minimumVersion=22
app.trust-graph.api.maximumTestedVersion=23
app.trust-graph.api.targetStability=experimental
app.trust-graph.api.experimentalCapabilitiesAccepted=true
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
compatibility metadata fields shown above. `catalog.version=3` adds production catalog channels,
maximum Cryptad compatibility, support/deprecation metadata, replacement app hints, and security
advisory references. `catalog.version=4` adds catalog-level security response policy.
`catalog.version=5` adds first-party maintenance policy metadata. `catalog.version=6` adds
third-party submission review workflow metadata such as submission ids, pre-review digests,
reviewer policy fingerprints, receipt fingerprints, decision-rationale digests, resubmission
links, and non-production markers. Current Cryptad nodes parse all six versions. Older strict
v1-v5 nodes reject newer catalogs rather than silently accepting unknown metadata fields.

Minimal v1 catalogs that only provide the required fields still parse and install unchanged. The
app-store metadata fields remain optional within the v2 schema. V1 and v2 catalogs that omit
production channel metadata default to `stable`, `supported`, `deprecation.status=none`, no
replacement app id, and no security advisories.

## Production channel metadata

Production catalog channels are signed catalog metadata. They do not replace catalog signature
verification, artifact digest checks, bundle signature verification, manifest id/version checks, or
review receipt verification.

| Channel | Meaning |
| --- | --- |
| `stable` | Production-safe default. Stable entries are the only entries eligible for automatic staging/apply under the default app-update policy. |
| `beta` | Operator-selected preview channel. Beta entries are visible only when the operator selects beta browsing or an update policy explicitly allows beta automation. |
| `nightly` | High-churn preview channel for release jobs and testers. Nightly is never mixed into stable browsing or stable-only automation. |
| `deprecated` | Retired or replacement-directed entry. Deprecated entries remain visible signed metadata, but they are not ordinary automatic update candidates. |

The v3 property set is:

```properties
app.<id>.channel=stable|beta|nightly|deprecated
app.<id>.minimumCryptaVersion=<semver-or-build-version>
app.<id>.maximumCryptaVersion=<semver-or-build-version>
app.<id>.support.status=supported|maintenance|experimental|deprecated|unsupported
app.<id>.deprecation.status=none|deprecated|retired
app.<id>.deprecation.message=<single-line operator-facing text>
app.<id>.replacementAppId=<normalized-app-id>
app.<id>.securityAdvisories=<comma-separated advisory ids>
app.<id>.securityAdvisory.<advisoryId>.uri=<safe metadata URI>
```

`replacementAppId` uses the same normalized app-id validation as catalog entries. Advisory URIs use
the same safe metadata URI policy as homepage, source, changelog, and screenshot links. The
`deprecated` channel and deprecation metadata are visible to API clients and the Web Shell; they
are not a signature bypass or artifact-verification bypass.

## First-party maintenance metadata

First-party maintenance metadata is authenticated by `catalog.version=5` signed catalog bytes. It
turns first-party app catalog entries into explicit maintenance commitments without replacing the
existing production-channel, support-status, security-advisory, deprecation, replacement, review,
or compatibility fields.

The v5 property set is:

```properties
app.<id>.maintenance.owner=crypta-core
app.<id>.maintenance.ownerUri=https://example.invalid/crypta/owners/core
app.<id>.maintenance.supportLevel=core|maintained|reference|local-rc|preview|maintenance|deprecated|unsupported
app.<id>.maintenance.dataSchemaPolicy=stateless|declared|migratable|external|not-applicable
app.<id>.maintenance.migrationPolicy=none|declared|dry-run-required|operator-approved|not-applicable
app.<id>.maintenance.backupRestore=not-applicable|export-only|export-import|operator-supported|unsupported
app.<id>.maintenance.securityPolicy=catalog-advisories|project-security-policy|unsupported
app.<id>.maintenance.deprecationPolicy=none|notice-only|replacement-required|security-only
app.<id>.maintenance.supportUri=https://example.invalid/crypta/apps/<app-id>/support
```

Catalogs that declare any `maintenance.*` field must declare all required maintenance policy
fields for that entry. Owner and URI text must be bounded and single-line. URI fields use the same
safe metadata URI validation as homepage, source, changelog, screenshot, and advisory URI fields.

The release channel remains `app.<id>.channel`. Supported daemon version bounds remain
`app.<id>.minimumCryptaVersion` and `app.<id>.maximumCryptaVersion`. Deprecation lifecycle and
replacement target remain `app.<id>.deprecation.*` and `app.<id>.replacementAppId`. Security
advisory handling remains `app.<id>.securityAdvisories` plus catalog-level security policy.

See [first-party-app-maintenance-policy.md](first-party-app-maintenance-policy.md) for the current
first-party policy table and the `app-catalog.first-party-maintenance-policy` certification
evidence.

## Third-party submission review metadata

Third-party submission review workflow metadata is authenticated by `catalog.version=6` signed
catalog bytes. Catalog candidate descriptors generated by `crypta-app submission catalog-candidate`
use v6 when they include `review.submission.*`, `review.preReview.*`,
`review.reviewer.*`, `review.receipt.fingerprint.sha256`,
`review.decision.reason.sha256`, `review.resubmissionOf`, or `review.nonProduction`.

The v6 fields are audit metadata only. They do not replace the independent embedded
`review.receipt.*` signature, artifact digest checks, or trusted reviewer-key evaluation. Older
catalog schemas must fail closed when these fields are present so strict older nodes reject the
catalog as unsupported instead of accepting unknown review metadata.

## App-store metadata

Catalog entries can include these optional fields:

| Catalog property | Meaning |
| --- | --- |
| `app.<id>.homepage` | Operator-facing homepage URI. |
| `app.<id>.source` | Source repository or source archive URI. |
| `app.<id>.license` | Single-line license label, such as `MIT` or `GPL-3.0-or-later`. |
| `app.<id>.categories` | Comma-separated category labels, normalized and deduplicated for display. |
| `app.<id>.channel` | Production channel: `stable`, `beta`, `nightly`, or `deprecated`. |
| `app.<id>.minimumCryptaVersion` | Advisory minimum Cryptad build/version string. Integer build numbers are the comparable form used by Platform API responses. |
| `app.<id>.maximumCryptaVersion` | Advisory maximum supported Cryptad build/version string. |
| `app.<id>.support.status` | Operator-facing support state: `supported`, `maintenance`, `experimental`, `deprecated`, or `unsupported`. |
| `app.<id>.deprecation.status` | Deprecation lifecycle state: `none`, `deprecated`, or `retired`. |
| `app.<id>.deprecation.message` | Single-line deprecation note shown to operators. |
| `app.<id>.replacementAppId` | Normalized replacement app id for deprecated or retired entries. |
| `app.<id>.securityAdvisories` | Comma-separated advisory identifiers with matching `securityAdvisory.<id>.uri` metadata links. |
| `app.<id>.maintenance.*` | First-party maintenance policy metadata. See [First-party maintenance metadata](#first-party-maintenance-metadata). |
| `app.<id>.review.status` | Advisory human review or submission workflow state. Supported values are `unreviewed`, `submitted`, `pre_review_passed`, `reviewed`, `caution`, `rejected`, and `resubmitted`. |
| `app.<id>.review.note` | Single-line advisory review note for operators. |
| `app.<id>.review.submission.id` | Third-party submission id that produced this candidate descriptor. |
| `app.<id>.review.submission.sha256` | SHA-256 digest of the submission ZIP. |
| `app.<id>.review.preReview.status` | Automated pre-review status: `pass`, `warn`, or `fail`. |
| `app.<id>.review.preReview.sha256` | SHA-256 digest of the pre-review JSON report. |
| `app.<id>.review.reviewer.keyId` | Reviewer key id that recorded the submission decision. |
| `app.<id>.review.reviewer.policy` | Reviewer policy id/version summary. |
| `app.<id>.review.receipt.fingerprint.sha256` | SHA-256 fingerprint of the independent review receipt. |
| `app.<id>.review.decision.reason.sha256` | SHA-256 digest of reviewer decision or rejection rationale. |
| `app.<id>.review.resubmissionOf` | Previous submission id linked by a resubmission. |
| `app.<id>.review.nonProduction` | `true` when the candidate was produced with fixture/test submission evidence. |
| `app.<id>.permissions.rationale.<permission>` | Explanation for a declared permission, keyed by the normalized permission name. |
| `app.<id>.screenshot.N` | Screenshot URI metadata, where `N` is a positive deterministic index. |
| `app.<id>.changelog.summary` | Single-line summary of changes for the catalog version. |
| `app.<id>.changelog.uri` | URI for full changelog text or release notes. |
| `app.<id>.api.minimumVersion` | Advisory minimum Platform API compatibility contract version. |
| `app.<id>.api.maximumTestedVersion` | Advisory maximum Platform API compatibility contract version tested by the app author. |
| `app.<id>.api.optionalCapabilities` | Advisory comma-separated optional capability names used for verifier and review warnings. |
| `app.<id>.api.targetStability` | App author target: `stable` for the Platform API 1.0 stable baseline or `experimental` for opt-in app-facing experimental API. |
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

Vault capabilities (`vault.secrets.*` and `vault.identities.*`) are experimental app-platform
capabilities. Catalog entries that advertise them should include permission rationales and, for
identity-use or secret access, trusted review receipt evidence appropriate to the catalog policy.
Catalog metadata never grants a shared identity by itself; the local operator grant in the identity
vault remains app-id-bound, scope-bound, revocable, and separate from the signed catalog.

Site Publisher remains the content-reference app and should not declare `vault.identities.*`
capabilities. Profile Publisher is the identity-profile reference app. Its catalog entry may
declare `vault.identities.read`, `vault.identities.create`, and `vault.identities.use` when the
bundle uses `POST /api/v1/app-vault/identities`,
`POST /api/v1/app-vault/identities/{identityId}/profile-document`, plus
`content.insert.app-document` when it uses `POST /api/v1/queue/inserts/app-document` without local
source-path authority. Catalog metadata and release evidence must not include raw request bodies,
private keys, raw signatures, private insert URIs, tokens, form passwords, or absolute staging
paths.

Feed Reader is the content-subscription reference app. Its catalog entry declares `content.fetch`
for `POST /api/v1/content/fetch` and `content.subscribe` for app-owned USK subscription metadata
under `/api/v1/content/subscriptions`; create and refresh require both capabilities. It can combine
`content.insert.app-document`, `queue.write`, and `queue.read` for generated feed publication.
Catalog metadata and release evidence must not include raw feed bodies, raw fetched content, raw
request bodies, private insert URIs, tokens, form passwords, browser-session tokens, private keys,
queue HTML, or local paths.

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
| `review.receipt.version` | Receipt schema version. Version `1` is the original receipt schema; version `2` adds the decision-rationale digest. |
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
| `review.receipt.decision.reason.sha256` | Optional reviewer decision-rationale digest. Requires `review.receipt.version=2`. |
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

## Third-party catalog candidates

`crypta-app submission catalog-candidate` converts a reviewed or caution submission package into a
developer-authored catalog descriptor. The descriptor records app identity, artifact digest, API
target stability, experimental opt-in state, submission id, submission digest, reviewer key id,
review policy, review receipt fingerprint, and non-production marker.

Rejected submissions cannot create installable catalog candidates. Caution candidates require an
explicit catalog policy choice and must preserve warning metadata in the descriptor. Reviewed
third-party candidates are not promoted into first-party stable channels automatically. Candidate
generation verifies the supplied receipt against a local `--trusted-reviewer-keys` registry before
writing the descriptor or copied bundle artifact, so hand-edited or untrusted receipts fail closed.

Catalog APIs expose third-party submission metadata as `thirdPartyReview`, separate from publisher
advisory `review` metadata and local trusted receipt evaluation in `reviewTrust`. See
[app-store-submission-and-review-workflow.md](app-store-submission-and-review-workflow.md) for the
submission package format, pre-review report, decision states, resubmission links, and transparency
events.

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

Version 2 reviewer registries are preferred for governed catalogs. They remain node-local trust
roots and add policy-version constraints plus lifecycle metadata:

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
reviewer.1.rotates.from=crypta-first-party-review-2026q1
reviewer.1.rotates.to=crypta-first-party-review-2026q3
```

Reviewer key status is local governance state. `active` keys can trust receipts inside their
validity window. `retired` keys can trust only historical receipts inside their window and render as
historical trust. `revoked` keys fail closed for all receipts and are reported as revoked reviewer
evidence rather than being hidden as unknown reviewers. A configured `policy.version` must match
the receipt policy version; mismatches are reported as `review_policy_mismatch`.

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
`missing_receipt`, `unknown_reviewer`, `retired_reviewer`, `revoked_reviewer`,
`reviewer_not_yet_valid`, `reviewer_expired`, `review_policy_mismatch`, `invalid_signature`,
`artifact_mismatch`, `app_mismatch`, `expired`, `publisher_claim_only`, and `not_configured`.

Cryptad also keeps a local review transparency log for review governance events. The log is
host-owned and tamper-evident through a local hash chain. It is not a global public transparency
log and does not make catalogs or apps trusted by itself. Web Shell review status is a local trust
decision and can change when reviewer keys, lifecycle metadata, policy constraints, or policy mode
change. See [app-review-governance.md](app-review-governance.md) for the lifecycle model,
transparency-log fields, Platform API routes, and CLI inspection commands.

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
api.targetStability=stable
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
  --catalog-signature-file dist/catalog/cryptad-app-catalog.signature \
  --expected-key-id dev-local \
  --trusted-key-id dev-local \
  --trusted-public-key-file /abs/path/to/dev-app-signing-public.pem
```

The catalog signature authenticates the exact bytes of `cryptad-app-catalog.properties`. Do not
rewrite, sort, or reformat the catalog after signing. See
[app-dev-cli.md](app-dev-cli.md) for the full standalone app CLI workflow.

`--catalog-signature-file` selects the exact detached sidecar instead of deriving the canonical
sibling filename. `--expected-key-id` additionally requires that sidecar to name the separately
declared signer, even when the trusted-key registry contains several valid keys. General local
verification may omit either option and use the canonical sibling or any trusted signer. Protected
release verification supplies both so a renamed sidecar or a different trusted key cannot satisfy
the frozen catalog identity.

For a local Site Publisher catalog, use a `file:` `bundle.uri` that points at the signed ZIP
artifact, create and sign the catalog, then add the catalog source through Platform API:

```bash
crypta-app catalog create \
  --catalog-file dist/catalog/cryptad-app-catalog.properties \
  --catalog-id local-site-publisher \
  --name "Local Site Publisher" \
  --entry site-publisher-catalog-entry.properties \
  --review-receipt review-receipt.properties

crypta-app catalog sign \
  --catalog-file dist/catalog/cryptad-app-catalog.properties \
  --key-id dev-local \
  --private-key-file /abs/path/to/dev-app-signing-private.pem

crypta-app catalog verify \
  --catalog-file dist/catalog/cryptad-app-catalog.properties \
  --catalog-signature-file dist/catalog/cryptad-app-catalog.signature \
  --expected-key-id dev-local \
  --trusted-key-id dev-local \
  --trusted-public-key-file /abs/path/to/dev-app-signing-public.pem
```

Add the local catalog source and install Site Publisher with the existing app-catalog routes:

```text
POST /api/v1/app-catalogs/add?source=<local-catalog-properties-path>
POST /api/v1/app-catalogs/local-site-publisher/refresh
POST /api/v1/app-catalogs/local-site-publisher/apps/site-publisher/install
```

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

Catalog verification has a catalog-specific registry boundary:

| Setting | Environment variable |
| --- | --- |
| `cryptad.appcatalog.trustedKeysFile` | `CRYPTAD_APPCATALOG_TRUSTED_KEYS_FILE` |

AppHost keeps using its existing app-bundle trusted-key settings, and reviewer verification keeps
using the separate reviewer lifecycle registry. A key trusted for one role is not thereby trusted
for another role. Stable production uses separate registry files and distinct key IDs and
fingerprints for catalog signing, first-party app signing, and review. When the catalog-specific
setting is present, the runtime compares the complete catalog and app-bundle registries and rejects
any stable key ID or SHA-256 X.509 public-key fingerprint present in both, including retiring,
retired, or revoked entries. Pointing both roles at the same file therefore fails closed.
Each lifecycle registry independently rejects a canonical public-key fingerprint repeated under
different stable IDs. This prevents a detached sidecar from relabeling revoked signing material as
an active alias while preserving existing v1 and v2 file shapes.

App-bundle trusted-key files retain version 1 compatibility. A version 1 entry is treated as an
active compatibility key. Ceremony-derived Stable app registries use closed version 2 entries
with `status`, `valid.from`, and `valid.until`. Normal install and update verification accepts only
an active key inside that interval. The explicit historical-verification path accepts active,
retiring, or retired keys inside their support interval; a revoked or out-of-window key fails both
purposes. AppHost applies that historical policy before every explicit installed-app launch and
every automatic restart, as well as before restoring a retained rollback bundle. The bundle
signature sidecar itself remains version 1 and unchanged.

For compatibility with deployments created before the catalog-specific setting existed, catalog
verification may use the AppHost trusted-key registry only when the catalog setting is absent. The
runtime emits a bounded migration warning. This fallback does not merge the roles permanently and
does not satisfy Stable production certification. A partial or conflicting catalog configuration
fails closed.

Unsigned catalogs are rejected. The local unsigned-bundle development bypass does not make remote
catalogs or catalog artifacts trusted. Existing v1 catalog and app signature sidecars remain
unchanged; role separation is applied by registry selection and lifecycle policy.

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

`crypta:` is a catalog transport, not a trust boundary. Signed catalog verification must still
verify the catalog signature against a configured trusted catalog key. Install and update flows
still verify the catalog entry's artifact size and SHA-256, then verify the extracted signed
bundle before AppHost receives it.

Catalog artifact URIs support:

- Local `file:` URIs.
- Remote `https:` URIs.
- Loopback-only `http:` URIs for local development.
- Immutable Crypta artifact URIs in the form `crypta:CHK@<artifact-key>`.

Crypta app ZIP artifacts must use bare CHK keys. `crypta:USK@...`, `crypta:SSK@...`, fragments,
and `?signature=...` companion queries are rejected for catalog entry artifacts. Mutable USK/SSK
keys remain supported for catalog sidecars, where they point to signed catalog bytes and sibling
signature sidecars.

For live USK catalog publication, publish `cryptad-app-catalog.properties` as the public
`crypta:USK@.../cryptad-app-catalog.properties` source and publish
`cryptad-app-catalog.signature` as the sibling at the same USK path and edition. When refresh
resolves a newer USK edition, Cryptad fetches the matching sibling signature sidecar from that
resolved edition and stores the replacement only after signed catalog verification succeeds.

`crypta:CHK@...` is a transport location, not a trust boundary. The runtime fetches those bytes
through `ContentFetchPort`, enforces the declared `bundle.size.bytes` and catalog artifact cap, and
then checks the lowercase `bundle.sha256` before extraction. The extracted bundle signature and
manifest id/version checks still run exactly as they do for `file:`, `https:`, and loopback `http:`
artifacts.

Catalog sources can also be operated as a primary source plus mirrors. Refresh tries the primary
first and then enabled mirrors in priority order, but every fetched catalog still must verify with
the configured trusted catalog key, parse successfully, match the configured catalog id, and pass
the stale/downgrade policy before it can replace the active revision. A mirror is only a transport
fallback and never a trust authority. Older mirror revisions are marked stale and cannot silently
replace the current verified catalog; only an explicit rollback to a previously verified revision
can move backward. See [catalog-operations-and-mirrors.md](catalog-operations-and-mirrors.md).

Remote fetches use finite timeouts, no automatic redirects, and size caps for catalog, signature,
and artifact downloads. Artifact bytes are written to catalog-owned scratch storage, checked
against the catalog size and SHA-256, then extracted into a separate staging directory. The
extractor rejects artifacts with more than 4096 ZIP entries, absolute ZIP paths, `..`, Windows drive
prefixes, backslash path separators, duplicate normalized entries, and rootless bundles. It drops
macOS archive metadata entries such as `__MACOSX/**`, AppleDouble `._*` files, and `.DS_Store`
before signed-bundle verification, so those files are not installed as app payload.

## First-party beta catalog onboarding

Cryptad exposes a recommended first-party beta catalog descriptor for the Web Shell and Platform
API. The descriptor is an onboarding hint, not an app store ranking system and not a trust bypass.
It is visible even when packaging has not configured a source, so operators can see why the catalog
is unavailable. See [first-party-beta-catalog.md](first-party-beta-catalog.md) for the full
maintainer publication flow and operator onboarding guidance.

Recommended catalog configuration:

| Setting | Environment variable | Meaning |
| --- | --- | --- |
| `cryptad.firstPartyCatalog.enabled` | `CRYPTAD_FIRST_PARTY_CATALOG_ENABLED` | Set to `false` to hide the recommendation. |
| `cryptad.firstPartyCatalog.id` | `CRYPTAD_FIRST_PARTY_CATALOG_ID` | Expected signed catalog id. Defaults to `crypta-first-party-beta`. |
| `cryptad.firstPartyCatalog.source` | `CRYPTAD_FIRST_PARTY_CATALOG_SOURCE` | Source URI for `cryptad-app-catalog.properties`, usually `crypta:USK@.../cryptad-app-catalog.properties`. |
| `cryptad.firstPartyCatalog.trustedCatalogKeyId` | `CRYPTAD_FIRST_PARTY_CATALOG_TRUSTED_CATALOG_KEY_ID` | Trusted catalog signing key id that must be present in the catalog-specific trusted-key registry or the explicitly selected legacy fallback. |
| `cryptad.firstPartyCatalog.trustedKeyId` | `CRYPTAD_FIRST_PARTY_CATALOG_TRUSTED_KEY_ID` | Legacy trusted-key id alias, retained for older packaging. |
| `cryptad.firstPartyCatalog.reviewerPolicyHint` | `CRYPTAD_FIRST_PARTY_CATALOG_REVIEWER_POLICY_HINT` | Optional display hint for the review policy used by the catalog. |

The first-party beta catalog is expected to contain the current first-party apps:
`queue-manager`, `publisher`, `site-publisher`, `profile-publisher`, `social-inbox`,
`feed-reader`, and `trust-graph`. Entries should include
source/review/API, sandbox, permission rationale, and changelog metadata, for example
`permissions.rationale.*`,
`api.minimumVersion`, `api.maximumTestedVersion`, and `changelog.summary`. First-party public
artifacts should be published as immutable CHK ZIP artifacts and referenced as:

```properties
app.queue-manager.bundle.uri=crypta:CHK@<artifact-key>
app.queue-manager.bundle.sha256=<lowercase-sha256-of-zip>
app.queue-manager.bundle.size.bytes=<exact-size>
app.queue-manager.bundle.type=zip
```

No private keys are shipped in the repository. Packagers or release maintainers provide trusted
public key configuration to the runtime and keep signing/reviewer private keys outside the tree.

## Platform API flow

Operators can manage catalogs through Platform API v1:

```text
GET    /api/v1/app-catalogs
GET    /api/v1/app-catalogs/recommended
POST   /api/v1/app-catalogs/add?source=<uri-or-path>
POST   /api/v1/app-catalogs/recommended/{catalogId}/add
DELETE /api/v1/app-catalogs/{catalogId}
POST   /api/v1/app-catalogs/{catalogId}/refresh
GET    /api/v1/app-catalogs/{catalogId}/apps
GET    /api/v1/app-catalogs/{catalogId}/apps/{appId}
POST   /api/v1/app-catalogs/{catalogId}/apps/{appId}/install
POST   /api/v1/app-catalogs/{catalogId}/apps/{appId}/update
```

Operational catalog routes add mirror, health, revision, rollback, key-rotation, and emergency
advisory refresh controls:

```text
GET    /api/v1/app-catalogs/<catalogId>/operations/health
GET    /api/v1/app-catalogs/<catalogId>/operations/revisions
GET    /api/v1/app-catalogs/<catalogId>/operations/key-rotation
GET    /api/v1/app-catalogs/<catalogId>/mirrors
POST   /api/v1/app-catalogs/<catalogId>/mirrors
POST   /api/v1/app-catalogs/<catalogId>/mirrors/<mirrorId>
DELETE /api/v1/app-catalogs/<catalogId>/mirrors/<mirrorId>
POST   /api/v1/app-catalogs/<catalogId>/operations/refresh-primary
POST   /api/v1/app-catalogs/<catalogId>/operations/rollback
POST   /api/v1/app-catalogs/<catalogId>/operations/emergency-refresh
```

Refresh failures update the catalog source's last-attempt and last-failure status, but they do not
replace or delete the last successfully verified catalog sidecars. Catalog listing, detail, review
metadata, and security inspection continue to use the last historically verifiable catalog until
a later refresh verifies a replacement. Preparing a new install or update additionally requires
that cached catalog's signing key remain active and inside its routine verification window.
Already installed apps are not removed or rolled back because a catalog refresh failed. Mirror
fallback records the active source and whether fallback was used. Verified revision history is
bounded and rollback candidates are re-verified before use. Emergency advisory refresh uses the
same fail-closed verification path and only updates verified catalog metadata.

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
compatibility summaries, production channel, support status, deprecation status/message,
replacement app id, security advisory references, permission rationales, and permission deltas for
install/update review.
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
metadata, channel badges, support/deprecation metadata, replacement app ids, security advisory
links, permission explanations, installed-vs-catalog version difference, advisory compatibility
hints, and changelog metadata when present. The channel selector defaults to `stable`; beta,
nightly, and deprecated entries are shown only when the operator selects that channel. Deprecated
entries do not render as ordinary install/update candidates in the shell. Web Shell wording must
distinguish "signed by catalog publisher" from "reviewed by trusted reviewer". Catalog operations
also show primary and mirror health, fallback warnings, key-rotation status, rollback candidates,
and emergency advisory refresh controls without rendering private insert URI values, private keys,
tokens, raw content, raw app data, scratch paths, staged paths, or an absolute local path. See
[app-update-lifecycle.md](app-update-lifecycle.md) for candidate detection, manual apply,
permission-delta review, and rollback scope.

## Future work

Manifest permissions are enforced for app-process Platform API calls as described in
[app-permissions-and-audit.md](app-permissions-and-audit.md). Public app-store governance,
security-advisory denylist enforcement, app-data migration, backup/restore, and remote screenshot
proxying remain future work. Catalog-backed candidate detection, explicit apply, and stable-only
default automation are implemented; silent broad-channel auto-update is not the default.

## Federated catalogs and local trust

Multiple independently signed catalogs can coexist when the operator enables federation and
creates an exact local catalog-ID/signer binding. A catalog signature authenticates bytes; it does
not authorize an app publisher or reviewer. Publisher authorization is evaluated with the exact
catalog/app context, reviewer acceptance remains local, and mirrors never become trust roots.

Discovery descriptors and endorsements are bounded signed hints. Import leaves a descriptor
pending and does not add a source, install a key, or create trust. Endorsements are non-transitive
and do not produce a reputation score. Unresolved cross-catalog payload, publisher, security, and
reviewer disagreements block automatic selection instead of using catalog-ID ordering. Catalog
installs retain host-owned origin provenance, updates remain pinned, and AppHost rollback swaps the
prior provenance with the prior bundle. See
[stable-1.0-federated-catalog-discovery-and-trust.md](stable-1.0-federated-catalog-discovery-and-trust.md).

Federation-enabled nodes expose pending discovery evidence through the host/operator-only `GET`
and form-password-guarded `POST /operator/catalog-federation/discovery` routes. The Web Shell can
paste one signed descriptor and optional direct endorsements into that pending store. It does not
fetch advertised source hints or call the catalog trust/source-add routes. A guarded `POST
/operator/catalog-federation/discovery/{descriptorId}/discard` removes only the retained pending
record.

Federation is explicitly enabled with `cryptad.appCatalogFederationEnabled=true`. Existing source
records without a stored local binding ID and digest are not auto-migrated into federated trust;
they require operator re-approval. Operator-only summaries and source-switch previews live below
`/operator/catalog-federation` and `/operator/apps/{appId}/catalog-origin`, outside the Stable 1.0
app-facing contract. A catalog `trust` mutation treats matching repeated `signerKeyId` and
`signerFingerprintSha256` values as the complete local signer set. During an overlapping key
rotation, the operator submits both predecessor and successor so retained predecessor revisions
remain eligible for exact historical rollback. `GET
/operator/catalog-federation/conflicts/{appId}` exposes the exact local
conflict-set identity and public subject digests; guarded `POST
/operator/catalog-federation/conflicts/{appId}/resolve` records a decision only when the submitted
conflict ID and subject-set digest still match. An `explicit-source-switch-required` decision never
selects a catalog automatically; it enables the exact preview-and-consent path for an operator's
chosen target. Because preview preparation downloads, extracts, and verifies a bundle, the
source-switch preview is a form-password-guarded `POST`, never a resource-consuming `GET`. The catalog update mutation accepts a preview's exact
`sourceSwitchConsent` digest when the catalog or publisher identity changes. A general catalog-add
request supplies `expectedCatalogId` in federation mode so the fetched authenticated identity is
bound to the operator's selected local trust record. The Web Shell populates that field from the
host/operator-only federation summary and offers only unused `active` bindings. It disables source
addition when local trust state cannot be read or no active binding is available; it never derives
the expected identity from unauthenticated fetched catalog bytes.
