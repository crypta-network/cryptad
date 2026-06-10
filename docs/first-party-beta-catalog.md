# First-party beta app catalog

This guide describes how Cryptad maintainers publish and operators onboard the first-party beta app
catalog. The beta catalog remains available as the preview channel under the production first-party
catalog channel model; stable remains the default production-safe selector.

## Scope

The first-party beta catalog is a signed catalog for the current first-party apps:
`queue-manager`, `publisher`, `site-publisher`, `profile-publisher`, `social-inbox`,
`feed-reader`, and `trust-graph`. It does not auto-install apps and does not
weaken any existing gates. Catalog signatures, bundle signatures, review receipts, artifact
SHA-256 checks, Platform API compatibility metadata, sandbox metadata, and permission review remain
separate layers.

Beta entries should declare `channel=beta`, `support.status=experimental`, and explicit
`minimumCryptaVersion` / `maximumCryptaVersion` bounds when release jobs know the supported daemon
range. Operators can browse beta entries in Web Shell by selecting the beta catalog channel, but
automatic update staging/apply remains stable-only unless local app-update policy explicitly
allows beta. Deprecated entries should use the production-channel deprecation and replacement
metadata documented in [production-first-party-catalog-channels.md](production-first-party-catalog-channels.md).

The third-party developer beta toolkit extends the standalone CLI with scaffold templates, a mock
dev server, offline app tests, catalog entry generation, a dry-run USK publication checklist, and
an explicit live USK publication command for release operators. It does not replace this
first-party beta catalog flow or its release gates. See
[developer-beta-toolkit.md](developer-beta-toolkit.md) for the app-author workflow.

`crypta:` transport is not a trust boundary. Crypta-hosted catalog and bundle artifacts still must
match signed catalog metadata and signed bundle sidecars before AppHost can install or update them.

First-party review receipts are governed by the node-local trusted reviewer-key registry. Registry
v1 remains supported, but release candidates should prefer v2 reviewer registries with explicit
active, retired, or revoked lifecycle state and policy-version constraints. The local review
transparency log records first-party review-chain events for operator audit; it is local and
tamper-evident, not a global public transparency service.

## Runtime configuration

Set the recommended catalog source and trusted key hint in runtime or packaging configuration:

| Setting | Environment variable | Example |
| --- | --- | --- |
| `cryptad.firstPartyCatalog.enabled` | `CRYPTAD_FIRST_PARTY_CATALOG_ENABLED` | `true` |
| `cryptad.firstPartyCatalog.id` | `CRYPTAD_FIRST_PARTY_CATALOG_ID` | `crypta-first-party-beta` |
| `cryptad.firstPartyCatalog.source` | `CRYPTAD_FIRST_PARTY_CATALOG_SOURCE` | `crypta:USK@.../cryptad-app-catalog.properties` |
| `cryptad.firstPartyCatalog.trustedCatalogKeyId` | `CRYPTAD_FIRST_PARTY_CATALOG_TRUSTED_CATALOG_KEY_ID` | `crypta-first-party-beta` |
| `cryptad.firstPartyCatalog.trustedKeyId` | `CRYPTAD_FIRST_PARTY_CATALOG_TRUSTED_KEY_ID` | Legacy trusted-key id alias, retained for older packaging. |
| `cryptad.firstPartyCatalog.reviewerPolicyHint` | `CRYPTAD_FIRST_PARTY_CATALOG_REVIEWER_POLICY_HINT` | `crypta-app-review-v1` |

The trusted key id hint must correspond to a public catalog/app signing key configured through the
normal trusted-key registry:

```text
CRYPTAD_APPHOST_TRUSTED_KEYS_FILE
CRYPTAD_APPHOST_TRUSTED_KEY_ID
CRYPTAD_APPHOST_TRUSTED_PUBLIC_KEY_BASE64
CRYPTAD_APPHOST_TRUSTED_PUBLIC_KEY_FILE
```

Do not place production private signing keys, reviewer private keys, private insert URIs, process
tokens, browser session tokens, form passwords, raw request bodies, raw profile-document
signatures, or absolute staging paths in the repository or in release-certification artifacts.

## Operator flow

The Web Shell Apps page reads:

```text
GET /api/v1/app-catalogs/recommended
```

When the first-party beta source and trusted key are configured, the page shows an Add catalog
action. Adding the recommendation calls:

```text
POST /api/v1/app-catalogs/recommended/crypta-first-party-beta/add
```

That route delegates to the same verified `AppCatalogManager.addSource(...)` path as manual catalog
add. The signed catalog id must match `crypta-first-party-beta`, the catalog signature must verify
against the configured trusted key registry, and no apps are installed automatically. Operators
still inspect entries and confirm install/update actions per app. The Web Shell catalog-channel
selector defaults to stable; operators must select beta to see beta entries from a mixed
production catalog.

## Maintainer publication flow

Build or stage the first-party apps with the existing Gradle tasks:

```bash
./gradlew stageFirstPartyApps
./gradlew signFirstPartyApps
./gradlew verifyFirstPartyApps
./gradlew :platform-devtools:installDist
```

Pack each staged first-party app with `crypta-app pack`, then insert each ZIP as immutable Crypta
CHK content through the maintainer's publishing workflow. Record the returned CHK key, exact ZIP
size, and lowercase SHA-256.

Author catalog entry descriptors with the public CHK artifact URI and required metadata:

```properties
artifact.path=/abs/path/to/queue-manager.zip
bundle.uri=crypta:CHK@<artifact-key>
summary=Manage local Crypta transfer queues.
name=Queue Manager
permissions=queue.read,queue.write
permissions.rationale.queue.read=Reads local transfer queue state.
permissions.rationale.queue.write=Updates local queue state after operator action.
api.minimumVersion=1
api.maximumTestedVersion=16
review.status=reviewed
review.note=First-party beta review completed.
changelog.summary=First public beta catalog entry.
```

Profile Publisher descriptors should include the profile permissions and route-specific rationale:

```properties
permissions=queue.read,queue.write,content.insert.app-document,vault.identities.read,vault.identities.create,vault.identities.use,app.data.read,app.data.write
permissions.rationale.vault.identities.create=Creates an app-owned profile identity without exporting private material.
permissions.rationale.vault.identities.use=Uses the profile-document route for identity-bound profile publishing.
permissions.rationale.content.insert.app-document=Queues the generated profile document through app-document insert without local source-path authority.
permissions.rationale.app.data.read=Restores bounded profile drafts and publish summaries.
permissions.rationale.app.data.write=Saves bounded profile drafts and publish summaries.
api.minimumVersion=9
api.maximumTestedVersion=16
api.experimentalCapabilitiesAccepted=true
```

Feed Reader descriptors should include the content-subscription, content-fetch, and generated-feed
publication rationales:

```properties
permissions=content.fetch,content.subscribe,content.insert.app-document,queue.read,queue.write,app.data.read,app.data.write
permissions.rationale.content.fetch=Fetches subscribed feed documents through POST /api/v1/content/fetch without local source-path authority.
permissions.rationale.content.subscribe=Registers bounded USK subscriptions with the platform scheduler and stores metadata only.
permissions.rationale.content.insert.app-document=Queues generated feed documents through app-document insert.
permissions.rationale.queue.write=Creates generated feed publication inserts.
permissions.rationale.queue.read=Displays publication progress from the local transfer queue.
permissions.rationale.app.data.read=Restores the app-owned feed list, selected subscriptions, read state, and safe draft metadata.
permissions.rationale.app.data.write=Saves bounded app-owned reader state through the durable app-data API.
categories=reader,publishing,content
review.status=reviewed
review.note=First-party feed reference app.
api.minimumVersion=9
api.maximumTestedVersion=16
api.experimentalCapabilitiesAccepted=false
```

Social Inbox RC descriptors should include vault, content-fetch, content-subscription,
generated-document publication, app-data, and app-service grant rationales while making clear that
the app is a threaded RC reference app, not full WoT, Freetalk/Sone/Freemail compatibility,
encrypted mail, a crawler, or a daemon-core message protocol:

```properties
permissions=vault.identities.read,vault.identities.create,vault.identities.use,content.fetch,content.subscribe,content.insert.app-document,queue.read,queue.write,app.data.read,app.data.write,app.services.read,app.services.call
permissions.rationale.vault.identities.read=Lists public metadata for app-owned social signing identities.
permissions.rationale.vault.identities.create=Creates an app-owned Social Inbox identity without exporting private material.
permissions.rationale.vault.identities.use=Uses the bounded social-message and profile-document routes without exposing generic browser signing.
permissions.rationale.content.fetch=Fetches bounded social outbox JSON selected by the user or a subscription.
permissions.rationale.content.subscribe=Manages durable USK social source subscriptions without global crawling.
permissions.rationale.content.insert.app-document=Publishes generated social outbox snapshots without local source-path authority.
permissions.rationale.queue.write=Creates generated social outbox publication inserts.
permissions.rationale.queue.read=Displays safe upload queue summaries.
permissions.rationale.app.data.read=Restores bounded sources, imported-message summaries, channel filters, message read-state-derived thread actions, outbox summaries, and explicit drafts.
permissions.rationale.app.data.write=Saves bounded Social Inbox RC state without private insert URIs, raw fetched documents, or private identity material.
permissions.rationale.app.services.read=Discovers local app-service descriptors and caller-visible grant state.
permissions.rationale.app.services.call=Requests and invokes an operator-approved Trust Graph score service grant.
services.requests=trust-score
service-request.trust-score.provider=trust-graph
service-request.trust-score.service=trust.score
service-request.trust-score.scopes=score.read
service-request.trust-score.contexts=message-author
service-request.trust-score.purpose=Annotate Social Inbox message authors using the local Trust Graph Local RC score service.
categories=social,identity,reference
review.status=reviewed
review.note=First-party Social Inbox RC reference app; local threading and Trust Graph annotations only, not full WoT, plugin compatibility, Freetalk/Sone/Freemail, encrypted mail, crawler, or daemon-core protocol.
api.minimumVersion=16
api.maximumTestedVersion=16
api.experimentalCapabilitiesAccepted=true
```

Trust Graph Preview descriptors should include trust, vault, content-fetch, content-subscription,
generated-document publication, and redacted audit rationales, while making clear that the app is a
local durable preview and not full WoT or a moderation system:

```properties
permissions=trust.read,trust.write,content.fetch,content.subscribe,content.insert.app-document,queue.read,queue.write,vault.identities.read,vault.identities.create,vault.identities.use,app.data.read,app.data.write
permissions.rationale.trust.read=Reads local trust graph scores, evidence, and redacted audit entries for preview queries.
permissions.rationale.trust.write=Imports local trust statements and manages local trust anchors.
permissions.rationale.vault.identities.create=Creates an app-owned trust identity without exporting private material.
permissions.rationale.vault.identities.use=Uses the bounded trust-statement route to sign trust statements.
permissions.rationale.content.fetch=Fetches bounded Crypta trust documents selected by the user.
permissions.rationale.content.subscribe=Manages trust statement content subscriptions without global crawling.
permissions.rationale.content.insert.app-document=Publishes generated trust statements as Crypta content.
permissions.rationale.queue.write=Creates generated trust statement publication inserts.
permissions.rationale.queue.read=Displays publication progress from the local transfer queue.
permissions.rationale.app.data.read=Restores UI-local drafts, selected filters, and redacted import summaries.
permissions.rationale.app.data.write=Saves bounded UI-local preview state separately from the trust backend.
services.provides=trust-score
service.trust-score.id=trust.score
service.trust-score.name=Trust Score Service
service.trust-score.version=1
service.trust-score.kind=platform-adapter
service.trust-score.adapter=trust-graph.score
service.trust-score.scopes=score.read
service.trust-score.contexts=message-author,profile
service.trust-score.description=Returns a bounded local RC Trust Graph score summary for an app-provided public subject.
categories=identity,trust,preview
channel=beta
support.status=experimental
deprecation.status=none
review.status=reviewed
review.note=First-party local trust graph preview; not full WoT or moderation.
api.minimumVersion=10
api.maximumTestedVersion=16
api.experimentalCapabilitiesAccepted=true
```

Create, sign, and verify the catalog with the existing CLI:

```bash
platform-devtools/build/install/crypta-app/bin/crypta-app catalog create \
  --catalog-file build/first-party-beta-catalog/cryptad-app-catalog.properties \
  --catalog-id crypta-first-party-beta \
  --name "Crypta First-Party Beta Catalog" \
  --generated-at 2026-05-13T00:00:00Z \
  --entry build/first-party-beta-catalog/queue-manager.properties \
  --entry build/first-party-beta-catalog/publisher.properties \
  --entry build/first-party-beta-catalog/site-publisher.properties \
  --entry build/first-party-beta-catalog/profile-publisher.properties \
  --entry build/first-party-beta-catalog/social-inbox.properties \
  --entry build/first-party-beta-catalog/feed-reader.properties \
  --entry build/first-party-beta-catalog/trust-graph.properties \
  --overwrite

platform-devtools/build/install/crypta-app/bin/crypta-app catalog sign \
  --catalog-file build/first-party-beta-catalog/cryptad-app-catalog.properties \
  --key-id crypta-first-party-beta \
  --private-key-file /abs/path/outside/repo/catalog-signing-private.pem

platform-devtools/build/install/crypta-app/bin/crypta-app catalog verify \
  --catalog-file build/first-party-beta-catalog/cryptad-app-catalog.properties \
  --trusted-key-id crypta-first-party-beta \
  --trusted-public-key-file /abs/path/outside/repo/catalog-signing-public.pem
```

Validate the release publication plan first:

```bash
platform-devtools/build/install/crypta-app/bin/crypta-app publish-usk --dry-run \
  --catalog-file build/first-party-beta-catalog/cryptad-app-catalog.properties \
  --catalog-signature-file build/first-party-beta-catalog/cryptad-app-catalog.signature \
  --catalog-source "crypta:USK@.../cryptad-app-catalog.properties" \
  --output build/first-party-beta-catalog/publication-plan.md
```

Publish `cryptad-app-catalog.properties` and `cryptad-app-catalog.signature` to the public live USK
catalog location with explicit live mode:

```bash
platform-devtools/build/install/crypta-app/bin/crypta-app publish-usk --live \
  --catalog-file build/first-party-beta-catalog/cryptad-app-catalog.properties \
  --catalog-signature-file build/first-party-beta-catalog/cryptad-app-catalog.signature \
  --catalog-source "crypta:USK@.../cryptad-app-catalog.properties" \
  --private-insert-uri-env CRYPTAD_FIRST_PARTY_CATALOG_INSERT_URI \
  --node-base-url http://127.0.0.1:8888/api/v1 \
  --form-password-env CRYPTAD_CERT_FORM_PASSWORD \
  --trusted-key-id crypta-first-party-beta \
  --trusted-public-key-file "$CRYPTAD_CATALOG_SIGNING_PUBLIC_KEY_FILE" \
  --output build/first-party-beta-catalog/live-publication-summary.json
```

The public catalog source is a USK whose latest edition keeps the same sibling sidecar names. The
operator-facing source becomes:

```text
crypta:USK@.../cryptad-app-catalog.properties
```

The signature sidecar is `cryptad-app-catalog.signature` at the same USK path and edition. Signed
catalog verification remains mandatory; live publication only changes the transport location for
the signed sidecars. Bundle artifacts in catalog entries should remain immutable
`crypta:CHK@...` ZIP URIs with declared size and SHA-256 values.

The live queue endpoint registers a disk-backed directory insert. The private insert URI must be the
matching private USK directory insert URI for the configured public source parent. For example,
`crypta:USK@PUBLIC.../catalog/42/cryptad-app-catalog.properties` is inserted from the secure
private USK root for the same `catalog/42` parent path, supplied only through the env/file option.
`crypta-app publish-usk --live` leaves the staged public catalog and signature sidecars in place
until the queued insert has finished consuming them; the sanitized summary records only a path-free
retention warning. With `--verify-live-fetch`, the CLI fetches both sidecars from the public source
and verifies that the currently fetched bytes match the signed local files, but it still retains the
staged directory because an identical pre-existing public edition does not prove that the new queued
insert has consumed its source files.

Generated ZIPs, descriptors, signed catalog files, and release working files belong under `build/`
or `dist/`. Do not check generated signed production catalogs, private signing keys, reviewer
private keys, private insert URIs, form passwords, tokens, raw request bodies, or raw catalog
private insertion material into the repository or uploaded release artifacts.

## Certification evidence

Release certification records `catalog.live-usk-publication`,
`catalog.live-usk-source-verification`, `app-update.live-catalog-refresh`,
`app-catalog.first-party-beta`, plus app-review governance evidence such as
`app-review.governance`, `app-review.reviewer-key-lifecycle`,
`app-review.transparency-log`, `app-review.review-history-api`, and
`app-review.first-party-review-chain`. The evidence is deterministic and offline: it checks for the
recommended descriptor, live USK publication code path, sibling signature verification for resolved
USK editions, scheduler catalog refresh before candidate discovery, API/Web Shell onboarding,
Crypta CHK artifact transport tests, first-party metadata documentation, governed reviewer-key
parsing, transparency-log verification, review-history routing, and whether the certification
environment has source and key hints configured. Profile Publisher is also covered by
`reference-app.profile-publisher`, `app-platform.identity-profile-publish`, and
`app-platform.generated-document-insert`. Social Inbox RC is covered by
`app-platform.social-message-signing`, `reference-app.social-inbox`,
`reference-app.social-inbox-signed-message`, `reference-app.social-inbox-subscriptions`,
`reference-app.social-inbox-app-data`, `reference-app.social-inbox-trust-annotations`,
`reference-app.social-inbox-service-grant`, `reference-app.social-inbox-rc-threading`, and
`migration.social-mail-preview`. Feed Reader is
covered by `reference-app.feed-reader`,
`reference-app.feed-reader-subscriptions`, `app-platform.content-fetch`,
`app-platform.content-subscriptions`, and `network-content.subscription-scheduler`. Trust Graph
Preview is covered by `reference-app.trust-graph`, `app-platform.trust-graph-preview`,
`app-platform.trust-statement-signing`, `app-services.registry`, `app-services.grants`,
`app-services.trust-score-provider`, `app-services.web-shell`, and `app-services.redaction`.
Normal certification must not record tokens, form passwords, private insert URIs, raw request
bodies, raw feed bodies, raw social message bodies, raw fetched social documents, raw trust
statement bodies from real users, raw app-service subject URIs, provider app data, private keys,
raw public key bytes, raw receipt signatures, transparency-log paths, or absolute staging paths.
It does not fetch a public Crypta network catalog during normal unit tests.

## Related docs

- [app-platform-developer-portal.md](app-platform-developer-portal.md) is the app ecosystem beta
  entry point.
- [app-platform-beta-tutorials.md](app-platform-beta-tutorials.md) gives offline developer flows
  for template, signing, catalog, and dry-run publication work.
- [app-platform-beta-known-limitations.md](app-platform-beta-known-limitations.md) records beta
  safety boundaries.
- [app-platform-beta-program.md](app-platform-beta-program.md) covers app submission, feedback, and
  release closeout.
- [app-catalogs.md](app-catalogs.md) documents signed catalog formats and runtime install/update.
- [app-dev-cli.md](app-dev-cli.md) documents the standalone `crypta-app` CLI.
- [app-review-governance.md](app-review-governance.md) documents review receipts, reviewer keys,
  and the local transparency log.
- [app-update-lifecycle.md](app-update-lifecycle.md) documents candidate detection, scheduler
  policy, manual apply, and rollback scope.
- [release-certification.md](release-certification.md) documents release-candidate evidence and
  the ecosystem certification matrix.
- [SECURITY.md](SECURITY.md) documents security reporting and sensitive data handling.
