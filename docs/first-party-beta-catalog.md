# First-party beta app catalog

This guide describes how Cryptad maintainers publish and operators onboard the first-party beta app
catalog.

## Scope

The first-party beta catalog is a signed catalog for the current first-party apps:
`queue-manager`, `publisher`, and `site-publisher`. It does not auto-install apps and does not
weaken any existing gates. Catalog signatures, bundle signatures, review receipts, artifact
SHA-256 checks, Platform API compatibility metadata, sandbox metadata, and permission review remain
separate layers.

The third-party developer beta toolkit extends the standalone CLI with scaffold templates, a mock
dev server, offline app tests, catalog entry generation, and a dry-run USK publication checklist.
It does not replace this first-party beta catalog flow or its release gates. See
[developer-beta-toolkit.md](developer-beta-toolkit.md) for the app-author workflow.

`crypta:` transport is not a trust boundary. Crypta-hosted catalog and bundle artifacts still must
match signed catalog metadata and signed bundle sidecars before AppHost can install or update them.

## Runtime configuration

Set the recommended catalog source and trusted key hint in runtime or packaging configuration:

| Setting | Environment variable | Example |
| --- | --- | --- |
| `cryptad.firstPartyCatalog.enabled` | `CRYPTAD_FIRST_PARTY_CATALOG_ENABLED` | `true` |
| `cryptad.firstPartyCatalog.id` | `CRYPTAD_FIRST_PARTY_CATALOG_ID` | `crypta-first-party-beta` |
| `cryptad.firstPartyCatalog.source` | `CRYPTAD_FIRST_PARTY_CATALOG_SOURCE` | `crypta:USK@.../cryptad-app-catalog.properties` |
| `cryptad.firstPartyCatalog.trustedCatalogKeyId` | `CRYPTAD_FIRST_PARTY_CATALOG_TRUSTED_KEY_ID` | `crypta-first-party-beta` |
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
tokens, browser session tokens, or form passwords in the repository or in release-certification
artifacts.

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
still inspect entries and confirm install/update actions per app.

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
api.maximumTestedVersion=4
review.status=reviewed
review.note=First-party beta review completed.
changelog.summary=First public beta catalog entry.
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

Publish `cryptad-app-catalog.properties` and `cryptad-app-catalog.signature` to the public Crypta
catalog location, usually a USK whose latest edition keeps the same sibling sidecar names. The
operator-facing source becomes:

```text
crypta:USK@.../cryptad-app-catalog.properties
```

Generated ZIPs, descriptors, signed catalog files, and release working files belong under `build/`
or `dist/`. Do not check generated signed production catalogs or private keys into the repository.

## Certification evidence

Release certification records `app-catalog.first-party-beta`. The evidence is deterministic and
offline: it checks for the recommended descriptor, API/Web Shell onboarding, Crypta CHK artifact
transport tests, first-party metadata documentation, and whether the certification environment has
source and key hints configured. It does not fetch a public Crypta network catalog during normal
unit tests.
