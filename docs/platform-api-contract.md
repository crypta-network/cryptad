# Platform API compatibility contract

The Platform API compatibility contract is the deterministic app-facing description of the current
Platform API v1 surface. It is separate from the URL version in `/api/v1/`: the URL version names
the transport route family, while the integer contract version is what app manifests, catalog
metadata, developer tooling, and release certification compare.

The current app-facing values are:

```text
apiVersion=v1
contractVersion=4
```

The contract does not change Platform API behavior. It publishes metadata that answers which
routes/actions exist, which manifest capabilities app principals need, and whether capabilities or
endpoints are stable, experimental, deprecated, scheduled for removal, or internal.

## Public snapshot

The current node exposes the contract at:

```text
GET /api/v1/platform/contract
```

Host/operator requests use the existing local-admin model. App process and browser principals can
read the endpoint only when their manifest grants:

```text
platform.contract.read
```

The response shape is:

```json
{
  "contract": {
    "apiVersion": "v1",
    "contractVersion": 4,
    "generatedBy": "cryptad",
    "stabilityPolicy": "...",
    "capabilities": [],
    "endpoints": []
  }
}
```

The snapshot is deterministic and excludes raw app process tokens, browser session tokens,
bootstrap nonces, form passwords, request bodies, query strings, filesystem paths, sandbox command
lines, environment variables, private keys, and private insert URIs.

## Descriptor fields

Capability descriptors contain:

- `name`
- `stability`
- `sinceContractVersion`
- optional `deprecation`
- short `description`

Endpoint descriptors contain:

- route family, HTTP method, and route template relative to `/api/v1`
- audit/authorization action label
- required manifest capabilities
- whether host/operator bypass is allowed through the existing local-admin model
- whether app process and app browser principals can call the route
- stability level, first contract version, optional deprecation/removal metadata, and description

The runtime app authorization path reads the same endpoint descriptors that the snapshot publishes,
so the contract and route-to-capability policy do not maintain separate route lists.

## Stability levels

| Stability | Meaning |
| --- | --- |
| `stable` | Covered by the current Platform API compatibility contract. |
| `experimental` | Available for explicit adopters, but may change in a later contract. |
| `deprecated` | Still callable, but app authors should migrate away. |
| `scheduled-for-removal` | Still callable now, with planned removal metadata. |
| `internal` | Not app-facing; developer tooling treats app use as an error. |

Contract version 2 adds the installed-app update lifecycle endpoints under
`/apps/{appId}/updates`. Contract version 3 adds the app vault and identity vault descriptors.
Contract version 4 adds the first-party catalog onboarding routes under
`/app-catalogs/recommended`. Existing version 1
capabilities and endpoints remain stable, and their descriptors keep `sinceContractVersion=1` so
tooling can distinguish old and newly introduced surface area.

The app secret and identity vault capability names are also part of the app permission vocabulary:
`vault.secrets.read`, `vault.secrets.write`, `vault.identities.read`,
`vault.identities.create`, `vault.identities.use`, and `vault.identities.manage`. They are
documented in [app-secret-and-identity-vault.md](app-secret-and-identity-vault.md). Developer
tooling recognizes those names for manifest validation and UI permission disclosure. Runtime route
authorization still depends on the endpoint descriptors exposed by the node's selected contract
snapshot.

Catalog-backed update lifecycle mutations preserve the catalog capability boundary for app
principals. App principals need `apps.manage` plus `catalogs.manage` for update `check`, `stage`,
and `apply` actions because those routes can refresh signed catalogs, prepare catalog install
plans, or apply catalog-staged bundles. Host/operator calls keep the existing local-management
bypass.

Recommended catalog onboarding follows the catalog capability boundary. Reading recommendations
requires `catalogs.read`; adding a recommendation through
`/app-catalogs/recommended/{catalogId}/add` requires `catalogs.manage` and still uses the verified
signed-catalog add path.

App-update summaries also include scheduler metadata for background catalog refresh and app update
checks. The scheduler fields are path-free and token-free: they expose enabled/status, last and
next check timestamps, result, failure count, sanitized error code, and a short message. The
scheduler does not add new app-facing routes and does not change the default `manual` update
policy.

## App manifest metadata

App manifests may declare optional API compatibility metadata:

```properties
api.minimumVersion=1
api.maximumTestedVersion=1
api.optionalCapabilities=alerts.read,diagnostics.read
api.experimentalCapabilitiesAccepted=false
```

Missing fields remain valid for old apps. `app.permissions` remains the authoritative capability
grant request; `api.optionalCapabilities` is advisory metadata for verification and review.

`api.minimumVersion` means the app expects at least that Platform API contract version.
`api.maximumTestedVersion` means the app was tested up to that contract version. A local node below
the minimum is incompatible. A local node above the maximum-tested version is a warning by default
and a failure in strict verification.

## Catalog metadata

Signed catalogs can mirror or summarize app API compatibility with optional entry fields:

```properties
app.<id>.api.minimumVersion=1
app.<id>.api.maximumTestedVersion=1
app.<id>.api.optionalCapabilities=alerts.read,diagnostics.read
app.<id>.api.experimentalCapabilitiesAccepted=false
```

Bundle manifest metadata remains authoritative for the app artifact. Catalog metadata is display
and review input. Developer tooling flags catalog-vs-bundle API metadata mismatches and permission
mismatches so catalog authors can fix them before signing. Old catalogs without API metadata still
parse and display an `unknown` advisory API compatibility status.

## Developer tooling

Create an offline snapshot:

```bash
crypta-app api snapshot --output build/platform-api-contract.json
```

Verify a staged bundle against the built-in current contract:

```bash
crypta-app compat verify --bundle-dir path/to/staged-app
```

Verify against an explicit target snapshot:

```bash
crypta-app compat verify \
  --bundle-dir path/to/staged-app \
  --contract build/platform-api-contract.json
```

Verify a catalog entry descriptor and referenced bundle:

```bash
crypta-app compat verify \
  --catalog-entry descriptor.properties \
  --contract build/platform-api-contract.json
```

`crypta-app validate --strict` also runs compatibility checks against the current contract.
Malformed `api.*` metadata is always a hard failure. Unknown future capability names,
experimental capability use without `api.experimentalCapabilitiesAccepted=true`, deprecated or
scheduled capabilities, a target above `api.maximumTestedVersion`, and catalog-vs-bundle metadata
mismatches are warnings by default and failures with `--strict`.

## Platform API and Web Shell display

Installed app summaries and catalog app summaries include an `apiCompatibility` object:

```json
{
  "minimumVersion": 1,
  "maximumTestedVersion": 2,
  "currentVersion": 2,
  "optionalCapabilities": [],
  "experimentalCapabilitiesAccepted": false,
  "declared": true,
  "status": "compatible",
  "warnings": []
}
```

Status values are `compatible`, `below_minimum`, `newer_than_tested`, `unknown`, and
`incompatible`. The Web Shell shows the status, current contract version, app minimum version,
maximum-tested version, optional capabilities, and warnings in app/catalog review cards.

## Release certification

`tools/release-certification/app_platform_smoke.py` now emits required
`platform-api.contract` evidence. It generates a contract snapshot with `crypta-app api snapshot`,
records descriptor counts and non-stable entries, and runs offline `crypta-app compat verify`
checks for first-party staged apps and the generated sample app.

In release-candidate mode, missing contract evidence, snapshot generation failure, descriptor
parse failure, or strict compatibility verifier failure blocks promotion unless an explicit
release-manager waiver is recorded in the aggregate certification report.
