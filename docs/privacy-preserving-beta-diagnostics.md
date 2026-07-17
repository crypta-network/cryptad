# Privacy-Preserving Beta Diagnostics

Privacy-preserving beta diagnostics are the default support-bundle model for production beta
operator support. They turn the local operator dashboard, diagnostics, recovery, catalog, app
update, subscription, app-data, app-service, Trust Graph, Social Inbox, content-format, and release
gate state into a JSON support bundle that an operator can preview, download, or copy.

The bundle is generated locally. Cryptad does not upload it, send it to maintainers, open a support
ticket, or phone home. Operators decide whether to share the exported JSON.

Public-beta users should start with
[public-beta/support-and-feedback.md](public-beta/support-and-feedback.md),
[public-beta/security-reporting.md](public-beta/security-reporting.md), and
[public-beta/troubleshooting.md](public-beta/troubleshooting.md) before exporting support evidence.
This page defines the diagnostics schema, redaction expectations, support intake, and release
gates.

## Operator Workflow

The Web Shell exposes the workflow under the Operator RC Recovery panel:

1. Use **Generate support bundle** to build the local preview and support JSON.
2. Review the redaction status, digest, omitted-field count, warnings, and safe lifecycle
   summaries.
3. Use **Download support JSON** or **Copy support JSON** only after reviewing the result.

If redaction status is `fail`, the Web Shell disables copy and download for the default flow. A
production beta go/no-go decision treats that failure as non-waivable.

## Schema

Support bundles use `kind=cryptad-operator-support-bundle` and schema version `2`.

Top-level fields are intentionally small and stable enough for support tooling:

| Field | Meaning |
| --- | --- |
| `kind` | Always `cryptad-operator-support-bundle`. |
| `schemaVersion` | Current support-bundle schema version. PR-277 uses version `2`. |
| `generatedAt` / `createdAt` | Bounded UTC timestamps with second precision. |
| `generatedAtEpochMillis` | Existing millisecond dashboard timestamp retained for compatibility. |
| `nodeSummary` | Safe local version/build/platform metadata only. |
| `releaseSummary` | Release id, channel, and Platform API contract version when known. |
| `privacy` | Boolean promises that raw content, raw app data, private insert URIs, tokens, identity material, and local paths are not included. |
| `redaction` | Redaction status, checked pattern labels, omitted field names/count, findings, and local-only marker. |
| `sections` | Safe lifecycle summaries by domain. |
| `dashboard` | Redacted operator dashboard summary. |
| `diagnostics` | Safe diagnostics summary; no raw lines or plaintext export. |
| `recentAppServiceAudit` | Redacted app-service audit metadata. |
| `legacyAdmin` | Redacted legacy-admin counters if available. |
| `warnings` | Operator-facing warnings about review and privacy boundaries. |
| `supportDigest` | `SHA-256` digest of the redacted bundle before the digest field is added. |

The schema can add fields in later versions. Support tooling should ignore unknown fields and
should treat missing required privacy/redaction fields as a blocker for production beta intake.

## Included Data

Default bundles include safe metadata useful for debugging beta issues:

- category and status for catalog, app update, subscriptions, app data, app-service grants,
  consent, migrations, sandbox, content formats, Trust Graph, Social Inbox, recovery,
  diagnostics, legacy fallbacks, and release certification;
- bounded counts, warning counts, failure counts, status labels, and last safe error codes;
- safe app ids, catalog ids, service ids, evidence ids, recovery action ids, capability names, and
  route names;
- source digests when a source URI or path would otherwise be sensitive;
- booleans that state which raw material was excluded;
- redaction metadata, omitted field names, and the support-bundle digest.

These summaries are meant to answer questions such as:

- which catalog is failing or missing a first-party recommendation;
- whether a catalog mirror, signature, rollback candidate, or security decision is unhealthy;
- whether an app update is pending, staged, blocked by review/security/permission changes, or
  rollback-ready;
- whether subscriptions are stuck, paused, backing off, or under queue pressure;
- whether app-service grants are pending, revoked, stale, or missing provider dependencies;
- whether consent, migration, sandbox, Trust Graph, Social Inbox, or content-format validation
  failures are present;
- whether release certification or go/no-go evidence reports a redaction failure.

## Never Included

Default support bundles must not include:

- raw content documents, raw fetched content, raw feed snapshots, raw profile documents, raw Trust
  Graph statements, raw Social Inbox messages, raw social outboxes, canonical signature payloads,
  raw signatures paired with raw documents, or raw document bodies;
- raw app-data record keys or values, app-data backup payloads, nested backup archives, or
  app-data restore payloads;
- app-service invocation request or response bodies;
- private insert URIs, private keys, seed material, recovery phrases, vault identity material, or
  reviewer/app/catalog signing private material;
- OAuth/API tokens, bearer tokens, app process tokens, browser session tokens, cookies, form
  passwords, or operator recovery plan tokens;
- absolute Unix, macOS, Windows, UNC, or `file:` paths;
- legacy plaintext diagnostics export text, raw diagnostic section lines, raw node refs, raw peer
  details, raw request bodies, command lines, or raw command bodies.

The direct `/api/v1/diagnostics` route can still expose local diagnostics to the operator because it
is a local read-only diagnostics endpoint. The default support bundle does not embed its raw
`plainTextExport` or raw section lines. Legacy plaintext diagnostics remain an explicit emergency
or support fallback, not the normal export path.

## Redaction

Redaction is structural first. If a map field name is unsafe, the field is omitted rather than
string-replaced. This applies to fields such as raw profile documents, raw feed snapshots, raw Trust
Graph statements, raw Social Inbox messages, raw app-data values, app-service invocation bodies,
private insert URIs, private key material, identity material, backup payloads, cookies, tokens, and
paths.

String redaction is defense in depth for obvious sensitive fragments inside safe fields. It replaces
content URIs, private-key blocks, sensitive header values, sensitive query parameters, and absolute
paths with placeholders. Safe counters and booleans such as `rawAppDataExcluded=true` remain
allowed because they describe the absence of raw app data.

`redaction.status=pass` means the bundle was built through the support-bundle schema and redaction
pass. `redaction.status=fail` means the bundle must not be shared and blocks production beta
promotion.

## Lifecycle Summaries

The `sections` object is the main support surface. It contains safe summaries for:

- `catalog`
- `appUpdates`
- `subscriptions`
- `appData`
- `appServiceGrants`
- `consent`
- `migrations`
- `sandbox`
- `contentFormats`
- `trustGraph`
- `socialInbox`
- `recovery`
- `diagnostics`
- `legacyFallbacks`
- `releaseCertification`

Each section should use status, bounded count, safe ids, last error code, last safe status message,
redacted source digest, recovery action id, and digest fields where applicable. It must not use raw
source URIs, raw documents, raw app-data keys/values, raw app-service bodies, or raw diagnostics
bodies.

## Support Intake

Maintainers should ask operators for digest and summary fields first, not raw JSON in public
issues. Support requests should reference the `supportDigest`, release id/channel, schema version,
diagnostic summary id, known issue id when relevant, and specific section statuses instead of
asking for raw content or local files. The public feedback loop is defined in
[public-beta/support-and-feedback.md](public-beta/support-and-feedback.md).

Maintainers must not request raw profile documents, feed snapshots, Trust Graph statements, Social
Inbox messages, app-data backups, private insert URIs, tokens, private keys, identity material, or
absolute local paths through normal beta support. If an exceptional security investigation needs
more detail, handle it under the security response process, with explicit operator consent and a
case-specific privacy review.

## Release Gates

Release certification records deterministic evidence under
`app-platform.privacy-preserving-beta-diagnostics`. The production beta go/no-go dashboard exposes
the `privacy-preserving-diagnostics-risk` domain and ties it to:

- `app-platform.privacy-preserving-beta-diagnostics`
- `operator-beta.support-bundle-redaction`
- `operator-rc.support-bundle-wizard`
- `multi-node-beta.support-bundle-drill`

Redaction failures are production-critical and non-waivable. Missing schema, missing support-bundle
routes, raw diagnostics embedded in default bundles, unsafe fuzz fixtures, or default bundle exports
that include legacy plaintext diagnostics are no-go conditions.

The production security response drill set also treats `support-bundle-intake-redaction` as a
required production drill. Its artifact may include boolean redaction metadata, safe omitted-field
counts, digests, and fixture result names, but it must not include raw support bundle bodies, raw
diagnostic lines, raw app data, raw profile/feed/trust/social documents, raw app-service bodies,
nested backup material, private insert URIs, tokens, private keys, or local paths. A missing,
failed, stale, malformed, fixture-only production, or redaction-unsafe drill blocks production beta
promotion through the go/no-go dashboard.

Stable GA additionally requires support and diagnostics evidence generated after the selected
protected RC freeze and explicitly bound to its product, freeze, archive, and catalog digests. The
record must cover support-bundle generation after a deliberately failed upgrade or recovery and
must remain fresh through protected publication. Raw bundle content cannot be copied into GA
validation, release notes, provenance, the maintenance baseline, or the publication receipt.

## Limitations

The support bundle is not telemetry, crash-report upload, analytics, remote logging, or automatic
support intake. It does not prove that an operator has reviewed the JSON before sharing it. It also
does not replace release certification, live-network evidence, multi-node soak evidence, security
response drills, or the direct local diagnostics endpoint.
