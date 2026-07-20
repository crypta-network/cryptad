# Catalog operations and mirrors

This guide describes the production operating model for signed app catalog sources. It covers
primary sources, mirrors, fallback refresh, verified revision history, explicit rollback,
catalog signing key rotation status, emergency advisory refresh, and release-certification
evidence.

Public-beta users should start with [public-beta/catalogs-and-apps.md](public-beta/catalogs-and-apps.md)
for channel, mirror, health, signature, advisory, denylist, and rollback concepts. This page
defines the operator route and release-certification details.

## Scope

Catalog operations are transport and operator-recovery features for signed catalogs. They do not
change the trust model: the signed `cryptad-app-catalog.properties` bytes and matching
`cryptad-app-catalog.signature` sidecar must verify against a trusted catalog signing key before a
catalog can replace the active revision. A mirror is only a transport fallback. It is never a
trust authority.

This workflow does not install, update, uninstall, or roll back apps automatically. It changes only
which verified catalog revision is active for catalog listing, candidate discovery, security
advisory visibility, and later explicit install/update decisions.

## Source model

Each configured catalog now has a primary source plus mirrors:

- The primary source is the operator-configured source from the original catalog add flow.
- Mirrors are additional enabled or disabled sources with a stable path-safe id and priority.
- Existing single-source catalogs load as a primary source with no mirrors, so operators do not
  need to re-add catalogs after upgrade.
- The active source records which endpoint last produced the active verified revision.

The source store keeps the legacy `catalog-source.properties` sidecar for compatibility and adds
bounded endpoint and health sidecars. Operator-facing API and Web Shell views expose ids, roles,
priorities, enabled state, last-attempt status, last success time, bounded error code/message,
catalog digest, generated time, signing key id, and redacted source display strings.

Do not configure private insert URI values as catalog sources. Public `crypta:` fetch keys,
`https:` URLs, loopback development URLs, and explicitly accepted local file sources remain the
only supported source forms. API and Web Shell output must not expose private insert URIs, private
keys, tokens, raw catalog content, raw app data, scratch paths, staged paths, or an absolute local
path.

## Refresh and fallback

Refresh tries the primary source first, then enabled mirrors in deterministic priority order. Every
candidate fetched from any endpoint must pass the same checks:

1. source URI validation;
2. catalog sidecar fetch and sibling signature fetch;
3. catalog signature verification with the trusted catalog-key registry;
4. catalog parser validation;
5. catalog id match with the configured source;
6. security advisory and denylist parser validation;
7. catalog digest and revision metadata calculation;
8. stale and downgrade policy.

Mirror fallback never weakens signed-catalog verification. A mirror cannot bypass a signature
check, change the catalog id, use an unknown or revoked signing key, or replace the current catalog
with stale bytes.

When the primary fails and a mirror returns the same or a newer verified revision, Cryptad accepts
the mirror result and records `fallbackUsed=true`. When a mirror returns an older generated time
than the active revision, Cryptad keeps the active catalog and marks the mirror stale. If revision
ordering is ambiguous in future catalog schemas, the safe behavior is to keep the current catalog
and require operator review instead of silently replacing it.

## Revision history

Every successful verified refresh is retained in bounded revision history before it can be used for
rollback. The store keeps the signed catalog bytes, signature sidecar, and revision metadata under
the catalog source directory. Metadata includes the revision digest, catalog id, generated time,
verified time, source role/id, redacted resolved source, signing key id, app count, advisory count,
denylist count, channel set, current flag, and rollback eligibility.

History is bounded to the latest retained revisions and always preserves the current revision.
History entries are support-safe metadata plus signed sidecars; they must not contain local scratch
paths, staged bundle paths, private keys, private insert URI values, raw app data, or tokens.

## Explicit rollback

Rollback is an operator action against a selected verified revision digest. It is intentionally
separate from ordinary refresh:

1. The operator lists rollback candidates through Platform API or Web Shell.
2. The operator selects one digest and supplies a bounded reason.
3. Cryptad re-verifies the stored catalog and signature against the current trusted catalog-key
   policy.
4. Cryptad rejects unknown, untrusted, or revoked signing keys and catalog id mismatches.
5. Cryptad records the current revision in history and replaces the active catalog sidecars with
   the selected verified revision.

The selected rollback target must precede the active catalog revision and bind different signed
catalog bytes. A same-revision, newer-revision, or same-digest target is not rollback evidence and
must fail release verification.

Rollback does not uninstall apps, change app data, bypass advisories, bypass denylists, or change
app-update policy. Installed apps remain under the normal AppHost and app-update rollback rules.

## Key rotation status

Catalog operations expose key-rotation status without storing or displaying private key material.
The status includes the current catalog signature key id, whether that key is trusted locally, an
optional next key id, optional rotation start/end timestamps, a planned/active/complete/blocked
state, and bounded blocker reasons such as `next_key_not_trusted`,
`current_key_revoked`, or `catalog_signature_untrusted`.

The status is derived from verified catalog metadata and local trusted-key policy. Release
certification verifies that key-rotation status is visible and redacted; it does not require real
production signing keys in the repository or in local test fixtures.

## Emergency advisory refresh

Emergency advisory refresh is an explicit operator action for security advisory and denylist
propagation. It uses the same primary-then-mirror refresh order and the same fail-closed signature,
catalog-id, parser, and stale-revision checks as ordinary refresh.

The emergency response records `emergency=true` style audit metadata, the active source id,
fallback state, revision digest, advisory ids added, denylist-entry delta, last attempt time, and
`redacted=true`. It does not install apps, update apps, uninstall apps, apply bundles, or fetch raw
app data. Update schedulers and security decisions see only the newly verified catalog data after
the signed refresh succeeds.

Use this action when an advisory or denylist must propagate faster than the normal background
refresh cadence. If the emergency candidate is signed by an unknown key, has a mismatched catalog
id, is malformed, or is older than the active revision, the active catalog remains unchanged.

## Platform API

Catalog operation routes are host/operator-only routes in Platform API v1. They are additive and
do not remove the legacy catalog fields such as `source`, `lastFetchStatus`, `lastResolvedUri`,
and `signatureKeyId`.

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

Read routes require catalog read authority. Mirror mutation, refresh, emergency refresh, and
rollback require catalog management authority. Responses include redacted display fields for
sources and resolved locations; clients must treat the legacy raw fields as compatibility fields
and prefer the redacted display fields for UI.

## Web Shell operations

The Web Shell Apps/Catalogs section surfaces source health, primary status, mirror status,
fallback warnings, the active source, revision digest, generated time, signing key id,
key-rotation status, rollback candidates, a guarded rollback form, refresh-primary, and emergency
advisory refresh controls.

The UI must not render private insert URI values, private keys, bearer/session/app tokens, raw
catalog bytes, raw signature bytes, raw fetched content, raw app data, scratch paths, staged paths,
or absolute local paths. File-backed sources are shown through redacted display strings.

## Release certification

Release certification includes deterministic `catalog.operations-and-mirrors` evidence. The
evidence is source-level and fixture-level; it does not require a live network catalog fetch,
production signing keys, or production mirror infrastructure.

The evidence checks that:

- the primary source plus mirrors model is present and backward compatible;
- mirror fallback keeps signed verification as the trust boundary;
- stale or downgrade mirror responses cannot silently replace the active catalog;
- verified revision history and explicit rollback re-verification are present;
- key-rotation status and emergency advisory refresh are visible;
- Platform API and Web Shell operations are wired;
- tests cover fallback, rollback, key rotation, emergency refresh, and redaction;
- docs cover mirror operations, rollback, key rotation, emergency advisory refresh, and privacy
  constraints.

Production beta release artifacts must remain redacted. The certification row may report counts,
statuses, ids, route names, booleans, digests, and bounded error codes, but it must not include
private insert URI values, private keys, tokens, raw content, raw app data, scratch paths, staged
paths, or absolute local paths.

## Stable GA publication

The Stable RC freeze binds the exact signed stable catalog bytes, signature sidecar, catalog id,
revision, generated timestamp, signing key id, first-party app entries, bundle/review digests,
rollback revision, and accepted exception history. Stable GA publishes or confirms those same
bytes; it does not rewrite the catalog, change an artifact URL, advance the revision, or re-sign a
bundle between RC selection and promotion.

The protected GA publication plan names one canonical public primary and distinct canonical public
mirrors. Before any tag or Release mutation, the workflow resolves each target to public addresses,
pins the fetch to the validated address set, and verifies that the current catalog, signature, and
rollback revision already match the authorized digests. It repeats the fetch after publication.
A stale mirror, duplicate location, missing sidecar, wrong rollback revision, untrusted signature,
or byte mismatch produces `publication-verification-failed`.

The redaction-safe publication receipt records public location ids/URIs and verification results.
It never records private insert URIs, credentials, authorization headers, raw catalog content,
private signing material, or runner-local paths. See
[Stable 1.0 RC validation and GA promotion](stable-1.0-rc-validation-and-ga-promotion.md).

## Maintenance publication and recovery

The Stable maintenance publication plan binds the exact signed catalog bytes, revision, primary,
mirrors, rollback state, and trust-transition evidence to the frozen candidate. A matching public
state is idempotent success only after every location is independently verified. A downgrade,
untrusted signature, stale mirror, partial conflict, or unavailable observation blocks completion;
the workflow does not overwrite or delete conflicting public state.

The catalog properties and detached signature are separate frozen and published assets. Protected
verification supplies both exact files and the candidate's independently declared signing-key id
to `crypta-app catalog verify`; a valid signature from another key in the trusted registry is not
an identity match. If the catalog bytes, signature bytes, or signing-key id changes, the edition or
revision must advance. Equal counters are allowed only when all three identities are unchanged.

Catalog publication and the package-based CoreUpdater descriptor remain separate protected
mutations with separate receipts. See the [Stable 1.0 maintenance release and security hotfix
path](stable-1.0-maintenance-release-and-hotfix-path.md).
