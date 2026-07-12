# Production security response runbook

This runbook defines the production beta response process for compromised or vulnerable app
catalogs, app versions, app signing keys, catalog signing keys, reviewer keys, review receipts, and
support artifacts.

## Scope

This is an app ecosystem response workflow. It uses signed app catalogs, catalog v4 security
advisory records, exact app-version denylists, local reviewer-key governance, review receipt
revocation, app-update gates, Web Shell warnings, operator RC recovery, support bundle redaction,
and release certification.

It does not add global moderation, network protocol changes, in-core plugin governance, automatic
uninstall, a peer-to-peer advisory crawler, or a real external incident-management system. FProxy
browse and emergency support surfaces remain retained according to the Phase 10 legacy-admin
retirement policy.

## Required artifacts

Every production security response uses these bounded artifacts:

| Artifact | Purpose | Privacy rule |
| --- | --- | --- |
| Advisory record | Signed catalog lifecycle, severity, action, timestamps, and operator guidance. | Include only bounded title, summary, advisory id, safe URI, app ids, versions, and timestamps. |
| Denylist entry | Exact app-version block for install, update, stage, apply, and scheduler policy. | Include exact app id/version and bounded reason text. |
| Reviewer registry update | Revoked reviewer key or exact receipt revocation. | Include key ids, receipt fingerprints, digests, timestamps, and bounded reasons only. |
| Emergency catalog candidate | Replacement metadata plus advisory and denylist state. | Sign with approved test or production process; do not publish private keys. |
| Operator status summary | Compact Web Shell and Platform API status. | Do not expose raw catalog bytes, local paths, staged bundle paths, tokens, or raw evidence JSON. |
| Support bundle | Redacted operator support context. | Use the [privacy-preserving beta diagnostics](privacy-preserving-beta-diagnostics.md) schema. Exclude private insert URIs, private keys, bearer/session/app tokens, raw fetched content, raw app data, raw request bodies, raw signatures, command lines, local absolute paths, and legacy plaintext diagnostics bodies. |
| Security release notes | Public communication for operators and packagers. | Credit reporters without private contact details or sensitive reproduction material. |
| Certification evidence | Deterministic proof that the response flow is executable. | Store only path-free, token-free, bounded summaries. |

Use [docs/templates/security-release-notes.md](templates/security-release-notes.md) for release
communication and
[`tools/release-certification/production-security-response-runbook.json`](../tools/release-certification/production-security-response-runbook.json)
for deterministic drill coverage.

## Advisory lifecycle

Catalog v4 security policy supports lifecycle status, severity, action, exact denylist records,
replacement guidance, safe uninstall/update guidance, advisory references, publication timestamps,
and updated timestamps. Production responses use these stable states:

| State | Use |
| --- | --- |
| `draft` | Internal prepared response. Do not publish in production catalogs. |
| `detected` | Triage confirmed the signal, but public details are not ready. Do not publish unless a bounded public holding advisory is intentional. |
| `active` or `published` | The advisory is current and can produce warning or blocking decisions. |
| `superseded` | A later advisory replaces this record. Keep it visible for history and link the successor in release notes. |
| `resolved` | The unsafe version is no longer distributed, but history remains useful. |
| `withdrawn` or `retracted` | The advisory was removed or corrected. Keep the correction visible and remove stale denylists only after verification. |

Only active or published advisory records should create warning or blocking decisions by themselves.
Exact denylist entries remain enforceable while they are present in a signed catalog, even when the
referenced advisory is later resolved or retracted for history.

## Common response sequence

1. Freeze the affected catalog candidate, app bundle, reviewer registry, or trusted key change.
2. Assign a synthetic advisory id, severity, affected app id/version, and response owner.
3. Collect evidence as hashes, fingerprints, bounded summaries, timestamps, receipt ids, reviewer
   key ids, catalog key ids, and affected exact versions.
4. Decide containment: denylist exact versions, block updates, warn with acknowledgement, revoke a
   receipt, revoke a reviewer key, rotate a catalog signing key, publish replacement metadata, or
   combine those actions.
5. Generate a dry-run emergency catalog candidate and reviewer registry change when applicable.
6. Verify signatures, advisory enforcement, denylist behavior, review trust failure, update
   scheduler behavior, Web Shell warning text, privacy-preserving support-bundle redaction, and
   release notes.
7. Publish the signed catalog or registry update through the approved channel.
8. Monitor operator-facing status and update the advisory lifecycle after remediation.

The process must fail closed for unknown catalog signing keys, untrusted catalog signatures,
denylisted app versions, revoked reviewer keys, revoked receipts, stale acknowledgements, and
malformed advisory or denylist records.

## Incident playbooks

### Vulnerable app version

| Step | Requirement |
| --- | --- |
| Trigger signals | Maintainer report, reviewer finding, crash/security test, operator report, or release certification drill. |
| Required evidence | Advisory id, app id, exact version, bundle digest, affected capability, severity, bounded impact summary, reporter contact class, and timestamps. |
| Immediate containment | Stop promotion of the affected version and create an exact denylist entry. |
| Catalog/advisory/denylist actions | Add an active or published advisory with `warn`, `block_update`, or `denylist`; add `catalog.securityDenylist.<id>` for exact unsafe versions. |
| Review/reviewer/revocation actions | Revoke the receipt only if the review evidence was wrong or no longer acceptable; otherwise keep the reviewer key active. |
| App update scheduler expected behavior | Skip staging and automatic apply when the target or installed version is denylisted or blocks automatic apply. |
| Web Shell/operator UX expected behavior | Show the active advisory, severity, denylist state, replacement guidance, and safe uninstall/update action labels. |
| Recovery guidance | Prefer update to the reviewed replacement. If no replacement exists, export app data before uninstall when the advisory says state may be useful. |
| Redaction requirements | Do not include raw exploit payloads, raw fetched content, raw app data, private insert URIs, tokens, or local paths. |
| Release note fields | Advisory id, app id/version, severity, impact, containment status, replacement version, update/uninstall guidance, support bundle note, and credits. |
| Verification steps | Parse and write the catalog, verify the signed catalog, confirm install/update/stage/apply reject the exact version, confirm Web Shell warnings, and run redaction checks. |
| Rollback or follow-up | Move advisory to `resolved` after replacement is widely available; keep denylist until the release manager removes it deliberately. |

### Malicious or compromised app version

| Step | Requirement |
| --- | --- |
| Trigger signals | Review rejection, suspicious bundle digest, maintainer compromise, operator report, or source mismatch. |
| Required evidence | App id, exact version, bundle digest, signing key fingerprint when available, review status, and bounded behavior summary. |
| Immediate containment | Remove the catalog entry from the candidate catalog and add an exact denylist entry for published catalogs. |
| Catalog/advisory/denylist actions | Publish a critical active advisory and denylist every known malicious exact version. |
| Review/reviewer/revocation actions | Revoke any positive receipt for the malicious bundle and record a transparency event when the local log is configured. |
| App update scheduler expected behavior | Treat the version as ineligible for staging or automatic apply. |
| Web Shell/operator UX expected behavior | Mark installed versions as vulnerable or denylisted and show replacement/uninstall guidance. |
| Recovery guidance | Stop the app, export only trusted app-owned data when safe, uninstall, and install a reviewed replacement only after verification. |
| Redaction requirements | Do not include raw malicious content, raw app data, raw command lines, or local filesystem paths. |
| Release note fields | Advisory id, affected bundle digest, severity, containment status, replacement status, and support instructions. |
| Verification steps | Confirm denylist status, receipt revocation status, update scheduler skip, Web Shell warning, and support bundle redaction. |
| Rollback or follow-up | Keep the denylist unless a later forensic review proves the version was not malicious. |

### App signing key compromise

| Step | Requirement |
| --- | --- |
| Trigger signals | Maintainer disclosure, unexpected signatures, leaked key report, repeated unknown artifacts, or release signing audit mismatch. |
| Required evidence | App id, compromised app signing key id or fingerprint, affected exact versions, trusted replacement key id, and replacement version. |
| Immediate containment | Stop publishing artifacts signed by the compromised key and denylist all affected exact versions. |
| Catalog/advisory/denylist actions | Add an active high or critical advisory, exact denylists, replacement app/version guidance, and safe uninstall guidance. |
| Review/reviewer/revocation actions | Revoke receipts that trusted artifacts signed by the compromised key if their evidence can no longer support the decision. |
| App update scheduler expected behavior | Reject compromised versions and stage only a verified replacement bundle signed by a trusted key and passing review policy. |
| Web Shell/operator UX expected behavior | Show compromised key response as bounded guidance; do not expose raw keys. |
| Recovery guidance | Update to the replacement app/version, or export data and uninstall if no replacement is available. |
| Redaction requirements | Never include private signing keys, key files, command lines, or absolute key paths. |
| Release note fields | Advisory id, app id, affected versions, signing key id or fingerprint, replacement key status, replacement version, and support guidance. |
| Verification steps | Confirm old versions are denied, replacement verifies, receipt state is unambiguous, and support bundles omit key material. |
| Rollback or follow-up | Retire the old key in maintainer docs and remove stale catalog entries after the replacement channel is healthy. |

### Reviewer key compromise

| Step | Requirement |
| --- | --- |
| Trigger signals | Reviewer disclosure, key exposure, impossible review sequence, local transparency mismatch, or audit finding. |
| Required evidence | Reviewer key id, revocation timestamp, bounded reason, affected receipt fingerprints, successor reviewer key id if available, and review policy id/version. |
| Immediate containment | Mark the reviewer key `status=revoked` in trusted reviewer registry v2/v3. |
| Catalog/advisory/denylist actions | Add or update advisories only for affected app versions; reviewer revocation alone is local governance. |
| Review/reviewer/revocation actions | Revoke exact receipt fingerprints when needed and ensure receipts signed by the revoked key fail as `revoked_reviewer`. |
| App update scheduler expected behavior | Treat candidates requiring trusted review as blocked when their only receipt is from the revoked key. |
| Web Shell/operator UX expected behavior | Show compact reviewer-key revoked status, receipt revocation counts, and review trust warnings without public key bytes. |
| Recovery guidance | Install or update only after a replacement trusted reviewer signs fresh receipts or policy is explicitly changed by the operator. |
| Redaction requirements | Exclude reviewer private keys, raw public key bytes, raw signatures, registry paths, and receipt bodies. |
| Release note fields | Advisory id when applicable, reviewer key id, compromise status, replacement reviewer key id, affected apps, and certification status. |
| Verification steps | Run reviewer-key lifecycle verification, verify revoked receipts fail closed, inspect Web Shell governance summary, and run redaction checks. |
| Rollback or follow-up | Do not reactivate a compromised reviewer key. Add a new trusted key with explicit validity bounds. |

### Review receipt revocation

| Step | Requirement |
| --- | --- |
| Trigger signals | Review correction, stale evidence, policy mismatch, compromised artifact, or false-positive review decision. |
| Required evidence | Receipt fingerprint, app id, version, bundle digest, reviewer key id, revoked timestamp, and bounded reason. |
| Immediate containment | Add a registry v3 `review.revocation.<id>` entry. |
| Catalog/advisory/denylist actions | Add catalog advisory or denylist only when the app version is unsafe, not merely because a receipt is corrected. |
| Review/reviewer/revocation actions | Verify the exact fingerprint fails as `revoked_receipt`; keep the reviewer key active unless the key is compromised. |
| App update scheduler expected behavior | Block trusted-review-required candidates when the matching receipt is revoked. |
| Web Shell/operator UX expected behavior | Show review trust status as revoked receipt and show bounded receipt metadata only. |
| Recovery guidance | Obtain a replacement receipt or use an explicit operator policy decision before install/update. |
| Redaction requirements | Do not expose raw receipt contents, raw signatures, evidence files, or local registry paths. |
| Release note fields | Receipt fingerprint, affected app/version, review policy, replacement receipt status, and support note. |
| Verification steps | Run receipt verification, review history API checks, Web Shell trust summary, and support redaction checks. |
| Rollback or follow-up | Supersede with a corrected receipt only after the original remains revoked for audit history. |

### Catalog signing key compromise or rotation

| Step | Requirement |
| --- | --- |
| Trigger signals | Catalog key exposure, planned rotation, unknown catalog signature, failed signature audit, or release-manager key rollover. |
| Required evidence | Old catalog signing key id, new catalog signing key id, rotation reason, effective timestamp, catalog id, and publication channel. |
| Immediate containment | Stop accepting new catalogs signed by the compromised key after the trust registry update; fail closed on unknown key ids. |
| Catalog/advisory/denylist actions | Publish emergency catalog metadata signed by the new trusted key after trust configuration is updated. |
| Review/reviewer/revocation actions | No receipt revocation is needed unless review evidence is also affected. |
| App update scheduler expected behavior | Refresh attempts signed by unknown, untrusted, or compromised catalog keys fail closed and do not create candidates. |
| Web Shell/operator UX expected behavior | Show catalog key id and rotation status as compact metadata. Do not show key material or key paths. |
| Recovery guidance | Operators update trusted catalog key configuration, then refresh the catalog and verify the signed candidate. |
| Redaction requirements | Exclude private catalog signing keys, public key bytes when not needed, trusted-key file paths, and command lines. |
| Release note fields | Catalog id, old key id, new key id, rotation reason, effective timestamp, verification behavior, and channel status. |
| Verification steps | Verify old signed candidate handling, new signed candidate verification, unknown-key fail-closed behavior, Web Shell summary, and release report key id. |
| Rollback or follow-up | Keep old key trusted only for the planned overlap window when it is a rotation, not a compromise. |

### Malicious catalog entry or catalog metadata compromise

| Step | Requirement |
| --- | --- |
| Trigger signals | Bad artifact URI/digest, metadata mismatch, unexpected permissions, malicious maintainer metadata, or compromised catalog publication. |
| Required evidence | Catalog id, entry app id/version, artifact digest, catalog signing key id, generated timestamp, and bounded mismatch summary. |
| Immediate containment | Remove the bad entry from the next signed catalog and add advisory/denylist if the app version was installable. |
| Catalog/advisory/denylist actions | Publish an emergency catalog with corrected metadata, denylisted exact app versions, and replacement guidance. |
| Review/reviewer/revocation actions | Revoke receipts only if they trusted the same malicious artifact or misleading metadata. |
| App update scheduler expected behavior | Reject candidates whose signed catalog decision blocks update or whose bundle digest/signature does not match. |
| Web Shell/operator UX expected behavior | Show catalog refresh status, signature key id, advisory/denylist summary, and safe actions. |
| Recovery guidance | Refresh catalog, update to replacement, or uninstall after export if no safe replacement exists. |
| Redaction requirements | Do not include raw catalog payloads, private sources, local cache paths, or fetched content. |
| Release note fields | Catalog id, affected entry, containment, replacement entry, catalog channel status, and verification status. |
| Verification steps | Parse and verify emergency catalog, confirm bad entry absent or denylisted, and run redaction/certification checks. |
| Rollback or follow-up | Supersede the advisory when corrected catalog metadata has propagated. |

### Emergency replacement app publication

| Step | Requirement |
| --- | --- |
| Trigger signals | Vulnerable or malicious version requires replacement faster than normal release cadence. |
| Required evidence | Replacement app id/version, bundle digest, signing key id, review receipt status, catalog channel, advisory id, and affected versions. |
| Immediate containment | Build and verify replacement bundle in dry-run mode before any live publication. |
| Catalog/advisory/denylist actions | Add replacement app/version metadata, denylist affected exact versions, and publish signed catalog candidate. |
| Review/reviewer/revocation actions | Produce fresh trusted review receipt or mark review status untrusted until review completes. |
| App update scheduler expected behavior | Discover the replacement only after signed catalog verification, review gates, compatibility gates, migration gates, and security gates pass. |
| Web Shell/operator UX expected behavior | Show replacement guidance, update action labels, and acknowledgement requirements. |
| Recovery guidance | Update when the replacement is reviewed; otherwise export and uninstall if containment requires removal. |
| Redaction requirements | Use test or production key references only; do not publish private keys or live private insert material. |
| Release note fields | Replacement version, review status, catalog channel, advisory id, containment, and support guidance. |
| Verification steps | Verify bundle signature, catalog signature, receipt trust, catalog install/update preview, scheduler behavior, and release certification evidence. |
| Rollback or follow-up | If replacement fails, remove it from the catalog and keep the denylist on affected versions. |

### Safe uninstall/update guidance

| Step | Requirement |
| --- | --- |
| Trigger signals | Advisory or denylist affects an installed app or blocked replacement path. |
| Required evidence | App id, installed version, installed security decision, app-data backup support status, replacement app/version, and operator risk summary. |
| Immediate containment | Prefer stop/update; if unsafe to keep installed, instruct export-before-uninstall. |
| Catalog/advisory/denylist actions | Keep `safeUninstallGuidance` and `replacementAppId` bounded and specific. |
| Review/reviewer/revocation actions | Require replacement review receipts when policy requires trusted review. |
| App update scheduler expected behavior | Do not auto-uninstall; do not auto-apply warning-level updates without explicit policy support. |
| Web Shell/operator UX expected behavior | Show safe uninstall, update, preserve-data uninstall, and support bundle labels without raw data. |
| Recovery guidance | Use Operator RC recovery for export-before-uninstall when app data exists; otherwise preserve data according to operator choice. |
| Redaction requirements | Support bundles must not contain backup payloads, raw app data, tokens, command lines, or local paths. |
| Release note fields | Installed app warning, update path, uninstall path, backup/export note, and support bundle guidance. |
| Verification steps | Check Web Shell labels, recovery action availability, support-bundle preview, and redaction output. |
| Rollback or follow-up | Confirm app-data preservation result and remove old guidance only after operators have a safe replacement. |

### Support bundle intake and redaction handling

| Step | Requirement |
| --- | --- |
| Trigger signals | Operator support request, failed emergency update, failed recovery action, reviewer/certification question, or post-incident audit. |
| Required evidence | Support reference digest, included sections, redaction status, omitted fields, incident category, affected app id/version, and bounded operator summary. |
| Immediate containment | Ask for a redacted support bundle preview first; request raw backups only through explicit sensitive-backup workflows when needed. |
| Catalog/advisory/denylist actions | None unless support evidence identifies a new affected version or catalog entry. |
| Review/reviewer/revocation actions | None unless support evidence identifies a receipt or reviewer-key problem. |
| App update scheduler expected behavior | No scheduler change from support intake alone. |
| Web Shell/operator UX expected behavior | Show redaction status, support guidance, and incident category without raw payloads. |
| Recovery guidance | Use typed recovery plans; do not accept arbitrary commands or paths as incident instructions. |
| Redaction requirements | Exclude private insert URIs, private keys, bearer tokens, browser/session tokens, app tokens, authorization headers, raw fetched content, raw app data, raw trust statements/signatures when not needed, command lines containing secrets, absolute local filesystem paths, and CI secret values. |
| Release note fields | Support bundle guidance, redaction note, credits, private reporter-data exclusion, and public-safe beta release notes linkage. |
| Verification steps | Run support redaction tests, production beta redaction scan, docs redaction scan, and release-certification redaction evidence. |
| Rollback or follow-up | Destroy raw intake artifacts that were not needed and keep only bounded summaries. |

## Emergency catalog update workflow

1. Create advisory and denylist records with fixed timestamps and exact affected versions.
2. Revoke reviewer receipt fingerprints or reviewer keys when evidence requires it.
3. Add replacement app/version metadata and review receipt references.
4. Regenerate the catalog candidate in dry-run or test-key mode.
5. Verify the catalog signature, catalog parser, advisory enforcement, exact denylist decisions,
   review trust state, update scheduler behavior, Web Shell warnings, and support redaction.
6. Use the catalog emergency advisory refresh action to pull the signed candidate through the
   configured primary source plus mirrors. Mirror transport fallback must not bypass catalog
   signature verification, trusted-key policy, catalog id checks, advisory parsing, or
   stale/downgrade protection.
7. Inspect Platform API or Web Shell source health for fallback warnings, active source id,
   advisory/denylist deltas, rollback candidates, and key-rotation status.
8. If the emergency catalog is bad but a previous verified revision remains safe, use explicit
   rollback to that digest after re-verification. Rollback does not uninstall apps, change app
   data, or bypass signed advisories and denylists.
9. Produce security release notes from [docs/templates/security-release-notes.md](templates/security-release-notes.md), and keep public beta support guidance aligned with [templates/beta-release-notes.md](templates/beta-release-notes.md) and [public-beta/support-and-feedback.md](public-beta/support-and-feedback.md).
10. Run `python3 tools/release-certification/certify.py security-response verify --manifest build/release-candidate.json`.
11. Generate the operational drill evidence. Use `release-candidate` for release-candidate
   certification, or `production-beta` when the summary will be attached to a protected
   production-beta pipeline run:
   ```bash
   python3 tools/release-certification/certify.py security-response drill-run-all \
     --manifest build/production-beta.json
   python3 tools/release-certification/certify.py security-response drill-verify-all \
     --manifest build/production-beta.json
   ```
12. Run `python3 tools/release-certification/certify.py app-platform --self-test`.
13. Run `python3 tools/release-certification/certify.py release-certification --self-test` before release
   candidate certification.
14. Publish only the signed emergency catalog and redacted release artifacts.

No production private key is required for deterministic tests. Fixture and dry-run artifacts use
synthetic ids, digests, and test keys only.

## Operational drill artifacts

The seven required production security scenarios are:

- `vulnerable-app-version`
- `app-signing-key-compromise`
- `reviewer-key-compromise`
- `catalog-signing-key-rotation`
- `malicious-catalog-entry`
- `emergency-replacement-app`
- `support-bundle-intake-redaction`

Each scenario generates a `kind=cryptad-security-response-drill`, `schemaVersion=2` JSON artifact.
The artifact records the scenario, release id, generated timestamp, severity, runbook scenario
digest, bounded verification evidence ids, per-step safe summaries, redacted release-note text, and
redaction metadata. It must not include private keys, private insert URIs, raw receipt signatures,
raw support bundle bodies, raw fetched content, raw app-data values, raw profile/feed/trust/social
documents, raw app-service bodies, nested backup material, tokens, or absolute local paths.

`drill run-all` writes one artifact per required scenario plus
`security-drills-summary.json`. The summary uses
`kind=cryptad-security-response-drills-summary`, reports `status`, `promotionReady`,
required/passed/failed/missing/stale scenario lists, artifact digests, release-notes template
status, advisory-template status, and the aggregate redaction result. Production beta promotion
requires this summary to be present, schema-valid, fresh, `promotionReady=true`, and free of
redaction findings. Missing scenarios, failed scenarios, stale artifacts, malformed envelopes,
fixture-only production drills, and redaction failures are production blockers. Redaction failures
are critical and non-waivable.

## Certification checklist

`production-security.response-runbook` passes only when release certification can prove:

- this runbook exists and covers the required incident scenarios;
- the deterministic drill model exists, validates, and has a fresh all-drills summary;
- advisory lifecycle, reviewer-key compromise, catalog signing key rotation, app signing key
  compromise, emergency catalog update, support redaction, release notes, Web Shell/API/operator
  status, and redaction boundaries are represented;
- catalog.operations-and-mirrors evidence covers mirror health, transport fallback, explicit
  rollback, key-rotation status, emergency advisory refresh, and redacted operator metadata;
- fixtures and docs contain no obvious private keys, private insert URIs, bearer/session/app
  tokens, raw fetched content, raw app data, local absolute paths, command lines with secrets, CI
  secret values, reporter private data, or raw support payloads.
