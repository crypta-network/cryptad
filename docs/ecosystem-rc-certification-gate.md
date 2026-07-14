# Ecosystem RC certification gate

The ecosystem RC gate is the strict release-candidate decision over compatibility, app-platform,
security, recovery, soak, documentation, legacy migration, and release-operation evidence.

## Run the gate

Copy the template, replace every placeholder, and run:

```bash
cp tools/release-certification/manifests/release-candidate.example.json \
  build/release-candidate.json
python3 tools/release-certification/certify.py release-certification \
  --manifest build/release-candidate.json
```

The gate writes its evidence envelope v2, report, redaction report, ecosystem matrix, history
comparison, and sanitized supporting artifacts under the candidate’s release workspace.

## Required behavior

The gate fails when required evidence is missing, skipped, malformed, stale, wrong-mode,
wrong-candidate, failing, or redaction-unsafe. Required coverage includes interop and performance,
Platform API compatibility, first-party apps and catalogs, review governance, app data and
services, reference apps, user consent, updates and rollback, sandbox enforcement, public-beta
security/support, network-scale and multi-node soak, previous-candidate upgrade, operator recovery,
legacy migration/retirement, dashboard readiness, and matrix completeness.

Network-scale and multi-node evidence must be generated for or explicitly attached to the current
workspace. Live-network evidence is mandatory only when required by the selected profile or
manifest.

## Waivers

Only policy-designated findings are waivable. Records require evidence ID, severity, scope,
rationale, approver, owner, references, and a future expiry. Waivers never suppress private
material, redaction failures, invalid candidate binding, malformed evidence, or policy-listed
non-waivable blockers.

## Redaction

The matrix and report expose digests, counts, statuses, and relative artifact references. They do
not expose signing material, form passwords, tokens, browser sessions, private insert URIs, raw
content, raw app data, raw trust/social/profile/feed documents, local paths, or private interop
artifacts.
