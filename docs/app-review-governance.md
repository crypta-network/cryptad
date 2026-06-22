# App Review Governance

Crypta app review governance is local node policy for independent app review receipts. It does not
replace catalog signatures, bundle signatures, artifact digest checks, Platform API compatibility
checks, permission-delta handling, sandbox checks, update rollback gates, or operator approval
flows.

Review receipts are independent of catalog signatures and app bundle signatures:

- Catalog signatures authenticate catalog publisher metadata.
- Bundle signatures authenticate the signed app bundle.
- Review receipts authenticate review evidence from a locally trusted reviewer key.

A catalog publisher can include advisory review metadata, but advisory metadata is not trusted
review evidence unless a receipt verifies against the node-local trusted reviewer-key registry.

## Trusted Reviewer Registries

Registry version 1 remains supported. A v1 entry is treated as an active trusted reviewer key with
no explicit validity window:

```properties
trusted.reviewers.version=1
reviewer.1.id=crypta-first-party-review
reviewer.1.algorithm=Ed25519
reviewer.1.public.key.base64=<X.509 Ed25519 public key bytes>
reviewer.1.display.name=Crypta First-Party Review
reviewer.1.policy.id=crypta-app-review-v1
```

Registry version 2 is preferred for governed deployments because it records policy-version
constraints and key lifecycle state:

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

Reviewer private keys must never be committed, embedded in catalogs, exposed through Platform API,
printed by Web Shell, printed by `crypta-app`, or copied into release-certification reports. The
trusted reviewer registry stores public verification keys only. API, Web Shell, CLI inspection, and
certification evidence expose redacted summaries: key ids, display names, algorithms, lifecycle
status, policy constraints, validity bounds, and rotation ids.

Registry version 3 adds local review receipt revocation. Receipt revocation is distinct from
revoking a reviewer key. It identifies one exact receipt by `receiptFingerprintSha256`, which
covers the canonical payload and detached signature metadata/value:

```properties
trusted.reviewers.version=3
review.revocations=receipt-1
review.revocation.receipt-1.receiptFingerprintSha256=<sha256>
review.revocation.receipt-1.appId=social-inbox
review.revocation.receipt-1.appVersion=0.1.0
review.revocation.receipt-1.bundleSha256=<bundle-sha256>
review.revocation.receipt-1.reviewerKeyId=crypta-first-party-review-2026q2
review.revocation.receipt-1.revokedAt=2026-06-11T00:00:00Z
review.revocation.receipt-1.reason=Receipt revoked after advisory CRYPTA-2026-0001.
```

A revoked receipt evaluates as `revoked_receipt`. It must not be treated as `trusted_reviewed`,
`trusted_caution`, or `trusted_rejected`, and review policy treats it as fail-closed evidence.
See [ecosystem-security-advisories.md](ecosystem-security-advisories.md) for the full advisory and
revocation response process.
See [production-security-response-runbook.md](production-security-response-runbook.md) for the
production reviewer-key compromise drill, emergency receipt revocation checklist, operator UX
expectations, support redaction requirements, and certification evidence.

## Lifecycle Semantics

Reviewer key statuses are local governance state:

- `active`: receipts can be trusted when their `reviewedAt` timestamp is inside the configured
  validity window, if one is configured.
- `retired`: receipts can be trusted only as historical evidence when `reviewedAt` is inside the
  configured validity window. Receipts outside that window fail as `retired_reviewer`.
- `revoked`: receipts from the key fail closed as `revoked_reviewer`, including historical
  receipts. Revocation is distinct from `unknown_reviewer` so operators can see revoked-key
  evidence.

Validity timestamps are strict ISO-8601 instants. `valid.until` is treated as an exclusive boundary:
a receipt reviewed at or after that instant is outside the key window.

Rotation metadata (`rotates.from` and `rotates.to`) is informational. It helps operators audit key
lifecycle continuity, but it does not automatically trust a successor or predecessor key.

For reviewer-key compromise, mark the affected key `status=revoked`, set `revoked.at`, and add a
bounded `revocation.reason`. Receipts signed by that key remain fail-closed as `revoked_reviewer`;
operators can inspect the lifecycle warning without seeing raw public key bytes, private key
material, or raw signatures.

## Policy ID And Version

Review receipts carry `policy.id` and `policy.version`. A trusted reviewer-key registry entry can
constrain both fields:

- If only `policy.id` is configured, any receipt policy version for that policy id can verify.
- If both `policy.id` and `policy.version` are configured, both must match.
- A mismatch produces `review_policy_mismatch`, not `unknown_reviewer`.

This lets operators answer which review policy produced a receipt and whether the local registry
currently accepts that policy id/version for the reviewer key.

## Local Transparency Log

Crypta keeps a host-owned app review transparency log below the app-catalog store. The log is local
and tamper-evident, not a global public transparency log and not a distributed consensus service.

The log stores redacted review governance events such as receipt observation, trust evaluation,
install/update review gates, policy apply gates, reviewer-key lifecycle events, and hash-chain
verification. Each record includes a sequence, previous record hash, and record hash over canonical
fields. The verifier recomputes the chain and reports sequence gaps or hash mismatches.

The transparency log must not contain secrets, local filesystem paths, app browser sessions, AppHost
process tokens, private keys, raw public key bytes, raw receipt signatures, form passwords, request
bodies, or raw exception traces.

Third-party submission review adds these local event kinds:

- `submission_created`
- `pre_review_completed`
- `review_decision_recorded`
- `review_receipt_issued`
- `submission_rejected`
- `submission_resubmitted`
- `catalog_candidate_created`

The events carry submission ids, app ids, versions, bundle digests, reviewer key ids, policy ids,
receipt status values, evidence digests, and short warnings only. They do not carry raw submission
packages, rationale bodies, private insert URIs, local paths, or receipt signatures.

## Third-party Submission Decisions

The app-store submission workflow supports `submitted`, `pre_review_passed`, `reviewed`, `caution`,
`rejected`, and `resubmitted` states. These states are catalog/display metadata until an independent
review receipt verifies against local trusted reviewer keys.

Use `crypta-app submission pre-review` before recording a decision. Reviewed and caution decisions
can issue a signed review receipt. Rejected decisions produce rejection metadata and transparency
events but must not produce an installable reviewed catalog candidate. Caution candidates require
explicit catalog policy and must preserve warning metadata.

Resubmissions use `submissionType=resubmission` and `resubmissionOf=<submission-id>` in
`crypta-app-submission.json` so reviewers and operators can follow the audit chain.

See [app-store-submission-and-review-workflow.md](app-store-submission-and-review-workflow.md) for
the full package layout, required rationale files, pre-review report format, CLI commands, and
redaction rules.

## Platform API And Web Shell

Operator-readable review governance routes include:

- `GET /api/v1/app-review/governance`
- `GET /api/v1/app-review/reviewer-keys`
- `GET /api/v1/app-review/transparency-log`
- `GET /api/v1/app-review/transparency-log/verify`
- `GET /api/v1/app-catalogs/{catalogId}/apps/{appId}/review-history`

Responses are redacted. They expose reviewer key ids and lifecycle summaries, but not public key
bytes, private keys, registry paths, transparency-log paths, local evidence paths, tokens, or raw
receipt signatures.

Catalog app summaries expose third-party submission status as `thirdPartyReview`, separate from
publisher advisory `review` metadata and independent trusted receipt `reviewTrust` evaluation.

Web Shell displays review governance in the Apps/Catalogs area. Its review status is a local trust
decision. It can change when local reviewer keys, reviewer lifecycle metadata, policy constraints,
or review policy mode change, even if the signed catalog bytes remain the same.

## Developer Tooling

`crypta-app review` includes lifecycle, fingerprint, and transparency helpers:

```bash
crypta-app review keys inspect \
  --trusted-reviewer-keys-file trusted-reviewers.properties

crypta-app review fingerprint \
  --receipt-file social-inbox-review.properties

crypta-app review keys migrate \
  --trusted-reviewer-keys-file trusted-reviewers-v1.properties \
  --output trusted-reviewers-v2.properties

crypta-app review keys verify-lifecycle \
  --trusted-reviewer-keys-file trusted-reviewers.properties

crypta-app review transparency verify \
  --log-file review-transparency-log.jsonl
```

CLI output is redacted. It may print reviewer key ids, display names, policy ids/versions,
lifecycle status, receipt fingerprints, receipt revocation counts, warnings, record counts, and
latest transparency hashes. It must not print private key material, raw public key bytes, raw
signatures, raw receipt contents, local evidence contents, local store paths, or tokens.
