# Public beta app submission walkthrough

Use this walkthrough to understand the public-beta path from a developer submission package to a
reviewed beta catalog candidate.

## Flow

1. Developer creates a submission package.
2. Developer verifies the package.
3. Developer runs automated pre-review.
4. Reviewer imports the package into the intake queue.
5. Reviewer assignment binds a trusted reviewer key id and reason.
6. Reviewer runs intake pre-review and records artifacts.
7. Reviewer decision is `reviewed`, `caution`, `rejected`, or `resubmission_requested`.
8. A reviewed or allowed caution decision issues a review receipt.
9. The local transparency log records intake and decision events.
10. A beta catalog candidate is staged.
11. Operators can install from the beta catalog only after normal signed catalog, signed bundle,
    review, compatibility, security, permission, and consent gates pass.

The complete workflow is defined in
[../app-store-submission-and-review-workflow.md](../app-store-submission-and-review-workflow.md).

## Developer package and pre-review

Developers use:

```bash
"$CRYPTA_APP" submission create \
  --bundle-dir build/dev-apps/hello-stable \
  --output build/artifacts/org.example.hello-submission.zip \
  --submission-type new_app \
  --maintainer-name "Example Maintainer" \
  --maintainer-contact "mailto:maintainer@example.invalid" \
  --source-url "https://example.invalid/org.example.hello" \
  --non-production \
  --overwrite

"$CRYPTA_APP" submission verify \
  --submission build/artifacts/org.example.hello-submission.zip \
  --json > build/artifacts/org.example.hello-submission-verify.json

"$CRYPTA_APP" submission pre-review \
  --submission build/artifacts/org.example.hello-submission.zip \
  --contract build/artifacts/platform-api-contract.json \
  --output build/artifacts/org.example.hello-pre-review.json \
  --overwrite
```

Submission packages are review inputs. They do not approve install, update, or catalog inclusion.

## Reviewer and release manager path

Reviewer-side public beta intake uses file-backed queue commands:

```bash
"$CRYPTA_APP" submission intake import \
  --queue-dir build/app-intake \
  --submission build/artifacts/org.example.hello-submission.zip \
  --transparency-log build/app-intake/review-transparency.jsonl

"$CRYPTA_APP" submission intake list \
  --queue-dir build/app-intake \
  --json

"$CRYPTA_APP" submission intake assign \
  --queue-dir build/app-intake \
  --submission-id sub-... \
  --reviewer-key-id reviewer-prod-1 \
  --trusted-reviewer-keys config/trusted-reviewers.properties \
  --reason docs/review-assignment-reason.md \
  --transparency-log build/app-intake/review-transparency.jsonl

"$CRYPTA_APP" submission intake pre-review \
  --queue-dir build/app-intake \
  --submission-id sub-... \
  --contract build/artifacts/platform-api-contract.json \
  --artifacts-dir build/app-intake/artifacts/sub-... \
  --transparency-log build/app-intake/review-transparency.jsonl \
  --overwrite
```

Use protected reviewer-key handling for real release work. Do not put reviewer private keys,
reviewer-key bytes, raw receipts, or local secret paths into public docs or issue reports.

## Decisions

| Decision | Catalog effect |
| --- | --- |
| `reviewed` | Candidate can proceed to policy-specific catalog staging. Stable still requires the stable channel review policy. |
| `caution` | Candidate can proceed only where caution is explicitly allowed, and users must see warnings. |
| `rejected` | Candidate does not enter the stable catalog. |
| `resubmission_requested` | Developer must submit a linked corrected package. |

Rejected apps do not enter the stable catalog. Caution apps show warnings. A beta catalog candidate
is not automatic stable promotion. Use `app-review-appeal.yml` for public-safe appeal or
resubmission feedback and [support-and-feedback.md](support-and-feedback.md) for the wider beta
feedback loop.

## Review receipt and transparency log

A review receipt is independent reviewer evidence. The local transparency log is tamper-evident
local governance evidence; it is not a global public log and does not create trust by itself.

Allowed metadata includes ids, statuses, timestamps, hashes, counts, and policy identifiers. Do not
publish raw reviewer public key bytes, reviewer private keys, raw signatures, raw receipt bodies,
local transparency-log paths, app package bodies, or raw rationale content.

## Catalog candidate

After a reviewed or allowed caution decision:

```bash
"$CRYPTA_APP" submission intake stage-candidate \
  --queue-dir build/app-intake \
  --submission-id sub-... \
  --trusted-reviewer-keys config/trusted-reviewers.properties \
  --beta-candidate-dir build/beta-catalog-candidates \
  --bundle-uri https://example.invalid/crypta-apps/hello-stable.zip \
  --decision-dir build/app-intake/decisions/sub-... \
  --transparency-log build/app-intake/review-transparency.jsonl

"$CRYPTA_APP" submission intake install-smoke \
  --queue-dir build/app-intake \
  --submission-id sub-... \
  --beta-candidate-dir build/beta-catalog-candidates \
  --transparency-log build/app-intake/review-transparency.jsonl
```

The candidate still needs signed catalog publication, Web Shell consent, compatibility checks,
security advisory checks, and update/install gates.

## Release evidence

Release managers should verify:

- `app-store.*` evidence from app-platform smoke;
- `third-party-intake.*` evidence when public beta intake is required;
- `third-party-developer.*` evidence for developer docs, sample app flow, compatibility, feedback,
  plugin migration, and redaction;
- `public-beta.docs-onboarding` and related public-beta docs evidence;
- `public-beta.support-feedback-loop` and child evidence for templates, known issues, beta release
  notes, security handoff, and redaction fixtures;
- go/no-go dashboard status before promotion.

See [../release-certification.md](../release-certification.md) and
[../production-beta-go-no-go-dashboard.md](../production-beta-go-no-go-dashboard.md). Public release
notes should use [../templates/beta-release-notes.md](../templates/beta-release-notes.md).
