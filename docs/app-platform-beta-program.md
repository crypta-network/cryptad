# App platform beta program

This page defines the app ecosystem beta program, app submission expectations, feedback workflow,
and current RC closeout runbook.

Public-beta users and operators should start with [public-beta/README.md](public-beta/README.md);
this page remains the program, feedback, submission, and maintainer closeout source of truth.

## Purpose

The beta is for proving that external app developers and release managers can complete an offline,
reproducible app flow:

```text
scaffold app -> run mock dev server -> run offline tests -> sign bundle -> pack artifact
-> create catalog entry -> create/sign/verify catalog -> produce dry-run USK publication plan
-> optionally run explicit live USK publication from the release/operator environment
-> review submission -> certify release readiness
```

The beta is not a public production app store, does not auto-install recommended catalog apps, and
does not introduce public network dependencies into tests.

External third-party authors should use
[third-party-developer-beta-program.md](third-party-developer-beta-program.md) as the public
happy-path guide, [third-party-app-submission-checklist.md](third-party-app-submission-checklist.md)
as the pre-submission checklist, and
[platform-api-compatibility-support-window.md](platform-api-compatibility-support-window.md) for
stable versus experimental support-window rules.

## Participants

| Role | What they test |
| --- | --- |
| App developers | Templates, manifest permissions, UI lint, SDK helpers, signing, packing, catalog entries, and `crypta-app test` output. |
| Reviewers | Manifest validation, capability rationale, review receipt evidence, reviewer key lifecycle, local transparency log behavior, and redaction. |
| Release managers | First-party catalog readiness, reference app coverage, update scheduler and rollback evidence, legacy retirement status, docs readiness, and the ecosystem certification matrix. |
| Operators | First-party/reference app install, update review, rollback behavior, Web Shell onboarding, and beta feedback. |

## App proposal checklist

An app proposal should include:

- App id, display name, and app version.
- `cryptad-app.properties` manifest.
- Requested capabilities and permission rationales.
- Platform API contract `api.minimumVersion` and `api.maximumTestedVersion`.
- Platform API stability target, using
  [platform-api-1.0-stable-reference.md](platform-api-1.0-stable-reference.md) and
  [platform-api-compatibility-support-window.md](platform-api-compatibility-support-window.md).
- UI lint output, preferably from `crypta-app ui lint --strict --json`.
- API compatibility output, preferably from `crypta-app compat verify --strict`.
- `crypta-app test --strict --json` output.
- Signed bundle digest and signing key id.
- Catalog entry descriptor or a safe excerpt with artifact digest, size, app id, version, and
  permission rationales.
- Optional review receipt status and reviewer policy id/version.
- Update policy expectations and permission-delta notes.
- Known risks and beta limitations.
- Security notes and redaction confirmation.

Do not include private keys, reviewer private keys, private insert URIs, session tokens, form
passwords, raw request bodies, raw feed bodies, raw trust documents from real users, raw receipt
signatures, or local absolute paths.

## Review expectations

Reviewers should check:

- Manifest parsing and bundle validation.
- Capability and permission rationale fit.
- Platform API compatibility range and optional capability metadata.
- UI safety: local resources, SDK/bootstrap ordering, permission disclosure, accessibility basics,
  and design-system use.
- Static asset safety and absence of remote runtime dependencies unless explicitly reviewed.
- Redaction: no private keys, tokens, request bodies, private URIs, raw user documents, raw
  signatures, or local absolute paths.
- Signed bundle verification and artifact digest consistency.
- Catalog entry metadata, signed catalog behavior, and review receipt handling.
- Reviewer key lifecycle status: active, retired, revoked, expired, unknown, or mismatched.
- Local transparency log behavior when review evidence is recorded.
- Update behavior, permission additions, compatibility gates, and rollback scope.

Review receipts are independent of catalog signatures and bundle signatures. Catalog publisher
metadata does not create reviewer trust by itself.
See [app-store-submission-and-review-workflow.md](app-store-submission-and-review-workflow.md) for
submission package verification, pre-review, reviewed/caution/rejected decisions, resubmission, and
catalog-candidate generation.

## Feedback categories

Use the closest category when filing beta feedback:

- Install/catalog issue.
- Update/rollback issue.
- Platform API compatibility issue.
- Third-party developer workflow issue.
- App submission/review issue.
- AppVault/identity issue.
- Content fetch/insert issue.
- Network budget, subscription pressure, or stale-source issue.
- Trust Graph Local RC issue.
- UI/design-system issue.
- Legacy plugin migration issue.
- Documentation issue.

Use `.github/ISSUE_TEMPLATE/app-platform-beta-feedback.yml` when filing general feedback and
`.github/ISSUE_TEMPLATE/app-submission-beta.yml` when proposing an app for beta review. Use
`.github/ISSUE_TEMPLATE/developer-beta-feedback.yml` for external developer workflow feedback,
`.github/ISSUE_TEMPLATE/app-review-appeal.yml` for review appeals or resubmissions,
`.github/ISSUE_TEMPLATE/platform-api-compatibility.yml` for compatibility-window issues, and
`.github/ISSUE_TEMPLATE/plugin-migration-feedback.yml` for legacy plugin author feedback.

## Bug report redaction

Do not include:

- Private keys or reviewer private keys.
- Seed phrases or private identity material.
- Private insert URIs.
- Browser session tokens, AppHost process tokens, form passwords, authorization headers, cookies,
  or request bodies.
- Raw trust documents, raw feed bodies, raw profile documents, or raw receipt signatures.
- Local absolute paths unless already redacted.

Acceptable replacements:

```text
<redacted>
<token-redacted>
crypta:CHK@<artifact-key>
crypta:USK@<catalog-key>/cryptad-app-catalog.properties
```

## Optional live AppHost smoke

Optional live AppHost lifecycle smoke exercises the generated sample app through localhost Platform
API routes. It is useful release-manager evidence, but normal PR and nightly evidence remain
offline-safe.

```bash
CRYPTAD_CERT_APP_SMOKE_LIVE=1 \
CRYPTAD_CERT_NODE_BASE_URL=http://127.0.0.1:<port> \
CRYPTAD_CERT_FORM_PASSWORD=<redacted> \
python3 tools/release-certification/certify.py release-certification --manifest build/release-candidate.json
```

The smoke installs, reads runtime status, starts, stops, updates, uninstalls, and reads diagnostics
for `cert-smoke`. It records only localhost metadata, status codes, and redacted response summaries;
it does not prove live network publication. If it fails after install, verify the stop/delete
cleanup before reusing the node.

## Live-network beta certification

Live-network beta certification is for release managers, not normal PR or nightly evidence. It
validates the app ecosystem against a localhost Crypta node and operator-provided live fixtures.

```bash
CRYPTAD_CERT_LIVE_NETWORK_BETA=1 \
CRYPTAD_CERT_REQUIRE_LIVE_NETWORK_BETA=1 \
CRYPTAD_CERT_NODE_BASE_URL=http://127.0.0.1:8888 \
CRYPTAD_CERT_FORM_PASSWORD=<redacted> \
CRYPTAD_CERT_LIVE_CATALOG_SOURCE=crypta:USK@<catalog-key>/cryptad-app-catalog.properties \
CRYPTAD_CERT_LIVE_CATALOG_EXPECTED_KEY_ID=crypta-first-party-beta \
CRYPTAD_CERT_LIVE_CONTENT_FETCH_URI=crypta:CHK@<artifact-key> \
CRYPTAD_CERT_LIVE_FEED_USK_URI=crypta:USK@<feed-key>/feed.json \
CRYPTAD_CERT_LIVE_TEST_INSERT_URI_FILE=<protected-insert-uri-file> \
python3 tools/release-certification/certify.py release-certification --manifest build/release-candidate.json
```

Use disposable fixture catalog keys for rehearsals. Public fixture URIs may use
`crypta:USK@<catalog-key>/cryptad-app-catalog.properties` for the catalog source and
`crypta:CHK@<artifact-key>` for immutable bundle artifacts. The matching private insert URI is a
bare private USK directory insert URI for the same catalog parent and must be loaded indirectly
through `CRYPTAD_CERT_LIVE_TEST_INSERT_URI_ENV` or `CRYPTAD_CERT_LIVE_TEST_INSERT_URI_FILE`. If
both are present, env-name indirection takes precedence and the summary records only fixture
presence.
Required live-network beta certification also requires
`CRYPTAD_CERT_LIVE_CATALOG_EXPECTED_KEY_ID`. The runner compares that configured public key id with
the `signatureKeyId` observed from the node's verified catalog summary and fails catalog evidence
when it is unset, unavailable, or mismatched.

The runner does not prove global propagation, public reputation, app safety beyond the signed
catalog/bundle/review gates, or deletion of published bytes. Preserve only the sanitized summary,
report, and matrix. Assume live synthetic content may remain retrievable and may not be deletable.
The Trust Graph `trust.score` app-service invocation runs only when
`CRYPTAD_CERT_LIVE_APP_SERVICE_SCORE=1` is set; otherwise it is reported as optional skipped
evidence. App-facing workflow steps use app browser sessions minted from each configured static app
bootstrap and never write those session tokens to artifacts. Required mode fails if an app-only
route cannot authenticate as the app principal. Cleanup deletes only an app that was absent before
the run and installed successfully by the smoke. Do not use real keys, production secrets, or user
content in fixture certification runs.

## Maintainer closeout runbook

Use this runbook to decide whether the ecosystem beta is ready for a release candidate.

1. Run the normal build and test commands for the release scope.

   ```bash
   ./gradlew test
   ```

2. Build the developer CLI and run the unified certification self-test suite.

   ```bash
   ./gradlew :platform-devtools:installDist
   python3 tools/release-certification/certify.py self-test all
   ```

3. Copy the release-candidate manifest, replace every placeholder, and run release certification.
   Keep secrets in protected environment variables or files, never in the manifest.

   ```bash
   cp tools/release-certification/manifests/release-candidate.example.json \
     build/release-candidate.json
   python3 tools/release-certification/certify.py release-certification --manifest build/release-candidate.json
   ```

4. Run live-network beta certification when the release will claim public first-party beta catalog
   readiness. Use the command above with disposable fixture keys unless the release manager is
   intentionally publishing the candidate catalog.

5. Inspect the release summary and report. Replace `<out-root>` and `<release-id>` with the values
   selected by the manifest. When the production beta pipeline runs, inspect its detailed
   engine-native dashboard too.

   ```text
   <out-root>/<release-id>/release-certification/summary.json
   <out-root>/<release-id>/release-certification/report.md
   <out-root>/<release-id>/release-certification/redaction-report.json
   <out-root>/<release-id>/release-certification/artifacts/legacy/ecosystem-certification-matrix.json
   <out-root>/<release-id>/release-certification/artifacts/legacy/ecosystem-certification-matrix.md
   <out-root>/<release-id>/app-platform/summary.json
   <out-root>/<release-id>/app-platform/report.md
   <out-root>/<release-id>/network-scale-soak/summary.json
   <out-root>/<release-id>/production-beta/artifacts/legacy/reports/go-no-go-dashboard.json
   <out-root>/<release-id>/production-beta/artifacts/legacy/reports/go-no-go-dashboard.md
   <out-root>/<release-id>/production-beta/artifacts/legacy/reports/go-no-go-redaction-report.json
   ```

6. Confirm the app-review governance evidence passes: review receipts, reviewer key lifecycle,
   local transparency log, review-history API, and first-party review chain.
7. Confirm the legacy plugin freeze and migration evidence passes:
   `legacy-plugin.freeze-policy`, `legacy-plugin.migration-guide`, and
   `legacy-plugin.social-inbox-spike`.
8. Confirm legacy retirement evidence passes, including `legacy-admin.removal-wave-3`,
   `legacy-admin.removal-wave-4`, `legacy-admin.removal-wave-5`,
   `legacy-admin.final-admin-surface`, `legacy-admin.browse-retained`, and
   `legacy-admin.emergency-fallback-retained`. Confirm FProxy browse/content rendering, content
   filter, startup wizard, security recovery fallback, and pending chat/translation/help/node-to-node
   routes remain retained or pending.
9. Confirm app-update evidence passes, including `app-update.lifecycle`, `app-update.scheduler`,
   `app-update.rollback`, `app-update.live-catalog-refresh`, and
   `app-update.data-migration-contract`.
10. Confirm network-scale evidence passes, including `network-scale.app-network-budget`,
   `network-scale.content-fetch-budget`, `network-scale.subscription-budget`,
   `network-scale.queue-pressure-backoff`, `network-scale.trust-graph-import-budget`,
   `network-scale.social-inbox-multi-source-soak`, `network-scale.redaction`, and
   `network-scale.rc-soak-summary`.
11. Confirm the [Operator beta dashboard](operator-beta-dashboard.md) evidence passes, including
   `operator-beta.dashboard`, `operator-beta.subscription-recovery`,
   `operator-beta.support-bundle-redaction`, and `operator-beta.web-shell`.
12. Confirm docs evidence passes: portal, beta tutorials, beta program, known limitations, issue
   templates, internal links, and redaction checks.
13. Confirm the ecosystem certification matrix includes `app-platform-beta-docs-and-program`,
   `operator-beta-ux-and-recovery`, `network-scale-soak-and-subscription-budget`, and no active
   blocker remains unless a release manager recorded an explicit waiver.
14. Publish release notes with the known beta limitations and any accepted waivers or residual
    risks.

Release-candidate mode should require docs and beta evidence unless a release-manager waiver
explicitly accepts a docs-only gap. Do not waive redaction failures.

## Phase 10 production beta closeout statement

The current production beta closeout story is:

```text
first-party catalog + developer toolkit + reference apps + Trust Graph Local RC
+ review governance + app-data backup/restore + app-service dependency/grant bundles
+ network-scale budgets/subscription soak + legacy plugin freeze + final legacy admin surface
+ production security response runbook + ecosystem certification matrix
-> documented and certified as production beta readiness
```

The closeout evidence must be redacted and reproducible. It should show that docs are present,
linked, current with the source code, and honest about beta limits.
