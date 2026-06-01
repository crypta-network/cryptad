# App platform beta program

This page defines the app ecosystem beta program, app submission expectations, feedback workflow,
and Phase 7 closeout runbook.

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

## Feedback categories

Use the closest category when filing beta feedback:

- Install/catalog issue.
- Update/rollback issue.
- Platform API compatibility issue.
- AppVault/identity issue.
- Content fetch/insert issue.
- Trust Graph Preview issue.
- UI/design-system issue.
- Legacy replacement issue.
- Documentation issue.

Use `.github/ISSUE_TEMPLATE/app-platform-beta-feedback.yml` when filing general feedback and
`.github/ISSUE_TEMPLATE/app-submission-beta.yml` when proposing an app for beta review.

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
tools/release-certification/run-release-certification.sh --mode nightly
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
tools/release-certification/run-release-certification.sh \
  --mode release-candidate \
  --live-network-beta \
  --require-live-network-beta
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

2. Build the developer CLI and run app-platform smoke self-tests.

   ```bash
   ./gradlew :platform-devtools:installDist
   python3 tools/release-certification/app_platform_docs_check.py --self-test
   python3 tools/release-certification/app_platform_smoke.py --self-test
   ```

3. Run release certification self-tests.

   ```bash
   python3 tools/release-certification/release_certification.py --self-test
   ```

4. Run release certification in the mode that matches the release stage.

   ```bash
   tools/release-certification/run-release-certification.sh --mode pr --skip-gradle --skip-git-metadata
   tools/release-certification/run-release-certification.sh --mode nightly --out-dir build/release-certification
   tools/release-certification/run-release-certification.sh --mode release-candidate --out-dir build/release-certification
   ```

5. Run live-network beta certification when the release will claim public first-party beta catalog
   readiness. Use the command above with disposable fixture keys unless the release manager is
   intentionally publishing the candidate catalog.

6. Inspect the release summary and report.

   ```text
   build/release-certification/release-certification-summary.json
   build/release-certification/release-certification-report.md
   build/release-certification/ecosystem-certification-matrix.json
   build/release-certification/ecosystem-certification-matrix.md
   build/release-certification/app-platform-smoke/summary.json
   build/release-certification/app-platform-smoke/app-platform-smoke-report.md
   ```

7. Confirm the app-review governance evidence passes: review receipts, reviewer key lifecycle,
   local transparency log, review-history API, and first-party review chain.
8. Confirm the legacy plugin migration guide evidence passes:
   `legacy-plugin.migration-guide` and `legacy-plugin.social-inbox-spike`.
9. Confirm legacy retirement evidence passes, including `legacy-admin.removal-wave-3`, and FProxy
   browse remains retained.
10. Confirm docs evidence passes: portal, beta tutorials, beta program, known limitations, issue
   templates, internal links, and redaction checks.
11. Confirm the ecosystem certification matrix includes `app-platform-beta-docs-and-program` and no
   active blocker remains unless a release manager recorded an explicit waiver.
12. Publish release notes with the known beta limitations and any accepted waivers or residual
    risks.

Release-candidate mode should require docs and beta evidence unless a release-manager waiver
explicitly accepts a docs-only gap. Do not waive redaction failures.

## Phase 7 closeout statement

The Phase 7 closeout story is:

```text
first-party catalog + developer toolkit + reference apps + trust graph preview
+ review governance + legacy plugin migration guide + legacy wave 3 + ecosystem certification matrix
-> documented and certified as Ecosystem Beta readiness
```

The closeout evidence must be redacted and reproducible. It should show that docs are present,
linked, current with the source code, and honest about beta limits.
