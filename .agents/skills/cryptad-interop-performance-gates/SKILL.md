---
name: cryptad-interop-performance-gates
description: "Maintain Cryptad's Hyphanet interop, performance regression, release-certification evidence gates, and production beta release pipeline under tools/interop, tools/perf, tools/release-certification, CI jobs, and release-readiness documentation."
---

# Cryptad interop and performance gates

Use this skill before changing `tools/interop`, `tools/perf`, `tools/release-certification`,
related CI jobs, or release-gate documentation.

## Read first

- Hyphanet interop gate: `tools/interop/README.md`
- Performance regression gate: `tools/perf/README.md`
- Release certification workflow: `docs/release-certification.md`
- Production beta release pipeline: `docs/production-beta-release-pipeline.md`
- Ecosystem RC certification gate: `docs/ecosystem-rc-certification-gate.md`
- Release certification tooling: `tools/release-certification/README.md`
- Release readiness gates: `docs/cryptad-release-workflow-and-runbook.md`
- Phase 3 platform closeout context: `docs/phase-3-platform-primacy-closeout.md`

## Hyphanet interop gate

- Tier 1 smoke is the release-readiness compatibility gate. It is Linux-only and runs a packaged
  Cryptad node against a pinned Hyphanet baseline.
- Tier 2 extended soak runs locally or through scheduled/manual CI when compatibility-sensitive
  behavior changed. It adds long-lived `SubscribeUSK`, persistent request replay, optional opennet
  plumbing, and longer diagnostics.
- Normal local commands:

```bash
python3 tools/interop/interop_smoke.py --self-test
tools/interop/run-hyphanet-interop-smoke.sh
INTEROP_SKIP_BUILD=1 tools/interop/run-hyphanet-interop-smoke.sh
INTEROP_MODE=extended INTEROP_SKIP_BUILD=1 tools/interop/run-hyphanet-interop-smoke.sh
```

- Do not publish `artifacts/private-insert-uris.json`; it contains temporary insert keys and CI
  excludes it from uploads.
- Preserve `build/interop-smoke/` or `build/interop-extended/` when a gate fails or when a release
  record needs compatibility evidence.

## Performance regression gate

- The performance gate records lightweight packaged-node startup, local FCP/Platform API timing,
  distribution size, Web Shell asset size, SDK asset size, and first-party static app source and
  staged-bundle size signals for Queue Manager, Publisher, Site Publisher, Profile Publisher,
  Social Inbox RC, Feed Reader, and Trust Graph Local RC. It is not a broad benchmark suite.
- The runner requires Python 3.12 or newer.
- Normal local commands:

```bash
python3 tools/perf/perf_smoke.py --self-test
tools/perf/run-performance-smoke.sh
PERF_SKIP_BUILD=1 tools/perf/run-performance-smoke.sh
PERF_MODE=collect PERF_SKIP_BUILD=1 tools/perf/run-performance-smoke.sh
```

- Deterministic asset-size failures are release blockers unless a maintainer records an accepted
  baseline update or waiver. Environment-sensitive timing regressions need comparable hardware or
  runner evidence before promotion decisions.
- Do not update `tools/perf/baselines/performance-smoke.json` only to silence a regression. Record
  before/after summaries, host or runner details, Java version, commit SHA, and the rationale.

## Release certification gate

- `tools/release-certification/release_certification.py` aggregates interop, performance,
  app-platform, network-scale soak, catalog, app-owned UI, operator beta recovery, optional
  live-network beta certification, legacy-admin retirement, and CI metadata into:

```text
build/release-certification/release-certification-summary.json
build/release-certification/release-certification-report.md
build/release-certification/ecosystem-certification-matrix.json
build/release-certification/ecosystem-certification-matrix.md
build/release-certification/artifacts/
build/release-certification/network-scale-soak/summary.json
build/release-certification/live-network-beta-smoke/summary.json
build/release-certification/live-network-beta-smoke/live-network-beta-smoke-report.md
```

- `tools/release-certification/production_beta_release.py` is the top-level production beta
  app-ecosystem release pipeline. It orchestrates Gradle build/install tasks, first-party app
  staging/signing/verification, signed catalog and review receipt generation, app-platform smoke,
  live-network beta smoke when required, network-scale soak, ecosystem RC certification, final
  artifact redaction, and public archive creation under `build/production-beta-release/`.
  `developer-dry-run` is CI-safe and non-release; `release-candidate` is strict but may use
  non-production signing labels; `production-beta` requires production signing, a complete
  in-pipeline Gradle build/stage/sign run, a public HTTPS artifact base URI, live-network evidence
  unless the explicit emergency skip is used, and a clean workspace before `promotionReady` can
  become true. Emergency build skips must leave `nonRelease=true` and fail the build-complete
  promotion gate.
- `tools/release-certification/app_platform_smoke.py` produces the app-platform summary consumed by
  the aggregator. It keeps `--self-test` offline and Python-only, including source/test evidence
  for the Platform API contract, Platform API 1.0 stable baseline, manifest/catalog target
  stability, first-party stability declarations, stable reference docs, app-vault capability docs,
  signed catalogs, first-party maintenance metadata, app-store submission package and pre-review
  evidence, catalog security advisory/denylist evidence, trusted app-review receipt/revocation
  evidence, unified user-consent snapshot/digest/audit evidence, app-owned UI origin behavior,
  app UI design-system/lint evidence, live USK catalog publication, Site Publisher
  reference-content coverage, Profile Publisher identity-profile coverage, Feed Reader
  content-fetch, subscription, app-data, and app-data migration coverage, Social Inbox RC
  multi-source/threading/read-state/local-filter/export/trust-grant coverage, Trust Graph Local RC
  durable exchange, import-preview, duplicate-issuer/conflict, anchor-lifecycle, bounded-score, and
  app-data migration coverage, app-data backup/restore portability evidence, app-service
  registry/grant/dependency/grant-bundle/redaction coverage, generated document insert/content-fetch
  and trust redaction coverage, app-network budget source evidence, legacy plugin freeze evidence,
  app-review governance/reviewer-key/transparency-log evidence, public-beta security hardening
  evidence, operator beta dashboard/recovery/support-bundle evidence, legacy-admin
  retirement/removal Wave 1-5 and final-surface evidence, production security response runbook
  evidence, sandbox provider selection, and app-update lifecycle/scheduler/rollback.
- `tools/release-certification/network_scale_soak.py` produces the deterministic simulated
  network-scale soak summary consumed by the aggregator. Normal PR and CI runs must use simulated
  time instead of a literal 24-hour test. Release-candidate runs may attach an external
  `simulated-rc-soak` or `live-rc-soak` summary with the same redacted schema.
- `tools/release-certification/live_network_beta_smoke.py` is the explicit release-manager live
  network collector. Its self-test is offline and deterministic, but normal runs may call only a
  validated localhost node and use env/protected-file fixtures for form passwords, catalog expected
  key ids, content/feed/profile/trust URIs, and private insert material. Required mode must fail
  closed for missing fixtures, failed required evidence, stale app principals, cleanup failures, or
  redaction findings.
- `tools/release-certification/app_platform_docs_check.py` produces deterministic app-platform
  beta docs evidence for the developer portal, tutorials, beta program, issue templates, relative
  Markdown links, and docs redaction checks.
- The wrapper resolves relative `--out-dir` values under the repository root, runs the
  app-platform smoke collector, regenerates the default network-scale soak summary unless an
  explicit summary path or `CRYPTAD_CERT_NETWORK_SCALE_SOAK_SUMMARY` is set, then aggregates the
  evidence.
- Normal local commands:

```bash
python3 tools/release-certification/app_platform_docs_check.py --self-test
python3 tools/release-certification/release_certification.py --self-test
python3 tools/release-certification/app_platform_smoke.py --self-test
python3 tools/release-certification/security_response_runbook.py verify
python3 tools/release-certification/network_scale_soak.py --self-test
python3 tools/release-certification/live_network_beta_smoke.py --self-test
python3 tools/release-certification/production_beta_release.py --self-test
tools/release-certification/run-release-certification.sh
tools/release-certification/run-release-certification.sh --mode release-candidate --out-dir build/release-certification
tools/release-certification/run-production-beta-release.sh --mode developer-dry-run --out-dir build/production-beta-dry-run
```

- Release-candidate mode fails when required evidence is missing, skipped, malformed, wrong-mode,
  or failing unless a release-manager waiver is recorded. Required app-platform evidence now
  includes `app-platform.first-party`, `app-platform.devtools-cli`,
  `app-platform.developer-beta-toolkit`, `app-platform.docs-portal`,
  `app-platform.beta-program`, `app-platform.beta-tutorials`,
  `app-platform.docs-redaction`, `app-platform.signed-bundles`, `catalog.smoke`,
  `app-catalog.first-party-beta`, `catalog.production-channels`,
  `app-catalog.first-party-maintenance-policy`, `catalog.security-advisories`,
  `catalog.version-denylist`, `app-review.receipt-revocation`,
  `app-review.reviewer-key-compromise-flow`, `app-update.security-denylist-gates`,
  `web-shell.security-advisory-trust-warnings`,
  `ecosystem-security.advisory-revocation-redaction`, `production-security.response-runbook`,
  `platform-api.contract`,
  `platform-api.stable-baseline`, `platform-api.stable-breaking-change-check`,
  `platform-api.manifest-target-stability`,
  `platform-api.first-party-stability-declarations`, `platform-api.stable-reference-docs`,
  `app-vault.capabilities`,
  `app-platform.identity-profile-publish`, `app-platform.generated-document-insert`,
  `app-platform.content-fetch`, `app-platform.content-subscriptions`,
  `network-content.subscription-scheduler`, `app-platform.durable-app-data-store`,
  `app-data.backup-restore-portability`, `app-platform.trust-graph-preview`,
  `app-platform.trust-graph-rc-scope-and-safety`, `app-platform.trust-graph-durable-store`,
  `app-platform.trust-graph-exchange`, `app-platform.trust-statement-signing`,
  `app-platform.social-message-signing`, `app-services.registry`, `app-services.grants`,
  `app-services.dependency-graph`, `app-services.grant-bundles`,
  `app-services.grant-expiry-renewal`, `app-services.provider-revalidation`,
  `app-services.trust-score-provider`, `app-services.web-shell`, `app-services.redaction`,
  `app-services.dependency-redaction`,
  `app-ui.design-system`, `app-ui.lint`, `app-ui.first-party-adoption`, `app-ui.smoke`,
  `reference-apps.content`, `reference-app.profile-publisher`,
  `reference-app.profile-publisher-app-data`, `reference-app.feed-reader`,
  `reference-app.feed-reader-subscriptions`, `reference-app.feed-reader-app-data`,
  `reference-app.social-inbox`, `reference-app.social-inbox-signed-message`,
  `reference-app.social-inbox-subscriptions`, `reference-app.social-inbox-app-data`,
  `reference-app.social-inbox-trust-annotations`, `reference-app.social-inbox-service-grant`,
  `reference-app.social-inbox-rc-threading`, `reference-app.social-inbox-service-dependency`,
  `migration.social-mail-preview`, `reference-app.trust-graph`,
  `reference-app.trust-graph-durable-exchange`, `reference-app.trust-graph-app-data-preview`,
  `legacy-plugin.freeze-policy`,
  `legacy.retirement`, `legacy-admin.removal-wave-1`, `legacy-admin.removal-wave-2`,
  `legacy-admin.removal-wave-3`, `legacy-admin.removal-wave-4`,
  `legacy-admin.removal-wave-5`, `legacy-admin.final-admin-surface`,
  `legacy-admin.browse-retained`, `legacy-admin.emergency-fallback-retained`,
  `apphost.sandbox-provider`,
  `app-update.lifecycle`,
  `app-update.scheduler`, `app-update.rollback`, `app-update.live-catalog-refresh`,
  `app-update.data-migration-contract`,
  `public-beta-security.*`, `operator-beta.*`, `operator-rc.*`, `app-review.trusted-receipts`,
  `app-review.policy`, `app-review.governance`, `app-review.reviewer-key-lifecycle`,
  `app-review.transparency-log`, `app-review.review-history-api`,
  `app-review.first-party-catalog`, `app-review.first-party-review-chain`, and
  `network-scale.app-network-budget`, `network-scale.content-fetch-budget`,
  `network-scale.subscription-budget`, `network-scale.queue-pressure-backoff`,
  `network-scale.trust-graph-import-budget`, `network-scale.social-inbox-multi-source-soak`,
  `network-scale.redaction`, `network-scale.rc-soak-summary`, and
  `release-certification.ecosystem-matrix`.
- Platform API stable-history checks compare the stable baseline name/counts/lists, stable endpoint
  required-capability sets, and stable endpoint app-process/app-browser access flags. In production
  history mode, missing previous baseline or endpoint metadata is a blocker; developer dry runs may
  warn when no production history is available.
- Network-scale release-candidate evidence must be generated fresh by the wrapper or attached
  explicitly. Do not let the aggregator reuse stale default `network-scale-soak/summary.json`
  files across release workspaces.
- `live-network-beta.*` evidence is release-blocking only when `--require-live-network-beta` or
  `CRYPTAD_CERT_REQUIRE_LIVE_NETWORK_BETA=1` is set. When live-network beta is disabled, the
  aggregator must ignore stale live summaries and must not copy stale live artifacts into the
  release record.
- Live-network beta runs must use only `http://127.0.0.1:<port>`,
  `http://localhost:<port>`, or `http://[::1]:<port>` node URLs without credentials, query
  strings, fragments, redirects, or proxy forwarding. Form passwords, app browser sessions,
  private insert URIs, and app-service grants must not leak into artifacts, shell history, or
  proxy traffic.
- Do not publish private signing keys, form passwords, app tokens, browser-session tokens, raw
  reviewer keys, raw trusted reviewer public key bytes, raw request bodies, raw feed bodies, raw
  trust documents from real users, raw social message bodies, raw fetched social documents, raw
  incident artifacts, raw app-service subject URIs, provider app data, raw app-data values, raw
  update/rollback command output, command lines containing secrets, CI secret values, queue HTML,
  budget-store file paths, private insert URIs, non-localhost endpoint metadata, catalog scratch
  paths, staged bundle paths, rollback backup paths, UI lint report paths, or other unsanitized
  local paths. The aggregator filters
  `artifacts/private-insert-uris.json` even when interop summaries reference it.
- Treat docs redaction findings as non-waivable blockers. Link-only or presence-only docs gaps can
  be waived by a release manager when policy allows, but raw secret/path findings must keep the
  evidence and matrix row failing.

## CI and release notes

- `.github/workflows/ci.yml` runs `interop-smoke` on push/PR, `interop-extended` on schedule/manual,
  interop self-tests on the multi-OS matrix, performance self-tests on the multi-OS matrix,
  release-certification self-tests on the multi-OS matrix, and `performance-smoke` on
  schedule/manual.
- `.github/workflows/release-certification.yml` runs scheduled/manual/release-ref certification,
  uploads sanitized certification artifacts, and uses `release-candidate` mode for `release/**`
  branches and `v*` tags.
- `.github/workflows/production-beta-release.yml` runs the production beta pipeline in
  `developer-dry-run` for PR-safe checks, `release-candidate` for release refs/manual dispatch, and
  protected `production-beta` only when release secrets, live-node inputs, and a real artifact base
  URI are available. Artifact uploads must stay gated on a passing production-beta redaction
  summary.
- Release notes should mention interop, performance, or certification gate changes only when they
  affect release readiness, operator confidence, app/platform behavior, or packager workflows.
