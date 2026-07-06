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
- Production beta go/no-go dashboard: `docs/production-beta-go-no-go-dashboard.md`
- Stable 1.0 readiness gate: `docs/stable-1.0-readiness-gate.md`
- Multi-node beta soak and upgrade drill: `docs/multi-node-beta-soak-and-upgrade-drill.md`
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
  app-platform, network-scale soak, multi-node beta soak, catalog, app-owned UI, operator beta
  recovery, optional live-network beta certification, legacy-admin retirement, and CI metadata into:

```text
build/release-certification/release-certification-summary.json
build/release-certification/release-certification-report.md
build/release-certification/ecosystem-certification-matrix.json
build/release-certification/ecosystem-certification-matrix.md
build/release-certification/artifacts/
build/release-certification/network-scale-soak/summary.json
build/release-certification/multi-node-beta-soak/summary.json
build/release-certification/multi-node-beta-soak/multi-node-beta-soak-summary.md
build/release-certification/live-network-beta-smoke/summary.json
build/release-certification/live-network-beta-smoke/live-network-beta-smoke-report.md
```

- `tools/release-certification/production_beta_release.py` is the top-level production beta
  app-ecosystem release pipeline. It orchestrates Gradle build/install tasks, first-party app
  staging/signing/verification, signed catalog and review receipt generation, app-platform smoke,
  live-network beta smoke when required, network-scale soak, multi-node beta soak and upgrade
  evidence, ecosystem RC certification, final artifact redaction, the production beta go/no-go
  dashboard, and public archive creation under `build/production-beta-release/`.
  `developer-dry-run` is CI-safe and non-release; `release-candidate` is strict but may use
  non-production signing labels; `production-beta` requires production signing, a complete
  in-pipeline Gradle build/stage/sign run, a public HTTPS artifact base URI, live-network evidence
  unless the explicit emergency skip is used, passing multi-node beta evidence, and a clean
  workspace before `promotionReady` can become true. Emergency build skips must leave
  `nonRelease=true` and fail the build-complete promotion gate.
- `tools/release-certification/production_beta_go_no_go_dashboard.py` is the final release-manager
  dashboard generator for production beta launch candidates. It consumes sanitized production beta,
  release-certification, ecosystem matrix, app-platform, live-network, network-scale, multi-node,
  security-response, and waiver inputs; emits JSON, Markdown, and a dashboard redaction report; and
  decides only `go`, `no-go`, or `go-with-waivers`. Production-beta mode fails closed for
  mandatory launch evidence, invalid or expired waivers, unsafe artifact hygiene, fixture/test
  signing, non-release summaries, dirty workspaces, and redaction findings.
- `tools/release-certification/stable_1_0_readiness.py` is the Stable 1.0 readiness gate. It
  consumes production beta outputs, go/no-go output, release certification, app-platform evidence,
  multi-node and network-scale soak, security drill summaries, public beta known issues, policy,
  known limitations, and Stable-scoped waivers. Required consumers must reject malformed summaries,
  mismatched `releaseId`, missing `stable-1.0.*` evidence rows, failed redaction, stale security or
  soak evidence, and non-release production beta inputs.
- `tools/release-certification/app_platform_smoke.py` produces the app-platform summary consumed by
  the aggregator. It keeps `--self-test` offline and Python-only, including source/test evidence
  for the Platform API contract, Platform API 1.0 stable baseline, compatibility-window metadata,
  previous contract snapshot policy, stable descriptor deprecation/removal windows,
  experimental-graduation policy, manifest/catalog target stability, first-party stability
  declarations, stable reference docs, app-vault capability docs,
  signed catalogs, first-party maintenance metadata, app-store submission package and pre-review
  evidence, catalog security advisory/denylist evidence, catalog operations and mirrors evidence,
  trusted app-review receipt/revocation evidence, unified user-consent snapshot/digest/audit
  evidence, app-owned UI origin behavior, app UI design-system/lint evidence, live USK catalog
  publication, Site Publisher
  reference-content coverage, Profile Publisher identity-profile coverage, Feed Reader
  content-fetch, subscription, app-data, and app-data migration coverage, Social Inbox RC
  multi-source/threading/read-state/local-filter/export/trust-grant coverage, Trust Graph Local RC
  durable exchange, import-preview, duplicate-issuer/conflict, anchor-lifecycle, bounded-score, and
  app-data migration coverage, app-data backup/restore portability evidence, app-service
  registry/grant/dependency/grant-bundle/redaction coverage, generated document insert/content-fetch
  and trust redaction coverage, app-network budget source evidence, third-party developer beta
  docs, template, sample-flow, checklist, compatibility, feedback, plugin-migration, and redaction
  evidence, legacy plugin freeze evidence, app-review governance/reviewer-key/transparency-log
  evidence, public-beta security hardening
  evidence, operator beta dashboard/recovery/support-bundle evidence, legacy-admin
  retirement/removal Wave 1-5 and final-surface evidence, production security response runbook
  evidence, sandbox provider selection, and app-update lifecycle/scheduler/rollback.
- `tools/release-certification/network_scale_soak.py` produces the deterministic simulated
  network-scale soak summary consumed by the aggregator. Normal PR and CI runs must use simulated
  time instead of a literal 24-hour test. Release-candidate runs may attach an external
  `simulated-rc-soak` or `live-rc-soak` summary with the same redacted schema.
- `tools/release-certification/multi_node_beta_soak.py` produces deterministic multi-node beta
  soak and upgrade/rollback/backup drill evidence consumed by the aggregator and production beta
  pipeline. Normal PR and CI runs use the checked-in simulated topology. Release-manager runs may
  attach an external `simulated`, `hybrid`, or `live` summary with the same redacted schema.
- `tools/release-certification/live_network_beta_smoke.py` is the explicit release-manager live
  network collector. Its self-test is offline and deterministic, but normal runs may call only a
  validated localhost node and use env/protected-file fixtures for form passwords, catalog expected
  key ids, content/feed/profile/trust URIs, and private insert material. Required mode must fail
  closed for missing fixtures, failed required evidence, stale app principals, cleanup failures, or
  redaction findings.
- `tools/release-certification/app_platform_docs_check.py` produces deterministic app-platform
  beta docs evidence for the developer portal, tutorials, beta program, third-party developer beta
  docs, issue templates, relative Markdown links, and docs redaction checks.
- The wrapper resolves relative `--out-dir` values under the repository root, runs the
  app-platform smoke collector, regenerates the default network-scale soak summary unless an
  explicit summary path or `CRYPTAD_CERT_NETWORK_SCALE_SOAK_SUMMARY` is set, regenerates the
  default multi-node beta soak summary unless `--multi-node-soak-summary` or
  `CRYPTAD_CERT_MULTI_NODE_SOAK_SUMMARY` is set, then aggregates the evidence.
- Normal local commands:

```bash
python3 tools/release-certification/app_platform_docs_check.py --self-test
python3 tools/release-certification/release_certification.py --self-test
python3 tools/release-certification/app_platform_smoke.py --self-test
python3 tools/release-certification/security_response_runbook.py verify
python3 tools/release-certification/network_scale_soak.py --self-test
python3 tools/release-certification/multi_node_beta_soak.py --self-test
python3 tools/release-certification/live_network_beta_smoke.py --self-test
python3 tools/release-certification/stable_1_0_readiness.py --self-test
python3 tools/release-certification/production_beta_go_no_go_dashboard.py --self-test
python3 tools/release-certification/production_beta_release.py --self-test
tools/release-certification/run-release-certification.sh
tools/release-certification/run-release-certification.sh --mode release-candidate --out-dir build/release-certification
tools/release-certification/run-release-certification.sh --mode release-candidate --multi-node-mode simulated --out-dir build/release-certification
tools/release-certification/run-production-beta-release.sh --mode developer-dry-run --out-dir build/production-beta-dry-run
```

- Release-candidate mode fails when required evidence is missing, skipped, malformed, wrong-mode,
  or failing unless a release-manager waiver is recorded. Required app-platform evidence now
  includes `app-platform.first-party`, `app-platform.devtools-cli`,
  `app-platform.developer-beta-toolkit`, `app-platform.docs-portal`,
  `app-platform.beta-program`, `app-platform.beta-tutorials`,
  `app-platform.docs-redaction`, `app-platform.signed-bundles`,
  `third-party-developer.beta-program`, `third-party-developer.docs`,
  `third-party-developer.template`, `third-party-developer.sample-app-flow`,
  `third-party-developer.submission-checklist`, `third-party-developer.compatibility-window`,
  `third-party-developer.feedback-workflow`, `third-party-developer.plugin-author-migration`,
  `third-party-developer.redaction`, `catalog.smoke`,
  `app-catalog.first-party-beta`, `catalog.production-channels`,
  `catalog.operations-and-mirrors`, `app-catalog.first-party-maintenance-policy`,
  `catalog.security-advisories`,
  `catalog.version-denylist`, `app-review.receipt-revocation`,
  `app-review.reviewer-key-compromise-flow`, `app-update.security-denylist-gates`,
  `web-shell.security-advisory-trust-warnings`,
  `ecosystem-security.advisory-revocation-redaction`, `production-security.response-runbook`,
  `platform-api.contract`,
  `platform-api.stable-baseline`, `platform-api.stable-breaking-change-check`,
  `platform-api.compatibility-window`, `platform-api.previous-contract-snapshot`,
  `platform-api.deprecation-window-policy`, `platform-api.experimental-graduation-policy`,
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
  `network-scale.redaction`, `network-scale.rc-soak-summary`, `multi-node-beta.soak`,
  `multi-node-beta.upgrade-drill`, `multi-node-beta.catalog-channel-update`,
  `multi-node-beta.app-install-update-rollback`, `multi-node-beta.app-data-migration`,
  `multi-node-beta.backup-restore`, `multi-node-beta.subscription-pressure`,
  `multi-node-beta.trust-graph-import`, `multi-node-beta.social-inbox-multi-source`,
  `multi-node-beta.support-bundle-drill`, `multi-node-beta.redaction`, and
  `release-certification.ecosystem-matrix`, `production-beta.go-no-go-dashboard`,
  `production-beta.go-no-go-decision`, `production-beta.waiver-validation`,
  `production-beta.dashboard-redaction`, and `production-beta.launch-artifact-hygiene`.
- Platform API stable-history checks compare the stable baseline name/counts/lists, stable endpoint
  required-capability sets, stable endpoint action labels, stable endpoint app-process/app-browser
  access flags, and compatibility-window metadata. App-platform smoke evidence must also inspect
  `stableDescriptorDeprecations` and fail `platform-api.deprecation-window-policy` when a stable
  descriptor is deprecated or scheduled for removal without valid metadata, has a future
  `deprecatedSinceContractVersion`, or publishes a too-short `removalContractVersion` window. In
  production history mode, missing previous baseline, compatibility-window, or endpoint metadata is
  a blocker; developer dry runs may warn when no production history is available.
- `catalog.operations-and-mirrors` is deterministic source-level evidence. It must verify the
  primary-plus-mirrors model, mirror fallback with signed verification, stale/downgrade
  prevention, bounded verified revision history, explicit rollback re-verification, key-rotation
  status visibility, emergency advisory refresh support, Platform API/Web Shell wiring, docs
  coverage, and redaction without requiring live mirror infrastructure or production signing keys.
- Network-scale release-candidate evidence must be generated fresh by the wrapper or attached
  explicitly. Do not let the aggregator reuse stale default `network-scale-soak/summary.json`
  files across release workspaces.
- Multi-node beta release-candidate evidence must be generated fresh by the wrapper or attached
  explicitly. Do not use the checked-in self-test topology as production promotion evidence, and do
  not let the aggregator reuse stale default `multi-node-beta-soak/summary.json` files across
  release workspaces.
- Stable readiness generated by the production beta wrapper must use
  `evidence/stable-readiness-multi-node-beta-soak.json` and
  `evidence/stable-readiness-network-scale-soak.json`, not the compact generic soak extracts. Those
  Stable-specific files preserve freshness metadata for the readiness gate.
- Stable readiness redaction is non-waivable. Keep dashboard redaction status separate from release
  artifact redaction status, and gate archive/upload decisions on both plus Stable readiness
  redaction when Stable artifacts are generated. Do not forward production beta go/no-go waiver
  files into Stable validation unless the waiver file is explicitly Stable-scoped.
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
  paths, staged bundle paths, rollback backup paths, multi-node node profile paths, previous
  candidate archive paths, UI lint report paths, or other unsanitized local paths. The aggregator
  filters `artifacts/private-insert-uris.json` even when interop summaries reference it.
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
  URI are available. Artifact uploads and job-summary dashboard publication must stay gated on the
  production-beta redaction summary, `go-no-go-redaction-report.json`, and any generated Stable
  readiness redaction status passing.
- Release notes should mention interop, performance, or certification gate changes only when they
  affect release readiness, operator confidence, app/platform behavior, or packager workflows.
