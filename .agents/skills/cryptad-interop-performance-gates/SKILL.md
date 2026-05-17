---
name: cryptad-interop-performance-gates
description: "Maintain Cryptad's Hyphanet interop, performance regression, and release-certification evidence gates under tools/interop, tools/perf, tools/release-certification, CI jobs, and release-readiness documentation."
---

# Cryptad interop and performance gates

Use this skill before changing `tools/interop`, `tools/perf`, `tools/release-certification`,
related CI jobs, or release-gate documentation.

## Read first

- Hyphanet interop gate: `tools/interop/README.md`
- Performance regression gate: `tools/perf/README.md`
- Release certification workflow: `docs/release-certification.md`
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
  staged-bundle size signals for Queue Manager, Publisher, Site Publisher, Profile Publisher, and
  Feed Reader. It is not a broad benchmark suite.
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
  app-platform, catalog, app-owned UI, legacy-admin retirement, and CI metadata into:

```text
build/release-certification/release-certification-summary.json
build/release-certification/release-certification-report.md
build/release-certification/artifacts/
```

- `tools/release-certification/app_platform_smoke.py` produces the app-platform summary consumed by
  the aggregator. It keeps `--self-test` offline and Python-only, including source/test evidence
  for the Platform API contract, app-vault capability docs, signed catalogs, trusted app-review
  receipts, app-owned UI origin behavior, app UI design-system/lint evidence, Site Publisher
  reference-content coverage, Profile Publisher identity-profile coverage, Feed Reader
  content-fetch coverage, generated document insert/content-fetch redaction coverage,
  legacy-admin retirement/removal evidence, sandbox provider selection, and app-update
  lifecycle/scheduler/rollback.
- The wrapper resolves relative `--out-dir` values under the repository root, then runs the
  app-platform smoke collector before aggregation.
- Normal local commands:

```bash
python3 tools/release-certification/release_certification.py --self-test
python3 tools/release-certification/app_platform_smoke.py --self-test
tools/release-certification/run-release-certification.sh
tools/release-certification/run-release-certification.sh --mode release-candidate --out-dir build/release-certification
```

- Release-candidate mode fails when required evidence is missing, skipped, malformed, wrong-mode,
  or failing unless a release-manager waiver is recorded. Required app-platform evidence now
  includes `app-platform.first-party`, `app-platform.devtools-cli`,
  `app-platform.developer-beta-toolkit`, `app-platform.signed-bundles`, `catalog.smoke`,
  `app-catalog.first-party-beta`, `platform-api.contract`, `app-vault.capabilities`,
  `app-platform.identity-profile-publish`, `app-platform.generated-document-insert`,
  `app-platform.content-fetch`, `app-ui.design-system`, `app-ui.lint`,
  `app-ui.first-party-adoption`, `app-ui.smoke`, `reference-apps.content`,
  `reference-app.profile-publisher`, `reference-app.feed-reader`, `legacy.retirement`,
  `legacy-admin.removal-wave-1`, `apphost.sandbox-provider`, `app-update.lifecycle`,
  `app-update.scheduler`, `app-update.rollback`, `app-review.trusted-receipts`,
  `app-review.policy`, and `app-review.first-party-catalog`.
- Do not publish private signing keys, form passwords, app tokens, browser-session tokens, raw
  reviewer keys, raw trusted reviewer public key bytes, raw request bodies, raw feed bodies, raw
  update/rollback command output, private insert URIs, non-localhost endpoint metadata, catalog
  scratch paths, staged bundle paths, rollback backup paths, UI lint report paths, or other
  unsanitized local paths. The aggregator filters `artifacts/private-insert-uris.json` even when
  interop summaries reference it.

## CI and release notes

- `.github/workflows/ci.yml` runs `interop-smoke` on push/PR, `interop-extended` on schedule/manual,
  interop self-tests on the multi-OS matrix, performance self-tests on the multi-OS matrix,
  release-certification self-tests on the multi-OS matrix, and `performance-smoke` on
  schedule/manual.
- `.github/workflows/release-certification.yml` runs scheduled/manual/release-ref certification,
  uploads sanitized certification artifacts, and uses `release-candidate` mode for `release/**`
  branches and `v*` tags.
- Release notes should mention interop, performance, or certification gate changes only when they
  affect release readiness, operator confidence, app/platform behavior, or packager workflows.
