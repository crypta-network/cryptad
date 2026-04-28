---
name: cryptad-interop-performance-gates
description: "Maintain Cryptad's Hyphanet interop and performance regression gates under tools/interop, tools/perf, CI jobs, and release-readiness documentation."
---

# Cryptad interop and performance gates

Use this skill before changing `tools/interop`, `tools/perf`, related CI jobs, or release-gate
documentation.

## Read first

- Hyphanet interop gate: `tools/interop/README.md`
- Performance regression gate: `tools/perf/README.md`
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
  distribution size, Web Shell asset size, SDK asset size, and first-party static app asset size
  signals. It is not a broad benchmark suite.
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

## CI and release notes

- `.github/workflows/ci.yml` runs `interop-smoke` on push/PR, `interop-extended` on schedule/manual,
  interop self-tests on the multi-OS matrix, performance self-tests on the multi-OS matrix, and
  `performance-smoke` on schedule/manual.
- Release notes should mention interop/performance gate changes only when they affect release
  readiness, operator confidence, app/platform behavior, or packager workflows.
