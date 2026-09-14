# Performance regression gate reference

Read for Performance regression gate. Commands and unlinked source paths are relative to the repository root.

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

## Authenticated runtime references

Use `docs/pr-308-authenticated-runtime-baselines.md` for the finite original reference campaign,
private attempt ledger, opaque proposal review context, pre-execution baseline selection, and
measurement v5/report v6 scoped consumer. Keep `runtime_baseline.py` as the pure arithmetic owner;
its v1 review remains local. The fixed scheduler workload is synthetic even when historical raw
series label protected execution `operational`. A narrow accepted resource component cannot
complete full app budgets, maintenance performance, or Phase 12. Normal Linux CI exercises native
private-file checks with synthetic original-provider seams; actual review and protected execution
remain separate operational inputs. Preserve PR-307's restricted-worker blocker.
