# Stable 1.0 readiness gate

Use Stable readiness to decide whether a promotable production-beta candidate satisfies the
additional compatibility, maturity, security, soak, support, migration, and limitations policy for
Stable 1.0.

## Run the gate

Copy the Stable review template, then configure production, dashboard, certification,
app-platform, soak, security, known-issue, policy, known-limitation, and Stable-scoped waiver inputs.
Every v2 input must be bound to the same finalized release ID.

```bash
cp tools/release-certification/manifests/stable-review.example.json \
  build/stable-review.json
# Replace every placeholder before running the review.
python3 tools/release-certification/certify.py stable-readiness \
  --manifest build/stable-review.json
```

The command writes evidence envelope v2 under `<out-root>/<release-id>/stable-readiness/`. The
summary, report, redaction report, blocker list, and known-limitations artifact contain only
sanitized metadata and relative references.

A passing readiness decision measures whether the candidate is eligible for Stable review; it
does not freeze, package, tag, or publish the candidate. To cut a reviewable release candidate, use
the one-command [Stable 1.0 RC execution and release-freeze workflow](stable-1.0-rc-execution-and-release-freeze.md).
That protected workflow generates Stable readiness inside the same `stable-review` run, copies
every allowed limitation into the freeze and RC notes, and verifies the packaged candidate for
post-freeze drift.

## Decisions

- `ready` means all required Stable domains pass and no allowed limitation remains open.
- `ready-with-allowed-limitations` means the candidate has no blocker or disallowed limitation,
  but policy explicitly permits a bounded limitation that remains visible in the release record.
- `not-ready` means at least one Stable blocker, disallowed limitation, beta-only limitation,
  redaction failure, or non-waivable evidence failure remains.

Warnings can coexist with `ready`; they remain visible and set their domains to warning status.
A candidate-bound go/no-go v2 envelope with `go-with-waivers` therefore reaches Stable policy
evaluation as warning evidence. Stable readiness evaluates the referenced waivers rather than
rejecting the envelope before policy processing.

## Required domains

Stable review validates production release state, release certification, Platform API 1.0
compatibility, first-party app maturity, third-party intake, security drills, live/multi-node and
network-scale soak, legacy migration, public-beta support/feedback, known limitations, and artifact
redaction.

Every input must use the same release ID. Production evidence must be release-capable, not
fixture-only, test-signed, dirty, skipped, or marked non-release. Security and soak evidence must be
fresh according to policy and retain per-scenario freshness metadata.
Generated Stable multi-node soak extracts carry the manifest release ID explicitly; the project
version remains version metadata and is not used to synthesize a different candidate identity.

## Non-waivable blockers

Redaction findings, non-promotable production beta, `no-go`, missing release certification,
missing Platform API stable baseline, unsupported stable API breaks, stale or fixture-only security
drills, missing previous-candidate upgrade evidence, insufficient live/multi-node/network-scale
coverage, incomplete stable first-party app recovery/support metadata, critical known issues, and
unreplaced mutating legacy-admin paths always block Stable 1.0.

Stable waivers require explicit Stable scope and complete approval metadata. Production-beta
dashboard waivers are not forwarded automatically.

## V1 history

Stable consumers accept only evidence envelope v2. Migrate the previous candidate and history with
`certify.py migrate-v1` before the first v2 Stable review.
