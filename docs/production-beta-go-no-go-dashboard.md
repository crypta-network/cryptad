# Production beta go/no-go dashboard

This document explains how release managers generate and read the production beta go/no-go
dashboard.

## Scope

The dashboard is a final review surface over existing sanitized release outputs. It consumes the
production beta summary, release-certification summary, ecosystem matrix, app-platform smoke
summary, live-network evidence when required, network-scale soak evidence, multi-node beta soak
evidence, security response evidence, and optional waiver records.

The dashboard does not sign artifacts, collect live-node evidence, approve third-party apps, or
replace release certification. It records one release-manager decision:

```text
go
no-go
go-with-waivers
```

## Generate the dashboard

The production beta pipeline writes the dashboard automatically under
`build/production-beta-release/reports/`:

```text
reports/go-no-go-dashboard.json
reports/go-no-go-dashboard.md
reports/go-no-go-redaction-report.json
```

You can also generate it directly from existing redacted summaries:

```bash
python3 tools/release-certification/production_beta_go_no_go_dashboard.py build \
  --workspace-root . \
  --out-dir build/production-beta-go-no-go \
  --production-beta-summary build/production-beta-release/reports/production-beta-summary.json \
  --release-certification-summary build/release-certification/release-certification-summary.json \
  --ecosystem-matrix build/release-certification/ecosystem-certification-matrix.json \
  --app-platform-summary build/app-platform-smoke/summary.json \
  --live-network-summary build/live-network-beta-smoke/summary.json \
  --network-scale-soak-summary build/network-scale-soak/summary.json \
  --multi-node-beta-soak-summary build/multi-node-beta-soak/summary.json \
  --security-response-summary build/security-response-runbook/summary.json \
  --waivers release/waivers.json \
  --mode production-beta
```

Run the offline fixture tests with:

```bash
python3 tools/release-certification/production_beta_go_no_go_dashboard.py --self-test
```

The self-test does not require Gradle, signing keys, network access, or a live node.

## Required inputs

Production beta mode fails closed when these critical inputs are missing or malformed:

| Input | Purpose |
| --- | --- |
| `production-beta-summary.json` | Top-level pipeline status, promotion gates, signing profile, redaction status, and artifact references. |
| `release-certification-summary.json` | Ecosystem RC decision, evidence ids, gates, history comparison, and waiver records. |
| `ecosystem-certification-matrix.json` | Matrix rows, release blocker count, coverage, docs mapping, and redaction coverage. |
| `app-platform-smoke/summary.json` | Platform API freeze, app signing, catalog/review, consent, legacy admin, third-party developer beta, and security response evidence. |
| `live-network-beta-smoke/summary.json` | Required production beta live-network smoke evidence. |
| `network-scale-soak/summary.json` | Network-scale budget, pressure, and redaction evidence. |
| `multi-node-beta-soak/summary.json` | Multi-node soak, upgrade drill, scenario, and redaction evidence. |

Developer dry-runs tolerate missing production-only inputs so PR and local runs remain CI-safe. A
dry-run can complete successfully, but the dashboard still marks non-release artifacts as
`no-go` for publication.

## Decision states

`go` means all required production beta gates pass, the production summary is promotion-ready,
production signing is used, `nonRelease=false`, redaction passed, and there are no unwaived
blockers.

`go-with-waivers` means every remaining blocker is waivable and has a valid, scoped, approved, and
unexpired waiver. The waiver remains visible in JSON and Markdown. Waived blockers are not hidden
or converted to `pass`.

`no-go` means at least one of these conditions exists:

- unwaived blocker or critical finding;
- missing critical production-beta input;
- failed critical production gate;
- invalid, expired, unknown-target, or out-of-scope waiver;
- critical redaction finding;
- unsafe artifact hygiene finding such as AppleDouble metadata, `.DS_Store`, or `__MACOSX`;
- production beta mode using test-only or generated signing material;
- production beta artifact marked `nonRelease=true`.

## Waiver format

The dashboard accepts a JSON waiver file:

```json
{
  "schemaVersion": 1,
  "releaseId": "crypta-production-beta-2026-06-24",
  "waivers": [
    {
      "id": "waiver-live-network-lab-outage-001",
      "evidenceId": "live.live-network-beta.content-fetch",
      "severity": "blocker",
      "scope": "production-beta",
      "rationale": "Lab live node unavailable during the RC window.",
      "approvedBy": "release-manager@example.invalid",
      "owner": "release-engineering",
      "createdAt": "2026-06-24T00:00:00Z",
      "expiresAt": "2026-06-30T00:00:00Z",
      "references": ["internal-ticket-1234"]
    }
  ]
}
```

Each waiver must include `id`, `evidenceId`, `severity`, `scope`, `rationale`, `approvedBy`,
`owner`, and `expiresAt`. `expiresAt` must be in the future at dashboard generation time. Scope is
exact; `release-candidate-only` does not apply to production beta.

Unknown evidence ids are rejected unless the waiver explicitly sets
`externalRiskAccepted=true`. External risk waivers still need owner, approver, rationale, scope,
and expiry.

## Non-waivable findings

These findings always produce `no-go`:

- private insert URI, private key material, bearer token, app token, browser-session token, form
  password, authorization header, CI secret value, raw fetched content, raw app data, raw backup
  payload, or local absolute path in dashboard inputs or outputs;
- AppleDouble `._*`, `.DS_Store`, `__MACOSX/`, secret-like filenames, key-store files, symlinks,
  special files, invalid archives, or unsafe nested archive entries;
- production beta using test-only signing material or generated test keys;
- production beta output marked `nonRelease=true`;
- malformed or expired waiver records.

The scanner allows deterministic placeholders such as `<redacted-private-insert-uri>`,
`<redacted-token>`, `<repo>`, `<workdir>`, `<home>`, and `<redacted-absolute-path>`.

## Reading the Markdown dashboard

Start with the topline:

- Release ID;
- mode;
- decision;
- promotion-ready boolean;
- recommendation.

Then review:

- top blockers;
- top warnings;
- waivers used;
- domain table;
- redaction status;
- required follow-ups;
- redacted artifact references.

The Markdown report only links or names redacted artifacts. It must not include raw JSON dumps,
raw command output, local absolute paths, or secret-bearing values.

## CI behavior

The production beta GitHub Actions workflow writes the dashboard during both dry-run and protected
production-beta jobs. The workflow appends the Markdown dashboard to the job summary only when the
production beta redaction status is `pass` and the dashboard's own redaction report status is
`pass`.

Protected `production-beta` dispatches fail on `no-go`. A `go-with-waivers` decision is allowed
only when the dashboard validates and records the waiver records that made the candidate
launchable.

## Release-manager workflow

1. Generate the production beta pipeline outputs.
2. Open `reports/go-no-go-dashboard.md`.
3. If the decision is `no-go`, resolve the listed blockers and regenerate the dashboard.
4. If the decision is `go-with-waivers`, confirm each waiver owner, approver, scope, expiry, and
   release-record reference.
5. Preserve the JSON dashboard, Markdown dashboard, redaction report, production beta summary,
   release-certification summary, ecosystem matrix, evidence directory, checksums, and public
   archive with the release candidate.
