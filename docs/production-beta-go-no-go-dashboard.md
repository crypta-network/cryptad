# Production beta go/no-go dashboard

This document explains how release managers generate and read the production beta go/no-go
dashboard.

## Scope

The dashboard is a final review surface over existing sanitized release outputs. It consumes the
production beta summary, release-certification summary, ecosystem matrix, app-platform smoke
summary, first-party beta quality evidence, live-network evidence when required, network-scale soak
evidence, multi-node beta soak evidence, security response evidence, and optional waiver records.

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
  --security-drills-summary build/security-drills/security-drills-summary.json \
  --waivers release/waivers.json \
  --mode production-beta
```

`--security-response-summary` remains a developer dry-run legacy fallback. Strict
release-candidate and production-beta dashboard runs must pass `--security-drills-summary`.

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
| `multi-node-beta-soak/summary.json` | Multi-node soak, previous-candidate upgrade drill, scenario, app migration, backup/restore, Social Inbox, Trust Graph, support-bundle, and redaction evidence. |
| `security-drills/security-drills-summary.json` | Operational production security response drill summary, required scenario status, artifact digests, release-notes/advisory template status, and aggregate redaction status. |
| `third-party-intake-summary.json` | Optional third-party app intake summary copied by the release wrapper when `--third-party-intake-summary` or `--run-third-party-intake-sample-flow` is used. |

Developer dry-runs tolerate missing production-only inputs so PR and local runs remain CI-safe. A
dry-run can complete successfully, but the dashboard still marks non-release artifacts as
`no-go` for publication.

The dashboard has a dedicated `first-party-app-beta-quality` domain for
`first-party-app.beta-quality-pass`. Missing beta-quality evidence is a blocker in production beta,
and diagnostics redaction findings in that evidence are non-waiverable. Copy or accessibility
warnings may be displayed as risk, but they do not hide the domain from the go/no-go summary.

The dashboard also has a dedicated `trust-social-content-format-risk` domain for
`app-platform.trust-social-content-format-profiles`. Missing or failing content-format evidence is
a blocker when it indicates registry, SDK, route, trust graph, canonical signing, parser, app UI,
or docs drift. Dashboard inputs and outputs may include profile ids, status, failed check names,
digests, and redaction booleans, but they must not include raw fetched content, raw document
bodies, raw social message bodies, raw trust statements, raw feed bodies, raw signatures, private
insert URIs, private keys, tokens, browser sessions, raw app-data values, or absolute local paths.

The dashboard also has a dedicated `privacy-preserving-diagnostics-risk` domain. It ties
`app-platform.privacy-preserving-beta-diagnostics`, `operator-beta.support-bundle-redaction`,
`operator-rc.support-bundle-wizard`, and `multi-node-beta.support-bundle-drill` together. Missing
support-bundle schema, missing preview/export routes, unsafe lifecycle summaries, raw legacy
plaintext diagnostics in the default bundle, or redaction fixture failures are `no-go` conditions
in production beta. Redaction failures in this domain are non-waivable.

The dashboard also has a dedicated `public-beta-docs-onboarding` domain. It ties
`public-beta.docs-onboarding`, `public-beta.user-guide`, `public-beta.developer-quickstart`,
`public-beta.troubleshooting`, `public-beta.security-reporting`, `public-beta.limitations`, and
`public-beta.links-redaction` together. Missing public-beta onboarding docs, missing
user/operator/developer/security/troubleshooting paths, missing Trust Graph Local RC or Social
Inbox RC limitations, broken required public-beta Markdown links, or unsafe public-beta docs
examples are `no-go` conditions in production beta. Redaction findings for private insert URIs,
private keys, app/browser tokens, raw support bundles, raw fetched/social/trust/profile/feed/app
data, unsafe file URI links, or absolute local paths are non-waivable.

The dashboard also has a dedicated `public-beta-support-feedback-loop` domain. It ties
`public-beta.support-feedback-loop`, `public-beta.support-feedback-docs`,
`public-beta.issue-templates`, `public-beta.triage-taxonomy`,
`public-beta.known-issues-tracker`, `public-beta.feedback-to-backlog`,
`public-beta.release-notes-template`, `public-beta.support-bundle-guidance`,
`public-beta.security-reporting-handoff`, `public-beta.app-specific-feedback`,
`public-beta.catalog-incident-feedback`, and `public-beta.redaction-fixtures` together. Missing
support-feedback docs, missing issue templates, missing required redaction confirmation, missing
known issue tracker, missing beta release notes template, missing security handoff, unsafe
redaction fixture behavior, or redaction-unsafe known issue/release note/support feedback evidence
is `no-go` for production beta. Minor deterministic taxonomy wording gaps may be warnings only when
the artifacts remain complete and redaction-safe.

The `production-security-response` domain consumes the
`cryptad-security-response-drills-summary` artifact. The dashboard reports required, passed,
failed, missing, stale, and malformed scenario counts; aggregate redaction status;
release-notes/advisory template status; support-bundle intake redaction status; fixture-only and
non-release markers; and the critical blockers derived from the summary. A missing summary, missing
required scenario, failed scenario, stale artifact, malformed envelope, fixture-only production
summary, or critical redaction finding is `no-go`. Redaction findings from security drills are
non-waivable, and waiver attempts for critical drill redaction are recorded as invalid.

These content profiles are Crypta app ecosystem profiles. They are not compatibility promises for
legacy WoT, Freetalk, Sone, Freemail, or any old plugin ABI/protocol.

The dashboard also has a dedicated `legacy-plugin-migration-finalization` domain for
`legacy-plugin.migration-finalization`. Missing or failing evidence is a no-go condition when the
failure means the cookbook, matrix, examples, app-service dependency examples,
data/identity/subscription preservation guidance, beta submission path, source-surface audit,
legacy-admin maintenance-only boundary, retained FProxy browse boundary, or migration artifact
redaction checks are incomplete. Source-surface reintroduction, old plugin compatibility shims, old
FCP plugin command compatibility, or migration artifact redaction leaks are non-waivable blockers.

## Decision states

`go` means all required production beta gates pass, the production summary is promotion-ready,
production signing is used, `nonRelease=false`, redaction passed, and there are no unwaived
blockers.

`go-with-waivers` means every remaining blocker is waivable and has a valid, scoped, approved, and
unexpired waiver. The waiver remains visible in JSON and Markdown. Waived blockers are not hidden
or converted to `pass`. In `production-beta` mode, mandatory launch evidence is not waivable; a
`go-with-waivers` decision is possible only for waiverable residual blockers outside the strict
production launch set.

`no-go` means at least one of these conditions exists:

- unwaived blocker or critical finding;
- missing critical production-beta input;
- failed critical production gate;
- invalid, expired, unknown-target, or out-of-scope waiver;
- critical redaction finding;
- unsafe artifact hygiene finding such as AppleDouble metadata, `.DS_Store`, or `__MACOSX`;
- production beta mode using test-only or generated signing material;
- production beta artifact marked `nonRelease=true`;
- missing security drill summary, missing required scenario, failed scenario, stale drill artifact,
  malformed drill envelope, fixture-only production drill, or drill redaction finding;
- missing or redaction-unsafe public beta support-feedback-loop evidence, including missing
  structured issue templates, known issues tracker, release notes template, security handoff, or
  redaction fixtures;
- missing public-beta onboarding docs, missing public-beta security reporting path, missing
  Trust Graph/Social Inbox limitation wording, broken required public-beta docs links, or unsafe
  public-beta docs redaction finding;
- production beta summary with failed promotion gates or `promotionReady=false`.

Previous-candidate upgrade evidence is a production-beta launch blocker. Missing, failing, warning,
or redaction-unsafe previous-candidate evidence makes the dashboard decision `no-go` in
production-beta mode. A warning is allowed only in developer or PR-safe contexts where the
candidate remains non-release.

Third-party app intake rows are shown in the app submission and review workflow domain as
`third-party-intake.queue-schema` through `third-party-intake.redaction`. Missing rows are warnings
unless the production beta release wrapper was run with `--require-third-party-intake`. When intake
is required, the production summary includes failed `third-party-intake.*` promotion gates for
missing sample flow, failed reviewer assignment, failed pre-review artifacts, failed
install-from-beta-catalog smoke, rejected-candidate bypass, missing caution warning, non-production
fixture evidence, or failed redaction. Redaction findings remain critical because the dashboard
must not publish raw submission contents, private insert URIs, private keys, tokens, raw app data,
or absolute local paths.

## Waiver format

The dashboard accepts a JSON waiver file:

```json
{
  "schemaVersion": 1,
  "releaseId": "crypta-production-beta-2026-06-24",
  "waivers": [
    {
      "id": "waiver-release-candidate-doc-followup-001",
      "evidenceId": "app-store.submission-cli",
      "severity": "blocker",
      "scope": "release-candidate",
      "rationale": "Release-candidate docs follow-up is accepted before production-beta promotion.",
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

The dashboard also accepts the existing release-certification structured waiver schema
(`version`, `reason`, `status: approved`, `allowReleaseCandidate`) so a release-candidate pipeline
can pass one waiver file through release certification and the final dashboard. When a record has
no dashboard `scope`, `allowReleaseCandidate=true` maps to release-candidate scope only; it is not
treated as a production-beta waiver.

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
- missing public beta support-feedback-loop evidence or missing redaction confirmation in a
  required public beta feedback template;
- fixture evidence, skipped Gradle build/stage/sign/verify stages, or dirty/unknown workspace in
  production beta;
- missing or failing live-network beta evidence, sandbox provider evidence, production signing,
  previous-candidate summary validation, previous-candidate multi-node upgrade evidence,
  multi-node redaction, security drill redaction, or ecosystem RC gates in production beta;
- missing or failing legacy plugin migration finalization evidence in production beta;
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
- previous candidate upgrade section;
- redaction status;
- required follow-ups;
- redacted artifact references.

The previous candidate upgrade section reports:

| Field | Meaning |
| --- | --- |
| Previous release | `releaseId` from the verified previous beta candidate summary. |
| Previous version | Version upgraded from. |
| Current version | Version upgraded to. |
| Previous summary | Whether the configured previous summary was provided, schema-valid, passing, and promotable. |
| Evidence binding | Whether `previousSummaryDrillDigest` in the multi-node upgrade evidence matches the supplied previous summary metadata. |
| Upgrade drill | `multi-node-beta.upgrade-drill` status. |
| App migrations | Feed Reader, Social Inbox, and Trust Graph app-data migration status. |
| Backup before update | Whether backup-before-update coverage passed. |
| Restore into clean node | Whether restore portability passed. |
| Social Inbox | Social Inbox schema migration status without raw message bodies. |
| Trust Graph | Trust Graph state migration status without raw trust statements. |
| Support bundle | Redaction status for the support bundle generated after the failed upgrade path. |

The dashboard treats waiver attempts for critical previous-candidate redaction or security findings
as invalid. Waivers can document release-manager context, but they cannot convert raw/private
material or missing production upgrade evidence into a launchable `go`.

The Markdown report only links or names redacted artifacts. It must not include raw JSON dumps,
raw command output, local absolute paths, or secret-bearing values.

## CI behavior

The production beta GitHub Actions workflow writes the dashboard during both dry-run and protected
production-beta jobs. The workflow appends the Markdown dashboard to the job summary only when the
production beta redaction status is `pass` and the dashboard's own redaction report status is
`pass`.

Protected `production-beta` dispatches fail on `no-go`. A `go-with-waivers` decision is allowed
only when the dashboard validates and records the waiver records that made the candidate
launchable and the production summary already has `promotionReady=true`, `nonRelease=false`, no
failed promotion gates, and passing redaction. The release wrapper treats any launchable dashboard
decision over a failed or non-release production summary as a failed run.

## Release-manager workflow

1. Generate the production beta pipeline outputs.
2. Open `reports/go-no-go-dashboard.md`.
3. If the decision is `no-go`, resolve the listed blockers and regenerate the dashboard.
4. If the decision is `go-with-waivers`, confirm each waiver owner, approver, scope, expiry, and
   release-record reference.
5. Preserve the JSON dashboard, Markdown dashboard, redaction report, production beta summary,
   release-certification summary, ecosystem matrix, evidence directory, checksums, and public
   archive with the release candidate.
