# Release certification

Release certification is the reproducible evidence bundle for a Cryptad release candidate.  It
aggregates compatibility, performance, app-platform, catalog, app-owned UI, legacy-admin
retirement, and CI metadata into one redacted report.

The generated artifacts are:

```text
build/release-certification/release-certification-summary.json
build/release-certification/release-certification-report.md
build/release-certification/artifacts/
```

The Markdown report is intended for human release review.  The JSON summary is the stable
machine-readable companion for later automation and report comparison.

## Modes

| Mode | Purpose | Behavior |
| --- | --- | --- |
| `pr` | Quick local or normal PR evidence. | Runs Python-only certification and lightweight app-platform checks.  It does not require a live node, signing keys, Hyphanet baseline download, or packaged-node smoke. |
| `nightly` | Scheduled/manual evidence aggregation. | Records missing optional evidence as warnings and can run heavier app-platform checks. |
| `release-candidate` | Strict release gate. | Fails when required evidence is missing, skipped, or failing unless a release-manager waiver is recorded. |

## Run locally

The release-certification tools require Python 3.10 or newer and use only the Python standard
library.

Run self-tests first:

```bash
python3 tools/release-certification/release_certification.py --self-test
python3 tools/release-certification/app_platform_smoke.py --self-test
```

Generate a lightweight local report:

```bash
tools/release-certification/run-release-certification.sh
```

The wrapper may be invoked from outside the repository. Relative `--out-dir` values are resolved
under the repository root so shell cleanup, app-platform smoke output, and aggregation read the same
evidence directory.

Generate a release-candidate report:

```bash
tools/release-certification/run-release-certification.sh \
  --mode release-candidate \
  --out-dir build/release-certification
```

The wrapper consumes the existing gate outputs when present:

```text
build/interop-smoke/summary.json
build/interop-extended/summary.json
build/perf-smoke/summary.json
build/perf-smoke/artifacts/perf-report.md
build/release-certification/app-platform-smoke/summary.json
```

Run the source gates before the release-candidate aggregation when their evidence is required:

```bash
tools/interop/run-hyphanet-interop-smoke.sh
INTEROP_MODE=extended INTEROP_SKIP_BUILD=1 tools/interop/run-hyphanet-interop-smoke.sh
tools/perf/run-performance-smoke.sh
```

## Required evidence

Release-candidate mode requires these evidence ids:

| Evidence id | Source | Required condition |
| --- | --- | --- |
| `interop.smoke` | `build/interop-smoke/summary.json` | Tier 1 Hyphanet interop smoke passed with CHK, SSK, USK, peer exchange, and restart-recovery coverage. |
| `performance.smoke` | `build/perf-smoke/summary.json` | Performance smoke did not fail required metrics or deterministic regression thresholds. |
| `app-platform.first-party` | App-platform smoke summary. | First-party staged apps have valid manifests, launchers, static UI assets, and SDK wiring. |
| `app-platform.devtools-cli` | App-platform smoke summary. | `crypta-app init`, `validate`, and `pack` work for a generated sample app. |
| `app-platform.signed-bundles` | App-platform smoke summary. | First-party and sample bundle signing/verification evidence exists with configured non-production or release signing inputs. |
| `catalog.smoke` | App-platform smoke summary. | Signed catalog create/sign/verify evidence exists and records digest, catalog id, and app id without private key material. |
| `platform-api.contract` | App-platform smoke summary. | The deterministic Platform API compatibility contract snapshot was generated, parsed, and used for offline compatibility verification of first-party/sample apps. |
| `app-ui.smoke` | App-platform smoke summary. | First-party static UI and `crypta-platform.js` remain coherent and do not expose process-token names. |
| `legacy.retirement` | App-platform smoke summary. | The legacy-admin retirement registry is visible, counts are stable, replaced surfaces are absent from primary shell fallback links, and direct fallback URLs remain documented. |
| `apphost.sandbox-provider` | App-platform smoke summary. | AppHost sandbox provider source and deterministic offline tests prove bubblewrap selection, enforced status reporting, fail-closed required sandbox behavior, and token/path-free public status. |
| `app-update.lifecycle` | App-platform smoke summary. | Offline source and test evidence proves manual/stage/apply-when-stopped update policy, candidate detection semantics, compatibility/review/permission gates, and process health-gated apply behavior. |
| `app-update.rollback` | App-platform smoke summary. | Offline source and test evidence proves durable installed-bundle backup/restore behavior and confirms rollback is scoped to the immutable bundle, not app data/cache/run state. |

`interop.extended` is optional in the machine gate but required by the release runbook when a
release changes compatibility-sensitive behavior. `apphost.sandbox-provider` does not require
host-installed bubblewrap in normal CI; it uses source checks and fake/offline provider tests.
`app-update.lifecycle` and `app-update.rollback` do not require a live node; missing update
evidence blocks release-candidate mode unless a release-manager waiver is recorded. `apphost.live`
is optional stronger evidence because normal PR and scheduled CI must not require a live local node
or operator form password.

`platform-api.contract` is generated offline with `crypta-app api snapshot`. In
release-candidate mode, snapshot generation failure, contract parse failure, missing contract
evidence, or strict compatibility verifier failure is a blocker unless a release-manager waiver is
recorded.

## Waivers

Use waivers sparingly and only with a concrete release-manager reason:

```bash
tools/release-certification/run-release-certification.sh \
  --mode release-candidate \
  --waive interop.extended="No FCP, peer, datastore, restart, USK/SSK, packaging, or startup compatibility behavior changed."
```

A waiver turns that evidence item into `warn`, records `details.waived=true`, and includes the
reason in `details.waiverReason`.  Waivers are visible in both the report and the JSON summary.

Do not use waivers to hide failed required smoke evidence.  Fix the failing gate or record a
release-manager decision that explicitly accepts the risk.

## Optional live-node evidence

Live AppHost evidence is opt-in:

```bash
CRYPTAD_CERT_APP_SMOKE_LIVE=1 \
CRYPTAD_CERT_NODE_BASE_URL=http://127.0.0.1:<port> \
CRYPTAD_CERT_FORM_PASSWORD=<redacted> \
tools/release-certification/run-release-certification.sh --mode nightly
```

When enabled, the app-platform smoke runner uses the generated sample app and localhost Platform
API routes to install, read runtime status, start, stop, update, uninstall, and read diagnostics.
The live smoke only records localhost metadata, status codes, and redacted JSON response summaries.
It does not write the form password, raw request bodies, app process tokens, or browser-session
tokens.

## Redaction

The report and copied artifacts must not contain:

- private signing keys;
- app process tokens;
- app browser session tokens;
- the host/operator form password;
- raw request bodies;
- raw update or rollback command output;
- full query strings that may contain secrets;
- private insert URIs;
- absolute developer-specific filesystem paths;
- catalog scratch paths, staged bundle paths, installed bundle paths, data/cache/run paths, and
  rollback backup paths;
- non-localhost remote addresses.

`artifacts/private-insert-uris.json` from interop runs must never be uploaded or pasted into a
public release record.  The certification aggregator filters that private artifact reference and
copies only sanitized summaries and public reports into `build/release-certification/artifacts/`.
