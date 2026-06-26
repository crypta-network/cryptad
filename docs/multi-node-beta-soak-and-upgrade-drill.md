# Multi-node beta soak and upgrade drill

This guide describes the multi-node beta soak and upgrade drill used by release certification and
the production beta release pipeline.

## Scope

The drill models or exercises several beta nodes as one release-candidate topology. It checks
catalog channel behavior, previous-candidate upgrade readiness, first-party app install and update
paths, rollback, app-data migration, backup and restore, subscription pressure, Trust Graph import,
Social Inbox multi-source behavior, support bundle redaction, and final release evidence
consumption.

The drill does not create a distributed testnet manager, change peer protocols, or replace the
existing app-platform smoke, live-network beta smoke, network-scale soak, security response, or
release-certification tools. It consumes and complements those tools.

## Modes

| Mode | Purpose | Network behavior |
| --- | --- | --- |
| `simulated` | PR-safe and local deterministic evidence. | Does not contact nodes, use secrets, or require live network access. |
| `hybrid` | Attach existing smoke, release, or previous-candidate summaries while still using deterministic topology checks. | Reads only local summary files named in the topology config. |
| `live` | Release-manager drill against prepared local beta nodes. | May check configured localhost node base URLs. `--require-live` fails closed if no configured localhost node is reachable. |

Normal pull requests and developer dry-runs use `simulated`. Release-candidate runs can use
`simulated` or `hybrid`. Protected production beta promotion requires attached passing evidence or
an explicit production `hybrid`/`live` topology. `simulated` and the checked-in self-test topology
are PR-safe only and cannot satisfy production promotion gates.

## Topology config

The topology config is JSON with `schemaVersion=1` and
`kind=cryptad-multi-node-beta-soak-config`. It describes candidate versions, catalog channels,
nodes, enabled scenarios, and redaction checks.

Use the checked-in deterministic fixture as the starting point:

```bash
python3 tools/release-certification/multi_node_beta_soak.py plan \
  --config tools/release-certification/fixtures/self-test-multi-node-beta-soak.json \
  --out build/multi-node-beta-soak/plan.json
```

Required top-level fields are:

| Field | Meaning |
| --- | --- |
| `mode` | `simulated`, `hybrid`, or `live`. The CLI `--mode` can override it. |
| `durationProfile` | `ci-smoke`, `rc-soak`, or `24h-soak`. Simulated time is used for CI-safe runs. |
| `previousCandidate` | Previous beta version, optional previous summary path, and previous catalog channel. |
| `currentCandidate` | Current beta version, optional production beta summary path, and current catalog channel. |
| `nodes` | Two or more modeled nodes with stable ids, roles, catalog channels, and installed app ids. |
| `scenarios` | Boolean switches for each required drill scenario. |
| `redaction` | Redaction fail-closed switches for private insert URIs, raw fetched content, tokens, and local paths. |
| `strict` | Optional strictness controls, including whether a previous-candidate summary is required. |

The tool rejects unknown modes, invalid catalog channels, duplicate node ids, invalid app ids, and
unsupported config fields. Live node URLs, when present, must be localhost-only and must not contain
credentials, query strings, or fragments.

## Scenarios

The generated summary contains one status per scenario:

| Scenario | Evidence id | What it proves |
| --- | --- | --- |
| `catalog-channel-update` | `multi-node-beta.catalog-channel-update` | Stable nodes stay on stable apps, beta opt-in is explicit, deprecated and denylisted candidates are blocked, and catalog signature or review-chain evidence is represented. |
| `app-install-update-rollback` | `multi-node-beta.app-install-update-rollback` | First-party apps install, Feed Reader, Social Inbox, and Trust Graph update, a health failure triggers rollback, and major update consent gates remain enforced. |
| `app-data-migration` | `multi-node-beta.app-data-migration` | Migration dry-runs exist, backup-before-update is enforced, failed migrations block update or trigger rollback, and only schema or digest metadata is reported. |
| `backup-restore` | `multi-node-beta.backup-restore` | Feed Reader, Social Inbox, and Trust Graph app data can be exported and restored into a clean profile without mixing support exports and backup bundles. |
| `subscription-pressure` | `multi-node-beta.subscription-pressure` | Multiple USK subscriptions exercise queue pressure, backoff, and global fetch policy without recording fetched bodies. |
| `trust-graph-import` | `multi-node-beta.trust-graph-import` | Trust Graph imports are bounded, duplicate, hostile, and oversized inputs are summarized safely, and local-scope wording remains intact. |
| `social-inbox-multi-source` | `multi-node-beta.social-inbox-multi-source` | Social Inbox covers multiple sources, dedupe, thread state, read state, Trust Graph score grants, revoke behavior, and degrade behavior. |
| `support-bundle-drill` | `multi-node-beta.support-bundle-drill` | Support bundles can be generated after failed update, subscription pressure, or advisory events and pass redaction scans. |
| `upgrade-from-previous-candidate` | `multi-node-beta.upgrade-drill` | Previous beta candidate evidence can be consumed, the current upgrade path is represented, and migration, backup, and rollback status are included. |
| Redaction | `multi-node-beta.redaction` | The JSON and Markdown artifacts contain no private insert URI, private key, token, raw content, raw app data, local path, or forbidden archive sidecar reference. |

## Local commands

Run the self-test:

```bash
python3 tools/release-certification/multi_node_beta_soak.py --self-test
```

Run the deterministic simulated drill:

```bash
python3 tools/release-certification/multi_node_beta_soak.py run \
  --mode simulated \
  --out-dir build/multi-node-beta-soak
```

Verify the generated summary:

```bash
python3 tools/release-certification/multi_node_beta_soak.py verify \
  --summary build/multi-node-beta-soak/multi-node-beta-soak-summary.json
```

Use a topology config:

```bash
python3 tools/release-certification/multi_node_beta_soak.py run \
  --config tools/release-certification/fixtures/self-test-multi-node-beta-soak.json \
  --mode simulated \
  --out-dir build/multi-node-beta-soak
```

Use strict verification when production promotion must fail on warnings or missing scenarios:

```bash
python3 tools/release-certification/multi_node_beta_soak.py verify \
  --summary build/multi-node-beta-soak/multi-node-beta-soak-summary.json \
  --strict
```

## Release certification

`tools/release-certification/run-release-certification.sh` generates
`build/release-certification/multi-node-beta-soak/summary.json` by default unless
`--multi-node-soak-summary` or `CRYPTAD_CERT_MULTI_NODE_SOAK_SUMMARY` attaches an external summary.

Release certification consumes these evidence ids:

```text
multi-node-beta.soak
multi-node-beta.upgrade-drill
multi-node-beta.catalog-channel-update
multi-node-beta.app-install-update-rollback
multi-node-beta.app-data-migration
multi-node-beta.backup-restore
multi-node-beta.subscription-pressure
multi-node-beta.trust-graph-import
multi-node-beta.social-inbox-multi-source
multi-node-beta.support-bundle-drill
multi-node-beta.redaction
```

The ecosystem matrix row is `multi-node-beta-soak-and-upgrade-drill`. Release-candidate mode
requires the evidence to be present. Warnings are visible in the matrix and summary. Redaction
findings remain unwaivable blockers.

## Production beta pipeline

The production beta command can run or attach the drill:

```bash
tools/release-certification/run-production-beta-release.sh \
  --mode developer-dry-run \
  --multi-node-mode simulated \
  --run-multi-node-soak
```

The canonical protected production command attaches real previous-candidate and multi-node evidence:

```bash
tools/release-certification/run-production-beta-release.sh \
  --workspace-root . \
  --out-dir build/production-beta-release \
  --mode production-beta \
  --catalog-channel stable \
  --artifact-base-uri "$CRYPTAD_PRODUCTION_BETA_ARTIFACT_BASE_URI" \
  --require-live-network \
  --require-multi-node-soak \
  --require-sandbox-provider-tests \
  --previous-summary "$PREVIOUS_RELEASE_CERTIFICATION_SUMMARY" \
  --multi-node-soak-summary "$MULTI_NODE_BETA_SOAK_SUMMARY"
```

Useful flags are:

| Flag | Meaning |
| --- | --- |
| `--run-multi-node-soak` | Generate multi-node evidence during release certification. |
| `--multi-node-soak-config <path>` | Use a specific topology config. |
| `--multi-node-soak-summary <path>` | Attach an existing summary instead of generated evidence. |
| `--multi-node-mode simulated|hybrid|live` | Select the drill mode for generated evidence. Production-beta promotion rejects `simulated`. |
| `--require-multi-node-soak` | Require passing multi-node evidence for production beta promotion gates. |

Production beta mode requires multi-node soak evidence by default. It also requires
`--previous-summary`, passing `upgrade-from-previous-candidate` evidence, and a real attached summary
or explicit non-self-test `hybrid`/`live` topology. The final `reports/production-beta-summary.json`
includes a compact `multiNodeBetaSoak` object with status, mode, scenario statuses, blockers,
warnings, and the evidence artifact path.

The checked-in self-test topology is suitable for developer dry-runs and PR-safe validation only.
Protected production-beta workflow dispatches must use an attached passing summary or a production
topology whose previous-candidate upgrade evidence can pass without warnings. Missing previous
candidate summaries, simulated mode, the checked-in self-test topology, failed scenario evidence, or
redaction findings are production blockers and cannot be waived into a launchable dashboard
decision.

When the manual GitHub Actions workflow consumes prior evidence from another run, the
`previous_summary` and `multi_node_soak_summary` dispatch inputs may be a checked-out local path, an
HTTPS JSON URL, or an Actions artifact reference:

```text
actions-artifact://<run-id>/<artifact-name>/<path-inside-artifact>
```

The workflow downloads or restores those sources into a private runner temp directory before it runs
the production-beta file checks, so the release manager does not need to commit previous-candidate
summaries into the repository.

## Previous candidate summaries

Set `previousCandidate.summaryPath` in the topology config to consume a previous production beta or
release-certification summary. In simulated and release-candidate contexts, a missing previous
summary is recorded as a warning so the rest of the drill can still prove the gates. In
production-beta promotion, missing previous-candidate evidence is blocking even if the topology
would otherwise pass.

When a previous summary path is supplied, the file must be a `schemaVersion=1` summary with passing
or warning status, or a release-certification summary with `releaseCandidatePassed=true`. Empty,
malformed, or explicitly failing previous summaries fail the upgrade drill.

When `currentCandidate.productionBetaSummaryPath` is supplied, that current production beta summary
must meet the same schema and non-failing status requirements. Missing, malformed, explicitly
failing, or explicitly non-promotable current summaries fail the upgrade drill.

## Status policy

| Status | Meaning |
| --- | --- |
| `pass` | All scenarios and redaction checks passed. |
| `warn` | Evidence is usable but has a clearly marked gap, such as a missing previous-candidate summary in simulated mode. |
| `fail` | A required scenario, strict previous-candidate check, live reachability check, or redaction scan failed. |

`promotionReady=true` means there are no blockers and redaction passed. It can be true with warnings
for developer or release-candidate evidence. Protected production beta promotion still requires
the stricter production gates to pass.

## Redaction rules

The drill summary and Markdown report must not include:

- private insert URIs;
- private keys;
- app, browser-session, bearer, or CI tokens;
- authorization header values;
- raw fetched content;
- raw social message bodies;
- raw trust statements;
- raw app data or backup payloads;
- vault private identity material;
- absolute local paths or file URIs;
- AppleDouble sidecars or `__MACOSX` archive entries.

Use digests, counts, bounded identifiers, schema versions, status labels, and redacted source
shapes instead.

## Known limitations

The simulated mode proves gate shape, scenario coverage, and redaction behavior. It does not prove
real network latency, live queue behavior, storage pressure, or node-to-node timing. Hybrid mode is
only as current as the summaries supplied to it. Live mode is intentionally minimal and localhost
only; it does not manage a fleet, provision nodes, or publish catalogs by itself.

## Non-goals

The drill does not implement a distributed testnet manager, change the app platform contract,
weaken retained FProxy browse behavior, reintroduce legacy admin dependencies, or copy raw content
into release artifacts to prove that a scenario ran.
