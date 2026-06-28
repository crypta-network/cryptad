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

Write the previous beta candidate summary schema:

```bash
python3 tools/release-certification/multi_node_beta_soak.py previous-summary-schema \
  --out build/previous/previous-beta-candidate-summary.schema.json
```

Normalize the previous release's public certification summaries into the production-beta input
contract:

```bash
python3 tools/release-certification/multi_node_beta_soak.py previous-summary \
  --release-certification-summary build/previous/release-certification-summary.json \
  --production-beta-summary build/previous/production-beta-summary.json \
  --out build/previous/previous-beta-candidate-summary.json \
  --report build/previous/previous-beta-candidate-summary.md
```

Both source summaries must already be passing and promotable. The normalizer rejects a failing
release-certification summary, a failing production-beta summary, `promotionReady=false`, or
`nonRelease=true`; it does not convert failed source evidence into a passing previous-candidate
summary. By default the generated summary uses the current UTC time for `generatedAt`; reserve
`--generated-at` for deterministic fixture generation and reproducible tests.
The source summaries must also contain the sanitized previous-candidate metadata blocks listed
below, either as top-level fields or under an explicit previous-candidate metadata container. The
normalizer copies those values into the previous-candidate summary and rejects missing or
conflicting source metadata; it does not synthesize catalog editions, app digests, app-data
migration state, Trust Graph state, Social Inbox state, or support-bundle evidence.

Verify that summary before attaching it to a production run:

```bash
python3 tools/release-certification/multi_node_beta_soak.py verify-previous-summary \
  --summary build/previous/previous-beta-candidate-summary.json \
  --strict \
  --max-age-days 90
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
  --previous-summary "$PREVIOUS_BETA_CANDIDATE_SUMMARY" \
  --previous-release-certification-summary "$PREVIOUS_RELEASE_CERTIFICATION_SUMMARY" \
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
`--previous-summary`, a schema-valid previous beta candidate summary, passing
`upgrade-from-previous-candidate` evidence, and a real attached summary or explicit non-self-test
`hybrid`/`live` topology. The final `reports/production-beta-summary.json` includes a compact
`multiNodeBetaSoak` object with status, mode, scenario statuses, blockers, warnings, a
`previousCandidateUpgrade` status block, and the evidence artifact path. The compact upgrade block
includes `previousSummaryDrillDigest`, a stable digest of the previous-candidate metadata used by
the drill, so production-beta can reject upgrade evidence generated from a different previous
summary even when release id and version strings match.

The checked-in self-test topology is suitable for developer dry-runs and PR-safe validation only.
Protected production-beta workflow dispatches must use an attached passing summary or a production
topology whose previous-candidate upgrade evidence can pass without warnings. Missing previous
candidate summaries, simulated mode, the checked-in self-test topology, failed scenario evidence, or
redaction findings are production blockers and cannot be waived into a launchable dashboard
decision.

When the manual GitHub Actions workflow consumes prior evidence from another run, the
`previous_summary`, `previous_release_certification_summary`, and `multi_node_soak_summary`
dispatch inputs may be a checked-out local path, an HTTPS JSON URL, or an Actions artifact
reference:

```text
actions-artifact://<run-id>/<artifact-name>/<path-inside-artifact>
```

The workflow downloads or restores those sources into a private runner temp directory before it runs
the production-beta file checks, so the release manager does not need to commit previous-candidate
summaries into the repository.

## Previous beta candidate summary schema

Production-beta promotion consumes a dedicated previous-candidate summary with
`kind=cryptad-previous-beta-candidate-summary` and `schemaVersion=1`. It is generated from the last
candidate's sanitized release-certification and production-beta summaries with the
`previous-summary` command above. It is intentionally metadata-only; it records digests, counts,
schema versions, and pass/fail states, never raw app data or message content.

Required top-level fields are:

| Field | Required production meaning |
| --- | --- |
| `releaseId`, `version`, `generatedAt` | Identify the previous candidate and when the normalized evidence was produced. |
| `source` | Git commit, HTTPS artifact base URI, release-certification summary digest, and production-beta summary digest. |
| `status`, `promotionReady` | Must be `pass` and `true` for production-beta promotion. |
| `catalog` | Previous stable and beta channel editions, catalog digest, signing key id, and mirror health status. |
| `platformApi` | Stable baseline name, contract version, and snapshot digest used by the previous candidate. |
| `firstPartyApps` | At least `feed-reader`, `profile-publisher`, `trust-graph`, and `social-inbox`, each with bundle digest, data schema version, migration contract digest, backup support, and rollback support. |
| `appData` | Backup manifest digest, restore drill status, migration coverage for Feed Reader, Social Inbox, and Trust Graph, and `rawValuesIncluded=false`. |
| `trustGraph` | Store schema version, anchor and statement counts, state digest, and `rawStatementsIncluded=false`. |
| `socialInbox` | Schema version, thread and source counts, state digest, and `rawMessageBodiesIncluded=false`. |
| `supportBundle` | Format version, redaction status, and support-bundle digest. |
| `redaction` | `status=pass` with no unsafe findings. |

Strict verification rejects malformed summaries, failing summaries, `promotionReady=false`, stale
production summaries when `--max-age-days` is supplied, missing required app or migration metadata,
missing Trust Graph or Social Inbox state metadata, missing support-bundle redaction metadata, raw
app data, raw social message bodies, raw trust statements, private insert URIs, private keys,
tokens, absolute local paths, AppleDouble names, or `__MACOSX` references.

Set `previousCandidate.summaryPath` in the topology config to the verified
`previous-beta-candidate-summary.json`. In simulated and release-candidate contexts, a missing
previous summary is recorded as a warning so the rest of the drill can still prove the gates. In
production-beta promotion, missing, malformed, failing, stale, non-promotable, or redaction-unsafe
previous-candidate evidence is blocking even if the topology would otherwise pass.

When `currentCandidate.productionBetaSummaryPath` is supplied, that current production beta summary
must be a non-failing, promotable production beta summary. Missing, malformed, explicitly failing,
or explicitly non-promotable current summaries fail the upgrade drill.

The `multi-node-beta.upgrade-drill` evidence includes:

- previous and current versions;
- previous and current catalog channels;
- previous stable and beta catalog editions plus the current edition;
- daemon upgrade representation;
- first-party app install, update, migration, and rollback status;
- backup-before-update and restore-into-clean-node status;
- failed migration block/rollback status;
- Social Inbox schema migration status and state digest;
- Trust Graph state migration status and state digest;
- support bundle generated after a failed upgrade path with redaction status;
- `rawDataIncluded=false` and release-report fields that are digest/count/status only.

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
