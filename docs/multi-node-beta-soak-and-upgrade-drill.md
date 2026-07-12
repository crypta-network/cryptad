# Multi-node beta soak and upgrade drill

Use the multi-node beta command to plan, run, and verify app ecosystem behavior across a bounded
multi-node topology and a previous-candidate upgrade.

## Commands

Configure topology, mode, candidate inputs, freshness, and output options under
`commands.multi-node-beta` in the release-run manifest.

```bash
python3 tools/release-certification/certify.py multi-node-beta plan \
  --manifest build/release-candidate.json
python3 tools/release-certification/certify.py multi-node-beta run \
  --manifest build/release-candidate.json
python3 tools/release-certification/certify.py multi-node-beta verify \
  --manifest build/release-candidate.json
```

Focused offline tests run with:

```bash
python3 tools/release-certification/certify.py multi-node-beta --self-test
```

## Modes

`simulated` is deterministic and appropriate for PR, CI, and developer dry runs. `hybrid` combines
deterministic orchestration with attached release-manager evidence. `live` records a real bounded
topology. Production promotion cannot use the checked-in self-test topology or simulated-only
evidence.

When `requirements.multiNodeSoak=true` and the effective topology mode is `live`, collection also
requires at least one configured localhost node to be reachable. Deterministic scenario fallback
can remain visible as warning evidence for optional live runs, but it cannot satisfy a required
live gate.

## Scenarios

The gate covers catalog channel updates, app install/update/health rollback, app-data migrations,
backup and clean-node restore, subscription pressure and backoff, bounded Trust Graph import,
multi-source Social Inbox behavior, support-bundle redaction, and upgrade from the previous beta
candidate.

Previous-candidate upgrade evidence binds the previous summary digest and release identity. It
records daemon upgrade, first-party app migrations, backup-before-update, failed-migration
rollback, Social Inbox and Trust Graph state migration, clean restore, and post-failure support
bundle redaction without raw app data, messages, trust statements, or backup payloads.

## Output and release policy

Each action writes its v2 summary below `<out-root>/<release-id>/multi-node-beta/<action>/`.
Release-candidate and production evidence must be fresh, explicitly attached or generated for the
current run, candidate-bound, and redaction-safe. A stale default summary from another workspace
must never be reused.

Private insert URIs, tokens, browser sessions, raw app data, raw messages, raw trust documents,
node profile paths, rollback backup paths, and local absolute paths are excluded from release
artifacts.
