# Production beta go/no-go dashboard

Use the go/no-go command to turn sanitized production-beta evidence into the release manager’s
final `go`, `no-go`, or `go-with-waivers` decision.

## Generate the dashboard

Configure the input summaries and waiver file in the release-run manifest, then run:

```bash
python3 tools/release-certification/certify.py go-no-go \
  --manifest build/production-beta.json
```

The dashboard writes evidence envelope v2 under `<out-root>/<release-id>/go-no-go/`, including
`summary.json`, `report.md`, `redaction-report.json`, and sanitized supporting artifacts.

## Decision policy

- `go` means all mandatory domains pass without an active waiver.
- `go-with-waivers` means every remaining waivable blocker has a valid, active, correctly scoped
  release-manager waiver and the production summary is otherwise promotable.
- `no-go` means a mandatory domain, production summary, candidate binding, artifact hygiene, or
  non-waivable finding failed.

The dashboard validates release ID, mode/profile, production summary, release certification,
ecosystem matrix, app-platform, live-network, network-scale, multi-node, security drill, previous
candidate, waiver, and optional Stable evidence. It does not trust `promotionReady` without
validating the underlying rows.

## Waivers

Waivers require an ID, evidence ID, severity, exact scope, rationale, approver, owner, references,
and future expiry. Unknown evidence IDs require explicit external-risk acceptance. Candidate-only
waivers do not apply to production beta, and production beta waivers are not forwarded to Stable
review automatically.

## Non-waivable findings

Private keys, signing material, private insert URIs, passwords, tokens, cookies, authorization
headers, raw fetched content, raw app data, raw backup payloads, local absolute paths, unsafe
archives, symlinks, production test signing, fixture-only production evidence, non-release
summaries, dirty/unknown production workspaces, and malformed or expired waivers always produce
`no-go`.

The Markdown report contains only sanitized summaries and relative artifact references. Never add
raw JSON dumps, raw command output, local paths, or secret-bearing values to the dashboard.
