# Hyphanet interop gate

Use this gate to verify that a packaged Cryptad node can interoperate with a pinned Hyphanet
baseline over darknet peering and FCP content operations.

## Scope

The gate is Linux-only and runs two local nodes:

- Cryptad from `build/cryptad-dist/bin/cryptad`
- Hyphanet from the configured baseline in `hyphanet-baseline.env`

Both nodes bind client/FCP access to `127.0.0.1`. The harness disables opennet, browser/FProxy, and
the console endpoint so the test stays deterministic and local to the CI runner or developer
machine.

The mandatory flows are:

| Flow             | Validation                                                                                                                             |
|------------------|----------------------------------------------------------------------------------------------------------------------------------------|
| FCP handshake    | `ClientHello`, `NodeHello`, `GetNode`, and `NodeData` on both nodes                                                                    |
| Peer exchange    | `AddPeer`, `ListPeers`, connected darknet status, and `ModifyPeer` disable/re-enable by default                                        |
| CHK cross-fetch  | Cryptad inserts a CHK and Hyphanet fetches it; Hyphanet inserts a CHK and Cryptad fetches it                                           |
| SSK cross-fetch  | Each side generates an SSK keypair, inserts deterministic bytes, and the other side fetches them                                       |
| USK smoke        | Each side inserts editions `0` and `1`; the other side fetches deterministic edition URIs                                              |
| Restart recovery | Cryptad restarts, FCP returns, the peer relationship reconnects, and Hyphanet refetches content inserted by the restarted Cryptad node |

Content inserts use `ConsecutiveRNFsCountAsSuccess=0` so the gate treats route-not-found results as
real insert failures. That prevents FCP `PutSuccessful` from masking a block that never reached the
baseline peer in the two-node test network. For single-block payloads the harness may keep the
source insert local and make the opposite node fetch the resulting URI; the compatibility assertion
is the cross-node fetch and byte comparison, not broad network propagation in a two-node topology.

The restart flow uses the current minimum release gate: restart and refetch. The harness also calls
`ListPersistentRequests` before and after restart and records the results. Creating a long-lived
persistent request and proving replay across restart remains a follow-up because it needs more
runtime soak time than this CI smoke should consume.

## Run locally

Build the packaged distribution and run the gate:

```bash
tools/interop/run-hyphanet-interop-smoke.sh
```

If `build/cryptad-dist/` already exists:

```bash
INTEROP_SKIP_BUILD=1 tools/interop/run-hyphanet-interop-smoke.sh
```

Run only the Python parser/client self-test:

```bash
python3 tools/interop/interop_smoke.py --self-test
```

Useful local overrides:

```bash
INTEROP_SKIP_BUILD=1 \
INTEROP_WORKDIR=/tmp/cryptad-interop \
CRYPTAD_FCP_PORT=29402 \
HYPHANET_FCP_PORT=29502 \
tools/interop/run-hyphanet-interop-smoke.sh
```

Set `INTEROP_KEEP_WORKDIR=1` only for interactive debugging. That mode leaves child node processes
running and writes their PIDs to `artifacts/kept-processes.json`.

Peer mutation validation defaults to `ModifyPeer` disable/re-enable:

```bash
INTEROP_VALIDATE_PEER_MUTATION=modify tools/interop/run-hyphanet-interop-smoke.sh
```

Set `INTEROP_VALIDATE_PEER_MUTATION=remove-readd` to exercise destructive `RemovePeer` followed by
`AddPeer`. That mode is useful for manual investigation, but the default release gate avoids it
because deleting a peer can destabilize the two-node baseline before content-flow validation.

## Baseline configuration

`hyphanet-baseline.env` defines defaults and lets caller-provided environment variables win.

The checked-in default uses the verified Hyphanet 1506 Debian package:

- `HYPHANET_BASELINE_VERSION=1506`
- `HYPHANET_BASELINE_URL=https://github.com/hyphanet/fred/releases/download/build01506/freenet_0.7.5+1506-1_amd64.deb`
- `HYPHANET_BASELINE_SHA256=b97d04d8a8f34d8e168e296de82e74dc527a6a02b2aa98c46d1fe9d76e2d1ee3`

For local testing with a pre-downloaded baseline:

```bash
HYPHANET_BASELINE_JAR=/path/to/hyphanet-baseline.jar \
INTEROP_SKIP_BUILD=1 \
tools/interop/run-hyphanet-interop-smoke.sh
```

If the jar is not executable with `java -jar`, also set:

```bash
HYPHANET_BASELINE_CLASSPATH=/path/to/dependencies/* \
HYPHANET_BASELINE_MAIN_CLASS=freenet.node.NodeStarter
```

For a remote baseline, provide both URL and checksum:

```bash
HYPHANET_BASELINE_URL=https://example.invalid/hyphanet-baseline.jar \
HYPHANET_BASELINE_SHA256=<sha256> \
tools/interop/run-hyphanet-interop-smoke.sh
```

The harness fails before node startup if it cannot find a local jar or a verified URL/checksum pair.
It never downloads an unverified remote jar or package.
Verified baseline packages are cached in `build/interop-cache/` by default so reruns can work
without re-downloading the baseline. Set `INTEROP_CACHE_DIR` to use a different cache location.

## Timeouts and ports

Default timeouts:

- `INTEROP_TIMEOUT_SECONDS=900`
- `INTEROP_STARTUP_TIMEOUT_SECONDS=180`
- `INTEROP_PEER_TIMEOUT_SECONDS=120`
- `INTEROP_REQUEST_TIMEOUT_SECONDS=300`

Default ports:

- `CRYPTAD_FNP_PORT=19401`
- `CRYPTAD_FCP_PORT=19402`
- `HYPHANET_FNP_PORT=19501`
- `HYPHANET_FCP_PORT=19502`

The harness checks each port before startup and fails clearly if another local process is using it.

## Artifacts

Every run writes diagnostics under `build/interop-smoke/` unless `INTEROP_WORKDIR` or
`INTEROP_OUT_DIR` overrides the location:

```text
build/interop-smoke/
  downloads/
  cryptad/
  hyphanet/
  logs/
  transcripts/
  artifacts/
  summary.json
```

Important files:

- `summary.json` contains machine-readable status, flow results, ports, baseline details, URIs,
  process statuses, and failure reason.
- `transcripts/*.fcp.txt` logs sent and received FCP message names, identifiers, key fields, and
  data payloads. Private insert URIs are redacted in transcripts.
- `artifacts/*-node-reference.fref` and `artifacts/*-node-reference.json` contain exported node
  references.
- `artifacts/*peers*.json` records peer lists after add, re-add, and restart.
- `artifacts/private-insert-uris.json` contains temporary SSK/USK insert URIs and is written with
  owner-only file permissions.
- `logs/*.stdout.log` and `logs/*.stderr.log` capture each launched process.

CI uploads `build/interop-smoke/` on failure through the existing `interop-smoke` job.

## Debug failures

Start with `summary.json`. Check `failure_reason`, the `flows` map, and the recorded process exit
statuses. Then inspect the matching FCP transcript and node stderr log.

Common failures:

- Missing baseline: set `HYPHANET_BASELINE_JAR` or both `HYPHANET_BASELINE_URL` and
  `HYPHANET_BASELINE_SHA256`.
- Port conflict: override the four port variables listed above.
- Startup timeout: inspect `logs/cryptad*.stderr.log`, `logs/hyphanet*.stderr.log`, and the node
  config files under `cryptad/` and `hyphanet/`.
- Peer timeout: inspect `artifacts/*peers*.json` and both FCP transcripts for `AddPeer`,
  `ListPeers`, and `ProtocolError`.
- Content timeout: inspect `PutFailed`, `GetFailed`, or `ProtocolError` entries in the transcripts.

## Follow-ups

These are intentionally out of scope for this PR:

- Long-lived `SubscribeUSK` soak tests.
- Full persistent request replay with a deliberately unfinished request across restart.
- Multi-OS interop matrix.
- Opennet interop.
- Browser/UI automation.
- Performance benchmarking.
