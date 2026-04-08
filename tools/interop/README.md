# Hyphanet Interop Smoke

This directory contains the Linux-only interoperability smoke harness for verifying that the
packaged Cryptad runtime still interoperates with the current pinned Hyphanet baseline over live
darknet and FCP surfaces.

## What it does

The harness:

- builds or reuses `build/cryptad-dist`
- downloads the pinned official Hyphanet release asset defined in `hyphanet-baseline.env`
- launches one Cryptad node and one Hyphanet node in isolated localhost-only temp layouts
- uses FCP for:
  - `ClientHello`
  - `GetNode`
  - `AddPeer`
  - `ListPeers`
  - `GenerateSSK`
  - `ClientPut`
  - `ClientGet`
- proves:
  - Cryptad CHK insert -> Hyphanet fetch
  - Hyphanet CHK insert -> Cryptad fetch
  - Hyphanet SSK keypair generation -> insert -> Cryptad fetch
- writes diagnostics under `build/interop-smoke/`

To keep the two-node darknet smoke deterministic, the harness precomputes CHK URIs with
`GetCHKOnly=true`, starts the real insert on a live FCP connection, and then verifies that the
opposite node can fetch the content over the live network path. The actual two-node insert request
uses `LocalRequestOnly=true` so the smoke stays bounded to the local darknet pair.

The peering baseline is intentionally darknet-only and deterministic. Opennet, browser automation,
and HTML scraping are out of scope for this smoke.

## Local Run

From the repository root:

```bash
tools/interop/run-hyphanet-interop-smoke.sh
```

If `build/cryptad-dist/` already exists and you want to skip rebuilding it:

```bash
INTEROP_SKIP_BUILD=1 tools/interop/run-hyphanet-interop-smoke.sh
```

Useful overrides:

```bash
INTEROP_OUT_DIR=/tmp/cryptad-interop-out \
INTEROP_CACHE_DIR=/tmp/cryptad-interop-cache \
tools/interop/run-hyphanet-interop-smoke.sh
```

## Diagnostics

The harness writes:

- node stdout/stderr logs
- FCP transcripts
- generated config files
- node run/data directories used during the smoke
- `summary.json` with the key URIs and overall result

CI uploads that output directory on failure.

## Current Pin

The Hyphanet baseline is centralized in `hyphanet-baseline.env` and currently targets:

- Hyphanet `0.7.5`
- build `1506`
- official GitHub release asset `freenet_0.7.5+1506-1_amd64.deb`

## Deliberate Gaps

- No USK smoke yet. Add it only if it stays deterministic.
- No restart/persistence recovery coverage yet.
- No non-Linux matrix yet.
