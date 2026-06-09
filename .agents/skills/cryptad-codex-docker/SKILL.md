---
name: cryptad-codex-docker
description: Maintain Cryptad's tracked Codex Docker stack, Playwright remote browser server, helper scripts, and related docs under tools/codex-docker.
---

# Cryptad Codex Docker

Use this skill before changing `tools/codex-docker`, the Codex Docker helper scripts, the
Playwright remote browser service, or docs that describe this stack.

## Source of truth

- Runbook: `tools/codex-docker/README.md`
- Compose file: `tools/codex-docker/compose.yaml`
- Codex image: `tools/codex-docker/Dockerfile`
- Tailscale shell helpers: `tools/codex-docker/tailscale-shell/`

## Guardrails

- Never commit `.env`, Tailscale auth keys, SSH keys, GitHub tokens, OpenAI keys, or host-specific
  private paths.
- Keep the Playwright Docker image version and the Playwright npm package version exactly aligned.
- Keep browser binaries in the Playwright container. The Codex image owns only the CLI/test runner
  npm packages and the `playwright-remote` wrapper.
- Keep the internal Playwright endpoint stable at `ws://playwright:3000/` unless the runbook and
  Compose environment are updated together.
- Keep host exposure bound to loopback unless the user explicitly asks for a wider bind address and
  accepts the local security impact.

## Workflow

1. Read `tools/codex-docker/README.md` before editing Compose, Dockerfile, or helper scripts.
2. Inspect the current Compose shape with `docker compose --env-file ../../.env config` from
   `tools/codex-docker`.
3. Make the smallest change to the Docker stack and update the runbook in the same change.
4. Validate that root `.env` and any local generated outputs remain ignored.
5. Run a Playwright remote-connection smoke test when the Playwright service, image version,
   endpoint, or wrapper changes.

## Validation

From `tools/codex-docker`:

```bash
docker compose --env-file ../../.env config
docker compose --env-file ../../.env up -d codex playwright
docker compose --env-file ../../.env exec codex playwright --version
docker compose --env-file ../../.env exec playwright node --version
```

For a browser smoke test, connect from the Codex container to `ws://playwright:3000/` with the
matching Playwright package and open a simple `data:text/html` page.
