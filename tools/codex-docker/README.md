# Codex Docker stack

Use this stack to run the Cryptad Codex container and a remote Playwright browser server from a
tracked repository configuration.

## Prerequisites

- Docker with Compose v2.
- Network access to pull `docker.io/benyamin/codex-sandbox` and
  `mcr.microsoft.com/playwright`.
- Optional Tailscale auth state in repo-root `.env`. The root `.env` file is ignored and must not
  be committed.

## Configure

From this directory:

```bash
test -f ../../.env || cp .env.example ../../.env
```

Edit `../../.env` for local values. Keep `PLAYWRIGHT_VERSION` aligned across the Playwright image
and the Playwright npm package. The default is `1.60.0`.

If you need SSH access to the Codex container, set `CODEX_SSH_AUTHORIZED_KEYS` to one or more
public keys in `../../.env`. Do not commit private keys or local tokens.

## Start the stack

Run from `tools/codex-docker`:

```bash
docker compose --env-file ../../.env up -d --build codex playwright
```

Start Tailscale only when you need the remote shell helper:

```bash
docker compose --env-file ../../.env up -d tailscale-shell
```

List services:

```bash
docker compose --env-file ../../.env ps
```

## Playwright endpoints

| Caller | Endpoint |
| --- | --- |
| Codex container | `ws://playwright:3000/` |
| Host | `ws://127.0.0.1:${PLAYWRIGHT_HOST_PORT:-3000}/` |

The Playwright service publishes only to host loopback. Other containers in the Compose network use
the service name `playwright`.

## Use Playwright from Codex

The Codex image installs the matching `playwright` and `@playwright/test` npm packages without
browser binaries. Browser binaries live in the `mcr.microsoft.com/playwright` container.

Check the CLI:

```bash
docker compose --env-file ../../.env exec codex playwright --version
```

Run a Playwright test through the remote server:

```bash
docker compose --env-file ../../.env exec codex playwright-remote test <spec>
```

The `playwright-remote` wrapper sets `PW_TEST_CONNECT_WS_ENDPOINT` to `ws://playwright:3000/` when
the variable is not already set.

From the host, use a matching Playwright version:

```bash
PW_TEST_CONNECT_WS_ENDPOINT=ws://127.0.0.1:${PLAYWRIGHT_HOST_PORT:-3000}/ npx -y playwright@1.60.0 test
```

## Target URL rules

- Use `http://codex:<port>/` for servers running inside the Codex container. Bind those servers to
  `0.0.0.0`, not only `127.0.0.1`.
- Use `http://host.docker.internal:<port>/` for servers running on the host.
- Do not use `localhost` from inside the Playwright browser container unless the target server is
  inside that same container.

## Validation

Static checks:

```bash
docker compose --env-file ../../.env config
git status --short --ignored . ../../.env
rg -n "tskey-auth-[A-Za-z0-9]{8,}|OPENAI_API_KEY=|GITHUB_TOKEN=|BEGIN OPENSSH|PRIVATE KEY" \
  AGENTS.md .gitignore .agents/skills/cryptad-codex-docker tools/codex-docker tools/README.md \
  --glob '!tools/codex-docker/README.md'
```

Container checks:

```bash
docker compose --env-file ../../.env build codex tailscale-shell
docker compose --env-file ../../.env up -d codex playwright
docker compose --env-file ../../.env exec codex playwright --version
docker compose --env-file ../../.env exec playwright node --version
```

Use the root project test commands only when a code change also touches Java or Gradle behavior.

## Troubleshooting

- If Chromium crashes under load, confirm the `playwright` service still uses `ipc: host`.
- If a test cannot reach a local server, check whether the server is on the host, the Codex
  container, or the Playwright container and use the matching target URL rule above.
- If `docker compose` ignores values from `../../.env`, pass `--env-file ../../.env` explicitly.
- If the host port is busy, change `PLAYWRIGHT_HOST_PORT` in `../../.env`.
