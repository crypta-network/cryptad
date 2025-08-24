# Cryptad Directories (Adaptive)

This document summarizes where Cryptad places its files on each OS and how to override locations.

## User-Session Mode

- Linux (XDG):
  - config: `$XDG_CONFIG_HOME/Cryptad/config` or `~/.config/Cryptad/config`
  - data: `$XDG_DATA_HOME/Cryptad/data` or `~/.local/share/Cryptad/data`
  - cache: `$XDG_CACHE_HOME/Cryptad` or `~/.cache/Cryptad`
  - runtime: `$XDG_RUNTIME_DIR/cryptad` (else `/run/user/<uid>/cryptad` or `~/.cache/Cryptad/rt`)
  - logs: `~/.local/share/Cryptad/logs`

- macOS (native GUI):
  - config: `~/Library/Application Support/Cryptad/config`
  - data: `~/Library/Application Support/Cryptad/data`
  - cache: `~/Library/Caches/Cryptad`
  - runtime: `~/Library/Caches/Cryptad/run`
  - logs: `~/Library/Logs/Cryptad`
  - If `XDG_*` is set (e.g. Homebrew/CLI), XDG locations are honored instead of the macOS defaults.

- Windows (user):
  - config: `%APPDATA%\Cryptad\config`
  - data: `%LOCALAPPDATA%\Cryptad\data`
  - cache: `%LOCALAPPDATA%\Cache\Cryptad`
  - runtime: `%LOCALAPPDATA%\Cryptad\Run`
  - logs: `%LOCALAPPDATA%\Cryptad\Logs`

### Containers

- Snap (strict):
  - Detect via `SNAP` env.
  - `config`: XDG (`$SNAP_USER_DATA/.config`)
  - `data`: `$SNAP_USER_COMMON/Cryptad` (persistent across refreshes)
  - `cache`: XDG cache
  - `runtime`: `$XDG_RUNTIME_DIR/cryptad` (fallback `$SNAP_USER_DATA/tmp`)
  - Opt-out (per-revision data): set `CRYPTAD_SNAP_PER_REV=1`.

- Flatpak (desktop):
  - Detect via `FLATPAK_ID` env; XDG automatically maps to `~/.var/app/<APP_ID>/...`.
  - Runtime under `$XDG_RUNTIME_DIR/app/<APP_ID>/cryptad`.

- Docker:
  - Uses Linux/XDG defaults. Recommended overrides via env:
    - `APP_CONFIG_DIR`, `APP_DATA_DIR`, `APP_CACHE_DIR` (volume mount targets)

## Service Mode

Service mode activates if `CRYPTAD_SERVICE=1` or platform heuristics (systemd/launchd/Windows service).

- Linux (systemd):
  - If systemd exported directories are set, use them:
    - `CONFIGURATION_DIRECTORY`, `STATE_DIRECTORY`, `CACHE_DIRECTORY`, `LOGS_DIRECTORY`, `RUNTIME_DIRECTORY`
  - Else FHS fallback:
    - config: `/etc/cryptad`
    - state: `/var/lib/cryptad`
    - cache: `/var/cache/cryptad`
    - logs: `/var/log/cryptad`
    - run: `/run/cryptad`

- macOS (launchd):
  - config: `/Library/Application Support/Cryptad/config`
  - state: `/Library/Application Support/Cryptad/data`
  - cache: `/Library/Caches/Cryptad`
  - logs: `/Library/Logs/Cryptad`
  - run: `/Library/Caches/Cryptad/run`

- Windows Service:
  - Root: `%PROGRAMDATA%\Cryptad\`
  - `config`, `data`, `cache`, `logs`, `run` under that root

## Overrides

- CLI flags (highest precedence): `--config-dir=… --data-dir=… --cache-dir=… --run-dir=…`
- Env overrides: `CRYPTAD_CONFIG_DIR`, `CRYPTAD_DATA_DIR`, `CRYPTAD_CACHE_DIR`, `CRYPTAD_RUN_DIR`, `CRYPTAD_LOGS_DIR`
- Config-time placeholders (in `cryptad.ini`): `${configDir}`, `${dataDir}`, `${cacheDir}`, `${runDir}`, `${logsDir}`, `${home}`, `${tmp}`

## Mapping to legacy properties

These are computed as absolute paths from the above base dirs:

- `node.install.cfgDir = configDir`
- `node.install.storeDir = dataDir`
- `node.install.userDir = configDir`
- `node.install.pluginStoresDir = dataDir/plugin-data`
- `node.install.pluginDir = dataDir/plugins`
- `node.install.tempDir = cacheDir/tmp`
- `node.install.persistentTempDir = cacheDir/persistent-temp`
- `node.install.nodeDir = dataDir/node`
- `node.install.runDir = runDir`
- `node.downloadsDir = dataDir/downloads`
- `logger.dirname = logsDir`

## Migration

On first run with the new feature:

1. The config is read from the computed `configDir/cryptad.ini`.
2. If absent, an existing `cryptad.ini` from CWD or the executable directory is copied.
3. Legacy relative paths are rewritten to placeholders, then expanded at runtime.
4. A best-effort move migrates legacy directories (e.g. `./datastore`, `./plugins`, `./temp`).

## Diagnostics

Run `./gradlew printDirs` to print resolved directories for the current environment.

