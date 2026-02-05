---
name: cryptad-launcher-ui
description: "Work on the Swing launcher: start/stop logic, logging, keyboard shortcuts, FlatLaf/theme handling, and Windows specifics."
compatibility: opencode
metadata:
  area: launcher
  domain: cryptad
---

## When to use
Use this skill when working on:
- The Swing launcher (`network.crypta.launcher`)
- Wrapper start/stop behavior
- Log streaming/tailing
- Theme (FlatLaf) or Flatpak theme detection
- Windows launcher scripts and wrapper binaries

## Swing launcher overview
- Package: `network.crypta.launcher`
- Entry point: top-level `fun main()`
- UI: Java Swing (three rows — buttons, scrolling log, status bar), System LAF, 900×600.

## Starting Cryptad (wrapper script resolution order)
The launcher starts the wrapper script using this resolution order (first match wins):
- Env override: `CRYPTAD_PATH` (absolute or relative to `user.dir`)
- From running `cryptad.jar` directory:
  - Unix: `<jarDir>/cryptad`
  - Windows: `<jarDir>/cryptad.bat`
- From the assembled dist layout:
  - Unix: `<jarDir>/../bin/cryptad`
  - Windows: `<jarDir>/../bin/cryptad.bat`
- Fallbacks from `user.dir`:
  - Unix: `./bin/cryptad`, then `./cryptad`
  - Windows: `./bin/cryptad.bat`, then `./cryptad.bat`

## Stop behavior
- Unix/macOS:
  - Send SIGINT to the wrapper/JVM; if still alive after ~20s, escalate to TERM then KILL.
- Windows:
  - Delete a per-user anchor file to request a graceful Wrapper shutdown and wait up to ~25s.
  - If still alive, fall back to `taskkill` (soft then `/F`).

## Logging and UX
- Streams combined stdout+stderr and can also tail `wrapper.log` when configured.
- Enables `wrapper.console.flush=TRUE` in generated `wrapper.conf`.
- FProxy port detection parses `Starting FProxy on ...:<port>` from logs; enables “Launch in Browser” and auto-opens the first time per app session.

## Keyboard shortcuts
Global shortcuts via `KeyEventDispatcher`:
- ↑/↓ row; PgUp/PgDn page; ←/→ focus buttons (wrap-around)
- Enter/Space click
- `s` start/stop; `q` quit

## Concurrency model
- Uses `kotlinx-coroutines-swing` with:
  - `Dispatchers.Main.immediate` for UI
  - `Dispatchers.IO` for process I/O and file tailing
- Dedicated `shutdownScope` for quit

## Unix PTY fallback
If `script` exists, the launcher may wrap the process to reduce buffering.

## Build artifacts created by dist tasks
- `build/cryptad-dist/bin/cryptad-launcher`
- `build/cryptad-dist/bin/cryptad-launcher.bat`

## Local launcher entrypoint
- For local development without packaging, start the launcher directly with:
  - `./gradlew runLauncher`

## Local testing aid
- `-PuseDummyCryptad=true` replaces `bin/cryptad` with `tools/cryptad-dummy.sh` in the dist for local testing.

## Windows specifics (wrapper binaries + scripts)
- Distribution includes Windows-native wrapper binaries:
  - `bin/wrapper-windows-x86-64.exe`, `bin/wrapper-windows-arm-64.exe`
  - `lib/wrapper-windows-x86-64.dll`, `lib/wrapper-windows-arm-64.dll`
- Main Windows launcher: `bin/cryptad.bat`
  - Detects `AMD64` vs `ARM64` and runs the matching wrapper exe.
  - Passes per-user anchor file on the command line:
    - `wrapper.anchorfile=%LOCALAPPDATA%\Cryptad.anchor`
  - Native DLL resolution uses `wrapper.java.library.path=lib` in `wrapper.conf` (no `PATH` edits required).
  - Accepts same args as Unix script and uses `conf/wrapper.conf`.
- GUI launcher: `bin/cryptad-launcher.bat`

## Theme & Flatpak handling
- Swing LAF uses FlatLaf across platforms; macOS uses FlatMac* variants.
- Decide dark/light based on OS theme **before** any Swing components are created (EDT).
- Flatpak:
  - OS theme detection reads the XDG Desktop Portal setting `org.freedesktop.appearance/color-scheme` via dbus-java.
  - Portal detector: `src/main/kotlin/com/jthemedetecor/PortalThemeDetector.kt`
  - Factory: `src/main/kotlin/network/crypta/launcher/FlatpakAwareOsThemeDetector.kt` prefers the portal and falls back to upstream detector when unavailable.
- Ordering matters:
  - Register the browser theme change listener (`matchMedia('(prefers-color-scheme: dark)')`) before creating UI controls.

## Launcher code style guardrails
- Use the `APP_NAME` constant for window titles.
- Prefer logging via `LauncherLog` over silent catches.
- Keep Desktop integration hooks inside `try/catch` with debug logs.
