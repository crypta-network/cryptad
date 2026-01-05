# Project Configuration

## Project Overview

Crypta is a peer-to-peer network providing a distributed, encrypted, and decentralized datastore. It is a fork of
Hyphanet (formerly Freenet), building upon its technology for censorship-resistant communication and publishing. This
repository contains the reference node implementation (the "Crypta reference daemon") written primarily in Java with
some Kotlin components.

## Development Guidelines

- Primary language: Kotlin/Java
    - Kotlin source location: place all Kotlin sources under `src/*/kotlin/` (e.g., `src/main/kotlin`, `src/test/kotlin`). Do not add Kotlin files under `src/*/java/`.
    - Prefer top-level functions over wrapping in objects/classes when appropriate (idiomatic Kotlin)
- Code style:
    - Kotlin: Official coding convention described [here](https://kotlinlang.org/docs/coding-conventions.html)
    - Java: Google Java Style Guide described [here](https://google.github.io/styleguide/javaguide.html)
- Testing: JUnit 6 (Jupiter) and kotlin-test
- Coverage requirement: 80% minimum
- After editing a Java or Kotlin file, please check for any missing or poorly written JavaDoc/KDoc comments. Add or
  improve them as needed.
- Do not use "--no-daemon" for Gradle
- If the Java Runtime cannot be located, or if any other errors occur when running a command, request approval to
  proceed. Do not skip the command.

### Commenting Guidelines

- Prefer clean diffs over in-code historical explanations. Do not add "Removed …" style comments to explain code you just deleted in the same change. Rationale belongs in the commit message and PR description, not in source files.
  - Forbidden example (do not add):
    - `// (Removed) Temporary 'legacyLoggerCheck' task used during SLF4J migration.`
    - `// The legacy logger has been removed in PR8, so this guard task is no longer needed.`
    - `// Std stream capture has been removed; rely on configured appenders.`
    - `// No std stream capture to restore.`
- When deprecating behavior that remains in code, use standard `@Deprecated` (Java/Kotlin) and a brief forward-looking note (link to issue/PR). Avoid PR-number narratives in comments.
- If additional context is valuable long-term, document it here in `AGENTS.md` or in `docs/`, not inline next to removed code.

When operating as an autonomous or semi-autonomous agent, proactively leverage specialized skills/roles based on the
current task (e.g., context management, Kotlin/Java expertise, debugging, performance/security review, search, and
architecture review).

## Development Commands

### Building

- Build the node JAR: `./gradlew buildJar`
- Clean build: `./gradlew clean buildJar`
- Build output hash: The build prints the SHA-256 of `build/libs/cryptad.jar`

### Testing

- Run all tests in parallel: `./gradlew --parallel test`
- Run specific test class: `./gradlew --parallel test --tests *TestClassName`
- Run specific test method: `./gradlew --parallel test --tests *TestClassName.methodName`

### Code Quality

- Compile only: `./gradlew compileJava`
- Spotless and dependency verification guidance is provided below

### Running Your Build

1. Build: `./gradlew buildJar`
2. Stop the running node
3. Replace the existing node JAR with `build/libs/cryptad.jar`
4. Restart the node

## Recent Changes & Tips (Sep 2025)

- AEAD: OCB replaced with AES‑GCM (breaking)
  - We migrated AEAD streams from OCB to AES‑GCM and removed all legacy compatibility paths. Readers now treat the first 12 bytes of the 16‑byte on‑disk prefix as the GCM nonce; the remaining 4 bytes are reserved. Overhead remains 32 bytes (16‑byte prefix + 16‑byte tag).
  - Impact: Any AEAD‑encrypted data written by previous OCB code will fail to decrypt. Specifically:
    - Client persistence: `client.dat.crypt` / `client.dat.bak.crypt` cannot be read; the node will start without resuming persistent requests.
    - Plugin stores: `*.data.crypt` cannot be read; plugins will start with empty/default store data.
  - No fallback is provided. If you must retain old data, do not upgrade to this build or export/decrypt with an older version first.
  - Files: `src/main/java/network/crypta/crypt/AEADInputStream.java`, `src/main/java/network/crypta/crypt/AEADOutputStream.java`.

- Remote debugging (Wrapper/JDWP)
  - Set `CRYPTAD_REMOTE_DEBUG=1` to enable JDWP for the wrapped JVM at runtime (no `wrapper.conf` edits).
  - Tunables via env: `CRYPTAD_DEBUG_PORT` (default 5005), `CRYPTAD_DEBUG_HOST` (default 127.0.0.1), `CRYPTAD_DEBUG_SUSPEND` (`y|n`, default `n`), `CRYPTAD_DEBUG_TIMEOUT` (ms, optional).
  - The launcher appends Wrapper command-line properties: `wrapper.ignore_sequence_gaps=TRUE`, `wrapper.java.additional.250=<JDWP>`, `wrapper.java.additional.251=-Xdebug` so Tanuki’s `wrapper.java.detect_debug_jvm` can detect a debug JVM. The script logs `REMOTE_DEBUG=enabled (...)` when active.

- Datastore sizing heuristic
  - If free space > 50 GiB: suggest 20% of free space (min 10 GiB), bounded by Bloom cap (256 GiB). Disk I/O cap is aligned to the same 256 GiB cap.
  - If free space > 5 GiB: suggest 20% of free space (min 2 GiB). See `DatastoreUtil.java` for exact limits.

- First-Time Wizard bandwidth defaults
  - Defaults increased to `download=10240` KiB/s and `upload=1024` KiB/s.
  - “Detected” bandwidth row is currently disabled in the template pending a working detector; do not re‑enable without fixing detection.

- Theme switcher initialization
  - The browser theme change listener (`matchMedia('(prefers-color-scheme: dark)')`) is registered before creating the UI controls. Keep this ordering, as the wizard page may not render a navbar.

- Launcher code style guardrails
  - Use the `APP_NAME` constant for window titles; prefer logging via `LauncherLog` over silent catches; keep Desktop integration hooks inside `try/catch` with debug logs.

- AEAD/OCB nonce compatibility (Sep 2025)
  - Legacy on-disk format wrote `mainCipher.getBlockSize()` bytes (16 for AES) before the ciphertext; BouncyCastle OCB uses a nonce of at most 15 bytes.
  - Reader: `AEADInputStream` now consumes the full block size from the stream and initializes OCB with only the first 15 bytes. The extra byte is intentionally discarded so ciphertext is aligned.
  - Writer: `AEADOutputStream` persists a 16-byte prefix again (`WRITTEN_NONCE_SIZE=16`) while using only the first 15 bytes internally for OCB. This preserves backward compatibility.
  - Overhead: For AES, `AES_OVERHEAD` is 32 bytes (16-byte written nonce + 16-byte MAC).
  - Files: `src/main/java/network/crypta/crypt/AEADInputStream.java`, `src/main/java/network/crypta/crypt/AEADOutputStream.java`.
  - Guardrail: Do not change the on-disk prefix to 15 bytes; doing so would break reading of previously stored data.
  - Migration note: If any data was written during the brief 15-byte-prefix regression window, coordinate with maintainers for an optional autodetect path before enabling any reader changes.

### CoreUpdater Migration (Sep 2025)

- Core package-based updates
  - Replaces self-updating of `cryptad.jar` with a package-based updater (“CoreUpdater”).
  - Fetches `info/<N>` JSON from the existing update USK, selects an OS/arch-specific installer (deb/rpm/dmg/exe/flatpak/snap), and downloads to `nodeDir/updates/core/<version>/`.
  - Plugin updates are unchanged.
- Update system changes
  - `MainJarUpdater` removed; `NodeUpdateManager` now wires and coordinates `CoreUpdater` for core and `PluginJarUpdater` for plugins.
  - JAR Update-over-Mandatory (UOM) is disabled; `supportsJarUOM()` returns false and legacy jar UOM paths are gated or no-ops.
- New endpoint and UI
  - HTTP endpoint: `/core-update/` with actions `download`, `install`, and `openStore`.
  - Alerts panel shows progress percent when available; failures surface clear retry guidance (non‑fatal errors relabel to “Retry”).
- Platform specifics
  - Linux: prefers GUI handoff (gio/xdg-open) or PackageKit; in Flatpak uses the portal/`flatpak-spawn` to bridge to host tools. `.snap` files are never GUI-opened; installs use `snap install --dangerous`.
  - macOS: adds Gatekeeper guidance for unsigned builds.
  - Windows: adds SmartScreen guidance and SHA‑256 verification tips.
- Environment detection
  - `AppEnv` is the single source of truth for OS/arch/sandbox/service detection; launcher and updater code paths were refactored to use it.
- Descriptor format & integrity
  - JSON includes `version`, `packages` keyed by `<arch>.<ext>`, and optional `changelog_chk`/`fullchangelog_chk`.
  - CHK integrity covers content; any historical `sha256` fields in descriptors are ignored.

### Environment detection (AppEnv)

AppEnv is the SINGLE source of truth for runtime environment detection across the codebase. Do not read `System.getProperty("os.name")`, `os.arch`, or parse PATH directly in new code; use `AppEnv` instead.

- Location: `network.crypta.fs.AppEnv`
- Provides:
  - `isWindows()`, `isMac()`, `isLinux()`
  - `isFlatpak()`, `isSnap()`, `isDocker()`
  - `isServiceMode()` and service heuristics per-OS
  - `osKind(): OsKind` and `arch(): String` (returns `"amd64"` or `"arm64"`)
  - `onPath(cmd: String): Boolean`, `availableManagers(): List<String>` (Linux PATH probing)
  - `detectEnvironment(): EnvDetection` with `os/arch/availableManagers`
  - `osNameRaw()`, `osVersionRaw()` for display-only strings

Usage examples

- Kotlin
  - `val env = AppEnv(); if (env.isWindows()) { ... }`
  - `val det = AppEnv().detectEnvironment(); when (det.os) { AppEnv.OsKind.LINUX -> ... }`

- Java
  - `AppEnv env = new AppEnv(); if (env.isServiceMode()) { ... }`
  - `switch (env.osKind()) { case WINDOWS: ... }`

Refactoring guidance

- Prefer replacing raw `os.name`/`os.arch` checks and PATH scans with the corresponding `AppEnv` APIs.
- For legacy utilities that expose more granular enums (e.g., `FileUtil.OperatingSystem` with `FreeBSD`), map from `AppEnv.osKind()` and fall back only where necessary to preserve behavior.
## Repository Etiquette

- Branch naming: main, develop, feature/*, bugfix/*, hotfix/*, release/*
- Merge strategy: GitFlow
- Commit format: Conventional commits
- PR requirements: Tests pass, approved review
- PR creation: Always ask before creating a GitHub pull request. Do not open PRs without explicit approval from a maintainer/requester.

## Environment Setup

- Java version: 25 or higher
    - Java runtime has been installed in the environment. So you can run java and gradle related commands without issues
- Kotlin version: 2.3.0 or higher (matches `gradle/libs.versions.toml`)
    - The ki shell is installed in the environment.

## Project-Specific Notes

### Swing Launcher (Kotlin)

- Package: `network.crypta.launcher`. Entry: top‑level `fun main()`.
- UI: Java Swing (3 rows — buttons, scrolling log, status bar). System LAF, 900×600.
- Start: launches the wrapper script with this resolution order (first match wins).
  - Stop (Unix/macOS): sends SIGINT to the wrapper/JVM; if still alive after ~20s, escalates to TERM then KILL.
  - Stop (Windows): deletes a per‑user anchor file to request a graceful Wrapper shutdown and waits up to ~25s; if still alive, falls back to `taskkill` (soft then `/F`).
  - Env override: `CRYPTAD_PATH` (absolute or relative to `user.dir`).
  - From running `cryptad.jar` directory:
    - Unix: `<jarDir>/cryptad`; Windows: `<jarDir>/cryptad.bat`.
  - From assembled dist layout:
    - Unix: `<jarDir>/../bin/cryptad`; Windows: `<jarDir>/../bin/cryptad.bat`.
  - Fallbacks from `user.dir`:
    - Unix: `./bin/cryptad`, then `./cryptad`.
    - Windows: `./bin/cryptad.bat`, then `./cryptad.bat`.
- Logs: streams combined stdout+stderr and also tails `wrapper.log` when configured; enables `wrapper.console.flush=TRUE` in generated `wrapper.conf`.
- FProxy port detection: parses `Starting FProxy on ...:<port>` from logs; enables “Launch in Browser” and auto‑opens the first time per app session.
- Keyboard: global shortcuts via `KeyEventDispatcher`:
  - ↑/↓ row; PgUp/PgDn page; ←/→ focus buttons (wrap‑around); Enter/Space click; `s` start/stop; `q` quit.
- Coroutines: `kotlinx-coroutines-swing:1.10.2` with `Dispatchers.Main.immediate` for UI, `Dispatchers.IO` for process I/O and file tailing. Dedicated `shutdownScope` for quit.
- Unix PTY fallback: if `script` exists, wraps the process to reduce buffering.
- Build scripts: created during `assembleCryptadDist`:
  - `build/cryptad-dist/bin/cryptad-launcher` and `cryptad-launcher.bat`.
- Testing aid: `-PuseDummyCryptad=true` replaces `bin/cryptad` with `tools/cryptad-dummy.sh` in the dist for local testing.

#### Windows details

- The distribution includes Windows‑native wrapper binaries built from the latest release of `crypta-network/wrapper-windows-build`:
  - `bin/wrapper-windows-x86-64.exe` and `bin/wrapper-windows-arm-64.exe`.
  - DLLs are placed directly in `lib/` as `wrapper-windows-x86-64.dll` and `wrapper-windows-arm-64.dll`.
- The main Windows launcher is `bin/cryptad.bat`:
  - Detects `AMD64` vs `ARM64` and runs the matching `wrapper-windows-x86-64.exe` or `wrapper-windows-arm-64.exe`.
  - Passes a per‑user anchor on the command line so the GUI can stop gracefully by deleting it:
    - `"wrapper.anchorfile=%LOCALAPPDATA%\Cryptad.anchor"` (command‑line property overrides any value in `wrapper.conf`).
  - Native DLL resolution uses `wrapper.java.library.path=lib` in `wrapper.conf`. No `PATH` edits are required.
  - Accepts the same arguments as the Unix script and uses `conf/wrapper.conf`.
  - The GUI launcher is `bin/cryptad-launcher.bat`.
  
Tip: If GitHub API rate limits are hit during builds, set `GITHUB_TOKEN` in the environment.

## Architecture Overview

### Core Network Layer (`network.crypta.node`)

- Node coordination: `Node.java`
- Peer management: `PeerNode`, `PeerManager`
- Network transport: `PacketSender`, `FNPPacketMangler`
- Request orchestration: `RequestStarter`, `RequestScheduler`
- Updates: `NodeUpdateManager`

### Content Storage (`network.crypta.store`)

- Storage abstractions: `FreenetStore`
- CHK/SSK stores: `CHKStore`, `SSKStore`
- Caching: `SlashdotStore`

### Cryptography (`network.crypta.crypt`)

- Encryption: Block cipher/AES
- Signatures: DSA/ECDSA
- Hashing: SHA-256 and others
- RNG: `RandomSource`/Yarrow

### Key Management (`network.crypta.keys`)

- Client keys: `ClientCHK`, `ClientSSK`
- URIs: `FreenetURI`
- Updatable keys: USK

### Client APIs

- High-level client: `network.crypta.client`
- FCP: `network.crypta.clients.fcp`
- HTTP interface: `network.crypta.clients.http`

### Plugin System (`network.crypta.pluginmanager`)

- Management: `PluginManager`
- Capability interfaces: `FredPlugin*`
- Catalog: `OfficialPlugins`

### Configuration (`network.crypta.config`)

- Flexible type-safe configuration with persistence

### Supporting Infrastructure (`network.crypta.support`)

- Logging, data structures, threading, and helpers

## Key Design Patterns

### Request Routing

1. `RequestStarter` initiates requests
2. `RequestScheduler` manages queues and priorities
3. `SendableRequest` implementations perform request types
4. Routing uses location-based algorithms for discovery

### Update System

- `NodeUpdateManager` coordinates updates.
- Core updates: `CoreUpdater` fetches `info/<N>` JSON from the update USK, selects an OS/arch package, downloads under `nodeDir/updates/core/<version>/`, and exposes actions via `/core-update/`.
- Plugin updates: `PluginJarUpdater` continues to manage plugin downloads and deploys.
- JAR UOM: disabled for the core; jar UOM handlers are gated (`supportsJarUOM() == false`).
- Config keys: `node.updater.enabled`, `node.updater.autoupdate` remain (autoupdate downloads packages; OS installation is manual or guided).

### Security Model

- Content-addressed storage with cryptographic verification
- Encrypted link-level communication; request routing designed to conceal origin/destination
- Digital signatures for content authentication

## Key Tools and Instructions for Them

- Formatting: Spotless is configured (Kotlin via ktfmt; Java via google‑java‑format).
- Build: ./gradlew build
- Test: ./gradlew :test --tests [replace with TestClassName]

## Versioning System

- Single integer build number set in `build.gradle.kts` (`version = "<int>"`)
- Version tokens are replaced into `network/crypta/node/Version.kt` during build (`@build_number@`, `@git_rev@`)
- Version strings support both Cryptad and Fred formats; compatibility enforces protocol match and minimum builds
- Freenet interop: uses historical identifiers (e.g., `"Fred,0.7"`) for wire compatibility where applicable

## Build System

- Gradle with Kotlin DSL
- Targets Java 25+
- Kotlin components present alongside Java
- Dependency verification is configured and typically strict (temporarily set to lenient only when updating metadata)
- Version info (`Version.kt`) generated with current build number and git revision

### Distributions and Windows wrapper sources

- `assembleCryptadDist` creates a portable layout under `build/cryptad-dist` with `bin/`, `lib/`, and `conf/`.
  - Non‑Windows wrapper files come from the upstream Tanuki delta pack.
  - Windows x86_64/arm64 wrapper exe/DLL are fetched from the newest GitHub release of `crypta-network/wrapper-windows-build`.
  - Override points (optional):
    - `-PwrapperWinApiUrl=<api-url>` to pin a specific release API.
    - `-PwrapperWinAmd64Url=<asset-url>` / `-PwrapperWinArm64Url=<asset-url>` to force asset URLs.
- Archives:
  - `distZipCryptad` / `distTarCryptad` → `build/distributions/cryptad-v<version>.(zip|tar.gz)`.
  - `distJlinkCryptad` → `build/distributions/cryptad-jlink-v<version>.(zip|tar.gz)`.
  - Both include the Windows launchers and binaries above.

### Installers (jpackage)

We ship Gradle tasks that build a desktop app image and (on macOS/Linux) native installers via `jpackage`. The app
image bundles a minimal runtime (from our jlink flow) and the portable `cryptad-dist` tree so the GUI launcher can
start/stop the wrapper reliably.

- Tasks:
  - `./gradlew build` → builds the jpackage app image and enriches it with `cryptad-dist`. On Linux and macOS, it also builds native installers (`.deb`/`.rpm` on Linux when `dpkg-deb`/`rpmbuild` are available; `.dmg` on macOS). Missing tools cause those installer tasks to be skipped, not failed. Windows builds do not produce installers by default.
  - `./gradlew jpackageImageCryptad` → builds only the app image under `build/jpackage/`.
  - `./gradlew jpackageInstallerCryptad` → builds a native installer for the current OS (macOS: `.dmg`; Linux: `.deb` or `.rpm` when `dpkg-deb`/`rpmbuild` is available). Not available on Windows.
  - Linux type override: pass `-PlinuxInstaller=<deb|rpm>` (or set env `CRYPTA_LINUX_INSTALLER`) to force installer type. When both are available, RPM is preferred by default.
- Metadata:
  - Name: `Crypta`, Vendor: `crypta.network`, App ID: `network.crypta.cryptad`.
  - Main entry: `network.crypta.launcher.LauncherKt`.
- Versioning:
  - jpackage requires a numeric `--app-version`; we use the project version (e.g., `1`).
  - Installer filenames follow jpackage defaults (e.g., `Crypta-<version>.<ext>`); we do not produce an extra labeled copy.
  - Windows installers are not produced; only app images are built on Windows.
- Icons and resources:
  - macOS: `src/jpackage/macos/cryptad.icns`.
  - Windows: `src/jpackage/windows/cryptad.ico`.
  - Linux: `src/jpackage/linux/cryptad.png` (passed to `jpackage --icon`; copied verbatim into the image). The image also carries a `.desktop` entry that includes the GNOME mapping keys:
    - `StartupWMClass=network-crypta-launcher-LauncherKt`
    - `X-GNOME-WMClass=network-crypta-launcher-LauncherKt`
  - Root `LICENSE` is included as `LICENSE.txt` and `EULA.txt`; `README.md` as `README.txt`.
- Image layout:
  - App root: `Contents/app/` (macOS) contains `Crypta.cfg`, a tiny `bootstrap.jar`, and `cryptad-dist/`.
  - Classpath is rewritten to `app/cryptad-dist/lib/*.jar`; jars are not duplicated under `app/`.
- Troubleshooting (macOS):
  - If double‑click does nothing, run `Contents/MacOS/Crypta` in Terminal to see logs.
  - Clear quarantine on unsigned builds: `xattr -dr com.apple.quarantine build/jpackage/Crypta.app`.
  - Verify security status: `spctl --assess -vv build/jpackage/Crypta.app`.


- Troubleshooting (Windows)
  - Launch from a console to view errors: `build\\jpackage\\Crypta\\Crypta.exe`.
  - Image layout: `app/` contains `Crypta.cfg`, `bootstrap.jar`, and `cryptad-dist/`.
  - Verify paths exist:
    - `build\\jpackage\\Crypta\\app\\cryptad-dist\\lib\\cryptad.jar`
    - `build\\jpackage\\Crypta\\app\\Crypta.cfg`
  - Verify `app\\Crypta.cfg` contains:
    - `app.mainclass=network.crypta.launcher.LauncherKt`
    - One or more `app.classpath=$APPDIR/cryptad-dist/lib/*.jar` lines (including `cryptad.jar`).
  - If you find `cryptad-dist` or `Crypta.cfg` under `lib\\app\\` instead of `app\\`, rebuild; on Windows the app image uses `app/` (Linux uses `lib/app/`).

#### Linux installer behavior (DEB/RPM)

- Install location: the app image is installed under `/opt/cryptad/Crypta`. Some hosts may lowercase the directory to `/opt/cryptad/crypta`; our scripts auto‑detect the actual `APP_DIR` and normalize paths accordingly.
- Server vs desktop detection:
  - Treated as “desktop” only when a display manager (`display-manager.service`) exists and is enabled or active; otherwise falls back to detecting session files (`/usr/share/xsessions/*.desktop` or `/usr/share/wayland-sessions/*.desktop`).
  - This avoids misclassifying some servers that report a graphical default target.
- Conditional install actions:
  - Server (no desktop): install a systemd unit at `/etc/systemd/system/cryptad.service`, `daemon-reload`, and `enable` the service. Do not auto-start; require explicit admin `systemctl start`.
  - Desktop: install a `.desktop` entry (`/usr/share/applications/crypta.desktop`), refresh menus (`update-desktop-database`) and icon cache (`gtk-update-icon-cache`) when available. The installer rewrites the desktop entry `Exec`/`Icon` to the detected `APP_DIR` and ensures the GNOME mapping keys are present: `StartupWMClass=network-crypta-launcher-LauncherKt` and `X-GNOME-WMClass=network-crypta-launcher-LauncherKt`.
- System user: creates a `cryptad` system account for the service (`/var/lib/cryptad`, shell `nologin`) when missing.
- System group: creates an explicit `cryptad` system group and sets it as the primary group for the `cryptad` user.
- Maintainer scripts and spec:
  - DEB: `src/jpackage/linux/preinst`, `prerm`, `postinst`, `postrm` are flattened into the jpackage resource dir and marked executable. `prerm` tolerates missing `xdg-desktop-menu` on servers to avoid uninstall failures; `postinst/postrm` refresh desktop DB and icon cache when present.
  - RPM: `src/jpackage/linux/crypta.spec` handles conditional service/desktop logic and also creates the `cryptad` user. The systemd unit is staged under the image at `lib/systemd/system/cryptad.service` and installed to `/etc/systemd/system/` by the spec. Desktop entry removal happens in `%postun` only on final erase (`$1=0`) so upgrades do not delete `/usr/share/applications/crypta.desktop`.
- Icon and desktop entry:
  - A full‑size Linux icon is embedded; a `.desktop` file is prewritten into the image and patched on install so GNOME and other DEs display the correct icon. WM_CLASS is set to match the Swing window class.
 - Script library: common installer logic lives in `src/jpackage/linux/crypta-common.sh` (installed under `lib/` in the app image). Maintainer scripts and spec sections source it when present and include safe fallbacks to keep uninstall idempotent after files are removed. Do not duplicate `is_desktop`, `ensure_user`, or service control snippets elsewhere.
- Headless helper: DEB/RPM install a privileged, least‑privilege helper for non‑interactive core package installs:
  - Systemd oneshot unit `cryptad-core-install@.service` and script `cryptad-core-install.sh` (installed under the app image) validate paths under `/var/lib/cryptad/updates/core` and perform the install via PackageKit/native tools.
  - A polkit rule restricts starting only this unit and only to the `cryptad` user. When unavailable, the UI shows manual admin commands instead.

Debugging installers (Linux)
- Set `CRYPTA_DEBUG=1` in the environment to enable verbose logging from maintainer scripts. Logs append to `/var/log/crypta-installer.log`.
- If the dock icon is generic, verify the GNOME association:
  - `xprop WM_CLASS` and click the window → should include `network-crypta-launcher-LauncherKt`.
  - Confirm `/usr/share/applications/crypta.desktop` exists and has `StartupWMClass`/`X-GNOME-WMClass` matching the above.

Uninstall semantics
- Service cleanup: during removal, scripts use `systemctl is-enabled/is-active` before `disable --now` to avoid races; they remove `/etc/systemd/system/cryptad.service` and `daemon-reload`.
- Desktop cleanup: remove `crypta.desktop` and refresh caches when tools exist.
- Data/account retention: the `cryptad` user/group and `/var/lib/cryptad` remain to avoid data loss. Removing them is a manual admin action and must not be automated by default.

**Git Identity Policy**

- Do not set or override git identity when committing.
  - Never pass `--author`/`--reset-author` to `git commit`.
  - Never set `GIT_AUTHOR_NAME`, `GIT_AUTHOR_EMAIL`, `GIT_COMMITTER_NAME`, or `GIT_COMMITTER_EMAIL` in commit commands.
  - Do not run `git config user.name`/`git config user.email` in this repository during commit flows.
- Use the existing project/default identity configured for the environment.
- Only rewrite authorship/committer history when explicitly requested by a maintainer; use interactive rebase and push with `--force-with-lease`, and document rewritten SHAs in the PR.

- Pre‑commit identity check (required):
  - Before any `git commit` or history rewrite, verify identity is configured:
    - `git config --get user.name` and `git config --get user.email` must both be non‑empty.
  - If either is missing/empty:
    - STOP and do not proceed with the commit.
    - Warn the user and ask them to set their identity (agents must not set it themselves). Example:
      - "Git identity is not configured. Please run: git config --global user.name "<Your Name>" && git config --global user.email "<you@example.com>""
    - After the user confirms identity is set, resume the commit.

### Temporary Working Notes

- `tmp_changes.md` is for local, short‑lived notes and is ignored by Git. Do not commit it or include it in PRs.
- If accidentally staged: `git restore --staged tmp_changes.md` (and optionally `git checkout -- tmp_changes.md`).
- Copy any relevant, permanent information into this `AGENTS.md`, PR descriptions, or proper docs under `docs/`.

## Desktop & Theme Handling

- Swing Look & Feel uses FlatLaf across platforms; macOS uses FlatMac* variants. We choose dark/light based on the OS theme before any Swing components are created (EDT).
- Flatpak: OS theme detection reads the XDG Desktop Portal setting `org.freedesktop.appearance/color-scheme` via dbus-java.
  - Portal detector: `src/main/kotlin/com/jthemedetecor/PortalThemeDetector.kt`.
  - Factory: `src/main/kotlin/network/crypta/launcher/FlatpakAwareOsThemeDetector.kt` prefers the portal and falls back to the upstream detector when unavailable.
- We removed temporary debug prints and the late “ensureApplied()” safeguard. LAF is applied once early; fallback to the system LAF only occurs if FlatLaf isn’t already active.
- On Linux/Flatpak we use FlatLaf client-side window decorations for consistent title bars.

## Flatpak Build (local dev)

Requirements: `flatpak`, `org.freedesktop.Platform//24.08`, `org.freedesktop.Sdk//24.08`.

Commands

```bash
./gradlew -x spotlessKotlin -x spotlessApply -x spotlessJava -x spotlessKotlinGradle buildJar
./gradlew -x spotlessKotlin -x spotlessApply -x spotlessJava -x spotlessKotlinGradle distJlinkCryptad
cp -f build/distributions/cryptad-jlink-v1.tar.gz tools/flatpak/local/
rm -rf builddir repo .flatpak-builder
flatpak run org.flatpak.Builder --force-clean --user --arch=$(flatpak --default-arch) \
  --install-deps-from=flathub builddir tools/flatpak/cryptad.yaml
flatpak build-export --arch=$(flatpak --default-arch) repo builddir v1
flatpak build-bundle repo cryptad-v1-$( [ $(flatpak --default-arch) = aarch64 ] && echo arm64 || echo amd64 ).flatpak \
  network.crypta.cryptad v1 --arch=$(flatpak --default-arch)
flatpak --user install -y ./cryptad-v1-*.flatpak
flatpak run network.crypta.cryptad//v1
```

Notes
- Flatpak packaging files live under `tools/flatpak/` (manifest, desktop file, icon, metainfo).
- Spotless is scoped to `src/**`; `.spotlessignore` at the repo root prevents scanning Flatpak scratch dirs.

## Testing Strategy

- Unit tests for core utilities and logic
- Integration tests for network components and protocols
- Cryptographic tests for primitives
- Client API tests (FCP and HTTP)

### Test Support Package

- Package: `network.crypta.testsupport` (test sources only)
  - Purpose: Common helpers for tests that should not ship in production binaries.
  - Current utilities:
    - `FileTestUtils` — deterministic fill helpers for OutputStream/Bucket/RandomAccessBuffer used by tests.
      - `fill(OutputStream, Random, long)`
      - `fill(Bucket, Random, long)`
      - `fill(RandomAccessBuffer, Random, long offset, long length)`
  - Guidance:
    - Do not call these helpers from main sources. If production code needs random fill, use
      `FileUtil.fill(OutputStream, long)` or appropriate non-test utilities.
    - Replace any historical use of `BucketTools.fill(..., Random, ...)` in tests with
      `FileTestUtils.fill(...)`.

## Important Notes

- Requires Java 25+ to compile and run
- Updater supports automatic updates and includes legacy-related utilities
- Custom crypto implementations; avoid changes without review
- Network protocol changes must consider backward compatibility
- Simulator components exist for network behavior testing

## Spotless + Dependency Verification

When Gradle dependency verification is strict, Spotless may fail to resolve `google-java-format` and other tool artifacts, even with `mavenCentral()` configured.

Steps to update verification-metadata for Spotless
- Temporarily set verification to lenient:
  - Edit `gradle.properties` → `org.gradle.dependency.verification=lenient`.
- Write verification entries (SHA256 + PGP):
  - `./gradlew --write-verification-metadata sha256,pgp spotlessApply`
  - Optional: force refresh to capture the exact formatter version:
    - `./gradlew --refresh-dependencies --write-verification-metadata sha256,pgp spotlessApply`
  - Faster alternative (no formatting run):
    - `./gradlew --write-verification-metadata sha256,pgp spotlessInternalRegisterDependencies`
- Confirm entries in `gradle/verification-metadata.xml`:
  - Look for components under `com.google.googlejavaformat` and trusted keys for that group.
- Restore strict mode:
  - Edit `gradle.properties` → `org.gradle.dependency.verification=strict`.
- Validate:
  - `./gradlew spotlessApply` should pass with strict verification.
- Export keys (optional, recommended for reproducibility):
  - `./gradlew --export-keys`

Tips
- Keep Spotless config at the intended formatter version (currently `googleJavaFormat("1.28.0")`).
- If verification still blocks resolution, re-run the metadata write with `pgp` and ensure the group-level trusted key entry exists.
- Commit updated `gradle/verification-keyring.gpg` and `gradle/verification-keyring.keys` so new environments verify without re-fetching keys.

## Dependency Metadata

Note: `dependencies.properties` has been removed (Sep 2025). It is no longer packaged or used by the runtime or build.
- Gradle dependencies use the version catalog `gradle/libs.versions.toml` and `build.gradle.kts`.

## SonarLint (Gradle) — Oct 2025

- Plugin & wiring
  - Added Gradle plugin `name.remal.sonarlint` via the build-logic convention plugin `cryptad.sonar` (`build-logic/src/main/kotlin/cryptad.sonar.gradle.kts`).
  - Versions pinned in the version catalog:
    - `remalSonarlint = "7.0.0"`
    - `sonarqube = "7.2.2.6593"`
  - The convention applies both `org.sonarqube` and `name.remal.sonarlint`.
- Defaults
  - SonarLint is configured not to fail builds by default (`ignoreFailures = true`) to ease adoption.
  - A property passthrough recognizes `-Psonarlint.sources`/`-Psonar.inclusions` and forwards to `sonar.inclusions`.
- Tasks
  - Standard: `sonarlintMain`, `sonarlintTest` (from the plugin), plus `sonar`.
  - Build integration: SonarLint does NOT run during regular lifecycles (`build`, `check`).
    - Both `sonarlintMain` and `sonarlintTest` are gated with `onlyIf` and execute only when explicitly requested
      (i.e., when any requested task name contains `sonarlint`).
    - Example: `./gradlew build` → SonarLint tasks are skipped; `./gradlew sonarlintMain` → runs analysis.
  - Run manually:
    - Full main sources: `./gradlew sonarlintMain`
    - Test sources: `./gradlew sonarlintTest`
  - Single-file: added `sonarlintFile` to analyze one file only.
    - Usage: `./gradlew --quiet sonarlintFile -Psonarlint.file=src/main/java/SevenZip/LzmaAlone.java`
    - Aliases: `-Pfile=...`, `-Psonarlint.sources=...`.
    - Report: `build/reports/sonarLint/sonarlintFile/sonarlintFile.xml`.
  - Note: `sonarlintMain` may still index the full project; use `sonarlintFile` when scoping strictly to one file.
- Dependency verification & keys
  - Verification metadata and keyring were refreshed to include SonarLint artifacts.
  - To refresh on future bumps:
    1) Temporarily set `org.gradle.dependency.verification=lenient` in `gradle.properties`.
    2) Run: `./gradlew --write-verification-metadata sha256,pgp :build-logic:compileKotlin`
    3) Restore `org.gradle.dependency.verification=strict`.
    4) Optional: `./gradlew --export-keys`.
- Memory
  - Increased Gradle daemon heap to reduce OOM risk during SonarLint indexing:
    - `gradle.properties`: `org.gradle.jvmargs=-Xmx2g -XX:MaxMetaspaceSize=1g -Dfile.encoding=UTF-8`.

## JaCoCo & SonarCloud Coverage — Oct 2025

- Plugin & wiring
  - JaCoCo is applied via the build-logic convention plugin `cryptad.java-kotlin-conventions` (toolVersion `0.8.13`).
  - XML and HTML reports are enabled; XML lives at `build/reports/jacoco/test/jacocoTestReport.xml`.
  - The `check` lifecycle depends on both `jacocoTestReport` and `jacocoTestCoverageVerification`.
  - Coverage verification rule: 80% line coverage (LINE/COVEREDRATIO >= 0.80).
  - Builds do not fail on coverage by default: `isFailOnViolation = false` (violations are logged).

- SonarCloud
  - Sonar is configured via the `cryptad.sonar` convention plugin.
  - Host: `https://sonarcloud.io` with project `crypta-network_cryptad` and organization `crypta-network`.
  - Coverage is read from the JaCoCo XML path above (`sonar.coverage.jacoco.xmlReportPaths`).
  - The `sonarqube` task depends on `jacocoTestReport` to ensure XML is generated. If present, the optional `sonar` alias also depends on it.
  - Authentication: set `SONAR_TOKEN` in the environment; the convention maps it to `sonar.token`. No CLI flag is required.

- How to run locally
  - Tests + coverage: `./gradlew --parallel test jacocoTestReport`
  - Enforced check (non-failing gate): `./gradlew check`
  - Upload to SonarCloud: `export SONAR_TOKEN=<token>` then `./gradlew --parallel sonarqube`

- CI tips
  - Minimal job step: `./gradlew --parallel test jacocoTestReport sonarqube`
  - Provide the token securely (env `SONAR_TOKEN`).

## JUnit 6 Upgrade — Oct 2025

- Version bump
  - Upgraded to JUnit 6.0.0. Platform and Jupiter now share the same version (`6.0.0`).
  - Versions are pinned in the version catalog: `gradle/libs.versions.toml` → `junitJupiter=6.0.0`, `junitPlatform=6.0.0`.

- Gradle configuration
  - Tests run on the JUnit Platform (`useJUnitPlatform()` in `build-logic/src/main/kotlin/cryptad.java-kotlin-conventions.gradle.kts`).
  - Dependencies (resolved via catalog):
    - `testImplementation(libs.junitJupiterApi)` and `testImplementation(libs.junitJupiterParams)`
    - `testRuntimeOnly(libs.junitJupiterEngine)` and `testRuntimeOnly(libs.junitPlatformLauncher)`
  - Vintage is not included; avoid adding JUnit 4 tests unless you explicitly add Vintage for migration-only purposes.
  - Dependency verification: JUnit 6 introduces `org.jspecify:jspecify` (nullability annotations). If strict verification blocks resolution, follow the steps in “Spotless + Dependency Verification” to refresh metadata, then restore strict mode.

- Notes from JUnit 6 release
  - `junit-platform-runner` (JUnit 4 bridge) is not supported; do not use `@RunWith(JUnitPlatform.class)`.
  - `junit-platform-jfr` module is discontinued.
  - Certain deprecated APIs from pre-6 have been removed (e.g., some ordering strategies). Prefer current APIs.
  - Kotlin `suspend` test functions are supported in JUnit 6.

- How to run
  - All tests: `./gradlew --parallel test`
  - By class/method: `./gradlew --parallel test --tests *ClassName` or `--tests *ClassName.method`

Reference: JUnit 6.0.0 release notes (docs.junit.org)
