<p align="center"><img src="docs/images/crypta_logo.png" alt="Crypta Logo" width="160"></p>
<h1 align="center" style="padding-top: 0; margin-top: 0;"><strong>Crypta</strong></h1>
<p align="center"><em><strong>Crypta</strong> is a privacy‑first, decentralized datastore and app platform — a modern fork of Hyphanet/Freenet.</em></p>

<p align="center">
  <a href="https://github.com/crypta-network/cryptad/actions/workflows/ci.yml">
    <img alt="CI" src="https://github.com/crypta-network/cryptad/actions/workflows/ci.yml/badge.svg?branch=main" />
  </a>
  <a href="https://www.gnu.org/licenses/gpl-3.0">
    <img alt="License: GPLv3" src="https://img.shields.io/badge/license-GPLv3-blue.svg" />
  </a>
  <img alt="Java 25+" src="https://img.shields.io/badge/Java-25%2B-007396?logo=openjdk" />
  <img alt="Gradle" src="https://img.shields.io/badge/Build-Gradle-02303A?logo=gradle" />
</p>

## Overview

**Crypta** is a platform for censorship‑resistant communication and publishing. It is a fork of Hyphanet (formerly Freenet)
that builds on its core ideas while modernizing usability, performance, and developer experience. **Crypta** provides a
peer‑to‑peer, distributed, encrypted, and decentralized datastore on top of which applications such as forums, chat,
micro‑blogs, and websites can run without central servers.

Why fork? Hyphanet/Freenet pioneered privacy‑preserving routing and content‑addressed storage, but several long‑standing
frictions hold it back:

- Usability and onboarding: confusing opennet/darknet concepts, painful first‑run setup, and limited, dated UIs make it
  hard for new users to join and stay.
- Performance for cold content: the anonymity model and multi‑hop routing can lead to slower retrievals, especially for
  infrequently accessed data; bootstrap and NAT traversal further compound early‑session latency.
- Observability without compromising privacy: network‑wide performance and health are hard to measure, making tuning and
  evolution slow and error‑prone.

**Crypta**’s vision is to keep the privacy and resilience, while making it pleasant, fast, and sustainable to use and build
on:

- User experience first: a modern web UI, sensible defaults, and a one‑click guided onboarding that hides complexity
  (smart opennet bootstrap, optional darknet linking later).
- Faster routing and retrieval: adaptive, locality‑aware routing; popularity‑sensitive caching; opportunistic prefetch;
  and transport updates (e.g., QUIC/HTTP‑3, improved congestion control, and better NAT traversal) for lower tail
  latency.
- Safe observability: privacy‑preserving telemetry and reproducible benchmarking harnesses to inform tuning without
  leaking user data.
- A better platform: typed configuration and testable interfaces to make extending the network
  straightforward.

This repository contains the reference node (the “**Crypta** reference daemon”) that participates in the network, stores
data, and serves applications.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/screenshot_dark.png">
  <source media="(prefers-color-scheme: light)" srcset="docs/images/screenshot_light.png">
  <img alt="Fallback image description" src="docs/images/screenshot_dark.png">
</picture>

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Building](#building)
- [Testing](#testing)
- [Code Quality](#code-quality)
- [Running Your Build](#running-your-build)
- [Development Guidelines](#development-guidelines)
- [Dependencies](#dependencies)
- [Spotless + Dependency Verification](#spotless--dependency-verification)
- [Versioning](#versioning)
- [Branching & Releases](#branching--releases)
- [Update System](#update-system)
- [Architecture Overview](#architecture-overview)
- [License](#license)

## Quick Start

Choose one of the following options.

### A) Install via Packages (recommended)

- Windows
  - This repository does not build Windows installers. Use the portable distribution or the
    jpackage app image below. If a Windows installer is published on the project’s Releases page,
    you can install it by double‑clicking; if SmartScreen warns, click “More info” → “Run anyway”.

- macOS (.dmg)
  - Download the DMG from the Releases page and open it.
  - Drag “Crypta.app” to Applications. If Gatekeeper blocks it, right‑click → Open (or allow in Settings → Privacy & Security).
  - Launch “Crypta” from Applications/Launchpad.

- Debian/Ubuntu (.deb)
  - Install from a local .deb:
    ```bash
    sudo apt install ./Crypta-<version>_amd64.deb   # adjust arch/version
    ```

- Fedora/RHEL/openSUSE (.rpm)
  - Install from a local .rpm:
    ```bash
    sudo dnf install ./Crypta-<version>.x86_64.rpm  # or: sudo zypper install ./...
    ```

- Snap (.snap)
  - Local snap install (not from store):
    ```bash
    sudo snap install --dangerous ./crypta-<version>.snap
    ```

- Flatpak (.flatpak or .flatpakref)
  - Local Flatpak bundle:
    ```bash
    flatpak install --user ./crypta-<version>-amd64.flatpak
    flatpak run network.crypta.cryptad//v1
    ```

Linux servers (no desktop environment)
- On systems without a desktop environment, the installer (deb/rpm) creates a systemd unit `cryptad.service` and enables it, but does not start it automatically. You must start it manually after install:
  ```bash
  sudo systemctl start cryptad
  ```

After installation, start Crypta from your OS application launcher (on desktops). The app starts the daemon, opens the UI in your browser on the first successful start, and manages start/stop for you.

### B) Portable Distribution (for developers)

Build the portable distribution and run the Swing launcher without installing system packages:

```bash
./gradlew assembleCryptadDist
build/cryptad-dist/bin/cryptad-launcher    # Windows: cryptad-launcher.bat
```

The launcher starts the daemon, streams live logs, detects the FProxy port from lines like
`Starting FProxy on ...:<port>`, and opens `http://localhost:<port>/` on the first successful start.

Shortcuts (global):
- ↑/↓ one row; PgUp/PgDn one page.
- ←/→ move focus among the three buttons (wrap‑around).
- Enter/Space click focused button; s start/stop; q quit.

Notes
- Live output combines the wrapper’s console with tailing of the wrapper log file when configured, so JVM logs appear while the wrapper is running.
- On Unix/macOS the launcher uses a pseudo‑tty (via `script`) when available to reduce buffering.

## Building

We use the [Gradle Wrapper](https://docs.gradle.org/8.11/userguide/gradle_wrapper.html). If you trust the committed
wrapper, you can build immediately.

Prerequisites:

- Java 25 or newer
- A POSIX shell or Windows terminal

Build the node JAR (prints SHA‑256 of the output):

```bash
./gradlew buildJar
```

Clean build:

```bash
./gradlew clean buildJar
```

### Project Layout

Cryptad now uses a partial multi-project Gradle build.

- The root project remains the daemon/application project. It still owns the daemon JAR, tests,
  `run`, `runLauncher`, `assembleCryptadDist`, and jpackage task graph.
- `:foundation-support` owns the current stable generic support subset under
  `network.crypta.support`, `network.crypta.support.api`, `network.crypta.support.io`,
  `network.crypta.support.compress`, `network.crypta.support.math`,
  `network.crypta.support.transport.ip`, and `network.crypta.support.http`, plus
  `network.crypta.io.AddressIdentifier`, `network.crypta.io.WritableToDataOutputStream`,
  `network.crypta.node.FSParseException`, `network.crypta.node.FastRunnable`,
  `network.crypta.node.SemiOrderedShutdownHook`, and `network.crypta.support.IllegalValueException`.
- `:foundation-store-contracts` owns the neutral `network.crypta.store` contracts
  `BlockMetadata`, `GetPubkey`, and `StorableBlock`, plus the store-maintenance alert seam under
  `network.crypta.store.alerts`.
- `:foundation-crypto-keys` owns `network.crypta.crypt`, `network.crypta.keys`, and the
  crypto-adjacent `network.crypta.support.io.BucketTools` and
  `network.crypta.support.io.PrependLengthOutputStream` helpers.
- `:foundation-store` owns the reusable `network.crypta.store` implementations plus
  `network.crypta.store.caching` and `network.crypta.store.saltedhash`.
- `:interop-wire` owns the narrow wire/message/schema/version/probe nucleus: leaf-safe
  `network.crypta.io.comm` message/schema classes, `network.crypta.node.Version`,
  `network.crypta.node.probe.Error` and `Type`, and `network.crypta.support.Serializer`.
- `:foundation-config` owns `network.crypta.config`, `network.crypta.l10n`, and the main
  `network/crypta/l10n/crypta.l10n.en.properties` resource plus shared config helpers such as
  `DatastoreSizingSupport`. Its public APIs now export `:foundation-support` and `:foundation-fs`
  where config types expose `SimpleFieldSet` or filesystem-facing value types.
- `:foundation-fs` owns `network.crypta.fs`.
- `:foundation-compat` owns `network.crypta.compat`, including compatibility helpers such as the
  extracted bandwidth-detection support under `network.crypta.compat.bandwidth`.
- `:runtime-spi` owns `network.crypta.runtime.spi` and the JDK-only runtime/config boundary used
  by higher layers, including detached FCP peer management plus the admin-HTTP config,
  connectivity, connections, queue, security-levels, shared page-chrome, core-update action,
  first-time-wizard, symlinker, and welcome-page slices.
- `:runtime-node` owns the extracted daemon runtime body across `network.crypta.client`, large
  slices of `network.crypta.node`, `network.crypta.io.xfer`, `network.crypta.runtime.*`, and the
  remaining daemon-coupled `network.crypta.support` / `network.crypta.support.io` /
  `network.crypta.support.api` subset that has not moved into `:foundation-support`.
- `:adapter-fcp` owns `network.crypta.clients.fcp`, including
  `network.crypta.clients.fcp.bridge`.
- `:adapter-http-legacy-admin` owns the current legacy `network.crypta.clients.http` tree plus
  the matching `network/crypta/clients/http/**` main resources such as `staticfiles/**` and
  `templates/**`. The root project no longer owns that main source/resource tree, and the
  remaining legacy browse/FProxy shell inside this leaf is boundary-frozen until a later PR
  refines it further.
- `:thirdparty-onion` owns `com.onionnetworks` and `lib/fec.properties`.
- `:thirdparty-legacy` owns `org.bitpedia`, `org.sevenzip`, and `org.spaceroots`.
- `:launcher-desktop` owns `network.crypta.launcher`, `com.jthemedetecor`, `oshi`, and launcher
  resources.
- The daemon runtime body now spans extracted leaves plus a thin root composition layer. The root
  project still owns the daemon/application build, packaging/runtime tasks, all tests,
  `network.crypta.tools`, and root-local composition code such as
  `network.crypta.runtime.bootstrap.DefaultNodeRuntimeBridgeFactories`.
- Higher-level infrastructure now crosses a narrower boundary through
  `network.crypta.runtime.spi.RuntimePorts`, the minimal wire-side `MessageSource` seam used by
  leaf-owned messages, client-owned seams such as `network.crypta.client.async.alerts` and
  `network.crypta.client.async.persistence`, and runtime-owned seams such as
  `network.crypta.runtime.alerts.feed`, `network.crypta.runtime.fcp`,
  `network.crypta.runtime.http`, `network.crypta.runtime.http.security`,
  `network.crypta.runtime.peers.reference`, and `network.crypta.runtime.persistence`.
- Default production bridge selection now starts in
  `network.crypta.runtime.bootstrap.DefaultNodeRuntimeBridgeFactories`. Concrete adapter
  implementations stay in `network.crypta.clients.fcp.bridge`,
  `network.crypta.clients.http.bridge`, and `network.crypta.clients.http.updater`, while
  higher-level runtime code depends on runtime-owned seam types such as
  `network.crypta.runtime.endpoints.fcp.FcpEndpointHandle`,
  `network.crypta.runtime.http.HttpShellContainer`, and
  `network.crypta.runtime.http.security.PasswordFormPageRenderer`. For HTTP, this bootstrap
  factory remains the production binding site that imports the concrete bridge classes from the
  extracted adapter leaf.

The wrapper validates the distribution URL (`validateDistributionUrl=true` in
`gradle/wrapper/gradle-wrapper.properties`). To also verify the download by checksum, add
`distributionSha256Sum=<sha256>` for the chosen Gradle distribution.

## Testing

- Run all tests:

```bash
./gradlew test
```

- Run a specific test class:

```bash
./gradlew test --tests *TestClassName
```

- Run a specific test method:

```bash
./gradlew test --tests *TestClassName.methodName
```

## Code Quality

- Compile only:

```bash
./gradlew compileJava
```

- Formatting via Spotless is configured; see the Spotless + Dependency Verification section if verification blocks resolution.
- Gradle daemon is enabled by default; avoid passing `--no-daemon`.

## Running Your Build

To try your local build of **Crypta**:

1. Build it with `./gradlew buildJar`.
2. Stop your running node.
3. Replace the existing node JAR with `build/libs/cryptad.jar` produced by the build.
4. Start your node again.

If you want to test the launcher without the real daemon, build with a dummy script that simulates
output (including the FProxy line):

```
./gradlew -PuseDummyCryptad=true assembleCryptadDist
build/cryptad-dist/bin/cryptad-launcher
```

Distribution (Java Service Wrapper):

- Build a portable distribution (downloads the Tanuki wrapper and assembles bin/conf/lib):

```
./gradlew assembleCryptadDist
```

- Package it as a tar.gz:

```
./gradlew distTarCryptad
```

The resulting tree at `build/cryptad-dist` contains:
- `bin/cryptad` and wrapper binaries
- `bin/cryptad-launcher` (and `cryptad-launcher.bat` on Windows)
- `conf/wrapper.conf` configured to use `lib/*.jar`
- `lib/cryptad.jar`, runtime dependencies, and `lib/wrapper.jar`

The launcher defers config path resolution to the runtime via `AppEnv` (no hard‑coded
`cryptad.ini`), adapting to system services or per‑user environments.

Use the repo’s Gradle defaults for daemon, parallelism, and JVM settings. Avoid `--no-daemon`,
`--parallel`, and ad-hoc CLI JVM tuning when running local builds.

### JLink Runtime Distribution

Build a minimal JRE image that embeds the Cryptad distribution using direct jlink/jdeps tasks (no external runtime plugin):

```bash
# 1) Build the wrapper-based dist the jlink step consumes
./gradlew assembleCryptadDist

# 2) Create the jlink image and zip/tar.gz archives
./gradlew distJlinkCryptad

# Result:
#  - build/cryptad-jlink-image/           (runnable image)
#  - build/distributions/cryptad-jlink-v<version>.zip
#  - build/distributions/cryptad-jlink-v<version>.tar.gz

# Launch using the embedded runtime (no system JRE required):
build/cryptad-jlink-image/bin/cryptad-launcher    # Windows: cryptad-launcher.bat
```

Notes
- The jlink image includes `bin/cryptad-launcher` which prefers the embedded `bin/java` and uses `lib/*` for classpath.
- We explicitly include key modules (e.g., `jdk.crypto.ec`, `java.net.http`, `jdk.unsupported`, `java.desktop`) and call `jlink` directly.
- This does not alter the existing wrapper-based distribution; it is an additional, self-contained runtime option.
- `bin/cryptad-launcher` and `cryptad-launcher.bat` now auto-detect the embedded runtime: when run from the jlink image they prefer `image/bin/java`; outside the image they fall back to `$JAVA_HOME/bin/java` or `java` on `PATH`.

### Installers (jpackage)

Build a desktop app image and (on macOS/Linux) native installers with `jpackage`. The image embeds a minimal runtime and
bundles the portable distribution under `app/cryptad-dist/` so the GUI can invoke the wrapper reliably.

Commands

```bash
# Build includes the jpackage app image.
# On Linux and macOS, it also builds native installers when tooling is present
# (Linux: DEB/RPM via `dpkg-deb`/`rpmbuild`; macOS: DMG). On Windows, installers
# are not built by `build`.
./gradlew build

# App image only
./gradlew jpackageImageCryptad

# Native installer (macOS: .dmg; Linux: .deb or .rpm)
# - Auto-picks type on Linux (prefers rpm when available)
./gradlew jpackageInstallerCryptad

# Force a specific Linux package type
./gradlew jpackageInstallerRpm     # requires rpmbuild
./gradlew jpackageInstallerDeb     # requires dpkg-deb

# Or override the auto-detected Linux type
./gradlew -PlinuxInstaller=rpm jpackageInstallerCryptad
```

Outputs (macOS example)

- App image: `build/jpackage/Crypta.app`
- Installer: `build/jpackage/Crypta-<numeric>.dmg`

Details

- App metadata: Name `Crypta`, Vendor `crypta.network`, App ID `network.crypta.cryptad`.
- Main entry: `network.crypta.launcher.Launcher`.
- Icons: `src/jpackage/macos/cryptad.icns`, `src/jpackage/windows/cryptad.ico`, `src/jpackage/linux/cryptad.png`.
- Included docs: `LICENSE.txt`, `EULA.txt` (from `LICENSE`), `README.txt` (from `README.md`).
- App layout: the launcher config (`Crypta.cfg`) sets classpath to `app/cryptad-dist/lib/*.jar`; jars are not duplicated in `app/`.
- Versioning note: jpackage enforces numeric `--app-version` (e.g., `1`). Installer filenames follow jpackage defaults (e.g., `Crypta-<version>.<ext>`).
Note: Windows installers are not built; Windows builds produce only the app image.

Linux notes

- RPM builds require `rpmbuild` to be installed and on PATH.
- When both `dpkg-deb` and `rpmbuild` are installed, the default task prefers RPM. You can force DEB/RPM using the
  tasks above or `-PlinuxInstaller=<deb|rpm>`.
- The `build` task on Linux now depends on building all available Linux installers (DEB/RPM) and will skip any
  installer type whose tool is missing.

macOS notes

- The `build` task on macOS now also builds a `.dmg` via `jpackage`.
- Unsigned DMGs are fine for local testing; macOS may require right‑click → Open
  or removing quarantine to run the app the first time.

Linux behavior and service

- Install location: the app image installs under `/opt/cryptad/Crypta` and the launcher/scripts expect `/opt/cryptad`.
- Server vs desktop detection:
  - Considered a “desktop” only when a display manager (`display-manager.service`) exists and is enabled or active.
  - As a fallback, presence of session files (`/usr/share/xsessions/*.desktop` or `/usr/share/wayland-sessions/*.desktop`) also counts as desktop.
  - This avoids mislabeling headless servers that happen to default to `graphical.target`.
- Install‑time actions:
  - Server (no desktop): install a systemd unit at `/etc/systemd/system/cryptad.service`, then `systemctl daemon-reload` and `enable` it. The service is NOT auto‑started; start it manually when ready.
  - Desktop: install a `.desktop` entry at `/usr/share/applications/crypta.desktop` and refresh caches when tools are present (`update-desktop-database`, `gtk-update-icon-cache`).
- Accounts and data:
  - Creates an explicit system group `cryptad`, then a system user `cryptad` with primary group `cryptad` (home `/var/lib/cryptad`, shell `nologin`).
  - Ensures `/var/lib/cryptad` exists and is owned by `cryptad:cryptad` (0750). Application state/log/cache directories defined in the systemd unit (e.g., `StateDirectory=cryptad`) are managed by systemd on first start.
- Removal and cleanup:
  - DEB `postrm`/RPM `%preun` disable and stop the unit only when it is enabled or active (race‑free check), remove the unit file, and run `daemon-reload`.
  - Desktop caches are refreshed; `.desktop` is removed when present. Scripts tolerate missing desktop tooling.
  - The `cryptad` user/group and data directory are preserved to avoid data loss. Remove them manually if desired.

Manual service control (Linux)

Service management (Linux):

```bash
sudo systemctl status cryptad
sudo systemctl start cryptad   # start explicitly after installation
sudo systemctl stop cryptad
sudo systemctl disable --now cryptad
```

Package removal behavior (Linux)

- DEB removal: disables/stops the service if enabled/active, removes `/etc/systemd/system/cryptad.service`, reloads systemd, and removes the desktop entry if present. The `cryptad` user/group and `/var/lib/cryptad` remain.
- RPM removal: `%preun` performs the same service cleanup; the user/group and data remain.

To remove the account and data explicitly (optional):

```bash
sudo systemctl disable --now cryptad || true
sudo rm -f /etc/systemd/system/cryptad.service && sudo systemctl daemon-reload
sudo rm -rf /var/lib/cryptad
sudo userdel cryptad 2>/dev/null || true
sudo groupdel cryptad 2>/dev/null || true
```

Troubleshooting (macOS)

- Unsigned app first‑run: right‑click → Open, or clear quarantine:

```bash
xattr -dr com.apple.quarantine "build/jpackage/Crypta.app"
```

- See launcher logs by running the Mach‑O launcher in Terminal:

```bash
build/jpackage/Crypta.app/Contents/MacOS/Crypta 2>&1 | tee /tmp/crypta-run.log
```

- Run the embedded JRE directly to isolate classpath issues:

```bash
cd build/jpackage/Crypta.app/Contents
./runtime/bin/java -cp "app/cryptad-dist/lib/*" network.crypta.launcher.Launcher
```

## Launcher Details

### Windows shutdown behavior

- The Windows batch launcher (`bin/cryptad.bat`) passes a per‑user anchor location to the wrapper: `"wrapper.anchorfile=%LOCALAPPDATA%\Cryptad.anchor"`.
- The Swing launcher requests a graceful stop by deleting that file; the Java Service Wrapper notices and shuts down the JVM cleanly (running shutdown hooks, flushing logs, etc.).
- If the process tree is still alive after ~25 seconds, the launcher escalates to `taskkill` (first without `/F`, then with `/F`).
- Advanced: To change the anchor path, customize the batch file or pass a different property on the command line; a value in `wrapper.conf` is overridden by the batch property.

### Launcher script resolution

- Env override: set `CRYPTAD_PATH` to an absolute path or a path relative to your current working directory to force a specific wrapper script, e.g. `export CRYPTAD_PATH=bin/cryptad`.
- Default resolution order (first match wins):
  - From the running `cryptad.jar` directory: `<jarDir>/cryptad`.
  - From the assembled distribution layout: `<jarDir>/../bin/cryptad`.
  - Fallbacks from `user.dir`: `./bin/cryptad`, then `./cryptad`.

## Development Guidelines

- Primary language: Java
- Code style:
  - Java: https://google.github.io/styleguide/javaguide.html
- Tests: JUnit; target 80%+ coverage
- Documentation: Add or update Javadoc when editing Java files

## Dependencies

- Runtime: Java 25+
- Tooling: Gradle Wrapper (provided in this repo)
- External libraries are managed via Gradle.
- Dependency verification is enabled. When adding or updating libraries:
  - Declare versions in `gradle/libs.versions.toml` and add usages in `build.gradle.kts`.
  - Update verification metadata so `gradle/verification-metadata.xml` and keyrings reflect the new
    artifacts; use the commands in “Spotless + Dependency Verification” below.

Root build also includes:
- `:foundation-support`: extracted stable support/api/io/compress/math/transport subset plus
  `network.crypta.support.http`, `network.crypta.io.AddressIdentifier`,
  `network.crypta.io.WritableToDataOutputStream`, `network.crypta.node.FSParseException`,
  `network.crypta.node.FastRunnable`, `network.crypta.node.SemiOrderedShutdownHook`, and
  `network.crypta.support.IllegalValueException`.
- `:foundation-store-contracts`: neutral store contracts plus the store-maintenance alert seam
  shared by store code and root runtime/UI adapters.
- `:foundation-crypto-keys`: extracted `network.crypta.crypt`, `network.crypta.keys`, and the
  adjacent `BucketTools` / `PrependLengthOutputStream` helpers.
- `:foundation-store`: extracted reusable `network.crypta.store` implementations, caching, and
  salted-hash storage code.
- `:interop-wire`: extracted wire/message/schema/address/version/probe nucleus plus
  `network.crypta.support.Serializer`.
- `:foundation-config`: extracted config/l10n code, main l10n resources, and shared sizing helpers
  such as `DatastoreSizingSupport`. Its public APIs re-export `:foundation-support` and
  `:foundation-fs` where required.
- `:launcher-desktop`: Swing launcher code and desktop/theme detection dependencies.
- `:thirdparty-onion`: Onion FEC and related vendored sources/resources.
- `:thirdparty-legacy`: Bitpedia, SevenZip, and Spaceroots vendored code.
- `:runtime-spi`: JDK-only runtime ports plus immutable config snapshot/value types used by FCP
  and other infrastructure code.
- `:runtime-node`: extracted daemon runtime body across `network.crypta.client`, large
  `network.crypta.node` and `network.crypta.runtime.*` slices, `network.crypta.io.xfer`, and the
  remaining daemon-coupled support helpers.
- `:adapter-fcp`: extracted `network.crypta.clients.fcp` adapter code, including
  `network.crypta.clients.fcp.bridge`.
- `:adapter-http-legacy-admin`: extracted legacy `network.crypta.clients.http` adapter code plus
  `network/crypta/clients/http/**` main resources. The root project no longer owns that main
  HTTP source/resource tree, and the remaining browse/FProxy shell in this adapter is
  boundary-frozen for now.
- `:foundation-fs` and `:foundation-compat`: extracted filesystem/environment and compatibility
  leaf modules used by the root daemon. `:foundation-compat` also carries the wizard-neutral
  bandwidth-detection helpers now used by first-time setup flows.

### Spotless + Dependency Verification

When Gradle dependency verification is strict, Spotless may fail to resolve formatter artifacts (e.g., `google-java-format`). If that happens:

1. Temporarily set verification to lenient in `gradle.properties`:
   - `org.gradle.dependency.verification=lenient`
2. Write verification metadata (SHA256 + PGP):
   - `./gradlew --write-verification-metadata sha256,pgp spotlessApply`
   - Optional exact version refresh:
     - `./gradlew --refresh-dependencies --write-verification-metadata sha256,pgp spotlessApply`
   - Faster alternative (no formatting run):
     - `./gradlew --write-verification-metadata sha256,pgp spotlessInternalRegisterDependencies`
3. Confirm entries in `gradle/verification-metadata.xml` for `com.google.googlejavaformat` and trusted keys.
4. Restore strict mode:
   - `org.gradle.dependency.verification=strict`
5. Validate:
   - `./gradlew spotlessApply`

Tip: Keep the Spotless formatter at the intended version (currently `googleJavaFormat("1.28.0")`). If verification still blocks, re‑write metadata including `pgp` and ensure a group‑level trusted key entry. Commit updated verification keyring files as appropriate.

## Versioning

- The build number is a single integer in `build.gradle.kts` (e.g., `version = "<int>"`).
- During build, tokens are replaced into the generated version source file (e.g., `@build_number@`, `@git_rev@`).
- Version strings support both Cryptad and Fred formats for wire compatibility; protocol compatibility enforces minimum builds.

## Branching & Releases

- Standard branching and release workflow: see `docs/standard-git-branching-and-release-workflow.md` (validated copy). The original wiki page is also available: https://github.com/crypta-network/cryptad/wiki/Standard-Git-Branching-and-Release-Workflow-for-Cryptad
- [Release workflow and operations runbook](https://github.com/crypta-network/cryptad/wiki/Cryptad-Release-Workflow-and-Runbook)

## Update System

- Core updates use a package‑based updater (“CoreUpdater”). It subscribes to an `info/<N>` JSON descriptor via the existing update USK, selects an OS/arch‑specific installer (deb/rpm/dmg/exe/flatpak/snap), and downloads to `nodeDir/updates/core/<version>/`.
- Installing the OS package is a user/OS action. On Linux, the UI may hand off to the system’s software center or PackageKit. On macOS/Windows, follow the platform guidance shown in the UI.
- JAR Update‑over‑Mandatory (UOM) for the core is disabled in favor of the package flow.
- For developer testing, replacing `build/libs/cryptad.jar` manually (as noted above) is fine; for production use CoreUpdater and platform packages.

## Architecture Overview

- Build/module layout:
  - Root project `:cryptad` remains the daemon/application build and still owns the strongly
    coupled composition layer, all tests, packaging/runtime tasks, root-local bridge selection,
    and `network.crypta.tools`.
  - Leaf subprojects are `:foundation-support`, `:foundation-store`,
    `:foundation-store-contracts`, `:foundation-crypto-keys`, `:interop-wire`,
    `:foundation-config`, `:foundation-fs`, `:foundation-compat`, `:runtime-spi`,
    `:runtime-node`, `:adapter-fcp`, `:adapter-http-legacy-admin`, `:thirdparty-onion`,
    `:thirdparty-legacy`, and `:launcher-desktop`.
- Core network (`network.crypta.node`): `Node`, `PeerNode`, `PeerManager`, `PacketSender`, `RequestStarter`, `RequestScheduler`, `NodeUpdateManager`.
- Storage (`network.crypta.store`): `FreenetStore`, `CHKStore`, `SSKStore`, `SlashdotStore`.
  `:foundation-store` now owns the reusable store implementations, cache layer, and salted-hash
  storage code. `:foundation-store-contracts` owns the neutral contracts plus the
  `network.crypta.store.alerts` seam used by root runtime/UI adapters such as
  `UserAlertManagerStoreAlertSink`.
- Crypto (`network.crypta.crypt`): AES, DSA/ECDSA, SHA‑256, `RandomSource`/Yarrow. This package
  now lives in `:foundation-crypto-keys`.
- Keys (`network.crypta.keys`): `ClientCHK`, `ClientSSK`, `FreenetURI`, USK. This package now
  lives in `:foundation-crypto-keys`.
- Wire/message nucleus (`network.crypta.io.comm`, `network.crypta.node.Version`,
  `network.crypta.node.probe`, `network.crypta.support.Serializer`): `:interop-wire` owns the
  leaf-safe message/schema/address/version/probe subset, including `Message`, `MessageType`,
  `Peer`, `FreenetInetAddress`, `Version`, and the probe enums. The root project still owns the
  transport/socket/filter side of `network.crypta.io.comm`, and `Message` now depends on the
  minimal `MessageSource` seam rather than directly on `PeerContext`.
- Clients: `network.crypta.client`, FCP (`network.crypta.clients.fcp`), HTTP
  (`network.crypta.clients.http`). The async client layer now also owns client-local seams under
  `network.crypta.client.async.alerts` and `network.crypta.client.async.persistence` so runtime
  bridges can publish alerts and recover durable requests without owning those contracts.
  `network.crypta.clients.fcp` now lives in `:adapter-fcp`. It consumes execution, randomness,
  transfer policy, lifecycle, config access, and detached peer mutations through `RuntimePorts`
  and FCP-local adapters instead of reaching directly into daemon internals for those concerns.
  FCP bootstrap now flows through `FcpServerDependencies` and
  `CoreFcpServerDependenciesFactory`, with package-local seams such as
  `FcpServerRuntimeSupport`, `FcpMessageRuntimeSupport`, `FcpFetchRuntimeSupport`, and
  `FcpInsertRuntimeSupport` splitting server-owned, message-owned, GET/fetch, and insert/USK
  concerns. Runtime-owned FCP seam types now live under `network.crypta.runtime.fcp` and
  `network.crypta.runtime.endpoints.fcp`, while concrete persistent-request services, queue
  adapters, alert-feed adapters, and endpoint-handle wrappers now live under
  `network.crypta.clients.fcp.bridge`.
  `network.crypta.clients.http` now lives in `:adapter-http-legacy-admin` together with its
  `staticfiles/**` and `templates/**` resources. The migrated HTTP management and shell slices
  cross the boundary in three layers: `RuntimePorts` for JDK-only detached runtime state,
  runtime-owned shell and password-prompt seams under `network.crypta.runtime.http` and
  `network.crypta.runtime.http.security`, and client-local helpers such as
  `BookmarkRuntimeSupport`, `FProxyRuntimeSupport`, `HttpShellFProxyBootstrap`, and
  `FProxyRegistrarDependencies`. Concrete HTTP shell, bookmark, GeoIP, security-page, and
  updater-action adapters now live under `network.crypta.clients.http.bridge` and
  `network.crypta.clients.http.updater`, while root-local bridge selection stays in
  `DefaultNodeRuntimeBridgeFactories`. The remaining legacy browse/FProxy tree inside
  `:adapter-http-legacy-admin` is intentionally boundary-frozen until a later PR refines it
  further, and production code outside the adapter should keep depending on runtime seams rather
  than taking new `network.crypta.clients.http.*` dependencies.
- Runtime SPI (`network.crypta.runtime.spi`): JDK-only ports and detached DTOs such as
  `RuntimePorts`, `ConfigPort`, `NodeInfoPort`, `PeerPort`, `ConnectionsPagePort`,
  `ConnectionsSupportPort`, `DarknetConnectionsPort`, `DarknetMessagingPort`, `QueuePagePort`,
  `QueueDownloadPort`, `QueueInsertPort`, `QueueMutationPort`, `QueueSupportPort`,
  `QueueCompletionPort`, `SecurityLevelsPort`, `PageChromePort`, `CoreUpdateActionPort`,
  `FirstTimeWizardPort`, `ToadletSymlinkPort`, `WelcomePagePort`, `WelcomeActionPort`,
  `ConfigSnapshot`, `ConfigFieldSet`, `QueuePageSnapshot`, `QueueInsertOutcome`,
  `SecurityLevelsSnapshot`, `PageChromeSnapshot`, `FirstTimeWizardSnapshot`,
  `FirstTimeWizardCurrentBandwidthLimits`, `ToadletSymlinkEntry`, and `WelcomePageSnapshot`.
- Runtime package families (`network.crypta.runtime.*`): most behaviorful runtime code now lives
  in `:runtime-node`, including startup/CLI wiring such as `NodeStarter`, `NodeBootstrap`,
  `NodeCli`, and `NodeConfigManager`; core SPI adapters such as `LegacyRuntimePorts`,
  `LegacyConfigPort`, `LegacyConnectivityPort`, `LegacyNodeInfoPort`, `LegacyPeerPort`,
  `LegacyRequestQueuePort`, `LegacySecurityLevelsPort`, and `LegacyCoreUpdateActionPort`;
  page-oriented admin adapters such as `LegacyConnectionsPagePort`, `LegacyQueuePagePort`,
  `LegacyPageChromePort`, `LegacyFirstTimeWizardPort`, and `LegacyWelcomePagePort`; endpoint glue
  such as `ClientEndpoints`, `NodeClientCoreInit`, and `NodeClientPersistence`; shell/password
  seams under `runtime.http`; and updater classes such as `NodeUpdateManager` and `CoreUpdater`.
  The root project keeps the composition class `DefaultNodeRuntimeBridgeFactories`, which selects
  the concrete FCP and HTTP bridge implementations from the extracted adapter leaves.
- Config + localization leaf (`:foundation-config`): `network.crypta.config`,
  `network.crypta.l10n`, and the main l10n properties. Its public APIs re-export
  `:foundation-support` and `:foundation-fs` where config surfaces expose `SimpleFieldSet` or
  filesystem-facing types. Shared setup helpers such as `DatastoreSizingSupport` now also live in
  this leaf. Higher layers should still prefer `RuntimePorts#config()` and the root
  `network.crypta.runtime.core.LegacyConfigPort` bridge instead of reaching through daemon
  internals.
- Support foundation leaf (`:foundation-support`): stable generic support, support-api,
  support-io, support-compress, support-math, transport-IP, and support-http classes plus
  `network.crypta.io.AddressIdentifier`, `network.crypta.io.WritableToDataOutputStream`,
  `network.crypta.node.FSParseException`, `network.crypta.node.FastRunnable`,
  `network.crypta.node.SemiOrderedShutdownHook`, and `network.crypta.support.IllegalValueException`.
- Support (`network.crypta.support`): logging, data structures, threading, and helpers are now
  split between `:foundation-support` and the root project. Keep generic reusable utilities in the
  foundation leaf; daemon-coupled support code still remains in root.
- Launcher/Desktop: `:launcher-desktop` provides `network.crypta.launcher`,
  `com.jthemedetecor`, launcher resources, and desktop-theme integration.
- Extracted foundations: `:foundation-support` provides the stable generic support subset,
  `:foundation-store-contracts` provides neutral store contracts and alert seams,
  `:foundation-crypto-keys` provides `network.crypta.crypt` and `network.crypta.keys`,
  `:foundation-store` provides reusable store implementations, `:interop-wire` provides the
  wire/version/probe nucleus, `:foundation-config` provides config/l10n plus datastore-sizing
  helpers,
  `:foundation-fs` provides `network.crypta.fs`, and `:foundation-compat` provides
  `network.crypta.compat` plus compatibility helpers such as the extracted bandwidth-detection
  support.
- Runtime boundary leaves: `:runtime-spi` provides `network.crypta.runtime.spi`; `:runtime-node`
  provides the extracted daemon runtime body across `network.crypta.client`, large
  `network.crypta.node` / `network.crypta.runtime.*` slices, `network.crypta.io.xfer`, and the
  remaining daemon-coupled support helpers; `:adapter-fcp` provides
  `network.crypta.clients.fcp`; and `:adapter-http-legacy-admin` provides the current legacy
  `network.crypta.clients.http` classes and resources.
- Vendored libraries: `:thirdparty-onion` provides `com.onionnetworks`,
  `:thirdparty-legacy` provides `org.bitpedia`, `org.sevenzip`, and `org.spaceroots`.

You generally do not need to install libraries manually; Gradle resolves them.

## License

**Crypta** is free software licensed under the GNU General Public License, version 3 only. See `LICENSE` for the full text.

Some bundled components may be under permissive licenses (e.g., Apache‑2.0, BSD‑3‑Clause). These are compatible with
GPLv3 and included under their respective terms.
