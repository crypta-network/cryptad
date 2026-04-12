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
- On systems without a desktop environment, the installer (deb/rpm) creates a systemd unit `cryptad.service` and enables it, but does not start it automatically. You must start it manually after installation:
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

The launcher starts the daemon, streams live logs, waits for a structured readiness file under the
resolved runtime directory (currently `<runDir>/platform-ui.properties`), and opens
`http://localhost:<port>/` on the first successful start. If the readiness file cannot be used,
the launcher can still fall back to the legacy `Starting FProxy on ...:<port>` log line.

Shortcuts (global):
- ↑/↓ one row; PgUp/PgDn one page.
- ←/→ move focus among the three buttons (wrap‑around).
- Enter/Space click the focused button; s start/stop; q quit.

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
  `network.crypta.node.PrioRunnable`, `network.crypta.node.SemiOrderedShutdownHook`,
  `network.crypta.support.IllegalValueException`, `network.crypta.support.JVMVersion`, the generic
  `HTTPRequest` / `HTTPUploadedFile` / `MultiValueTable` / `SizeUtil` support surface, and the
  cycle-safe file-backed support I/O slice (`BaseFileBucket`, `FileBucket`,
  `FileRandomAccessBuffer`, `PersistentTempFileBucket`, `PooledFileRandomAccessBuffer`,
  `TempFileBucket`, and their related exceptions/factories).
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
  extracted bandwidth-detection support under `network.crypta.compat.bandwidth`, plus the shared
  `network.crypta.runtime.core.SSL` helper.
- `:kernel-content` owns the compile-neutral phase-1 content slice across selected
  `network.crypta.client`, `network.crypta.client.events`, `network.crypta.client.filter`,
  `network.crypta.client.async.alerts`, `network.crypta.client.async.persistence`, the leaf-safe
  `network.crypta.client.events` contract/helper subset (`ClientEventListener`,
  `ClientEventProducer`, `SimpleEventProducer`, `EventLogger`, `EventDumper`,
  `SplitfileProgressEvent`), the leaf-safe `network.crypta.client.async` utility/value subset (`BlockSet`, `BinaryBlob`,
  `BinaryBlobFormatException`, `BinaryBlobWriter`, `CacheFetchResult`, `ClientGetterOptions`,
  `ClientPutterOptions`, `PersistenceDisabledException`, `TooManyFilesInsertException`), the
  client failure/filter exception subset, the MIME helper `network.crypta.support.MediaType`, and
  the small manifest/model helper subset under `network.crypta.support.*` (`ManifestElement` and
  `ContainerSizeEstimator`) that stay free of `:runtime-node`, adapter, and root-composition
  dependencies.
- `:kernel-transport` owns the compile-neutral phase-1 transport slice across selected
  `network.crypta.io`, `network.crypta.io.comm`, and `network.crypta.io.xfer` helpers such as
  address matching, allowlist parsing, listener abstraction, I/O statistics collection, transfer
  throttling, and partially received block assembly that stay free of `:runtime-node`, adapters,
  and root-composition dependencies.
- `:kernel-routing` owns the compile-neutral phase-1 routing/helper slice across selected
  `network.crypta.node` value, exception, callback, and request-item helper types such as
  `BaseRequestThrottle`, `LowLevelGetException`, `LowLevelPutException`, `RequestClient`,
  `PeerStatusCounts`, and `SendableRequestItem*` that stay free of `:runtime-node`, adapters, and
  root-composition dependencies.
- `:runtime-spi` owns `network.crypta.runtime.spi` and the JDK-only runtime/config boundary used
  by higher layers, including detached FCP peer management plus the admin-HTTP config,
  connectivity, connections, queue, security-levels, shared page-chrome, core-update action,
  first-time-wizard, symlinker, and welcome-page slices plus shared path constants such as
  `ConnectivityPagePaths` and `UpdaterPaths`.
- `:platform-api` owns the transport-neutral Platform API v1 under
  `network.crypta.platform.api`. It sits above `:runtime-spi`, exposes detached runtime snapshots
  and the minimal local AppHost control surface as JSON-oriented responses, and is currently
  mounted at `/api/v1/` through a thin legacy HTTP bridge in `:adapter-http-legacy-admin`. The
  current surface covers node info, peers, config export, connectivity, security-level snapshots,
  and local app install/start/stop/update/uninstall routes; `GET /api/v1/config` defaults to the
  effective `CURRENT` section when `sections=` is omitted.
- `:platform-apphost` owns the transport-neutral out-of-process AppHost v1 core under
  `network.crypta.platform.apphost`. It defines the local manifest, installed-app layout, process
  lifecycle, and per-start launch-token plumbing for local apps while staying separate from future
  Web Shell, application-UI, and remote update-channel work.
- `:platform-web-shell` owns the first browser-facing Web Shell v1 under
  `network.crypta.platform.webshell`. It keeps the node-management shell's route constants,
  bootstrap payload, HTML renderer, and plain browser assets self-owned while staying separate
  from runtime, adapter, Platform API, and AppHost implementation code. That shell is mounted at
  `/app/node/` through a thin legacy HTTP bridge in `:adapter-http-legacy-admin`.
- `:runtime-alerts` owns the extracted leaf-safe alert/feed subset under
  `network.crypta.runtime.alerts`, including the full `feed` package plus the reusable alert
  model/base types that no longer need direct daemon state.
- `:runtime-node` owns the remaining daemon runtime body across the still-cyclic
  `network.crypta.client` async/request engine and high-level client APIs, large slices of
  `network.crypta.node` after the phase-1 routing/helper move, the retained runtime-owned client
  context and metadata implementation, and the retained node-coupled transport/message execution
  code in
  `network.crypta.io`, `network.crypta.io.comm`, and `network.crypta.io.xfer`, the remaining
  daemon-bound `network.crypta.runtime.*` implementation slices, and the remaining daemon-coupled
  `network.crypta.support` / `network.crypta.support.io` / `network.crypta.support.api` subset
  after the generic HTTP, multimap, size-formatting, and file-backed bucket slice moved into
  `:foundation-support` and the manifest/model helper subset moved into `:kernel-content`.
- `:adapter-fcp` owns the protocol-side `network.crypta.clients.fcp` package tree.
- `:bridge-fcp-runtime` owns the concrete runtime-binding bridge package
  `network.crypta.clients.fcp.bridge`.
- `:adapter-http-legacy-admin` owns the current legacy `network.crypta.clients.http` tree plus
  the matching `network/crypta/clients/http/**` main resources such as `staticfiles/**` and
  `templates/**`, excluding `network.crypta.clients.http.bridge` and
  `network.crypta.clients.http.geoip`. The remaining legacy
  browse/FProxy shell inside this leaf is boundary-frozen until a later PR refines it further.
  That shell also hosts the temporary `/api/v1/` mount for `:platform-api` plus the first
  `/app/node/` Web Shell bridge for `:platform-web-shell`; future AppHost UI and remote
  update-channel work remain separate. The concrete HTTP bridge implementations plus the legacy
  HTTP GeoIP helper package now live in `:bridge-http-runtime`, while the updater-action adapters stay in
  `network.crypta.clients.http.updater` under the adapter leaf. See
  [docs/legacy-http-boundary.md](docs/legacy-http-boundary.md) for the explicit maintenance
  boundary.
- `:thirdparty-onion` owns `com.onionnetworks` and `lib/fec.properties`.
- `:thirdparty-legacy` owns `org.bitpedia`, `org.sevenzip`, and `org.spaceroots`.
- `:launcher-desktop` owns `network.crypta.launcher`, `com.jthemedetecor`, `oshi`, and launcher
  resources.
- The daemon runtime body now spans extracted leaves plus a thin root composition layer. The root
  project still owns the daemon/application build, packaging/runtime tasks, most broad
  functional/unit/integration tests, `network.crypta.tools`, and root-local composition code such
  as `network.crypta.runtime.bootstrap.DefaultNodeRuntimeBridgeFactories`. The extracted leaves now
  keep their own focused boundary suites alongside the code they protect.
- Every extracted leaf keeps its aggregated-output ownership metadata in
  `<leaf>/gradle/owned-output-patterns.txt`. When you move main classes or resources between root
  and a leaf, or between leaves, update that metadata and validate it with
  `./gradlew verifySelectiveLeafOwnershipMetadata buildJar` so stale non-owner outputs do not leak
  back into aggregated builds.
- Higher-level infrastructure now crosses a narrower boundary through
  `network.crypta.runtime.spi.RuntimePorts`, the minimal wire-side `MessageSource` seam used by
  leaf-owned messages, the new phase-1 `:kernel-content` content slice, the phase-1
  `:kernel-transport` helper slice, the phase-1 `:kernel-routing` helper slice, client-owned seams
  such as `network.crypta.client.async.alerts`,
  `network.crypta.client.async.persistence`, and the leaf-safe
  `network.crypta.client.async` utility/value subset, and runtime-owned seams such as
  `network.crypta.runtime.alerts.feed`, `network.crypta.runtime.fcp`,
  `network.crypta.runtime.http`, `network.crypta.runtime.http.security`,
  `network.crypta.runtime.peers.reference`, and `network.crypta.runtime.persistence`.
- Default production bridge selection now starts in
  `network.crypta.runtime.bootstrap.DefaultNodeRuntimeBridgeFactories`. Concrete adapter
  implementations stay in `network.crypta.clients.fcp.bridge` under
  `:bridge-fcp-runtime`, `network.crypta.clients.http.bridge` under `:bridge-http-runtime`, and
  `network.crypta.clients.http.updater` under `:adapter-http-legacy-admin`, while higher-level
  runtime code depends on runtime-owned seam types such as
  `network.crypta.runtime.endpoints.fcp.FcpEndpointHandle`,
  `network.crypta.runtime.http.HttpShellContainer`, and
  `network.crypta.runtime.http.security.PasswordFormPageRenderer`. For HTTP, this bootstrap
  factory remains the production binding site that imports the concrete bridge classes from the
  extracted bridge leaf.

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

For extraction and boundary work, run the focused leaf-local boundary suites that freeze current
leaf ownership and import rules:

```bash
./gradlew :platform-api:test
./gradlew :platform-apphost:test
./gradlew :platform-web-shell:test
./gradlew :kernel-content:test
./gradlew :kernel-transport:test
./gradlew :kernel-routing:test
./gradlew :runtime-node:test
./gradlew :adapter-fcp:test
./gradlew :adapter-http-legacy-admin:test
```

Those boundary suites also enforce the current extracted-leaf documentation convention that the
production packages they own keep the required `package-info.java`.

Run the remaining root-owned composition and router slice against the root project explicitly:

```bash
./gradlew :test --tests *DefaultNodeRuntimeBridgeFactoriesTest --tests *PlatformApiRouterTest --tests *PlatformApiAppsIntegrationTest
```

Additional root and mixed verification slices remain available:

```bash
./gradlew :adapter-http-legacy-admin:test
./gradlew :test --tests *PlatformApiRouterTest --tests *PlatformApiAppsIntegrationTest
```

Platform boundary checks now live in `:platform-api`, `:platform-apphost`, and
`:platform-web-shell`.

## Code Quality

- Compile only:

```bash
./gradlew compileJava
```

- Formatting via Spotless is configured; see the Spotless and Dependency Verification section if verification blocks resolution.
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
- Server vs. desktop detection:
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
- Advanced: To change the anchor path, customize the batch file, or pass a different property on the command line; a value in `wrapper.conf` is overridden by the batch property.

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
  `network.crypta.support.IllegalValueException`, including the generic `HTTPRequest` /
  `HTTPUploadedFile` / `MultiValueTable` / `SizeUtil` surface and the cycle-safe file-backed
  support I/O slice.
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
- `:kernel-content`: compile-neutral phase-1 content leaf spanning selected
  `network.crypta.client`, `network.crypta.client.events`, `network.crypta.client.filter`,
  `network.crypta.client.async.alerts`, `network.crypta.client.async.persistence`, the
  `network.crypta.client.events` contract/helper subset (`ClientEventListener`,
  `ClientEventProducer`, `SimpleEventProducer`, `EventLogger`, `EventDumper`,
  `SplitfileProgressEvent`), the leaf-safe `network.crypta.client.async` utility/value subset, the leaf-safe
  client failure/filter exception subset, `network.crypta.support.MediaType`, and the small
  manifest/model helper subset under `network.crypta.support.*`.
- `:kernel-transport`: compile-neutral phase-1 transport leaf spanning selected
  `network.crypta.io`, `network.crypta.io.comm`, and `network.crypta.io.xfer` helpers such as
  allowlist parsing, listener abstraction, statistics collection, throttling, and partially
  received block assembly.
- `:kernel-routing`: compile-neutral phase-1 routing/helper leaf spanning selected
  `network.crypta.node` value, exception, callback, and request-item helper types such as
  `BaseRequestThrottle`, `LowLevelGetException`, `LowLevelPutException`, `RequestClient`,
  `PeerStatusCounts`, and `SendableRequestItem*`.
- `:runtime-spi`: JDK-only runtime ports plus immutable config snapshot/value types used by FCP
  and other infrastructure code, including shared path constants such as `ConnectivityPagePaths`
  and `UpdaterPaths`.
- `:platform-api`: transport-neutral Platform API v1 built on top of `:runtime-spi` and
  `:platform-apphost`, currently mounted under `/api/v1/` through the legacy HTTP admin adapter.
- `:platform-apphost`: transport-neutral out-of-process AppHost v1 core for installed local apps.
  Local staged app updates now flow through this core; future Web Shell, app UI, and remote
  update-channel work remain separate and later.
- `:platform-web-shell`: browser-facing Web Shell v1 leaf owning the node-management shell route
  descriptors, bootstrap payload, and static browser assets that the legacy HTTP adapter mounts at
  `/app/node/`.
- `:runtime-node`: extracted daemon runtime body across the remaining cyclic/high-level
  `network.crypta.client` body, the remaining peer/request/routing-engine and transport-heavy
  `network.crypta.node` / `network.crypta.runtime.*` slices, the retained node-coupled
  transport/message execution code in `network.crypta.io*`, and the remaining daemon-coupled
  support helpers after the generic HTTP, multimap, size-formatting, and file-backed bucket slice
  moved into `:foundation-support` and the manifest/model helper subset moved into
  `:kernel-content`.
- `:adapter-fcp`: extracted `network.crypta.clients.fcp` protocol leaf.
- `:bridge-fcp-runtime`: extracted concrete `network.crypta.clients.fcp.bridge` runtime-binding
  leaf.
- `:adapter-http-legacy-admin`: extracted legacy `network.crypta.clients.http` adapter code plus
  `network/crypta/clients/http/**` main resources. The root project no longer owns that main
  HTTP source/resource tree, and the remaining browse/FProxy shell in this adapter is
  boundary-frozen for now. It currently hosts both the temporary `/api/v1/` bridge for
  `:platform-api` and the initial `/app/node/` bridge for `:platform-web-shell`. See
  [docs/legacy-http-boundary.md](docs/legacy-http-boundary.md) for the explicit maintenance
  boundary.
- `:bridge-http-runtime`: extracted concrete `network.crypta.clients.http.bridge`
  runtime-binding leaf plus the legacy HTTP `network.crypta.clients.http.geoip` helper package
  used by that bridge. Root bootstrap still selects the default production bridge set in
  `DefaultNodeRuntimeBridgeFactories`, while `network.crypta.clients.http.updater` remains in
  `:adapter-http-legacy-admin`.
- `:foundation-fs` and `:foundation-compat`: extracted filesystem/environment and compatibility
  leaf modules used by the root daemon. `:foundation-compat` also carries the wizard-neutral
  bandwidth-detection helpers now used by first-time setup flows, plus the shared
  `network.crypta.runtime.core.SSL` helper.
- `:runtime-alerts`: extracted leaf-safe alert/feed module owning the full
  `network.crypta.runtime.alerts.feed` package plus reusable alert model/base classes that stay
  free of direct `Node`/`NodeClientCore` coupling.

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
- Local app lifecycle work is separate from CoreUpdater. The current platform can install, start,
  stop, uninstall, and replace an installed app bundle from a caller-supplied local staged
  directory through `:platform-apphost` and the Platform API v1. Remote catalogs, signed app
  channels, and background app-update fetching remain future work.

## Architecture Overview

- Build/module layout:
  - Root project `:cryptad` remains the daemon/application build and still owns the strongly
    coupled composition layer, most broad functional/unit/integration tests, packaging/runtime
    tasks, root-local bridge selection, and `network.crypta.tools`. Focused extracted-leaf
    boundary suites now live in the owning leaf modules.
  - Leaf subprojects are `:foundation-support`, `:foundation-store`,
    `:foundation-store-contracts`, `:foundation-crypto-keys`, `:interop-wire`,
    `:foundation-config`, `:foundation-fs`, `:foundation-compat`, `:kernel-content`,
    `:kernel-transport`, `:kernel-routing`, `:runtime-spi`, `:runtime-alerts`,
    `:platform-api`, `:platform-apphost`, `:platform-web-shell`, `:runtime-node`,
    `:adapter-fcp`, `:bridge-fcp-runtime`, `:bridge-http-runtime`,
    `:adapter-http-legacy-admin`, `:thirdparty-onion`, `:thirdparty-legacy`, and
    `:launcher-desktop`.
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
  `Peer`, `FreenetInetAddress`, `Version`, and the probe enums. `:kernel-transport` now owns the
  compile-neutral transport helper slice across selected `network.crypta.io`,
  `network.crypta.io.comm`, and `network.crypta.io.xfer` classes such as `AllowedHosts`,
  `NetworkInterface`, `IOStatisticCollector`, `SocketHandler`, `PacketThrottle`, and
  `PartiallyReceivedBlock`. `:kernel-routing` now owns the compile-neutral phase-1
  `network.crypta.node` helper/value slice, including `BaseRequestThrottle`,
  `LowLevelGetException`, `LowLevelPutException`, `RequestClient`, `PeerStatusCounts`,
  `RecentlyFailedReturn`, and `SendableRequestItem*`. `:runtime-node` keeps the node-coupled
  transport/socket/filter side of `network.crypta.io*` plus the remaining peer, scheduler,
  request-sender, and routing-engine side of `network.crypta.node`, and `Message` now depends on
  the minimal `MessageSource` seam rather than directly on `PeerContext`.
- Clients: `network.crypta.client`, FCP (`network.crypta.clients.fcp`), HTTP
  (`network.crypta.clients.http`). `:kernel-content` now owns the compile-neutral phase-1 content
  slice: selected client value/archive/helper classes, immutable client event values, a
  conservative subset of filter helper/parser types, the client-facing
  fetch/insert/content-safety failure subset, the full
  `network.crypta.client.async.alerts` seam, the client-local persistence seams under
  `network.crypta.client.async.persistence`, the leaf-safe
  `network.crypta.client.async` utility/value subset, and the MIME helper
  `network.crypta.support.MediaType`, plus the small manifest/model helper subset under
  `network.crypta.support.*` (`ManifestElement` and `ContainerSizeEstimator`). `:runtime-node`
  still owns the cyclic async
  scheduler/request engine, high-level client APIs, and the remaining filter/archive surfaces that
  still depend on runtime-owned request and node types.
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
  `network.crypta.clients.fcp.bridge` in `:bridge-fcp-runtime`.
  `network.crypta.clients.http` now lives in `:adapter-http-legacy-admin` together with its
  `staticfiles/**` and `templates/**` resources, excluding the concrete bridge package under
  `network.crypta.clients.http.bridge` and the legacy HTTP GeoIP helper package under
  `network.crypta.clients.http.geoip`. The migrated HTTP management and shell slices cross the
  boundary in three layers: `RuntimePorts` for JDK-only detached runtime state, `:platform-api`
  for the Platform API v1 router and JSON surface currently mounted at `/api/v1/`,
  `:platform-web-shell` for the first browser-facing node-management shell currently mounted at
  `/app/node/`, runtime-owned shell and password-prompt seams under
  `network.crypta.runtime.http` and `network.crypta.runtime.http.security`, and client-local
  helpers such as `BookmarkRuntimeSupport`, `FProxyRuntimeSupport`, `HttpShellFProxyBootstrap`,
  and the shared HTTP route registrar seam. Concrete HTTP shell, bookmark, GeoIP, and
  security-page adapters now live under `network.crypta.clients.http.bridge` in
  `:bridge-http-runtime`, and that leaf also owns the legacy HTTP GeoIP helper package
  `network.crypta.clients.http.geoip`. The updater-action adapters remain under
  `network.crypta.clients.http.updater` in `:adapter-http-legacy-admin`. Root-local bridge
  selection stays in `DefaultNodeRuntimeBridgeFactories`, which now installs the admin-owned HTTP
  registrar implementation into the shared shell. The remaining legacy browse/FProxy tree inside
  `:adapter-http-legacy-admin` is intentionally boundary-frozen until a later PR refines it
  further, and production code outside the adapter should keep depending on runtime seams rather
  than taking new `network.crypta.clients.http.*` dependencies. See
  [docs/legacy-http-boundary.md](docs/legacy-http-boundary.md) for the explicit maintenance
  boundary.
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
  The extracted `:runtime-alerts` leaf now owns the reusable alert/feed model subset under
  `network.crypta.runtime.alerts`, while `:runtime-node` keeps `UserAlertManager` and the
  daemon-coupled alert producers. The root project keeps the composition class
  `DefaultNodeRuntimeBridgeFactories`, which selects the concrete FCP and HTTP bridge
  implementations from the extracted adapter leaves.
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
  `network.crypta.node.PrioRunnable`, `network.crypta.node.SemiOrderedShutdownHook`, and
  `network.crypta.support.IllegalValueException`, plus `network.crypta.support.JVMVersion`.
- Support (`network.crypta.support`): logging, data structures, threading, and helpers are now
  split between `:foundation-support` and the root project. Keep generic reusable utilities in the
  foundation leaf; daemon-coupled support code still remains in the root.
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
  support and the shared `network.crypta.runtime.core.SSL` helper.
- Runtime boundary leaves: `:kernel-content` provides the compile-neutral phase-1 content slice
  across selected `network.crypta.client*` classes, the leaf-safe client failure/filter
  exception subset, the `network.crypta.client.async.persistence` seam, the leaf-safe
  `network.crypta.client.async` utility/value subset, plus
  `network.crypta.support.MediaType` and the small manifest/model helper subset under
  `network.crypta.support.*`;
  `:kernel-transport` provides the compile-neutral phase-1 transport slice across selected
  `network.crypta.io*` helpers; `:kernel-routing` provides the compile-neutral phase-1
  `network.crypta.node` helper slice across selected request/routing value, exception, callback,
  and request-item types; `:runtime-spi` provides `network.crypta.runtime.spi`;
  `:runtime-alerts` provides the extracted leaf-safe `network.crypta.runtime.alerts`
  feed/model subset;
  `:platform-api` provides the transport-neutral Platform API v1 plus the minimal AppHost
  control-plane routes; `:platform-apphost` provides the transport-neutral out-of-process AppHost
  v1 core for installed local apps;
  `:platform-web-shell` provides the browser-facing Web Shell v1 node-management assets and
  bootstrap contract; `:runtime-node`
  provides the extracted daemon runtime body across the remaining cyclic/high-level
  `network.crypta.client` body, the remaining peer/request/routing-engine
  `network.crypta.node` / `network.crypta.runtime.*` slices, the retained node-coupled
  transport/message execution code, and the remaining daemon-coupled support helpers outside the
  small `:kernel-content` manifest/model helper subset;
  `:adapter-fcp` provides `network.crypta.clients.fcp`;
  `:bridge-fcp-runtime` provides `network.crypta.clients.fcp.bridge`;
  `:bridge-http-runtime` provides `network.crypta.clients.http.bridge` and
  `network.crypta.clients.http.geoip`; and
  `:adapter-http-legacy-admin` provides the remaining legacy
  `network.crypta.clients.http` classes, resources, and updater surface outside those bridge-owned
  packages.
- Vendored libraries: `:thirdparty-onion` provides `com.onionnetworks`,
  `:thirdparty-legacy` provides `org.bitpedia`, `org.sevenzip`, and `org.spaceroots`.

You generally do not need to install libraries manually; Gradle resolves them.

## License

**Crypta** is free software licensed under the GNU General Public License, version 3 only. See `LICENSE` for the full text.

Some bundled components may be under permissive licenses (e.g., Apache‑2.0, BSD‑3‑Clause). These are compatible with
GPLv3 and included under their respective terms.
