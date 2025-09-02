# Project Configuration

## Project Overview

Crypta is a peer-to-peer network providing a distributed, encrypted, and decentralized datastore. It is a fork of
Hyphanet (formerly Freenet), building upon its technology for censorship-resistant communication and publishing. This
repository contains the reference node implementation (the "Crypta reference daemon") written primarily in Java with
some Kotlin components.

## Development Guidelines

- Primary language: Kotlin/Java
    - New files should be always in Kotlin
    - Prefer top-level functions over wrapping in objects/classes when appropriate (idiomatic Kotlin)
- Code style:
    - Kotlin: Official coding convention described [here](https://kotlinlang.org/docs/coding-conventions.html)
    - Java: Google Java Style Guide described [here](https://google.github.io/styleguide/javaguide.html)
- Testing: JUnit and kotlin-test
- Coverage requirement: 80% minimum
- After editing a Java or Kotlin file, please check for any missing or poorly written JavaDoc/KDoc comments. Add or
  improve them as needed.
- Do not use "--no-daemon" for Gradle
- Always request escalated permissions when running any Gradle command
- If the Java Runtime cannot be located, or if any other errors occur when running a command, request approval to
  proceed. Do not skip the command.

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

## Repository Etiquette

- Branch naming: main, develop, feature/*, bugfix/*, hotfix/*, release/*
- Merge strategy: GitFlow
- Commit format: Conventional commits
- PR requirements: Tests pass, approved review

## Environment Setup

- Java version: 21 or higher
    - Java runtime has been installed in the environment. So you can run java and gradle related commands without issues
- Kotlin version: 2.2.0 or higher
    - ki shell has been installed in the environment.

## Project-Specific Notes

### Swing Launcher (Kotlin)

- Package: `network.crypta.launcher`. Entry: top‑level `fun main()`.
- UI: Java Swing (3 rows — buttons, scrolling log, status bar). System LAF, 900×600.
- Start: launches the wrapper script with this resolution order (first match wins). Stop sends SIGINT (Unix) / `taskkill` (Windows) with a 20s grace period.
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

- The distribution includes Windows-native wrapper binaries built from the latest release of `crypta-network/wrapper-windows-build`:
  - `bin/wrapper-windows-amd64.exe` and `bin/wrapper-windows-arm64.exe`.
  - DLLs are placed directly in `lib/` as `wrapper-windows-x86-64.dll` and `wrapper-windows-arm-64.dll`.
- The main Windows launcher is `bin/cryptad.bat`:
  - Detects `AMD64` vs `ARM64` and runs the matching `wrapper-windows-<arch>.exe`.
  - Temporarily prepends `lib/windows/<arch>` to `PATH` so `wrapper.dll` is found consistently.
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

- `NodeUpdateManager` coordinates updates
- `MainJarUpdater` updates the main application
- `PluginJarUpdater` manages plugin updates
- Update-over-Mandatory (UOM) for network-wide updates

### Security Model

- Content-addressed storage with cryptographic verification
- Encrypted link-level communication; request routing designed to conceal origin/destination
- Digital signatures for content authentication

## Key Tools and Instructions for Them

- Kotlin lint: ktlint has been installed
- Build: ./gradlew build
- Test: ./gradlew :test --tests [replace with TestClassName]

## Versioning System

- Single integer build number set in `build.gradle.kts` (`version = "<int>"`)
- Version tokens are replaced into `network/crypta/node/Version.kt` during build (`@build_number@`, `@git_rev@`)
- Version strings support both Cryptad and Fred formats; compatibility enforces protocol match and minimum builds
- Freenet interop: uses historical identifiers (e.g., `"Fred,0.7"`) for wire compatibility where applicable

## Build System

- Gradle with Kotlin DSL
- Targets Java 21+
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

## Testing Strategy

- Unit tests for core utilities and logic
- Integration tests for network components and protocols
- Cryptographic tests for primitives
- Client API tests (FCP and HTTP)

## Important Notes

- Requires Java 21+ to compile and run
- Updater supports automatic updates and includes legacy-related utilities (e.g., `LegacyJarFetcher`)
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

- `dependencies.properties`: consumed by Java updater/runtime (e.g., `MainJarDependenciesChecker`), not by Gradle.
- Gradle dependencies use the version catalog `gradle/libs.versions.toml` and `build.gradle.kts`.
