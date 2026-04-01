---
name: cryptad-build-test
description: "Build, test, and run Cryptad safely using the Gradle wrapper (Java 25+, JUnit 6)."
compatibility: opencode
metadata:
  area: build
  domain: cryptad
  lang: java
---

## When to use
Use this skill when you need to:
- Build the node JAR, run tests, or compile the project.
- Run a single test class/method during debugging.
- Validate that your local build can be deployed to a running node.
- Diagnose Gradle/Java toolchain issues (Java 25+).

## Build layout
- Cryptad now uses a partial multi-project Gradle build.
- Use root-project tasks by default; the root project remains the daemon/application target.
- Current leaf projects are `:foundation-support`, `:foundation-store`,
  `:foundation-store-contracts`, `:foundation-crypto-keys`, `:interop-wire`,
  `:foundation-config`, `:foundation-fs`, `:foundation-compat`, `:runtime-spi`,
  `:runtime-node`,
  `:thirdparty-onion`, `:thirdparty-legacy`, and `:launcher-desktop`.
- The extracted leaf projects compile separately, but `buildJar`, `run`, `runLauncher`,
  `assembleCryptadDist`, and jpackage tasks are still rooted at `:cryptad`.
- `:foundation-support` owns the current stable generic support subset under
  `network.crypta.support*`, `network.crypta.support.transport.ip`,
  `network.crypta.support.http`, `network.crypta.io.AddressIdentifier`,
  `network.crypta.io.WritableToDataOutputStream`, `network.crypta.node.FSParseException`,
  `network.crypta.node.FastRunnable`, `network.crypta.node.SemiOrderedShutdownHook`, and
  `network.crypta.support.IllegalValueException`.
- `:foundation-store-contracts` owns the neutral `network.crypta.store` contracts
  `BlockMetadata`, `GetPubkey`, and `StorableBlock`, plus the `network.crypta.store.alerts`
  seam.
- `:foundation-crypto-keys` owns `network.crypta.crypt`, `network.crypta.keys`, and the adjacent
  `BucketTools` / `PrependLengthOutputStream` helpers.
- `:foundation-store` owns reusable `network.crypta.store` implementations plus
  `network.crypta.store.caching` and `network.crypta.store.saltedhash`.
- `:interop-wire` owns the narrow wire/message/schema/version/probe nucleus:
  leaf-safe `network.crypta.io.comm` message/schema classes, `network.crypta.node.Version`,
  `network.crypta.node.probe.Error` and `Type`, and `network.crypta.support.Serializer`.
- `:foundation-config` owns the main `network.crypta.config` and `network.crypta.l10n` sources,
  plus shared setup helpers such as `DatastoreSizingSupport`. Its public APIs now re-export
  `:foundation-support` and `:foundation-fs` where needed.
- `:foundation-compat` owns extracted compatibility helpers under `network.crypta.compat`,
  including the wizard-neutral bandwidth support moved to
  `network.crypta.compat.bandwidth`.
- Every extracted internal leaf must keep leaf-owned aggregated-output metadata in sync at
  `<leaf>/gradle/owned-output-patterns.txt`, even for structurally separate package/resource
  moves. Non-clean builds and branch switches can leave stale non-owner aggregated outputs behind,
  and `buildJar` still packages aggregated main outputs before leaf outputs.
- When moving additional main classes/resources from root into any extracted leaf, update that
  leaf's `owned-output-patterns.txt` and validate with
  `./gradlew verifySelectiveLeafOwnershipMetadata buildJar`.
- `:runtime-spi` is the JDK-only runtime/config API leaf. Its focused unit tests still live in the
  root test tree and run through the root build.
- `:runtime-node` is the extraction-prep runtime leaf. It currently owns selected
  `network.crypta.runtime.*` package docs plus selective-output ownership metadata seeds; runtime
  behavior still lives in the root project.
- All tests remain in the root project for now and compile against the leaf subprojects through
  the root build.
- File-system-based l10n tests still run from the root project and use
  `foundation-config/src/main/resources/network/crypta/l10n/` as the main resource path.

## Guardrails (must follow)
- Always use the Gradle wrapper: `./gradlew …`
- Do **not** use `--no-daemon`.
- Do **not** pass `--parallel` or any custom JVM args on the CLI. Parallelism/JVM settings are controlled by `gradle.properties`.
- If Java runtime/toolchain cannot be located **or any command errors occur**, stop and ask for user approval before proceeding. Do not skip the command.

## Core build commands
- Build the node JAR:
  - `./gradlew buildJar`
- Clean build:
  - `./gradlew clean buildJar`
- The build prints the SHA-256 of `build/libs/cryptad.jar`.

## Testing
Always give enough running time (more than 15 minutes) for Gradle to complete tests.
When running ./gradlew test via OpenCode bash, set timeout ≥ 15 minutes (≥ 900,000 ms).

- Run all tests:
  - `./gradlew test`
- Run one test class:
  - `./gradlew test --tests *TestClassName`
- Run one test method:
  - `./gradlew test --tests *TestClassName.methodName`

## Compile-only / quick checks
- Compile only:
  - `./gradlew compileJava`
- Compile the support leaf when you touched extracted generic support classes:
  - `./gradlew :foundation-support:classes`
- Compile the crypto/keys leaf when you touched `network.crypta.crypt`, `network.crypta.keys`,
  or the moved bucket/length helpers:
  - `./gradlew :foundation-crypto-keys:classes`
- Compile the reusable store leaf when you touched extracted `network.crypta.store`,
  `network.crypta.store.caching`, or `network.crypta.store.saltedhash` code:
  - `./gradlew :foundation-store:compileJava`
- Compile the neutral store-contracts leaf when you touched `BlockMetadata`, `GetPubkey`, or
  `StorableBlock`, or the store-maintenance alert seam:
  - `./gradlew :foundation-store-contracts:compileJava`
- Compile the wire/version leaf when you touched moved message/schema/address/version/probe code:
  - `./gradlew :interop-wire:compileJava`
- Compile the config/l10n leaf when you touched extracted config or l10n sources:
  - `./gradlew :foundation-config:classes`
- Compile the compat leaf when you touched extracted compatibility helpers such as
  `network.crypta.compat.bandwidth`:
  - `./gradlew :foundation-compat:classes`
- Compile only the runtime SPI leaf when you touched just that JDK-only API surface:
  - `./gradlew :runtime-spi:compileJava`
- Compile the runtime-node scaffold when you touched moved runtime package docs or selective-output
  ownership metadata:
  - `./gradlew :runtime-node:compileJava`
- Compile the root project and its unchanged test tree against the leaf-module layout:
  - `./gradlew compileJava compileTestJava`

## Run tasks
- Run daemon entrypoint (`network.crypta.runtime.bootstrap.NodeStarter`):
  - `./gradlew run`
- Pass daemon CLI args:
  - `./gradlew run --args="--help"`
  - `./gradlew run --args="--version"`
- Run Swing launcher entrypoint (`Launcher`):
  - `./gradlew runLauncher`

## Run your build (manual deployment)
1. Build: `./gradlew buildJar`
2. Stop the running node
3. Replace the existing node JAR with `build/libs/cryptad.jar`
4. Restart the node

## Environment expectations
- Java: 25 or higher

## JUnit 6 notes (when touching tests)
- Tests run on the JUnit Platform (`useJUnitPlatform()` in build logic).
- Prefer JUnit Jupiter APIs; do not add JUnit 4/Vintage unless explicitly requested for migration-only work.
- JUnit 6 introduces `org.jspecify:jspecify` (nullability annotations). If strict dependency verification blocks resolution, follow the project’s dependency-verification refresh procedure (see the build tooling skill).

## Test helpers (test sources only)
- Package: `network.crypta.testsupport`
- Utility: `FileTestUtils` provides deterministic fill helpers for `OutputStream` / `Bucket` / `RandomAccessBuffer`.
- Do **not** call these helpers from production (`src/main`) code. If production code needs to fill helpers, use the non-test utilities (for example `FileUtil.fill(OutputStream, long)`).

## Tip: GitHub API rate limits during builds
If builds hit GitHub API rate limits, set `GITHUB_TOKEN` in the environment.
