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
  `:foundation-config`, `:foundation-fs`, `:foundation-compat`, `:kernel-content`,
  `:kernel-transport`, `:kernel-routing`, `:runtime-spi`,
  `:runtime-node`, `:adapter-fcp`, `:adapter-http-legacy-admin`, `:thirdparty-onion`,
  `:thirdparty-legacy`, and `:launcher-desktop`.
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
- `:kernel-content` owns the compile-neutral phase-1 content slice across selected
  `network.crypta.client`, `network.crypta.client.events`, `network.crypta.client.filter`,
  `network.crypta.client.async.alerts`, and `network.crypta.support.MediaType`.
- `:kernel-transport` owns the compile-neutral phase-1 transport slice across selected
  `network.crypta.io`, `network.crypta.io.comm`, and `network.crypta.io.xfer` helpers such as
  allow-list parsing, listener abstraction, I/O statistics collection, throttling, and partially
  received block assembly.
- `:kernel-routing` owns the compile-neutral phase-1 routing/helper slice across selected
  `network.crypta.node` value, exception, callback, and request-item helper types such as
  `BaseRequestThrottle`, `LowLevelGetException`, `LowLevelPutException`, `RequestClient`,
  `PeerStatusCounts`, `RecentlyFailedReturn`, and `SendableRequestItem*`.
- Every extracted internal leaf must keep leaf-owned aggregated-output metadata in sync at
  `<leaf>/gradle/owned-output-patterns.txt`, even for structurally separate package/resource
  moves. Non-clean builds and branch switches can leave stale non-owner aggregated outputs behind,
  and `buildJar` still packages aggregated main outputs before leaf outputs.
- When moving additional main classes/resources from root into any extracted leaf, update that
  leaf's `owned-output-patterns.txt` and validate with
  `./gradlew verifySelectiveLeafOwnershipMetadata buildJar`.
- Root boundary tests now freeze the current extracted layout. `RuntimeNodeKernelSplitPrepBoundaryTest`,
  `KernelContentBoundaryTest`, `KernelTransportBoundaryTest`, `KernelRoutingBoundaryTest`, and
  `HttpLegacyAdminBoundaryTest` are the focused regression checks for leaf ownership/import
  boundaries, and the
  runtime/kernel-content tests enforce `package-info.java` coverage for production packages in
  those leaves.
- `:runtime-spi` is the JDK-only runtime/config API leaf. Its focused unit tests still live in the
  root test tree and run through the root build.
- `:runtime-node` is the extracted daemon runtime leaf. It now owns the remaining cyclic/high-level
  `network.crypta.client` body, the remaining peer/request/routing-engine side of
  `network.crypta.node`, the retained node-coupled transport/message execution code in
  `network.crypta.io*`, `network.crypta.runtime.*`, and the remaining daemon-coupled support
  helpers.
- `:adapter-fcp` owns `network.crypta.clients.fcp`, including
  `network.crypta.clients.fcp.bridge`.
- `:adapter-http-legacy-admin` owns the current legacy `network.crypta.clients.http` tree and the
  matching `network/crypta/clients/http/**` main resources. On the root test/runtime classpath,
  those resources often resolve from the leaf JAR, so tests must treat them as classpath resources
  rather than assume a plain filesystem `Path`.
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
- For extracted-leaf or boundary work, run the focused boundary tests:
  - `./gradlew test --tests *KernelTransportBoundaryTest --tests *KernelContentBoundaryTest --tests *KernelRoutingBoundaryTest --tests *RuntimeNodeKernelSplitPrepBoundaryTest --tests *HttpLegacyAdminBoundaryTest`

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
- Compile the phase-1 kernel-content leaf when you touched extracted compile-neutral client/content
  classes:
  - `./gradlew :kernel-content:compileJava`
- Compile the phase-1 kernel-transport leaf when you touched extracted compile-neutral transport
  helpers:
  - `./gradlew :kernel-transport:compileJava`
- Compile the phase-1 kernel-routing leaf when you touched extracted compile-neutral routing/helper
  classes:
  - `./gradlew :kernel-routing:compileJava`
- Compile only the runtime SPI leaf when you touched just that JDK-only API surface:
  - `./gradlew :runtime-spi:compileJava`
- Compile the extracted runtime-node leaf when you touched daemon runtime, node, client, xfer, or
  remaining support code that now lives there:
  - `./gradlew :runtime-node:compileJava`
- Compile the FCP adapter leaf when you touched `network.crypta.clients.fcp`:
  - `./gradlew :adapter-fcp:compileJava`
- Compile the legacy HTTP adapter leaf when you touched `network.crypta.clients.http` sources or
  resources:
  - `./gradlew :adapter-http-legacy-admin:compileJava :adapter-http-legacy-admin:processResources`
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
