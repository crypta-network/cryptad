<p align="center"><img src="docs/images/crypta_logo.png" alt="Crypta Logo" width="160"></p>
<h1 align="center" style="padding-top: 0; margin-top: 0;">Crypta</h1>

Crypta is a platform for censorship‑resistant communication and publishing. It is a fork of Hyphanet (formerly Freenet)
that builds on its core ideas while modernizing usability, performance, and developer experience. Crypta provides a
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

Crypta’s vision is to keep the privacy and resilience, while making it pleasant, fast, and sustainable to use and build
on:

- User experience first: a modern web UI, sensible defaults, and a one‑click guided onboarding that hides complexity
  (smart opennet bootstrap, optional darknet linking later).
- Faster routing and retrieval: adaptive, locality‑aware routing; popularity‑sensitive caching; opportunistic prefetch;
  and transport updates (e.g., QUIC/HTTP‑3, improved congestion control, and better NAT traversal) for lower tail
  latency.
- Safe observability: privacy‑preserving telemetry and reproducible benchmarking harnesses to inform tuning without
  leaking user data.
- A better platform: Kotlin‑first codebase, a stable plugin SDK, typed configuration, and testable interfaces to make
  extending the network straightforward.

This repository contains the reference node (the “Crypta reference daemon”) that participates in the network, stores
data, and serves applications.

![Crypta UI – Screenshot](docs/images/screenshot.png)

## Building

We use the [Gradle Wrapper](https://docs.gradle.org/8.11/userguide/gradle_wrapper.html). If you trust the committed
wrapper, you can build immediately.

Prerequisites:

- Java 21 or newer
- Kotlin 2.2+ (tooling; the project includes Kotlin Gradle plugins)
- A POSIX shell or Windows terminal

Build the node JAR (prints SHA‑256 of the output):

    ./gradlew buildJar

Clean build:

    ./gradlew clean buildJar

The wrapper is configured to [verify the distribution checksum](gradle/wrapper/gradle-wrapper.properties) from
`https://services.gradle.org`.

## Testing

- Run all tests in parallel:

  ./gradlew --parallel test

- Run a specific test class:

  ./gradlew --parallel test --tests *TestClassName

- Run a specific test method:

  ./gradlew --parallel test --tests *TestClassName.methodName

## Code Quality

- Compile only:

  ./gradlew compileJava

- Formatting via Spotless is configured; see the Spotless + Dependency Verification section if verification blocks resolution.
- Gradle daemon is enabled by default; avoid passing `--no-daemon`.

## Running Your Build

To try your local build of Crypta:

1. Build it with `./gradlew buildJar`.
2. Stop your running node.
3. Replace the existing node JAR with `build/libs/cryptad.jar` produced by the build.
4. Start your node again.

To override Gradle settings, create `gradle.properties` (see
the [Gradle docs](https://docs.gradle.org/8.11/userguide/build_environment.html)) and add entries like:

    org.gradle.parallel=true
    org.gradle.daemon=true
    org.gradle.jvmargs=-Xms256m -Xmx1024m
    org.gradle.configureondemand=true

## Development Guidelines

- Primary languages: Kotlin/Java
  - New files should be written in Kotlin
  - Prefer top‑level functions where idiomatic in Kotlin
- Code style:
  - Kotlin: https://kotlinlang.org/docs/coding-conventions.html
  - Java: https://google.github.io/styleguide/javaguide.html
- Tests: JUnit and kotlin‑test; target 80%+ coverage
- Documentation: Add/update JavaDoc/KDoc when editing Java/Kotlin files

## Dependencies

- Runtime: Java 21+
- Language/Tooling: Kotlin 2.2+, Gradle Wrapper (provided in this repo)
- External libraries: managed via Gradle; for offline distribution and installer integration, see
  `dependencies.properties`.
- Dependency verification is enabled; update both the `dependencies` and `dependencyVerification` blocks in
  `build.gradle.kts` when adding libraries.

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
- During build, tokens are replaced into `network/crypta/node/Version.kt` (e.g., `@build_number@`, `@git_rev@`).
- Version strings support both Cryptad and Fred formats for wire compatibility; protocol compatibility enforces minimum builds.

## Architecture Overview

- Core network (`network.crypta.node`): `Node`, `PeerNode`, `PeerManager`, `PacketSender`, `RequestStarter`, `RequestScheduler`, `NodeUpdateManager`.
- Storage (`network.crypta.store`): `FreenetStore`, `CHKStore`, `SSKStore`, `SlashdotStore`.
- Crypto (`network.crypta.crypt`): AES, DSA/ECDSA, SHA‑256, `RandomSource`/Yarrow.
- Keys (`network.crypta.keys`): `ClientCHK`, `ClientSSK`, `FreenetURI`, USK.
- Clients: `network.crypta.client`, FCP (`network.crypta.clients.fcp`), HTTP (`network.crypta.clients.http`).
- Plugins (`network.crypta.pluginmanager`): `PluginManager`, `FredPlugin*`, `OfficialPlugins`.
- Config (`network.crypta.config`): type‑safe persisted configuration.
- Support (`network.crypta.support`): logging, data structures, threading, helpers.

You generally do not need to install libraries manually; Gradle resolves them. When preparing installer assets or
offline bundles, ensure artifacts are listed in `dependencies.properties` and available through the project’s
distribution process.

## License

Crypta is free software licensed under the GNU General Public License, version 3 only. See `LICENSE` for the full text.

Some bundled components may be under permissive licenses (e.g., Apache‑2.0, BSD‑3‑Clause). These are compatible with
GPLv3 and included under their respective terms.
