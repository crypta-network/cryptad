# Crypta

Crypta is a platform for censorship-resistant communication and publishing. It is a fork of Hyphanet (formerly known as
Freenet), building upon its principles and technology. It is a peer‑to‑peer network that provides a distributed,
encrypted, and decentralized datastore. Applications such as forums, chat, micro‑blogs, and websites run on top of
Crypta without central servers.

Inspired by the goals of Hyphanet, Crypta focuses on privacy, resilience, and free expression:

- Privacy by design: data is encrypted end‑to‑end and routed through multiple peers.
- Decentralized and censorship‑resistant: no central point of control or failure.
- Publishing and discovery: content is addressed by keys and can be versioned and replicated across the network.
- Extensible platform: build apps that leverage the content store and routing to deliver interactive experiences.

Crypta plans to evolve with new technologies such as Kotlin Multiplatform, a modern frontend stack, improved
scalability, enhanced security measures, better developer tooling, and significantly improved user experiences.

This repository contains the reference node (the "Crypta reference daemon") that participates in the network, stores
data, and serves applications.

## Building

We use the [Gradle Wrapper](https://docs.gradle.org/8.11/userguide/gradle_wrapper.html). If you trust the committed
wrapper, you can build immediately.

Prerequisites:

- Java 21 or newer
- A POSIX shell or Windows terminal

Build the node JAR:

    ./gradlew jar

On Windows `cmd`:

    gradlew jar

The wrapper is configured to [verify the distribution checksum](gradle/wrapper/gradle-wrapper.properties) from
`https://services.gradle.org`.

## Testing

- Run all tests:

  ./gradlew --parallel test

- Run a specific test class or method:

  ./gradlew --parallel test --tests *M3UFilterTest

## Running Your Build

To try your local build of Crypta:

1. Build it with `./gradlew jar`.
2. Stop your running node.
3. Replace the existing node JAR with `build/libs/cryptad.jar` produced by the build.
4. Start your node again.

To override Gradle settings, create `gradle.properties` (see
the [Gradle docs](https://docs.gradle.org/8.11/userguide/build_environment.html)) and add entries like:

    org.gradle.parallel=true
    org.gradle.daemon=true
    org.gradle.jvmargs=-Xms256m -Xmx1024m
    org.gradle.configureondemand=true

## Dependencies

- Runtime: Java 21+
- Language/Tooling: Kotlin 2.2+, Gradle Wrapper (provided in this repo)
- External libraries: managed via Gradle; for offline distribution and installer integration, see
  `dependencies.properties`.
- Dependency verification is enabled; update both the `dependencies` and `dependencyVerification` blocks in
  `build.gradle.kts` when adding libraries.

You generally do not need to install libraries manually; Gradle resolves them. When preparing installer assets or
offline bundles, ensure artifacts are listed in `dependencies.properties` and available through the project’s
distribution process.

## License

Crypta is free software licensed under the GNU General Public License, version 3 only. See `LICENSE` for the full text.

Some bundled components may be under permissive licenses (e.g., Apache‑2.0, BSD‑3‑Clause). These are compatible with
GPLv3 and included under their respective terms.
