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
- The extracted leaf projects compile separately, but `buildJar`, `run`, `runLauncher`,
  `assembleCryptadDist`, and jpackage tasks are still rooted at `:cryptad`.
- All tests remain in the root project for now and compile against the leaf subprojects through the
  root build.

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
- Compile the root project and its unchanged test tree against the leaf-module layout:
  - `./gradlew compileJava compileTestJava`

## Run tasks
- Run daemon entrypoint (`NodeStarter`):
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
