# Project Configuration

## Development Guidelines

- Primary language: Kotlin/Java
- Code style:
    - Kotlin: Official coding convention described [here](https://kotlinlang.org/docs/coding-conventions.html)
    - Java: Google Java Style Guide described [here](https://google.github.io/styleguide/javaguide.html)
- Testing: JUnit and kotlin-test
- Coverage requirement: 80% minimum
- After editing a Java or Kotlin file, please check for any missing or poorly written JavaDoc/KDoc comments. Add or
  improve them as needed.
- Do not use "--no-daemon" for Gradle
- If the Java Runtime cannot be located, or if any other errors occur when running a command, request approval to
  proceed. Do not skip the command.

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

## Key Tools and Instructions for Them

- Kotlin lint: ktlint has been installed
- Build: ./gradlew build
- Test: ./gradlew :test --tests [replace with TestClassName]

## Auto-MCP Configuration

# Automatically configures MCP servers based on project type

project_type: full-stack
auto_mcp:

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
