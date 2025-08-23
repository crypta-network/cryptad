# Changelog

All notable changes to this project since the fork from Hyphanet are documented here.

- Fork point: hyphanet/next @ 55c8d24b73d3dc926002ee827411555263b03954
- This release: v1 (2025-08-23)

## v1 — 2025-08-23

### Breaking Changes
- Require Java 21+ to build and run the node. Older JVMs are no longer supported. (#9)
- Package renamed from `freenet.*` to `network.crypta.*`. Update imports and plugin API usages accordingly. (`e680030f3b`)
- Generated artifact renamed to `build/libs/cryptad.jar`. Default Gradle `:jar` task is disabled; use `:buildJar` instead. (`1d22cb0aa3`, `be070eea36`)
- Gradle build migrated to Kotlin DSL and standardized source layout (`src/main/java|resources`, `src/test/java|resources`). Custom `sourceSets` removed. (#6, #5, #3, #4)

### Features
- UI: Cryptaforge theme refinements and assorted UI improvements. (#14)
- UI: Open bookmark links in new browser tabs. (#16)
- Build/DevX: Print SHA‑256 of `cryptad.jar` after build; reproducible JAR ordering. (build logic)

### Fixes
- Networking: Prevent "Already freed" race in `SingleFileFetcher`. (#15)
- I/O: Resolve stream-closure and bucket management issues. (#11)
- Net utils: Use `equals()` for string comparison in `Inet6AddressMatcher`. (`3558c9e82d`)
- L10n: Fix missing language key and adjust unit tests. (`ddc436de51`, `84b7505c0c`)
- Logging: Correct string interpolation for SHA‑256 filename log. (`ffbaf9c07a`)
- Build: Ensure both Java and Kotlin classes are included in the built JAR. (`738e437a09`)

### Security
- Merge upstream improvements and security fixes from Hyphanet. (#13)

### Refactoring / Modernization
- Remove `finalize()` dependencies; modernize resource management. (#10)
- Modernize versioning system; generate `Version.kt` with build number and git revision. (#9)
- Comprehensive code cleanup and refactoring across modules. (#12)
- Convert utility and logging classes to Kotlin and prefer top‑level functions where appropriate:
  - `HexUtil` converted to Kotlin with top‑level functions; documentation added. (`c3ca9df73b`, `68d120d9f1`, `4cb7f41a74`)
  - Logger and subclasses converted to Kotlin; method parameters made nullable where appropriate. (`a92a57c079`, `e222d004fe`)
- Remove dependency on internal JDK class `com.sun.org.apache.xml.internal.serializer.OutputPropertiesFactory`. (`5929a72a33`)

### Rebranding / Localization
- Rebrand project and UI from Freenet to Crypta (names, titles, translations). (`edef669b54`, `c982b79d1d`, `4f375f190c`)
- Adjust and rename several localization keys for consistency. (`ef9cb865ba`)

### Build System & CI
- Standardize Gradle build, dependencies, and task wiring; add `buildJar` as the canonical artifact task. (#6, #5, #3)
- Introduce Spotless formatting with `google-java-format` and dependency verification metadata. (build config)
- Update Gradle Wrapper (8.14.3 → 9.0.0) and adopt Kotlin DSL for build scripts. (`8053ba42bc`, `f1c7ce6cc0`)
- Add reusable CI workflows; improve artifact naming and Git describe usage; switch default branch to `main`. (multiple CI commits)
- Update JNA to 5.17.0. (`90fa2287cd`)

### Documentation
- Rebrand README and docs to Crypta; add usage notes and cleanup. (#2)
- Add detailed documentation for `HexUtil` functions. (`4cb7f41a74`)
- README screenshot now adapts to dark/light modes. (`c3a38f5edb`)
- Restructure docs and tooling; remove stale `flatDir` and submodule. (#18)

### Plugins
- Update official plugins to use shadow JARs and fix plugin page NPE. (#17)

---

Commit range considered: 55c8d24b73d3dc926002ee827411555263b03954..HEAD (no-merge summaries). Some items summarized from multi-commit PRs.
