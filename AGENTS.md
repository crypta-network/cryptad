# Project Configuration

## Project Overview
Crypta is a peer-to-peer network providing a distributed, encrypted, and decentralized datastore. It is a fork of Hyphanet (formerly Freenet), building upon its technology for censorship-resistant communication and publishing. This repository contains the reference node implementation (the "Crypta reference daemon") written primarily in Java with some Kotlin components.

## Skills: load on demand

**Rule:** When a task matches any domain below, **MUST load the relevant skill(s)** before making decisions or code changes.

Load only what you need. It’s normal to load multiple skills for one task.

### Skill catalog

- **$cryptad-appenv** — Use AppEnv as the single source of truth for OS/arch/sandbox/service detection; refactor legacy checks safely.
- **$cryptad-architecture** — Navigate Cryptad’s module/package architecture, key subsystems, design patterns, security model, and versioning scheme.
- **$cryptad-build-test** — Build, test, and run Cryptad safely using the Gradle wrapper (Java 25+, JUnit 6).
- **$cryptad-build-tooling** — Maintain formatting and code-quality tooling: Spotless, SpotBugs, Gradle dependency verification (verification-metadata), SonarLint, Error Prone, JaCoCo coverage, and SonarCloud uploads.
- **$cryptad-core-updater** — Understand and modify the package-based CoreUpdater update system: /core-update/ endpoints, descriptor format, UI wiring, and platform behaviors.
- **$cryptad-crypto-aead** — Work safely on AEAD streams and persistent formats (AES-GCM migration + legacy OCB compatibility notes).
- **$cryptad-git-workflow** — Follow repository etiquette: branch naming, GitFlow merges, conventional commits, PR rules, and strict git identity policy.
- **$cryptad-launcher-ui** — Work on the Swing launcher: start/stop logic, logging, keyboard shortcuts, FlatLaf/theme handling, and Windows specifics.
- **$cryptad-packaging** — Build and troubleshoot distributions and installers (assembleCryptadDist, jpackage, Windows wrapper assets, Flatpak, Linux DEB/RPM behavior).
- **$cryptad-style-docs** — Apply Cryptad Kotlin/Java style, file layout rules, and long-lived documentation/commenting practices.
- **$codebase-retrieval** — Use semantic codebase retrieval to identify 1–5 target files before significant reading or edits when the file scope is unclear.
- **$web-search** — Use both Exa and Tavily for external/current web research, then cross-check sources before answering.

### Skill-first workflow

1. Identify the task domain(s) (build/test, tooling, packaging, updater, platform detection, crypto formats, UI, etc.).
2. Load the matching skill(s) via `skill(...)`.
3. If relevant files are not already known, load `$codebase-retrieval` first, then inspect code, and run targeted searches (don’t guess).
4. Make the smallest safe change.
5. Run the relevant Gradle checks (see `$cryptad-build-test` / `$cryptad-build-tooling`).
6. Update docs/tests when needed.

## Always-on rules (keep these in mind)

- **Languages:** Kotlin + Java.
  - Kotlin sources must live under `src/*/kotlin` (including tests). Do not add Kotlin files under `src/*/java/`.
- **OpenCode LSP:** Treat LSP/typechecker diagnostics as blockers for touched files.
  - If the OpenCode `lsp` tool is enabled, prefer it for definition/reference/hover instead of guessing
- **Repository discovery:** If the task does not provide exact paths/symbols, load `$codebase-retrieval` before making code changes.
- **Compatibility:** Avoid breaking persistent formats, on-disk layouts, and wire protocols without an explicit migration plan.
  - For AEAD stream / format changes, load `$cryptad-crypto-aead` first.
- **Environment detection:** Treat `AppEnv` as the single source of truth. Load `$cryptad-appenv` before touching OS/arch/sandbox/service detection code.
- **Updater:** For any changes touching CoreUpdater descriptors, endpoints, or UI, load `$cryptad-core-updater`.
- **Packaging/Installers:** For dist builds, installers, or Flatpak, load `$cryptad-packaging`.
- **Web research:** For the latest/current external information or multi-source fact checks, load `$web-search`.

## Quick commands (high-level)

Prefer the Gradle wrapper and follow the project’s build/test/tooling guidance in the skills (always load `$cryptad-build-test` skill):

- `./gradlew build`
- `./gradlew test` (Always give enough running time (more than 15 minutes) for Gradle to complete tests.)
- `./gradlew spotlessApply`

(See `$cryptad-build-test` and `$cryptad-build-tooling` for the full matrix and platform-specific notes.)

## Architecture pointer

For the full module/package map, request routing patterns, update system architecture, security model, and versioning scheme, load `$cryptad-architecture`.

## Maintenance rule

Keep this file concise. When project-specific procedures evolve, **update the relevant SKILL.md** rather than expanding AGENTS.md.
