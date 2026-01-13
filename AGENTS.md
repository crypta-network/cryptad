# Project Configuration

## Project Overview
Crypta is a peer-to-peer network providing a distributed, encrypted, and decentralized datastore. It is a fork of Hyphanet (formerly Freenet), building upon its technology for censorship-resistant communication and publishing. This repository contains the reference node implementation (the "Crypta reference daemon") written primarily in Java with some Kotlin components.

## OpenCode Skills: load on demand

**Rule:** When a task matches any domain below, **MUST load the relevant skill(s)** before making decisions or code changes.

Load only what you need. It’s normal to load multiple skills for one task.

### Skill catalog

- **cryptad-appenv** — Use AppEnv as the single source of truth for OS/arch/sandbox/service detection; refactor legacy checks safely.
- **cryptad-architecture** — Navigate Cryptad’s module/package architecture, key subsystems, design patterns, security model, and versioning scheme.
- **cryptad-build-test** — Build, test, and run Cryptad safely using the Gradle wrapper (Java 25+, JUnit 6).
- **cryptad-build-tooling** — Maintain formatting and code-quality tooling: Spotless, Gradle dependency verification (verification-metadata), SonarLint, JaCoCo coverage, and SonarCloud uploads.
- **cryptad-core-updater** — Understand and modify the package-based CoreUpdater update system: /core-update/ endpoints, descriptor format, UI wiring, and platform behaviors.
- **cryptad-crypto-aead** — Work safely on AEAD streams and persistent formats (AES-GCM migration + legacy OCB compatibility notes).
- **cryptad-git-workflow** — Follow repository etiquette: branch naming, GitFlow merges, conventional commits, PR rules, and strict git identity policy.
- **cryptad-launcher-ui** — Work on the Swing launcher: start/stop logic, logging, keyboard shortcuts, FlatLaf/theme handling, and Windows specifics.
- **cryptad-packaging** — Build and troubleshoot distributions and installers (assembleCryptadDist, jpackage, Windows wrapper assets, Flatpak, Linux DEB/RPM behavior).
- **cryptad-style-docs** — Apply Cryptad Kotlin/Java style, file layout rules, and long-lived documentation/commenting practices.

### Skill-first workflow

1. Identify the task domain(s) (build/test, tooling, packaging, updater, platform detection, crypto formats, UI, etc.).
2. Load the matching skill(s) via `skill(...)`.
3. Inspect code and run targeted searches (don’t guess).
4. Make the smallest safe change.
5. Run the relevant Gradle checks (see `cryptad-build-test` / `cryptad-build-tooling`).
6. Update docs/tests when needed.

## JetBrains IDE inspections (required after every edit)

After **any** action that creates or modifies a file, immediately run JetBrains IDE inspections on that file via the IDE MCP server (`jetbrains`) tool `get_file_problems`.

- Use `filePath` relative to the project root.
- Always pass `projectPath` (repo root / current working directory) to reduce ambiguous calls.
- Default to `errorsOnly: true` (errors only). If you are chasing quality issues, re-run with `errorsOnly: false` to include warnings.
- If problems are reported, fix them and **re-run `get_file_problems` until the file is clean** before moving on.

Example call:

```
get_file_problems({
  "projectPath": "<repo-root>",
  "filePath": "src/main/kotlin/…",
  "errorsOnly": true,
  "timeout": 30000
})
```

If the IDE MCP server is unavailable, fall back to the relevant Gradle compile/test task but treat IDE inspections as the default fast feedback loop.

## Always-on rules (keep these in mind)

- **Languages:** Kotlin + Java.
  - Kotlin sources must live under `src/*/kotlin` (including tests). Do not add Kotlin files under `src/*/java/`.
- **Compatibility:** Avoid breaking persistent formats, on-disk layouts, and wire protocols without an explicit migration plan.
  - For AEAD stream / format changes, load `cryptad-crypto-aead` first.
- **Environment detection:** Treat `AppEnv` as the single source of truth. Load `cryptad-appenv` before touching OS/arch/sandbox/service detection code.
- **Updater:** For any changes touching CoreUpdater descriptors, endpoints, or UI, load `cryptad-core-updater`.
- **Packaging/Installers:** For dist builds, installers, or Flatpak, load `cryptad-packaging`.

## Quick commands (high-level)

Prefer the Gradle wrapper and follow the project’s build/test/tooling guidance in the skills:

- `./gradlew build`
- `./gradlew test`
- `./gradlew spotlessApply`

(See `cryptad-build-test` and `cryptad-build-tooling` for the full matrix and platform-specific notes.)

## Architecture pointer

For the full module/package map, request routing patterns, update system architecture, security model, and versioning scheme, load `cryptad-architecture`.

## Maintenance rule

Keep this file concise. When project-specific procedures evolve, **update the relevant SKILL.md** rather than expanding AGENTS.md.
