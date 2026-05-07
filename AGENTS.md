# Project Configuration

## Project Overview
Crypta is a peer-to-peer network providing a distributed, encrypted, and decentralized datastore plus a local app platform. It is a fork of Hyphanet (formerly Freenet), building upon its technology for censorship-resistant communication and publishing. This repository contains the reference node implementation (the "Crypta reference daemon").

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
- **$cryptad-git-workflow** — Canonical guide for branch/release policy: GitFlow naming, integer build version/tags, merge rules, PR policy, and strict git identity safeguards.
- **$cryptad-start-work-branch** — Start `feature/*` or `bugfix/*` work from `develop` with naming, Conventional Commits, and PR policy.
- **$cryptad-release-workflow** — Run release branch flow: cut/stabilize `release/<build-number>`, set integer build version, tag `v<build>`, and no-squash `--no-ff` merges to `main` and `develop`.
- **$cryptad-hotfix-workflow** — Run emergency hotfix flow: cut `hotfix/<build-number>` from `main`, ship fix, tag `v<build>`, and no-squash `--no-ff` merges to `main` and `develop`.
- **$cryptad-launcher-ui** — Work on the Swing launcher: start/stop logic, logging, keyboard shortcuts, FlatLaf/theme handling, and Windows specifics.
- **$cryptad-packaging** — Build and troubleshoot distributions and installers (assembleCryptadDist, jpackage, Windows wrapper assets, Flatpak, Linux DEB/RPM behavior).
- **$cryptad-platform-apps** — Work on Platform API v1/contract, AppHost runtime/rollback, signed app bundles/catalogs, trusted app-review receipts, app-update lifecycle, app-owned static UI, the browser SDK, the app UI design system/linter, app permissions/audit, sandbox providers, and legacy admin retirement routing.
- **$cryptad-interop-performance-gates** — Maintain Hyphanet interop, performance regression, and release-certification evidence gates under `tools/interop`, `tools/perf`, `tools/release-certification`, and CI/release readiness docs.
- **$improve-unit-test-coverage-for-current-changes** — Improve unit test coverage for current branch/local Java changes with targeted Gradle runs and one final full-suite pass.
- **$cryptad-runtime-debugging** — Debug live or reproducible Cryptad JVM failures on Windows, macOS, and Linux using `jcmd`, `jdb`, thread dumps, and the default JDWP listener on `127.0.0.1:5005`.
- **$cryptad-write-release-notes** — Draft or review GitHub release notes and changelog artifacts for Cryptad builds, including `changelog-full.md`, `changelog-short.txt`, and `changelog-full.txt`.
- **$write-javadoc-for-new-java-files** — Apply the repo’s `write-javadoc` workflow to every newly added non-test Java file in the current branch/local diff or since a base ref.
- **$cryptad-writing-guides** — Apply Cryptad prose conventions for README/docs content, release notes, migration notes, and other operator-facing writing.
- **$cryptad-style-docs** — Apply Cryptad Java style, file layout rules, and long-lived documentation/commenting practices.
- **$web-search** — Use both Exa and Tavily for external/current web research, then cross-check sources before answering.

### Skill-first workflow

1. Identify the task domain(s) (build/test, tooling, packaging, updater, app platform, compatibility/performance gates, platform detection, crypto formats, UI, git branching/release/hotfix workflows, etc.).
2. Load the matching skill(s) via `skill(...)`.
3. If relevant files are not already known, identify them with targeted local searches first, then inspect code (don’t guess).
4. Make the smallest safe change.
5. Run the relevant Gradle checks (see `$cryptad-build-test` / `$cryptad-build-tooling`).
6. Update docs/tests when needed.

## Always-on rules (keep these in mind)

- **Language:** Java.
  - Java sources must live under `src/*/java/` (including tests).
- **OpenCode LSP:** Treat LSP/typechecker diagnostics as blockers for touched files.
  - If the OpenCode `lsp` tool is enabled, prefer it for definition/reference/hover instead of guessing
- **Repository discovery:** If the task does not provide exact paths/symbols, identify the relevant files with deterministic local search before making code changes.
- **Compatibility:** Avoid breaking persistent formats, on-disk layouts, and wire protocols without an explicit migration plan.
  - For AEAD stream / format changes, load `$cryptad-crypto-aead` first.
- **Environment detection:** Treat `AppEnv` as the single source of truth. Load `$cryptad-appenv` before touching OS/arch/sandbox/service detection code.
- **Updater:** For any changes touching CoreUpdater descriptors, endpoints, or UI, load `$cryptad-core-updater`.
- **App platform:** For Platform API/contract, AppHost runtime/rollback, app catalogs/bundles, trusted app-review receipts, app-update lifecycle, app-owned UI routes, the browser SDK, app UI design-system/lint behavior, app permission/audit, sandbox providers, or legacy admin retirement routing, load `$cryptad-platform-apps`.
- **Interop/performance/certification gates:** For `tools/interop`, `tools/perf`, `tools/release-certification`, related CI jobs, or release-gate evidence, load `$cryptad-interop-performance-gates`.
- **Packaging/Installers:** For dist builds, installers, or Flatpak, load `$cryptad-packaging`.
- **Runtime debugging:** For live deadlocks, hangs, blocked threads, stalled requests, or JDWP debugging with `jcmd` / `jdb`, load `$cryptad-runtime-debugging`.
- **Branch workflow questions:** For branch model/merge/tag/version policy questions, load `$cryptad-git-workflow`.
- **Starting feature/bugfix work:** Before creating a new `feature/*` or `bugfix/*` branch, load `$cryptad-start-work-branch`.
- **Release operations:** For `release/<build-number>` branch creation/stabilization, version bumping, tagging, and merge-back flow, load `$cryptad-release-workflow`.
- **Release notes/changelog:** For GitHub Releases or changelog artifact work, load `$cryptad-write-release-notes` and `$cryptad-writing-guides`.
- **Hotfix operations:** For urgent production fixes via `hotfix/<build-number>`, including tags and back-merges, load `$cryptad-hotfix-workflow`.
- **Coverage work for branch/local changes:** When improving unit coverage for the current branch or local Java diff, load `$improve-unit-test-coverage-for-current-changes`.
- **Prose/Javadoc writing:** For README/docs/release-note writing, and when using the generic `write-javadoc` skill in this repo, also load `$cryptad-writing-guides`.
- **New Java file Javadoc:** When newly added non-test Java files in the branch or local diff need package/class/member docs, load `$write-javadoc-for-new-java-files` and `$cryptad-writing-guides`.
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
