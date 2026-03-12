# Writing style guide

This document defines the voice and style for Cryptad writing. It applies to repo docs, GitHub release notes, wiki/runbook drafts, and long-form technical explanations.

## Core identity

We write as maintainers explaining a privacy-first distributed system to developers, packagers, and node operators.

The overall feeling is:

`Here is what changed, why it matters, and exactly what to run or check.`

## Tone characteristics

### What we are

- Confident. Make direct statements once they are verified.
- Practical. Lead with the answer, command, or consequence.
- Concrete. Use real component names, file paths, tags, and operating systems.
- Honest. Say when behavior is limited, experimental, or platform-specific.
- Security-aware. Be precise about risks and guarantees.

### What we are not

- Not marketing copy.
- Not vague security theater.
- Not academic or abstract when a command or file path would be clearer.
- Not chatty.

## Stay concrete

- Name the real component: `CoreUpdater`, `Launcher`, `build.gradle.kts`, `release/<build-number>`.
- Use exact tags, build numbers, and dates when release timing matters.
- When naming a numbered release in prose or headings, include the tag prefix: write `Cryptad v2`, not `Cryptad 2`.
- Explain consequences, not just mechanics: `does not auto-start on Linux servers`, `requires a package install`, `changes the bundled Java runtime`.
- Distinguish current guidance from archival material such as `docs/legacy/NEWS.md`.

## Avoid common AI writing tells

### Hollow importance claims

Do not write sentences that only claim significance.

Don't:

> This release is a major milestone that highlights Cryptad's commitment to usability and performance.

Do:

> This release adds native installers, a launcher, and a package-based updater. Those changes make first-time setup and upgrades easier on desktop systems.

### Trailing gerunds

Avoid ending sentences with weak `-ing` clauses.

Don't:

> The launcher tails wrapper logs, giving users better visibility into startup.

Do:

> The launcher tails wrapper logs. Users can see startup progress without opening separate log files.

### Formulaic transitions

Cut filler such as `Furthermore,`, `Moreover,`, and `It is important to note that`.

### Empty adjective stacks

Avoid phrases like `fast, flexible, and powerful` unless you immediately prove each claim with specifics.

### Security theater

Do not imply guarantees that the project does not actually provide.

Don't:

> Cryptad completely solves metadata leakage.

Do:

> Cryptad aims to reduce correlation risk, but routing, deployment choices, and operator behavior still matter.

## Pronouns and voice

- Use `you` for direct instructions.
- Use `we` for maintainer perspective and design choices.
- Use the software name when describing behavior: `The updater downloads the installer`, not `we download the installer`.
- Prefer active voice.

## Commands and examples

- The first command example should be runnable as written, apart from obvious placeholders.
- Use repo conventions: `python3`, `./gradlew`, and commands that avoid forbidden Gradle flags.
- Show platform differences explicitly when Linux, macOS, and Windows behavior diverge.
- Use meaningful file names, tags, and paths.

## Mechanics

- Use sentence case headings.
- Contractions are fine.
- Use American English spelling.
- Do not include Claude/Codex attribution in the written artifact.
