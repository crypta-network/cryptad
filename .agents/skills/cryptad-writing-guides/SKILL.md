---
name: cryptad-writing-guides
description: Style and structure guides for Cryptad prose. Use when writing or editing README/docs content, GitHub release notes, migration notes, contributor docs, or long-form technical articles about Cryptad.
---

# Cryptad writing guides

Use this skill when the task is mostly about words rather than code.

## Scope

- Repo docs in repo-root `README.md`, `docs/**/*.md`, and changelog artifacts such as `changelog-full.md`, `changelog-short.txt`, and `changelog-full.txt`.
- GitHub release bodies, generated Stable RC/GA note templates, and operator-facing upgrade notes.
- Technical deep dives, architecture notes, and wiki/blog-style articles about Cryptad.

## Workflow

1. Start with `references/writing-guide.md`.
2. For repo docs and runbooks, read `references/docs-guide.md`.
3. For long-form engineering posts or deep dives, read `references/blog-guide.md`.
4. For releases, read `references/release-notes-guide.md` and usually also load `../cryptad-write-release-notes/SKILL.md`.

## Guardrails

- Keep prose aligned with repo conventions from `AGENTS.md`: `python3`, `./gradlew`, no `--no-daemon`, no `--parallel`, and no CLI JVM tuning.
- Treat GitHub Releases as the authoritative changelog unless the task explicitly targets repo-root `docs/legacy/NEWS.md`.
- Prefer concrete commands, file paths, build numbers, and platform names over broad claims.
- Keep validation, authorization, and publication distinct in Stable release prose. Never write
  that GA was published unless a verified publication receipt proves the public state.
