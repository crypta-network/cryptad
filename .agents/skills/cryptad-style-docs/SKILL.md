---
name: cryptad-style-docs
description: "Apply Cryptad Kotlin/Java style, file layout rules, and long-lived documentation/commenting practices."
compatibility: opencode
metadata:
  area: style
  domain: cryptad
  lang: java-kotlin
---

## When to use
Use this skill when you:
- Add/edit Kotlin or Java sources.
- Touch comments, deprecations, or docs.
- Need to ensure changes match the repo’s style and documentation practices.

## Kotlin/Java layout rules
- Kotlin sources go under `src/*/kotlin/` (for example `src/main/kotlin`, `src/test/kotlin`).
  - Do **not** add Kotlin files under `src/*/java/`.
- Prefer top-level functions in Kotlin instead of wrapping in objects/classes when appropriate (idiomatic Kotlin).

## Style guides
- Kotlin: follow the official Kotlin coding conventions.
- Java: follow the Google Java Style Guide.

(Use the canonical upstream docs; do not invent new local style rules unless the repo already enforces them.)

## Documentation expectations (Javadoc/KDoc)
After editing any Java or Kotlin file:
- Check for missing/poor Javadoc (Java) or KDoc (Kotlin).
- Add or improve them as needed, especially for public APIs, non-obvious invariants, and protocol/format details.

## Commenting guidelines (very important)
Prefer clean diffs over in-code historical explanations.
- Do **not** add “Removed …” style comments to explain code you just deleted in the same change.
- Rationale belongs in the commit message and PR description, not in source files.

### Deprecations
When deprecating behavior that remains in code:
- Use standard `@Deprecated` (Java/Kotlin).
- Add a brief forward-looking note (preferably linking to an issue/PR).
- Avoid PR-number narratives or “history of the removal” in comments.

## Where to put long-lived context
If additional context is valuable long-term:
- Document it in `AGENTS.md` or under `docs/`, not inline next to removed code.
