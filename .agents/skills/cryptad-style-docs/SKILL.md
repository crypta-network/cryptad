---
name: cryptad-style-docs
description: "Apply Cryptad Java style, file layout rules, and long-lived documentation/commenting practices."
compatibility: opencode
metadata:
  area: style
  domain: cryptad
  lang: java
---

## When to use
Use this skill when you:
- Add/edit Java sources.
- Touch comments, deprecations, or docs.
- Need to ensure changes match the repo’s style and documentation practices.

## Java layout rules
- Java sources go under `src/*/java/` (for example `src/main/java`, `src/test/java`).
- For extracted production leaves such as `:runtime-node`, `:kernel-content`, `:platform-api`,
  `:platform-apphost`, `:platform-app-ui`, `:platform-appdist`, `:platform-appcatalog`,
  `:platform-web-shell`, and the adapter modules, keep `package-info.java` in each production
  package you add or move. Boundary tests currently enforce this for the runtime, kernel,
  platform, FCP, and HTTP leaves, and the adapter packages follow the same convention.

## Style guides
- Java: follow the Google Java Style Guide.

(Use the canonical upstream docs; do not invent new local style rules unless the repo already enforces them.)

## Documentation expectations (Javadoc)
After editing any Java file:
- Check for missing/poor Javadoc.
- Add or improve them as needed, especially for public APIs, non-obvious invariants, and protocol/format details.

## Commenting guidelines (very important)
Prefer clean diffs over in-code historical explanations.
- Do **not** add “Removed …” style comments to explain code you just deleted in the same change.
- Rationale belongs in the commit message and PR description, not in source files.

### Deprecations
When deprecating behavior that remains in code:
- Use standard `@Deprecated`.
- Add a brief forward-looking note (preferably linking to an issue/PR).
- Avoid PR-number narratives or “history of the removal” in comments.

## Where to put long-lived context
If additional context is valuable long-term:
- Document it in `AGENTS.md` or under `docs/`, not inline next to removed code.
