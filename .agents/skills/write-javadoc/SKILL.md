---
name: write-javadoc
description: |
  For a single file, fix doclint-clean Javadoc (Java) or KDoc (Kotlin) issues and enrich
  public/protected API docs with substantive long-form documentation, without changing code behavior.
---

# Doclint-clean Javadoc/KDoc for one file (long-form for large files)

## How to invoke (provide the “input” in your message)
Skills don’t take positional/structured parameters. When you invoke this skill, include the target file path.

Use either format:

**One-liner**
`$write-javadoc Target file: src/main/java/com/acme/FooService.java`

**Two lines**
```
$write-javadoc
Target file: src/main/kotlin/com/acme/FooService.kt
```

Treat the file path as **relative to the repository root**, unless the user clearly indicates otherwise.

---

## Goal
For the target file:
- Fix **all** Javadoc issues reported by Java **doclint** (Java only), and
- Write **substantive, longer documentation** for public/protected APIs,
- Without changing code behavior.

---

## File type & scope
- If the target ends with **`.java`**: apply **Javadoc** rules and run **doclint** (loop below).
- If the target ends with **`.kt`**: apply **KDoc** rules; **do not** run doclint.
- Otherwise: return unchanged.

### Allowed edits
- Comments and log message strings only.

### Forbidden edits
- Code semantics, names, signatures, visibility, imports, formatting/spacing, control flow, logic;
- Adding/removing/reordering log calls; changing log levels or arguments.

---

## Placeholders policy
- Do not introduce new markers: `TODO`, `FIXME`, `TBD`, `XXX`, `NOTE`.
- You may refine existing markers for clarity and actionability:
  - Keep the same marker word and comment style.
  - Keep the same location; do not move, duplicate, or split.
  - Improve grammar/precision/context; preserve original intent and scope.
- Token-count rule: for each marker, the output count must be **<=** the input count.

---

## Doclint loop (Java only)
Iterate until doclint reports **zero warnings** for the target file.

### 1) Run doclint (prefer `javadoc`) on only the target file
Primary:
```sh
javadoc -quiet -Xdoclint:all -d /tmp/doclint-out -sourcepath . "<target>" 2>&1 | tee "/tmp/doclint-<file>.out"
```

If symbol resolution blocks analysis (Gradle):
```sh
./gradlew -q classes || true
javadoc -quiet -Xdoclint:all \
  -classpath "build/classes/java/main:build/resources/main" \
  -sourcepath . \
  -d /tmp/doclint-out "<target>" 2>&1 | tee "/tmp/doclint-<file>.out"
```

Or (Maven):
```sh
mvn -q -DskipTests compile || true
javadoc -quiet -Xdoclint:all \
  -classpath "target/classes" \
  -sourcepath . \
  -d /tmp/doclint-out "<target>" 2>&1 | tee "/tmp/doclint-<file>.out"
```

Fallback (`javac`):
```sh
javac -proc:none -Xdoclint:all -Werror -d /tmp/doclint-out "<target>" 2>&1 | tee "/tmp/doclint-<file>.out"
```

### 2) Map warnings
Map each warning to exact members:
- types, ctors, methods, fields, enum constants, type params, package info.

### 3) Fix documentation only
Fix doc blocks in the target file to resolve the warnings (rules below).
Do not guess uncertain facts—prefer neutral phrasing or omit.

### 4) Re-run and repeat
Re-run doclint until **no warnings** remain.

### 5) Enrichment pass (after zero warnings)
Expand docs per **Length & Depth Controls** and **Prioritization** below (still no code changes).

---

## Length & depth controls (make docs longer, but relevant)

### Top-level type (class/interface/enum/record)
- Summary: 1 crisp sentence.
- Extended description: **80–160 words** across 1–3 paragraphs answering:
  - What it does, when to use it, typical call patterns.
  - Key invariants, life-cycle/state model, trade-offs.
  - Concurrency/thread-safety and mutability (if applicable).
- Bullets: add a short list when helpful (e.g., Responsibilities, Notable behaviors).
  - Java: valid HTML lists.
  - Kotlin: Markdown lists.
- See also: `@see` or inline `{@link ...}` for closely related symbols that resolve.

### Methods / constructors (public & protected)
- Summary: 1 sentence.
- Extended description: **40–120 words**, including:
  - Purpose/outcome; pre/postconditions; idempotency.
  - Units/ranges/defaults; performance notes if non-trivial.
  - Edge cases (empty/null inputs, timeouts, retries, partial failures).
- Tags:
  - `@param` for every parameter (>= 6–12 words each).
  - `@return` for non-void (>= 8–16 words).
  - `@throws` for each declared checked exception (and common runtime exceptions if explicitly thrown) (>= 6–12 words).
  - Type params: `@param <T>` etc.
- Usage snippet (optional): only if deducible without guessing; keep <= 6 lines:
  - Java: `<pre>{@code ...}</pre>`

### Fields / enum constants (public & protected)
- Summary: 1 sentence.
- Details: **20–60 words** on meaning, units, ranges, mutability, and read-mostly/constant.

Never fabricate semantics. If info cannot be known from code, omit or use neutral phrasing.

---

## Prioritization for large files
When the file has many public/protected members (e.g., > 30):
1) Ensure doclint compliance for all members (minimal but correct tags + summary).
2) Deepen docs first for the most important 15–25 members, prioritized by:
   - public API surface and call density,
   - concurrency/caching/error-handling complexity,
   - likely entry points (constructors, create/build/start/execute).
3) If tokens remain, deepen the rest. Favor complete docs for fewer members over thin docs for many.

---

## Javadoc rules (Java)
- Javadoc block goes **above annotations** to avoid dangling doc comments.
- US English; present tense; neutral tone; wrap ~100 cols; match indentation.
- Required tags as listed; tag names must match exactly.
- Use `{@code ...}` for inline code/literals; `{@link ...}` only when the symbol resolves.
- Valid HTML5 only: close tags; proper lists; `<pre>{@code ...}</pre>` for blocks.
- For overrides with identical semantics, `/** {@inheritDoc} */` is acceptable; add clarifications only when needed.

---

## KDoc rules (Kotlin)
- Markdown allowed; backticks for code.
- Tags: `@param`, `@return`, `@throws`, `@receiver`, `@constructor`, `@property`, and type params via `@param T`.
- Same scope constraints as Java; no doclint.

---

## Inline comments (both languages)
- Prefer short `//` comments for non-obvious intent (invariants, edge cases, concurrency), <= 2 short lines, placed above the code.
- Use `/* … */` for slightly longer local notes (not doc blocks).
- Remove stale or self-evident comments; fix grammar and outdated names.

---

## Log message edits (text only)
- Do not change logger, level, arguments, or call structure.
- Keep placeholder syntax and **count identical** (`{}`, `%s`, `{name}`) and argument order unchanged.
- Style: present tense, active voice, 1 line; lead with event; include stable identifiers and units; no exclamation marks.
- No secrets/PII; mask sensitive values; preserve structured keys.

---

## Preservation & promotion
- Preserve license headers, annotations, and any valid existing docs; improve wording/formatting where helpful.
- Promote meaningful `//` explanations of public/protected behavior to proper Javadoc/KDoc when appropriate (without moving/duplicating placeholder markers).
- Keep private/internal docs concise.

---

## Self-check before finishing
- Only comments and log message strings changed.
- Java only: doclint reports zero warnings for the target file.
- Public/protected Javadoc blocks are above annotations.
- Length targets met where information is available.
- Tags complete/accurate; valid HTML; summaries first.
- Log placeholders/argument order unchanged; no level/structure changes.
- Placeholder markers not added; counts did not increase.
- Wrap ~100 columns; indentation consistent.
