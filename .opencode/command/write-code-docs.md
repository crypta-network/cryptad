# Prompt: Doclint‑clean Javadoc in `$1`, with **long-form** API docs for large files

**Goal:** For file `$1`, fix *all* Javadoc issues reported by Java **doclint** and write **substantive, longer documentation** for public/protected APIs—without changing code behavior.

---

## File Type & Scope

- If `$1` ends with **`.java`**, apply **Javadoc** rules and run **doclint** (see loop below).
- If `$1` ends with **`.kt`**, apply **KDoc** rules; **do not** run doclint.
- Otherwise, **return unchanged**.

**Edits allowed:** comments and log message strings only.  
**Edits forbidden:** code semantics, names, signatures, visibility, imports, formatting/spacing, control flow, logic; adding/removing/reordering log calls; changing log levels or arguments.

---

## Placeholders Policy

- **Do not introduce** new markers: `TODO`, `FIXME`, `TBD`, `XXX`, `NOTE`.
- You **may refine** existing markers for clarity and actionability:
  - Keep the **same marker word** and comment style.
  - Keep the **same location**; do **not** move, duplicate, or split.
  - Improve grammar, precision, and context; preserve the original intent and scope.
- **Token-count rule:** For each marker (e.g., `TODO`), the **count in the output must be ≤ the count in the input**. If zero in input, zero in output.

---

## Doclint Loop (Java only)

When `$1` is a **`.java`** file, iterate until doclint reports **zero warnings** for `$1`:

1. **Run doclint** (prefer `javadoc`) on only `$1`:
   ```sh
   javadoc -quiet -Xdoclint:all -d /tmp/doclint-out -sourcepath . "$1" 2>&1 | tee /tmp/doclint-$1.out
   ```
   If symbol resolution blocks analysis, attempt:
   ```sh
   ./gradlew -q classes || true
   javadoc -quiet -Xdoclint:all \
     -classpath "build/classes/java/main:build/resources/main" \
     -sourcepath . \
     -d /tmp/doclint-out "$1" 2>&1 | tee /tmp/doclint-$1.out
   ```
   or (Maven):
   ```sh
   mvn -q -DskipTests compile || true
   javadoc -quiet -Xdoclint:all \
     -classpath "target/classes" \
     -sourcepath . \
     -d /tmp/doclint-out "$1" 2>&1 | tee /tmp/doclint-$1.out
   ```
   **Fallback (javac):**
   ```sh
   javac -proc:none -Xdoclint:all -Werror -d /tmp/doclint-out "$1" 2>&1 | tee /tmp/doclint-$1.out
   ```

2. **Map warnings** to exact members (types, ctors, methods, fields, enum constants, type params, package info).

3. **Fix documentation only** in `$1` to resolve the warnings (rules below). Do not guess uncertain facts—prefer neutral phrasing or omit.

4. **Re-run doclint** and repeat until **no warnings** remain for `$1`.

5. **Enrichment pass:** After zero warnings, expand the docs per the **Length & Depth Controls** and **Prioritization** below (still no code changes).

---

## Length & Depth Controls (make docs longer, but relevant)

Target **minimums** (use more when code is complex). The goal is *substance*, not padding.

### Top-level type (class/interface/enum/record)
- **Summary:** 1 crisp sentence.
- **Extended description:** **80–160 words** across 1–3 paragraphs answering:
  - What it does, when to use it, and typical call patterns.
  - Key invariants, life-cycle/state model, and notable trade-offs.
  - Concurrency/thread-safety and mutability (if applicable).
- **Bullets:** Add a short list when helpful (e.g., *Responsibilities*, *Notable behaviors*). Use valid HTML lists.
- **See also:** Use `@see` or inline `{@link ...}` for closely related types/members that resolve.

### Methods / constructors (public & protected)
- **Summary:** 1 sentence.
- **Extended description:** **40–120 words**, including:
  - Purpose and outcome; preconditions/postconditions; idempotency.
  - Units/ranges/defaults; performance notes if non-trivial.
  - Edge cases (empty/null inputs, timeouts, retries, partial failures).
- **Tags:**
  - `@param` for **every** parameter — **≥ 6–12 words** each, stating role, accepted values/ranges/units, nullability.
  - `@return` for non-void — **≥ 8–16 words**, clarify ownership/immutability and special cases.
  - `@throws` for each declared checked exception (and common runtime exceptions if explicitly thrown) — **≥ 6–12 words** on conditions.
  - Type params: `@param <T>` etc.
- **Usage snippet (optional but encouraged):** If deducible **without guessing external types**, include a minimal example:
  ```html
  <pre>{@code
  // Example: brief typical call path
  var out = service.fetch(id);
  }</pre>
  ```
  Keep snippets **≤ 6 lines** and consistent with visible types/members.

### Fields / enum constants (public & protected)
- **Summary:** 1 sentence.
- **Details:** **20–60 words** on meaning, units, valid ranges, mutability, and whether read-mostly/constant.

> If information cannot be known from code, omit or use neutral phrasing. Never fabricate semantics.

---

## Prioritization for Large Files

When the file has many public/protected members (e.g., **> 30**):

1. **Ensure doclint compliance for all** members (minimal but correct tags + summary).
2. **Deepen docs first** for the most important 15–25 members, prioritized by:
   - Called-by density / centrality (public API surface, non-trivial behavior, external effects I/O/network).
   - Concurrency, caching, or error-handling complexity.
   - Entry points likely used by library clients (constructors, `create*`, `build*`, `start*`, `execute*`).
3. If tokens remain, deepen the rest. Favor **complete docs for fewer members** over thin docs for many.

> Never stray into speculation. Prefer stating constraints, shapes, and observable effects derived from code.

---

## Javadoc Rules (Java)

**Placement**
- Javadoc block goes **above** annotations (e.g., `@Deprecated`) to avoid “Dangling Javadoc comment”.

**Structure & correctness**
- US English; present tense; neutral tone; wrap ~100 cols; match indentation.
- Required tags as listed above; names **must match** exactly.
- `{@code ...}` for inline code/literals; `{@link ...}` only when the symbol resolves.
- Valid HTML5 only: close tags; proper lists; `<pre>{@code ...}</pre>` for blocks; avoid deprecated tags; ensure a summary sentence first.
- For overrides with identical semantics, `/** {@inheritDoc} */` is acceptable; add clarifications only when needed.

---

## KDoc Rules (Kotlin)

- Markdown allowed; backticks for code.
- Tags: `@param`, `@return`, `@throws`, `@receiver`, `@constructor`, `@property`, type params via `@param T`.
- Same scope constraints as Java. No doclint.

---

## Inline Comments (both languages)

- Prefer short `//` comments for non-obvious intent (invariants, edge cases, concurrency), ≤ 2 short lines, placed **above** the code.
- Use `/* … */` for slightly longer local notes (not doc blocks).
- Remove stale or self-evident comments. Fix grammar and outdated names.

---

## Log Message Edits (text only)

- Do **not** change logger, level, arguments, or call structure.
- Keep placeholder syntax and **count identical** (`{}`, `%s`, `{name}`) and argument order unchanged.
- Style: present tense, active voice, 1 line; lead with event; include stable identifiers and units; no exclamation marks.
- No secrets or PII; mask sensitive values. Preserve structured keys.

**Examples**
- Bad: `Error saving` → Good: `Save failed for orderId={}, status={}, retryable={}`  
- Bad: `User authenticated successfully!` → Good: `Authentication succeeded for userId={}`  
- Bad: `Timeout` → Good: `Upstream call timed out after {} ms (endpoint={}, attempt={})`

---

## Preservation & Promotion

- Preserve license headers, annotations, and any **valid** existing docs; improve wording and formatting where helpful.
- Promote meaningful `//` explanations of **public/protected** behavior to proper Javadoc/KDoc when appropriate (without moving/duplicating placeholder markers).
- Keep private/internal docs concise.

---

## Self‑Check Before Returning

- Only **comments** and **log message strings** were changed.
- Doclint reports **zero warnings** for `$1`.
- Public/protected Javadoc blocks are **above** annotations.
- Length targets met where information is available (see **Length & Depth**).
- All tags complete and accurate; valid HTML; summaries first.
- Log messages retain placeholders and argument order; no level/structure changes.
- Placeholder markers (e.g., `TODO`) were not added, and their counts did not increase.
- Formatting consistent; wraps at ~100 columns.
