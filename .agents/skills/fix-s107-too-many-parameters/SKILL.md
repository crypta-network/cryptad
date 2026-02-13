---
name: fix-s107-too-many-parameters
description: |
  Fix SonarLint java:S107 (Too Many Parameters) in ONE target Java file by introducing/reusing
  shared parameter objects across the project, preserving behavior and avoiding duplicate Params types.
---

# Fix SonarLint java:S107 (Too Many Parameters) with shared parameter objects

## How to invoke (provide the “inputs” in your message)
Skills don’t take positional/structured parameters. When you invoke this skill, include the target file path.

Use either format:

**One-liner**
`$fix-s107-too-many-parameters Target file: src/main/java/com/acme/FooService.java`

**Two lines**
```
$fix-s107-too-many-parameters
Target file: src/main/java/com/acme/FooService.java
```

Treat the file path as **relative to the repository root**, unless the user clearly indicates otherwise.

---

## Goal
Refactor the **target file** to eliminate **SonarLint `java:S107`** issues by reducing excessive parameter lists **without changing behavior**.

**Key requirement (project-wide reuse):** if multiple methods/constructors anywhere in the project use the *same* or *highly similar* parameter groups, they must **reuse the same** newly introduced **parameter record/class**. Do **not** create duplicate “Params” types that represent the same concept in different packages/files.

---

## Do this

### 0) Repo conventions
1) Read and follow `AGENTS.md` (and any formatting/linting conventions) if present. Use `$cryptad-build-tooling` skill.
2) Keep changes minimal and localized unless call sites require updates.
3) Prefer consistent naming/location patterns already used in the repo (e.g., `*Params`, `*Request`, `*Options`, `Context`, `Paging`, etc.).

### 1) Identify `java:S107` offenders in the target file
In the target file, find every method/constructor flagged for too many parameters.

In your scratchpad (not in the final output), list for each offender:
- method/constructor name
- parameter list (types and names)
- call sites (how it is invoked), if visible

### 2) Project-wide discovery: find existing or similar parameter groupings
Before creating any new parameter types, search the **whole project** for:

1) **Existing parameter objects** that already represent the same concept:
   - `*Params`, `*Options`, `*Request`, `Context`, `Criteria`, `Filter`, `Paging/Pagination`, etc.
   - Look for records/classes that contain the same fields as the offender’s parameters.

2) **Other methods with similar parameter lists** (even if not in the target file):
   - Find methods that accept the same repeated parameter clusters (e.g., `(tenantId, userId, requestId)`, `(page, size, sort)`, `(from, to, timezone)`, etc.).
   - These indicate a shared concept that should be extracted **once** and reused.

**Rule:** Prefer reusing an existing type over introducing a new one. If an existing type is “almost right,” prefer extending/adapting it (without breaking behavior) over cloning it.

### 3) Design shared parameter objects (records/classes) — project-wide reuse required
For each offender, group parameters into coherent parameter objects:
- Prefer **one parameter object per conceptual group**, not “one record per method.”
- **Reuse rule:** if two (or more) methods share the same parameter subset (same meaning; usually same names/types), they should use **the same** parameter type — even across different modules/packages.

#### Reuse heuristics (apply in this order)
1) **Exact match:** identical parameter sets (types and names) → **one shared param type** (reuse if it already exists).
2) **High overlap:** ≥ three parameters shared with the same semantics → extract a shared type for those shared fields and keep method-specific extras separate.
3) **Stable concept:** parameters that represent stable domain concepts (pagination, request context, auth/user context, time window, retry policy, filtering criteria, locale/currency, etc.) → create a reusable type even if only used twice.

#### Duplicate avoidance & consolidation
- If you find multiple near-duplicate parameter types already in the repo:
  - **Consolidate** to a single canonical type if it can be done safely (minimal churn, no behavior changes).
  - Prefer the one in the most “shared” or conventional package, or the one with the clearest semantics.
  - If consolidation is too risky right now, **do not add another** duplicate — reuse the best existing one and include a short note in the summary.

### 4) Where to place shared parameter types (important)
Because reuse is project-wide, **do not** create nested parameter objects inside the target file unless the type truly is private to that one class.

Placement strategy:
1) If the type is reusable across several packages: put it in an existing shared area (look for packages like `common`, `shared`, `core`, `util`, `model`, `dto`, `api`, `request`, `params`).
2) Otherwise, put it in the package where it is most broadly applicable (closest common ancestor package of the call sites).
3) Avoid creating “one-off” packages; follow existing patterns.

Naming guidance:
- Prefer clear, semantic names: `RequestContext`, `Pagination`, `QueryParams`, `CreateFooParams`, `FooOptions`, `TimeWindow`, `RetryPolicy`, etc.
- Avoid generic names like `Params1`, `Data`, `Input`.

### 5) Record vs. class
- Use a **`record`** when:
  - project language level supports it
  - you want immutable data carriers
  - you don’t need framework-specific proxies or no-arg constructors
- Use a **final class** when:
  - you need explicit validation logic in the constructor
  - framework constraints require it (e.g., serialization tooling)
  - you need multiple constructors/builders

If unsure, start with a record and switch to a class only if required by compilation/tests/framework.

### 6) Refactor signatures safely
Refactor each offending method/constructor in the target file to accept the shared parameter object(s), reducing the parameter count below the threshold.

Prefer:
- `doThing(RequestContext ctx, QueryParams query, Options opts)`
over:
- `doThing(User user, String tenantId, UUID requestId, int page, int size, …)`

### 7) Update call sites (project-wide)
Search the repo for invocations and update them to use the shared parameter object(s).
- Ensure you don’t create multiple near-identical parameter types; consolidate to one.
- If constructing the param object is noisy, add:
  - static factory methods (e.g., `FooParams.of(…)`)
  - a small builder (only if it reduces complexity and is justified)

### 8) Validation and null-safety
- Preserve existing validation behavior:
  - If the old method validated arguments, move that logic into:
    - the new method (preferred for behavior parity), or
    - the parameter type constructor/factory
- Preserve nullability semantics:
  - If the project uses annotations (`@Nullable`, `@NotNull`), keep them consistent.

### 9) Formatting, compilation, tests
1) Run the project’s normal verification command(s), for example:
   - Gradle: `./gradlew test`
   - Maven: `mvn test`
2) Ensure the target file no longer triggers `java:S107`.
3) Ensure the repo does not gain duplicate parameter objects for the same concept.

---

## Acceptance criteria
- All `java:S107` issues in the target file are resolved (or suppressed only for legacy delegators if the repo already uses that pattern).
- Parameter objects are **reused project-wide** for similar parameter groups (no duplicates for the same concept).
- No behavioral changes (inputs → outputs and side effects remain the same).
- Build/tests pass.

---

## Output format (what to report back)
When you finish, summarize:
- which methods were refactored in the target file?
- what shared parameter types were reused (existing types) and where they live
- what new shared parameter types were introduced (and why they are shared)?
- any consolidation performed (or any near-duplicates discovered and how you avoided creating more)
- any legacy delegator methods kept (and why)
