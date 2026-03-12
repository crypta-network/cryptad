---
name: reduce-cognitive-complexity
description: |
  Refactor ONE Java method so its Sonar Cognitive Complexity (java:S3776) is <= 15,
  preserving behavior and improving readability without suppressing warnings or adding deps.
---

# Reduce Cognitive Complexity (java:S3776) to <= 15

## How to invoke (provide the “inputs” in your message)
Skills don’t take positional/structured parameters. When you invoke this skill, include the class and method in the message.

Use either format:

**One-liner**
`$reduce-cognitive-complexity Class: path/to/MyClass.java | Method: myMethod(...)`

**Two lines**
```
$reduce-cognitive-complexity
Class: path/to/MyClass.java
Method: myMethod(...)
```

Notes:
- Prefer **file path** for `Class:` (relative to repo root). If you only have a fully qualified class name, include it, and the agent should locate the file.
- For `Method:`, include the **method name** and (when ambiguous) its **parameter types** or full signature.

## Role
Act as a **Senior Java Maintainer & SonarQube/SonarLint specialist**: refactor for clarity and maintainability while preserving behavior.

## Goal
Given the target Java class and method, refactor so the method’s **Cognitive Complexity is <= 15** (Sonar rule **java:S3776**) with **no functional changes**.

## Acceptance criteria
1) Target method’s Cognitive Complexity <= 15 after refactor.
2) Behavior preserved (same inputs → same outputs/side effects).
3) Readability improved: flatter control flow, clearer intent, small cohesive methods.
4) No new external dependencies (Java standard library only).
5) Unit tests compile and pass (or add minimal, focused tests/assertions if none exist).
6) Keep public API stable unless explicitly allowed.
7) **NEVER suppress** the warning (no `@SuppressWarnings`, `//NOSONAR`, etc.).

## Refactoring plan (apply as needed; stop once <= 15)

### 1) Map complexity hotspots
- Identify each flow break (if/else, switch, loop, try/catch, early return/continue/break) and nesting site in the target method.
- List them as bullet points to show where complexity accumulates.

### 2) Flatten nesting with guard clauses
- Replace “pyramid” nesting with early returns and fail-fast checks.
- Convert negative conditions to positive guards when clearer.

### 3) Replace long if/else-if chains
- If branching is on a single selector (enum/string/type), prefer `switch` / switch expressions (Java 14+).
- Or use a lookup map / strategy-by-key when it simplifies the method.

### 4) Extract cohesive blocks
- Extract private helper methods with clear names for independent steps.
- Keep each extracted method’s own Cognitive Complexity reasonable (< 15).
- Separate side-effecting code from pure calculations when it improves clarity.

### 5) Simplify loops and conditionals
- Prefer early `continue` / `return` to reduce nesting.
- Split nested loops into helper methods where appropriate.
- Use streams only when they reduce nesting and improve clarity (avoid long/branchy pipelines).

### 6) Leverage modern Java (project Java level permitting)
- Switch expressions, pattern matching for `instanceof`, try-with-resources, `Optional` for guard handling, etc.
- Replace complex boolean logic with clear, named helpers.

### 7) Eliminate dead or duplicate logic
- Remove redundant checks, merge equivalent branches, inline obvious temporaries.

### 8) Review for readability
- Names reflect intent; keep methods short and single-purpose.
- Don’t over-extract trivial one-liners—extract meaningful steps.

## Guardrails & style
- Do not change externally visible behavior unless explicitly allowed.
- Keep exception and logging semantics intact.
- Preserve performance characteristics; mention any trade-off introduced.
- Keep thread-safety and null-safety intact; add guards where needed.

## What to output (return ONLY these sections, in this order)
1) **Refactoring Plan** – bullet list of targeted changes (1–2 sentences per bullet).
2) **Why this passes S3776** – a short note linking changes to reduced branching and nesting.
3) **Risk & Test Notes** – impacted code paths + suggested tests/assertions to validate behavior.

## Quick checklist (before finishing)
- Target method’s Cognitive Complexity <= 15
- Nesting depth is meaningfully reduced (guard clauses / early exits)
- The long if/else-if chain is replaced with switch/strategy/lookup where helpful
- Cohesive steps extracted into well-named private methods
- Tests/ notes are included to demonstrate behavior unchanged
- No new deps; Java level respected
- No warning suppressions
