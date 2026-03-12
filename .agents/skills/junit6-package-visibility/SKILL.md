---
name: unittest-remove-public
description: |
  In a single JUnit 6 test file, remove unnecessary 'public' modifiers from test classes and
  test lifecycle/test methods to enforce package visibility and clear SonarLint issues like
  "Remove this 'public' modifier.", without changing behavior.
---

# JUnit 6 tests: enforce package visibility (remove `public`)

## How to invoke (provide the “input” in your message)
Skills don’t take positional/structured parameters. When you invoke this skill, include the target test file path.

Use either format:

**One-liner**
`$unittest-remove-public Target file: src/test/java/com/acme/FooServiceTest.java`

**Two lines**
```
$unittest-remove-public
Target file: src/test/java/com/acme/FooServiceTest.java
```

Treat the file path as **relative to the repository root**, unless the user clearly indicates otherwise.

---

## Goal
In the target file, fix all occurrences of the SonarLint issue:
- **"Remove this 'public' modifier."**

by changing JUnit 6 test classes and methods to **default (package) visibility**.

---

## Scope and constraints
- Target is **one test file**.
- Keep changes minimal and localized.
- Do not change production code.
- Do not change test logic, assertions, or behavior (inputs → outputs/side effects remain the same).
- Avoid unrelated formatting churn.

### Language note
- This skill is intended for **Java** test files (`.java`) where “package visibility” exists.
- If the target is not `.java`, stop without changes and report that Java package visibility does not apply.

---

## What to change
Remove the `public` modifier where it is unnecessary, especially on:

### Test classes
- Top-level test class declarations:
  - `public class FooTest { ... }` → `class FooTest { ... }`
- Nested JUnit test classes (e.g., `@Nested`):
  - `public static class ...` → `static class ...`
  - `public class ...` → `class ...`

### Test and lifecycle methods
Remove `public` from methods that are part of the test API surface:
- `@Test`, `@ParameterizedTest`, `@RepeatedTest`, `@TestFactory`, `@TestTemplate`
- Lifecycle:
  - `@BeforeEach`, `@AfterEach`, `@BeforeAll`, `@AfterAll`
- `@Nested` class methods that are tests/lifecycle hooks

Example:
- `public void myTest() { ... }` → `void myTest() { ... }`

### Keep behavior and compilation intact
- Do not remove `static` or change method signatures.
- If a method is referenced from a different package/module (rare for tests), keep visibility as required by compilation.
  - Prefer fixing call sites within tests over keeping `public`, unless changing call sites would expand scope materially.

---

## Procedure
1) Open the target file and identify all `public` modifiers.
2) Determine which are related to JUnit tests:
   - class declarations that are test classes (by name, location under `src/test`, annotations),
   - methods annotated with JUnit test/lifecycle annotations.
3) Remove `public` from those declarations to make them package-visible.
4) Run fast verification:
   - Gradle: `./gradlew test --tests '<FQCN.of.TestClass>'` when possible
5) Run SonarLint check used by the repo (e.g., `./gradlew sonarlint` or file-specific task) and confirm the target file has no remaining “Remove this 'public' modifier.” issues.
6) If failures occur, adjust only what’s necessary to restore compilation/tests while keeping modifiers minimal.

---

## Output / reporting
Summarize:
- which classes/methods had `public` removed (brief list),
- how you verified (test command + SonarLint command),
- any cases where `public` had to remain (and why).
