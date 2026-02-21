---
name: convert-tests-to-aaa
description: |
  Convert all non-AAA style test methods in ONE test file to Arrange-Act-Assert structure and
  rename tests to method_whenCondition_expectOutcome, preserving behavior and keeping diffs focused.
---

# Convert test methods to AAA + rename

## How to invoke (provide the “input” in your message)
Skills don’t take positional/structured parameters. When you invoke this skill, include the target test file path.

Use either format:

**One-liner**
`$convert-tests-to-aaa Target file: src/test/java/com/acme/FooServiceTest.java`

**Two lines**
```
$convert-tests-to-aaa
Target file: src/test/java/com/acme/FooServiceTest.java
```

Treat the file path as **relative to the repository root**, unless the user clearly indicates otherwise.

---

## Goal
For the target test file, convert all **non-AAA style** test methods to:
- **AAA structure** (Arrange, Act, Assert), and
- Rename each converted test method to `method_whenCondition_expectOutcome`.

Behavior must remain the same.

---

## Constraints
- Do not change production code.
- Keep changes minimal and localized to the target test file.
- Preserve test semantics (same assertions, same expected exceptions, same verification behavior).
- Do not add flakiness (no sleep, no timing assumptions).
- Avoid unrelated formatting churn.

---

## What counts as AAA
For each test method:
- **Arrange:** setup, input creation, mocks/stubs, fixtures.
- **Act:** the single primary call under test (or a clear “action” block).
- **Assert:** assertions and verifications.

Implement as either:
- comment separators:
  - `// Arrange`
  - `// Act`
  - `// Assert`
or
- blank-line separated blocks (use whichever the repo already prefers).

Prefer one main Act step. If there are multiple actions, split into multiple tests when reasonable.

---

## Renaming rule
Rename tests to `method_whenCondition_expectOutcome`:
- `method`: the method under test (or a short API name).
- `whenCondition`: key scenario/inputs/state.
- `expectOutcome`: expected result/exception/side effect.

Guidelines:
- Use lowerCamelCase.
- Keep names concise but specific.
- If the repo uses parameterized tests, ensure the name remains stable and descriptive (e.g., keep method name but reflect parameter nature).

If SonarLint flags method naming in tests (java:S100), add/keep the repo-standard suppression (commonly `@SuppressWarnings("java:S100")` at the class level) rather than changing the naming convention.

---

## Procedure
1) Open the target file and list all test methods (`@Test`, `@ParameterizedTest`, etc.).
2) For each test method:
   - Determine if it already follows AAA (clear arrange/act/assert separation).
   - If not AAA, refactor into AAA:
     - move setup to Arrange,
     - isolate the action into Act,
     - keep assertions/verifications in Assert,
     - remove duplicate setup across tests only if it reduces noise and stays minimal.
   - Rename to `method_whenCondition_expectOutcome`.
3) Ensure compilation and imports remain correct:
   - no wildcard imports,
   - keep assertion static imports consistent with the repo.
4) Run the smallest relevant test task:
   - Gradle: `./gradlew test --tests '<FQCN>'` when possible.
5) Confirm all tests still pass.

---

## Output / reporting
Summarize:
- which test methods were converted?
- key test renames (old → new),
- any non-trivial restructuring decisions (e.g., split into multiple tests).
