---
name: write-or-improve-unit-tests
description: |
  Write or improve deterministic, maintainable unit tests for a single class under test (Java/Kotlin),
  using JUnit (project-configured; typically JUnit 6 per repo) and Mockito, without modifying production code.
---

# Write or Improve Unit Tests for one class/file

## How to invoke (provide the “input” in your message)
Skills don’t take positional/structured parameters. When you invoke this skill, include the class/file under test.

Use either format:

**One-liner**
`$write-or-improve-unit-tests Target: src/main/java/com/acme/FooService.java`

or

`$write-or-improve-unit-tests Target: com.acme.FooService`

**Two lines**
```
$write-or-improve-unit-tests
Target: src/main/kotlin/com/acme/FooService.kt
```

Notes:
- `Target:` may be a **path** or a **fully-qualified class name**.
- Infer language from the target (`.java` -> Java, `.kt` -> Kotlin). If you only get an FQCN, locate the source file via repo search.

---

## Test framework and mocking
- **Test framework:** JUnit (use the version configured by the repo; target JUnit 6 APIs if present).
- **Mocking:** Mockito (Kotlin: prefer `mockito-kotlin` helpers if already used in the repo).

---

## Goal
Produce deterministic, comprehensive, maintainable tests for the target class/file.
Output **one** compilable test file, or updates merged into the existing test file.

---

## Output requirements
- A single test class named **`<ClassUnderTest>Test`** in the correct `package` with all required imports.
- If an existing **`<ClassUnderTest>Test`** exists, merge new tests into it.
- Otherwise, create it and **move any existing tests** for the class under test into this class so only one remains.
- **Do not modify production code.**

---

## Method

### 1) Read the class under test
Enumerate:
- Public methods and their contracts.
- Invariants, state transitions, and pre/postconditions.
- Edge cases: null, empty, boundary values, overflow/underflow, locale, time zones, I/O/error paths, and concurrency if applicable.

### 2) Locate existing tests
Search under `src/test/*` (and any repo-standard test roots) for tests covering the class.
- Rewrite them to follow the Rules below.
- Remove duplication so only one `<ClassUnderTest>Test` remains.

### 3) Write new tests
Cover:
- Happy paths for each public method.
- Error and exception paths using `assertThrows`.
- Boundary values and equivalence classes.
- Parameterized combinations where appropriate.
- `equals`/`hashCode`/`toString` if meaningful; serialization if present.

If the target contains multiple top-level types, focus on the primary public type and note any uncovered types.

### 4) Ensure determinism
- Replace randomness with fixed seeds.
- Control time with `java.time.Clock` or suppliers; inject and mock with Mockito.
- Mock external I/O (network, filesystem, DB). Use `@TempDir` for temporary files.
- Avoid sleeps and timing assumptions.

### 5) Iterate until green
- All tests pass locally.
- No SonarLint issues in the test file. If Gradle, verify with `./gradlew sonarlint` (or the repo’s SonarLint task).

### 6) Gradle test execution discipline
While developing:
- Run only the new/modified test class to iterate fast:
  - `./gradlew test --tests '<FQCN.of.ClassUnderTestTest>'`

After each new test passes locally:
- Run the full test suite **once**:
  - `./gradlew test`

Do not run the full suite on every iteration.

---

## Rules
- **Style:** AAA (Arrange, Act, Assert). One logical assertion group per test.
- **Naming:** `method_whenCondition_expectOutcome`.
- **Parameterized tests:** Use JUnit parameterized tests with `@CsvSource`, `@MethodSource`, or `@EnumSource` when useful.
- **Mockito usage:**
  - Java: `@ExtendWith(MockitoExtension.class)` when mocks are used.
  - Mock collaborators and I/O boundaries only; prefer constructor injection in tests.
- **No flakiness:** Fixed seeds; controlled time; deterministic data; no network.
- **Independence:** Tests must be isolated; no shared mutable state.
- **Imports:** No wildcard imports; explicit static imports for assertions.
- **Visibility:** Test classes and methods should generally have package visibility unless repo conventions differ.
- Add `@SuppressWarnings("java:S100")` at the test class level to allow the naming convention.

### Language specifics
- **Java:** Prefer `assertThrows` and explicit static imports from `org.junit.jupiter.api.Assertions` (or the repo’s configured JUnit assertion class).
- **Kotlin:** Use Mockito + any existing repo helpers (`mockito-kotlin` if present). Use backtick test names only if the project already uses them; otherwise follow the naming rule above.

---

## Acceptance criteria
- Meaningful branch coverage of the public API.
- Null, empty, boundary, and error paths covered.
- Deterministic execution with no flaky behavior.
- SonarLint reports **zero** issues for the test file.
