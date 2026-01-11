# Write or Improve Unit Tests for `$1`

**Test framework:** JUnit 6  
**Mocking:** Mockito

## Goal
Produce deterministic, comprehensive, maintainable tests for `$1`. Output a single compilable test file or updates merged into the existing test file.

## Inputs
- **$1**: Path or fully qualified name of the class/file under test.
- **Language**: Infer from `$1`. `.java` → Java. `.kt` → Kotlin.

## Output
- A single test class named **`<ClassUnderTest>Test`** in the correct `package` with all required imports.
- If an existing **`<ClassUnderTest>Test`** exists, merge new tests into it. Otherwise, create it and **move any existing tests** into this class.
- Do **not** modify production code.

## Method
1) **Read `$1`.** Enumerate:
   - Public methods and their contracts.
   - Invariants, state transitions, and pre/postconditions.
   - Edge cases: null, empty, boundary values, overflow/underflow, locale, time zones, I/O/error paths, and concurrency if applicable.

2) **Locate existing tests** for `$1` under `src/test/*`:
   - Rewrite to follow the Rules below.
   - Remove duplication so only one **`<ClassUnderTest>Test`** remains.

3) **Write new tests** to cover:
   - Happy paths for each public method.
   - Error and exception paths using `assertThrows`.
   - Boundary values and equivalence classes.
   - Parameterized combinations where appropriate.
   - `equals`/`hashCode`/`toString` if meaningful; serialization if present.

4) **Ensure determinism**:
   - Replace randomness with fixed seeds.
   - Control time with `java.time.Clock` or suppliers; inject and mock with Mockito.
   - Mock external I/O (network, filesystem, DB). Use `@TempDir` for temporary files.
   - Avoid sleeps and timing assumptions.

5) **Iterate until**:
   - All tests pass locally.
   - No SonarLint issues in the test file. If Gradle, verify with `./gradlew sonarlint`.

6) **Gradle test execution discipline**:
   - While developing, run only the new or modified test class to iterate fast. Example:
     ```bash
     ./gradlew test --tests '<FQCN.of.ClassUnderTestTest>'
     ```
   - After each **new test** passes locally, run the **full test suite once** to confirm all green:
     ```bash
     ./gradlew test
     ```
   - Do **not** run the full test suite on every iteration.

## Rules
- **Style:** AAA (Arrange, Act, Assert). One logical assertion group per test.
- **Naming:** `method_whenCondition_expectOutcome`. (Suppress Sonarlint's java:S100 warnings.)
- **Parameterized tests:** Use JUnit 6 `@ParameterizedTest` with `@CsvSource`, `@MethodSource`, or `@EnumSource` when useful.
- **Mockito usage:**
  - JUnit 6: `@ExtendWith(MockitoExtension.class)` (or Kotlin equivalent).
  - Mock collaborators and I/O boundaries only; prefer constructor injection in tests.
- **No flakiness:** Fixed seeds; controlled time; deterministic data; no network.
- **Independence:** Tests must be isolated; no shared mutable state.
- **Imports:** No wildcard imports; explicit static imports for assertions.
- **Language specifics:**
  - **Java:** JUnit 6 + Mockito. Prefer `assertThrows` and `Assertions` static imports.
  - **Kotlin:** JUnit 6 + `mockito-kotlin` helpers. Use backtick test names only if the project already uses them; otherwise follow the naming rule above.
- If `$1` defines multiple top-level types, focus on the primary public type and note any uncovered types.
- JUnit 6 test classes and methods should generally have **package** visibility.
- @SuppressWarnings("java:S100") at the class level.

## Acceptance Criteria
- Meaningful branch coverage of the public API.
- Null, empty, boundary, and error paths covered.
- Deterministic execution with no flaky behavior.
- SonarLint reports **zero** issues for the test file.
