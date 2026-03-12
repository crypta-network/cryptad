---
name: fix-file-until-green
description: |
  Fix all problems in ONE target file with minimal, behavior-preserving changes.
  Iterate: run relevant Gradle tests and SonarLint file analysis until tests pass and
  SonarLint has no remaining non-ignored issues for that file, then run the full test suite.
---

# Fix the file until tests + SonarLint are green

## How to invoke (provide the “input” here)
Skills don’t take structured parameters. When you invoke the skill, include the file path in your message.

Use either format:

**One-liner**
`$fix-file-until-green Target file: path/to/File.java`

**Two lines**
```
$fix-file-until-green
Target file: path/to/File.java
```

Treat the provided path as **relative to the repository root**, unless the user clearly indicates otherwise.

## Goal
Given the target file path from the invocation message, fix issues in that file so that:
1) Relevant tests pass (iteratively), and
2) `sonarlintFile` reports **no remaining problems** for that file (excluding the ignored rules below),
3) Finally, the **full** test suite passes.

## Non-negotiable constraints
- **Do not rename packages.**
- **Do not suppress warnings** (no `@SuppressWarnings`, `//NOSONAR`, `@Suppress`, etc.). Fix root causes.
- **Do not change or add features.** Keep behavior the same; only correctness / quality fixes.
- **Do not introduce unnecessary fully qualified names.** Prefer imports.
- Keep changes **minimal** and **localized** to what’s required to go green.

## Allowed external help
- **context7** (preferred for exact library docs, matching the project’s precise dependency version):
    - `resolve-library-id` → `get-library-docs`
- **exa** (web/code search for errors, API usage, and examples):
    - Use exa when stuck, especially with stack traces or unfamiliar APIs.
    - **Do not** use exa to list repository files.

## SonarLint rules to ignore (do not “fix” these)
- `java:S120` — “Rename this package name to match the regular expression …”
- `java:S107`

### SonarLint rules to ignore for unit test files only
- `java:S100` — “Rename this method name to match the regular expression …”

## Procedure (loop until green)

### 0) Setup & sanity checks
- Work from the **project root**.
- Confirm the target file exists and is inside the repository.
- Confirm Gradle wrapper is executable.

### 1) Run targeted tests
Run Gradle tests in a way that is **as narrow as possible** while still exercising changes related to the target file.

Recommended narrowing strategy (use the first that applies):
1. If the target file is itself a test file, run that test class directly (use `--tests`).
2. If the target file is a production file, infer likely test class name(s) (e.g., `Foo` → `FooTest`, `FooTests`) and run those via `--tests`.
3. If unsure, run the smallest relevant module test task that is still reasonably related (avoid immediately running the full suite).

Then:
- Parse failure output and collect:
    - failing test names,
    - stack traces,
    - file paths and line numbers,
    - root exception messages.
- Fix only what’s needed, keeping changes minimal and behavior-preserving.

After each fix cycle, rerun the same targeted tests.

### 2) Run SonarLint file analysis
Run the Gradle `sonarlintFile` task and analyze:
- `build/reports/sonarLint/sonarlintFile/sonarlintFile.xml`

Workflow:
1. Execute `./gradlew sonarlintFile` for the target file according to the project’s task contract.
2. Open and parse the XML report.
3. For each reported issue:
    - Identify the rule key (e.g., `java:SXXXX`) and location.
    - **Skip** issues that match the ignore lists above (including the “unittest-files-only” rule when the target file is a unit test).
    - Fix the root cause with the smallest code change that does not alter behavior.

If the rule meaning is unclear:
- Prefer context7 for the exact version of the relevant library / API.
- Otherwise, use exa to search the rule key, error message, or stack trace.

### 3) Repeat until green
Repeat **1 → 2** until:
- Targeted tests pass, and
- SonarLint XML report for the target file has **zero remaining** non-ignored issues.

### 4) Run full test suite
Finally run:
- `./gradlew test`

If the full suite fails:
- Fix regressions (still under the same constraints),
- Re-run until the full suite is green.

## Quality bar (what “done” looks like)
- No test failures.
- No non-ignored SonarLint issues for the target file.
- No package renamings.
- No warning suppressions.
- No feature changes.
- Minimal diff, clean imports, and behavior preserved.

## Output expectations
When finishing a run of this skill, provide:
- A concise summary of what was fixed (by category: test failures, SonarLint issues).
- The final commands run and their outcomes (targeted tests and full suite).
- Any SonarLint rules that remained only because they are explicitly ignored above.
