---
name: improve-unit-test-coverage-for-current-changes
description: |
  Improve unit test coverage for Java changes in the current working tree and, when the current
  branch is not develop, files changed on the branch since develop. Use when Codex should inspect
  staged, unstaged, untracked, and branch-local Java changes, identify the touched production
  classes or changed test files, add or update the smallest relevant JUnit tests, and verify them
  with targeted Gradle runs plus one final full-suite run.
---

# Improve unit test coverage for current changes

## Invoke the skill

Invoke the skill without arguments when all current branch and local changes are in scope:

`$improve-unit-test-coverage-for-current-changes`

Allow optional scoping hints in the same message when the user wants to narrow the work:

```text
$improve-unit-test-coverage-for-current-changes
Limit to: src/main/java/network/crypta/...
Base ref: HEAD
```

Default to these assumptions unless the user says otherwise:

- Treat staged, unstaged, and untracked files as in scope.
- If the current branch is `develop`, compare local changes to `HEAD`.
- If the current branch is not `develop`, include files changed between the current branch and
  `develop`. Prefer the merge base with `origin/develop`; use local `develop` when
  `origin/develop` is unavailable.
- If `Base ref:` is provided, use that ref instead of the branch-aware default.
- Focus on unit-test coverage, not project-wide coverage percentages.

## Follow guardrails

- Keep production-code edits out of scope unless the user explicitly asks for them, or a tiny testability fix is unavoidable and clearly lower risk than leaving the change untested.
- Keep diffs focused on the impacted test files. Do not rewrite unrelated tests just because they are nearby.
- Prefer deterministic tests only: fixed seeds, controlled clocks, mocked I/O boundaries, no network, no sleep.
- Use JUnit Jupiter/JUnit 6 APIs and Mockito when mocking is needed.
- Preserve existing package names, test style, and file ownership conventions.
- Use the Gradle wrapper only: `./gradlew ...`
- Do not use `--no-daemon`, `--parallel`, or custom JVM args on the CLI.
- Run targeted tests while iterating, then run the full suite once at the end.

When you need more detail on repo-specific test execution rules, open
[`../cryptad-build-test/SKILL.md`](../cryptad-build-test/SKILL.md). When you need detailed test
style guidance for a single class, borrow conventions from
[`../write-or-improve-unit-tests/SKILL.md`](../write-or-improve-unit-tests/SKILL.md).

## Determine the changed files

Start from the branch-aware base plus the current working tree.

First choose the comparison base deterministically:

- Run `git rev-parse --abbrev-ref HEAD`.
- If `Base ref:` was provided, use it.
- If the current branch is `develop`, use `HEAD`.
- If the current branch is not `develop`, use `git merge-base HEAD origin/develop` when
  `origin/develop` exists. If it does not exist, use `git merge-base HEAD develop`.
- If neither develop ref exists, fall back to `HEAD` and mention that fallback in the final report.

Then use deterministic Git commands:

- `git diff --name-only --diff-filter=ACMR <base-ref> -- '*.java'`
- `git ls-files --others --exclude-standard -- '*.java'`

Then inspect actual hunks for each candidate file:

- `git diff --unified=0 <base-ref> -- <path>`

Apply these filters:

- Keep only Java files that live under any `src/main/java/` or `src/test/java/` source root,
  including nested module layouts such as `launcher-desktop/src/main/java/...`.
- Prioritize changed production Java files under any `src/main/java/` source root.
- Include changed or new test files under any `src/test/java/` source root.
- Ignore docs, generated files, formatting-only churn, and unrelated build changes unless they directly affect the tests you need to run.
- If `Limit to:` is provided, intersect the Git-derived list with that path or subtree.

If there are no changed production or test Java files, stop and report that there is no unit-test
coverage work to do for the selected branch and local changes.

## Decide what to cover

For each changed production file, inspect the diff and the current source to answer:

- Which methods, constructors, branches, exceptions, or state transitions changed?
- Which changed lines alter behavior rather than only formatting or comments?
- Which paths are most likely to regress: new conditionals, null handling, boundary checks, error handling, resource cleanup, or concurrency edges?

Prefer changed-behavior coverage over raw line count. Do not chase a global percentage target.

Use this prioritization order:

1. New or changed public behavior.
2. Bug-fix paths and regression scenarios.
3. New branches, exceptions, and boundary conditions.
4. New helper logic that is only reachable through an existing public method.

If the diff touches only test files, strengthen those tests and verify they still match the intended
behavior.

## Find the smallest relevant test file

For each changed production class:

1. Look for an existing dedicated test class with the same basename under the corresponding
   `src/test/java` source root, usually in the same module as the changed production class.
2. Search for broader package tests in that module or shared top-level tests that already exercise
   the class.
3. Create a new `<ClassName>Test` only when no sensible existing home exists.

Prefer updating one existing test file over scattering small assertions across many files.

Keep these conventions:

- Use AAA structure.
- Name tests `method_whenCondition_expectOutcome`.
- Keep test classes and test methods package-visible unless the repo already requires something else.
- Avoid wildcard imports.
- Add `@SuppressWarnings("java:S100")` at the class level when the naming convention needs it.

## Update the tests

Work one impacted class at a time.

For each test file you touch:

- Add or extend tests that exercise the changed logic directly.
- Cover happy path, failure path, and the smallest meaningful boundary cases exposed by the diff.
- Mock collaborators and external I/O boundaries only when needed to keep the test deterministic.
- Reuse existing fixtures and helpers instead of inventing parallel test infrastructure.
- Remove or replace stale assertions only when the production diff made them obsolete.

Avoid these traps:

- Do not add assertions for unchanged behavior just to inflate line coverage.
- Do not mass-convert the whole file to a new style unless that is necessary to keep the test readable.
- Do not add broad integration coverage when a focused unit test can cover the change.

If the changed behavior is not unit-testable without invasive production edits, add the narrowest
deterministic higher-level test you can and report the remaining coverage gap explicitly.

## Verify incrementally

While iterating, run only the smallest relevant tests:

- `./gradlew test --tests '<FQCN.of.ChangedTest>'`
- If several touched classes share one test slice, run only those affected test classes.

After the targeted tests pass, run the full suite once:

- `./gradlew test`

Always give Gradle enough time to finish the full suite. Do not use aggressive timeouts.

If a touched test file surfaces obvious test-only SonarLint/style issues during the work, fix them
only when they are local to the file and do not expand the scope materially.

## Report the result

When you finish, summarize:

- Which local production files or test files were in scope.
- Which comparison base was used, especially when the current branch was compared with `develop`.
- Which behaviors gained new or improved tests.
- Which targeted Gradle commands you ran and whether they passed.
- Whether the final `./gradlew test` run passed.
- Any residual coverage gap that remains and why.
