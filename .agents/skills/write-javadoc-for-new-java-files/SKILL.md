---
name: write-javadoc-for-new-java-files
description: |
  Apply the existing `write-javadoc` workflow to every newly added non-unit-test Java file in the
  current git working tree and, when the current branch is not develop, every newly added
  non-unit-test Java file on the branch since develop. Use when Codex should inspect git for new
  Java sources, exclude test files and test-like classes, and fix doclint-clean Javadoc one file at
  a time without changing code behavior.
---

# Apply write-javadoc to new Java files

## Invoke the skill

Invoke the skill without arguments when all newly added branch and local Java files are in scope:

`$write-javadoc-for-new-java-files`

Allow optional scoping hints in the same message when the user wants to narrow the work:

```text
$write-javadoc-for-new-java-files
Base ref: HEAD
Limit to: src/main/java/network/crypta/client
```

Default to these assumptions unless the user says otherwise:

- If the current branch is `develop`, compare local additions to `HEAD`.
- If the current branch is not `develop`, compare branch additions to the merge base with
  `origin/develop`; use local `develop` when `origin/develop` is unavailable.
- Include staged, unstaged, and untracked additions.
- If `Base ref:` is provided, use that ref instead of the branch-aware default.
- Exclude unit-test and other test-like Java files from the target set.

## Load the dependent guidance

Before editing any target file:

- Open [`../write-javadoc/SKILL.md`](../write-javadoc/SKILL.md) and treat it as the source of
  truth for the per-file doclint loop, allowed edits, and enrichment rules.
- Do not bypass the Cryptad prose guidance that `write-javadoc` requires. If it is not already
  loaded, also open [`../cryptad-writing-guides/SKILL.md`](../cryptad-writing-guides/SKILL.md) and
  [`../cryptad-writing-guides/references/writing-guide.md`](../cryptad-writing-guides/references/writing-guide.md).

## Determine the target files

Run the helper script from the repository root:

- `python3 .agents/skills/write-javadoc-for-new-java-files/scripts/list_new_non_test_java_files.py`
- `python3 .agents/skills/write-javadoc-for-new-java-files/scripts/list_new_non_test_java_files.py --base-ref HEAD --limit src/main/java/network/crypta/client`

By default, the helper computes the same branch-aware base described above. Use `--base-ref HEAD`
only when the user explicitly wants local additions and untracked files, excluding already-committed
branch history.

Selection rules:

- Include only files ending in `.java`.
- Keep files newly added relative to the computed or provided `Base ref:` plus untracked Java files.
- Exclude files under any `src/test/`, `src/testFixtures/`, `src/integrationTest/`, or
  `src/functionalTest/` source root, including nested module layouts such as
  `module-a/src/test/java/...`.
- Exclude basenames ending with `Test.java`, `Tests.java`, `IT.java`, or `ITCase.java`, even when
  those files live outside the excluded test source roots.
- Keep `package-info.java` when it is newly added and not under an excluded test source root.
- If `Limit to:` is provided, intersect the result with that exact path or subtree.

If the script returns no files, stop and report that there are no newly added non-test Java files
that need Javadoc work.

## Process one file at a time

For each target file, in sorted order:

1. Read the file and any directly related package or API context needed to document it accurately.
2. Apply the exact single-file workflow from [`../write-javadoc/SKILL.md`](../write-javadoc/SKILL.md).
3. Keep edits limited to comments and log message strings.
4. Finish the full doclint loop for the current file before moving to the next file.
5. Re-check `git diff --name-only -- <file>` if needed to confirm the work stayed scoped.

Do not batch-edit multiple target files at once. The point of this skill is to repeat the proven
single-file workflow safely across a git-derived file list.

## Verify the result

After all target files are updated:

- Re-run the helper script with the same arguments and confirm the target list is unchanged or
  reduced only because the user narrowed the scope.
- Confirm each processed file reached zero doclint warnings under the `write-javadoc` loop.
- Do not run unrelated tests unless the user asks for them or the documentation edits surfaced a
  build issue that must be investigated.

## Report the outcome

Summarize:

- Which files were selected.
- Which comparison base was used, especially when the current branch was compared with `develop`.
- Which files were processed or skipped.
- The doclint verification status for each processed file.
- Any ambiguous files that were excluded and why.
