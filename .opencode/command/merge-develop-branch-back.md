# Codex CLI Prompt — Merge `develop` into current branch (resolve conflicts)

You are running inside my git repository with shell access.

## Goal
Merge the latest commits from the `develop` branch into **the currently checked-out branch**, resolve any merge conflicts, make sure the repo builds/tests, and leave the branch in a clean, ready-to-push state.

## Guardrails
- **Do not lose local work.** If the working tree is not clean, stop and tell me what’s dirty. Do **not** stash/commit without asking.
- Prefer a **normal merge** (not rebase) unless a fast-forward is possible.
- Do **not push** to any remote unless I explicitly ask.
- Keep changes minimal and consistent with existing code style and project conventions.
- After resolving conflicts, run the project’s standard checks/tests and fix any breakages introduced by the merge.

## Steps to execute
1. **Confirm current state**
   - Identify the current branch name.
   - Run `git status` and ensure the working tree is clean.
   - Show the current HEAD (`git rev-parse --short HEAD`).

2. **Update refs**
   - Fetch remotes (default to `origin`; if the repo uses a different remote, detect it via `git remote -v`).
   - Confirm the latest `develop` commit (e.g., `git log -1 --oneline origin/develop` and/or `develop`).

3. **Merge `develop` into current branch**
   - Merge the up-to-date `develop` into the current branch (prefer `origin/develop` if that’s the authoritative ref).
   - If fast-forward is possible, allow it; otherwise create a merge commit.

4. **Resolve conflicts (if any)**
   - List conflicted files (`git status --porcelain` and `git diff --name-only --diff-filter=U`).
   - For each conflicted file:
     - Open it, remove conflict markers, and produce a correct, consistent final version.
     - Prefer preserving existing behavior on the current branch unless `develop` contains a clear fix/required update.
     - If both sides contain meaningful changes, integrate both.
   - Re-run `git status` until there are **no** conflicted files.
   - Ensure there are no leftover conflict markers (search for `<<<<<<<`, `=======`, `>>>>>>>`).

5. **Run validation**
   - Run the repo’s standard checks / tests.
   - If failures occur due to the merge, fix them with the smallest sensible edits.

6. **Commit the merge (if needed)**
   - If a merge commit is required and not yet created, commit with a clear message like:
     - `Merge develop into <current-branch>`
   - Do not amend or rewrite unrelated commits.

7. **Final report**
   - Show:
     - `git status`
     - A concise summary of what was merged (e.g., `git log --oneline --decorate -n 20`).
     - Any conflicts that were resolved and how (brief bullet list).
     - What checks/tests were run and their results.
   - Confirm the branch is clean and ready for me to push.

## If you get stuck
If there is ambiguity in conflict resolution (e.g., competing API shapes, unclear intended behavior), present the options **and choose the safest default** that preserves existing behavior, and document the choice in the final report.
