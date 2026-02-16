---
name: git-commit-push
description: |
  Run Gradle spotlessApply, review all uncommitted + untracked changes without editing files,
  then use $git-commit-helper to add related files, commit, and push (never commit on main/develop).
---

# Spotless → Review → Commit & Push (no direct commits to main/develop)

## How to invoke
Invoke the skill and include (optional) branch + commit intent in the same message.

**One-liner**
`$git-commit-push Branch: feature/my-branch-name | Notes: <what changed / why>`

**Two lines**
```
$git-commit-push
Branch: feature/my-branch-name
Notes: <what changed / why>
```

---

## Hard rules
- Run `./gradlew spotlessApply` first.
- Review **both**:
  - modified/staged files (uncommitted), and
  - untracked files.
- **Do not edit any files manually** (beyond what `spotlessApply` changes).
- Use `$git-commit-helper` to:
  - add all related files,
  - commit,
  - push.
- If currently on `main` or `develop`, create a new `feature/…`, `bugfix/…`, or `hotfix/…` branch **before** any commit.
  - **Never** commit directly to `main` or `develop`.

---

## Procedure

### 0) Run Spotless first
- `./gradlew spotlessApply`

### 1) Review changes (read-only)
You must inspect what changed before committing.

1) Show status (including untracked):
- `git status`

2) Review the diff for tracked changes:
- `git diff`
- Optionally also:
  - `git diff --stat`
  - `git diff --name-only`

3) Inspect untracked files:
- `git ls-files --others --exclude-standard`

For each untracked file, open/read it (do not edit), using an appropriate viewer command (e.g., `sed -n '1,200p' <file>` or `cat <file>`), and confirm it makes sense to commit.

### 2) Ensure you’re on a safe branch (branch naming must relate to changes)
1) Determine current branch:
- `git rev-parse --abbrev-ref HEAD`

2) If the current branch is **NOT** `main` or `develop`:
- Keep the current branch (unless the user provided `Branch:`; if they did, switch/create it safely).

3) If the current branch **IS** `main` or `develop`:
- If the user provided `Branch: ...`, create and switch:
  - `git checkout -b <branch>`
- If `Branch:` is omitted, create and switch to a branch whose name is **related to the changed code**, using this deterministic naming heuristic:

#### Default branch naming heuristic (when Branch is omitted)
- Collect changed paths:
  - tracked: `git diff --name-only`
  - untracked: `git ls-files --others --exclude-standard`

- Derive a short **scope** slug from those paths:
  1) If many paths share a meaningful top-level directory (e.g., `moduleA/...`), use that directory name as the scope
     (ignore non-scopes like `src`, `build`, `.github`, `gradle`).
  2) Otherwise, if changes are mostly under `src/.../java/...`, derive scope from the package path:
     - take the first “feature” segment after `src/*/java/`, skipping common roots like `com`, `org`, `net`, `io`, `dev`,
       and skipping the next “company/org” segment if it’s clearly an org identifier.
     - Example: `src/main/java/com/acme/payments/...` -> scope `payments`
  3) If changes span multiple unrelated areas, use scope `multi`.
  4) If scope can’t be determined, use `misc`.

- Normalize scope:
  - lowercase, digits and hyphens only; replace other chars with `-`; collapse repeats.

- Create the branch with one of these prefixes (prefer `feature/` unless the user indicates bugfix/hotfix intent):
  - `feature/<scope>-spotless`
  - `bugfix/<scope>-spotless`
  - `hotfix/<scope>-spotless`

- Command (example):
  - `git checkout -b feature/<scope>-spotless`

### 3) Commit & push via helper skill
1) Load and follow `$git-commit-helper`.
2) Add **all related files** (including any new files that belong to the change).
3) Create a commit message that reflects what Spotless changed (and any other intended changes).
4) Push the branch to the remote.

### 4) Finish
Report:
- current branch name,
- files included in the commit,
- commit hash,
- pushed remote branch name.
