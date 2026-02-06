---
name: create-pr
description: Review the current branch’s commit history and source diffs, format/commit any pending changes, then open a GitHub PR targeting the develop branch via the GitHub MCP server.
allowed-tools: Bash(git:*), Bash(./gradlew:*), Bash(gradle:*), Read, Grep, Glob, MCP(github:*)
---

# Create Pull Request (to develop)

Create a GitHub pull request **into `develop`** by first reviewing the current branch’s commit history and diffs, ensuring any pending local changes are formatted and committed, then opening the PR via the GitHub MCP server.

## Branch safety rules

- **Never commit directly on `develop` or `main`.** If the current branch is `develop` or `main`, create a new `feature/…` or `bugfix/…` branch **before** running formatters or creating commits.
- Keep PRs focused: avoid mixing unrelated refactors/features/fixes.

## PR title format

```
<type>(<scope>): <summary>
```

### Types (required)

| Type       | Description                                      |
|------------|--------------------------------------------------|
| `feat`     | New feature                                      |
| `fix`      | Bug fix                                          |
| `perf`     | Performance improvement                          |
| `test`     | Adding/correcting tests                          |
| `docs`     | Documentation only                               |
| `refactor` | Code change (no bug fix or feature)              |
| `build`    | Build system or dependencies                     |
| `ci`       | CI configuration                                 |
| `chore`    | Routine tasks, maintenance                       |

### Summary rules

- Imperative present tense: “Add …”, “Fix …”, “Refactor …”
- Capitalize the first letter
- No trailing period

## Steps

### 1) Fetch + identify base branch

```bash
git fetch origin --prune
git rev-parse --abbrev-ref HEAD
```

Base is `origin/develop`.

### 2) If on `develop` or `main`, create a new branch first

```bash
BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [ "$BRANCH" = "develop" ] || [ "$BRANCH" = "main" ]; then
  # Pick one:
  #   feature/<short-slug>
  #   bugfix/<short-slug>
  git switch -c "feature/<short-slug>"
fi
```

Branch naming guidance:
- Use `bugfix/…` if the change primarily fixes incorrect behavior, crashes, or regressions.
- Otherwise, use `feature/…`.
- Keep `<short-slug>` short, lowercase, and hyphen-separated.

### 3) If there are local changes that need committing, format + commit them

1) Check for uncommitted changes:

```bash
git status --porcelain
```

2) If the output is non-empty, run Spotless:

```bash
./gradlew spotlessApply
# or: gradle spotlessApply
```

3) Then use **`$git-commit-helper`** to:
- decide commit granularity (one commit vs multiple)
- write appropriate Conventional/typed commit messages
- `git add` / `git commit`
- `git push` (set upstream if needed)

> Important: do not create commits until you have left `develop`/`main` (Step 2).

### 4) Review commit history on the current branch

List commits that will go into the PR:

```bash
git log --oneline --decorate --no-merges origin/develop..HEAD
```

Optionally, review details commit-by-commit:

```bash
git log --reverse --no-merges --pretty=format:'%h %s' origin/develop..HEAD
# then for each sha:
#   git show --name-status <sha>
#   git show <sha> -- <key-path>
```

### 5) Read the source diffs that will be in the PR

High-level summary:

```bash
git diff --stat origin/develop...HEAD
```

Full diff (focus on source code paths):

```bash
git diff origin/develop...HEAD
```

Use the commit history + diff to determine the PR’s:
- **type** (`feat`/`fix`/…)
- **scope** (module/package/area)
- **summary** (what changes for users/devs)

### 6) Ensure the branch is pushed

If `$git-commit-helper` already pushed, this may be a no-op. Otherwise:

```bash
git push -u origin HEAD
```

### 7) Create the PR via the GitHub MCP server (base: develop)

Use the GitHub MCP server’s PR creation capability (tool names vary; look for an operation like “create pull request”).

Provide at minimum:
- `base`: `develop`
- `head`: current branch name (or `owner:branch` if required)
- `title`: `<type>(<scope>): <summary>`
- `body`: include summary + test plan; incorporate `.github/pull_request_template.md` if present
- `draft`: `false` (create a ready-for-review PR; do not create a draft PR first)

Example shape (adjust to the MCP server you have configured):

```text
tool: github.create_pull_request
args:
  repo: <owner>/<repo>
  base: develop
  head: <branch>
  title: "feat(core): Add …"
  body: |
    ## Summary
    …

    ## How to test
    …
  draft: false
```

After creation:
- return the PR URL
- summarize key changes and how to test

## Validation

If the repo enforces a PR-title regex, ensure the title conforms (example Conventional style):

```
^(feat|fix|perf|test|docs|refactor|build|ci|chore|revert)(\([a-zA-Z0-9 _-]+\))?!?: [A-Z].+[^.]$
```
