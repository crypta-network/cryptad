---
name: create-pr
description: Review the current branch’s commit history and source diffs, format/commit any pending changes, then open a GitHub PR targeting the develop branch by default (or another specified base branch) via the GitHub MCP server.
allowed-tools: Bash(git:*), Bash(./gradlew:*), Bash(gradle:*), Read, Grep, Glob, MCP(github:*)
---

# Create Pull Request (default: develop)

Create a GitHub pull request **into `develop` by default** by first reviewing the current branch’s commit history and diffs, ensuring any pending local changes are formatted and committed, then opening the PR via the GitHub MCP server.

## Target branch selection

- **Default base branch:** `develop`
- **Override:** If the user explicitly specifies a different target base branch (e.g., “into `release/1.2`”, “base=`hotfix`”, “target `main`”), use that branch instead of `develop`.
- **Validation:** Always `git fetch` first, then verify the remote base branch exists as `origin/<base>`. If `origin/develop` does not exist *and the user did not specify a base*, fall back to `main`.

> In the commands below, treat `BASE_BRANCH` as the chosen base branch name (default `develop`).

## Branch safety rules

- **Never commit directly on `develop` or `main`.**
- **Also never commit directly on the chosen base branch** (if different).
- If the current branch is `develop`, `main`, or equals `BASE_BRANCH`, create a new `feature/…` or `bugfix/…` branch **before** running formatters or creating commits.
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
| `revert`   | Reverting a previous change                      |

### Summary rules

- Imperative present tense: “Add …”, “Fix …”, “Refactor …”
- Capitalize the first letter
- No trailing period

## Steps

### 1) Fetch + identify current branch + choose base branch

```bash
git fetch origin --prune
git rev-parse --abbrev-ref HEAD
```

Set/confirm the base branch:

- Default: `develop`
- If the user specified a base branch, set `BASE_BRANCH` to it.
- Validate it exists on `origin`.

Example bash snippet (adjust if you set `BASE_BRANCH` some other way):

```bash
# If the user explicitly asked for a base branch, set BASE_BRANCH before this block.
# This flag preserves whether BASE_BRANCH came from user input or the default.
USER_SPECIFIED_BASE="${USER_SPECIFIED_BASE:-false}"
if [ -z "${BASE_BRANCH:-}" ]; then
  BASE_BRANCH="develop"
else
  USER_SPECIFIED_BASE=true
fi

# Ensure the remote base exists (fallback to main only if develop is missing and not user-specified).
if ! git show-ref --verify --quiet "refs/remotes/origin/$BASE_BRANCH"; then
  if [ "$BASE_BRANCH" = "develop" ] && [ "$USER_SPECIFIED_BASE" = "false" ]; then
    BASE_BRANCH="main"
  fi
fi

git show-ref --verify --quiet "refs/remotes/origin/$BASE_BRANCH" || {
  echo "Base branch origin/$BASE_BRANCH not found"; exit 1;
}
echo "Using base branch: $BASE_BRANCH"
```

### 2) If on `develop` / `main` / base branch, create a new branch first

```bash
BRANCH="$(git rev-parse --abbrev-ref HEAD)"

# BASE_BRANCH should already be set from Step 1
if [ "$BRANCH" = "develop" ] || [ "$BRANCH" = "main" ] || [ "$BRANCH" = "$BASE_BRANCH" ]; then
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

> Important: do not create commits until you have left `develop`/`main`/`BASE_BRANCH` (Step 2).

### 4) Review commit history on the current branch (relative to base)

List commits that will go into the PR:

```bash
git log --oneline --decorate --no-merges "origin/$BASE_BRANCH..HEAD"
```

Optionally, review details commit-by-commit:

```bash
git log --reverse --no-merges --pretty=format:'%h %s' "origin/$BASE_BRANCH..HEAD"
# then for each sha:
#   git show --name-status <sha>
#   git show <sha> -- <key-path>
```

### 5) Read the source diffs that will be in the PR (relative to base)

High-level summary:

```bash
git diff --stat "origin/$BASE_BRANCH...HEAD"
```

Full diff (focus on source code paths):

```bash
git diff "origin/$BASE_BRANCH...HEAD"
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

### 7) Create the PR via the GitHub MCP server (base: default `develop`, override allowed)

Use the GitHub MCP server’s PR creation capability (tool names vary; look for an operation like “create pull request”).

Provide at minimum:
- `base`: `BASE_BRANCH` (default `develop`, unless overridden)
- `head`: current branch name (or `owner:branch` if required)
- `title`: `<type>(<scope>): <summary>`
- `body`: include summary + test plan; incorporate `.github/pull_request_template.md` if present
- `draft`: `false` (create a ready-for-review PR; do not create a draft PR first)

Example shape (adjust to the MCP server you have configured):

```text
tool: github.create_pull_request
args:
  repo: <owner>/<repo>
  base: <BASE_BRANCH>
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
- clearly state which base branch was used (e.g., “PR opened into `develop`” / “PR opened into `release/1.2`”)

## Validation

If the repo enforces a PR-title regex, ensure the title conforms (example Conventional style):

```
^(feat|fix|perf|test|docs|refactor|build|ci|chore|revert)(\([a-zA-Z0-9 _-]+\))?!?: [A-Z].+[^.]$
```
