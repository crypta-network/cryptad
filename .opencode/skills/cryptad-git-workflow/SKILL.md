---
name: cryptad-git-workflow
description: "Follow repository etiquette: branch naming, GitFlow merges, conventional commits, PR rules, and strict git identity policy."
compatibility: opencode
metadata:
  area: git
  domain: cryptad
---

## When to use
Use this skill whenever you:
- Create branches, commits, tags, or prepare a release.
- Resolve merge conflicts or integrate changes between branches.
- Prepare a pull request (even if you won’t open it yet).

## Repository etiquette
- Branch naming:
  - `main`, `develop`
  - `feature/*`, `bugfix/*`, `hotfix/*`, `release/*`
- Merge strategy: GitFlow.
- Commit format: Conventional Commits.
- PR requirements: tests pass and an approved review.
- **Always ask before creating a GitHub pull request.** Do not open PRs without explicit approval.

## Git identity policy (must follow)
### Never override authorship/committer identity
- Do not pass `--author` or `--reset-author` to `git commit`.
- Do not set `GIT_AUTHOR_NAME`, `GIT_AUTHOR_EMAIL`, `GIT_COMMITTER_NAME`, or `GIT_COMMITTER_EMAIL` in commit flows.
- Do not run `git config user.name` / `git config user.email` inside this repository during commit flows.
- Use the existing project/default identity configured for the environment.

### Pre-commit identity check (required)
Before any `git commit` **or** history rewrite, verify identity is configured:
```bash
git config --get user.name
git config --get user.email
```

If either is missing/empty:
1. STOP. Do not proceed with the commit or rewrite.
2. Warn the user and ask them to set identity themselves (agents must not set it).
   Example:
   ```bash
   git config --global user.name "<Your Name>" && git config --global user.email "<you@example.com>"
   ```
3. Resume only after the user confirms identity is set.

### History rewrites
Only rewrite authorship/committer history when explicitly requested by a maintainer.
- Prefer interactive rebase.
- Push with `--force-with-lease`.
- Document rewritten SHAs in the PR.
