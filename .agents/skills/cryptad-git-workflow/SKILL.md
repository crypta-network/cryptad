---
name: cryptad-git-workflow
description: "Canonical Cryptad Git workflow guide for branching/release rules, integer build versioning/tags, merge policy, PR rules, and strict git identity safeguards."
compatibility: opencode
metadata:
  area: git
  domain: cryptad
---

## When to use
Use this skill whenever you:
- Need the canonical branch/release policy reference.
- Create branches, commits, tags, releases, or hotfixes.
- Resolve merge conflicts or integrate changes between branches.
- Prepare a pull request (even if you won’t open it yet).

## Workflow reference
### Goals
- Keep `main` always releasable and matching the latest production build.
- Use a single integer build number for shipped versions.
- Keep feature work parallel while preserving auditable release/hotfix history.

### Versioning and tags
- The build number is a single integer in `build.gradle.kts` (example: `version = 2`).
- Release/hotfix tags must use `v<build-number>` (example: `v2`).
- If a release/hotfix changes the shipped build, bump `version` to the intended build number.

### Branching model (GitFlow-inspired)
- Primary branches:
  - `main`: production-ready; every commit is release-quality.
  - `develop`: integration branch for the next release.
- Supporting branches:
  - `feature/<name>`: new features/refactors targeting `develop`.
  - `bugfix/<name>`: non-production fixes targeting `develop`.
  - `release/<build-number>`: stabilization branch from `develop`.
  - `hotfix/<build-number>`: emergency production fix branch from `main`.

## Merge and PR policy
- Commit format: Conventional Commits.
- `feature/*` and `bugfix/*` PRs: squash-and-merge is encouraged.
- `release/*` and `hotfix/*` merges:
  - Do not squash or rebase these merges.
  - Merge into `main` with `--no-ff`.
  - Back-merge into `develop` with `--no-ff`.
- PR policy: require green CI and at least one approval.
- **Always ask before creating a GitHub pull request.** Do not open PRs without explicit approval.

## Release/hotfix checklist
- [ ] `build.gradle.kts` has the intended integer `version`.
- [ ] CI is green on the release/hotfix branch.
- [ ] Tag created as `v<build-number>`.
- [ ] Merged to `main` with `--no-ff` (no squash), then back-merged to `develop` with `--no-ff`.
- [ ] Branches and tags are pushed.
- [ ] Release notes updated (if applicable).

## Git identity policy (must follow)
### GitHub operation identity
- All GitHub operations for this repository must use the `leumor` account, including PR creation,
  review comments, issue comments, review-thread resolution, release edits, CI inspection, and
  branch pushes.
- Do not rely on the active/default `gh` account. Prefix every manual `gh` command with:
  `GH_TOKEN="$(gh auth token --user leumor)" gh ...`.
- If a GitHub MCP or plugin tool performs a write operation, verify the created PR/comment/review
  author is `leumor`. If it is not `leumor`, delete or close the accidental artifact when possible
  and recreate it as `leumor`.
- If `gh auth token --user leumor` fails, stop and ask the user to authenticate `leumor`; do not
  fall back to another GitHub account.

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
