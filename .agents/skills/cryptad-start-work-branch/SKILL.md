---
name: cryptad-start-work-branch
description: |
  Start feature/* or bugfix/* work for Cryptad from develop, using Conventional Commits,
  and the expected PR merge policy (squash & merge for feature/bugfix; approvals + green CI).
---

# Start a feature or bugfix branch (from develop)

## How to invoke
Include the branch type and a short name (kebab-case).

**One-liner**
`$cryptad-start-work-branch Type: feature | Name: payments-cache`

**Two lines**
```
$cryptad-start-work-branch
Type: bugfix
Name: null-pointer-on-startup
```

---

## Rules
- Always branch from `develop`.
- Use Conventional Commits for commit messages (e.g., `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`).
- PR creation policy: open PRs only with maintainer/requester approval; PRs require at least one approval and green CI.
- For `feature/*` and `bugfix/*`, squash & merge is encouraged.
- Do not commit directly to `main`.

---

## Procedure
1) Sync `develop`:
```sh
git checkout develop
git pull
```

2) Create the branch:
```sh
git checkout -b <type>/<name>
```

3) Work and commit using Conventional Commits.

4) Push branch:
```sh
git push -u origin <type>/<name>
```

5) Open PR to `develop` (only with maintainer/requester approval).
- Use squash & merge.
- After merge, delete the branch if that’s the repo convention.
