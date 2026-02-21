---
name: cryptad-git-workflow-reference
description: |
  Reference guide for Cryptad’s standard Git branching + release workflow (main/develop, feature/bugfix,
  release/<build>, hotfix/<build>, integer build-number versioning, tags v<build>, merge rules).
---

# Cryptad Git workflow reference

## How to invoke
Use this skill when you want the branching/release rules and checklists in one place.

**One-liner**
`$cryptad-git-workflow-reference`

---

## Goals
- Keep `main` always releasable and matching the latest production build.
- Use a simple versioning model driven by a single integer build number.
- Allow parallel feature development while keeping release/hotfix flows safe and auditable.

---

## Versioning system
- A single integer build number is set in `build.gradle.kts` (example: `version = 2`).
- Tags use `v<build-number>` (example: `v2`).
- Artifacts/installers use this integer where a numeric version is required.

---

## Branching model (GitFlow-inspired)

### Primary branches
- `main`: production-ready code; every commit must be release-quality.
- `develop`: integration branch for upcoming work that will land in the next release.

### Supporting branches
- `feature/<name>`: new features or refactors targeting the next release.
- `bugfix/<name>`: fixes for work on `develop` before a release branch is cut.
- `release/<build-number>`: release stabilization for the numbered build; only critical changes.
- `hotfix/<build-number>`: emergency fix for production; based on `main`.

---

## Merge and commit policy
- Use **Conventional Commits** (e.g., `feat:`, `fix:`, `docs:`).
- **Squash & merge** for `feature/*` and `bugfix/*` PRs is encouraged.
- **Do not squash** `release/*` or `hotfix/*` merges.
- Use `--no-ff` merges for `release/*` and `hotfix/*` into both `main` and `develop` to preserve branch context.
- PR creation policy: open PRs only with maintainer/requester approval; PRs require at least one approval and green CI.

---

## Do / Don’t
### Do
- Keep `main` releasable; use `develop` for integration.
- Tag every release/hotfix with `v<build-number>`.
- After release/hotfix, always back-merge to `develop`.

### Don’t
- Don’t rebase or squash `release/*` or `hotfix/*` when merging into `main`/`develop`.
- Don’t skip bumping the build number when a release/hotfix changes the shipped build.
- Don’t open PRs without maintainer/requester approval.

---

## Release/hotfix checklist
- [ ] `build.gradle.kts` has the intended numeric `version` (build number).
- [ ] CI is green on the release/hotfix branch.
- [ ] Tag created: `v<build-number>`.
- [ ] Merged to `main` (no squash), then back-merged to `develop` (no squash).
- [ ] Pushed tags and branches.
- [ ] Release notes updated (if applicable).
