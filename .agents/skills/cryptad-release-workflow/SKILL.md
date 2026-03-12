---
name: cryptad-release-workflow
description: |
  Cut and stabilize a release/<build-number> branch for Cryptad, using integer build-number versioning,
  tags v<build>, and no-squash --no-ff merges into main and develop.
---

# Release workflow (release/<build-number>)

## How to invoke
Provide the intended build number (integer).

**One-liner**
`$cryptad-release-workflow Build: 2`

**Two lines**
```
$cryptad-release-workflow
Build: 2
```

---

## Rules
- Release branches are `release/<build-number>` and must be based on `develop`.
- The build number is a single integer in `build.gradle.kts` (e.g., `version = 2`).
- Tag the release as `v<build-number>` on the release branch.
- Merge `release/*` into `main` and back-merge into `develop` using **no squash** and `--no-ff`.
- Stabilization only: allow critical fixes/docs/release tasks; avoid large refactors.
- Do not rebase/squash release merges.

---

## Procedure
1) Sync `develop` and create the release branch:
```sh
git checkout develop
git pull
git checkout -b release/<build-number>
```

2) Set the build number in `build.gradle.kts` (e.g., `version = <build-number>`), and run CI/tests per repo conventions.

3) Stabilize on `release/<build-number>` (critical fixes only). Keep diffs minimal.

4) Tag the release on the release branch:
```sh
git tag v<build-number>
```

5) Merge forward to `main` (no squash; preserve branch context):
```sh
git checkout main
git pull
git merge --no-ff release/<build-number>
```

6) Back-merge to `develop` (no squash):
```sh
git checkout develop
git pull
git merge --no-ff release/<build-number>
```

7) Push branches and tag:
```sh
git push origin main develop release/<build-number>
git push origin v<build-number>
```

---

## Checklist
- [ ] `build.gradle.kts` version is the intended integer build number.
- [ ] CI green on `release/<build-number>`.
- [ ] Tag `v<build-number>` created.
- [ ] Merged to `main` with `--no-ff` (no squash), then back-merged to `develop` with `--no-ff`.
- [ ] Branches and tag pushed.
- [ ] Release notes updated (if applicable).
