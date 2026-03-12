---
name: cryptad-hotfix-workflow
description: |
  Create a hotfix/<build-number> branch from main for Cryptad, bump integer build-number versioning if shipped,
  tag v<build>, then no-squash --no-ff merge into main and develop and push branches/tags.
---

# Hotfix workflow (hotfix/<build-number>)

## How to invoke
Provide the intended hotfix build number (integer).

**One-liner**
`$cryptad-hotfix-workflow Build: 3`

**Two lines**
```
$cryptad-hotfix-workflow
Build: 3
```

---

## Rules
- Hotfix branches are `hotfix/<build-number>` and must be based on `main`.
- If the hotfix changes the shipped build, bump the integer `version` in `build.gradle.kts` to the next build number.
- Tag the hotfix as `v<build-number>` on the hotfix branch.
- Merge `hotfix/*` into `main` and back-merge into `develop` using **no squash** and `--no-ff`.
- Do not rebase/squash hotfix merges.

---

## Procedure
1) Sync `main` and create the hotfix branch:
```sh
git checkout main
git pull
git checkout -b hotfix/<build-number>
```

2) Apply the fix, run tests/CI per repo conventions.
- If the hotfix changes the shipped build, set `version = <build-number>` in `build.gradle.kts`.

3) Tag the hotfix on the hotfix branch:
```sh
git tag v<build-number>
```

4) Merge to `main` (no squash; preserve branch context):
```sh
git checkout main
git pull
git merge --no-ff hotfix/<build-number>
```

5) Back-merge to `develop` (no squash):
```sh
git checkout develop
git pull
git merge --no-ff hotfix/<build-number>
```

6) Push branches and tag:
```sh
git push origin main develop hotfix/<build-number>
git push origin v<build-number>
```

---

## Checklist
- [ ] `build.gradle.kts` version is the intended integer build number (if shipped).
- [ ] CI green on `hotfix/<build-number>`.
- [ ] Tag `v<build-number>` created.
- [ ] Merged to `main` with `--no-ff` (no squash), then back-merged to `develop` with `--no-ff`.
- [ ] Branches and tag pushed.
