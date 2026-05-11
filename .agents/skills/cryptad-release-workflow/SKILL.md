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
- Use `docs/cryptad-release-workflow-and-runbook.md` as the detailed release-readiness source of
  truth. Current release gates include the release certification report, first-party app
  staging/signing/verification, catalog and trusted app-review receipt smoke, app-owned UI
  design-system/lint smoke, app-vault capability evidence, Site Publisher reference-content
  evidence, `crypta-app` CLI smoke, legacy-admin retirement/removal evidence, Hyphanet interop
  smoke/soak evidence, and the packaged-node performance smoke.

---

## Procedure
1) Sync `develop` and create the release branch:
```sh
git checkout develop
git pull
git checkout -b release/<build-number>
```

2) Set the build number in `build.gradle.kts` (e.g., `version = <build-number>`), and run CI/tests per repo conventions.
   Follow the release gates in `docs/cryptad-release-workflow-and-runbook.md`; load
   `$cryptad-build-test`, `$cryptad-platform-apps`, and `$cryptad-interop-performance-gates` when
   those areas are involved.

   Before promotion, generate or verify the release-candidate certification artifacts:
   ```sh
   tools/release-certification/run-release-certification.sh \
     --mode release-candidate \
     --out-dir build/release-certification
   ```
   Preserve `build/release-certification/release-certification-summary.json`,
   `build/release-certification/release-certification-report.md`, and sanitized
   `build/release-certification/artifacts/`.

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
- [ ] Release certification report generated in `release-candidate` mode and required evidence
      passed or has an explicit release-manager waiver.
- [ ] First-party AppHost bundles staged, signed, and verified when shipping app-platform artifacts.
- [ ] `crypta-app` CLI smoke completed when `:platform-devtools` changed.
- [ ] Signed catalog, trusted app-review receipt, Platform API contract, app-vault capability,
      app UI design-system/lint, app-owned UI smoke, Site Publisher reference-content, AppHost
      sandbox-provider, app-update lifecycle, app-update rollback, and legacy-admin
      retirement/removal evidence are present in the certification summary.
- [ ] Hyphanet interop smoke passed or CI evidence recorded; extended interop captured when
      compatibility-sensitive behavior changed.
- [ ] Performance smoke passed or scheduled/manual CI evidence recorded when release readiness or
      performance-sensitive changes require it.
- [ ] Release record excludes `artifacts/private-insert-uris.json`, private signing keys, private
      reviewer keys, form passwords, app tokens, browser-session tokens, raw request bodies, raw
      trusted reviewer public key bytes, and unsanitized local paths.
- [ ] Tag `v<build-number>` created.
- [ ] Merged to `main` with `--no-ff` (no squash), then back-merged to `develop` with `--no-ff`.
- [ ] Branches and tag pushed.
- [ ] Release notes updated (if applicable).
