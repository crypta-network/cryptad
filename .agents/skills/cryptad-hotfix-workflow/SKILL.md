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
- Tag an ordinary hotfix as `v<build-number>` on the hotfix branch. For a Stable 1.0 security
  hotfix, the protected maintenance workflow creates or verifies the annotated tag after
  authorization; do not tag it manually.
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

3) For an ordinary hotfix, tag the hotfix on the hotfix branch:
```sh
git tag v<build-number>
```

For a Stable 1.0 security hotfix, do not run that command. Validate the exact candidate with
`stable-maintenance` and let the protected maintenance workflow create or idempotently verify the
annotated tag. The workflow never merges the hotfix branch.

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

6) Push branches and tag for an ordinary hotfix:
```sh
git push origin main develop hotfix/<build-number>
git push origin v<build-number>
```

---

## Checklist
- [ ] `build.gradle.kts` version is the intended integer build number (if shipped).
- [ ] CI green on `hotfix/<build-number>`.
- [ ] Ordinary hotfix: tag `v<build-number>` created. Stable 1.0 security hotfix: protected
      publication receipt verifies the annotated tag.
- [ ] Merged to `main` with `--no-ff` (no squash), then back-merged to `develop` with `--no-ff`.
- [ ] Branches and tag pushed.

## Stable 1.0 security hotfix path

A Stable 1.0 hotfix uses `policies.releaseClass=security-hotfix` on
`hotfix/<build-number>` based on the currently published `main` state. Run the side-effect-free
command against a copied, completed maintenance manifest:

```bash
python3 tools/release-certification/certify.py stable-maintenance \
  --manifest build/stable-1.0-maintenance.json
```

The critical-security policy requires an incident/advisory id, qualified severity and affected
scope, release-manager authorization, exact candidate identity, full non-waivable compatibility,
packaging, updater, upgrade, rollback, migration, backup, signing, and redaction gates, and a
deadline-bound follow-up obligation for any shortened observation window. It is not a generic skip
or waiver. Declare a nonempty `affectedPackageKeys` subset even when publishing the complete
package matrix. A narrowed matrix requires a passing unaffected-target proof and must equal that
affected set exactly; a complete matrix uses `unaffectedPackageProofStatus=not-applicable`. Close
the obligation later with the side-effect-free `close-hotfix-follow-up` mode; do not rebuild or
mutate the published hotfix. The aggregate interval and every obligated row must independently
meet the normal duration and freshness policy, must have completed by the validation time, and must
bind both the original hotfix predecessor and the immutable GA identity where the scenario is a
direct-GA upgrade. When another authorized hotfix carries an open or overdue
obligation, closure evidence and authorization remain bound to the originally obligated build and
bytes. The latest activated baseline, receipt, and pointer separately authenticate where that
obligation is currently carried; do not substitute the superseding hotfix's evidence or
authorization. Authenticate the original candidate freeze against the predecessor observation
recorded in that freeze, not against a later baseline carrying the obligation. Protected pointer
activation uses a fresh activation-only authorization after environment approval; it does not alter
the published hotfix authorization or bytes.

Follow `docs/stable-1.0-maintenance-release-and-hotfix-path.md`. The protected workflow publishes
but never merges; explicit no-squash, `--no-ff` merges into `main` and `develop` remain required.
Before approval, confirm the protected environment has exact producer identities in
`CRYPTAD_STABLE_MAINTENANCE_INPUT_SIGNER_WORKFLOW` and
`CRYPTAD_STABLE_MAINTENANCE_WINDOWS_SIGNER_WORKFLOW` and a reviewed
`CRYPTAD_STABLE_MAINTENANCE_PUBLICATION_BACKEND`. A hotfix does not weaken those provenance or
publication-boundary requirements. Pin the two producer identities to the checked-in
`.github/workflows/stable-1.0-maintenance-input-producer.yml` and
`.github/workflows/stable-1.0-maintenance-windows-package-producer.yml` workflows at the exact
candidate commit; do not substitute a generic artifact upload or a URL-only producer.

If the hotfix replaces a lifecycle-revoked or security-fixes-only build, its lifecycle transition
must bind the same public advisory/incident authorization and authenticated hotfix publication.
Only the separate protected lifecycle workflow may make the verified hotfix `current-stable` and
retain the predecessor's revocation or support history. Build revocation never blows the update key
and cannot be cleared by routine maintenance. Follow
`docs/stable-1.0-support-lifecycle-and-deprecation-governance.md`.
