---
name: cryptad-release-workflow
description: |
  Cut and stabilize a Cryptad release branch using integer build-number versioning, v-number tags,
  no-squash --no-ff merges into main and develop, and the protected Stable 1.0 RC/GA or later
  maintenance path when the release targets that product milestone.
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
- Stable 1.0 is a product/API milestone, not a semantic project version. Keep the integer build and
  `v<build-number>` tag model; never introduce `1.0.0`.
- For Stable 1.0, freeze with `stable-rc` and promote that exact product with `stable-ga`. Do not
  rebuild, re-sign, rewrite the catalog, or create the GA tag/Release outside the explicitly
  protected publication operation.
- After Stable 1.0 GA, use `stable-maintenance` for both routine maintenance and security hotfix
  candidates. It builds and freezes one new integer-build candidate; the protected maintenance
  workflow publishes only those authorized bytes and never merges the branch.
- Use `docs/cryptad-release-workflow-and-runbook.md` as the detailed release-readiness source of
  truth. Current release gates include the release certification report, first-party app
  staging/signing/verification, first-party beta catalog and trusted app-review receipt smoke,
  app-review governance/reviewer-key/transparency-log evidence, app-owned UI design-system/lint
  smoke, Platform API 1.0 stable baseline, target-stability, and stable breaking-change evidence,
  app-vault capability evidence, generated-document insert evidence, content-fetch evidence,
  durable content-subscription evidence, shared app-network budget and network-scale soak evidence,
  durable app-data and app-data backup/restore evidence, app-service
  registry/grant/dependency/grant-bundle evidence, Trust Graph Local RC evidence, Site
  Publisher/Profile Publisher/Social Inbox RC/Feed Reader/Trust Graph Local RC reference-app
  evidence, app platform beta docs/program evidence, third-party developer beta evidence,
  multi-node beta soak and upgrade drill evidence, live USK catalog publication evidence,
  catalog operations and mirrors evidence, production beta artifact redaction evidence, production
  beta go/no-go dashboard evidence, waiver validation, and
  `production-security.response-runbook` when app artifacts ship, app-update
  lifecycle/scheduler/rollback and app-data migration contract evidence, `crypta-app` developer
  beta toolkit smoke, operator RC
  recovery/support evidence, legacy plugin freeze evidence, legacy-admin retirement/removal Wave
  1-5 and final-surface evidence, Hyphanet interop smoke/soak evidence, and the packaged-node
  performance smoke.

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

   Before promotion, run the unified certification suite, copy the example manifest, and replace
   every placeholder. The checked-in example is a template and must not be executed directly.
   ```sh
   python3 tools/release-certification/certify.py self-test all
   cp tools/release-certification/manifests/release-candidate.example.json \
     build/release-candidate.json
   # Set release.id, release.version, inputs, policies, requirements, and execution controls.
   python3 tools/release-certification/certify.py release-certification \
     --manifest build/release-candidate.json
   ```
   Unified component inputs must be expected-kind, candidate-bound v2 envelopes. For the first v2
   release, use `certify.py migrate-v1` with the finalized candidate ID, then point
   `inputs.previousCandidate` and `inputs.releaseHistory` at those immutable migration summaries.
   Keep manifest values non-secret; signing keys, credentials, private URIs, and other private
   material belong only in protected environment variables or files.
   Preserve the complete marked `<out-root>/<release-id>/` workspace. With the example output root,
   preserve `build/release-certification/<release-id>/`, including
   `build/release-certification/<release-id>/release-certification/summary.json`,
   `build/release-certification/<release-id>/release-certification/report.md`,
   `build/release-certification/<release-id>/release-certification/redaction-report.json`,
   `build/release-certification/<release-id>/release-certification/artifacts/`,
   `build/release-certification/<release-id>/network-scale-soak/summary.json`,
   `build/release-certification/<release-id>/multi-node-beta/run/summary.json`, and
   `build/release-certification/<release-id>/security-response/`. Replace `<release-id>` with the
   finalized manifest `release.id`. If `execution.writeHistory=true`, also preserve the shared
   `build/release-certification-history/` archive; failed candidates do not replace its latest
   passing summary.

   When the release includes production beta app-ecosystem artifacts, run the top-level production
   beta pipeline instead of manually assembling app bundles, catalogs, review receipts, lower-level
   certification output, and the public archive:
   ```sh
   cp tools/release-certification/manifests/production-beta.example.json \
     build/production-beta.json
   # Replace every placeholder and bind every v2 input to the same release.id.
   python3 tools/release-certification/certify.py production-beta \
     --manifest build/production-beta.json
   ```
   Set the release identity, output root, production profile, catalog channel, artifact base URI,
   required gates, and evidence inputs in the manifest before running either command.
   Preserve the common JSON/Markdown summaries and production redaction report. Detailed go/no-go
   dashboard JSON/Markdown, dashboard redaction, extracted evidence, and checksums live under
   `<out-root>/<release-id>/production-beta/artifacts/legacy/`, including `reports/`, `evidence/`,
   and `dist/checksums.txt`. Validated attached extracts live under `artifacts/inputs/`. Any summary
   with `nonRelease=true`, `promotionReady=false`, `goNoGo`
   decision `no-go`, failed production or dashboard redaction, dirty workspace, fixture evidence,
   test signing, skipped production-beta build stages, or an emergency live-network skip is not
   promotable. A `go-with-waivers` decision is launchable only when every residual blocker has a
   valid, scoped, approved, unexpired waiver and none of the non-waivable production-beta evidence,
   redaction, signing, live-network, sandbox, multi-node, or artifact-hygiene gates failed.

   For the Stable 1.0 milestone, continue with the canonical freeze and promotion path:

   ```sh
   cp tools/release-certification/manifests/stable-1.0-rc.example.json \
     build/stable-1.0-rc.json
   # Replace every placeholder and provide protected production inputs.
   python3 tools/release-certification/certify.py stable-rc \
     --manifest build/stable-1.0-rc.json

   cp tools/release-certification/manifests/stable-1.0-ga.example.json \
     build/stable-1.0-ga.json
   # Bind the latest successful freeze, exact product, post-freeze evidence, and authorization.
   python3 tools/release-certification/certify.py stable-ga \
     --manifest build/stable-1.0-ga.json
   ```

   Treat the commands above as validation/preparation boundaries. `stable-rc` does not publish GA,
   and `stable-ga` never publishes by itself. Dispatch
   `.github/workflows/stable-1.0-ga-promotion.yml` with publication explicitly enabled only after
   protected approval. The workflow must revalidate the exact RC, authorization, release branch,
   public artifact base, catalog targets, and any existing tag/Release/assets before side effects.
   Retain the verified publication receipt and `stable-1.0-maintenance-baseline.json`. If any frozen
   payload or release input needs a fix, stop and complete an authorized RC refreeze, then restart
   post-freeze validation.

3) Stabilize on `release/<build-number>` (critical fixes only). Keep diffs minimal.

4) Tag the release on the release branch. For an ordinary release, create the tag manually:
```sh
git tag v<build-number>
```

For Stable 1.0 GA or a later Stable 1.0 maintenance release, do not run that command manually. The
applicable explicitly authorized protected publication job creates or idempotently verifies the
annotated `v<build-number>` tag at the exact authorized commit. It does not merge the release
branch.

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

7) Push branches and tag for an ordinary release:
```sh
git push origin main develop release/<build-number>
git push origin v<build-number>
```

For Stable 1.0, push the branches after the release-manager-approved merges and verify the tag
against the retained publication receipt; the protected GA publication job already owns tag and
GitHub Release creation.

---

## Checklist
- [ ] `build.gradle.kts` version is the intended integer build number.
- [ ] CI green on `release/<build-number>`.
- [ ] Release certification report generated in `release-candidate` mode and required evidence
      passed or has an explicit release-manager waiver.
- [ ] Production beta app-ecosystem pipeline summary reviewed when first-party app artifacts ship;
      `promotionReady=true`, `nonRelease=false`, production signing, complete in-pipeline build,
      clean workspace, public HTTPS artifact base URI, required live-network evidence, required
      multi-node beta evidence, and redaction `pass` are all present before publication. Confirm the
      security response section reports `production-security.response-runbook` passing with no
      blockers and confirm `developerBetaProgram.status=pass`.
- [ ] First-party AppHost bundles staged, signed, and verified when shipping app-platform artifacts.
- [ ] `crypta-app` CLI smoke completed when `:platform-devtools` changed.
- [ ] Signed catalog, first-party beta catalog, production catalog channels, catalog operations
      and mirrors, first-party maintenance policy, catalog security advisory/denylist gates,
      trusted app-review receipt, Platform API contract, Platform API 1.0
      stable baseline, target-stability, and stable breaking-change evidence, app-vault capability,
      generated-document insert, content-fetch/subscription, shared
      app-network budget, network-scale soak, durable app-data, app-data backup/restore, app-service
      registry/grant/dependency/grant-bundle/redaction, app UI design-system/lint, app-owned UI
      smoke, Site Publisher reference-content, Profile
      Publisher identity-profile, Social Inbox RC threading/trust/service-dependency, Feed Reader
      content-subscription, Trust Graph Local RC durable exchange/scope, live USK catalog refresh,
      app-review governance/reviewer-key lifecycle and transparency-log, app platform beta
      docs/program/redaction, third-party developer beta docs, template, sample-flow, checklist,
      compatibility, feedback, plugin-migration and redaction, multi-node beta soak, upgrade,
      rollback, backup, support-bundle and redaction, AppHost sandbox-provider, app-update
      lifecycle, app-update scheduler, app-update rollback, app-update data migration contract,
      developer beta toolkit, operator RC recovery/support, production security response runbook,
      legacy plugin freeze, and legacy-admin retirement/removal Wave 1-5/final-surface evidence
      are present in the certification summary.
- [ ] Hyphanet interop smoke passed or CI evidence recorded; extended interop captured when
      compatibility-sensitive behavior changed.
- [ ] Performance smoke passed or scheduled/manual CI evidence recorded when release readiness or
      performance-sensitive changes require it.
- [ ] For Stable 1.0, the selected RC is the latest successful protected freeze/refreeze;
      freeze/product/archive/catalog/app/API/profile digests match; post-freeze production
      validation and explicit GA authorization pass; `rcProductDigest == gaProductDigest`; and the
      protected publication receipt verifies the tag, Release assets, notes, artifact base, and
      catalog primary/mirrors before publication is called complete.
- [ ] For Stable 1.0, retain `stable-1.0-maintenance-baseline.json`; do not create the tag or
      GitHub Release from tests, local validation, or an ordinary PR workflow.
- [ ] Release record excludes `artifacts/private-insert-uris.json`, private signing keys, private
      reviewer keys, form passwords, app tokens, browser-session tokens, raw request bodies, raw
      feed bodies, raw social message bodies, raw trust documents, raw app-data values, raw
      app-data backup payloads, raw diagnostic exports, raw app-service subject URIs, private
      insert URIs, raw trusted reviewer public key bytes, provider app data, raw signatures, raw
      incident artifacts, raw fetched content, command lines containing secrets, CI secret values,
      and unsanitized local paths.

## Stable 1.0 maintenance releases after GA

For a later routine Stable 1.0 release, copy
`tools/release-certification/manifests/stable-1.0-maintenance.example.json`, replace every
placeholder, select `policies.releaseClass=maintenance`, and run:

```bash
python3 tools/release-certification/certify.py stable-maintenance \
  --manifest build/stable-1.0-maintenance.json
```

The command is side-effect-free. It authenticates the immutable GA v1 baseline and complete GA
receipt, authenticates the latest published predecessor, freezes one new candidate, enforces
compatibility and evidence gates, and prepares an authorization or closes a hotfix follow-up. The
protected `.github/workflows/stable-1.0-maintenance-release.yml` workflow revalidates current public
state, creates or verifies the annotated tag, publishes exact bytes, and activates a successor v2
baseline only after receipt verification. It never creates or merges `release/<build-number>`.
Publication retries may continue only after an exact matching target prefix; non-prefix partial
state is a conflict. Latest-baseline activation uses a fresh, activation-only authorization issued
inside the protected activation environment and bound to the verified receipt, successor, history,
original authorization digest, and expected pointer. Do not extend or replace the immutable public
publication authorization merely because an activation approval wait crossed its expiry.
The evidence environment must configure exact producer identities in
`CRYPTAD_STABLE_MAINTENANCE_INPUT_SIGNER_WORKFLOW` and
`CRYPTAD_STABLE_MAINTENANCE_WINDOWS_SIGNER_WORKFLOW`. Configure the reviewed publication-backend
source commit, wheel digest, signer workflow, and entry point as repository-level Actions variables
so they are visible to the evidence-scoped independent verifier and both publication environments;
never scope those four immutable identity pins only to a publication environment. Missing producer
authentication or publication infrastructure is a hard stop, not permission to accept a path or
URL as identity.
Use the checked-in protected input and Windows package producer workflow identities. The input
producer retrieves only the exact-digest, public-safe phase ZIP through the evidence environment's
secret locator. It must reject every non-global DNS result, connect only to the validated numeric
addresses, verify the connected peer, and retain the original hostname for TLS SNI and certificate
verification before sending any bearer credential. The Windows producer builds once,
Authenticode-signs and verifies the amd64 EXE, rechecks tracked source state, and attests both the
EXE and its receipt.

Run `.github/workflows/stable-1.0-maintenance-release.yml` through its four closed operations:
`freeze-candidate`, `prepare-authorization`, `validate-authorization`, then `publish`. Only freeze
may build candidate assets. Prepare consumes the exact attested freeze plus post-freeze evidence;
authorization validation consumes the exact prepared bundle plus one exact authorization JSON; and
publish consumes only that authorized bundle. The macOS producer must Developer-ID-sign, notarize,
staple, and verify its DMG before the freeze record is written. Publication jobs authenticate and
install the pinned provider wheel on the clean runner and recheck the remote release/hotfix ref and
authorization before mutation. Never collapse the four operations into one run or accept a
replacement candidate/evidence/authorization input at publication time.
Record the exact producing run id, artifact name, and Actions artifact digest at every handoff.
Freeze additionally requires the protected Windows producer coordinates and exact EXE SHA-256;
publish additionally requires the reviewed publication-backend producer coordinates. A path,
artifact name, run id, or digest by itself is not a complete producer identity.

Configure `LEUMOR_GITHUB_TOKEN` on both maintenance publication environments. The protected
workflow must verify that token's `/user` login is exactly `leumor` and give it, rather than the
job-scoped Actions token, to tag, GitHub Release, and release-asset mutations. Keep the Actions
token read-only and use it only to authenticate workflow artifacts and attestations.

The canonical provider verifies a separately pre-staged artifact base and uses a closed deployment
service for catalog, CoreUpdater, publication verification, and latest-pointer state. Its
`verify-publication` request carries the digest-bound records needed to build the receipt,
successor, and history; do not provision an undocumented service-side candidate copy. Follow
`tools/release-certification/publication-backend/README.md` for the exact protocol and accepted
public-HTTPS endpoint forms.

Follow `docs/stable-1.0-maintenance-release-and-hotfix-path.md`. Preserve manual no-squash,
`--no-ff` merges into `main` and `develop` after the release-manager-approved publication flow.

After a Stable 1.0 maintenance publication and successor-baseline activation are independently
verified, prepare the separate support lifecycle transition from the authenticated history. The
release publication itself does not make a candidate `current-stable` in mutable lifecycle state.
Use the protected lifecycle workflow to authorize, publish, and verify the exact next
`support-lifecycle` descriptor edition; never rewrite the release's historical `core-info.json` or
activate lifecycle state from an unverified/partial release publication. Follow
`docs/stable-1.0-support-lifecycle-and-deprecation-governance.md`.
- [ ] Tag `v<build-number>` created.
- [ ] Merged to `main` with `--no-ff` (no squash), then back-merged to `develop` with `--no-ff`.
- [ ] Branches and tag pushed.
- [ ] Release notes updated (if applicable).
