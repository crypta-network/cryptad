# Cryptad Release Workflow and Runbook

> Updated May 1, 2026, to cover the release certification report that aggregates interop,
> performance, app-platform, catalog, app-owned UI, legacy-admin retirement, and CI evidence for a
> release candidate.

## Overview
- Purpose: publish a Cryptad release so running nodes discover a new `info/<edition>` descriptor, download OS-specific installers, and guide operators through installation without self-replacing the running JAR.
- Mechanism: `CoreUpdater` subscribes to an update USK, fetches a JSON manifest (`core-info.json`), detects the current platform via `AppEnv`, selects the best package (`<arch>.<ext>`), and downloads it under `updates/core/<version>/`. The legacy HTTP action layer currently lives in `:adapter-http-legacy-admin` at `network.crypta.clients.http.updater.CoreActionToadlet`, which exposes `/core-update/` for Download / Install / Open-in-store actions while progress appears in the global Alerts panel.
- Scope: Core releases now ship native installers or archives (DEB/RPM/DMG/EXE/Flatpak/Snap/tar). The legacy plugin runtime has been removed, so this runbook only covers core package releases.

## Artifacts and Keys
- **Update USK**: `USK@<update-key>/info/<BUILD_N>` (editions increment per release build).
- **Revocation SSK**: `NodeUpdateManager.REVOCATION_URI`; inserting a message disables automatic downloads and surfaces the text in Alerts.
- **Core Info descriptor** (`core-info.json`):
  ```json
  {
    "version": "1",
    "release_page_url": "https://crypta.network/releases/1",
    "changelog_chk": "CHK@...",              // optional short changelog text
    "fullchangelog_chk": "CHK@...",          // optional detailed changelog text
    "packages": {
      "amd64.deb": {
        "chk": "CHK@...",                    // required for direct downloads
        "size": 97216543,                     // optional, bytes
        "store_url": null                     // optional: fallback store link
      },
      "amd64.rpm": { "chk": "CHK@..." },
      "arm64.dmg": { "chk": "CHK@...", "size": 131072000 },
      "amd64.exe": { "chk": "CHK@..." },
      "amd64.flatpak": { "store_url": "https://flathub.org/apps/..." }
    }
  }
  ```
  - Keys follow `<arch>.<ext>` naming. Supported extensions include `deb`, `rpm`, `tar.gz`, `dmg`, `exe`, `msi`, `flatpak`, `snap`, `pkg`, `zip`.
  - `version` must be a base-10 integer string (for example `"1501"`). Noninteger values are treated as invalid for release gating and will not be advertised as updates.
  - `store_url` enables the "Open in Store" action when a direct download is not provided (Flatpak/Snap).
  - `changelog_chk` and `fullchangelog_chk` should point to CHK inserts containing Markdown or plaintext.
- **Optional extras**: continue to publish seed node lists, installer references, or IP databases separately (outside `info/`). Link to them from release notes if needed.

## Pre-Release Checklist
- **Versioning**: bump the integer `version` in `build.gradle.kts`. Ensure `Version.currentBuildNumber()` reflects the new build after `./gradlew build`.
- **Release notes**: prepare short (user-facing) and full (developer) changelog text files for CHK publishing.
- **Package matrix**: decide which OS/arch artifacts to ship this cycle. The minimum recommendation is macOS (DMG), Windows (EXE), Linux desktop/server (DEB + RPM), and Flatpak if maintained.
- **Environment validation**: run smoke tests on each target OS using `build/jpackage/Crypta`, `build/distributions/`, or the staged Flatpak bundle. Ensure the installers launch and locate `cryptad-dist/` correctly.
- **Dependency review**: verify updater metadata and package checksums are consistent with produced artifacts.

## Platform Release Gates
Treat these as release blockers, in order:

1. **Normal Gradle checks** - run the standard repository build and test path before any publish step. For release readiness, this means the usual Gradle verification path for the branch, including `./gradlew clean build` and any project-required test tasks used in CI.
2. **Release certification report** - generate the release-candidate report after the source gates
   below have produced their summaries:
   ```bash
   tools/release-certification/run-release-certification.sh \
     --mode release-candidate \
     --out-dir build/release-certification
   ```
   Preserve `build/release-certification/release-certification-summary.json`,
   `build/release-certification/release-certification-report.md`,
   `build/release-certification/history-comparison.json`,
   `build/release-certification/history-comparison.md`,
   `build/release-certification/ecosystem-certification-matrix.json`,
   `build/release-certification/ecosystem-certification-matrix.md`, and the sanitized
   `build/release-certification/artifacts/` directory as release-candidate evidence. Restore the
   previous release's sanitized summary and add
   `--previous-summary build/release-certification-history/latest-summary.json` when it is
   available. If the previous summary is not available, record that limitation in the release log;
   use `--require-history` for promotion runs where historical regression context is mandatory.
   Treat the ecosystem certification matrix as the release-manager checklist for required
   evidence coverage, ecosystem gate coverage, first-party app coverage, docs coverage, waivers,
   and row-level regressions. The workflow is documented in
   [release-certification.md](release-certification.md).
3. **First-party app staging** - stage repo-owned AppHost bundles with the app module tasks or `./gradlew stageFirstPartyApps`. The app workflow source of truth is [app-distribution.md](app-distribution.md).
4. **First-party app signing and verification** - sign with the intended release or staging key inputs, then verify with the matching trusted public key inputs. Gate promotion on successful `./gradlew signFirstPartyApps` and `./gradlew verifyFirstPartyApps` runs. Keep private signing keys outside the repository.
5. **App catalog smoke, when catalog sources ship** - verify each signed catalog source refreshes,
   validates artifact size/SHA-256, extracts safely, and can install or update through
   `/api/v1/app-catalogs`. The catalog contract is documented in
   [app-catalogs.md](app-catalogs.md).
6. **Developer app CLI smoke, when `:platform-devtools` changes** - run
   `./gradlew :platform-devtools:test` and `./gradlew :platform-devtools:installDist`, then verify
   `platform-devtools/build/install/crypta-app/bin/crypta-app --help`. The CLI contract is
   documented in [app-dev-cli.md](app-dev-cli.md).
7. **App-owned UI smoke and lint, when static UI apps ship** - open the advertised `uiUrl` for at
   least one static UI app, confirm nested-entry assets load on the isolated app origin or the
   `/apps/{appId}/` compatibility fallback, and verify no filesystem path leaks appear in error
   responses. Also verify the release certification report includes `app-ui.design-system`,
   `app-ui.lint`, and `app-ui.first-party-adoption` so first-party bundles have canonical local
   design-system assets, strict UI lint summaries, and visible permission disclosure. The route
   contract is documented in [app-owned-ui.md](app-owned-ui.md); the design-system/lint contract is
   documented in [app-ui-design-system.md](app-ui-design-system.md).
8. **App-vault and reference-app evidence** - verify the release certification report includes
   `app-vault.capabilities`, `app-platform.identity-profile-publish`,
   `app-platform.generated-document-insert`, `app-platform.content-fetch`,
   `reference-apps.content`, `reference-app.profile-publisher`, and
   `reference-app.feed-reader`. Site Publisher is the content-oriented reference app;
   release evidence must prove its staged bundle, SDK usage, design-system adoption, permission
   disclosure, content/queue helper usage, and absence of vault/identity permissions. Profile
   Publisher is the identity-profile reference app; evidence must prove browser-safe app-owned
   identity creation, profile-document publishing, app-generated document insertion, declared
   vault/content/queue permissions, and redaction of tokens, form passwords, private insert URIs,
   raw request bodies, private keys, signatures, and absolute staging paths.
   Feed Reader is the content-fetch reference app; evidence must prove `content.fetch`,
   `POST /api/v1/content/fetch`, SDK feed-helper usage, generated-feed publication permissions,
   and redaction of raw feed bodies, raw request bodies, tokens, form passwords, private insert
   URIs, and local paths.
9. **Trusted app-review receipt evidence** - verify the release certification report includes
   `app-review.trusted-receipts`, `app-review.policy`, and `app-review.first-party-catalog` when
   first-party catalog evidence is part of the candidate. Review receipt evidence is independent of
   app and catalog signing keys. Keep reviewer private keys outside the checkout and out of release
   artifacts. The catalog/review contract is documented in [app-catalogs.md](app-catalogs.md).
10. **AppHost sandbox-provider evidence** - verify the release certification report includes
   `apphost.sandbox-provider`. The evidence is deterministic and does not require live bubblewrap in
   normal CI; it must prove the bubblewrap provider contract, required-sandbox fail-closed behavior,
   and token/path-free public status. Manual Linux smoke with host-installed `bwrap` is useful
   release-manager evidence when sandbox behavior changed.
11. **App update lifecycle evidence** - verify the release certification report includes
   `app-update.lifecycle`, `app-update.scheduler`, and `app-update.rollback`. The required offline
   evidence must cover manual/stage/apply-when-stopped policy behavior, background catalog refresh
   and app checks through the shared update service, path-free staged and scheduler summaries,
   process health-gated apply, durable previous-bundle rollback, and the rule that rollback does
   not restore app data or cache. Optional live smoke may exercise install/update/rollback through
   localhost routes, but normal release-candidate evidence must not require a live node.
12. **Legacy-admin retirement evidence** - record the current retirement map, removal-wave policy,
   and diagnostics shape before any release promotion. The certification report must include
   primary-replaced, retained, and pending surface counts, confirm primary-replaced surfaces are
   absent from Web Shell fallback navigation, prove `legacy-admin.removal-wave-1` replacement and
   blocked-mutation behavior, prove `legacy-admin.removal-wave-2` safe-read replacement behavior,
   route-scope expansion metadata, partial mutation fallbacks, and retained raw diagnostic export
   status, and confirm retained/pending legacy routes remain documented.
   Optional live evidence may read `GET /api/v1/diagnostics`; those counters are process-local and
   are not durable audit logs. The retirement source of truth is
   [legacy-retirement-plan.md](legacy-retirement-plan.md).
13. **Hyphanet interop Tier 1 smoke** - run the packaged-node compatibility smoke locally on Linux
   when the environment is prepared, or verify that the CI `interop-smoke` job passed for the
   release candidate. The gate is documented in
   [tools/interop/README.md](../tools/interop/README.md) and summarized in
   [phase-3-platform-primacy-closeout.md](phase-3-platform-primacy-closeout.md).
14. **Interop Tier 2 extended soak, when compatibility-sensitive behavior changed** - run or verify
   the scheduled/manual `interop-extended` job when the release changes FCP, peer handling,
   datastore persistence, restart behavior, USK/SSK request handling, packaging layout, or node
   startup. Record `SubscribeUSK` duration, persistent request replay identifier, opennet enabled
   status, timeout settings, host OS, baseline, and the final `summary.json` path in the release
   record.
15. **Interop failure artifacts** - if an interop gate fails, preserve `build/interop-smoke/` or
   `build/interop-extended/` from the local run or CI uploaded artifact before rerunning or cleaning
   the workspace. Do not publish `artifacts/private-insert-uris.json`; CI uploads exclude it.
16. **Performance regression smoke** - run the packaged performance smoke locally or verify the
   scheduled/manual `performance-smoke` CI job when preparing a release candidate. The gate is
   documented in [tools/perf/README.md](../tools/perf/README.md). Treat deterministic asset-size
   failures as release blockers unless a maintainer records an accepted baseline update or waiver.
17. **Performance evidence, when performance-sensitive behavior changed** - run or verify the
    performance smoke when the release changes startup, packaging layout, Platform API, Web Shell,
    SDK assets, first-party app bundles, FCP startup, storage, routing, persistence, or JVM/runtime
    packaging. Record the command, mode, host OS or runner label, Java version, baseline path,
    `summary.json` path, and comparison status in the release record.

## Build
1. Clean build for deterministic artifacts:
   ```bash
   ./gradlew clean build
   ```
   - Produces `build/libs/cryptad.jar`, `build/cryptad-dist/`, the jpackage image (`build/jpackage/Crypta`), and—when tooling is available—native installers under `build/distributions/`.
   - The build logs print SHA-256 hashes for produced artifacts.
2. Optional focused tasks:
   - `./gradlew buildJar` regenerates just `cryptad.jar`.
   - `./gradlew distJlinkCryptad` refreshes the jlink archive consumed by Flatpak packaging.
   - `./gradlew jpackageInstallerCryptad` (macOS/Linux) produces `.dmg`, `.deb`, `.rpm` installers when platform tooling exists.
3. Verify each expected artifact exists and launches:
   - macOS: `open build/jpackage/Crypta.app` (or run `Contents/MacOS/Crypta`).
   - Windows: test `build/jpackage/Crypta/Crypta.exe` inside a VM.
   - Linux: install with `dpkg -i` / `rpm -i` on fresh VMs; validate service + desktop flows.
   - Interop caveat: the Hyphanet interop harness is Linux-only. macOS and Windows release
     readiness must come from installer, launcher, and application smoke tests on those platforms.

## Generate Release Descriptor and CHKs
1. **Insert artifacts to Crypta to obtain CHKs**. Run `fcpupload` separately for each installer type you ship and record both the returned CHK and the artifact size:
   - Linux `.deb` (example amd64 build):
     ```bash
     ART=build/distributions/cryptad-v${BUILD_N}-amd64.deb   # adjust if your build omits the arch suffix
     CHK=$(fcpupload -p 2 -e "$ART" | awk '/^CHK@/ {print $1}')
     SIZE=$(stat -c%s "$ART")
     ```
   - Linux `.rpm` (example amd64 build):
     ```bash
     ART=build/distributions/cryptad-v${BUILD_N}-amd64.rpm
     CHK=$(fcpupload -p 2 -e "$ART" | awk '/^CHK@/ {print $1}')
     SIZE=$(stat -c%s "$ART")
     ```
   - macOS `.dmg` (from `jpackageInstallerCryptad`):
     ```bash
     ART=build/distributions/Crypta-${BUILD_N}.dmg
     CHK=$(fcpupload -p 2 -e "$ART" | awk '/^CHK@/ {print $1}')
     SIZE=$(stat -f%z "$ART")
     ```
   - Windows installer (`.exe` or `.msi`):
     ```bash
     ART=build/distributions/Crypta-${BUILD_N}.exe   # or .msi if you package MSI
     CHK=$(fcpupload -p 2 -e "$ART" | awk '/^CHK@/ {print $1}')
     SIZE=$(stat -c%s "$ART")
     ```
   - Flatpak/Snap: record the published store URL instead of a CHK when distributing through stores only.
   - Adjust paths/filenames if you stage artifacts elsewhere or publish additional archives (e.g., `cryptad-jlink-v${BUILD_N}.tar.gz`).
   - Retain each CHK and size for the descriptor.
   - For store-distributed formats (Flatpak/Snap), ensure the store page is live and copy its URL instead of a CHK.
2. **Publish changelog texts** via CHK uploads and record their URIs.
3. **Author `core-info.json`** using the template above. Keep package entries sorted for readability.
4. Store the descriptor alongside release artifacts for auditability.

## Publish to Crypta
1. **Staging channel**
   - Upload installers (step 1 already inserts them globally—confirm reachability).
   - Insert the descriptor at `USK@<staging-update-key>/info/<BUILD_N>`:
     ```bash
     fcpput -p reboot -r 1 -g "USK@<staging-key>/info/${BUILD_N}" core-info.json
     ```
   - Update changelog CHKs in the descriptor if content changes between staging iterations.
2. **Verification** (see next section) ensures package selection, changelog links, and UI wiring behave correctly.
3. **Production channel**
   - Repeat the inserts against the production key after staging passes.
   - Record the exact JSON text/CHKs in the release log.

## Staging Verification
- Configure a staging node:
  ```ini
  node.updater.URI=USK@<staging-key>/info/
  node.updater.enabled=true
  node.updater.autoupdate=true   # auto-download only; installation remains manual
  ```
- Monitor logs:
  - Watch for `[CoreUpdater] info.json parsed` with detected `env.os/env.arch`.
  - Confirm downloads land in `updates/core/<version>/<arch>.<ext>`.
  - Validate Alerts UI: progress %, `Download` → `Install` transition, retry messaging, and `Open in Store` behaviour.
  - Exercise `/core-update/` Install; ensure installers launch or store portals open for Flatpak/Snap.
- Verify changelog links resolve through the recorded CHKs.
- On Linux, inspect preference order (Flatpak inside sandbox, native packages on host) matches expectations.
- Verify the Linux Tier 1 Hyphanet interop gate:
  ```bash
  tools/interop/run-hyphanet-interop-smoke.sh
  ```
  In CI, the `interop-smoke` job builds with `./gradlew assembleCryptadDist` and then runs the same
  gate with `INTEROP_SKIP_BUILD=1`. The expected diagnostics root is `build/interop-smoke/`.
- Inspect `build/interop-smoke/summary.json` for `status=success`, `mode=smoke`, all Tier 1
  `flows` marked `passed`, `restart_recovery_level=restart-and-refetch`,
  recorded `restart_recovery_checks`,
  Hyphanet baseline metadata, public URI records, and process statuses.
- Preserve `build/interop-smoke/` for the release record when the run fails.
- For Tier 2, run or verify `interop-extended` and preserve `build/interop-extended/` when it fails
  or when the release record needs soak evidence. The extended summary should include
  `usk_subscribe_soak`, `persistent_request_replay`, `enabled_flows`, `skipped_flows`,
  `artifacts/usk-subscribe-soak.json`, `artifacts/persistent-request-replay.json`, and
  `artifacts/interop-report.md`.
- Do not attach `artifacts/private-insert-uris.json` to release records or shared diagnostics. It
  contains temporary SSK/USK insert keys and is intentionally excluded from CI artifact uploads.
- Verify the lightweight performance gate with Python 3.12 or newer:
  ```bash
  PERF_SKIP_BUILD=1 tools/perf/run-performance-smoke.sh
  ```
  If `build/cryptad-dist/` has not been built yet, omit `PERF_SKIP_BUILD=1` and let the wrapper run
  `./gradlew assembleCryptadDist`.
- Inspect `build/perf-smoke/summary.json` and `build/perf-smoke/artifacts/perf-report.md`.
  Deterministic asset-size regressions should block promotion unless the release record includes a
  maintainer-reviewed baseline update. Environment-sensitive startup, FCP, and Platform API timing
  regressions should be investigated on comparable hardware before promotion. CI uploads
  `summary.json` and `artifacts/` from the scheduled/manual `performance-smoke` job.
- Generate the release certification report after the interop, performance, and app-platform
  evidence exists:
  ```bash
  tools/release-certification/run-release-certification.sh \
    --mode release-candidate \
    --out-dir build/release-certification
  ```
  Add `--previous-summary build/release-certification-history/latest-summary.json` after restoring
  the previous release's sanitized summary locally or in CI.
  Inspect `build/release-certification/release-certification-report.md` and
  `build/release-certification/release-certification-summary.json`,
  `build/release-certification/history-comparison.md`, and
  `build/release-certification/history-comparison.json`. Then inspect
  `build/release-certification/ecosystem-certification-matrix.md` for row status, previous
  status, regression status, release blockers, waiver ids, coverage checks, and recommendations.
  Missing required evidence, failed required evidence, missing signed bundle/catalog/review evidence, missing app UI
  design-system/lint evidence, missing `apphost.sandbox-provider` evidence, required evidence
  regressions, or failing ecosystem gates block release-candidate promotion unless a release
  manager records an explicit waiver. If the previous summary predates PR-231 and the matrix
  reports `previousMatrixPresent=false`, record that baseline transition in the release log and
  continue only after the row-level evidence and gate coverage checks pass or have explicit
  waivers. Do not attach `artifacts/private-insert-uris.json`, private
  signing keys, private reviewer keys, form passwords, app tokens, browser session tokens, raw
  request bodies, raw trusted reviewer public key bytes, or unsanitized local paths to the release
  record. CI uploads contain sanitized certification artifacts only; preserve raw local or CI gate
  failure directories separately when deeper diagnostics are needed.

## Production Rollout
- Publish descriptor and artifacts to the production USK.
- Announce the release with links to installers, release notes, and any manual installation guidance.
- Monitor:
  - Node logs for `[CoreUpdater] progress` and `Download Completed` entries.
  - Support channels for installer/store issues.

## Emergency Procedures
- **Hotfix**: bump build number, rebuild, generate new descriptor, and publish to `info/<BUILD_N+1>`. Nodes will surface in the newer package immediately.
- **Revoke updater**: insert a clear message into `REVOKE_SSK`; `NodeUpdateManager` disables auto-downloads and shows the text in Alerts.
- **Pull a bad release**: publish a replacement descriptor at the same edition with `packages` emptied or pointing to a warning changelog. Communicate manual cleanup steps because cached files under `updates/core/` are retained.

## Operator Notes (for node users)
- Enable the updater via `node.updater.enabled=true`; opt into background downloads with `node.updater.autoupdate=true`.
- Downloads appear under `updates/core/`; installation requires manual confirmation from the Alerts panel.
- `Install` launches platform installers or store portals. Windows may require SmartScreen confirmation.
- Alerts now show retry messaging for transient failures; use the `Retry` button without restarting the node.

## Appendix: Code Path Reference
- `NodeUpdateManager`: orchestrates CoreUpdater lifecycle, changelog exposure, download state, and auto-download toggles.
- `CoreUpdater`: subscribes to the update USK, parses `core-info.json`, selects packages based on `AppEnv`, manages `PackageFetcher`, and auto-downloads when allowed.
- `network.crypta.clients.http.updater.CoreActionToadlet` in `:adapter-http-legacy-admin`:
  handles `/core-update/` POST actions (download, install, open store) and surfaces status
  transitions.
- `PackageFetcher`: wraps the client getter to track splitfile progress and expose retryable status to the UI.
- `AppEnv`: single source of truth for OS/arch/service detection (replaces direct `os.name` probes).
- `UpdateOverMandatoryManager`: core JAR UoM paths are disabled (`supportsJarUOM=false`).

## Release Runbook (Template)

### Variables
```bash
export BUILD_N=<INT_BUILD_NUMBER>
export STAGING_USK="USK@<staging-update-key>/info/"
export PROD_USK="USK@<prod-update-key>/info/"
export REVOKE_SSK="SSK@<revocation-key>/revoked"
export VERSION_STRING="$BUILD_N"               # must stay an integer string; used for update gating
export RELEASE_PAGE="https://crypta.network/releases/$BUILD_N"
```

### 1) Build Artifacts
```bash
./gradlew clean build
ls -lh build/distributions/
```
Confirm the presence of:
- `cryptad-v${BUILD_N}.deb`, `cryptad-v${BUILD_N}.rpm`
- `Crypta-${BUILD_N}.dmg`
- `Crypta-${BUILD_N}.exe` (or `.msi`)
- `cryptad-jlink-v${BUILD_N}.tar.gz` (optional, publish as `amd64.tar.gz` / `arm64.tar.gz`)

### 2) Generate CHKs
For each artifact (example: Debian amd64 package):
```bash
ART=build/distributions/cryptad-v${BUILD_N}.deb
SIZE=$(stat -c%s "$ART")
CHK=$(fcpupload -p 2 -e "$ART" | awk '/^CHK@/ {print $1}')
printf '  "amd64.deb": { "chk": "%s", "size": %s },\n' "$CHK" "$SIZE" >> packages.json
```
Repeat for every platform.

### 3) Publish Changelogs
```bash
SHORT_CHK=$(fcpupload -p 2 -e CHANGELOG-${BUILD_N}.md | awk '/^CHK@/ {print $1}')
FULL_CHK=$(fcpupload -p 2 -e FULLCHANGELOG-${BUILD_N}.md | awk '/^CHK@/ {print $1}')
```

### 4) Assemble Descriptor
```bash
cat > core-info.json <<'JSON'
{
  "version": "${VERSION_STRING}",
  "release_page_url": "${RELEASE_PAGE}",
  "changelog_chk": "${SHORT_CHK}",
  "fullchangelog_chk": "${FULL_CHK}",
  "packages": {
$(sed '$s/,$//' packages.json)
  }
}
JSON
```
Sanity-check formatting (`jq . core-info.json`).

### 5) Publish to Staging
```bash
fcpput -p reboot -r 1 -g "${STAGING_USK}${BUILD_N}" core-info.json
```
Verify a staging node downloads and exposes the installer correctly (`updates/core/` and Alerts UI).

### 6) Record Performance Gate
```bash
tools/perf/run-performance-smoke.sh
jq '.status, .comparison.status' build/perf-smoke/summary.json
```
Record the command line, mode, host OS or runner label, Java version, commit SHA, baseline path,
`build/perf-smoke/summary.json`, key threshold decisions, whether `distribution.build_ms` was
collected or intentionally skipped, and whether a baseline update was made.

### 7) Promote to Production
```bash
fcpput -p reboot -r 1 -g "${PROD_USK}${BUILD_N}" core-info.json
```
Retain the descriptor and package CHKs in the release record.

### 8) Post-release Checklist
- Update the public release page and announcement channels.
- Monitor `[CoreUpdater] progress` logs across canary nodes.
- Retain `build/perf-smoke/` or the CI performance artifact when a performance gate fails or when
  the release record needs performance evidence.
- Prepare a fallback plan (revocation message, follow-up descriptor) in case regressions surface.

### 9) Emergency Actions
```bash
# Pause downloads network-wide
echo "Emergency: pause ${BUILD_N}. Investigating installer regressions." | \
  fcpput -p reboot -r 1 -g "${REVOKE_SSK}"
```
To supersede a bad release, craft a new descriptor with corrected `packages` and publish to the next
edition number. If the incident is a confirmed performance regression, link the relevant
`build/perf-smoke/summary.json` or CI artifact in the incident record.

---
Keep this runbook synchronized with future CoreUpdater/AppEnv changes. Update references whenever package selection logic or descriptor schema evolves.
