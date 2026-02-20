# Cryptad Release Workflow and Runbook

> Updated September 16, 2025 to cover the CoreUpdater package-based distribution flow.

## Overview
- Purpose: publish a Cryptad release so running nodes discover a new `info/<edition>` descriptor, download OS-specific installers, and guide operators through installation without self-replacing the running JAR.
- Mechanism: `CoreUpdater` subscribes to an update USK, fetches a JSON manifest (`core-info.json`), detects the current platform via `AppEnv`, selects the best package (`<arch>.<ext>`), and downloads it under `updates/core/<version>/`. `CoreActionToadlet` exposes `/core-update/` for Download / Install / Open-in-store actions, while progress appears in the global Alerts panel.
- Scope: Core releases now ship native installers or archives (DEB/RPM/DMG/EXE/Flatpak/Snap/tar). Plugin updates continue to use their existing channels.

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
  - `store_url` enables the "Open in Store" action when a direct download is not provided (Flatpak/Snap).
  - `changelog_chk` and `fullchangelog_chk` should point to CHK inserts containing Markdown or plaintext.
- **Optional extras**: continue to publish seed node lists, installer references, or IP databases separately (outside `info/`). Link to them from release notes if needed.

## Pre-Release Checklist
- **Versioning**: bump the integer `version` in `build.gradle.kts`. Ensure `Version.currentBuildNumber()` reflects the new build after `./gradlew build`.
- **Release notes**: prepare short (user-facing) and full (developer) changelog text files for CHK publishing.
- **Package matrix**: decide which OS/arch artifacts to ship this cycle. Minimum recommendation is macOS (DMG), Windows (EXE), Linux desktop/server (DEB + RPM), and Flatpak if maintained.
- **Environment validation**: run smoke tests on each target OS using `build/jpackage/Crypta`, `build/distributions/`, or the staged Flatpak bundle. Ensure the installers launch and locate `cryptad-dist/` correctly.
- **Dependency review**: verify updater metadata and package checksums are consistent with produced artifacts.

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

## Production Rollout
- Publish descriptor and artifacts to the production USK.
- Announce the release with links to installers, release notes, and any manual install guidance.
- Monitor:
  - Node logs for `[CoreUpdater] progress` and `Download Completed` entries.
  - Support channels for installer/store issues.
  - Plugin releases remain on their existing USKs; coordinate scheduling if releasing simultaneously.

## Emergency Procedures
- **Hotfix**: bump build number, rebuild, generate new descriptor, and publish to `info/<BUILD_N+1>`. Nodes will surface the newer package immediately.
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
- `CoreActionToadlet`: handles `/core-update/` POST actions (download, install, open store) and surfaces status transitions.
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
export VERSION_STRING="$BUILD_N"               # or semantic tag if desired
export RELEASE_PAGE="https://crypta.network/releases/$BUILD_N"
```

### 1) Build Artifacts
```bash
./gradlew clean build
ls -lh build/distributions/
```
Confirm presence of:
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

### 6) Promote to Production
```bash
fcpput -p reboot -r 1 -g "${PROD_USK}${BUILD_N}" core-info.json
```
Retain the descriptor and package CHKs in the release record.

### 7) Post-release Checklist
- Update the public release page and announcement channels.
- Monitor `[CoreUpdater] progress` logs across canary nodes.
- Prepare fallback plan (revocation message, follow-up descriptor) in case regressions surface.

### 8) Emergency Actions
```bash
# Pause downloads network-wide
echo "Emergency: pause ${BUILD_N}. Investigating installer regressions." | \
  fcpput -p reboot -r 1 -g "${REVOKE_SSK}"
```
To supersede a bad release, craft a new descriptor with corrected `packages` and publish to the next edition number.

---
Keep this runbook synchronized with future CoreUpdater/AppEnv changes. Update references whenever package selection logic or descriptor schema evolves.
