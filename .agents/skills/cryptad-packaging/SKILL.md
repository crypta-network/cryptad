---
name: cryptad-packaging
description: "Build and troubleshoot distributions and installers, including Stable 1.0 deterministic RC archives, exact-byte GA promotion, and built-once maintenance/hotfix packages (assembleCryptadDist, jpackage, Windows wrapper assets, Flatpak, and Linux DEB/RPM behavior)."
metadata:
  area: packaging
  domain: cryptad
---

## When to use
Use this skill when working on:
- Distribution layout under `build/cryptad-dist`
- Archive tasks (`distZipCryptad`, `distTarCryptad`, `distJlinkCryptad`)
- jpackage app images/installers
- Linux installer behavior (DEB/RPM), systemd service, desktop integration
- Flatpak build and packaging files
- Windows wrapper asset sourcing/pinning
- Stable RC deterministic product/archive identity and no-rebuild GA packaging

## Ownership in the partial multi-project build
- Packaging remains root-owned.
- The root project `:cryptad` still owns `buildJar`, `assembleCryptadDist`, `dist*`, `run`,
  `runLauncher`, and jpackage tasks.
- Current contributing leaf modules are `:foundation-support`, `:foundation-store`,
  `:foundation-store-contracts`, `:foundation-crypto-keys`, `:interop-wire`,
  `:foundation-config`, `:foundation-fs`, `:foundation-compat`, `:kernel-content`,
  `:kernel-transport`, `:kernel-routing`, `:runtime-spi`, `:platform-api`,
  `:platform-apphost`, `:platform-app-ui`, `:platform-appvault`, `:platform-appdist`,
  `:platform-appcatalog`, `:platform-trustgraph`, `:platform-design-system`,
  `:platform-devtools`, `:platform-sdk-js`, `:platform-web-shell`, `:runtime-alerts`,
  `:runtime-node`, `:adapter-fcp`,
  `:bridge-fcp-runtime`, `:bridge-http-runtime`, `:adapter-http-legacy-admin`,
  `:adapter-http-legacy-browse`, `:thirdparty-onion`,
  `:thirdparty-legacy`, and `:launcher-desktop`.
- Extracted leaf modules contribute jars and resources through the root runtime classpath.
- `:foundation-support` and `:foundation-store-contracts` contribute shared runtime classes via
  their leaf JARs like the other extracted modules.
- `:foundation-crypto-keys` and `:foundation-store` contribute the extracted crypto/key/store
  runtime classes through their leaf JARs.
- `:interop-wire` contributes the extracted message/schema/version/probe nucleus and serializer
  classes through its leaf JAR.
- `:foundation-config` contributes the config/l10n code and main l10n resources via its leaf JAR
  and re-exports `:foundation-support` and `:foundation-fs` where public APIs expose those types.
- The `:runtime-spi` JAR is packaged like the other leaf artifacts; packaging still produces one
  daemon distribution rooted at `:cryptad`.
- The `:platform-api` JAR contributes the transport-neutral Platform API v1 surface, compatibility
  contract, app-vault route handlers, generated app-document inserts, bounded content fetch,
  shared app-network budget service/store, durable content subscriptions, durable app data,
  app-data backup/restore routes, app-service dependency graph/grant-bundle routes, Trust Graph
  Local RC route handlers, and app-update lifecycle/scheduler coordination, and the
  `:platform-apphost` JAR contributes the transport-neutral local AppHost core, sandbox-provider
  selection, and durable bundle rollback used by that API.
- The `:platform-app-ui` JAR contributes app-owned static UI route/origin helpers used by the
  legacy HTTP admin adapter to serve isolated per-app loopback origins and the `/apps/{appId}/`
  compatibility fallback.
- The `:platform-appvault` JAR contributes app secret and identity vault records, local wrapping-key
  provider, grant metadata, and audit/redaction value types used by Platform API app/vault routes.
- The `:platform-appdist` JAR contributes signed local app bundle digest, signature, verifier,
  trusted-key, packager, and distribution-tool classes used by first-party app tasks, developer
  tooling, and AppHost validation.
- The `:platform-appcatalog` JAR contributes signed catalog source parsing, catalog writing,
  verification, Crypta catalog source fetching, app-store/API compatibility metadata parsing,
  independent app-review receipt trust metadata, catalog security advisory/denylist policy,
  artifact download, safe ZIP extraction, and verified staging support.
- The `:platform-trustgraph` JAR contributes local Trust Graph Local RC statement parsing,
  canonicalization, verification, process-local store/anchor behavior, lifecycle/status records,
  and deterministic scoring used by Platform API trust routes.
- The `:platform-design-system` JAR contributes canonical local static app UI assets and helper
  APIs used by first-party app staging and the standalone developer CLI. It is packaged as a normal
  leaf artifact but the CSS/JS bytes are copied into app bundles, not loaded from a daemon-hosted
  CDN.
- The `:platform-devtools` application builds the standalone `crypta-app` developer CLI
  distribution with its own `installDist` output, including scaffold, validation, signing,
  packaging, mock dev server, offline test, catalog, review, developer-key, and publication-plan
  helpers. It is developer tooling, not a daemon entrypoint inside `build/cryptad-dist`.
- The `:platform-sdk-js` JAR contributes the browser SDK resource staged into first-party static
  app bundles and loaded by app-owned UIs on isolated loopback origins or the `/apps/{appId}/`
  fallback.
- The `:platform-web-shell` JAR contributes the browser-facing node-management shell HTML, CSS,
  JavaScript, and bootstrap resources that the legacy HTTP adapter mounts at `/app/node/`,
  including app-service dependency/grant-bundle review, operator app-data backup/restore controls,
  and explicit legacy security/diagnostic fallback actions.
- The `:runtime-alerts` JAR contributes the detached alert/feed model subset, including the
  `UserAlertSurface` consumed by the legacy HTTP/admin shell.
- The `:runtime-node` JAR now carries a large extracted daemon runtime/node/client/support subset
  and participates in the root runtime classpath and packaged distribution like the other leaf
  artifacts.
- The `:adapter-fcp` JAR carries the extracted FCP adapter code, including the deterministic
  unsupported-command handler for old plugin FCP command names. It must not package a restored
  plugin runtime.
- The `:bridge-fcp-runtime` JAR carries the concrete runtime-binding
  `network.crypta.clients.fcp.bridge` implementations.
- The `:adapter-http-legacy-admin` JAR carries the shared legacy HTTP shell/admin classes plus the
  matching `network/crypta/clients/http/**` resources. Static files and templates now ship from
  that leaf JAR on the runtime classpath, so packaged/runtime code must treat them as classpath
  resources rather than plain files. This leaf also hosts the current `/api/v1/` bridge for
  `:platform-api`, the `/app/node/` bridge for `:platform-web-shell`, and the per-app loopback
  origin server used by isolated static app UIs, plus legacy-admin retirement policy, Wave 5
  final-surface metadata, and explicit retained emergency fallback routes.
- The `:adapter-http-legacy-browse` JAR carries the concrete legacy browse/FProxy classes.
- The `:bridge-http-runtime` JAR carries the concrete `network.crypta.clients.http.bridge`
  runtime-binding implementations plus the legacy HTTP `network.crypta.clients.http.geoip`
  helper package.
- Packaging does not have separate entrypoints per leaf project; it still assembles a single daemon
  artifact and distribution layout from the root build.
- First-party app projects such as `:apps:queue-manager`, `:apps:publisher`,
  `:apps:site-publisher`, `:apps:profile-publisher`, `:apps:social-inbox`,
  `:apps:feed-reader`, and `:apps:trust-graph` provide staged app bundles through their
  `stageApp`, `signApp`, and `verifyApp` tasks. Those bundles are release artifacts and AppHost
  install inputs; they are not daemon entrypoints inside `build/cryptad-dist`.
  Their static UI staging copies the current `:platform-sdk-js` browser resource and canonical
  `:platform-design-system` assets into each bundle's `static/` assets.

## Distributions and Windows wrapper sources
- `assembleCryptadDist` creates a portable layout under `build/cryptad-dist` with `bin/`, `lib/`, and `conf/`.
  - Non-Windows wrapper files come from the upstream Tanuki delta pack.
  - Windows x86_64/arm64 wrapper exe/DLL are fetched from the newest GitHub release of `crypta-network/wrapper-windows-build`.

### Override points (optional)
- `-PwrapperWinApiUrl=<api-url>` to pin a specific release API.
- `-PwrapperWinAmd64Url=<asset-url>` / `-PwrapperWinArm64Url=<asset-url>` to force asset URLs.

### Archives
- `distZipCryptad` / `distTarCryptad` → `build/distributions/cryptad-v<version>.(zip|tar.gz)`
- `distJlinkCryptad` → `build/distributions/cryptad-jlink-v<version>.(zip|tar.gz)`
- Both include Windows launchers and binaries.
- These general Gradle archive tasks normalize member order, timestamps, ownership, modes, and
  gzip/ZIP metadata inside the Java 25 Gradle build. They do not require Python; the Python release
  certification command independently verifies the resulting archive bytes.
- Archive modes come only from deterministic member-path roles, never host execute-access checks:
  ordinary files are `0644`, directories are `0755`, and only Unix/JRE launchers, jlink helper
  executables, and the shipped wrapper native libraries receive `0755`.
- The Python maintenance archive rewriter and independent hygiene gate must apply that same
  member-path policy. They must not preserve a source archive's execute bits or accept both `0644`
  and `0755` indiscriminately for regular files.
- Treat canonical member names as extraction identities. Reject raw `.` or empty components,
  trailing-slash file/directory aliases, duplicate canonical paths at every nested level, POSIX,
  drive-qualified, and UNC absolute paths, escaping symlink targets, and special files. Require
  closed gzip headers, only necessary canonical PAX extensions, empty ZIP archive/member comments
  and extra fields, and explicit Unix type/mode metadata for every ZIP member. Bound a nested
  member before reading or decompressing its bytes.

## Stable 1.0 RC and GA archives

- Use `python3 tools/release-certification/certify.py stable-rc --manifest <copied-manifest>` as the
  canonical Stable RC packaging boundary. It consumes the production pipeline output and writes
  `crypta-stable-1.0-rc-<build>-product.tar.gz` plus the outer
  `cryptad-stable-1.0-rc-<build>.tar.gz`, checksums, provenance, and freeze records.
- The deterministic product archive is the immutable payload selected for GA. Its tar/gzip
  ordering, timestamps, uid/gid, names, modes, members, and content digests are part of the freeze.
  Do not reproduce it by rerunning Gradle, extracting/repacking it, changing an RC marker, or
  generating a same-version replacement.
- `stable-ga` copies or references the exact frozen product and verifies its digest before and after
  GA metadata generation. GA labels, promotion records, notes, checksums, provenance, and the
  maintenance baseline stay outside the immutable product payload.
- If a platform package, launcher, migration command, catalog/app member, file mode, or any other
  payload member must change after freeze, stop promotion and complete a new authorized RC refreeze.
  A GA waiver cannot hide payload drift.
- Keep tests and ordinary PR/local runs side-effect-free. They may validate deterministic fixtures
  and mocked publication receipts, but they must not create tags, Releases, public catalog updates,
  update descriptors, or network inserts.

## Installers (jpackage)
We ship Gradle tasks that build a desktop app image and (on macOS/Linux) native installers via `jpackage`.

### Tasks
- `./gradlew build`
  - Builds the jpackage app image and enriches it with `cryptad-dist`.
  - On Linux/macOS, also builds native installers (`.deb`/`.rpm` on Linux when tools exist; `.dmg` on macOS).
  - Missing tools cause installer tasks to be skipped, not failed.
- `./gradlew jpackageImageCryptad`
  - Builds only the app image under `build/jpackage/`.
- `./gradlew jpackageInstallerCryptad`
  - Builds a native installer for the current OS (macOS: `.dmg`; Linux: `.deb` or `.rpm` when tools exist).
  - Not available on Windows by default.

### Linux installer type override
- Pass `-PlinuxInstaller=<deb|rpm>` (or set env `CRYPTA_LINUX_INSTALLER`) to force installer type.
- When both are available, RPM is preferred by default.

### Metadata and entrypoint
- Name: `Crypta`, Vendor: `crypta.network`, App ID: `network.crypta.cryptad`
- Main entry: `network.crypta.launcher.Launcher`
- Versioning: jpackage requires numeric `--app-version`. Linux and macOS use the project version
  integer. Windows maps that same integer to the MSI-safe technical form `1.0.<build>` at the app
  image, launcher-configuration, and EXE stages; this does not change Cryptad's project version.

### Icons and resources
- macOS: `src/jpackage/macos/cryptad.icns`
- Windows: `src/jpackage/windows/cryptad.ico`
- Linux: `src/jpackage/linux/cryptad.png`

### Troubleshooting (macOS)
- If double-click does nothing, run `Contents/MacOS/Crypta` in Terminal to see logs.
- Clear quarantine on unsigned builds:
  - `xattr -dr com.apple.quarantine build/jpackage/Crypta.app`
- Verify:
  - `spctl --assess -vv build/jpackage/Crypta.app`

### Troubleshooting (Windows)
- Launch from a console:
  - `build\jpackage\Crypta\Crypta.exe`
- Verify key paths exist:
  - `build\jpackage\Crypta\app\cryptad-dist\lib\cryptad.jar`
  - `build\jpackage\Crypta\app\Crypta.cfg`
- Verify `Crypta.cfg` includes:
  - `app.mainclass=network.crypta.launcher.Launcher`
  - one or more `app.classpath=$APPDIR/cryptad-dist/lib/*.jar` lines

## Linux installer behavior (DEB/RPM)
- Install location: app image under `/opt/cryptad/Crypta` (some hosts may lowercase it; scripts auto-detect and normalize).
- Desktop vs server detection:
  - Considered “desktop” only when a display manager service exists and is enabled/active; otherwise checks session files.
- Conditional actions:
  - Server: install systemd unit at `/etc/systemd/system/cryptad.service`, daemon-reload, enable (do not auto-start).
  - Desktop: install `.desktop` entry under `/usr/share/applications/crypta.desktop`, refresh menus/caches when tools exist.

### System account behavior
- Creates `cryptad` system user (home `/var/lib/cryptad`, shell `nologin`) when missing.
- Creates explicit `cryptad` system group and sets it as primary group.

### Script library
Common installer logic lives in `src/jpackage/linux/crypta-common.sh` (installed under `lib/` in the app image).
- Do not duplicate `is_desktop`, `ensure_user`, or service control snippets elsewhere.

### Headless helper for core package installs
DEB/RPM install:
- `cryptad-core-install@.service` + `cryptad-core-install.sh`
- Validates paths under `/var/lib/cryptad/updates/core` and performs installs via PackageKit/native tools.
- Polkit rule restricts starting only this unit and only to the `cryptad` user.

### Debugging installers (Linux)
- Set `CRYPTA_DEBUG=1` to enable verbose logging from maintainer scripts.
- Logs append to `/var/log/crypta-installer.log`.
- If dock icon is generic, verify GNOME association with `xprop WM_CLASS` and confirm `.desktop` keys.

### Uninstall semantics
- Service cleanup disables/stops safely and removes unit; does `daemon-reload`.
- Desktop cleanup removes `.desktop` entry and refreshes caches when tools exist.
- Data/account retention: `cryptad` user/group and `/var/lib/cryptad` remain by default to avoid data loss.

## Flatpak build (local dev)
Requirements: `flatpak`, `org.freedesktop.Platform//24.08`, `org.freedesktop.Sdk//24.08`.

Typical flow:
```bash
./gradlew buildJar
./gradlew distJlinkCryptad
cp -f "build/distributions/cryptad-jlink-v$(./gradlew -q printVersion).tar.gz" tools/flatpak/local/cryptad-jlink-v1.tar.gz
rm -rf builddir repo .flatpak-builder
flatpak run org.flatpak.Builder --force-clean --user --arch=$(flatpak --default-arch) \
  --install-deps-from=flathub builddir tools/flatpak/cryptad.yaml
flatpak build-export --arch=$(flatpak --default-arch) repo builddir v1
flatpak build-bundle repo cryptad-v1-$( [ $(flatpak --default-arch) = aarch64 ] && echo arm64 || echo amd64 ).flatpak \
  network.crypta.cryptad v1 --arch=$(flatpak --default-arch)
flatpak --user install -y ./cryptad-v1-*.flatpak
flatpak run network.crypta.cryptad//v1
```

Notes:
- Flatpak packaging files live under `tools/flatpak/`.
- Spotless is scoped to `src/**`; `.spotlessignore` at repo root prevents scanning Flatpak scratch dirs.

## Stable 1.0 maintenance candidate packaging

Unlike GA promotion, a later Stable 1.0 release introduces new bytes. Build and freeze the product
archive and all declared packages exactly once through `stable-maintenance`; normalize and inspect
archives with the established RC rules, then bind every filename, size, mode, digest, signature,
source commit, and installer result into candidate checksums and provenance. Any changed byte after
authorization requires a new candidate and authorization.

After each protected package build, require `HEAD` to remain the exact candidate commit and reject
any staged or unstaged change to a tracked path before producer metadata or attestations are
created. Ignore untracked Gradle outputs for that source-drift decision. The aggregate freeze must
also prove that the exact `release.sourceCommit` in the authenticated latest predecessor baseline
is an ancestor of the candidate; branch-base ancestry alone is insufficient.

The normal matrix covers the portable distribution and supported Linux DEB/RPM, macOS DMG, and
Windows EXE targets. A local Linux or macOS run must not claim that target passed. Dispatch the
checked-in protected Windows producer at the exact candidate commit; it runs
`jpackageInstallerWindowsExeCryptad` once on the hosted Windows runner, Authenticode-signs and
verifies the final amd64 PE, rechecks tracked source state, and attests both the EXE and its receipt.
The app-image prerequisite, rewritten launcher configuration, and EXE task all map integer build
`<build>` to MSI ProductVersion `1.0.<build>` so the release number uses MSI's 16-bit build
component; protected Windows releases fail closed above build 65535.
The hosted Ubuntu maintenance producer must install the distribution `rpm` package and verify both
`rpm` and `rpmbuild` before invoking `jpackageInstallerLinuxAll`; the package task intentionally
skips RPM creation when that external toolchain is absent.
Every security hotfix declares a nonempty affected-package subset. A full-matrix hotfix records
`unaffectedPackageProofStatus=not-applicable`; a narrowed matrix must equal the affected set
exactly and records `unaffectedPackageProofStatus=pass` only when advisory evidence proves the
omitted targets do not ship the vulnerable code. A narrowed hotfix without a DMG must not attach
the authenticated macOS notarization receipt to any selected non-DMG package.

The protected maintenance package producer uses keyless GitHub/Sigstore attestations to
cryptographically sign every exact staged DEB, RPM, portable archive, and DMG without changing its
bytes. It must immediately verify each subject against the exact maintenance workflow and source
commit, emit a separate redaction-safe per-asset verification receipt, and upload those receipts
with the producer artifact. The freeze boundary independently repeats `gh attestation verify` and
uses the matching per-asset receipt digest for `signingReceiptDigest`; a generic producer receipt,
checksum, `productionSigning` Boolean, or build attestation cannot stand in for this check. This
path uses the workflow's OIDC and attestation permissions and has no private-key or passphrase
input. Never add signing secret material to the workflow command line, logs, receipts, or retained
artifacts.

For the protected macOS maintenance freeze, import the reviewed Developer ID Application identity
into an ephemeral keychain and run `jpackageInstallerCryptad` with
`-PmacSigningKeyUserName=<exact identity>`. After enrichment has copied `cryptad-dist` and rewritten
the launcher configuration, that opt-in property makes `signFinalMacAppImageCryptad` replace the
jpackage signatures in explicit inside-out order and sign the app root last. Preserve the existing
identifier and entitlement metadata on the jpackage JVM, framework, and app-root code while
switching to Developer ID `codesign --options runtime --timestamp`; fail closed if that metadata
is absent. Select nested signable files by their thin/universal Mach-O magic, not by POSIX execute
bits or filename suffixes: the enriched portable distribution also contains executable Linux ELF
and Windows PE files, which are app resources on macOS and must be covered only by the final app
root seal. Sign recognized nested native bundles after their contained Mach-O code. Do not use
recursive `--deep` signing to replace nested signatures. Do not attempt JDK
25's rejected
`--type app-image --app-image` combination. The installer task runs only after that boundary and
retains jpackage's mac signing flags, but those flags do not prove that jpackage signed the outer
DMG container. Ordinary local packaging remains unchanged when the property is absent. Explicitly
Developer-ID-sign and verify the exact DMG after jpackage and before notarization submission, then
staple and verify those resulting bytes again before computing the frozen digest and copying the
DMG into the frozen asset set. Also verify the app, stapling ticket, and Gatekeeper assessment. Do
not freeze a DMG based only on declared signing metadata.

The workflow variable is `CRYPTAD_MACOS_DEVELOPER_ID_APPLICATION`. Keep the P12 and notary values
only in the evidence environment secrets
`CRYPTAD_MACOS_DEVELOPER_ID_APPLICATION_P12_BASE64`,
`CRYPTAD_MACOS_DEVELOPER_ID_APPLICATION_P12_PASSWORD`,
`CRYPTAD_MACOS_NOTARY_APPLE_ID`, `CRYPTAD_MACOS_NOTARY_APP_PASSWORD`, and
`CRYPTAD_MACOS_NOTARY_TEAM_ID`. Never place those values in Gradle properties files, workflow
inputs, command output, receipts, or retained artifacts.

Publication copies the frozen assets; it never reruns Gradle, jpackage, signing, notarization, or
archive creation. Follow `docs/stable-1.0-maintenance-release-and-hotfix-path.md`.

Focused cross-platform argument checks are:

```bash
./gradlew verifyMacAppImageSigningArguments verifyWindowsExeInstallerArguments
```

When portable archive logic changes, build the affected `distZipCryptad`, `distTarCryptad`, and
`distJlinkCryptad` tasks, then run
`python3 tools/release-certification/certify.py stable-maintenance --self-test` so the independent
Python hygiene rules are exercised against the Java normalizer contract. These checks do not
replace protected signing, notarization, multi-OS packaging, or publication.
