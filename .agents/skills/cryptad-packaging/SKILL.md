---
name: cryptad-packaging
description: "Build and troubleshoot distributions and installers (assembleCryptadDist, jpackage, Windows wrapper assets, Flatpak, Linux DEB/RPM behavior)."
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
- Versioning: jpackage requires numeric `--app-version`; we use the project version integer.

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
