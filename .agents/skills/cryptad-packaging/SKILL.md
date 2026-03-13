---
name: cryptad-packaging
description: "Build and troubleshoot distributions and installers (assembleCryptadDist, jpackage, Windows wrapper assets, Flatpak, Linux DEB/RPM behavior)."
compatibility: opencode
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
- Extracted leaf modules contribute jars and resources through the root runtime classpath.
- Packaging does not have separate entrypoints per leaf project; it still assembles a single daemon
  artifact and distribution layout from the root build.

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
