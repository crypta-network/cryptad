# Tools

This directory contains official, optional utilities and packaging assets that support development, ops, and distribution. These are not part of the core daemon runtime.

- generator: Client-side utility code and assets (GWT/JS) historically used to generate/update web UI helpers. See the [generator README](generator/README.md) for details and usage.
- codex-docker: Tracked Codex Docker and Playwright remote-browser debugging stack. See the [codex-docker README](codex-docker/README.md).
- stats: Network size and churn probe utilities (scripts + small Java tool) to sample a local node, summarize data, and plot/upload graphs. See the [stats README](stats/README.md).
- packaging/debian: Debian/Ubuntu packaging metadata and rules for building `.deb` packages (control, rules, maintainer scripts, defaults). Build Debian packages using debhelper from within `tools/packaging/debian` so paths like `debian/*` resolve correctly.

## Flatpak Packaging (`tools/flatpak`)

This directory contains the Flatpak manifest and metadata used to build and test a sandboxed Crypta launcher on Linux desktops.

- Files:
  - `cryptad.yaml`: Flatpak manifest (uses the Freedesktop 24.08 runtime/SDK).
  - `cryptad.desktop`: Desktop entry for the launcher.
  - `network.crypta.cryptad.metainfo.xml`: AppStream metadata.
  - `cryptad-512.png`: App icon.
  - `local/`: Place the jlink tarball here before building (created locally; not tracked).

Quick build and run (requires `flatpak` and Freedesktop 24.08 runtime/SDK):

```bash
./gradlew buildJar
./gradlew distJlinkCryptad
mkdir -p tools/flatpak/local
cp -f build/distributions/cryptad-jlink-v1.tar.gz tools/flatpak/local/
rm -rf builddir repo .flatpak-builder
flatpak run org.flatpak.Builder --force-clean --user --arch=$(flatpak --default-arch) \
  --install-deps-from=flathub builddir tools/flatpak/cryptad.yaml
flatpak build-export --arch=$(flatpak --default-arch) repo builddir v1
flatpak build-bundle repo cryptad-v1-$( [ $(flatpak --default-arch) = aarch64 ] && echo arm64 || echo amd64 ).flatpak \
  network.crypta.cryptad v1 --arch=$(flatpak --default-arch)
flatpak --user install -y ./cryptad-v1-*.flatpak
flatpak run network.crypta.cryptad//v1
```

Notes
- The launcher inside Flatpak uses portal-based theme detection for dark/light mode and applies FlatLaf.
- We request D-Bus access to `org.freedesktop.portal.Desktop` for reading theme settings.
- The build creates temporary `builddir/`, `.flatpak-builder/`, and `repo/` directories at the repository root.

Notes
- These utilities may have external tool dependencies (e.g., Java, gnuplot, netcat, debhelper). Refer to each subdirectory’s README or scripts for specifics.
- Changes here should not affect the main build; keep versions and instructions in sub-readmes up to date.
