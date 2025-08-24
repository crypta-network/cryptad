# JReleaser Packaging (Snap)

This folder contains JReleaser configuration and helpers for packaging the Crypta
reference daemon as a Snap. It assumes the Gradle distribution already assembles
an executable layout under `bin/` with all runtime jars under `lib/`.

Key files
- `tools/packaging/jreleaser/jreleaser.yml` — main JReleaser config.
- `src/jreleaser/distributions/cryptad/snap/snap/snapcraft.yaml.tpl` — Snapcraft
  template used by JReleaser (Java 21, fixes launcher permissions).
- `tools/packaging/jreleaser/snapcraft-exported-login` — placeholder for a
  Snap Store exported login used by JReleaser (replace with a real export when
  publishing).
- Output staging: `out/jreleaser/prepare/cryptad/snap/` and
  `out/jreleaser/package/cryptad/snap/`.

## Prerequisites

- Java 21+ and Gradle (repo already configured).
- JReleaser CLI (1.19+): `jreleaser --version`.
- Snapcraft:
  - Linux: `sudo snap install snapcraft --classic`.
  - macOS: `brew install snapcraft multipass`; then authenticate Multipass once:
    `multipass authenticate`.

Note (macOS): Snapcraft runs in a Multipass VM. If you see permission issues
writing logs under your user Library, run commands from the repo root with
`HOME=$(pwd)` to keep logs inside the repo, or build fully inside a VM (see below).

## Build the Gradle distribution

This produces the tarball JReleaser/Snapcraft use as input:

```
./gradlew distTarCryptad
```

Result: `build/distributions/cryptad-dist-<version>.tgz` (version is taken from
`build.gradle.kts`).

## JReleaser config basics

- Config file: `tools/packaging/jreleaser/jreleaser.yml`.
- Distribution: `JAVA_BINARY` named `cryptad`, executable `bin/cryptad`.
- Packager: Snap (core22, classic confinement, Java 21).
- Template is overridden to:
  - Use `openjdk-21-jre-headless` as stage-package.
  - Set `JAVA_HOME` to `$SNAP/usr/lib/jvm/java-21-openjdk-$SNAP_ARCH`.
  - Force `bin/cryptad` to be world-readable/executable during build with
    `override-build` (fixes Snap validation).
- For CLI consistency, use equals-style flags, e.g. `--config-file=...`.

JReleaser requires a release provider set; we keep GitHub enabled but use a dummy
secret locally. Set one of:

- Environment variable: `JRELEASER_GITHUB_TOKEN=dummy`
- Or disable on the CLI: `--set-property release.github.enabled=false`

Snap Store login (for publishing):
- JReleaser’s Snap packager requires an exported Snap Store login file when
  active. A placeholder lives at `tools/packaging/jreleaser/snapcraft-exported-login`.
- Replace it with a real export when you plan to publish:
  `snapcraft export-login --snaps cryptad --channels stable tools/packaging/jreleaser/snapcraft-exported-login`.

## Linux: build Snap with JReleaser

1) Prepare Snapcraft project (generates `snapcraft.yaml` and staging files):

```
JRELEASER_GITHUB_TOKEN=dummy \
  jreleaser prepare \
  --basedir=. \
  --config-file=tools/packaging/jreleaser/jreleaser.yml \
  --packager=snap \
  --distribution=cryptad
```

2) Ensure the input tarball is alongside `snapcraft.yaml` (required because
   `source: cryptad-dist-<version>.tgz` is a local path in the template):

```
cp build/distributions/cryptad-dist-<version>.tgz out/jreleaser/prepare/cryptad/snap/
```

3) Package:

```
JRELEASER_GITHUB_TOKEN=dummy \
  jreleaser package \
  --basedir=. \
  --config-file=tools/packaging/jreleaser/jreleaser.yml \
  --packager=snap \
  --distribution=cryptad
```

Result: `out/jreleaser/package/cryptad/snap/cryptad_<version>_amd64.snap` (on
x86_64) or `_arm64.snap` on ARM.

## macOS: build via Multipass VM (recommended)

On macOS, Snapcraft uses Multipass. You can either let JReleaser invoke
Snapcraft (requires `multipass authenticate`) or build fully inside a VM.

Example flow using a VM named `cryptad-snap` (Ubuntu 22.04):

1) Create/ensure a VM and install Snapcraft once:

```
multipass launch 22.04 --name cryptad-snap --cpus 2 --memory 4G --disk 16G
multipass exec cryptad-snap -- sudo snap install snapcraft --classic
multipass authenticate
```

2) Prepare on host and copy the project into the VM:

```
./gradlew distTarCryptad
JRELEASER_GITHUB_TOKEN=dummy \
  jreleaser prepare \
  --basedir=. \
  --config-file=tools/packaging/jreleaser/jreleaser.yml \
  --packager=snap \
  --distribution=cryptad
cp build/distributions/cryptad-dist-<version>.tgz out/jreleaser/prepare/cryptad/snap/

multipass exec cryptad-snap -- bash -lc 'rm -rf ~/cryptad-snap && mkdir -p ~/cryptad-snap'
multipass transfer --recursive out/jreleaser/prepare/cryptad/snap/. cryptad-snap:/home/ubuntu/cryptad-snap/
```

3) Build inside the VM shell:

```
multipass exec cryptad-snap -- bash -lc 'cd ~/cryptad-snap && snapcraft pack --destructive-mode'
```

4) Copy the `.snap` back to the host (optional):

```
mkdir -p out/jreleaser/package/cryptad/snap
multipass transfer cryptad-snap:/home/ubuntu/cryptad-snap/cryptad_<version>_arm64.snap \
  out/jreleaser/package/cryptad/snap/
```

## Troubleshooting

- Missing Multipass auth (macOS):
  - Error: `The client is not authenticated with the Multipass service.`
  - Fix: `multipass authenticate` (once) then rerun.

- Permission error writing Snapcraft logs (macOS):
  - If Snapcraft can’t write to `~/Library/Logs/snapcraft`, run commands with
    `HOME=$(pwd)` from the repo root, or build inside the VM.

- Launcher permissions fail Snap validation:
  - Error: `"bin/cryptad" should be world-readable and executable`.
  - Fixed by template `override-build` (chmod 0755) and by Gradle setting
    executable permissions when creating the launcher.

- JReleaser complains about release provider:
  - Set `JRELEASER_GITHUB_TOKEN=dummy`, or pass
    `--set-property=release.github.enabled=false` on the command.

## Install and test the Snap

On Ubuntu test boxes:

```
sudo snap install --dangerous cryptad_<version>_<arch>.snap
```

The snap uses classic confinement. Adjust to `strict` (with the necessary plugs)
if you plan to publish to the Snap Store.
