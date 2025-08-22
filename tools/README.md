# Tools

This directory contains official, optional utilities and packaging assets that support development, ops, and distribution. These are not part of the core daemon runtime.

- generator: Client-side utility code and assets (GWT/JS) historically used to generate/update web UI helpers. See the [generator README](generator/README.md) for details and usage.
- stats: Network size and churn probe utilities (scripts + small Java tool) to sample a local node, summarize data, and plot/upload graphs. See the [stats README](stats/README.md).
- packaging/debian: Debian/Ubuntu packaging metadata and rules for building `.deb` packages (control, rules, maintainer scripts, defaults). Build Debian packages using debhelper from within `tools/packaging/debian` so paths like `debian/*` resolve correctly.

Notes
- These utilities may have external tool dependencies (e.g., Java, gnuplot, netcat, debhelper). Refer to each subdirectory’s README or scripts for specifics.
- Changes here should not affect the main build; keep versions and instructions in sub-readmes up to date.
