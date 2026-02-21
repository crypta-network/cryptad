# Plugin System Status

Last updated: 2026-02-20

The plugin runtime has been removed from the Cryptad node.

What this means:
- The `network.crypta.pluginmanager` package and plugin toadlets/FCP plugin commands are no longer implemented.
- Legacy FCP plugin command names are rejected with a deterministic unsupported-message response.
- Core update behavior remains package-based (`CoreUpdater`).

This document is intentionally short to avoid preserving outdated plugin-architecture guidance.
