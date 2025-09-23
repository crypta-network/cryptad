Place OS-specific PNGs for the launcher Dock/window icon here:
 - macOS: `network/crypta/launcher/crypta-launcher-icon-macos.png`
 - Windows: `network/crypta/launcher/crypta-launcher-icon-windows.png`

Recommended sizes: 256x256 or 512x512 with transparency.

At runtime, the launcher loads the OS-specific resource above. On other OSes, it
falls back to the macOS icon if present. When running from source without
resources, it falls back to `docs/images/crypta_logo.png`.
