# Legacy plugin freeze policy

This policy defines the production RC freeze boundary for Cryptad's removed legacy plugin system.

## Scope

The policy applies to the old in-process plugin runtime, plugin-manager APIs, plugin toadlets,
legacy plugin ABI classes, and historical FCP plugin commands. It does not apply to Gradle
`plugins {}` blocks, app-platform bundles, signed catalogs, app-service providers, or historical
archive text under `docs/legacy/**`.

## Freeze requirements

Cryptad's production RC app ecosystem uses the app platform as the only forward path for
plugin-like functionality.

The node must preserve these requirements:

- Do not add a new in-core plugin runtime.
- Do not add new daemon-core plugin APIs.
- Do not restore `network.crypta.pluginmanager`.
- Do not restore old plugin ABI classes such as `PluginManager`, `PluginRespirator`, or
  `PluginTalker`.
- Do not restore plugin toadlets or old plugin admin pages.
- Do not restore old FCP plugin command compatibility.
- Keep old FCP plugin command names mapped only to deterministic unsupported responses.
- Do not add compatibility shims for WebOfTrust, Freetalk, Sone, Freemail, or other old plugin
  APIs.

`adapter-fcp/src/main/java/network/crypta/clients/fcp/UnsupportedPluginMessage.java` is the narrow
compatibility boundary for historical FCP plugin command names. It may keep the protocol stream
synchronized and return a deterministic unsupported error. It must not execute plugin code, load
plugin state, call app-platform services on behalf of the old command, or emulate old plugin APIs.

## Migration path

Replacement work should use out-of-process app/platform mechanisms:

| Legacy plugin concern | Replacement mechanism |
| --- | --- |
| Plugin UI | App-owned isolated UI, Web Shell entry points where appropriate, and the browser SDK |
| Plugin distribution | Signed app bundles, signed catalogs, trusted review receipts, and catalog governance |
| Node interaction | Bounded Platform API routes with declared capabilities |
| Identity and private material | AppVault grants and bounded AppVault signing routes |
| Mutable app state | Durable app data namespaces and records |
| Content polling or follows | Budgeted USK content subscriptions |
| Trust annotations | Trust Graph Local RC plus operator-approved `trust.score` app-service grants |
| Cross-app local services | App-service descriptors, dependency bundles, operator approval, expiry, and revalidation |

The [legacy plugin migration guide](legacy-plugin-migration-guide.md) maps common old plugin
categories to those mechanisms.

## Historical material

Files under `docs/legacy/**` are historical reference material. They may mention old plugin
packages, release notes, CHKs, plugin names, or old maintenance workflows. Those references are not
current implementation commitments and must not be used as justification to reintroduce daemon-core
plugin behavior.

## Certification evidence

Release certification should include `legacy-plugin.freeze-policy` evidence with source-surface
checks. The evidence should prove:

- `docs/plugin-system.md` and this policy declare the removed/frozen status.
- The migration guide links to the freeze policy and points to the app-platform path.
- No current Java source reintroduces `network.crypta.pluginmanager` or old plugin runtime classes.
- `UnsupportedPluginMessage` remains the only runtime handler for old FCP plugin command names.
- `FCPMessage` maps old plugin command names to the unsupported handler instead of plugin
  execution.
- App-platform docs preserve the non-goals: not full Web of Trust, not old WebOfTrust plugin
  compatibility, not Freetalk/Sone/Freemail compatibility, not encrypted mail transport, and not a
  daemon-core social or mail protocol, generic crawler, or unbounded subscription polling.

Evidence must remain redacted. It should record booleans, route ids, filenames, class names, and
bounded status strings only. It must not include private insert URIs, tokens, request bodies, form
passwords, raw fetched content, raw app data, raw diagnostic output, raw signatures, private keys,
or absolute local paths.
