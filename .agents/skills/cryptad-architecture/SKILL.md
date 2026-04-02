---
name: cryptad-architecture
description: "Navigate Cryptad’s module/package architecture, key subsystems, design patterns, security model, and versioning scheme."
compatibility: opencode
metadata:
  area: architecture
  domain: cryptad
---

## When to use
Use this skill when you need to:
- Find the right package/class for a change.
- Understand request routing, updates, plugins, or storage.
- Make changes that could affect wire compatibility or on-disk formats.

## Build/module layout (current)
- Cryptad now uses a partial multi-project Gradle build.
- The root project `:cryptad` remains the daemon/application project.
- The root project still owns `buildJar`, `run`, `runLauncher`, distribution/jpackage tasks, the
  strongly coupled core packages, and all tests.
- Leaf subprojects:
  - `:foundation-support` → the current stable generic subset of `network.crypta.support`,
    `network.crypta.support.api`, `network.crypta.support.io`,
    `network.crypta.support.compress`, `network.crypta.support.math`,
    `network.crypta.support.transport.ip`, and `network.crypta.support.http`, plus
    `network.crypta.io.AddressIdentifier`, `network.crypta.io.WritableToDataOutputStream`,
    `network.crypta.node.FSParseException`, `network.crypta.node.FastRunnable`,
    `network.crypta.node.SemiOrderedShutdownHook`, and `network.crypta.support.IllegalValueException`
  - `:foundation-store-contracts` → neutral `network.crypta.store` contracts
    `BlockMetadata`, `GetPubkey`, `StorableBlock`, plus the `network.crypta.store.alerts` seam
    (`StoreAlertSink`, `StoreMaintenanceAlertKind`, `StoreMaintenanceAlertSource`)
  - `:foundation-crypto-keys` → `network.crypta.crypt`, `network.crypta.keys`, plus
    `network.crypta.support.io.BucketTools` and
    `network.crypta.support.io.PrependLengthOutputStream`
  - `:foundation-store` → reusable `network.crypta.store` implementations plus
    `network.crypta.store.caching` and `network.crypta.store.saltedhash`
  - `:interop-wire` → the leaf-safe wire/message/schema/version/probe nucleus:
    selected `network.crypta.io.comm` types, `network.crypta.node.Version`,
    `network.crypta.node.probe.Error`, `network.crypta.node.probe.Type`, and
    `network.crypta.support.Serializer`
  - `:foundation-config` → `network.crypta.config`, `network.crypta.l10n`, the main l10n
    resources, and shared setup helpers such as `DatastoreSizingSupport`; public config APIs
    re-export `:foundation-support` and `:foundation-fs` where they expose shared types
  - `:foundation-fs` → `network.crypta.fs`
  - `:foundation-compat` → `network.crypta.compat`, including
    `network.crypta.compat.bandwidth`
  - `:kernel-content` → the compile-neutral phase-1 content slice across selected
    `network.crypta.client`, `network.crypta.client.events`,
    `network.crypta.client.filter`, `network.crypta.client.async.alerts`, and
    `network.crypta.support.MediaType`
  - `:runtime-spi` → `network.crypta.runtime.spi` (JDK-only runtime/config boundary)
  - `:runtime-node` → extracted daemon runtime body across the remaining cyclic/high-level
    `network.crypta.client` body, large `network.crypta.node` and `network.crypta.runtime.*`
    slices, `network.crypta.io.xfer`, and the remaining daemon-coupled
    `network.crypta.support` / `network.crypta.support.io` / `network.crypta.support.api` subset
  - `:adapter-fcp` → `network.crypta.clients.fcp`, including
    `network.crypta.clients.fcp.bridge`
  - `:adapter-http-legacy-admin` → the full current legacy `network.crypta.clients.http` tree
    plus matching `network/crypta/clients/http/**` main resources
  - `:thirdparty-onion` → `com.onionnetworks` plus `lib/fec.properties`
  - `:thirdparty-legacy` → `org.bitpedia`, `org.sevenzip`, `org.spaceroots`
  - `:launcher-desktop` → `network.crypta.launcher`, `com.jthemedetecor`, `oshi`, launcher
    resources
- The runtime boundary is split intentionally:
  - `:runtime-spi` exposes small JDK-only ports and immutable config DTOs.
  - `:runtime-node` now implements the daemon-backed ports across
    `network.crypta.runtime.core` and `network.crypta.runtime.admin`. The runtime nucleus lives in
    `network.crypta.runtime.core.LegacyRuntimePorts` plus core adapters such as
    `LegacyConfigPort`, `LegacyConnectivityPort`, `LegacyNodeInfoPort`, `LegacyPeerPort`,
    `LegacyRequestQueuePort`, `LegacySecurityLevelsPort`, and `LegacyCoreUpdateActionPort`.
    Page-oriented adapters such as `LegacyConnectionsPagePort`,
    `LegacyConnectionsSupportPort`, `LegacyDarknetConnectionsPort`,
    `LegacyDarknetMessagingPort`, `LegacyQueuePagePort`, `LegacyQueueMutationPort`,
    `LegacyQueueSupportPort`, `LegacyPageChromePort`, `LegacyDiagnosticPort`,
    `LegacyStatisticsPort`, `LegacyFirstTimeWizardPort`, `LegacyToadletSymlinkPort`,
    `LegacyWelcomePagePort`, and `LegacyWelcomeActionPort` now live in
    `network.crypta.runtime.admin`, supported by queue helper seams under
    `network.crypta.runtime.admin.queue` and `network.crypta.runtime.admin.queue.page`.
    Queue completion/download/insert bridges plus the remaining concrete FCP bridge
    implementations now live under `network.crypta.clients.fcp.bridge`.
  - The root project keeps application composition, packaging/runtime tasks, tests, tools, and
    root-local bridge selection in
    `network.crypta.runtime.bootstrap.DefaultNodeRuntimeBridgeFactories`.
- The daemon runtime body now spans extracted leaves plus a thin root composition layer:
  `:kernel-content` owns the compile-neutral phase-1 client/content slice, `:runtime-node` owns
  the remaining runtime/node/client/support body, `:adapter-fcp` owns the FCP adapter tree,
  `:adapter-http-legacy-admin` owns the legacy HTTP adapter tree and resources, and the root
  project keeps tests, packaging, tool entrypoints, and remaining composition glue.
- The wire split is intentionally narrow:
  `:interop-wire` owns the message/schema nucleus, while root keeps `MessageCore`,
  `MessageFilter`, `AsyncMessageFilterCallback`, `SlowAsyncMessageFilterCallback`,
  `PeerContext`, incoming-packet filters, socket handlers, and statistics collection.
  `network.crypta.io.comm.Message` now depends on the minimal `MessageSource` seam instead of
  directly on `PeerContext`.
- `:foundation-config` is the current home for all main `network.crypta.config` and
  `network.crypta.l10n` sources. Their unit tests still live in the root test tree and are run by
  the root project.
- Every extracted internal leaf relies on leaf-owned aggregated-output metadata at
  `<leaf>/gradle/owned-output-patterns.txt`. This is required even for structurally separate
  package/resource moves, because stale non-owner aggregated outputs from earlier builds or branch
  switches can still shadow leaf outputs while `buildJar` packages aggregated main outputs first.
- Update that metadata whenever a leaf starts owning additional main classes/resources that root
  used to compile/package. This applies to existing leaves such as `:foundation-support` and
  `:foundation-store-contracts` just as much as any future extraction.
- Root boundary tests now freeze the extracted layout. In particular,
  `RuntimeNodeKernelSplitPrepBoundaryTest`, `KernelContentBoundaryTest`, and
  `HttpLegacyAdminBoundaryTest` guard leaf ownership/import rules, and the runtime/kernel-content
  tests require `package-info.java` in every production package under those leaves.

## Architecture overview (by package)
### Core network layer (`network.crypta.node`)
- Node coordination: `Node.java`
- Peer management: `PeerNode`, `PeerManager`
- Network transport: `PacketSender`, `FNPPacketMangler`
- Request orchestration: `RequestStarter`, `RequestScheduler`
- Updates now bootstrap through `network.crypta.runtime.updater.NodeUpdateManager`

### Runtime orchestration packages (`network.crypta.runtime.*`)
- Startup/CLI/config bootstrap: `network.crypta.runtime.bootstrap`
  (`NodeStarter`, `NodeBootstrap`, `NodeCli`, `NodeConfigManager`, `LoggingConfigHandler`)
- Runtime SPI nucleus and daemon-backed core adapters: `network.crypta.runtime.core`
- Page-oriented admin/runtime adapters: `network.crypta.runtime.admin`
- Operator-facing alerts and alert-feed seams: `network.crypta.runtime.alerts`
- Endpoint bootstrap glue for FCP/HTTP/TMCI: `network.crypta.runtime.endpoints`
- Service coordination: `network.crypta.runtime.services`
- Core update subsystem: `network.crypta.runtime.updater`

### Content storage (`network.crypta.store`)
- Storage abstractions: `FreenetStore`
- CHK/SSK stores: `CHKStore`, `SSKStore`
- Caching: `SlashdotStore`
- `:foundation-store` now owns the reusable store implementations, cache layer, and salted-hash
  store code.
- Neutral contracts `BlockMetadata`, `GetPubkey`, and `StorableBlock` live in
  `:foundation-store-contracts`, along with the store-maintenance alert seam in
  `network.crypta.store.alerts`.
- Root-owned runtime/UI integration now lives in `network.crypta.runtime.alerts`, for example
  `UserAlertManagerStoreAlertSink`.

### Cryptography (`network.crypta.crypt`)
- Encryption: block cipher / AES streams
- Signatures: DSA/ECDSA
- Hashing: SHA-256 and others
- RNG: `RandomSource` / Yarrow
- This package now lives in `:foundation-crypto-keys`.

### Key management (`network.crypta.keys`)
- Client keys: `ClientCHK`, `ClientSSK`
- URIs: `FreenetURI`
- Updatable keys: USK
- This package now lives in `:foundation-crypto-keys`.

### Wire/message nucleus (`network.crypta.io.comm`, `network.crypta.node.Version`)
- `:interop-wire` owns the leaf-safe message/schema/address subset such as `Message`,
  `MessageType`, `Peer`, `FreenetInetAddress`, and related exceptions.
- `:interop-wire` also owns `network.crypta.node.Version`,
  `network.crypta.node.VersionParseException`, `network.crypta.node.probe.Error`,
  `network.crypta.node.probe.Type`, and `network.crypta.support.Serializer`.
- Root keeps transport-facing code such as `PeerContext`, `MessageCore`, filters, packet/socket
  handlers, and runtime helpers like `network.crypta.runtime.core.SSL`.

### Client APIs
- High-level client: `network.crypta.client`
  - `:kernel-content` now owns the compile-neutral phase-1 content slice: selected
    archive/value/helper classes, immutable event values, a conservative subset of filter
    helper/parser types, the full `network.crypta.client.async.alerts` seam, and
    `network.crypta.support.MediaType`.
  - `:runtime-node` still owns the cyclic async scheduler/request engine, high-level client APIs,
    and the remaining filter/archive surfaces that still depend on request scheduling or node
    internals.
  - The async client layer also retains client-local seams under
    `network.crypta.client.async.persistence` so runtime/FCP bridges can recover durable requests
    without owning those contracts.
- FCP: `network.crypta.clients.fcp`
  - This package now lives in `:adapter-fcp`.
  - Runtime-facing execution, randomness, lifecycle, transfer-policy, and config access now come
    through `RuntimePorts`.
  - `FcpRuntimeAdapters` preserves legacy FCP-local shapes such as `PriorityAwareExecutor` and
    `RandomSource` on top of the SPI.
  - Detached peer-management operations such as `ModifyPeer` now go through `RuntimePorts#peer()`.
  - Server bootstrap now flows through `FcpServerDependencies` and
    `CoreFcpServerDependenciesFactory`.
  - Package-local seams split the remaining daemon-backed work by concern:
    `FcpServerRuntimeSupport`, `FcpMessageRuntimeSupport`, `FcpFetchRuntimeSupport`, and
    `FcpInsertRuntimeSupport`.
  - Runtime-owned FCP seam types now live under `network.crypta.runtime.fcp` and
    `network.crypta.runtime.endpoints.fcp`, while concrete persistent-request services, queue
    adapters, alert-feed adapters, and endpoint-handle wrappers now live under
    `network.crypta.clients.fcp.bridge`.
- HTTP interface: `network.crypta.clients.http`
  - This package now lives in `:adapter-http-legacy-admin` together with the matching
    `network/crypta/clients/http/**` main resources such as `staticfiles/**` and `templates/**`.
  - The migrated management and shell slices no longer depend directly on live daemon peers or
    node-info exports for their core data flow.
  - `ConfigToadlet` now takes detached configuration export/update capabilities from
    `ConfigPort` through `ConfigToadletRuntimePorts`.
  - `ConnectionsToadlet`, `DarknetConnectionsToadlet`, `OpennetConnectionsToadlet`, and
    `DarknetAddRefToadlet` use detached ports such as `ConnectionsPagePort`,
    `ConnectionsSupportPort`, `PeerPort`, and `NodeInfoPort`.
  - `QueueToadlet` now acts as an HTTP adapter over `QueuePagePort`, `QueueDownloadPort`,
    `QueueInsertPort`, `QueueMutationPort`, `QueueSupportPort`, `QueueCompletionPort`,
    `TransferAccessPort`, `DarknetConnectionsPort`, and `DarknetMessagingPort`.
  - `SecurityLevelsToadlet` uses `SecurityLevelsPort` for detached page state, warning HTML, and
    master-password mutation flows.
  - `PageMaker` reads shared shell status through `PageChromePort`.
  - `network.crypta.clients.http.updater.CoreActionToadlet` reaches updater availability,
    download triggers, and installer-path validation through `CoreUpdateActionPort`.
  - `FirstTimeWizardToadlet` and `FirstTimeWizardNewToadlet` use `FirstTimeWizardPort` for
    detached snapshot export, validation bounds, bandwidth/security suggestions, current-bandwidth
    rows, and submission handling.
  - `SymlinkerToadlet` persists aliases through `ToadletSymlinkPort`.
  - `WelcomeToadlet` splits detached GET state and POST actions across `WelcomePagePort` and
    `WelcomeActionPort`, bundled in `WelcomeToadletRuntimePorts`.
  - FProxy and shell bootstrap now have local package-private seams:
    `BookmarkRuntimeSupport`, `FProxyRuntimeSupport`, `HttpShellRuntimeSupport`,
    `HttpShellFProxyBootstrap`, and `FProxyRegistrarDependencies`.
  - Concrete HTTP shell, bookmark, GeoIP, and security-page bridge implementations now live under
    `network.crypta.clients.http.bridge`.
  - `BookmarkEditorToadletRuntimePorts` and `FileInsertWizardToadletRuntimePorts` are small
    page-specific records used to keep constructor surfaces explicit during HTTP wiring.
  - `N2NTMToadlet` uses `DarknetConnectionsPort` and `DarknetMessagingPort` for selected-peer
    lookup, transfer confirmations, and compose/send actions.

### Runtime SPI (`network.crypta.runtime.spi`)
- Aggregate boundary: `RuntimePorts`
- Small ports include: `ExecutionPort`, `RandomnessPort`, `TransferAccessPort`, `LifecyclePort`,
  `ConfigPort`, `ConnectivityPort`, `ConnectionsPagePort`, `ConnectionsSupportPort`,
  `DarknetConnectionsPort`, `DarknetMessagingPort`, `DiagnosticPort`, `QueueSupportPort`,
  `QueueCompletionPort`, `QueuePagePort`, `QueueDownloadPort`, `QueueInsertPort`,
  `QueueMutationPort`, `StatisticsPort`, `SecurityLevelsPort`, `PageChromePort`,
  `CoreUpdateActionPort`, `FirstTimeWizardPort`, `ToadletSymlinkPort`, `WelcomePagePort`,
  `WelcomeActionPort`, `RequestQueuePort`, `NodeInfoPort`, and `PeerPort`
- Detached DTOs include config, connectivity, peer, darknet-friends, node-reference, queue,
  security-level, shared shell, first-time-wizard, symlinker, welcome-page, and statistics/report
  snapshot types such as
  `ConfigSnapshot`, `ConfigFieldSet`, `ConfigSection`, `PeerSnapshot`,
  `DarknetConnectionPeerSnapshot`, `DarknetUploadedFile`, `NodeReferenceSnapshot`,
  `QueuePageSnapshot`, `QueuePersistenceStatusSnapshot`, `QueueInsertOutcome`,
  `SecurityLevelsSnapshot`, `PageChromeSnapshot`, `FirstTimeWizardSnapshot`,
  `FirstTimeWizardCurrentBandwidthLimits`, `ToadletSymlinkEntry`, and `WelcomePageSnapshot`
- Daemon-backed adapters in `network.crypta.runtime.core` (currently in `:runtime-node`):
  `LegacyRuntimePorts`, `LegacyConfigPort`,
  `LegacyConnectivityPort`, `LegacyNodeInfoPort`, `LegacyPeerPort`, `LegacyRequestQueuePort`,
  `LegacySecurityLevelsPort`, and `LegacyCoreUpdateActionPort`
- Daemon-backed adapters in `network.crypta.runtime.admin` (currently in `:runtime-node`):
  `LegacyConnectionsPagePort`,
  `LegacyConnectionsSupportPort`, `LegacyDarknetConnectionsPort`,
  `LegacyDarknetMessagingPort`, `LegacyDiagnosticPort`, `LegacyStatisticsPort`,
  `LegacyPageChromePort`, `LegacyQueuePagePort`, `LegacyQueueMutationPort`,
  `LegacyQueueSupportPort`, `LegacyFirstTimeWizardPort`, `LegacyToadletSymlinkPort`,
  `LegacyWelcomePagePort`, and `LegacyWelcomeActionPort`, plus queue helper seams under
  `network.crypta.runtime.admin.queue` and `network.crypta.runtime.admin.queue.page`
- Adapter-owned concrete FCP bridges in `network.crypta.clients.fcp.bridge`:
  `LegacyQueueCompletionPort`, `LegacyQueueDownloadPort`, `LegacyQueueInsertPort`,
  `CoreFcpPersistentRequestCatalog`, `FcpPersistentRequestRecoveryCodec`,
  `FcpQueueAdminBackend`, `FcpQueuePageBackend`, `FcpUserAlertFeedSubscriber`,
  `FcpUserAlertFeedMessageFactory`, `FcpPersistentRequestServices`, and endpoint-handle wrappers

### Plugin system
- The legacy plugin runtime has been removed from the node.
- Do not expect `network.crypta.pluginmanager`, plugin toadlets, or plugin FCP commands in the
  current codebase.

### Configuration (`network.crypta.config`)
- Main sources live in `:foundation-config`.
- Type-safe configuration with persistence
- Main localization sources and `crypta.l10n.en.properties` also live in `:foundation-config`
  under `network.crypta.l10n`.
- Shared setup helpers such as `DatastoreSizingSupport` also live in `:foundation-config`.
- Higher layers should prefer the narrow `RuntimePorts` sub-port that already covers the needed
  operation (`config()`, `peer()`, `nodeInfo()`, `connectionsPage()`, `connectionsSupport()`,
  `darknetConnections()`, `darknetMessaging()`, `queuePage()`, `queueDownload()`,
  `queueInsert()`, `queueMutation()`, `queueSupport()`, `queueCompletion()`,
  `securityLevels()`, `pageChrome()`, `coreUpdateAction()`, `firstTimeWizard()`,
  `toadletSymlinks()`, `welcomePage()`, `welcomeAction()`, etc.) instead of traversing daemon
  internals directly
- File-system-based l10n tests still run from the root project and resolve main resources through
  `foundation-config/src/main/resources/network/crypta/l10n/`.

### Supporting infrastructure (`network.crypta.support`)
- Logging, data structures, threading, helpers
- `:foundation-support` now owns the stable generic support subset across `network.crypta.support`,
  `network.crypta.support.api`, `network.crypta.support.io`,
  `network.crypta.support.compress`, `network.crypta.support.math`,
  `network.crypta.support.transport.ip`, and `network.crypta.support.http`.
- `:foundation-support` also owns `network.crypta.io.AddressIdentifier`,
  `network.crypta.io.WritableToDataOutputStream`, `network.crypta.node.FastRunnable`,
  `network.crypta.node.SemiOrderedShutdownHook`, `network.crypta.support.IllegalValueException`,
  and `network.crypta.support.SerializationLimits`.
- The root project still owns daemon-coupled support code and higher-level wiring that is not yet
  stable enough to extract cleanly.

### Launcher/Desktop leaf module (`:launcher-desktop`)
- Swing launcher: `network.crypta.launcher`
- Desktop theme detection: `com.jthemedetecor`
- Vendored OSHI annotations and launcher resources

### Foundation leaf modules
- `:foundation-support`: stable generic `network.crypta.support*` subset plus
  `network.crypta.io.AddressIdentifier`, `network.crypta.io.WritableToDataOutputStream`,
  `network.crypta.node.FSParseException`, `network.crypta.node.FastRunnable`,
  `network.crypta.node.SemiOrderedShutdownHook`, `network.crypta.support.http`, and
  `network.crypta.support.IllegalValueException`
- `:foundation-store-contracts`: neutral `network.crypta.store` contracts plus
  `network.crypta.store.alerts`
- `:foundation-crypto-keys`: `network.crypta.crypt`, `network.crypta.keys`
- `:foundation-store`: reusable `network.crypta.store` implementations
- `:interop-wire`: wire/message/schema/version/probe nucleus
- `:foundation-config`: `network.crypta.config`, `network.crypta.l10n`,
  `DatastoreSizingSupport`
- `:foundation-fs`: `network.crypta.fs`
- `:foundation-compat`: `network.crypta.compat`, `network.crypta.compat.bandwidth`
- `:kernel-content`: compile-neutral phase-1 content slice across selected `network.crypta.client*`
  classes plus `network.crypta.support.MediaType`
- `:runtime-spi`: `network.crypta.runtime.spi`
- `:runtime-node`: extracted daemon runtime body across the remaining cyclic/high-level
  `network.crypta.client` body, large `network.crypta.node` / `network.crypta.runtime.*` slices,
  `network.crypta.io.xfer`, and the remaining daemon-coupled support helpers
- `:adapter-fcp`: `network.crypta.clients.fcp`
- `:adapter-http-legacy-admin`: `network.crypta.clients.http`

### Vendored library leaf modules
- `:thirdparty-onion`: `com.onionnetworks`
- `:thirdparty-legacy`: `org.bitpedia`, `org.sevenzip`, `org.spaceroots`

### UID trace logging
- UID lifecycle tracing logs routing/timeout/finish events to `crypta-uidtrace-latest.log` to debug
  stuck requests/inserts.
- Disabled by default in `src/main/resources/logback.xml` (logger `network.crypta.uidtrace`).
- Enable by setting `logger.priorityDetail=network.crypta.uidtrace:INFO` (or `DEBUG`) and
  restarting. The log file is written under `logger.dirname` (falls back to `crypta.log.dir`).

## Key design patterns
### Request routing (high level)
1. `RequestStarter` initiates requests
2. `RequestScheduler` manages queues and priorities
3. `SendableRequest` implementations perform request types
4. Routing uses location-based algorithms for discovery

### Update system (high level)
- `NodeUpdateManager` coordinates updates.
- Core updates use the package-based `CoreUpdater` (see the CoreUpdater skill for details).
- The legacy plugin runtime has been removed; there is no separate plugin updater path in the
  current node.
- Core updater state is exposed through CorePackage APIs in `NodeUpdateManager`:
  - `hasNewCorePackage()`, `newCorePackageVersion()`, `newCorePackageVersionLabel()`
  - `fetchingNewCorePackage()`, `fetchingNewCorePackageVersion()`
- Release gating comes from `core-info.json` `version` (strict integer parse) rather than semantic
  version strings; invalid/non-integer values are ignored for update availability.
- JAR Update-over-Mandatory (UOM) payload transfer is disabled for core; revocation/dependency
  signaling remains and legacy UOM wire names are retained for compatibility.
- Config keys such as `node.updater.enabled` and `node.updater.autoupdate` remain.

## Security model (high level)
- Content-addressed storage with cryptographic verification
- Encrypted link-level communication; routing conceals origin/destination
- Digital signatures for content authentication

## Versioning system
- A single integer build number is set in `build.gradle.kts` (`version = "<int>"`).
- Version tokens are replaced into the `:interop-wire` `network/crypta/node/Version.java`
  template during build (`@build_number@`, `@git_rev@`).
- Version strings support both Cryptad and Fred formats; compatibility enforces protocol match and minimum builds.
- Freenet interop uses historical identifiers (e.g., `"Fred,0.7"`) for wire compatibility where applicable.
- Core update descriptors (`core-info.json`) must publish `version` as an integer string; this value
  is compared against `Version.currentBuildNumber()` to determine whether a core package update is
  available.
