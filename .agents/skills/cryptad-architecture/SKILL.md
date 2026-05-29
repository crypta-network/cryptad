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
  strongly coupled core packages, and most broad tests.
- Leaf subprojects:
  - `:foundation-support` → the current stable generic subset of `network.crypta.support`,
    `network.crypta.support.api`, `network.crypta.support.io`,
    `network.crypta.support.compress`, `network.crypta.support.math`,
    `network.crypta.support.transport.ip`, and `network.crypta.support.http`, plus
    `network.crypta.io.AddressIdentifier`, `network.crypta.io.WritableToDataOutputStream`,
    `network.crypta.node.FSParseException`, `network.crypta.node.FastRunnable`,
    `network.crypta.node.PrioRunnable`, `network.crypta.node.SemiOrderedShutdownHook`,
    `network.crypta.support.IllegalValueException`, `network.crypta.support.JVMVersion`, the
    generic `HTTPRequest` / `HTTPUploadedFile` / `MultiValueTable` / `SizeUtil` support surface,
    generic helpers such as `URIPreEncoder`, `IOUtils`, and `LegacyFileSupport`, and the
    cycle-safe file-backed support I/O slice
  - `:foundation-store-contracts` → neutral `network.crypta.store` contracts
    `BlockMetadata`, `GetPubkey`, `StorableBlock`, plus the `network.crypta.store.alerts` seam
    (`StoreAlertSink`, `StoreMaintenanceAlertKind`, `StoreMaintenanceAlertSource`)
  - `:foundation-crypto-keys` → `network.crypta.crypt`, `network.crypta.keys`, plus
    `network.crypta.support.io.BucketTools`, `network.crypta.support.io.NoFreeBucket`, and
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
    `network.crypta.client.filter`, `network.crypta.client.async.alerts`,
    `network.crypta.client.async.persistence`, selected filter policy/helper types such as
    `HTMLFilterPolicy`, concrete media/CSS/HTML parser/filter helpers, selected event/helper
    types such as `SplitfileCompatibilityMode*`, and `network.crypta.support.MediaType`
  - `:kernel-transport` → the compile-neutral phase-1 transport slice across selected
    `network.crypta.io`, `network.crypta.io.comm`, and `network.crypta.io.xfer` helpers such as
    address matchers, allow-list parsing, listener abstractions, `SSLNetworkInterface`,
    I/O statistics collection, throttling, and partially received block assembly
  - `:kernel-routing` → the compile-neutral phase-1 routing/helper slice across selected
    `network.crypta.node` value, exception, callback, and request-item helper types such as
    `BaseRequestThrottle`, `LowLevelGetException`, `LowLevelPutException`, `RequestClient`,
    `PeerStatusCounts`, `RecentlyFailedReturn`, `RequestPriorityClasses`, and
    `SendableRequestItem*`
  - `:runtime-spi` → `network.crypta.runtime.spi` (JDK-only runtime/config boundary)
  - `:platform-api` → `network.crypta.platform.api` (transport-neutral Platform API v1,
    compatibility contract, app capabilities/audit, app-vault routes, app-generated document
    inserts, bounded content fetch, durable content subscriptions, durable app data,
    local app-service discovery/grants, and app-update lifecycle/scheduler)
  - `:platform-apphost` → `network.crypta.platform.apphost` (transport-neutral out-of-process
    AppHost core, sandbox status, durable rollback records, and AppHost-managed quota enforcement)
  - `:platform-app-ui` → `network.crypta.platform.appui` (app-owned static UI route and asset
    resolution helpers, isolated origin metadata, and browser-session helpers)
  - `:platform-appvault` → `network.crypta.platform.appvault` (app secret and identity vault
    records, grants, local wrapping-key provider, and audit/redaction value types)
  - `:platform-design-system` → `network.crypta.platform.designsystem` (canonical local app UI
    CSS/JS resources plus asset metadata and safe bundle-copy helpers)
  - `:platform-sdk-js` → browser SDK resource for app-owned static UI bootstrap, Platform API
    transport helpers, mutation form handling, queue/content/vault/feed/app-data/app-service
    helpers, error parsing, and conservative fragment sanitization
  - `:platform-appdist` → `network.crypta.platform.appdist` (signed local app bundle digest,
    signature, manifest, verifier, trusted-key, deterministic packager, and distribution tooling)
  - `:platform-appcatalog` → `network.crypta.platform.appcatalog` (signed catalog sources,
    catalog writer/descriptors, Crypta catalog source handling, app-store/API compatibility
    metadata, independent app-review receipts, artifact verification, safe ZIP extraction, and
    verified staging)
  - `:platform-trustgraph` → `network.crypta.platform.trustgraph` (Trust Graph Preview statement
    parsing, canonicalization, verification, process-local store/anchor behavior, and deterministic
    direct-anchor scoring)
  - `:platform-devtools` → `network.crypta.platform.devtools` (standalone `crypta-app` developer
    CLI for staged-bundle, UI lint, mock dev server, offline tests, catalog-authoring, developer
    keys, publication plans, explicit live USK catalog publication, API snapshot, and compatibility
    verification workflows)
  - `:platform-web-shell` → `network.crypta.platform.webshell` (browser-facing Web Shell v1,
    including Apps, catalog, update, review, and app-service grant operator surfaces)
  - `:runtime-alerts` → the extracted leaf-safe `network.crypta.runtime.alerts` feed/model subset
    plus the detached `UserAlertSurface`
  - `:runtime-node` → extracted daemon runtime body across the remaining cyclic/high-level
    `network.crypta.client` body, the remaining peer/request/routing-engine and transport-heavy
    `network.crypta.node` / `network.crypta.runtime.*` slices, the retained node-coupled
    transport/message execution code in `network.crypta.io*`, and the remaining daemon-coupled
    `network.crypta.support` / `network.crypta.support.io` / `network.crypta.support.api` subset
  - `:adapter-fcp` → the detached protocol-side `network.crypta.clients.fcp` package tree
  - `:bridge-fcp-runtime` → the concrete runtime-binding FCP bridge package
    `network.crypta.clients.fcp.bridge`
  - `:adapter-http-legacy-admin` → the detached shared legacy `network.crypta.clients.http`
    shell, admin toadlets, `/api/v1/` and `/app/node/` bridge entrypoints, the app-UI loopback
    origin server, and matching `network/crypta/clients/http/**` main resources
  - `:adapter-http-legacy-browse` → the concrete legacy browse/FProxy routes, toadlets, helper
    models, and browse-only packages under `network.crypta.clients.http`
  - `:bridge-http-runtime` → the concrete runtime-binding HTTP bridge implementations under
    `network.crypta.clients.http.bridge` plus the legacy HTTP GeoIP helper package
    `network.crypta.clients.http.geoip`
  - `:thirdparty-onion` → `com.onionnetworks` plus `lib/fec.properties`
  - `:thirdparty-legacy` → `org.bitpedia`, `org.sevenzip`, `org.spaceroots`
  - `:launcher-desktop` → `network.crypta.launcher`, `com.jthemedetecor`, `oshi`, launcher
    resources
- First-party app bundle subprojects:
  - `:apps:queue-manager` → staged Queue Manager AppHost bundle with a static UI under
    an isolated app origin when available, with `/apps/queue-manager/static/` as fallback
  - `:apps:publisher` → staged Publisher AppHost bundle with a static UI under
    an isolated app origin when available, with `/apps/publisher/static/` as fallback
  - `:apps:site-publisher` → staged Site Publisher content reference AppHost bundle with a static
    UI under an isolated app origin when available, with `/apps/site-publisher/static/` as fallback
  - `:apps:profile-publisher` → staged Profile Publisher identity-profile reference AppHost bundle
    with a static UI under an isolated app origin when available, using app-vault profile-document
    creation and app-generated document insertion
  - `:apps:social-inbox` → staged Social Inbox Preview social/mail migration reference AppHost
    bundle with a static UI under an isolated app origin when available, using bounded AppVault
    social-message signing, generated outbox insertion, durable content subscriptions, durable app
    data, and operator-approved Trust Graph score app-service grants
  - `:apps:feed-reader` → staged Feed Reader content-fetch and subscription reference AppHost bundle
    with a static UI under an isolated app origin when available, using bounded Crypta content
    fetch, durable USK content subscriptions, durable app data, and app-generated feed document
    insertion
  - `:apps:trust-graph` → staged Trust Graph Preview local trust-service reference AppHost bundle
    with a static UI under an isolated app origin when available, using `trust.read`,
    `trust.write`, durable trust graph storage/exchange, bounded content fetch/subscriptions,
    AppVault trust-statement signing, app-generated trust statement insertion, and the
    `trust.score` app-service provider
- The runtime boundary is split intentionally:
  - `:runtime-spi` exposes small JDK-only ports plus immutable config, alert, queue, peer, wizard,
    updater, and shell DTOs.
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
  - The root project keeps application composition, packaging/runtime tasks, most broad tests,
    tools, and root-local bridge selection in
    `network.crypta.runtime.bootstrap.DefaultNodeRuntimeBridgeFactories`.
- The daemon runtime and app-platform build now span extracted leaves plus a thin root composition
  layer:
  `:kernel-content` owns the compile-neutral phase-1 client/content slice,
  `:kernel-transport` owns the compile-neutral phase-1 transport helper slice,
  `:kernel-routing` owns the compile-neutral phase-1 routing/helper slice,
  `:platform-api` owns the transport-neutral Platform API surface including app-vault route
  handlers, social-message signing, app-generated document inserts, bounded content fetch,
  durable content subscriptions, durable app data, local app-service discovery/grants, and
  app-update scheduling,
  `:platform-apphost` owns the transport-neutral AppHost core, `:platform-app-ui` owns
  app-owned static UI route helpers,
  `:platform-appvault` owns app secret and identity vault records/grants,
  `:platform-design-system` owns canonical local app UI assets, `:platform-sdk-js` owns the
  browser SDK resource, `:platform-appdist` owns signed local bundle distribution,
  `:platform-appcatalog` owns signed catalog sources, trusted app-review receipts, and verified
  staging, `:platform-trustgraph` owns local trust statement parsing and deterministic preview
  scoring, `:platform-devtools` owns the standalone app developer CLI and offline UI linter,
  `:platform-web-shell` owns the browser-facing
  node-management shell, `:runtime-alerts` owns the extracted alert/feed model subset,
  `:runtime-node` owns the
  remaining runtime/node/client/support body, `:adapter-fcp` owns the FCP adapter tree,
  `:bridge-fcp-runtime` owns the concrete FCP bridge implementations,
  `:adapter-http-legacy-admin` owns the shared legacy HTTP shell/admin layer,
  `:adapter-http-legacy-browse` owns the concrete browse/FProxy layer,
  `:bridge-http-runtime` owns the concrete HTTP runtime bridge, and the root project keeps tests,
  packaging, tool entrypoints, and remaining composition glue.
- The wire split is intentionally narrow:
  `:interop-wire` owns the message/schema nucleus, `:kernel-transport` owns the compile-neutral
  transport helper slice (`AllowedHosts`, `NetworkInterface`, `IOStatisticCollector`,
  `SSLNetworkInterface`, `SocketHandler`, `PacketThrottle`, `PartiallyReceivedBlock`, etc.),
  while `:runtime-node` keeps `MessageCore`, `MessageFilter`, `AsyncMessageFilterCallback`,
  `SlowAsyncMessageFilterCallback`, `PeerContext`, incoming-packet filters, active socket
  handlers, and transfer send/receive code.
  `network.crypta.io.comm.Message` now depends on the minimal `MessageSource` seam instead of
  directly on `PeerContext`.
- For the detached adapter/runtime boundary details, prefer the maintenance docs in
  `docs/fcp-boundary.md` and `docs/legacy-http-boundary.md` over older migration narratives.
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
- Focused leaf-local boundary tests now freeze the extracted layout. In particular,
  `RuntimeNodeKernelSplitPrepBoundaryTest`, `KernelContentBoundaryTest`,
  `KernelTransportBoundaryTest`, `KernelRoutingBoundaryTest`, `PlatformApiBoundaryTest`,
  `AdapterFcpBoundaryTest`, `BridgeFcpRuntimeBoundaryTest`, `AppHostBoundaryTest`,
  `CryptaPlatformSdkBoundaryTest`, `WebShellBoundaryTest`, `HttpLegacyAdminBoundaryTest`,
  `LegacyHttpBrowseBoundaryTest`, and `BridgeHttpRuntimeBoundaryTest` guard leaf
  ownership/import rules. The runtime, kernel,
  platform, FCP, and HTTP boundary suites also require `package-info.java` in the production
  packages they own.

## Architecture overview (by package)
### Core network layer (`network.crypta.node`)
- Node coordination: `Node.java`
- Peer management: `PeerNode`, `PeerManager`
- Network transport: `PacketSender`, `FNPPacketMangler`
- Request orchestration: `RequestStarter`, `RequestScheduler`
- `:kernel-routing` now owns the compile-neutral phase-1 helper/value slice inside
  `network.crypta.node`, including request client metadata, low-level routing exceptions,
  lightweight peer-status summaries, and sendable-request item helper interfaces.
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
- `:kernel-transport` owns the compile-neutral transport helper slice across selected
  `network.crypta.io`, `network.crypta.io.comm`, and `network.crypta.io.xfer` classes such as
  `AllowedHosts`, `NetworkInterface`, `IOStatisticCollector`, `SocketHandler`,
  `PortForwardSensitiveSocketHandler`, `PacketThrottle`, and `PartiallyReceivedBlock`.
- `:kernel-routing` owns the compile-neutral phase-1 `network.crypta.node` helper/value slice,
  including `BaseRequestThrottle`, `LowLevelGetException`, `LowLevelPutException`,
  `RequestClient`, `PeerStatusCounts`, `RecentlyFailedReturn`, and `SendableRequestItem*`.
- `:runtime-node` keeps the node-coupled transport-facing code such as `PeerContext`,
  `MessageCore`, packet filters, active socket handlers, transfer send/receive code, and the
  remaining peer/request/routing-engine side of `network.crypta.node`, plus runtime helpers like
  `network.crypta.runtime.core.SSL`.

### Client APIs
- High-level client: `network.crypta.client`
  - `:kernel-content` now owns the compile-neutral phase-1 content slice: selected
    archive/value/helper classes, immutable event values, the full
    `network.crypta.client.async.alerts` seam, client-local seams under
    `network.crypta.client.async.persistence`, a conservative subset of filter helper/parser
    types plus policy holders such as `HTMLFilterPolicy`, concrete media/CSS/HTML parser/filter
    helpers, event/helper types such as `ClientEventProducer` and `SplitfileCompatibilityMode*`,
    utility/value types such as `ClientGetterOptions` and `ClientPutterOptions`, `InsertUriChecks`,
    and
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
  - FCP insert request options and mutable insert-context handles stay adapter-owned through
    `FcpInsertOptions`, `FcpInsertBehaviorOptions`, and `FcpInsertContextHandle`; bridge code
    adapts those seams to runtime insert contexts.
  - Runtime-owned FCP seam types now live under `network.crypta.runtime.fcp` and
    `network.crypta.runtime.endpoints.fcp`, while concrete persistent-request services, queue
    adapters, alert-feed adapters, and endpoint-handle wrappers now live under
    `network.crypta.clients.fcp.bridge`.
- HTTP interface: `network.crypta.clients.http`
  - The package family is now split physically:
    `:adapter-http-legacy-admin` owns the shared shell/admin routes and the matching
    `network/crypta/clients/http/**` main resources such as `staticfiles/**` and `templates/**`;
    `:adapter-http-legacy-browse` owns the concrete browse/FProxy routes, toadlets, and helper
    models; `:bridge-http-runtime` owns the concrete runtime-binding bridge implementations under
    `network.crypta.clients.http.bridge` plus the legacy HTTP GeoIP helper package.
  - The migrated management and shell slices no longer depend directly on live daemon peers or
    node-info exports for their core data flow.
  - `ConfigToadlet` now takes detached configuration export/update capabilities from
    `ConfigPort` through `ConfigToadletRuntimePorts` and classifies directory-browser fields
    through the detached `network.crypta.config.DirectorySelectionCallback` marker instead of
    importing `ProgramDirectory`.
  - `ConnectionsToadlet`, `DarknetConnectionsToadlet`, `OpennetConnectionsToadlet`, and
    `DarknetAddRefToadlet` use detached ports such as `ConnectionsPagePort`,
    `ConnectionsSupportPort`, `PeerPort`, and `NodeInfoPort`.
  - `QueueToadlet` now acts as an HTTP adapter over `QueuePagePort`, `QueueDownloadPort`,
    `QueueInsertPort`, `QueueMutationPort`, `QueueSupportPort`, `QueueCompletionPort`,
    `TransferAccessPort`, `DarknetConnectionsPort`, and `DarknetMessagingPort`.
  - `SecurityLevelsToadlet` uses `SecurityLevelsPort` for detached page state, warning HTML, and
    master-password mutation flows.
  - `PageMaker` reads shared shell status through `PageChromePort`.
  - `LegacyAdminRetirementRegistry` maps replaced legacy admin surfaces, and
    `LegacyAdminUsageRecorder` feeds process-local legacy-page counters into Platform API
    diagnostics without storing query strings, form bodies, tokens, or remote addresses.
  - `network.crypta.clients.http.updater.CoreActionToadlet` reaches updater availability,
    download triggers, and installer-path validation through `CoreUpdateActionPort`.
  - `FirstTimeWizardToadlet` and `FirstTimeWizardNewToadlet` use `FirstTimeWizardPort` for
    detached snapshot export, validation bounds, bandwidth/security suggestions, current-bandwidth
    rows, and submission handling.
  - `SymlinkerToadlet` persists aliases through `ToadletSymlinkPort`.
  - `WelcomeToadlet` splits detached GET state and POST actions across `WelcomePagePort` and
    `WelcomeActionPort`, bundled in `WelcomeToadletRuntimePorts`.
  - FProxy and shell bootstrap now have local package-private seams:
    `BookmarkRuntimeSupport`, `BrowseContentClient`, `FProxyRuntimeSupport`,
    `HttpShellRuntimeSupport`,
    `HttpShellFProxyBootstrap`, and `FProxyRegistrarDependencies`.
  - HTTP/admin alert rendering now crosses the detached
    `network.crypta.runtime.alerts.UserAlertSurface` instead of importing
    `UserAlertManager` directly.
  - Concrete HTTP shell, bookmark, GeoIP, and security-page bridge implementations now live under
    `network.crypta.clients.http.bridge` in `:bridge-http-runtime`.
  - `BookmarkEditorToadletRuntimePorts` and `FileInsertWizardToadletRuntimePorts` are small
    page-specific records used to keep constructor surfaces explicit during HTTP wiring.
  - `N2NTMToadlet` uses `DarknetConnectionsPort` and `DarknetMessagingPort` for selected-peer
    lookup, transfer confirmations, and compose/send actions.

### Platform control/UI modules
- `:platform-api` owns the transport-neutral Platform API v1 under `network.crypta.platform.api`.
  It exposes node/config/peer/connectivity/security, queue, updates, wizard, alerts, diagnostics,
  apps, app updates, app-catalog control-plane families, app-vault route handlers, generated
  app-document inserts, bounded content fetch, durable content subscriptions, durable app data,
  local app-service discovery/grants, and the deterministic Platform API compatibility contract,
  and is currently mounted at `/api/v1/` by the legacy HTTP adapter. It also owns app-token and
  browser-session authorization decisions, bounded process-local app audit logs, and local
  app-update lifecycle/scheduler coordination above AppHost, signed catalog, vault, app-data,
  content-fetch, content-subscription, trust graph, and app-service primitives.
- `:platform-apphost` owns the transport-neutral out-of-process AppHost v1 under
  `network.crypta.platform.apphost`. It validates staged local app bundles, owns the immutable
  installed-bundle layout plus mutable data/cache/run directories, and provides local
  install/list/describe/start/stop/update/uninstall operations, per-launch app tokens, minimal
  launch environments, token-redacted process-log snapshots, durable previous-bundle rollback
  records, sandbox policy/status reporting, Linux bubblewrap provider selection for enforced
  restricted-process launches, AppHost-managed data/cache quota enforcement, bounded process logs,
  and in-session restart attempts for manifests that opt in.
- `:platform-app-ui` owns `network.crypta.platform.appui`, the transport-neutral app-owned static
  UI path and origin layer. It maps installed static UI manifests to isolated per-app loopback
  origins with `/apps/{appId}/` retained as a compatibility fallback, preserves nested entry base
  URLs, resolves bundle assets, rejects traversal/symlink/reparse escapes, and supplies
  deterministic content-type, security-header, launch-proof bootstrap, and browser-session helpers
  for HTTP adapters.
- `:platform-appvault` owns `network.crypta.platform.appvault`, the local app secret and identity
  vault model. It provides encrypted record envelopes, local wrapping-key lookup, app-owned and
  shared identity metadata, grant records, identity-use result types, and audit/redaction values
  used by Platform API app, profile-document, trust-statement, and social-message workflows without
  exporting raw private material.
- `:platform-sdk-js` owns the dependency-free browser SDK resource staged into first-party static
  app bundles. It wraps route bootstrap, same-origin Platform API reads, app-browser form
  mutations, queue/content/app-vault/feed/app-data/app-service helpers, error parsing, and
  conservative legacy HTML fragment sanitization; it is not an authority or isolation boundary.
- `:platform-appdist` owns `network.crypta.platform.appdist`, the signed local bundle
  distribution layer. It parses normalized app manifests, writes deterministic SHA-256 digest
  sidecars, verifies Ed25519 signatures, rejects reserved sidecars as executable/UI entries,
  carries sandbox/quota/API compatibility manifest fields, and exposes the packager/distribution
  tool used by first-party app Gradle tasks and developer tooling.
- `:platform-appcatalog` owns `network.crypta.platform.appcatalog`, the signed catalog source and
  artifact staging layer. It writes catalogs from descriptors, verifies catalog signatures,
  enforces source/URI policy including `crypta:` catalog sources, parses optional review/API
  compatibility metadata, verifies independent app-review receipts against trusted reviewer keys
  and local review policy, validates artifact size and SHA-256, safely extracts ZIP bundles, and
  delegates verified staged bundles to AppHost install/update flows.
- `:platform-trustgraph` owns `network.crypta.platform.trustgraph`, the local Trust Graph Preview
  model and scoring layer. It parses bounded trust statement documents, canonicalizes and verifies
  statement payloads, stores process-local anchors/statements, and computes deterministic direct
  trust scores without changing peer protocols or claiming full Web of Trust behavior.
- `:platform-devtools` owns `network.crypta.platform.devtools`, the standalone `crypta-app` CLI. It
  wires app template scaffolding, bundle validation, signing, packaging, verification, permission
  linting, offline UI linting, mock dev serving, offline app tests, developer key generation,
  publication plan dry-runs, explicit live USK catalog publication, API contract
  snapshot/compatibility verification, review receipt signing/verification, and catalog
  create/sign/verify commands around the platform distribution, API, design-system, and catalog
  libraries.
- `:platform-web-shell` owns the first browser-facing Web Shell v1 under
  `network.crypta.platform.webshell`. It provides the current node-management shell route
  constants, bootstrap payload, renderer, and static browser assets mounted at `/app/node/`; it
  opens app-owned `uiUrl` values when installed app summaries expose them and surfaces app catalog
  review, update candidate, staged update, policy, health-gate, rollback, advertised app-service,
  and service-grant approval/revocation state for operators.

### Runtime SPI (`network.crypta.runtime.spi`)
- Aggregate boundary: `RuntimePorts`
- Small ports include: `ExecutionPort`, `RandomnessPort`, `TransferAccessPort`, `LifecyclePort`,
  `ConfigPort`, `ConnectivityPort`, `ConnectionsPagePort`, `ConnectionsSupportPort`,
  `DarknetConnectionsPort`, `DarknetMessagingPort`, `DiagnosticPort`, `QueueSupportPort`,
  `QueueCompletionPort`, `QueuePagePort`, `QueueDownloadPort`, `QueueInsertPort`,
  `QueueMutationPort`, `StatisticsPort`, `SecurityLevelsPort`, `PageChromePort`,
  `CoreUpdateActionPort`, `FirstTimeWizardPort`, `ToadletSymlinkPort`, `WelcomePagePort`,
  `WelcomeActionPort`, `AlertFeedPort`, `AlertMutationPort`, `LegacyAdminUsagePort`,
  `RequestQueuePort`, `NodeInfoPort`, `PeerPort`, and `ContentFetchPort`
- Detached DTOs include config, connectivity, peer, darknet-friends, node-reference, queue,
  security-level, shared shell, first-time-wizard, symlinker, welcome-page, alert, and
  statistics/report snapshot types such as
  `ConfigSnapshot`, `ConfigFieldSet`, `ConfigSection`, `PeerSnapshot`,
  `DarknetConnectionPeerSnapshot`, `DarknetUploadedFile`, `NodeReferenceSnapshot`,
  `BoundedContentFetchRequest`, `BoundedContentFetchResult`, `ContentFetchException`,
  `QueuePageSnapshot`, `QueuePersistenceStatusSnapshot`, `QueueInsertOutcome`,
  `SecurityLevelsSnapshot`, `PageChromeSnapshot`, `FirstTimeWizardSnapshot`,
  `FirstTimeWizardCurrentBandwidthLimits`, `ToadletSymlinkEntry`, `WelcomePageSnapshot`,
  `AlertListSnapshot`, `AlertSnapshot`, `AlertSeverity`, `LegacyAdminUsageSnapshot`, and
  `LegacyAdminSurfaceUsage`
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
- Narrow callback-level UI markers such as
  `network.crypta.config.DirectorySelectionCallback` also live in `:foundation-config`, so HTTP
  admin code can classify directory-selection fields without importing concrete runtime-owned
  callback implementations.
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
  `network.crypta.node.PrioRunnable`, `network.crypta.node.SemiOrderedShutdownHook`,
  `network.crypta.support.IllegalValueException`, `network.crypta.support.JVMVersion`, the
  generic HTTP request/upload and multimap/size-formatting surface, generic helpers such as
  `URIPreEncoder`, `IOUtils`, and `LegacyFileSupport`, the cycle-safe file-backed support I/O
  slice, and `network.crypta.support.SerializationLimits`.
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
  `network.crypta.node.PrioRunnable`, `network.crypta.node.SemiOrderedShutdownHook`,
  `network.crypta.support.http`, `network.crypta.support.IllegalValueException`,
  `network.crypta.support.JVMVersion`, the generic `HTTPRequest` / `HTTPUploadedFile` /
  `MultiValueTable` / `SizeUtil` surface, generic helpers such as `URIPreEncoder`, `IOUtils`,
  `LegacyFileSupport`, and `HTMLDecoder`, and the cycle-safe file-backed support I/O slice
- `:foundation-store-contracts`: neutral `network.crypta.store` contracts plus
  `network.crypta.store.alerts`
- `:foundation-crypto-keys`: `network.crypta.crypt`, `network.crypta.keys`, plus adjacent
  support-IO helpers such as `BucketTools`, `NoFreeBucket`, and
  `PrependLengthOutputStream`
- `:foundation-store`: reusable `network.crypta.store` implementations
- `:interop-wire`: wire/message/schema/version/probe nucleus
- `:foundation-config`: `network.crypta.config`, `network.crypta.l10n`,
  `DatastoreSizingSupport`
- `:foundation-fs`: `network.crypta.fs`
- `:foundation-compat`: `network.crypta.compat`, `network.crypta.compat.bandwidth`
- `:kernel-content`: compile-neutral phase-1 content slice across selected `network.crypta.client*`
  classes, `network.crypta.client.async.persistence`, event/helper types such as
  `SplitfileCompatibilityMode*`, filter policy/helper types such as `HTMLFilterPolicy`, concrete
  media/CSS/HTML parser/filter helpers, `InsertUriChecks`, and `network.crypta.support.MediaType`
- `:kernel-transport`: compile-neutral phase-1 transport slice across selected
  `network.crypta.io*` helpers including `SSLNetworkInterface`
- `:kernel-routing`: compile-neutral phase-1 routing/helper slice across selected
  `network.crypta.node` helper/value types
- `:runtime-spi`: `network.crypta.runtime.spi`
- `:platform-api`: `network.crypta.platform.api`
- `:platform-apphost`: `network.crypta.platform.apphost`
- `:platform-app-ui`: `network.crypta.platform.appui`
- `:platform-appvault`: `network.crypta.platform.appvault`
- `:platform-sdk-js`: browser SDK resource under `network/crypta/platform/sdk/js`
- `:platform-appdist`: `network.crypta.platform.appdist`
- `:platform-appcatalog`: `network.crypta.platform.appcatalog`
- `:platform-trustgraph`: `network.crypta.platform.trustgraph`
- `:platform-devtools`: `network.crypta.platform.devtools`
- `:platform-web-shell`: `network.crypta.platform.webshell`
- `:runtime-alerts`: `network.crypta.runtime.alerts`, including the detached
  `UserAlertSurface`
- `:runtime-node`: extracted daemon runtime body across the remaining cyclic/high-level
  `network.crypta.client` body, the remaining peer/request/routing-engine
  `network.crypta.node` / `network.crypta.runtime.*` slices, the retained node-coupled
  transport/message execution code, and the remaining daemon-coupled support helpers
- `:adapter-fcp`: `network.crypta.clients.fcp`
- `:bridge-fcp-runtime`: `network.crypta.clients.fcp.bridge`
- `:adapter-http-legacy-admin`: shared legacy HTTP shell/admin layer plus matching resources
- `:adapter-http-legacy-browse`: concrete legacy browse/FProxy layer
- `:bridge-http-runtime`: `network.crypta.clients.http.bridge` and
  `network.crypta.clients.http.geoip`

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
- `ClientRequestSelector` returns the earliest useful cooldown wakeup, and
  `ClientRequestScheduler#scheduleWakeStarterAt` coalesces starter wakeup jobs. Selector code
  should not queue duplicate ticker wakeups directly.

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
