---
name: cryptad-build-test
description: "Build, test, and run Cryptad safely using the Gradle wrapper (Java 25+, JUnit 6)."
metadata:
  area: build
  domain: cryptad
  lang: java
---

## When to use
Use this skill when you need to:
- Build the node JAR, run tests, or compile the project.
- Run a single test class/method during debugging.
- Validate that your local build can be deployed to a running node.
- Diagnose Gradle/Java toolchain issues (Java 25+).

## Build layout
- Cryptad now uses a partial multi-project Gradle build.
- Use root-project tasks by default; the root project remains the daemon/application target.
- Current leaf projects are `:foundation-support`, `:foundation-store`,
  `:foundation-store-contracts`, `:foundation-crypto-keys`, `:interop-wire`,
  `:foundation-config`, `:foundation-fs`, `:foundation-compat`, `:kernel-content`,
  `:kernel-transport`, `:kernel-routing`, `:runtime-spi`, `:platform-api`,
  `:platform-apphost`, `:platform-app-ui`, `:platform-appvault`, `:platform-appdist`,
  `:platform-appcatalog`, `:platform-trustgraph`, `:platform-design-system`,
  `:platform-devtools`, `:platform-sdk-js`, `:platform-web-shell`, `:runtime-alerts`,
  `:runtime-node`, `:adapter-fcp`,
  `:bridge-fcp-runtime`, `:bridge-http-runtime`,
  `:adapter-http-legacy-admin`, `:adapter-http-legacy-browse`, `:thirdparty-onion`,
  `:thirdparty-legacy`, and `:launcher-desktop`.
- First-party app bundle projects live under `:apps:queue-manager`, `:apps:publisher`,
  `:apps:site-publisher`, `:apps:profile-publisher`, `:apps:social-inbox`,
  `:apps:feed-reader`, and `:apps:trust-graph`.
- The extracted leaf projects compile separately, but `buildJar`, `run`, `runLauncher`,
  `assembleCryptadDist`, and jpackage tasks are still rooted at `:cryptad`.
- `:foundation-support` owns the current stable generic support subset under
  `network.crypta.support*`, `network.crypta.support.transport.ip`,
  `network.crypta.support.http`, `network.crypta.io.AddressIdentifier`,
  `network.crypta.io.WritableToDataOutputStream`, `network.crypta.node.FSParseException`,
  `network.crypta.node.FastRunnable`, `network.crypta.node.PrioRunnable`,
  `network.crypta.node.SemiOrderedShutdownHook`, `network.crypta.support.IllegalValueException`,
  `network.crypta.support.JVMVersion`, the generic `HTTPRequest` / `HTTPUploadedFile` /
  `MultiValueTable` / `SizeUtil` surface, generic helpers such as `URIPreEncoder`, `IOUtils`,
  `LegacyFileSupport`, and `HTMLDecoder`, plus the cycle-safe file-backed support I/O slice.
- `:foundation-store-contracts` owns the neutral `network.crypta.store` contracts
  `BlockMetadata`, `GetPubkey`, and `StorableBlock`, plus the `network.crypta.store.alerts`
  seam.
- `:foundation-crypto-keys` owns `network.crypta.crypt`, `network.crypta.keys`, and the adjacent
  `BucketTools` / `NoFreeBucket` / `PrependLengthOutputStream` helpers.
- `:foundation-store` owns reusable `network.crypta.store` implementations plus
  `network.crypta.store.caching` and `network.crypta.store.saltedhash`.
- `:interop-wire` owns the narrow wire/message/schema/version/probe nucleus:
  leaf-safe `network.crypta.io.comm` message/schema classes, `network.crypta.node.Version`,
  `network.crypta.node.probe.Error` and `Type`, and `network.crypta.support.Serializer`.
- `:foundation-config` owns the main `network.crypta.config` and `network.crypta.l10n` sources,
  plus shared setup helpers such as `DatastoreSizingSupport`. Its public APIs now re-export
  `:foundation-support` and `:foundation-fs` where needed.
- `:foundation-compat` owns extracted compatibility helpers under `network.crypta.compat`,
  including the wizard-neutral bandwidth support moved to
  `network.crypta.compat.bandwidth`.
- `:kernel-content` owns the compile-neutral phase-1 content slice across selected
  `network.crypta.client`, `network.crypta.client.events`, `network.crypta.client.filter`,
  `network.crypta.client.async.alerts`, `network.crypta.client.async.persistence`,
  event/helper types such as `SplitfileCompatibilityMode*`, filter policy/helper types such as
  `HTMLFilterPolicy`, concrete media/CSS/HTML parser/filter helpers, `InsertUriChecks`, and
  `network.crypta.support.MediaType`.
- `:kernel-transport` owns the compile-neutral phase-1 transport slice across selected
  `network.crypta.io`, `network.crypta.io.comm`, and `network.crypta.io.xfer` helpers such as
  allow-list parsing, listener abstraction, `SSLNetworkInterface`, I/O statistics collection,
  throttling, and partially received block assembly.
- `:kernel-routing` owns the compile-neutral phase-1 routing/helper slice across selected
  `network.crypta.node` value, exception, callback, and request-item helper types such as
  `BaseRequestThrottle`, `LowLevelGetException`, `LowLevelPutException`, `RequestClient`,
  `PeerStatusCounts`, `RecentlyFailedReturn`, `RequestPriorityClasses`, and
  `SendableRequestItem*`.
- Every extracted internal leaf must keep leaf-owned aggregated-output metadata in sync at
  `<leaf>/gradle/owned-output-patterns.txt`, even for structurally separate package/resource
  moves. Non-clean builds and branch switches can leave stale non-owner aggregated outputs behind,
  and `buildJar` still packages aggregated main outputs before leaf outputs.
- When moving additional main classes/resources from root into any extracted leaf, update that
  leaf's `owned-output-patterns.txt` and validate with
  `./gradlew verifySelectiveLeafOwnershipMetadata buildJar`.
- Focused leaf-local boundary tests now freeze the current extracted layout.
  `RuntimeNodeKernelSplitPrepBoundaryTest`, `KernelContentBoundaryTest`,
  `KernelTransportBoundaryTest`, `KernelRoutingBoundaryTest`, `PlatformApiBoundaryTest`,
  `AdapterFcpBoundaryTest`, `BridgeFcpRuntimeBoundaryTest`, `AppHostBoundaryTest`,
  `CryptaPlatformSdkBoundaryTest`, `WebShellBoundaryTest`, `HttpLegacyAdminBoundaryTest`,
  `LegacyHttpBrowseBoundaryTest`, and `BridgeHttpRuntimeBoundaryTest` are the focused regression
  checks for leaf ownership/import boundaries. The runtime, kernel, platform, FCP, and HTTP
  boundary suites also enforce
  `package-info.java` coverage for the production packages they own.
- `:runtime-spi` is the JDK-only runtime/config API leaf. Its focused unit tests still live in the
  root test tree and run through the root build.
- `:platform-api` owns the transport-neutral Platform API v1, deterministic compatibility contract,
  app capability/audit decisions, app-vault route handlers, content/app-data/subscription/service
  routes, app-data backup/restore planning and commit routes, app-service dependency graph and
  grant-bundle routes, shared app-network budget service/store, app-update lifecycle service,
  app-data migration planning/execution and internal update snapshots, and host/operator-only beta
  dashboard/support-bundle routes. Its focused leaf tests now live under
  `platform-api/src/test/java`.
- `:platform-apphost` owns the transport-neutral out-of-process AppHost core, sandbox
  policy/status reporting, Linux bubblewrap provider selection, durable rollback records,
  data/cache quota enforcement, and focused leaf tests under `platform-apphost/src/test/java`.
- `:platform-app-ui` owns app-owned static UI route, isolated origin metadata, path, content-type,
  header, asset resolver, launch-proof bootstrap, and browser-session helpers plus focused tests
  under `platform-app-ui/src/test/java`.
- `:platform-appvault` owns the app secret and identity vault records, local key provider, grant
  metadata, redaction/audit value types, and focused tests under
  `platform-appvault/src/test/java`.
- `:platform-appdist` owns signed local app bundle digest, signature, verifier, manifest,
  app-data schema/migration metadata parsing, deterministic packager, and distribution-tool code
  plus focused tests under `platform-appdist/src/test/java`.
- `:platform-appcatalog` owns signed catalog source parsing, catalog writer/descriptor support,
  verification, `crypta:` catalog source fetching, app-store/API compatibility metadata,
  independent app-review receipt trust metadata, artifact download, safe ZIP extraction, and
  verified staging code plus focused tests under `platform-appcatalog/src/test/java`.
- `:platform-trustgraph` owns Trust Graph Local RC statement parsing, canonicalization,
  verification, process-local store/anchor behavior, lifecycle/status records, and deterministic
  scoring plus focused tests under `platform-trustgraph/src/test/java`.
- `:platform-design-system` owns the canonical local app UI CSS/JS resources plus safe
  asset-listing, hashing, and bundle-copy helpers. Its focused tests live under
  `platform-design-system/src/test/java`.
- `:platform-devtools` owns the standalone `crypta-app` developer CLI, including API snapshot and
  compatibility verification commands and offline app UI linting, plus focused CLI/linter tests
  under `platform-devtools/src/test/java`.
- `:platform-sdk-js` owns the dependency-free browser SDK resource and focused resource/boundary
  tests under `platform-sdk-js/src/test/java`.
- `:platform-web-shell` owns the browser-facing Web Shell leaf, including app/catalog/update/review
  views, app-service dependency/grant-bundle review, operator beta dashboard and app-data
  backup/restore controls, legacy explicit fallback actions, and focused leaf tests under
  `platform-web-shell/src/test/java`.
- `:runtime-alerts` owns the extracted leaf-safe `network.crypta.runtime.alerts` feed/model
  subset plus the detached `UserAlertSurface` used by legacy HTTP/admin code.
- `:runtime-node` is the extracted daemon runtime leaf. It now owns the remaining cyclic/high-level
  `network.crypta.client` body, the remaining peer/request/routing-engine side of
  `network.crypta.node`, the retained node-coupled transport/message execution code in
  `network.crypta.io*`, `network.crypta.runtime.*`, and the remaining daemon-coupled support
  helpers.
- `:adapter-fcp` owns the detached protocol-side `network.crypta.clients.fcp` tree.
- `:bridge-fcp-runtime` owns the concrete runtime-binding
  `network.crypta.clients.fcp.bridge` implementations, remains the only FCP leaf with the direct
  `:runtime-node` binding, and keeps its focused leaf tests under
  `bridge-fcp-runtime/src/test/java`.
- `:bridge-http-runtime` owns the concrete `network.crypta.clients.http.bridge` runtime-binding
  implementations plus the legacy HTTP `network.crypta.clients.http.geoip` helper package, with
  focused leaf tests under `bridge-http-runtime/src/test/java`.
- `:adapter-http-legacy-admin` owns the detached shared legacy `network.crypta.clients.http`
  shell, admin toadlets, `/api/v1/` and `/app/node/` bridge entrypoints, and the matching
  `network/crypta/clients/http/**` main resources.
- `:adapter-http-legacy-browse` owns the concrete browse/FProxy routes, toadlets, and helper
  models under `network.crypta.clients.http`, with focused leaf tests under
  `adapter-http-legacy-browse/src/test/java`.
- On the root test/runtime classpath, admin-owned HTTP resources often resolve from the leaf JAR,
  so tests must treat them as classpath resources rather than assume a plain filesystem `Path`.
- Most tests still live in the root project and compile against the leaf subprojects through the
  root build, but the extracted boundary suites now live with their owning leaves under each
  module's `src/test/java` tree.
- File-system-based l10n tests still run from the root project and use
  `foundation-config/src/main/resources/network/crypta/l10n/` as the main resource path.

## Guardrails (must follow)
- Always use the Gradle wrapper: `./gradlew …`
- Do **not** use `--no-daemon`.
- Do **not** pass `--parallel` or any custom JVM args on the CLI. Parallelism/JVM settings are controlled by `gradle.properties`.
- If Java runtime/toolchain cannot be located **or any command errors occur**, stop and ask for user approval before proceeding. Do not skip the command.

## Core build commands
- Build the node JAR:
  - `./gradlew buildJar`
- Clean build:
  - `./gradlew clean buildJar`
- The build prints the SHA-256 of `build/libs/cryptad.jar`.

## Testing
Always give enough running time (more than 15 minutes) for Gradle to complete tests.
When running ./gradlew test via OpenCode bash, set timeout ≥ 15 minutes (≥ 900,000 ms).

- Run all tests:
  - `./gradlew test`
- Run one test class:
  - `./gradlew test --tests *TestClassName`
- Run one test method:
  - `./gradlew test --tests *TestClassName.methodName`
- Run the focused leaf-local boundary suites:
  - `./gradlew :platform-api:test`
  - `./gradlew :platform-apphost:test`
  - `./gradlew :platform-app-ui:test`
  - `./gradlew :platform-appvault:test`
  - `./gradlew :platform-appdist:test`
  - `./gradlew :platform-appcatalog:test`
  - `./gradlew :platform-trustgraph:test`
  - `./gradlew :platform-design-system:test`
  - `./gradlew :platform-devtools:test`
  - `./gradlew :platform-sdk-js:test`
  - `./gradlew :platform-web-shell:test`
  - `./gradlew :kernel-content:test`
  - `./gradlew :kernel-transport:test`
  - `./gradlew :kernel-routing:test`
  - `./gradlew :runtime-node:test`
  - `./gradlew :adapter-fcp:test`
  - `./gradlew :bridge-fcp-runtime:test`
  - `./gradlew :bridge-http-runtime:test`
  - `./gradlew :adapter-http-legacy-admin:test`
  - `./gradlew :adapter-http-legacy-browse:test`
- Run the remaining root-owned Platform API/bootstrap slice explicitly against the root project:
  - `./gradlew :test --tests *DefaultNodeRuntimeBridgeFactoriesTest --tests *PlatformApiRouterTest --tests *PlatformApiAppsIntegrationTest`

## Compile-only / quick checks
- Compile only:
  - `./gradlew compileJava`
- Compile the support leaf when you touched extracted generic support classes:
  - `./gradlew :foundation-support:classes`
  - Representative moved types: `URIPreEncoder`, `IOUtils`, `LegacyFileSupport`, `HTMLDecoder`,
    file-backed buckets, generic HTTP request/upload helpers.
- Compile the crypto/keys leaf when you touched `network.crypta.crypt`, `network.crypta.keys`,
  or the moved bucket/length helpers:
  - `./gradlew :foundation-crypto-keys:classes`
  - Representative moved types: `NoFreeBucket`, `BucketTools`,
    `PrependLengthOutputStream`.
- Compile the reusable store leaf when you touched extracted `network.crypta.store`,
  `network.crypta.store.caching`, or `network.crypta.store.saltedhash` code:
  - `./gradlew :foundation-store:compileJava`
- Compile the neutral store-contracts leaf when you touched `BlockMetadata`, `GetPubkey`, or
  `StorableBlock`, or the store-maintenance alert seam:
  - `./gradlew :foundation-store-contracts:compileJava`
- Compile the wire/version leaf when you touched moved message/schema/address/version/probe code:
  - `./gradlew :interop-wire:compileJava`
- Compile the config/l10n leaf when you touched extracted config or l10n sources:
  - `./gradlew :foundation-config:classes`
- Compile the compat leaf when you touched extracted compatibility helpers such as
  `network.crypta.compat.bandwidth`:
  - `./gradlew :foundation-compat:classes`
- Compile the phase-1 kernel-content leaf when you touched extracted compile-neutral client/content
  classes:
  - `./gradlew :kernel-content:compileJava`
  - Representative moved types: `ClientEventProducer`, `SplitfileCompatibilityMode*`,
    `HTMLFilterPolicy`, concrete media/CSS/HTML parser/filter helpers, `InsertUriChecks`,
    `PersistentRequestCoordinatorContext`, `ClientGetterOptions`.
- Compile the phase-1 kernel-transport leaf when you touched extracted compile-neutral transport
  helpers:
  - `./gradlew :kernel-transport:compileJava`
  - Representative moved types: `SSLNetworkInterface`, `NetworkInterface`,
    `AllowedHosts`, `SocketHandler`.
- Compile the phase-1 kernel-routing leaf when you touched extracted compile-neutral routing/helper
  classes:
  - `./gradlew :kernel-routing:compileJava`
  - Representative moved types: `RequestPriorityClasses`, `RequestClient`, `SendableRequestItem*`.
- Compile only the runtime SPI leaf when you touched just that JDK-only API surface:
  - `./gradlew :runtime-spi:compileJava`
- Compile the Platform API leaf when you touched `network.crypta.platform.api`:
  - `./gradlew :platform-api:compileJava`
- Compile the AppHost leaf when you touched `network.crypta.platform.apphost`:
  - `./gradlew :platform-apphost:compileJava`
- Compile the app-owned static UI leaf when you touched `network.crypta.platform.appui`:
  - `./gradlew :platform-app-ui:compileJava`
- Compile the app vault leaf when you touched `network.crypta.platform.appvault`:
  - `./gradlew :platform-appvault:compileJava`
- Compile the app distribution leaf when you touched `network.crypta.platform.appdist`:
  - `./gradlew :platform-appdist:compileJava`
- Compile the app catalog leaf when you touched `network.crypta.platform.appcatalog`:
  - `./gradlew :platform-appcatalog:compileJava`
- Compile the Trust Graph Local RC leaf when you touched `network.crypta.platform.trustgraph`:
  - `./gradlew :platform-trustgraph:compileJava`
- Compile the developer app CLI leaf when you touched `network.crypta.platform.devtools`:
  - `./gradlew :platform-devtools:compileJava`
- Process and test the Platform SDK resource leaf when you touched
  `platform-sdk-js/src/main/resources/network/crypta/platform/sdk/js/crypta-platform.js`:
  - `./gradlew :platform-sdk-js:processResources :platform-sdk-js:test`
- Compile the Web Shell leaf when you touched `network.crypta.platform.webshell`:
  - `./gradlew :platform-web-shell:compileJava`
- Compile the extracted runtime-alerts leaf when you touched `network.crypta.runtime.alerts`:
  - `./gradlew :runtime-alerts:compileJava`
- Compile the extracted runtime-node leaf when you touched daemon runtime, node, client, xfer, or
  remaining support code that now lives there:
  - `./gradlew :runtime-node:compileJava`
- Compile the FCP adapter leaf when you touched `network.crypta.clients.fcp`:
  - `./gradlew :adapter-fcp:compileJava`
- Compile the concrete FCP bridge leaf when you touched `network.crypta.clients.fcp.bridge`:
  - `./gradlew :bridge-fcp-runtime:compileJava`
- Compile the shared legacy HTTP admin leaf when you touched shared shell/admin
  `network.crypta.clients.http` sources or admin-owned resources:
  - `./gradlew :adapter-http-legacy-admin:compileJava :adapter-http-legacy-admin:processResources`
- Compile the concrete legacy HTTP browse leaf when you touched browse/FProxy classes:
  - `./gradlew :adapter-http-legacy-browse:compileJava`
- Compile the concrete legacy HTTP runtime bridge leaf when you touched
  `network.crypta.clients.http.bridge` or `network.crypta.clients.http.geoip`:
  - `./gradlew :bridge-http-runtime:compileJava`
- Compile the root project and its unchanged test tree against the leaf-module layout:
  - `./gradlew compileJava compileTestJava`

## First-party app bundle checks
- Stage first-party app bundles, especially after changing `:platform-sdk-js` or
  `:platform-design-system` because Queue Manager, Publisher, Site Publisher, Profile Publisher,
  Social Inbox Preview, Feed Reader, and Trust Graph Local RC copy those assets into staged static UI
  bundles:
  - `./gradlew stageFirstPartyApps`
- Run app project tests:
  - `./gradlew :apps:queue-manager:test`
  - `./gradlew :apps:publisher:test`
  - `./gradlew :apps:site-publisher:test`
  - `./gradlew :apps:profile-publisher:test`
  - `./gradlew :apps:social-inbox:test`
  - `./gradlew :apps:feed-reader:test`
  - `./gradlew :apps:trust-graph:test`
- Sign and verify staged bundles only when signing/trusted-key inputs are available:
  - `./gradlew signFirstPartyApps`
  - `./gradlew verifyFirstPartyApps`

## Run tasks
- Run daemon entrypoint (`network.crypta.runtime.bootstrap.NodeStarter`):
  - `./gradlew run`
- Pass daemon CLI args:
  - `./gradlew run --args="--help"`
  - `./gradlew run --args="--version"`
- Run Swing launcher entrypoint (`Launcher`):
  - `./gradlew runLauncher`

## Run your build (manual deployment)
1. Build: `./gradlew buildJar`
2. Stop the running node
3. Replace the existing node JAR with `build/libs/cryptad.jar`
4. Restart the node

## Environment expectations
- Java: 25 or higher

## JUnit 6 notes (when touching tests)
- Tests run on the JUnit Platform (`useJUnitPlatform()` in build logic).
- Prefer JUnit Jupiter APIs; do not add JUnit 4/Vintage unless explicitly requested for migration-only work.
- JUnit 6 introduces `org.jspecify:jspecify` (nullability annotations). If strict dependency verification blocks resolution, follow the project’s dependency-verification refresh procedure (see the build tooling skill).

## Test helpers (test sources only)
- Package: `network.crypta.testsupport`
- Utility: `FileTestUtils` provides deterministic fill helpers for `OutputStream` / `Bucket` / `RandomAccessBuffer`.
- Do **not** call these helpers from production (`src/main`) code. If production code needs to fill helpers, use the non-test utilities (for example `FileUtil.fill(OutputStream, long)`).

## Tip: GitHub API rate limits during builds
If builds hit GitHub API rate limits, set `GITHUB_TOKEN` in the environment.
