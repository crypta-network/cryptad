# Crypta Plugin System — Architecture, Risks, and Roadmap

Last updated: 2025-08-22

## Executive Summary

Crypta’s plugin subsystem enables dynamic loading of JAR-based plugins, with a curated set of “official” plugins, automatic update fetching via the node’s main update USK, and UI/CLI/FCP management. Security today relies primarily on a hardcoded official catalog and Freenet integrity (CHK/USK), plus a minimum-version gate for official plugins. There is no cryptographic publisher signing, no capability sandbox, and limited collision resistance for names.

This report documents the current architecture, identifies risks and limitations, and proposes an actionable roadmap to modernize the system: stable plugin identities, signing and verification, permissioned APIs and isolation, robust updates and rollback, dependency management, and a better developer/user experience.

---

## Current Architecture

### Components Overview

- Official catalog: `OfficialPlugins`
  - Hardcoded list of official plugins with metadata: `name`, `group`, `minimumVersion`, `recommendedVersion`, flags (`essential`, `experimental`, `advanced`, `deprecated`, `unsupported`), `usesXML`, and an optional `FreenetURI` (CHK or USK).
  - `alwaysFetchLatestVersion` (USK only) forces a negative edition to fetch the latest on restart.

- Manager: `PluginManager`
  - Starts plugins from four sources: Official (by name), Freenet URI, HTTP/FTP URL, or local file.
  - Downloads into `plugins/` cache with timestamped names; cleans old cached copies.
  - Loads JARs via a dedicated `JarClassLoader`, instantiates `Plugin-Main-Class`, maps plugin interfaces (HTTP toadlets, IP detector, config toadlets, etc.), and registers them with the node.
  - For official plugins, enforces `minimumVersion` by querying `FredPluginRealVersioned.getRealVersion()` after instantiation.

- Update system: `NodeUpdateManager` + `PluginJarUpdater` (subclass of `NodeUpdater`)
  - For each official plugin which is loaded or desired, subscribes to the main update USK under `docName=<pluginName>`.
  - On new edition, fetches plugin blob to a persistent temp file, parses manifest (`Required-Node-Version`), and if newer than the currently running plugin, creates a user alert to update.
  - Deployment is gated by the revocation checker (`RevocationChecker`); after “no revocation found” (3 DNFs or recent success), writes `plugins/<name>.jar`, unloads the old instance, and reloads the plugin.

- User interfaces
  - Web UI (`PproxyToadlet`): lists loaded plugins, groups official plugins by category, provides forms to load official/unofficial/Freenet plugins, and offers an “Update” button when updates are available.
  - Text CLI (`TextModeClientInterface`): `PLUGLOAD:O/F/U/K` to load plugins from different sources.
  - FCP (`LoadPlugin`): supports loading plugins with `URLType` (official, file, url, freenet).

### Data and Identity Model

- Official identity: the `OfficialPlugins` “name” (e.g., `Library`) is the canonical label for UI and updates.
- Runtime identity: the plugin’s `Plugin-Main-Class` fully-qualified class name (FQN). Loading enforces uniqueness by FQN to prevent duplicate loads.
- Display name: official plugins are localized via `pluginName.<Name>` and `pluginDesc.<Name>`; non‑official plugins are shown by their provided spec (path/URL/URI).

### Update Lifecycle (Official Plugins)

1. Start: `PluginManager.startPluginOfficial(name)` fetches the JAR (official URI or node’s main update USK), caches it, verifies manifest, instantiates, checks `minimumVersion`, and registers.
2. Subscribe: `NodeUpdateManager.startPluginUpdater(name)` spawns a `PluginJarUpdater` bound to `updateURI/<name>`.
3. Detect: On new USK edition, `NodeUpdater.maybeUpdate()` fetches the blob and stores it.
4. Validate: `PluginJarUpdater` parses `Required-Node-Version` and compares `fetchedVersion` vs `getRealVersion()` of the loaded plugin.
5. Offer: If newer, create a `UserAlert` to update.
6. Gate: `RevocationChecker` ensures the revocation key isn’t present; after 3 DNFs or recent success, `onNoRevocation()` proceeds.
7. Deploy: Write `plugins/<name>.jar`, unload old plugin, reload new, unregister the alert.

---

## Strengths

- Simple JAR-based model with per-plugin classloaders.
- Clear official catalog defining supported plugins and their minimum/recommended versions.
- Centralized update mechanism using the node’s main USK; unified gating via a revocation checker.
- UI and CLI coverage for loading, updating, and management.

---

## Risks and Limitations

### Identity and Impersonation

- UI confusion from name collisions: The official “available plugins” list removes entries by comparing a loaded plugin’s simple class name against official names. An unofficial plugin with a main class whose simple name matches an official plugin name can hide the official entry in the add‑list. This is a known vector for social engineering.
- FQN uniqueness: Loading prevents two plugins with identical `Plugin-Main-Class` FQNs; however, this alone doesn’t prevent misleading branding or “preemptive” loading to block an official plugin.

### Trust and Integrity

- No publisher signing: There is no cryptographic verification of plugin publishers (official or community) aside from CHK integrity (and USK recency). Unofficial loads via file/URL have no built‑in authenticity guarantees.
- `usesXML` flag is present in `OfficialPlugins` but not enforced at load time to block known‑vulnerable JVMs.

### Safety and Isolation

- No runtime sandbox: Plugins run in-process with full JVM permissions and broad access to node APIs once they get the `PluginRespirator`.
- No resource controls: No CPU/memory quotas, I/O policing, or network/file access controls per plugin.

### Updates and Rollback

- Official updates rely on the main node update USK; per‑plugin USKs are supported only via special flags (`alwaysFetchLatestVersion`) and require restart to pick up changes.
- No formal rollback path for plugins on failed deployment; relies on restart/load behavior and cached copies.

### Dependencies

- No dependency model for plugins (no semantic version constraints or conflict resolution).

### Developer and User Experience

- No signed marketplace or verified repository listing; discovery is limited to the hardcoded official catalog and manual entries.
- No formal SDK, local test harness, or hot‑reload for plugin authors.

---

## Recommendations and Roadmap

### 1) Stable Plugin Identity (High Priority)

- Introduce a mandatory `Plugin-Id` (UUID) in plugin manifest.
- Use `Plugin-Id` as the primary key throughout: loading, listing, updates, and persistence. Map human‑friendly names as metadata, not identifiers.
- UI and manager logic: stop comparing by simple class name. For official availability filtering, compare by official catalog entry (by id or exact official name mapping), not by a loaded plugin’s class name.

Acceptance criteria:
- Each loaded plugin displays its `Plugin-Id`, publisher, and version in the UI.
- The “Add official plugin” list cannot be hidden by any unofficial plugin.

### 2) Publisher Signing and Verification (High Priority)

- Require JAR signing for official plugins (PKIX or PGP) and verify at load time before classloading.
- Pin official publishers’ keys at group-level (e.g., `com.crypta.plugins`) with a trusted keyring bundled in the distribution and updated via the node’s main USK.
- For unofficial plugins, support a “community verified” tier if signatures match a whitelist; otherwise show as “unverified” with prominent warnings.
- Record and display signature status and certificate chain in the UI.

Acceptance criteria:
- Loading an unsigned (or incorrectly signed) official plugin fails with a clear error.
- UI shows signature status for each plugin (Official/Verified/Unverified).

### 3) Capability‑Gated APIs and Isolation (High Priority)

- Define a capability model for node APIs (e.g., FCP server, HTTP endpoints, disk write, network egress, peer access, config changes).
- Plugins declare capabilities in manifest; the loader mediates access via wrappers. Deny by default.
- Consider JPMS module layers to restrict reflective access to internal packages.
- For stronger isolation, add an optional “out‑of‑process” runner: launch certain plugins in a separate JVM with a minimal RPC boundary. Add per‑plugin CPU/memory limits (OS‑level cgroups where available).

Acceptance criteria:
- A plugin requesting undeclared capabilities cannot obtain node services for them.
- An out‑of‑process plugin failure cannot crash the node; resource limits are enforced.

### 4) Update Model Enhancements (Medium Priority)

- Per‑plugin update channels in manifest: `stable`, `beta`, `dev`, with user‑selectable policy.
- Staged rollouts and rollback: keep last‑known‑good JAR per plugin; one‑click rollback on failure.
- Replace `alwaysFetchLatestVersion` with channel policy and periodic checks (no restart required).
- Integrate delta updates where practical to reduce bandwidth.
- Optional plugin‑specified update URIs in manifest (with strict approval workflow): allow plugins to point to their own USKs or signed HTTP endpoints while still passing through revocation gating and signature verification. Disabled by default; opt‑in per plugin with explicit user consent.
- Multi‑source verification (advanced): optional consensus policy requiring multiple independent sources (e.g., two USKs/publishers) to agree on an artifact hash before deployment. Long‑term item due to complexity.

Acceptance criteria:
- Users can opt into `beta` channel per plugin; rollback is exposed in UI and functional.

### 5) Dependency Management (Medium Priority)

- Add manifest fields for dependencies (`group`, `artifact`, `version range`, checksum/signatures).
- Resolve dependencies into isolated classloaders per plugin; detect and prevent conflicting transitive versions.
- Optionally support shared “platform” libraries with strict version pinning and signing.

Acceptance criteria:
- Plugin with unsatisfied or conflicting dependencies cannot load; UI shows actionable error.

### 6) Security Hardening (Medium Priority)

- Enforce `usesXML` at load time: block on known‑vulnerable JVMs or require safe XML parsers.
- Static checks: ban sensitive reflective access by default; audit dangerous packages unless explicitly permitted by capability.
- Optionally scan plugin JARs with a lightweight analyzer (bytecode patterns) and flag risky APIs.

Acceptance criteria:
- Attempt to load a `usesXML` plugin on a vulnerable JVM yields a clear, safe refusal.

### 7) Marketplace and UX (Medium Priority)

- Build an in‑app marketplace: search, categories, signed metadata, publisher identity, ratings, and screenshots.
- Show detailed plugin info: `Plugin-Id`, publisher, signature status, required node version, permissions requested, changelog.

Acceptance criteria:
- The marketplace displays verified publisher info and differentiates official/verified/unverified.

### 8) Developer Experience (Medium Priority)

- Provide a Plugin SDK: project templates, local test harness, mocks for `PluginRespirator` and node services.
- Hot‑reload for development mode; structured API versioning with stability guarantees and deprecation windows.

Acceptance criteria:
- New plugin template builds and runs locally with a single command; API versioning documented.

### 9) Plugin Lifecycle Management (Medium Priority)

- Standardize graceful shutdown contracts with maximum wait and fallback termination strategies; surface shutdown timing in UI.
- Persist minimal plugin state across restarts using a per‑plugin storage area managed by the platform.
- Add resource usage monitoring (CPU, memory, IO, network) per plugin; expose in UI.
- Health checks and auto‑recovery: define optional plugin‑exposed health endpoints; restart unhealthy plugins according to policy.

Acceptance criteria:
- UI shows live resource usage per plugin; unhealthy plugins are detected and can be auto‑restarted according to policy.

### 10) Monitoring and Diagnostics (Medium Priority)

- Per‑plugin performance metrics dashboard (latency, throughput for HTTP toadlets, queue depth, errors).
- Crash/error reporting (locally stored, with opt‑in privacy‑preserving telemetry export).
- Network activity overview per plugin (host/port counters), respecting privacy constraints.

Acceptance criteria:
- Operators can view per‑plugin metrics and recent errors; optional telemetry export is off by default and anonymized.

### 11) Plugin Communication (Medium Priority)

- Event bus for inter‑plugin communication with namespaced topics and type‑safe payloads.
- Plugin service discovery/registration so plugins can expose typed APIs safely.
- Explicit capability grants required for bus publish/subscribe to avoid covert channels.

Acceptance criteria:
- Plugins can publish/subscribe to events under granted namespaces; bus enforces permissions.

### 12) Resource Management (High to Medium Priority)

- Enforce per‑plugin CPU and memory quotas (where supported) in out‑of‑process mode; soft‑limits with monitoring in in‑process mode.
- Filesystem isolation via virtualized per‑plugin data directories; opt‑in access to additional paths.
- Network access controls per plugin (destination restrictions, rate limits) driven by capabilities.
- Resource pooling APIs (HTTP clients, thread pools) with quotas to prevent exhaustion.

Acceptance criteria:
- Misbehaving plugins cannot starve the node; resource policy violations are visible in diagnostics.

### 13) Advanced Plugin Types (Long‑Term)

- Multi‑language support:
  - WebAssembly runtime support for safe, portable plugins.
  - JavaScript/TypeScript via GraalVM (or alternative polyglot runtimes) with capability gates.
  - Native integrations via JNI with strict sandbox and limited use cases.
- Execution models:
  - Container/OCI or microservice plugins (external processes) for strong isolation.
  - Web‑based UI plugins via iframe isolation for management consoles (no node access unless granted).

Acceptance criteria:
- At least one non‑JVM language path exists behind capabilities and isolation; documentation and examples provided.

### 14) Governance and Community (Medium to Long‑Term)

- Publisher identity verification program and certification for official/community‑verified tiers.
- Community submission workflow with automated checks (lint, build, signing) and human review queue.
- Public documentation, templates, and forums for developers.
- Bounty/funding mechanisms for high‑value plugins.

Acceptance criteria:
- Clear contributor pipeline from submission to verified listing with auditable steps.

### 15) Analytics and Telemetry (Medium to Long‑Term)

- Optional, privacy‑preserving usage metrics for the ecosystem (opt‑in, aggregated, anonymized).
- Cross‑plugin performance benchmarking harness.
- Vulnerability disclosure process and security advisories binding to plugin IDs and versions.

Acceptance criteria:
- Operators can opt‑in to share anonymized usage; advisories reference `Plugin-Id` and versions.

### 16) Orchestration and Integration (Long‑Term)

- Plugin workflows/pipelines and conditional loading based on configuration or runtime signals.
- Failover/redundancy for critical capability providers (e.g., multiple bandwidth indicators).
- External integrations: OAuth flows, third‑party APIs behind explicit capabilities and user consent.

Acceptance criteria:
- Operators can define simple load conditions and switch between equivalent providers without downtime.

---

## Immediate Bugfixes and Low‑Risk Improvements

1. Fix official list filtering:
   - In `PproxyToadlet`, filter official availability using the official name against the manager’s “known plugin names”, not a plugin’s simple class name. Alternatively, check `PluginInfoWrapper.isOfficialPlugin()` to avoid unofficial plugins hiding official entries.

2. Enforce `usesXML` gating:
   - At load time, block `usesXML` plugins when JVM/XML libraries are known vulnerable or enforce safe XML libraries.

3. Essential plugin version cap:
   - Honor the `FIXME` comment: ensure connectivity-essential plugins do not have `minimumVersion` bumped beyond what updaters will deploy automatically; document policy.

4. Side‑effect minimization:
   - Pre‑validate version requirements before plugin constructor side effects where possible (e.g., query a version service or manifest property first) to avoid temporary thread spawns for ultimately rejected loads.

---

## Migration Strategy

1. Identity-first: introduce `Plugin-Id` and start displaying it without breaking existing loads. Record and persist mapping from (FQN, official name) → Plugin-Id.
2. Signing opt‑in: start by signing official plugins and verifying at load; warn for unsigned. Later, require signatures for official and “community verified”.
3. Capability opt‑in: begin with read-only capabilities and HTTP-only plugins; expand to other capabilities over time. Provide shims for legacy plugins.
4. Update channels: add per‑plugin channel configuration surfaced in UI; default to `stable`.
5. Dependencies: add manifest fields, warn-only initially; enforce after a grace period.

Long‑term items:
- Multi‑language runtimes, advanced execution models (containers/microservices), marketplace governance, and privacy‑preserving telemetry should follow once identity/signing/capabilities are mature.

Backwards compatibility:
- Legacy plugins without `Plugin-Id` or signatures remain loadable initially, but show warnings and reduced trust tier. Provide a documented deadline for stricter enforcement.

---

## Implementation Plan (Incremental)

Phase 1 (Security Baseline)
- Add `Plugin-Id` (manifest), display in UI.
- Fix official availability filtering logic.
- Implement signature verification for official plugins; bundle trusted keys.
- Enforce `usesXML` gating.

Phase 2 (Isolation & Policies)
- Introduce capability declarations and middleware wrappers for node services.
- Optional out‑of‑process runner for high‑risk plugins.
- Add per‑plugin update channels + rollback cache.
- Add lifecycle management primitives (state storage, health checks), per‑plugin diagnostics, and initial event bus.

Phase 3 (Dependencies & Marketplace)
- Implement dependency metadata and loader isolation/conflict checks.
- Build a signed plugin index and marketplace UI.
- Provide SDK, templates, and a local test harness.
- Add resource policy enforcement (quotas, FS/network ACLs) in out‑of‑process mode; expand to in‑process soft limits.
- Explore multi‑language support (WASM/GraalVM) and advanced plugin types where isolation guarantees suffice.

---

## Acceptance Criteria Summary

- Identity: Every plugin shows a stable `Plugin-Id` and cannot hide or spoof official entries.
- Signing: Official plugins are signature‑verified; UI shows trust tier for all plugins.
- Isolation: Capability enforcement in place; optional out‑of‑process mode available.
- Updates: Channel selection and rollback work; revocation gating remains respected.
- Dependencies: Loader validates and isolates dependencies; clear errors on conflicts.
- UX/DevX: Marketplace available; SDK with templates and docs provided.

---

## Appendix: Key Code Touchpoints

- Catalog: `src/main/java/network/crypta/pluginmanager/OfficialPlugins.java`
- Manager & Loader: `src/main/java/network/crypta/pluginmanager/PluginManager.java`, `PluginDownLoader*`
- Updates: `src/main/java/network/crypta/node/updater/NodeUpdateManager.java`, `PluginJarUpdater.java`, `NodeUpdater.java`, `RevocationChecker.java`
- UI: `src/main/java/network/crypta/clients/http/PproxyToadlet.java`
- CLI/FCP: `src/main/java/network/crypta/node/TextModeClientInterface.java`, `src/main/java/network/crypta/clients/fcp/LoadPlugin.java`
