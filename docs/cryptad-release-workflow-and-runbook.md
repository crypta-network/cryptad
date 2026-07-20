# Cryptad Release Workflow and Runbook

> Updated July 13, 2026, for the manifest-driven certification CLI, candidate-bound v2 evidence,
> release-scoped workspaces, shared history archives, and the production beta pipeline. The release
> report aggregates interop, performance, app-platform, third-party developer beta, multi-node beta
> soak and upgrade drills, beta documentation, public-beta hardening, operator beta recovery,
> network-scale soak, ecosystem RC certification, optional live-network beta certification,
> app-review governance, catalog, app-owned UI, legacy-admin retirement, and CI evidence.

## Overview
- Purpose: publish a Cryptad release so running nodes discover a new `info/<edition>` descriptor, download OS-specific installers, and guide operators through installation without self-replacing the running JAR.
- Mechanism: `CoreUpdater` subscribes to an update USK, fetches a JSON manifest (`core-info.json`), detects the current platform via `AppEnv`, selects the best package (`<arch>.<ext>`), and downloads it under `updates/core/<version>/`. The legacy HTTP action layer currently lives in `:adapter-http-legacy-admin` at `network.crypta.clients.http.updater.CoreActionToadlet`, which exposes `/core-update/` for Download / Install / Open-in-store actions while progress appears in the global Alerts panel.
- Scope: Core releases now ship native installers or archives (DEB/RPM/DMG/EXE/Flatpak/Snap/tar). The legacy plugin runtime has been removed, so this runbook only covers core package releases.

## Artifacts and Keys
- **Update USK**: `USK@<update-key>/info/<BUILD_N>` (editions increment per release build).
- **Revocation SSK**: `NodeUpdateManager.REVOCATION_URI`; inserting a message disables automatic downloads and surfaces the text in Alerts.
- **Core Info descriptor** (`core-info.json`):
  ```json
  {
    "version": "1",
    "release_page_url": "https://crypta.network/releases/1",
    "changelog_chk": "CHK@...",              // optional short changelog text
    "fullchangelog_chk": "CHK@...",          // optional detailed changelog text
    "packages": {
      "amd64.deb": {
        "chk": "CHK@...",                    // required for direct downloads
        "size": 97216543,                     // optional, bytes
        "store_url": null                     // optional: fallback store link
      },
      "amd64.rpm": { "chk": "CHK@..." },
      "arm64.dmg": { "chk": "CHK@...", "size": 131072000 },
      "amd64.exe": { "chk": "CHK@..." },
      "amd64.flatpak": { "store_url": "https://flathub.org/apps/..." }
    }
  }
  ```
  - Keys follow `<arch>.<ext>` naming. Supported extensions include `deb`, `rpm`, `tar.gz`, `dmg`, `exe`, `msi`, `flatpak`, `snap`, `pkg`, `zip`.
  - `version` must be a base-10 integer string (for example `"1501"`). Noninteger values are treated as invalid for release gating and will not be advertised as updates.
  - `store_url` enables the "Open in Store" action when a direct download is not provided (Flatpak/Snap).
  - `changelog_chk` and `fullchangelog_chk` should point to CHK inserts containing Markdown or plaintext.
- **Optional extras**: continue to publish seed node lists, installer references, or IP databases separately (outside `info/`). Link to them from release notes if needed.

## Pre-Release Checklist
- **Versioning**: bump the integer `version` in `build.gradle.kts`. Ensure `Version.currentBuildNumber()` reflects the new build after `./gradlew build`.
- **Release notes**: prepare short (user-facing) and full (developer) changelog text files for CHK publishing.
- **Package matrix**: decide which OS/arch artifacts to ship this cycle. The minimum recommendation is macOS (DMG), Windows (EXE), Linux desktop/server (DEB + RPM), and Flatpak if maintained.
- **Environment validation**: run smoke tests on each target OS using `build/jpackage/Crypta`, `build/distributions/`, or the staged Flatpak bundle. Ensure the installers launch and locate `cryptad-dist/` correctly.
- **Dependency review**: verify updater metadata and package checksums are consistent with produced artifacts.

## Platform Release Gates
Treat these as release blockers, in order:

When the candidate targets the Stable 1.0 product milestone, run the protected
[Stable 1.0 RC execution and release-freeze workflow](stable-1.0-rc-execution-and-release-freeze.md)
after the prerequisite production evidence passes and before generating release descriptors,
tags, or publication material. The RC command uses the existing `stable-review` profile and the
repository's integer build identity; it does not replace the `v<build-number>` tag policy. A
blocker fix after freeze invalidates the old archive, checksums, provenance, and freeze and requires
a complete authorized re-freeze to final `no-drift`.

An RC `go` or policy-compliant `go-with-waivers` authorizes review of the frozen candidate. It does
not authorize a tag, GitHub Release, merge, update-descriptor insertion, or Stable 1.0 GA
publication. Those remain separate release-manager operations later in this runbook.

After selecting the final RC, follow the
[Stable 1.0 RC validation and GA promotion runbook](stable-1.0-rc-validation-and-ga-promotion.md).
The `stable-ga` command authenticates the latest successful protected RC lineage and consumes the
exact RC summary, freeze, sidecar, outer archive, product, checksums, and provenance. It never
rebuilds the candidate. Its protected post-freeze evidence must include at least 24 hours of real
soak bound to the frozen product digest plus the required install, upgrade, rollback, migration,
backup/restore, live-network, interop, performance, security, sandbox, and support results.

Keep these Stable GA stages separate:

1. side-effect-free validation in the `stable-ga` component;
2. explicit GA authorization bound to the final immutable validation identity and exact RC digests;
3. attestation of the exact validation and authorization bytes through the protected
   `stable-1-0-ga-evidence` environment; and
4. explicitly dispatched publication through the protected `stable-1-0-ga` environment.

The Stable RC and Stable GA workflows use the same integer-build concurrency group. The lock spans
validation, protected-environment waits, and publication; do not run a refreeze concurrently with
GA. If a blocker requires an urgent refreeze while GA is waiting for approval, cancel GA, inspect
the shared build queue, and only then dispatch the refreeze. GitHub keeps at most one pending run
for a concurrency group, so do not treat a queued run as an audit log or rely on it to preempt the
currently running operation.

Run the Stable GA workflow with `publish=false` first. The protected evidence job attests the exact
post-freeze validation and authorization files from that passing run. A later `publish=true`
dispatch must use the identical attested bytes and the exact `release/<build-number>` ref and
candidate commit. The publication job verifies those attestations and reruns `stable-ga` after its
environment approval and before every public-state mutation. It repeats the current-time gate
before recording completion. Repository paths, HTTPS downloads, and Actions artifacts are input
transports; they are not sufficient producer authentication by themselves.

Supply the exact migrated previous-candidate envelope whose digest was frozen by PR-283, plus the
SHA-256 of the published predecessor product exercised by the upgrade drill. The workflow rejects
an envelope that differs from either the selected freeze or RC provenance. Stable GA derives the
predecessor release ID and integer build from that envelope and binds them, the envelope digest,
and the product digest into the authorization identity.

After publication approval, the job also refreshes the selected Stable RC workflow run and every
matching freeze/refreeze attempt directly from GitHub. It orders completed attempts by their
GitHub completion/update timestamps, rejects an active, ambiguous, or newer attempt, and verifies
that the retained lineage record still identifies the latest successful freeze before any tag or
Release operation begins. It performs this refresh even when all matching public state already
exists, and repeats it before recording a successful receipt.

A validation `go` does not claim publication. The publication job must verify the release branch
`release/<build-number>`, use the repository-required `leumor` identity for GitHub operations,
create or verify the annotated `v<build-number>` tag and exact GitHub Release assets, and verify
every asset at the declared public artifact base and the frozen stable catalog independently at its
primary, mirrors, and authorized rollback location. Configure the `stable-1-0-ga` environment's
`STABLE_CATALOG_TRUSTED_KEYS_BASE64` secret with the production trusted catalog public-key
properties registry; never put private signing material in it. It never merges the release branch
automatically. The final receipt must be
`publication-complete`; a partial or mismatched result is `publication-verification-failed` and
must not be announced as GA. Its failure audit path only observes remote state and writes a
sanitized receipt; it never resumes a tag or draft-Release mutation after a failed lineage or
conflict check.

All seven assets must already be staged at the independently managed public artifact base before
the `publish=true` dispatch. The workflow freshly resolves and verifies every exact byte at that
base before its first tag or Release mutation, and repeats the check after GitHub publication. Do
not configure a GitHub Release URL that does not exist until this same workflow publishes it.

The release branch is not a one-time preflight assertion. The job rereads it at every publication
mutation boundary, before creating the tag reference after an annotated tag object was created,
and before writing `publication-complete`. Any movement away from the authorized candidate commit
fails closed and is recorded without resuming publication from the audit path.

1. **Normal Gradle checks** - run the standard repository build and test path before any publish step. For release readiness, this means the usual Gradle verification path for the branch, including `./gradlew clean build` and any project-required test tasks used in CI.
2. **Production beta app-ecosystem pipeline, when shipping production beta app artifacts** - use
   the top-level production beta wrapper when the release includes first-party app bundles,
   signed catalog output, review receipts, live-network beta evidence, and a redacted public app
   artifact archive:
   ```bash
   cp tools/release-certification/manifests/production-beta.example.json \
     build/production-beta.json
   # Replace every placeholder before running the protected pipeline.
   python3 tools/release-certification/certify.py production-beta --manifest build/production-beta.json
   ```
   Select `developer-dry-run` in the manifest for local or PR-safe rehearsal and
   `release-candidate` for release-branch evidence without production signing or protected live
   inputs.
   A promotable `production-beta` run requires production signing inputs, a complete in-pipeline
   Gradle build/stage/sign run, a clean git workspace, a public HTTPS artifact base URI, required
   live-network beta evidence, required multi-node beta soak evidence, ecosystem RC certification,
   a passing final artifact redaction scan, and a passing go/no-go dashboard redaction report.
   Signed catalog bundle URLs resolve under the published artifact root, for example
   `<base>/build/app-bundles/<app>-<version>.zip`. Preserve
   the marked `<out-root>/<release-id>/production-beta/` workspace, including its `summary.json`,
   `report.md`, `redaction-report.json`, `artifacts/`, checksums, and public archive. The workflow,
   modes, required secrets, artifact layout, cleanup guard, and rerun rules are documented in
   [production-beta-release-pipeline.md](production-beta-release-pipeline.md).
   Read [production-beta-go-no-go-dashboard.md](production-beta-go-no-go-dashboard.md) first. It is
   the release-manager launch surface that rolls the production beta summary, ecosystem matrix,
   redaction report, waivers, live-network evidence, and multi-node evidence into `go`, `no-go`, or
   `go-with-waivers`; drill into the detailed summaries only after reviewing that decision. Treat
   `go-with-waivers` as launchable only when every
   residual blocker has a valid, scoped, approved, and unexpired waiver and no non-waivable
   redaction, signing, fixture-evidence, live-network, sandbox, multi-node, production summary, or
   artifact-hygiene gate failed.
   Confirm `production-security.response-runbook` passes in the production beta summary, and review
   the compact `multiNodeBetaSoak` and `developerBetaProgram` sections before promotion. Security
   releases or app ecosystem incident responses must also run
   `python3 tools/release-certification/certify.py security-response verify --manifest build/release-candidate.json`,
   `python3 tools/release-certification/certify.py security-response drill-run-all --manifest build/release-candidate.json`,
   and
   `python3 tools/release-certification/certify.py security-response drill-verify-all --manifest build/release-candidate.json`.
   Preserve the `security-response/drill-run-all/` component, the seven per-scenario drill
   artifacts, and any generated redacted security release notes draft as release evidence. Draft
   public notes from [templates/security-release-notes.md](templates/security-release-notes.md).
   Missing, failed, stale, fixture-only production, malformed, or redaction-unsafe drills are
   production blockers. The operational procedure is
   [production-security-response-runbook.md](production-security-response-runbook.md).
3. **Release certification report** - generate the release-candidate report after the source gates
   below have produced their summaries:
   ```bash
   cp tools/release-certification/manifests/release-candidate.example.json \
     build/release-candidate.json
   # Replace every placeholder and bind all v2 inputs to release.id.
   python3 tools/release-certification/certify.py release-certification --manifest build/release-candidate.json
   ```
   Preserve the marked `<out-root>/<release-id>/` workspace, especially the
   `release-certification/`, `network-scale-soak/`, and `multi-node-beta/` components. Restore the
   previous release's sanitized summaries through the manifest and use `migrate-v1` for the first
   v2 candidate. If history is unavailable, record that limitation in the release log; set
   `requirements.history=true` for promotion runs where regression context is mandatory.
   Treat the ecosystem certification matrix as the release-manager checklist for required
   evidence coverage, ecosystem gate coverage, first-party app coverage, docs coverage, waivers,
   and row-level regressions. The workflow is documented in
   [release-certification.md](release-certification.md).
   Confirm the final `ecosystem.rc-certification` gate and
   `ecosystem-rc-certification-gate` matrix row match the release plan. That row is the
   release-manager summary for required-evidence status, ecosystem gate status, matrix coverage,
   network-scale soak, required live-network beta evidence, redaction, and waivers. Its scope and
   non-claims are documented in
   [ecosystem-rc-certification-gate.md](ecosystem-rc-certification-gate.md).
   Production beta runs also surface this gate through
   [production-beta-go-no-go-dashboard.md](production-beta-go-no-go-dashboard.md), which is the
   final launch decision artifact for app-ecosystem production beta candidates.
   Confirm the `network-scale-soak-and-subscription-budget` row and
   `network-scale.rc-soak-summary` evidence are present. The wrapper generates a fresh simulated
   summary by default. Set manifest `inputs.networkScaleSoak` only for an externally collected
   `simulated-rc-soak` or `live-rc-soak` summary that uses the same redacted schema. Record any
   external soak source and redaction status in the release log.
   Confirm the `multi-node-beta-soak-and-upgrade-drill` row and `multi-node-beta.*` evidence are
   present. The unified command generates a fresh deterministic summary by default. Set
   `inputs.multiNodeSoak` only for an externally collected redacted summary. Set
   `inputs.multiNodeSoakConfig` and `commands.multi-node-beta.mode` when generating a
   release-specific topology. Production beta
   promotion requires passing multi-node evidence unless the run is explicitly non-promotable.
   Confirm the `third-party-developer-beta-program` row and `third-party-developer.*` evidence are
   present. The evidence must cover the public developer beta docs, `hello-stable` template,
   checked-in sample app, submission checklist, compatibility support window, feedback workflow,
   plugin migration path, sample submission/review/catalog-candidate flow, operator-only negative
   path, and redaction checks.
   Confirm `app-platform.docs-portal`, `app-platform.beta-program`,
   `app-platform.beta-tutorials`, `app-platform.docs-redaction`, and the
   `app-platform-beta-docs-and-program` matrix row are present. Docs-only gaps require an explicit
   release-manager waiver; redaction findings must remain blockers.
   Also confirm the deterministic `public-beta-security.*` evidence ids, `operator-beta.*`
   evidence ids, `operator-rc.*` evidence ids, `operator-beta-ux-and-recovery` and
   `operator-rc-recovery-and-support-workflow` matrix rows, and disabled-or-passing
   `live-network-beta-certification` row match the release plan. Live-network beta evidence is
   optional unless the release manager sets manifest `requirements.liveNetwork=true`; stale live-network
   summaries must not be copied when the mode is disabled.
4. **First-party app staging** - stage repo-owned AppHost bundles with the app module tasks or `./gradlew stageFirstPartyApps`. The app workflow source of truth is [app-distribution.md](app-distribution.md).
5. **First-party app signing and verification** - sign with the intended release or staging key inputs, then verify with the matching trusted public key inputs. Gate promotion on successful `./gradlew signFirstPartyApps` and `./gradlew verifyFirstPartyApps` runs. Keep private signing keys outside the repository.
6. **App catalog smoke, when catalog sources ship** - verify each signed catalog source refreshes,
   validates artifact size/SHA-256, extracts safely, and can install or update through
   `/api/v1/app-catalogs`. For first-party live USK catalog publication, verify the report includes
   `catalog.live-usk-publication` and `catalog.live-usk-source-verification`; the public source is
   `crypta:USK@.../cryptad-app-catalog.properties`, and
   `cryptad-app-catalog.signature` is the sibling at the same USK edition. The catalog contract is
   documented in
   [app-catalogs.md](app-catalogs.md).
   When stable or beta catalog operations are part of the release, also verify
   `catalog.operations-and-mirrors` passes. That deterministic evidence covers primary-plus-mirror
   source metadata, signed mirror fallback, stale/downgrade prevention, bounded verified revision
   history, explicit rollback re-verification, signing-key rotation status, emergency advisory
   refresh, Platform API/Web Shell wiring, docs coverage, and redaction without requiring live
   mirror infrastructure. The operational runbook is
   [catalog-operations-and-mirrors.md](catalog-operations-and-mirrors.md).
   PR-246 live-network beta certification is an explicit release-manager wrapper mode. Run it only
   with a localhost node, redacted environment variables, and disposable live fixtures unless the
   release manager is intentionally publishing the candidate first-party beta catalog. It becomes
   release-blocking only when required live-network beta mode is enabled:
   ```bash
   CRYPTAD_CERT_LIVE_NETWORK_BETA=1 \
   CRYPTAD_CERT_REQUIRE_LIVE_NETWORK_BETA=1 \
   CRYPTAD_CERT_NODE_BASE_URL=http://127.0.0.1:8888 \
   CRYPTAD_CERT_FORM_PASSWORD=<redacted> \
   CRYPTAD_CERT_LIVE_CATALOG_SOURCE=crypta:USK@<catalog-key>/cryptad-app-catalog.properties \
   CRYPTAD_CERT_LIVE_CATALOG_EXPECTED_KEY_ID=crypta-first-party-beta \
   CRYPTAD_CERT_LIVE_CONTENT_FETCH_URI=crypta:CHK@<artifact-key> \
   CRYPTAD_CERT_LIVE_FEED_USK_URI=crypta:USK@<feed-key>/feed.json \
   CRYPTAD_CERT_LIVE_TEST_INSERT_URI_FILE=<protected-insert-uri-file> \
   python3 tools/release-certification/certify.py release-certification --manifest build/release-candidate.json
   ```
   The private insert URI must be the bare private USK directory insert URI for the same catalog
   parent as the public `crypta:USK@<catalog-key>/cryptad-app-catalog.properties` fixture source.
   Load it through `CRYPTAD_CERT_LIVE_TEST_INSERT_URI_ENV` or
   `CRYPTAD_CERT_LIVE_TEST_INSERT_URI_FILE`, never as an inline shell assignment. Use env-name
   indirection only when a protected channel already exported the private URI and the command names
   that variable without showing its value; if both are present, env-name indirection wins
   deterministically. In required mode `CRYPTAD_CERT_LIVE_CATALOG_EXPECTED_KEY_ID` must match the
   node-observed public `signatureKeyId` from the verified catalog summary, otherwise catalog
   evidence fails.
   Preserve only the sanitized summary, report, and matrix, and assume live
   synthetic content may remain retrievable and may not be deletable. Do not use real keys,
   production secrets, or user content in fixture runs.
   The live workflow mints app browser sessions from each configured static app bootstrap and keeps
   those tokens in memory only. If a required app cannot provide a bootstrap session, required mode
   fails instead of retrying as the host operator. Cleanup deletes only an app that was absent
   before the run and installed successfully by the smoke; use disposable app ids when certifying
   on a node that already has first-party apps installed.
6. **Developer app CLI smoke, when `:platform-devtools` changes** - run
   `./gradlew :platform-devtools:test` and `./gradlew :platform-devtools:installDist`, then verify
   `platform-devtools/build/install/crypta-app/bin/crypta-app --help`. When template,
   compatibility, mock Platform API, or submission commands changed, also exercise the
   `hello-stable` path or confirm `third-party-developer.*` evidence is passing. The CLI contract
   is documented in [app-dev-cli.md](app-dev-cli.md); the external developer path is documented in
   [third-party-developer-beta-program.md](third-party-developer-beta-program.md).
7. **App-owned UI smoke and lint, when static UI apps ship** - open the advertised `uiUrl` for at
   least one static UI app, confirm nested-entry assets load on the isolated app origin or the
   `/apps/{appId}/` compatibility fallback, and verify no filesystem path leaks appear in error
   responses. Also verify the release certification report includes `app-ui.design-system`,
   `app-ui.lint`, and `app-ui.first-party-adoption` so first-party bundles have canonical local
   design-system assets, strict UI lint summaries, and visible permission disclosure. The route
   contract is documented in [app-owned-ui.md](app-owned-ui.md); the design-system/lint contract is
   documented in [app-ui-design-system.md](app-ui-design-system.md).
8. **App-vault, app-service, trust graph, and reference-app evidence** - verify the release
   certification report includes
   `app-vault.capabilities`, `app-platform.identity-profile-publish`,
   `app-platform.generated-document-insert`, `app-platform.content-fetch`,
   `app-platform.content-subscriptions`, `network-content.subscription-scheduler`,
   `app-platform.durable-app-data-store`, `app-platform.trust-graph-preview`,
   `app-platform.trust-graph-durable-store`, `app-platform.trust-graph-exchange`,
   `app-platform.trust-graph-rc-scope-and-safety`,
   `app-platform.trust-statement-signing`, `app-platform.social-message-signing`,
   `app-data.backup-restore-portability`, `app-services.registry`, `app-services.grants`,
   `app-services.dependency-graph`, `app-services.grant-bundles`,
   `app-services.grant-expiry-renewal`, `app-services.provider-revalidation`,
   `app-services.trust-score-provider`, `app-services.web-shell`, `app-services.redaction`,
   `app-services.dependency-redaction`, `reference-apps.content`,
   `reference-app.profile-publisher`, `reference-app.social-inbox`,
   `reference-app.social-inbox-signed-message`, `reference-app.social-inbox-subscriptions`,
   `reference-app.social-inbox-app-data`, `reference-app.social-inbox-trust-annotations`,
   `reference-app.social-inbox-service-grant`, `reference-app.social-inbox-rc-threading`,
   `reference-app.social-inbox-service-dependency`, `migration.social-mail-preview`,
   `reference-app.feed-reader`, `reference-app.feed-reader-subscriptions`,
   `reference-app.feed-reader-app-data`, `reference-app.trust-graph`,
   `reference-app.trust-graph-durable-exchange`, and
   `reference-app.trust-graph-app-data-preview`. Site Publisher is the
   content-oriented reference app;
   release evidence must prove its staged bundle, SDK usage, design-system adoption, permission
   disclosure, content/queue helper usage, and absence of vault/identity permissions. Profile
   Publisher is the identity-profile reference app; evidence must prove browser-safe app-owned
   identity creation, profile-document publishing, app-generated document insertion, declared
   vault/content/queue permissions, and redaction of tokens, form passwords, private insert URIs,
   raw request bodies, private keys, signatures, and absolute staging paths.
   Feed Reader is the content-subscription reference app; evidence must prove `content.fetch`,
   `content.subscribe`, `POST /api/v1/content/fetch`, `/api/v1/content/subscriptions`, SDK
   feed/subscription-helper usage, generated-feed publication permissions, scheduler backoff and
   dedupe metadata, and redaction of raw feed bodies, raw fetched content, raw request bodies,
   tokens, form passwords, private insert URIs, queue HTML, and local paths.
   Trust Graph Local RC is the local trust-service reference app; evidence must prove Platform API
   v7 trust routes, v10 URI import/audit routes, v22 import preview and anchor lifecycle routes,
   `trust.read`, `trust.write`, durable file-backed trust graph storage, bounded AppVault
   trust-statement signing, SDK trust exchange helper usage, trust-statement subscription
   management, generated trust-statement publication permissions, and redaction of raw trust
   documents, raw fetched content, raw request bodies, tokens, form passwords, private insert URIs,
   raw signatures, and local paths.
   App-data backup/restore evidence must stay host/operator-only and metadata-only in support
   bundles and restore previews; do not include backup payload values, raw app data, form
   passwords, tokens, or local paths in release artifacts.
   App-service dependency and grant-bundle evidence must prove operator-mediated grants without
   exposing raw service request bodies, raw subject URIs, raw trust data, provider app data, tokens,
   private insert URIs, or local paths.
9. **Trusted app-review receipt evidence** - verify the release certification report includes
   `app-review.trusted-receipts`, `app-review.policy`, `app-review.governance`,
   `app-review.reviewer-key-lifecycle`, `app-review.transparency-log`,
   `app-review.review-history-api`, `app-review.first-party-catalog`, and
   `app-review.first-party-review-chain` when first-party catalog evidence is part of the
   candidate. Review receipt evidence is independent of app and catalog signing keys. Keep
   reviewer private keys outside the checkout and out of release artifacts. The catalog/review
   contract is documented in [app-catalogs.md](app-catalogs.md) and
   [app-review-governance.md](app-review-governance.md).
10. **AppHost sandbox-provider evidence** - verify the release certification report includes
   `apphost.sandbox-provider`. The evidence is deterministic and does not require live bubblewrap in
   normal CI; it must prove the bubblewrap provider contract, required-sandbox fail-closed behavior,
   and token/path-free public status. Manual Linux smoke with host-installed `bwrap` is useful
   release-manager evidence when sandbox behavior changed.
11. **App update lifecycle evidence** - verify the release certification report includes
   `app-update.lifecycle`, `app-update.scheduler`, `app-update.live-catalog-refresh`, and
   `app-update.rollback`. The required offline evidence must cover manual/stage/apply-when-stopped
   policy behavior, background catalog refresh and app checks through the shared update service,
   live USK catalog refresh before candidate discovery, path-free staged and scheduler summaries,
   process health-gated apply, durable previous-bundle rollback, and the rule that rollback does
   not restore app data or cache. Optional live smoke may exercise install/update/rollback through
   localhost routes, but normal release-candidate evidence must not require a live node.
12. **Legacy-admin retirement evidence** - record the current retirement map, removal-wave policy,
   and diagnostics shape before any release promotion. The certification report must include
   primary-replaced, retained, and pending surface counts, confirm primary-replaced surfaces are
   absent from Web Shell fallback navigation, prove `legacy-admin.removal-wave-1` replacement and
   blocked-mutation behavior, prove `legacy-admin.removal-wave-2` safe-read replacement behavior,
   route-scope expansion metadata and partial mutation fallbacks, prove
   `legacy-admin.removal-wave-3` security-level redirects plus the exact
   `legacyFallback=security-levels` fallback, prove `legacy-admin.removal-wave-4` diagnostic
   redirects plus the exact `legacyFallback=diagnostic-export` plaintext export fallback, and prove
   `legacy-admin.removal-wave-5`, `legacy-admin.final-admin-surface`,
   `legacy-admin.browse-retained`, and `legacy-admin.emergency-fallback-retained`. Wave 5 is the
   maintenance-only final admin surface gate: it must show whether any new route ids were promoted,
   keep FProxy browse/content rendering and content filter retained, keep startup wizard/recovery
   flows, security recovery fallback, diagnostic export fallback, chat, translation, help, and
   node-to-node message routes explicit, and forbid new daily legacy-admin surfaces.
   Optional live evidence may read `GET /api/v1/diagnostics`; those counters are process-local and
   are not durable audit logs. The retirement source of truth is
   [legacy-retirement-plan.md](legacy-retirement-plan.md).
13. **Hyphanet interop Tier 1 smoke** - run the packaged-node compatibility smoke locally on Linux
   when the environment is prepared, or verify that the CI `interop-smoke` job passed for the
   release candidate. The gate is documented in
   [tools/interop/README.md](../tools/interop/README.md) and summarized in
   [phase-3-platform-primacy-closeout.md](phase-3-platform-primacy-closeout.md).
14. **Interop Tier 2 extended soak, when compatibility-sensitive behavior changed** - run or verify
   the scheduled/manual `interop-extended` job when the release changes FCP, peer handling,
   datastore persistence, restart behavior, USK/SSK request handling, packaging layout, or node
   startup. Record `SubscribeUSK` duration, persistent request replay identifier, opennet enabled
   status, timeout settings, host OS, baseline, and the final `summary.json` path in the release
   record.
15. **Interop failure artifacts** - if an interop gate fails, preserve `build/interop-smoke/` or
   `build/interop-extended/` from the local run or CI uploaded artifact before rerunning or cleaning
   the workspace. Do not publish `artifacts/private-insert-uris.json`; CI uploads exclude it.
16. **Performance regression smoke** - run the packaged performance smoke locally or verify the
   scheduled/manual `performance-smoke` CI job when preparing a release candidate. The gate is
   documented in [tools/perf/README.md](../tools/perf/README.md). Treat deterministic asset-size
   failures as release blockers unless a maintainer records an accepted baseline update or waiver.
17. **Performance evidence, when performance-sensitive behavior changed** - run or verify the
    performance smoke when the release changes startup, packaging layout, Platform API, Web Shell,
    SDK assets, first-party app bundles, FCP startup, storage, routing, persistence, or JVM/runtime
    packaging. Record the command, mode, host OS or runner label, Java version, baseline path,
    `summary.json` path, and comparison status in the release record.

## Build
1. Clean build for deterministic artifacts:
   ```bash
   ./gradlew clean build
   ```
   - Produces `build/libs/cryptad.jar`, `build/cryptad-dist/`, the jpackage image (`build/jpackage/Crypta`), and—when tooling is available—native installers under `build/distributions/`.
   - The build logs print SHA-256 hashes for produced artifacts.
2. Optional focused tasks:
   - `./gradlew buildJar` regenerates just `cryptad.jar`.
   - `./gradlew distJlinkCryptad` refreshes the jlink archive consumed by Flatpak packaging.
   - `./gradlew jpackageInstallerCryptad` (macOS/Linux) produces `.dmg`, `.deb`, `.rpm` installers when platform tooling exists.
3. Verify each expected artifact exists and launches:
   - macOS: `open build/jpackage/Crypta.app` (or run `Contents/MacOS/Crypta`).
   - Windows: test `build/jpackage/Crypta/Crypta.exe` inside a VM.
   - Linux: install with `dpkg -i` / `rpm -i` on fresh VMs; validate service + desktop flows.
   - Interop caveat: the Hyphanet interop harness is Linux-only. macOS and Windows release
     readiness must come from installer, launcher, and application smoke tests on those platforms.

## Generate Release Descriptor and CHKs
1. **Insert artifacts to Crypta to obtain CHKs**. Run `fcpupload` separately for each installer type you ship and record both the returned CHK and the artifact size:
   - Linux `.deb` (example amd64 build):
     ```bash
     ART=build/distributions/cryptad-v${BUILD_N}-amd64.deb   # adjust if your build omits the arch suffix
     CHK=$(fcpupload -p 2 -e "$ART" | awk '/^CHK@/ {print $1}')
     SIZE=$(stat -c%s "$ART")
     ```
   - Linux `.rpm` (example amd64 build):
     ```bash
     ART=build/distributions/cryptad-v${BUILD_N}-amd64.rpm
     CHK=$(fcpupload -p 2 -e "$ART" | awk '/^CHK@/ {print $1}')
     SIZE=$(stat -c%s "$ART")
     ```
   - macOS `.dmg` (from `jpackageInstallerCryptad`):
     ```bash
     ART=build/distributions/Crypta-${BUILD_N}.dmg
     CHK=$(fcpupload -p 2 -e "$ART" | awk '/^CHK@/ {print $1}')
     SIZE=$(stat -f%z "$ART")
     ```
   - Windows installer (`.exe` or `.msi`):
     ```bash
     ART=build/distributions/Crypta-${BUILD_N}.exe   # or .msi if you package MSI
     CHK=$(fcpupload -p 2 -e "$ART" | awk '/^CHK@/ {print $1}')
     SIZE=$(stat -c%s "$ART")
     ```
   - Flatpak/Snap: record the published store URL instead of a CHK when distributing through stores only.
   - Adjust paths/filenames if you stage artifacts elsewhere or publish additional archives (e.g., `cryptad-jlink-v${BUILD_N}.tar.gz`).
   - Retain each CHK and size for the descriptor.
   - For store-distributed formats (Flatpak/Snap), ensure the store page is live and copy its URL instead of a CHK.
2. **Publish changelog texts** via CHK uploads and record their URIs.
3. **Author `core-info.json`** using the template above. Keep package entries sorted for readability.
4. Store the descriptor alongside release artifacts for auditability.

## Publish to Crypta
1. **Staging channel**
   - Upload installers (step 1 already inserts them globally—confirm reachability).
   - Insert the descriptor at `USK@<staging-update-key>/info/<BUILD_N>`:
     ```bash
     fcpput -p reboot -r 1 -g "USK@<staging-key>/info/${BUILD_N}" core-info.json
     ```
   - Update changelog CHKs in the descriptor if content changes between staging iterations.
2. **Verification** (see next section) ensures package selection, changelog links, and UI wiring behave correctly.
3. **Production channel**
   - Repeat the inserts against the production key after staging passes.
   - Record the exact JSON text/CHKs in the release log.

## Staging Verification
- Configure a staging node:
  ```ini
  node.updater.URI=USK@<staging-key>/info/
  node.updater.enabled=true
  node.updater.autoupdate=true   # auto-download only; installation remains manual
  ```
- Monitor logs:
  - Watch for `[CoreUpdater] info.json parsed` with detected `env.os/env.arch`.
  - Confirm downloads land in `updates/core/<version>/<arch>.<ext>`.
  - Validate Alerts UI: progress %, `Download` → `Install` transition, retry messaging, and `Open in Store` behaviour.
  - Exercise `/core-update/` Install; ensure installers launch or store portals open for Flatpak/Snap.
- Verify changelog links resolve through the recorded CHKs.
- On Linux, inspect preference order (Flatpak inside sandbox, native packages on host) matches expectations.
- Verify the Linux Tier 1 Hyphanet interop gate:
  ```bash
  tools/interop/run-hyphanet-interop-smoke.sh
  ```
  In CI, the `interop-smoke` job builds with `./gradlew assembleCryptadDist` and then runs the same
  gate with `INTEROP_SKIP_BUILD=1`. The expected diagnostics root is `build/interop-smoke/`.
- Inspect `build/interop-smoke/summary.json` for `status=success`, `mode=smoke`, all Tier 1
  `flows` marked `passed`, `restart_recovery_level=restart-and-refetch`,
  recorded `restart_recovery_checks`, recorded `restart_recovery_deferred_checks`,
  Hyphanet baseline metadata, public URI records, and process statuses.
- Preserve `build/interop-smoke/` for the release record when the run fails.
- For Tier 2, run or verify `interop-extended` and preserve `build/interop-extended/` when it fails
  or when the release record needs soak evidence. The extended summary should include
  `usk_subscribe_soak`, `persistent_request_replay`, `enabled_flows`, `skipped_flows`,
  `artifacts/usk-subscribe-soak.json`, `artifacts/persistent-request-replay.json`, and
  `artifacts/interop-report.md`.
- Do not attach `artifacts/private-insert-uris.json` to release records or shared diagnostics. It
  contains temporary SSK/USK insert keys and is intentionally excluded from CI artifact uploads.
- Verify the lightweight performance gate with Python 3.12 or newer:
  ```bash
  PERF_SKIP_BUILD=1 tools/perf/run-performance-smoke.sh
  ```
  If `build/cryptad-dist/` has not been built yet, omit `PERF_SKIP_BUILD=1` and let the wrapper run
  `./gradlew assembleCryptadDist`.
- Inspect `build/perf-smoke/summary.json` and `build/perf-smoke/artifacts/perf-report.md`.
  Deterministic asset-size regressions should block promotion unless the release record includes a
  maintainer-reviewed baseline update. Environment-sensitive startup, FCP, and Platform API timing
  regressions should be investigated on comparable hardware before promotion. CI uploads
  `summary.json` and `artifacts/` from the scheduled/manual `performance-smoke` job.
- Generate the release certification report after the interop, performance, app-platform,
  app-review, and beta documentation evidence exists:
  ```bash
  python3 tools/release-certification/certify.py release-certification --manifest build/release-candidate.json
  ```
  If the production beta pipeline already ran, inspect its marked release workspace first. Set
  the previous candidate and history paths in the manifest before rerunning lower-level evidence.
  Inspect the `release-certification/summary.json`, `report.md`, and `artifacts/` files for matrix
  row status, regressions, release blockers, waiver IDs, coverage checks, and recommendations.
  Missing required evidence, failed required evidence, missing signed bundle/catalog/review
  evidence, missing app UI design-system/lint evidence, missing beta documentation evidence,
  failing docs redaction, missing `apphost.sandbox-provider` evidence, required evidence
  regressions, failing ecosystem gates, missing or stale network-scale RC soak evidence, required
  live-network beta failures, or a failing `ecosystem.rc-certification` gate block
  release-candidate promotion unless a release manager records an explicit waiver for a waivable
  gap. Redaction findings remain blockers. If the previous summary predates PR-231
  and the matrix
  reports `previousMatrixPresent=false`, record that baseline transition in the release log and
  continue only after the row-level evidence and gate coverage checks pass or have explicit
  waivers. Do not attach `artifacts/private-insert-uris.json`, private signing keys, private
  reviewer keys, form passwords, app tokens, browser session tokens, raw request bodies, raw feed
  bodies, raw trust documents, private insert URIs, raw trusted reviewer public key bytes, or
  unsanitized local paths to the release record. CI uploads contain sanitized certification
  artifacts only; preserve raw local or CI gate failure directories separately when deeper
  diagnostics are needed.
- Run optional live AppHost lifecycle smoke only when a localhost node is prepared:
  ```bash
  CRYPTAD_CERT_APP_SMOKE_LIVE=1 \
  CRYPTAD_CERT_NODE_BASE_URL=http://127.0.0.1:<port> \
  CRYPTAD_CERT_FORM_PASSWORD=<redacted> \
  python3 tools/release-certification/certify.py release-certification --manifest build/release-candidate.json
  ```
  This proves local install/start/status/stop/update/uninstall paths for the generated sample app;
  it does not prove live network publication or global app safety. The smoke attempts stop/delete
  cleanup for `cert-smoke` after failures.

## Production Rollout
- For Stable 1.0, complete the protected GA validation, authorization, publication, and receipt
  verification in
  [the Stable GA runbook](stable-1.0-rc-validation-and-ga-promotion.md) before announcing GA.
  Promote the exact frozen RC product and catalog bytes; do not rebuild them during rollout.
- Treat matching existing tag, GitHub Release, and catalog state as idempotent only when the
  commit, notes, asset names, sizes, digests, catalog revision, signature, and mirror results all
  match the authorization. Stop on conflicts instead of overwriting public state.
- Publish descriptor and artifacts to the production USK.
- Announce the release with links to installers, release notes, and any manual installation guidance.
- Monitor:
  - Node logs for `[CoreUpdater] progress` and `Download Completed` entries.
  - Support channels for installer/store issues.

## Emergency Procedures
- **Hotfix**: bump build number, rebuild, generate new descriptor, and publish to `info/<BUILD_N+1>`. Nodes will surface in the newer package immediately.
- **Revoke updater**: insert a clear message into `REVOKE_SSK`; `NodeUpdateManager` disables auto-downloads and shows the text in Alerts.
- **Pull a bad release**: publish a replacement descriptor at the same edition with `packages` emptied or pointing to a warning changelog. Communicate manual cleanup steps because cached files under `updates/core/` are retained.

## Operator Notes (for node users)
- Enable the updater via `node.updater.enabled=true`; opt into background downloads with `node.updater.autoupdate=true`.
- Downloads appear under `updates/core/`; installation requires manual confirmation from the Alerts panel.
- `Install` launches platform installers or store portals. Windows may require SmartScreen confirmation.
- Alerts now show retry messaging for transient failures; use the `Retry` button without restarting the node.

## Appendix: Code Path Reference
- `NodeUpdateManager`: orchestrates CoreUpdater lifecycle, changelog exposure, download state, and auto-download toggles.
- `CoreUpdater`: subscribes to the update USK, parses `core-info.json`, selects packages based on `AppEnv`, manages `PackageFetcher`, and auto-downloads when allowed.
- `network.crypta.clients.http.updater.CoreActionToadlet` in `:adapter-http-legacy-admin`:
  handles `/core-update/` POST actions (download, install, open store) and surfaces status
  transitions.
- `PackageFetcher`: wraps the client getter to track splitfile progress and expose retryable status to the UI.
- `AppEnv`: single source of truth for OS/arch/service detection (replaces direct `os.name` probes).
- `UpdateOverMandatoryManager`: core JAR UoM paths are disabled (`supportsJarUOM=false`).

## Release Runbook (Template)

### Variables
```bash
export BUILD_N=<INT_BUILD_NUMBER>
export STAGING_USK="USK@<staging-update-key>/info/"
export PROD_USK="USK@<prod-update-key>/info/"
export REVOKE_SSK="SSK@<revocation-key>/revoked"
export VERSION_STRING="$BUILD_N"               # must stay an integer string; used for update gating
export RELEASE_PAGE="https://crypta.network/releases/$BUILD_N"
```

### 1) Build Artifacts
```bash
./gradlew clean build
ls -lh build/distributions/
```
Confirm the presence of:
- `cryptad-v${BUILD_N}.deb`, `cryptad-v${BUILD_N}.rpm`
- `Crypta-${BUILD_N}.dmg`
- `Crypta-${BUILD_N}.exe` (or `.msi`)
- `cryptad-jlink-v${BUILD_N}.tar.gz` (optional, publish as `amd64.tar.gz` / `arm64.tar.gz`)

### 2) Generate CHKs
For each artifact (example: Debian amd64 package):
```bash
ART=build/distributions/cryptad-v${BUILD_N}.deb
SIZE=$(stat -c%s "$ART")
CHK=$(fcpupload -p 2 -e "$ART" | awk '/^CHK@/ {print $1}')
printf '  "amd64.deb": { "chk": "%s", "size": %s },\n' "$CHK" "$SIZE" >> packages.json
```
Repeat for every platform.

### 3) Publish Changelogs
```bash
SHORT_CHK=$(fcpupload -p 2 -e CHANGELOG-${BUILD_N}.md | awk '/^CHK@/ {print $1}')
FULL_CHK=$(fcpupload -p 2 -e FULLCHANGELOG-${BUILD_N}.md | awk '/^CHK@/ {print $1}')
```

### 4) Assemble Descriptor
```bash
cat > core-info.json <<'JSON'
{
  "version": "${VERSION_STRING}",
  "release_page_url": "${RELEASE_PAGE}",
  "changelog_chk": "${SHORT_CHK}",
  "fullchangelog_chk": "${FULL_CHK}",
  "packages": {
$(sed '$s/,$//' packages.json)
  }
}
JSON
```
Sanity-check formatting (`jq . core-info.json`).

### 5) Publish to Staging
```bash
fcpput -p reboot -r 1 -g "${STAGING_USK}${BUILD_N}" core-info.json
```
Verify a staging node downloads and exposes the installer correctly (`updates/core/` and Alerts UI).

### 6) Record Performance Gate
```bash
tools/perf/run-performance-smoke.sh
jq '.status, .comparison.status' build/perf-smoke/summary.json
```
Record the command line, mode, host OS or runner label, Java version, commit SHA, baseline path,
`build/perf-smoke/summary.json`, key threshold decisions, whether `distribution.build_ms` was
collected or intentionally skipped, and whether a baseline update was made.

### 7) Promote to Production
```bash
fcpput -p reboot -r 1 -g "${PROD_USK}${BUILD_N}" core-info.json
```
Retain the descriptor and package CHKs in the release record.

### 8) Post-release Checklist
- Update the public release page and announcement channels.
- Monitor `[CoreUpdater] progress` logs across canary nodes.
- Retain `build/perf-smoke/` or the CI performance artifact when a performance gate fails or when
  the release record needs performance evidence.
- Prepare a fallback plan (revocation message, follow-up descriptor) in case regressions surface.

### 9) Emergency Actions
```bash
# Pause downloads network-wide
echo "Emergency: pause ${BUILD_N}. Investigating installer regressions." | \
  fcpput -p reboot -r 1 -g "${REVOKE_SSK}"
```
To supersede a bad release, craft a new descriptor with corrected `packages` and publish to the next
edition number. If the incident is a confirmed performance regression, link the relevant
`build/perf-smoke/summary.json` or CI artifact in the incident record.

---
Keep this runbook synchronized with future CoreUpdater/AppEnv changes. Update references whenever package selection logic or descriptor schema evolves.

## Stable 1.0 maintenance and security hotfix publication

After Stable 1.0 GA, routine work stabilizes on `release/<build-number>` from `develop`; an
emergency security fix stabilizes on `hotfix/<build-number>` from the published `main` state. Both
use the next suitable integer build, the `stable-maintenance` command, and the same exact-byte
candidate, package, catalog, and CoreUpdater trust model.

The protected workflow owns annotated `v<build-number>` tag creation and publication. It never
creates or merges branches. After a verified publication receipt, complete the existing release or
hotfix merge-back with no squash and `--no-ff` merges. See the [Stable 1.0 maintenance release and
security hotfix path](stable-1.0-maintenance-release-and-hotfix-path.md).

For this Stable path, do not use the earlier manual `core-info.json`, tag, GitHub Release, catalog,
or update-key steps in this general runbook. The four protected maintenance operations are
`freeze-candidate`, `prepare-authorization`, `validate-authorization`, and `publish`; each consumes
the prior phase's exact run id, artifact name, and Actions artifact digest. Only freeze builds
packages. Publish additionally authenticates the reviewed publication-backend wheel, requires an
exact pre-staged artifact base, verifies public state independently, and activates the successor
baseline with a separate short-lived activation authorization.

Use Java 25 or newer for local packaging checks. The focused side-effect-free validation is:

```bash
python3 tools/release-certification/certify.py stable-maintenance --self-test
./gradlew verifyMacAppImageSigningArguments verifyWindowsExeInstallerArguments
```

Those commands do not replace hosted Windows Authenticode production, macOS Developer ID signing
and notarization, Linux package production, protected catalog-signature verification, or public
publication verification.
