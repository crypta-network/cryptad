---
name: cryptad-interop-performance-gates
description: "Maintain Cryptad's Hyphanet interop, performance regression, release-certification evidence gates, production beta pipeline, Stable 1.0 RC/GA flow, later exact-byte maintenance or security-hotfix publication, and Stable 1.0 lifecycle/deprecation governance under tools/interop, tools/perf, tools/release-certification, CI, and release-readiness documentation."
---

# Cryptad interop and performance gates

Use this skill before changing `tools/interop`, `tools/perf`, `tools/release-certification`,
related CI jobs, or release-gate documentation.

## Read first

- Hyphanet interop gate: `tools/interop/README.md`
- Performance regression gate: `tools/perf/README.md`
- Release certification workflow: `docs/release-certification.md`
- Production beta release pipeline: `docs/production-beta-release-pipeline.md`
- Production beta go/no-go dashboard: `docs/production-beta-go-no-go-dashboard.md`
- Stable 1.0 readiness gate: `docs/stable-1.0-readiness-gate.md`
- Stable 1.0 RC execution and freeze: `docs/stable-1.0-rc-execution-and-release-freeze.md`
- Stable 1.0 RC validation and GA promotion:
  `docs/stable-1.0-rc-validation-and-ga-promotion.md`
- Stable 1.0 maintenance and security hotfix path:
  `docs/stable-1.0-maintenance-release-and-hotfix-path.md`
- Stable 1.0 backport and release-train governance:
  `docs/stable-1.0-backport-and-release-train-governance.md`
- Stable 1.0 support lifecycle and deprecation governance:
  `docs/stable-1.0-support-lifecycle-and-deprecation-governance.md`
- Stable maintenance publication provider protocol:
  `tools/release-certification/publication-backend/README.md`
- Multi-node beta soak and upgrade drill: `docs/multi-node-beta-soak-and-upgrade-drill.md`
- Ecosystem RC certification gate: `docs/ecosystem-rc-certification-gate.md`
- Release certification tooling: `tools/release-certification/README.md`
- Release readiness gates: `docs/cryptad-release-workflow-and-runbook.md`
- Phase 3 platform closeout context: `docs/phase-3-platform-primacy-closeout.md`

## Hyphanet interop gate

- Tier 1 smoke is the release-readiness compatibility gate. It is Linux-only and runs a packaged
  Cryptad node against a pinned Hyphanet baseline.
- Tier 2 extended soak runs locally or through scheduled/manual CI when compatibility-sensitive
  behavior changed. It adds long-lived `SubscribeUSK`, persistent request replay, optional opennet
  plumbing, and longer diagnostics.
- Normal local commands:

```bash
python3 tools/interop/interop_smoke.py --self-test
tools/interop/run-hyphanet-interop-smoke.sh
INTEROP_SKIP_BUILD=1 tools/interop/run-hyphanet-interop-smoke.sh
INTEROP_MODE=extended INTEROP_SKIP_BUILD=1 tools/interop/run-hyphanet-interop-smoke.sh
```

- Do not publish `artifacts/private-insert-uris.json`; it contains temporary insert keys and CI
  excludes it from uploads.
- Preserve `build/interop-smoke/` or `build/interop-extended/` when a gate fails or when a release
  record needs compatibility evidence.

## Performance regression gate

- The performance gate records lightweight packaged-node startup, local FCP/Platform API timing,
  distribution size, Web Shell asset size, SDK asset size, and first-party static app source and
  staged-bundle size signals for Queue Manager, Publisher, Site Publisher, Profile Publisher,
  Social Inbox RC, Feed Reader, and Trust Graph Local RC. It is not a broad benchmark suite.
- The runner requires Python 3.12 or newer.
- Normal local commands:

```bash
python3 tools/perf/perf_smoke.py --self-test
tools/perf/run-performance-smoke.sh
PERF_SKIP_BUILD=1 tools/perf/run-performance-smoke.sh
PERF_MODE=collect PERF_SKIP_BUILD=1 tools/perf/run-performance-smoke.sh
```

- Deterministic asset-size failures are release blockers unless a maintainer records an accepted
  baseline update or waiver. Environment-sensitive timing regressions need comparable hardware or
  runner evidence before promotion decisions.
- Do not update `tools/perf/baselines/performance-smoke.json` only to silence a regression. Record
  before/after summaries, host or runner details, Java version, commit SHA, and the rationale.

## Release certification gate

- `tools/release-certification/certify.py release-certification` aggregates interop, performance,
  app-platform, network-scale soak, multi-node beta soak, catalog, app-owned UI, operator beta
  recovery, optional live-network beta certification, legacy-admin retirement, and CI metadata into:

```text
build/release-certification/<release-id>/release-certification/summary.json
build/release-certification/<release-id>/release-certification/report.md
build/release-certification/<release-id>/release-certification/redaction-report.json
build/release-certification/<release-id>/release-certification/artifacts/
build/release-certification/<release-id>/network-scale-soak/summary.json
build/release-certification/<release-id>/multi-node-beta/run/summary.json
build/release-certification/<release-id>/live-network-beta/summary.json
build/release-certification/<release-id>/security-response/
```

- `tools/release-certification/certify.py production-beta` is the top-level production beta
  app-ecosystem release pipeline. It orchestrates Gradle build/install tasks, first-party app
  staging/signing/verification, signed catalog and review receipt generation, app-platform smoke,
  live-network beta smoke when required, network-scale soak, multi-node beta soak and upgrade
  evidence, ecosystem RC certification, final artifact redaction, the production beta go/no-go
  dashboard, and public archive creation below
  `<out-root>/<release-id>/production-beta/artifacts/legacy/`.
  `developer-dry-run` is CI-safe and non-release; `release-candidate` is strict but may use
  non-production signing labels; `production-beta` requires production signing, a complete
  in-pipeline Gradle build/stage/sign run, a public HTTPS artifact base URI, live-network evidence
  unless the explicit emergency skip is used, passing multi-node beta evidence, and a clean
  workspace before `promotionReady` can become true. Emergency build skips must leave
  `nonRelease=true` and fail the build-complete promotion gate.
- `tools/release-certification/certify.py go-no-go` is the final release-manager
  dashboard generator for production beta launch candidates. It consumes sanitized production beta,
  release-certification, ecosystem matrix, app-platform, live-network, network-scale, multi-node,
  security-response, and waiver inputs; emits JSON, Markdown, and a dashboard redaction report; and
  decides only `go`, `no-go`, or `go-with-waivers`. Production-beta mode fails closed for
  mandatory launch evidence, invalid or expired waivers, unsafe artifact hygiene, fixture/test
  signing, non-release summaries, dirty workspaces, and redaction findings.
- `tools/release-certification/certify.py stable-readiness` is the Stable 1.0 readiness gate. It
  consumes production beta outputs, go/no-go output, release certification, app-platform evidence,
  multi-node and network-scale soak, security drill summaries, public beta known issues, policy,
  known limitations, and Stable-scoped waivers. Required consumers must reject malformed summaries,
  mismatched `releaseId`, missing `stable-1.0.*` evidence rows, failed redaction, stale security or
  soak evidence, and non-release production beta inputs.
- `tools/release-certification/certify.py stable-rc` is the only canonical Stable 1.0 RC execution
  and freeze command. It reuses the `stable-review` profile, executes the required production and
  readiness stages, freezes the candidate, emits the deterministic product and outer RC archives,
  records checksums/provenance/limitations/API/content-profile/catalog/app identities, and verifies
  post-package drift. Do not create a second RC format or promote any result with
  `promotionReady=false`, `nonRelease=true`, incomplete freeze, drift other than `no-drift`, or a
  decision outside `go` and policy-compliant `go-with-waivers`.
- `tools/release-certification/certify.py stable-ga` is side-effect-free. It authenticates the
  selected RC summary, freeze/sidecar, product/archive/checksums/provenance, latest successful
  protected freeze/refreeze lineage, and frozen catalog/app/API/profile identities. It requires
  production post-freeze evidence and an explicit protected authorization bound to the exact
  digests, emits deterministic promotion/publication/maintenance records, and verifies a supplied
  publication receipt. It never creates a tag, GitHub Release, branch, catalog update, or network
  insert. Any payload change must return to `stable-rc` refreeze.
- `tools/release-certification/certify.py app-platform` produces the app-platform summary consumed by
  the aggregator. It keeps `--self-test` offline and Python-only, including source/test evidence
  for the Platform API contract, Platform API 1.0 stable baseline, compatibility-window metadata,
  previous contract snapshot policy, stable descriptor deprecation/removal windows,
  experimental-graduation policy, manifest/catalog target stability, first-party stability
  declarations, stable reference docs, app-vault capability docs,
  signed catalogs, first-party maintenance metadata, app-store submission package and pre-review
  evidence, catalog security advisory/denylist evidence, catalog operations and mirrors evidence,
  trusted app-review receipt/revocation evidence, unified user-consent snapshot/digest/audit
  evidence, app-owned UI origin behavior, app UI design-system/lint evidence, live USK catalog
  publication, Site Publisher
  reference-content coverage, Profile Publisher identity-profile coverage, Feed Reader
  content-fetch, subscription, app-data, and app-data migration coverage, Social Inbox RC
  multi-source/threading/read-state/local-filter/export/trust-grant coverage, Trust Graph Local RC
  durable exchange, import-preview, duplicate-issuer/conflict, anchor-lifecycle, bounded-score, and
  app-data migration coverage, app-data backup/restore portability evidence, app-service
  registry/grant/dependency/grant-bundle/redaction coverage, generated document insert/content-fetch
  and trust redaction coverage, app-network budget source evidence, third-party developer beta
  docs, template, sample-flow, checklist, compatibility, feedback, plugin-migration, and redaction
  evidence, legacy plugin freeze evidence, app-review governance/reviewer-key/transparency-log
  evidence, public-beta security hardening
  evidence, operator beta dashboard/recovery/support-bundle evidence, legacy-admin
  retirement/removal Wave 1-5 and final-surface evidence, production security response runbook
  evidence, sandbox provider selection, and app-update lifecycle/scheduler/rollback.
- `tools/release-certification/certify.py network-scale-soak` produces the deterministic simulated
  network-scale soak summary consumed by the aggregator. Normal PR and CI runs must use simulated
  time instead of a literal 24-hour test. Release-candidate runs may attach an external
  `simulated-rc-soak` or `live-rc-soak` summary with the same redacted schema.
- `tools/release-certification/certify.py multi-node-beta` produces deterministic multi-node beta
  soak and upgrade/rollback/backup drill evidence consumed by the aggregator and production beta
  pipeline. Normal PR and CI runs use the checked-in simulated topology. Release-manager runs may
  attach an external `simulated`, `hybrid`, or `live` summary with the same redacted schema.
- `tools/release-certification/certify.py live-network-beta` is the explicit release-manager live
  network collector. Its self-test is offline and deterministic, but normal runs may call only a
  validated localhost node and use env/protected-file fixtures for form passwords, catalog expected
  key ids, content/feed/profile/trust URIs, and private insert material. Required mode must fail
  closed for missing fixtures, failed required evidence, stale app principals, cleanup failures, or
  redaction findings.
- `tools/release-certification/certify.py app-platform-docs` produces deterministic app-platform
  beta docs evidence for the developer portal, tutorials, beta program, third-party developer beta
  docs, issue templates, relative Markdown links, and docs redaction checks.
- With `execution.collectEvidence=true`, the unified command runs candidate-scoped app-platform,
  network-scale, multi-node, and security-drill collectors before aggregation. Set the matching
  `inputs` path to attach external evidence instead. `requirements.liveNetwork=true` or
  `execution.collectLiveNetwork=true` also runs the candidate-scoped live collector.
  Internally collected component directories are rebuilt on every invocation, including runs with
  `output.reset=false`; only explicit manifest inputs are reusable. Strict release-candidate and
  production-beta app-platform collection normally runs the first-party Gradle sign/verify tasks.
  PR-mode collection automatically skips those tasks; other modes may use an explicit
  `execution.skipGradle=true`. Strict runs with that explicit skip remain non-promotable or
  emergency evidence as enforced by production policy. Reused run workspaces must reject
  symlinked component or artifact directories and any resolved path outside the marked run root.
  Apply the same confinement checks to nested engine output directories such as
  `artifacts/legacy`. Before recollecting evidence, reject an already completed aggregate so a
  failed rerun cannot leave old aggregate output beside newly rebuilt component evidence.
  Manifests must remain non-secret in both field names and scalar values, published input paths
  must be reduced to `<repo>/...` or `<external-input>`, and a nonzero component process exit must
  always produce and require failed evidence.
  Legacy outputs without explicit redaction metadata require a complete safe payload scan; false
  direct or nested guarantees fail closed. Validate every component path segment before cleanup so
  intermediate symlinks are never followed, and preserve production `goNoGo.decision` in the
  common envelope result.
  Inputs mapped to unified components must require candidate-bound v2 envelopes of their assigned
  kind, profile-compatible policy, component identity, and declared candidate version. Strict
  profiles must reject PR, nightly, and developer-dry-run evidence even when the kind and release ID
  match. Stable review may consume production-beta evidence, and release or production aggregation
  may consume an explicit Stable-review summary; do not add other cross-profile transitions.
  Explicit external or non-envelope interop, performance, ecosystem-matrix, and third-party intake
  inputs retain their native JSON contracts. Policy command modes must match the mode derived from
  `release.profile` so command configuration cannot weaken or mislabel strict evidence. An
  explicitly attached optional live-network summary enables the live gate without making it
  required. Reject argparse abbreviations of every adapter-controlled option before forwarding
  command escape-hatch arguments. Normalize known negative live redaction facts such as
  `rawBodiesStored: false` into true positive v2 guarantees without accepting unsafe true values.
  Migration and fallback scans must recursively reject payload-bearing sensitive JSON field names
  and all local POSIX, Windows drive, and UNC absolute path forms outside public API route shapes.
  They must accept complete canonical `<repo>/relative/path` placeholders produced by existing
  release summaries without accepting traversal, malformed separators, or mixed absolute paths.
  Workflow dispatches that attach candidate-bound multi-node, security-drill, history, or Stable
  v2 summaries must require the matching explicit candidate release ID before generating a manifest.
  Generate workflow manifest `release.version` from the checked-out build with
  `./gradlew -q printVersion`; require attached v2 evidence to carry that same candidate version.
  Reject attached v2 inputs for strict hand-authored manifests when `release.version` is null;
  never treat an absent strict candidate version as a wildcard.
  Required-but-missing evidence remains an engine gate: for example,
  `requirements.history=true` without `inputs.releaseHistory` must load successfully and produce a
  failed release-candidate certification aggregate and report.
  Before extracting an attached v2 input, scan its legacy payload independently of the claimed
  outer redaction result. Scan and digest-check every referenced security-drill sidecar, copying
  sidecars from the effective verification input directory. Preserve the validated envelope
  identity when unwrapping multi-node evidence, and use configured live-network and network-scale
  input paths when producing downstream production extracts.
  If a legacy engine exits early, returns nonzero, or emits unsafe fallback content, remove unsafe
  raw copies from the publishable workspace and emit only sanitized failed evidence with
  `promotionReady=false`. Shared output writers and extracted-input directories must reject
  symlinks and paths outside the marked workspace. Completed component and migration summaries are
  immutable unless the manifest explicitly requests a safe reset.
  Keep `certify.py` as a thin entry point and split engine modules before they exceed 5,000 lines;
  `self-test core` enforces the source-size boundary.
- Normal local commands:

```bash
python3 tools/release-certification/certify.py self-test all
cp tools/release-certification/manifests/release-candidate.example.json \
  build/release-candidate.json
# Replace every placeholder before running candidate-bound commands.
python3 tools/release-certification/certify.py security-response verify --manifest build/release-candidate.json
python3 tools/release-certification/certify.py release-certification --manifest build/release-candidate.json
cp tools/release-certification/manifests/production-beta.example.json \
  build/production-beta.json
# Replace every placeholder before running the protected pipeline.
python3 tools/release-certification/certify.py production-beta --manifest build/production-beta.json
cp tools/release-certification/manifests/stable-1.0-rc.example.json \
  build/stable-1.0-rc.json
# Replace every placeholder and use protected production inputs.
python3 tools/release-certification/certify.py stable-rc \
  --manifest build/stable-1.0-rc.json
cp tools/release-certification/manifests/stable-1.0-ga.example.json \
  build/stable-1.0-ga.json
# Bind the selected exact RC, post-freeze evidence, and protected authorization.
python3 tools/release-certification/certify.py stable-ga \
  --manifest build/stable-1.0-ga.json
```

- Release-candidate mode fails when required evidence is missing, skipped, malformed, wrong-mode,
  or failing unless a release-manager waiver is recorded. Required app-platform evidence now
  includes `app-platform.first-party`, `app-platform.devtools-cli`,
  `app-platform.developer-beta-toolkit`, `app-platform.docs-portal`,
  `app-platform.beta-program`, `app-platform.beta-tutorials`,
  `app-platform.docs-redaction`, `app-platform.signed-bundles`,
  `third-party-developer.beta-program`, `third-party-developer.docs`,
  `third-party-developer.template`, `third-party-developer.sample-app-flow`,
  `third-party-developer.submission-checklist`, `third-party-developer.compatibility-window`,
  `third-party-developer.feedback-workflow`, `third-party-developer.plugin-author-migration`,
  `third-party-developer.redaction`, `catalog.smoke`,
  `app-catalog.first-party-beta`, `catalog.production-channels`,
  `catalog.operations-and-mirrors`, `app-catalog.first-party-maintenance-policy`,
  `catalog.security-advisories`,
  `catalog.version-denylist`, `app-review.receipt-revocation`,
  `app-review.reviewer-key-compromise-flow`, `app-update.security-denylist-gates`,
  `web-shell.security-advisory-trust-warnings`,
  `ecosystem-security.advisory-revocation-redaction`, `production-security.response-runbook`,
  `platform-api.contract`,
  `platform-api.stable-baseline`, `platform-api.stable-breaking-change-check`,
  `platform-api.compatibility-window`, `platform-api.previous-contract-snapshot`,
  `platform-api.deprecation-window-policy`, `platform-api.experimental-graduation-policy`,
  `platform-api.manifest-target-stability`,
  `platform-api.first-party-stability-declarations`, `platform-api.stable-reference-docs`,
  `app-vault.capabilities`,
  `app-platform.identity-profile-publish`, `app-platform.generated-document-insert`,
  `app-platform.content-fetch`, `app-platform.content-subscriptions`,
  `network-content.subscription-scheduler`, `app-platform.durable-app-data-store`,
  `app-data.backup-restore-portability`, `app-platform.trust-graph-preview`,
  `app-platform.trust-graph-rc-scope-and-safety`, `app-platform.trust-graph-durable-store`,
  `app-platform.trust-graph-exchange`, `app-platform.trust-statement-signing`,
  `app-platform.social-message-signing`, `app-services.registry`, `app-services.grants`,
  `app-services.dependency-graph`, `app-services.grant-bundles`,
  `app-services.grant-expiry-renewal`, `app-services.provider-revalidation`,
  `app-services.trust-score-provider`, `app-services.web-shell`, `app-services.redaction`,
  `app-services.dependency-redaction`,
  `app-ui.design-system`, `app-ui.lint`, `app-ui.first-party-adoption`, `app-ui.smoke`,
  `reference-apps.content`, `reference-app.profile-publisher`,
  `reference-app.profile-publisher-app-data`, `reference-app.feed-reader`,
  `reference-app.feed-reader-subscriptions`, `reference-app.feed-reader-app-data`,
  `reference-app.social-inbox`, `reference-app.social-inbox-signed-message`,
  `reference-app.social-inbox-subscriptions`, `reference-app.social-inbox-app-data`,
  `reference-app.social-inbox-trust-annotations`, `reference-app.social-inbox-service-grant`,
  `reference-app.social-inbox-rc-threading`, `reference-app.social-inbox-service-dependency`,
  `migration.social-mail-preview`, `reference-app.trust-graph`,
  `reference-app.trust-graph-durable-exchange`, `reference-app.trust-graph-app-data-preview`,
  `legacy-plugin.freeze-policy`,
  `legacy.retirement`, `legacy-admin.removal-wave-1`, `legacy-admin.removal-wave-2`,
  `legacy-admin.removal-wave-3`, `legacy-admin.removal-wave-4`,
  `legacy-admin.removal-wave-5`, `legacy-admin.final-admin-surface`,
  `legacy-admin.browse-retained`, `legacy-admin.emergency-fallback-retained`,
  `apphost.sandbox-provider`,
  `app-update.lifecycle`,
  `app-update.scheduler`, `app-update.rollback`, `app-update.live-catalog-refresh`,
  `app-update.data-migration-contract`,
  `public-beta-security.*`, `operator-beta.*`, `operator-rc.*`, `app-review.trusted-receipts`,
  `app-review.policy`, `app-review.governance`, `app-review.reviewer-key-lifecycle`,
  `app-review.transparency-log`, `app-review.review-history-api`,
  `app-review.first-party-catalog`, `app-review.first-party-review-chain`, and
  `network-scale.app-network-budget`, `network-scale.content-fetch-budget`,
  `network-scale.subscription-budget`, `network-scale.queue-pressure-backoff`,
  `network-scale.trust-graph-import-budget`, `network-scale.social-inbox-multi-source-soak`,
  `network-scale.redaction`, `network-scale.rc-soak-summary`, `multi-node-beta.soak`,
  `multi-node-beta.upgrade-drill`, `multi-node-beta.catalog-channel-update`,
  `multi-node-beta.app-install-update-rollback`, `multi-node-beta.app-data-migration`,
  `multi-node-beta.backup-restore`, `multi-node-beta.subscription-pressure`,
  `multi-node-beta.trust-graph-import`, `multi-node-beta.social-inbox-multi-source`,
  `multi-node-beta.support-bundle-drill`, `multi-node-beta.redaction`, and
  `release-certification.ecosystem-matrix`, `production-beta.go-no-go-dashboard`,
  `production-beta.go-no-go-decision`, `production-beta.waiver-validation`,
  `production-beta.dashboard-redaction`, and `production-beta.launch-artifact-hygiene`.
- Platform API stable-history checks compare the stable baseline name/counts/lists, stable endpoint
  required-capability sets, stable endpoint action labels, stable endpoint app-process/app-browser
  access flags, and compatibility-window metadata. App-platform smoke evidence must also inspect
  `stableDescriptorDeprecations` and fail `platform-api.deprecation-window-policy` when a stable
  descriptor is deprecated or scheduled for removal without valid metadata, has a future
  `deprecatedSinceContractVersion`, or publishes a too-short `removalContractVersion` window. In
  production history mode, missing previous baseline, compatibility-window, or endpoint metadata is
  a blocker; developer dry runs may warn when no production history is available.
- `catalog.operations-and-mirrors` is deterministic source-level evidence. It must verify the
  primary-plus-mirrors model, mirror fallback with signed verification, stale/downgrade
  prevention, bounded verified revision history, explicit rollback re-verification, key-rotation
  status visibility, emergency advisory refresh support, Platform API/Web Shell wiring, docs
  coverage, and redaction without requiring live mirror infrastructure or production signing keys.
- Network-scale release-candidate evidence must be generated fresh by the wrapper or attached
  explicitly. Do not let the aggregator reuse stale default `network-scale-soak/summary.json`
  files across release workspaces.
- Multi-node beta release-candidate evidence must be generated fresh by the wrapper or attached
  explicitly. Do not use the checked-in self-test topology as production promotion evidence, and do
  not let the aggregator reuse stale default `multi-node-beta-soak/summary.json` files across
  release workspaces.
  For developer and release-candidate production-pipeline runs, `runMultiNodeSoak=true` without an
  explicit topology config invokes `multi-node-beta run` without `--config`, which selects the
  checked-in PR-safe default topology. When `inputs.multiNodeSoakConfig` is set, unified
  multi-node `plan` and `run` actions must pass that exact path as `--config`; command escape-hatch
  arguments cannot replace the structured topology. Multi-node and security-response passthrough
  output flags are likewise reserved: manifests cannot override `--out`, `--out-dir`, `--report`,
  `--summary-out`, or `--release-notes-out`, and generated files must remain candidate-scoped.
  A required multi-node run whose effective configured or overridden mode is `live` must propagate
  `--require-live`; deterministic fallback evidence with zero reachable localhost nodes cannot be
  promotion-ready.
  Protected `production-beta` promotion still requires a production topology config or attached
  summary.
- Stable readiness generated by the production beta wrapper must use
  `evidence/stable-readiness-multi-node-beta-soak.json` and
  `evidence/stable-readiness-network-scale-soak.json`, not the compact generic soak extracts. Those
  Stable-specific files preserve freshness metadata for the readiness gate. Generated multi-node
  Stable extracts must also carry the selected manifest `release.id`; do not derive candidate
  identity from `currentCandidate.version` when an explicit release ID exists.
- Stable readiness redaction is non-waivable. Keep dashboard redaction status separate from release
  artifact redaction status, and gate archive/upload decisions on both plus Stable readiness
  redaction when Stable artifacts are generated. Do not forward production beta go/no-go waiver
  files into Stable validation unless the waiver file is explicitly Stable-scoped.
- `live-network-beta.*` evidence is release-blocking only when manifest
  `requirements.liveNetwork=true`. When live-network beta is disabled, the
  aggregator must ignore stale live summaries and must not copy stale live artifacts into the
  release record.
- Live-network beta runs must use only `http://127.0.0.1:<port>`,
  `http://localhost:<port>`, or `http://[::1]:<port>` node URLs without credentials, query
  strings, fragments, redirects, or proxy forwarding. Form passwords, app browser sessions,
  private insert URIs, and app-service grants must not leak into artifacts, shell history, or
  proxy traffic.
- Do not publish private signing keys, form passwords, app tokens, browser-session tokens, raw
  reviewer keys, raw trusted reviewer public key bytes, raw request bodies, raw feed bodies, raw
  trust documents from real users, raw social message bodies, raw fetched social documents, raw
  incident artifacts, raw app-service subject URIs, provider app data, raw app-data values, raw
  update/rollback command output, command lines containing secrets, CI secret values, queue HTML,
  budget-store file paths, private insert URIs, non-localhost endpoint metadata, catalog scratch
  paths, staged bundle paths, rollback backup paths, multi-node node profile paths, previous
  candidate archive paths, UI lint report paths, or other unsanitized local paths. The aggregator
  filters `artifacts/private-insert-uris.json` even when interop summaries reference it.
- Treat docs redaction findings as non-waivable blockers. Link-only or presence-only docs gaps can
  be waived by a release manager when policy allows, but raw secret/path findings must keep the
  evidence and matrix row failing.

## CI and release notes

- `.github/workflows/ci.yml` runs `interop-smoke` on push/PR, `interop-extended` on schedule/manual,
  interop self-tests on the multi-OS matrix, performance self-tests on the multi-OS matrix,
  release-certification self-tests on the multi-OS matrix, and `performance-smoke` on
  schedule/manual. Certification self-tests allow 30 minutes on Ubuntu and macOS and 60 minutes on
  Windows; keep workspace paths canonical before comparing absolute paths across those runners.
- `.github/workflows/release-certification.yml` runs scheduled/manual/release-ref certification,
  uploads sanitized certification artifacts, and uses `release-candidate` mode for `release/**`
  branches and `v*` tags. When the manual extended gate produces
  `build/interop-extended/summary.json`, the generated manifest must bind it as
  `inputs.interopExtended`. Interop smoke, extended interop, and performance inputs must be omitted
  when their tolerated producer step did not write a summary so aggregation can record the missing
  gate instead of failing during manifest input loading.
- `.github/workflows/production-beta-release.yml` runs the production beta pipeline in
  `developer-dry-run` for PR-safe checks, `release-candidate` for release refs/manual dispatch, and
  protected `production-beta` only when release secrets, live-node inputs, and a real artifact base
  URI are available. Protected production dispatches must also require and materialize
  `third_party_intake_summary`, bind it as `inputs.thirdPartyIntake`, and set
  `requirements.thirdPartyIntake=true`; the non-release sample flow cannot satisfy this gate.
  Artifact uploads and job-summary dashboard publication must stay gated on the
  production-beta redaction summary, `go-no-go-redaction-report.json`, and any generated Stable
  readiness redaction status passing. PR and developer-dry-run manifests must omit interop and
  performance input paths when those producer steps did not run. Release-candidate history is
  required only when a history artifact is supplied or policy explicitly requires it; protected
  production-beta runs continue to require candidate-bound history.
- `.github/workflows/stable-1.0-rc-release.yml` is the protected RC producer. It authenticates
  candidate-bound inputs, runs `stable-rc`, uploads only the passing public component, and performs
  no GA tag/Release/catalog publication. Its concurrency key is shared with Stable GA for the same
  release/build so a refreeze cannot race publication.
- `.github/workflows/stable-1.0-ga-promotion.yml` separates a read-only validation job from an
  explicitly dispatched protected publication job. Treat external validation and authorization
  evidence as protected producer artifacts with attested digests. Reauthenticate the latest RC
  lineage, release branch, evidence freshness, authorization expiry, artifact base, and catalog
  targets immediately before mutation boundaries. Conflict and recovery paths must inspect and
  record public state without creating or repairing it. Matching existing tag/Release/assets are
  idempotent only after the same checks pass; mismatches produce a verified failure receipt.
- Release notes should mention interop, performance, or certification gate changes only when they
  affect release readiness, operator confidence, app/platform behavior, or packager workflows.

## Stable 1.0 backport and release-train evidence

Before Stable maintenance freezes or authorizes a candidate, run
`python3 tools/release-certification/certify.py stable-backport`. Its closed modes are
`evaluate`, `prepare-candidate`, `validate-authorization`, and
`verify-release-completion`; every mode is side-effect-free.

Treat `tools/release-certification/stable-1.0-backport-release-train-policy.json` as the source of
the classification, disposition, state, provenance, evidence, deadline, role, queue, no-fork, and
redaction contracts. Authenticate only full commit object ids and exact repository/object-graph
relationships. Do not trust branch names, labels, trailers, or patch-id equality as authorization,
and do not fetch arbitrary remotes during evaluation.

The queue is append-only and digest chained. Carry unresolved accepted fixes, deferred/rejected
history, superseding relationships, critical obligations, hotfix follow-up, and branch
reconciliation forward. Account for every candidate change as an accepted fix, approved release
metadata/tooling/docs, explained merge context, or `unaccounted`; `unaccounted` always blocks.
GA is the only queue genesis. Every later published predecessor must authenticate both the prior
queue and prior validation; never accept a missing prior queue as a fresh chain.
Bind every evidence row to the exact reviewed policy and queue digests. Compute the queue identity
by normalizing only embedded evidence queue-binding slots to the fixed all-zero SHA-256 value;
do not omit evidence content or another queue field from that digest. Evidence ids listed as
protected by policy must remain `visibility: protected`.

Cryptad has one authenticated Stable 1.0 publication chain. Historical builds are lifecycle-aware
upgrade, advisory, or recovery coverage sources, never independent mutable release targets.
Routine trains use `release/<build>` and `routine-maintenance`; critical incident trains use
`hotfix/<build>` and `security-hotfix`. Every accepted hotfix row must be a critical
incident-bound `security-fix` under one incident/advisory pair. Record incident-required package,
app, or release-tooling effects inside that security fix’s scope and evidence, never as an unrelated
ordinary row.
The protected workflow independently freezes the exact protected `main` tip as
`mainLineageCommit` for a hotfix. Require the hotfix base to equal that tip and the tagged
publication predecessor to remain its ancestor; the older tagged candidate is not an adequate
base after the required no-ff `main` reconciliation.
Candidate handoff includes only fixes in `verified` state; `landed` alone is not release
authorization. Check every critical-fix response interval after state re-entry as well as an open
current interval, and reject a critical deferral after its bounded review time. A rejected
critical record remains a blocker, but a new append-only authorized `rejected`-to-`triaged`
transition may reopen its investigation without rewriting history. Superseding a critical record
requires an affected-scope, incident, advisory, and critical-severity equivalent replacement. A
separately authorized
superseding security hotfix may carry exactly one
`hotfix-follow-up`. If maintenance publication created it after the prior train queue was
authorized, the first queue row must bind the authenticated predecessor baseline’s exact
obligation digest, obligated build/train and generation time to the predecessor queue’s critical
source fixes; later queues inherit the row unchanged. Routine trains, unbound or multiple
follow-ups, and branch-reconciliation obligations remain blocked. Preserve the obligation id
through release completion.
The maintenance workflow may therefore consume a `blocked` train queue only when a successful
`security-hotfix` validation carries that one sole open follow-up; every routine, multi-obligation,
new, wrong-type, or reconciliation-blocked queue still fails.

Clean cherry-picks require the policy-defined protected review evidence in addition to matching
patch identity. Manual conflict resolution requires the corresponding protected review plus
focused tests. Authenticate the exact successful
`.github/workflows/stable-1.0-backport-review-authorization.yml` run and Actions artifact in the
`stable-1.0-backport-review` environment, then bind its role, policy, source, predecessor,
candidate, normalized diff, path inventory, focused tests, and validity window. Repeating a
caller-selected digest in provenance, ownership, and evidence is not authorization.

`stable-maintenance` consumes the exact result as the non-waivable
`stable-maintenance.backport-release-train` evidence row and binds the train digest into notes,
checksums, provenance, history, successor governance, and lifecycle context. Release-train
authorization approves composition only and does not replace maintenance publication
authorization.
The maintenance freeze artifact retains the exact train validation and full train authorization;
prepare and validation byte-compare both files with the preceding attested artifact before they
can authorize the frozen candidate.
At the protected publication boundary, require the train authorization to have been current at the
exact maintenance-authorization handoff recorded in that immutable bundle. Do not re-age this
composition-only grant against each later publication target, resumable-prefix retry, or
verify-public-state-only run. Continue to enforce current candidate-evidence deadlines plus the
separate maintenance publication and activation authorizations at their side-effect boundaries.

The maintenance handoff must retain both the exact train validation and the complete canonical
train authorization (stored under the historical authorization-summary filename). Authenticate
the protected backport workflow run and exact Actions artifact digest before materializing those
files; never accept a validation or authorization synthesized only by the maintenance input
producer. Keep the train candidate-file digest distinct from the maintenance candidate semantic
identity digest and compare their shared exact commit/release/predecessor bindings instead.
Before accepting a train, authenticate a fresh public lifecycle observation bound to the exact
descriptor edition and bytes, ledger, plan, update-key scope, and prior lifecycle authorization.
Train authorization must not predate that observation or any intake, state-transition, evidence,
or obligation event it approves.

The backport producer is manual-dispatch only. Do not add `workflow_call` without a separate
caller-run plus referenced-workflow attestation model. A credential-free, no-checkout preflight
must authenticate the manual event, exact workflow ref/SHA, protected source ref, source commit,
lane, and operation before any evidence or authorization environment is requested. Retain
environment deployment-branch restrictions as an independent second gate: evidence may run only
on protected `main`, `develop`, `release/*`, or `hotfix/*` refs, and authorization only on
protected `release/*` or `hotfix/*` refs. Repeat exact identity checks after checkout.

Completion verifies that the published candidate itself is the merged tip in each separate no-ff
merge to `main` and `develop`. Per-fix provenance commits may precede the publication tip but must
be ancestors of it. Read-only completion may occur after the original train handoff authorization
expires because the maintenance receipt freezes the exact validation digest accepted while the
authorization was current. Consume that exact frozen validation, and require authenticated
protected `main`/`develop` tips that contain the attested merge commits. For merge coverage, compare
the recorded tree with Git's automatic merge and use the union of per-parent changed paths when it
differs; combined diff alone can hide a one-parent resolution. The two reconciliation commits must
be distinct and each must be on its protected tip's first-parent chain, not merely reachable
through a side parent.
If that authenticated graph contains non-automatic merge content, keep strict Git inspection
failing it as reconciled, then let the completion layer derive the exact policy-named
reconciliation obligation and mark `reconciliationStatus: content-review-required`. Bind the
obligation evidence to the merge record and a digest of the bounded resolution-path inventory,
without exposing raw paths in the obligation. The next intake may advance the published fixes to
`released` only when it seeds the exact completion-created row; the resulting queue remains
blocked pending separately authenticated content-review evidence. Do not convert another Git,
branch-tip, parent, or attestation failure into an obligation.
Do not allow a fix included by the prior authorized validation to transition directly from
`verified` to `superseded`; authenticate publication and reconciliation and transition it to
`released` first.
For the next train, use the successful prior completion workflow run and exact Actions artifact
while it remains available and byte-compare the protected completion and validation. After Actions
retention expires, reauthenticate the same completion, validation, queue, receipt, and lifecycle
authority from the digest-pinned support-lifetime protected input bundle. Both paths independently
resolve current protected `main` and `develop`, require both recorded merges on those first-parent
chains, and carry the resulting `previousStableBackportCompletionHandoff` through every phase.
Keep the authoritative queue and validation protected. Public phase artifacts may contain only
`stable-1.0-release-train-queue-public.json` and the filtered
`stable-1.0-release-train-validation-public.json`; they must not contain the full validation,
authorization record, completion record, predecessor-completion handoff, or internal
checksums/provenance. Those public projections omit touched/conflict paths, protected evidence
ids/digests, private-record digests, and exact per-fix source/backport internals.
Transport authoritative phase and provenance-review handoffs through authenticated encrypted
Actions envelopes only. Bind each envelope to the exact repository, workflow/commit, run attempt,
operation, subject, and artifact name; decrypt it only inside the next protected environment with
the canonical base64 32-byte `CRYPTAD_STABLE_BACKPORT_HANDOFF_KEY_BASE64` secret. Keep that same
secret in the backport-review, backport-evidence, backport-authorization, and
maintenance-evidence environments, plus both Stable maintenance publication environments that
must independently reopen the frozen train at the side-effect boundary. Never put it in workflow
inputs, repository variables, logs, summaries, or artifacts. Repository-readable Actions
artifacts must never contain those authoritative records in plaintext. Retain support-lifetime
plaintext only in the separately access-controlled digest-pinned input archive.
After maintenance consumes the backport envelope, reseal the exact train validation and full
authorization for every freeze, preparation, validation, publication, and independent-verification
handoff. Strip duplicate plaintext copies from staged protected inputs and publication audits.
Allow a candidate-handoff authorization at most 72 hours so the exact grant can survive the
mandatory 24-hour post-freeze soak and bounded review/handoff time. It remains composition-only
authority and cannot authorize publication.
The public queue's digest-only `intakeCompositionDigest` commits those protected immutable fields.
For `evaluate-intake` to `prepare-candidate`, require that digest and the exact fix/obligation
identity sets to remain unchanged, and require every opaque per-fix transition-digest list to be
an exact prefix of its prepared successor. Bind every obligation's exact `sourceTrainId`,
`sourceFixIds`, type, identity, and generation time inside that commitment. The candidate and
candidate-bound evidence may advance; any composition or history rewrite requires a new
evaluation. After resolving protected completion tips through GitHub, fetch those exact
API-selected commit identities from the canonical origin before local object and ancestry checks.
Treat provenance-review `expiresAt` as exclusive; equality with the captured validation time is
expired.

Use the focused offline check while changing the train engine, schemas, workflow, or docs:

```bash
python3 tools/release-certification/certify.py stable-backport --self-test
```

## Stable 1.0 maintenance evidence

After GA, `python3 tools/release-certification/certify.py stable-maintenance` is the canonical
routine-maintenance and security-hotfix gate. It authenticates the GA root and latest predecessor,
then requires candidate-bound, fresh production live-network, Hyphanet interop, performance,
multi-node, sandbox, security, upgrade/recovery, and support evidence under the current policy
windows. Fixture, simulated-only, skipped, stale, dirty, test-signing, or wrong-candidate evidence
cannot satisfy production gates.

Routine maintenance uses the complete production windows and target matrix. A policy-qualified
critical security hotfix may shorten only the named prepublication observation windows; it still
passes every non-waivable gate and emits a deadline-bound full-window follow-up obligation. Closing
that obligation is side-effect-free and cannot change the published bytes. Preserve immutable
pre-release-train v1 authorizations for closure: the v1 schema may omit
`backportReleaseTrainDigest` only on this historical path, while every current preparation,
validation, and protected publication must require the exact train digest semantically. Follow
`docs/stable-1.0-maintenance-release-and-hotfix-path.md` and keep protected publication separate
from evidence production. Configure `STABLE_CATALOG_TRUSTED_KEYS_BASE64` on
`stable-1.0-maintenance-evidence` with the public-key-only production catalog registry. The freeze
must verify the exact catalog and detached signature under the declared key id, record the registry
SHA-256, and delete the decoded registry without publishing public-key bytes or embedding raw
signature content in JSON. The exact detached signature sidecar remains a frozen public asset.
Keep the publication provider's immutable source, wheel, signer, and
entry-point identity pins in repository-level Actions variables so the evidence-scoped independent
verifier and both publication environments authenticate the same backend without exposing any
publication-only target secret to the verifier.
Materialize target credentials before backend construction, then permanently remove their names
from both the adapter's environment snapshot and ambient process environment. Backend imports,
observations, and untargeted publication calls must see no catalog, CoreUpdater, or maintenance
state secret; deliver each opaque input only to its closed target operation.
Before authorization, expand and canonicalize every concrete publication-object URI—including
artifact-base children and the detached catalog-signature sibling—and reject aliases across
GitHub Release, artifacts, catalog primary/mirrors/rollback/signature, and CoreUpdater roles.
The canonical maintenance provider verifies but does not populate the public artifact base.
Pre-stage every planned object independently, then require an exact matching artifact-base prefix
before the tag is the first permitted mutation. An absent, partial, or mismatched artifact base
must fail protected preflight; it is not a resumable empty publication state.
Supplied maintenance publication receipts must bind the nested GitHub Release identity—including
release id, integer-build tag, and canonical public page URI—to the exact authorized target; a
passing operation, notes digest, and aggregate public observation are not sufficient.
Before authorization, require the GitHub Release page to be exactly
`https://github.com/crypta-network/cryptad/releases/tag/v<build>`. The protected provider owns that
fixed repository and must compare the deterministic `Cryptad v<build>` title as well as the tag,
commit, page, notes, draft/prerelease state, and assets when verifying exact existing state.
Protected phase-ZIP intake must allowlist the complete extracted file tree, not only the
`protected-inputs/` subtree: the canonical phase manifest and files beneath explicitly referenced
directory inputs are the only survivors, and unrelated root-level or sibling files are blockers.
The latest-baseline activation job must retain its pre-adapter mutation-boundary marker on every
outcome. Its workflow audit conservatively reports that side effects may have occurred once that
marker exists and carries the observed pointer digest from an activation receipt when available;
never describe a missing receipt after that boundary as proof that the pointer was unchanged.
The deployment provider's `verify-publication` call must remain self-contained: send every closed,
digest-bound candidate, lineage, baseline, evidence, provenance, CoreUpdater, and nullable follow-up
record needed to construct the receipt, successor baseline, and history entry. Do not introduce an
undocumented service-side candidate store or treat service construction as producer
authentication; the protected adapter must independently validate every returned record.

Use this focused offline check while changing the maintenance engine, schemas, workflows, or
provider, followed by the broader suites appropriate to the touched integration:

```bash
python3 tools/release-certification/certify.py stable-maintenance --self-test
```

## Stable 1.0 support lifecycle evidence

After authenticating the immutable GA root and complete no-fork maintenance history,
`python3 tools/release-certification/certify.py stable-lifecycle` derives the real published build
inventory and evaluates the policy-driven lifecycle ledger. It never accepts a manifest label as
publication evidence and never publishes from `evaluate`, `prepare-transition`, self-test, or pull
request execution. Use the checked-in support lifecycle policy and closed schemas; do not hardcode
support durations in Python or Java.

The lifecycle ledger is append-only and digest chained. Normal transitions advance through
`current-stable`, `supported-maintenance`, `security-fixes-only`, `deprecated`, and
`end-of-support`. An explicit advisory-backed protected transition may instead enter terminal build
`revoked`; it remains separate from update-key revocation. Authorization must bind the exact
transition request, previous state, resulting ledger, descriptor edition/digest, and target.
Publication then binds the authorization and exact descriptor bytes. Do not create a circular
authorization/ledger digest or represent a self-derived row digest as protected approval.

Keep producer output inside the runtime's closed descriptor contract: at most 256 complete
inventory entries; entry `statusEffectiveAt` no later than descriptor `effectiveAt`; identical
status/security effective timestamps for revocation; and bounded safe recovery text accepted by
both schema and Java parser. `supported-maintenance` carries no mandatory `replacementBuild`;
descriptor-level `recommendedBuild` provides the optional upgrade. A schema-valid producer result
that runtime nodes cannot parse or activate is a release blocker.

The protected workflow has six closed operations: `prove-genesis`, `evaluate`,
`prepare-transition`, `validate-authorization`, `publish`, and `verify-publication`. Bind every
dispatch to the exact release id, chain-tip integer build, source commit, producer run, artifact
name, and Actions artifact digest. Edition 1 requires an attested HTTP `404` proof for the exact
target; HTTP `410` is a tombstone, not genesis. Later editions require the exact prior
ledger/descriptor pair. Publish and verification consume a separately attested lifecycle-only
provider wheel; only publish receives insert material.

Lifecycle workflow source is trusted only when the dispatch ref is protected `main`, the exact
`release/<build>`, or the exact `hotfix/<build>` ref. Require the selected source commit to equal
the workflow-dispatch `GITHUB_SHA` and checked-out `HEAD` so artifact provenance and executed code
have one source identity. It must also remain reachable from the authenticated live remote tip;
that ancestry check permits the branch to advance after dispatch, not an independently selected
older commit. Require GitHub's protected-ref context before requesting an environment. Use a
credential-free preflight for producer inputs, then recheck branch protection and ancestry before
input credentials or publication insert material are exposed.
Configure the lifecycle evidence, authorization, and publication environments with
deployment-branch restrictions for protected `main`, `release/*`, and `hotfix/*`; keep the
workflow's exact-build allowlist as an independent gate.

Keep the complete post-publication component plus external receipt available for independent
verification, but remove protected input trees from the verification bundle. Read-only
verification may occur after approval expiry when it proves that the original receipt timestamp
fell inside the authorization interval. Authorization validation and publication still require a
currently valid approval. Resolve current ledger/descriptor subjects by canonical component path,
because successor bundles intentionally retain prior artifacts with the same basenames.

Stable maintenance certification consumes the authenticated lifecycle state to reject an ordinary
EOL/revoked predecessor, prevent support-clock resets, and propose successor lifecycle changes only
after verified release publication. The protected lifecycle workflow inserts the separate
`support-lifecycle` update-key edition, accepts identical existing bytes only after verification,
and never overwrites a conflict. Follow
`docs/stable-1.0-support-lifecycle-and-deprecation-governance.md` and run:

```bash
python3 tools/release-certification/certify.py stable-lifecycle --self-test
```
