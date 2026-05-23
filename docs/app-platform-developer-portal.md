# App platform developer portal

This page is the entry point for app developers, reviewers, operators, and release managers working
with the Crypta app ecosystem beta.

## Scope

The app platform beta covers offline app authoring, signed bundle and catalog workflows, local
review evidence, first-party reference apps, and release certification. It is not a public
production app store and it does not change FNP, FCP, Hyphanet/Freenet compatibility behavior, or
retained FProxy browse behavior.

Use this portal first, then follow the detailed source-of-truth pages for the area you are touching:

| Area | Source of truth |
| --- | --- |
| Copyable beta tutorials | [app-platform-beta-tutorials.md](app-platform-beta-tutorials.md) |
| Known beta limits and safety boundaries | [app-platform-beta-known-limitations.md](app-platform-beta-known-limitations.md) |
| Beta submission, feedback, and closeout runbook | [app-platform-beta-program.md](app-platform-beta-program.md) |
| Developer CLI reference | [app-dev-cli.md](app-dev-cli.md) |
| Developer beta toolkit flow | [developer-beta-toolkit.md](developer-beta-toolkit.md) |
| Signed app bundles | [app-distribution.md](app-distribution.md) |
| Signed catalogs and catalog sources | [app-catalogs.md](app-catalogs.md) |
| First-party beta catalog | [first-party-beta-catalog.md](first-party-beta-catalog.md) |
| Platform API contract | [platform-api-contract.md](platform-api-contract.md) |
| Platform API route surface | [platform-api-surface.md](platform-api-surface.md) |
| Browser SDK | [platform-sdk-js.md](platform-sdk-js.md) |
| App-owned UI and isolated origins | [app-owned-ui.md](app-owned-ui.md) |
| App UI design system and lint | [app-ui-design-system.md](app-ui-design-system.md) |
| Permissions and audit | [app-permissions-and-audit.md](app-permissions-and-audit.md) |
| AppVault secret and identity material | [app-secret-and-identity-vault.md](app-secret-and-identity-vault.md) |
| AppHost runtime hardening | [apphost-runtime-hardening.md](apphost-runtime-hardening.md) |
| App update lifecycle and rollback | [app-update-lifecycle.md](app-update-lifecycle.md) |
| App review governance | [app-review-governance.md](app-review-governance.md) |
| Feed Reader reference app | [feed-reader-reference-app.md](feed-reader-reference-app.md) |
| Trust Graph Preview | [trust-graph-preview.md](trust-graph-preview.md) |
| Legacy HTTP boundary | [legacy-http-boundary.md](legacy-http-boundary.md) |
| Legacy retirement plan | [legacy-retirement-plan.md](legacy-retirement-plan.md) |
| Release certification | [release-certification.md](release-certification.md) |
| Security reporting and data handling | [SECURITY.md](SECURITY.md) |

## Platform API versions

Cryptad exposes the current local Platform API transport under `/api/v1`. That route family is
separate from the integer app compatibility contract version used by manifests, catalogs,
developer tooling, and release certification.

The current source declares:

```text
PlatformApiContract.CURRENT_API_VERSION = "v1"
PlatformApiContract.CURRENT_CONTRACT_VERSION = 7
```

In docs, manifests, and catalog descriptors:

- `/api/v1` identifies the transport route family.
- `contractVersion=7` identifies the Platform API compatibility contract snapshot.
- `api.minimumVersion` and `api.maximumTestedVersion` compare against the integer contract
  version, not against the URL route prefix or the Cryptad build number.

Use [platform-api-contract.md](platform-api-contract.md) for compatibility rules and
[platform-api-surface.md](platform-api-surface.md) for route families.

## First-party app set

The current first-party app ecosystem beta includes these repo-owned bundles:

| App | App id | Role |
| --- | --- | --- |
| Queue Manager | `queue-manager` | Queue read/write operator workflow. |
| Publisher | `publisher` | Legacy publisher replacement for content insert workflows. |
| Site Publisher | `site-publisher` | Static-site content publishing reference pattern. |
| Profile Publisher | `profile-publisher` | AppVault identity/profile signing plus generated app-document insert. |
| Feed Reader & Publisher | `feed-reader` | Bounded `content.fetch` plus generated feed snapshot publication. |
| Trust Graph Preview | `trust-graph` | Local trust statement import, scoring, signing, and publication preview. |

See [first-party-beta-catalog.md](first-party-beta-catalog.md),
[feed-reader-reference-app.md](feed-reader-reference-app.md), and
[trust-graph-preview.md](trust-graph-preview.md) for app-specific notes.

## Developer path

Start with the offline workflow. The first three commands do not require a live Crypta node, public
network access, signing secrets, Docker, Node.js, or npm:

```bash
./gradlew :platform-devtools:installDist
export CRYPTA_APP="$PWD/platform-devtools/build/install/crypta-app/bin/crypta-app"
"$CRYPTA_APP" --help
```

Then follow this path:

| Step | Command or doc |
| --- | --- |
| Scaffold an app from a template | `crypta-app init --template static-basic|queue-dashboard|publisher|vault-profile` in [app-platform-beta-tutorials.md](app-platform-beta-tutorials.md) |
| Run local UI against mock Platform API fixtures | `crypta-app dev --bundle-dir <bundle>` in [developer-beta-toolkit.md](developer-beta-toolkit.md) |
| Run offline checks | `crypta-app test --bundle-dir <bundle> --strict --json <report.json>` |
| Generate local development signing keys | `crypta-app keys generate` |
| Sign and verify the staged bundle | `crypta-app sign`, then `crypta-app verify` |
| Pack a deterministic ZIP artifact | `crypta-app pack` |
| Create a catalog entry descriptor | `crypta-app catalog entry` |
| Create, sign, and verify a catalog | `crypta-app catalog create`, `crypta-app catalog sign`, `crypta-app catalog verify` |
| Produce an offline USK publication plan | `crypta-app publish-usk --dry-run` |
| Submit app proposal or beta feedback | [app-platform-beta-program.md](app-platform-beta-program.md) |

`crypta-app dev` is loopback-only by default and serves a mock Platform API. It does not install
the app, fetch catalogs, talk to the public Crypta network, or prove live-node permission grants.

## Release manager path

Phase 7 closeout treats these workstreams as one ecosystem beta readiness story:

| Readiness area | Evidence and docs |
| --- | --- |
| First-party catalog | [first-party-beta-catalog.md](first-party-beta-catalog.md), `app-catalog.first-party-beta`, `catalog.smoke` |
| Developer toolkit | [developer-beta-toolkit.md](developer-beta-toolkit.md), `app-platform.devtools-cli`, `app-platform.developer-beta-toolkit` |
| Reference apps | [feed-reader-reference-app.md](feed-reader-reference-app.md), [trust-graph-preview.md](trust-graph-preview.md), `reference-app.*` evidence |
| Review governance | [app-review-governance.md](app-review-governance.md), `review receipt`, `reviewer key lifecycle`, `transparency log` evidence |
| Updates and rollback | [app-update-lifecycle.md](app-update-lifecycle.md), `background update scheduler`, `rollback` evidence |
| Legacy admin status | [legacy-retirement-plan.md](legacy-retirement-plan.md), `legacy-admin.removal-wave-1`, `legacy-admin.removal-wave-2`; FProxy browse remains retained |
| Ecosystem matrix | [release-certification.md](release-certification.md), `ecosystem certification matrix` |
| Docs and beta program | This portal, [app-platform-beta-tutorials.md](app-platform-beta-tutorials.md), [app-platform-beta-known-limitations.md](app-platform-beta-known-limitations.md), [app-platform-beta-program.md](app-platform-beta-program.md) |

Release candidates should run the normal build/test gates plus release certification:

```bash
python3 tools/release-certification/app_platform_docs_check.py --self-test
python3 tools/release-certification/release_certification.py --self-test
python3 tools/release-certification/app_platform_smoke.py --self-test
tools/release-certification/run-release-certification.sh --mode release-candidate --out-dir build/release-certification
```

The generated release summary, release report, app-platform smoke report, review transparency-log
evidence, legacy retirement evidence, and ecosystem certification matrix are the closeout record.

## Security entry points

The beta security model is capability-based and local-node enforced. Browser origin isolation,
signed catalogs, signed bundles, review receipts, and AppVault routes are separate layers.

Start here:

- [app-platform-beta-known-limitations.md](app-platform-beta-known-limitations.md) for conservative
  beta boundaries.
- [app-owned-ui.md](app-owned-ui.md) and [platform-sdk-js.md](platform-sdk-js.md) for browser
  sessions and static UI origins.
- [app-permissions-and-audit.md](app-permissions-and-audit.md) for capability checks and redacted
  audit behavior.
- [app-secret-and-identity-vault.md](app-secret-and-identity-vault.md) for AppVault routes and
  identity/private-material limits.
- [app-catalogs.md](app-catalogs.md) and [app-review-governance.md](app-review-governance.md) for
  signed catalogs, trusted reviewer keys, local review transparency logs, and review policy modes.
- [app-update-lifecycle.md](app-update-lifecycle.md) for manual, stage, and apply-when-stopped
  update behavior plus rollback scope.
- [SECURITY.md](SECURITY.md) for security reporting.

## Feedback and submissions

Use [app-platform-beta-program.md](app-platform-beta-program.md) for proposal requirements,
feedback categories, redaction rules, and the maintainer closeout runbook. GitHub issue forms are
available for app platform beta feedback and app submission proposals when GitHub issue templates
are enabled for the repository.
