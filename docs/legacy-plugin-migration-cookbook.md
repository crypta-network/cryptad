# Legacy plugin migration cookbook

Use this cookbook to turn an old plugin design into a public-beta app or app-service design without
restoring the removed in-process plugin runtime.

Former plugin authors should start with
[public-beta/legacy-plugin-authors.md](public-beta/legacy-plugin-authors.md), then use this
cookbook for hands-on migration patterns, unsupported boundaries, app-service examples, and safe
artifact rules.

## Scope

This cookbook is for plugin authors, reviewers, and release managers. It covers public-beta
migration design, review evidence, and safe migration artifacts. It does not provide old plugin ABI
compatibility, old FCP plugin command compatibility, WebOfTrust/Freetalk/Sone/Freemail protocol
compatibility, or daemon-core compatibility shims. There is no compatibility shim for the old
plugin runtime, old FCP plugin commands, or old plugin APIs.

The old plugin runtime remains removed and frozen. See
[legacy-plugin-freeze-policy.md](legacy-plugin-freeze-policy.md),
[legacy-plugin-migration-guide.md](legacy-plugin-migration-guide.md), and
[plugin-system.md](plugin-system.md).

## Plugin author migration quickstart

Start with a written migration plan, then build the smallest app-platform replacement that exposes
only the reviewed capabilities it needs:

```bash
./gradlew :platform-devtools:installDist
export PATH="$PWD/platform-devtools/build/install/crypta-app/bin:$PATH"

crypta-app init \
  --template hello-stable \
  --id app-id.example \
  --name "Example Migrated App" \
  --version 0.1.0 \
  --dir build/plugin-migration/app-id.example

cd build/plugin-migration/app-id.example
crypta-app test --bundle-dir . --strict --json ../artifacts/app-test.json
crypta-app ui lint --bundle-dir . --strict --json ../artifacts/ui-lint.json
crypta-app api snapshot --output ../artifacts/platform-api-contract.json
crypta-app compat verify \
  --bundle-dir . \
  --contract ../artifacts/platform-api-contract.json \
  --target-stability stable \
  --strict \
  --json ../artifacts/api-compatibility.json
crypta-app pack --bundle-dir . --output ../artifacts/app-id.example.zip --overwrite
```

The `hello-stable` template proves the stable Platform API 1.0 path. If the migration needs
AppVault, app services, Trust Graph Local RC, or Social Inbox RC behavior, switch the manifest to
`api.targetStability=experimental`, set `api.experimentalCapabilitiesAccepted=true`, and explain
why stable API 1.0 is not sufficient in review notes.

## Decision tree

Use this tree before adding code:

```text
Legacy plugin function
-> needs local UI?
   -> build app-owned static UI with browser SDK and UI lint
-> exposes a capability other apps should call?
   -> build an app-service provider with a signed descriptor and bounded scopes
-> consumes another local app's service?
   -> declare an app-service dependency and request an operator-approved grant bundle
-> publishes or fetches structured public documents?
   -> use a content format profile and bounded content fetch/subscription routes
-> keeps mutable local state?
   -> define app-data namespace, schema version, migration steps, and backup/restore policy
-> signs public identity/profile/trust/social documents?
   -> request AppVault app-scoped identity grants and bounded signing routes
-> follows public sources?
   -> use budgeted content subscriptions with source limits and safe retry status
-> distributes to users?
   -> create a submission package, pass pre-review, obtain review decision, stage catalog candidate
-> unsupported daemon hook, old ABI, old FCP command, or protocol compatibility need?
   -> unsupported; no public-beta compatibility path is promised
```

## Migration matrix

| Old plugin concern | Public-beta replacement |
| --- | --- |
| Old plugin UI | App-owned isolated UI plus browser SDK and design-system lint. |
| Plugin config and state | Durable app data namespaces, schema migrations, backup/restore docs, and operator-reviewed migration steps. |
| Plugin identity and secrets | AppVault app-owned identities and app-scoped secret grants. Never export private identity material. |
| Plugin trust score lookup | Trust Graph Local RC `trust.score` app-service dependency with operator-approved grant. |
| Plugin social feed or forum | Social Inbox RC pattern, `crypta.social.message.v1`, `crypta.social.outbox.v1`, content subscriptions, app data, and optional Trust Graph annotations. |
| Plugin content publishing | Site/Profile/Feed publishing patterns, generated app documents, queue APIs, and content format profiles. |
| Queue or insert helper | Queue Manager, Publisher, Site Publisher, Profile Publisher, and Platform API queue/content routes. |
| Plugin distribution ZIP | Submission package, pre-review, review receipt, transparency log, catalog candidate, and beta catalog install smoke. |
| Plugin daemon callback | Platform API capability or app-service grant only when intentionally exposed. |
| Plugin diagnostics | Privacy-preserving diagnostics, support bundle summaries, digests, and explicit redaction checks. |
| Old FCP plugin command | Deterministic unsupported response through `UnsupportedPluginMessage`; no compatibility shim. |

## Unsupported forever or outside public beta

These patterns stay unsupported:

- in-process daemon hooks;
- old plugin ABI/FCP command compatibility;
- WebOfTrust plugin API compatibility;
- Freetalk/Sone/Freemail protocol compatibility;
- ambient localhost RPC;
- raw FProxy scraping;
- direct daemon internals;
- private-key export;
- unbounded crawling;
- daemon-core social, mail, moderation, crawler, or peer-selection stores.

Retained FProxy browse, content rendering, and the content filter remain product surfaces for
content browsing. They do not create a new plugin API and they do not bypass app review.

## WebOfTrust-like trust annotations

Recommended replacement: Trust Graph Local RC plus an app-service grant for `trust.score`.

Use this pattern when the old plugin had local trust anchors, trust statements, profile trust
annotations, or advisory score lookups. The replacement is local-only. It does not define global
truth, global moderation, routing policy, peer-selection policy, content-filter policy, or old
WebOfTrust plugin API compatibility.

| Migration concern | Public-beta requirement |
| --- | --- |
| App mechanism | Trust Graph Local RC app and platform trust graph routes. |
| Provider role | Trust Graph advertises `trust.score` as a local app-service provider. |
| Consumer role | A migrated app declares a dependency on provider `trust-graph`, service `trust.score`, scope `score.read`, and a bounded context such as `profile` or `message-author`. |
| Manifest capabilities | Provider uses trust/content/vault/queue/app-data capabilities. Consumers use `app.services.read` and `app.services.call` only when they need the service. |
| App-data boundary | Store UI-local drafts, filters, imports-in-progress, and redacted summaries in app data. Trust anchors, imported statements, lifecycle records, and scoring state stay in Trust Graph Local RC state. |
| AppVault boundary | Use AppVault for app-owned identities and bounded trust-statement signing. Do not export private identity material. |
| Content profile | Use `crypta.trust.statement.v1` and canonical payload rules from [trust-social-content-format-profiles.md](trust-social-content-format-profiles.md). |
| Import authority | Importing statements is a Trust Graph app capability. A generic consumer app can request scores, but it does not gain raw import/write authority by consuming `trust.score`. |
| Operator consent | Service dependency and grant bundle approval are required before a consumer invokes `trust.score`. |
| Backup/restore | Back up app UI state through app-data backup/restore. Document Trust Graph Local RC export/import separately and keep raw statements out of support bundles. |
| Diagnostics | Release and support evidence may include counts, digests, score status, provider id, service id, and grant status. It must not include raw trust statements or signatures. |
| Non-goals | No full WoT, old WebOfTrust API, global moderation, route/routing policy, peer-selection policy, crawler, or daemon-core trust store. |

Example: [wot-like-trust-graph-app.md](examples/plugin-migration/wot-like-trust-graph-app.md).

## Freetalk/Sone-like social, forum, and profile flows

Recommended replacement: Social Inbox RC plus Profile Publisher, Feed Reader, content
subscriptions, content profiles, app data, AppVault, and optional Trust Graph annotations.

Social Inbox RC is a reference app. It is not Freetalk/Sone protocol compatibility, Freemail
compatibility, full WoT, network moderation, or a daemon-core social store.

| Migration concern | Public-beta requirement |
| --- | --- |
| App mechanism | Build an app-owned UI or reuse the Social Inbox RC pattern for local threads, read state, filters, and source management. |
| Manifest capabilities | Typical social apps need `vault.identities.read`, `vault.identities.create`, `vault.identities.use`, `content.fetch`, `content.subscribe`, `content.insert.app-document`, `queue.read`, `queue.write`, `app.data.read`, and `app.data.write`. Add `app.services.read` and `app.services.call` only for optional Trust Graph annotations. |
| App-data boundary | Store sources, subscription ids, imported-message summaries, local filters, read/unread/archive/pin state, drafts, and UI preferences. Do not store raw fetched documents or private insert URIs. |
| AppVault boundary | Create or use app-owned identities for profiles and signed social messages. Do not share private identity material with another app. |
| Content profiles | Use bounded `crypta.social.message.v1`, `crypta.social.outbox.v1`, and profile/feed content profiles. |
| Subscriptions | Follow explicit USK social outbox sources with content subscriptions. Apply source limits, budgeted refresh, queue-pressure backoff, and bounded errors. |
| Trust annotations | Optional. Consumers call Trust Graph `trust.score` only through app-service grants. Missing provider, rejected grant, revoked grant, expired grant, or provider descriptor drift disables annotations and leaves messages visible. |
| Backup/restore | Include app-data namespaces and schema versions in backup/restore docs. Record what cannot be migrated automatically. |
| Diagnostics | Include counts, source digests, status labels, and redaction booleans only. Support artifacts must not include raw social messages, raw profile documents, raw fetched documents, or signatures. |
| Non-goals | No Freetalk/Sone protocol compatibility, no daemon-core message store, no global moderation, no crawler, and no raw FProxy scraping. |

Example: [social-inbox-migration.md](examples/plugin-migration/social-inbox-migration.md).

## Freemail-like future Mail app pattern

Recommended replacement: no implementation in PR-279. Use a future out-of-process Mail app or
mail app-service design pattern.

Freemail-like authors should treat Social Inbox RC as a bounded message/thread UX reference only.
It is not encrypted mail transport, Freemail protocol compatibility, or a daemon-core mail store.

| Migration concern | Public-beta requirement |
| --- | --- |
| App mechanism | Future Mail should be an out-of-process app or app-service. It must not move mail state into daemon core. |
| Manifest capabilities | Start from app data, AppVault identity use, content subscriptions for mailbox/source polling patterns, and any future mail-specific service dependency only after review. |
| App-data boundary | Store message bodies and mailbox UI state in app data under a documented schema. Do not use daemon internals as a mailbox store. |
| AppVault boundary | Handle identities and signing/encryption keys through AppVault grants. Do not export private identity material. |
| Transport | Encrypted mail transport is out of scope for PR-279. Do not claim compatibility until a future reviewed design defines transport, threat model, and evidence. |
| App-service dependencies | Future services may expose address-book-like summaries, sender reputation, or score annotations. Each service needs a descriptor, dependency declaration, grant bundle, and revalidation. |
| Review | Submission requires explicit threat model, privacy rationale, data schema, migration plan, backup/restore plan, and redaction policy. |
| Non-goals | No Freemail protocol compatibility, encrypted mail implementation, daemon-core mail store, or old plugin API shim. |

Example: [future-mail-app-pattern.md](examples/plugin-migration/future-mail-app-pattern.md).

## Content publishing plugins

Recommended replacement: Site Publisher, Profile Publisher, Feed Reader publishing patterns,
generated app documents, queue APIs, and content format profiles.

| Migration concern | Public-beta requirement |
| --- | --- |
| App mechanism | App-owned publisher UI or first-party publisher pattern. |
| Manifest capabilities | Use `content.insert.app-document`, `queue.read`, and `queue.write` for generated app documents. Add `content.fetch` or `content.subscribe` only when the app actually reads or follows content. |
| App-data boundary | Store drafts, publish summaries, public read URI summaries, document digests, queue request ids, and retry state. Do not store private insert URIs. |
| AppVault boundary | Use AppVault only when signing profile, feed, trust, or social documents. |
| Content profile | Use the relevant profile such as `crypta.profile.v1`, `crypta.feed.snapshot.v1`, or another reviewed app ecosystem profile. |
| Review | Explain generated document bytes, maximum sizes, content type, queue behavior, and redaction plan. |
| Non-goals | No local source-path authority unless a reviewed Platform API route explicitly provides it, and no FProxy page scraping. |

Example: [content-publisher-migration.md](examples/plugin-migration/content-publisher-migration.md).

## Queue and insert-helper plugins

Recommended replacement: Queue Manager, Publisher, Site Publisher, Profile Publisher, and
Platform API queue/content routes.

Queue helpers should use SDK queue helpers and generated app-document inserts. They must not parse
legacy queue HTML, scrape FProxy pages, invoke removed FCP plugin commands, or rely on daemon
internals. A queue helper that only summarizes queue state should request `queue.read`; a helper
that creates app-generated inserts should add `queue.write` and `content.insert.app-document`.

Review evidence should include queue request ids, counts, content types, digests, and status
labels only. It must not include private insert URIs, raw generated documents, raw request bodies,
absolute local paths, or queue HTML.

## Identity and profile plugins

Recommended replacement: Profile Publisher plus AppVault app-owned identities and profile content
profiles.

Identity migrations should classify which old values are public profile metadata, app UI state,
subscription pointers, or private identity material. Public profile metadata can become a bounded
profile document. Private identity material must stay in AppVault and must not be exported through
migration artifacts, app data, support bundles, or review notes.

Use `vault.identities.read`, `vault.identities.create`, and `vault.identities.use` only when the
app needs identity creation or bounded signing. Do not request `vault.identities.manage` for a
third-party migration.

## Diagnostics and support plugins

Recommended replacement: privacy-preserving diagnostics and support bundles.

Diagnostics migrations should produce safe summaries: status labels, bounded counts, feature ids,
capability names, app ids, catalog ids, evidence ids, digests, and redaction booleans. They should
not export raw legacy plugin state, raw support bundles, raw FProxy HTML, raw app data, raw
messages, raw trust statements, raw profile/feed documents, private insert URIs, tokens, cookies,
form passwords, private keys, or local paths.

## Data, identity, and subscription preservation

Every migration plan should classify state before it creates an app-data schema:

| State class | Preservation guidance |
| --- | --- |
| Public content | Keep as public content references, content profiles, document digests, and public read URI summaries. |
| Local config | Move to app data with namespace, schema version, bounds, and defaults. |
| App data | Use additive migrations first. Include dry-run, backup/export before destructive steps, and restore notes. |
| Identity and secrets | Keep in AppVault. Never export private identity material, private keys, seeds, or recovery phrases. |
| Subscriptions | Move explicit public USK follows to content subscriptions with budgets, source limits, and retry metadata. |
| Trust statements | Import only through Trust Graph Local RC. Keep raw statements and signatures out of diagnostics and support artifacts. |
| Messages | Store app-owned message state in app data. Keep support evidence to counts, digests, status labels, and schema versions. |
| Diagnostics | Emit summaries and redaction status only. Do not include raw plugin export bodies or raw FProxy HTML. |

Migration steps should:

- inventory old plugin state and side effects;
- define app-data namespaces and schema versions;
- write additive migrations before destructive migrations;
- support dry-run mode;
- provide backup/export before destructive migration;
- avoid private identity export;
- avoid private insert URI persistence;
- avoid raw fetched document support bundles;
- bind operator consent to data migration and app-service grant deltas;
- document what cannot be migrated automatically.

Use [templates/plugin-migration-plan.md](templates/plugin-migration-plan.md) as the review
template.

## App-service dependency examples

The app-service path is local Platform API mediation, not localhost trust.

| Scenario | Expected behavior |
| --- | --- |
| Social Inbox consumes Trust Graph `trust.score` | Social Inbox declares an optional dependency, requests a grant bundle, and invokes only after operator approval. |
| Generic migrated app requests an optional service | The manifest declares provider, service, scopes, contexts, dependency kind, feature id, degrade behavior, and grant bundle. |
| Provider unavailable | Feature degrades to unavailable state. App does not call localhost or another fallback RPC path. |
| Grant revoked or expired | Invocation fails closed. App shows the feature as unavailable and may request a new bundle. |
| Provider descriptor changed | Grant status becomes revalidation-required until the operator reviews current descriptors. |
| Support bundle generated | Evidence includes provider id, service id, scope, context, status, and digests only. No app-service request bodies or tokens are included. |

Example: [app-service-grant-migration.md](examples/plugin-migration/app-service-grant-migration.md).

## Beta submission flow

Former plugin authors use the same third-party beta intake path as other app authors:

1. Create a migration plan from [templates/plugin-migration-plan.md](templates/plugin-migration-plan.md).
2. Scaffold or adapt an app with `crypta-app init`.
3. Declare manifest capabilities and app-service dependencies.
4. Write permission rationale, security notes, app-data schema notes, migration notes, and
   backup/restore notes.
5. Run `crypta-app test`, `crypta-app ui lint`, and `crypta-app compat verify`.
6. Package with `crypta-app pack`.
7. Create and verify a submission package with `crypta-app submission create` and
   `crypta-app submission verify`.
8. Run `crypta-app submission pre-review`.
9. Reviewers record `reviewed`, `caution`, `rejected`, or `resubmission_requested`.
10. Reviewed or allowed-caution submissions can become catalog candidates.
11. Operators install from the beta catalog after signed bundle, signed catalog, review receipt,
    compatibility, and consent gates pass.

Use these source-of-truth docs:

- [third-party-developer-beta-program.md](third-party-developer-beta-program.md)
- [third-party-app-submission-checklist.md](third-party-app-submission-checklist.md)
- [app-store-submission-and-review-workflow.md](app-store-submission-and-review-workflow.md)

Example: [plugin-author-submission-flow.md](examples/plugin-migration/plugin-author-submission-flow.md).

## Safe artifact rules

Migration examples, fixtures, review notes, support bundles, and release evidence may use
synthetic placeholders such as:

```text
crypta:USK@<example-public-read-key>/profile/1/profile.json
sha256:example-digest
app-id.example
reviewer.example
```

They must not include private insert URIs, private keys, app tokens, browser session tokens,
cookies, form passwords, raw legacy plugin state, raw social messages, raw trust statements, raw
profile documents, raw feed snapshots, raw app-data values, raw signatures, local paths, raw
FProxy HTML, or raw support bundles.

## Review checklist for migrated apps

Before submission, verify:

- old plugin ABI/FCP/runtime/toadlet/admin surfaces are not used;
- manifest capabilities are minimal and justified;
- app-service dependencies are declared and optional features degrade safely;
- AppVault boundaries keep private identity material out of app data and diagnostics;
- app-data namespaces, schema versions, migrations, dry-run behavior, and backup/restore policy
  are documented;
- content subscriptions are bounded and budget-aware;
- content format profiles are documented when public documents are used;
- review notes contain threat model, privacy rationale, security notes, and redaction policy;
- release/support evidence is summary-only and redaction-clean;
- unsupported old plugin protocol/API behavior is listed as a non-goal.
