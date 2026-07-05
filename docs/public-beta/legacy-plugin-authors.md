# Public beta onboarding for former plugin authors

Use this guide to map old plugin work to the public-beta app platform without assuming old plugin
compatibility.

## Scope

The old in-process plugin runtime is frozen and removed. The public-beta path is app migration
through signed bundles, reviewed catalogs, Platform API capabilities, app-service grants, durable
app data, content subscriptions, and redacted support evidence.

Start with:

- [../legacy-plugin-freeze-policy.md](../legacy-plugin-freeze-policy.md)
- [../legacy-plugin-migration-guide.md](../legacy-plugin-migration-guide.md)
- [../legacy-plugin-migration-cookbook.md](../legacy-plugin-migration-cookbook.md)
- [../templates/plugin-migration-plan.md](../templates/plugin-migration-plan.md)
- [developer-quickstart.md](developer-quickstart.md)
- [app-submission-walkthrough.md](app-submission-walkthrough.md)
- [support-and-feedback.md](support-and-feedback.md)
- [feedback-to-backlog.md](feedback-to-backlog.md)

## Boundaries

Public beta does not promise:

- old plugin ABI compatibility;
- old FCP plugin command compatibility;
- plugin toadlets;
- old plugin admin pages;
- WebOfTrust protocol compatibility;
- Freetalk protocol compatibility;
- Sone protocol compatibility;
- Freemail protocol compatibility;
- daemon-core social or mail store;
- global moderation;
- daemon-core identity sharing.

FProxy browse remains retained where the legacy-retirement docs say it remains retained. Legacy
admin is maintenance-only.

## Migration entry points

| Old plugin shape | Public-beta entry point |
| --- | --- |
| WebOfTrust-like trust annotations | Trust Graph Local RC pattern and operator-approved `trust.score` app-service grants. |
| Freetalk/Sone-like social or forum UI | Social Inbox RC pattern, content subscriptions, local filters, and durable app data. |
| Freemail-like mail | Future Mail app/service pattern; Social Inbox is not encrypted mail transport. |
| Content publishing | Publisher or Site Publisher reference app patterns. |
| Queue and insert helpers | Queue Manager or app-owned document insert capabilities. |
| Identity/profile plugins | Profile Publisher and AppVault identity grants. |
| Diagnostics plugins | Operator beta dashboard, privacy-preserving diagnostics, and support bundle export. |

See the worked examples under `../examples/plugin-migration/` from
[../legacy-plugin-migration-cookbook.md](../legacy-plugin-migration-cookbook.md).

## Migration plan

Create a migration plan before coding:

1. Identify old plugin state classes and data that need preservation.
2. Map user-visible workflows to app UI, Platform API capabilities, content subscriptions, app data,
   app-service dependencies, and AppVault grants.
3. Decide what remains unsupported forever or outside public beta.
4. Define backup and restore behavior.
5. Define redaction policy for support bundles, review notes, and migration evidence.
6. Build a stable or experimental app with `crypta-app`.
7. Submit through the public-beta app review path.

Use [../templates/plugin-migration-plan.md](../templates/plugin-migration-plan.md).

## Safe artifacts

Migration examples, support reports, and app submissions must stay summary-only. Counts, statuses,
schema versions, app ids, service ids, provider ids, digests, and redaction booleans are acceptable.

Do not publish raw legacy plugin exports, raw social messages, raw trust statements, raw profile or
feed documents, raw app-data values, raw FProxy HTML, private insert URIs, private keys, app or
browser tokens, form passwords, cookies, authorization headers, or local absolute paths.

Use `plugin-migration-feedback.yml` through [support-and-feedback.md](support-and-feedback.md) when
the migration question should become maintainer feedback. Maintainers may match the report to
[known-issues.md](known-issues.md) or turn it into a backlog candidate through
[feedback-to-backlog.md](feedback-to-backlog.md).
