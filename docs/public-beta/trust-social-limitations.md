# Trust Graph and Social Inbox public beta limitations

Read this page before testing Trust Graph Local RC, Social Inbox RC, or apps that request
Trust Graph score annotations.

## Trust Graph Local RC

Trust Graph Local RC is local advisory trust only.

It is:

- a local reference capability for importing, previewing, scoring, and explaining trust statements;
- bounded by local operator decisions and app-service grants;
- useful for local annotations such as `trust.score` where the operator approved the provider and
  consumer relationship.

Boundaries:

- not global WebOfTrust;
- not routing policy;
- not global moderation;
- not a crawler;
- not legacy WoT compatibility;
- not a daemon-core identity-sharing system;
- not authority for apps to import or mutate trust data without approved capabilities or grants.

Apps use `trust.score` only through operator-approved app-service grants. A grant to read score
annotations does not grant authority to import statements, mutate anchors, change lifecycle states,
or publish trust material.

Source docs:

- [../trust-graph-preview.md](../trust-graph-preview.md)
- [../trust-social-content-format-profiles.md](../trust-social-content-format-profiles.md)
- [../legacy-plugin-migration-cookbook.md](../legacy-plugin-migration-cookbook.md)

Report Trust Graph import warnings with [support-and-feedback.md](support-and-feedback.md) and
`app-specific-feedback.yml`. Include app id, app version, catalog channel, redacted trust/social
document profile id when relevant, warning code, support bundle digest, expected result, and actual
result. Do not include raw trust statements.

## Social Inbox RC

Social Inbox RC is a local threaded social/message reference app.

It can:

- manage bounded local subscriptions and message threads;
- keep read/unread state, local filters, exports, and profile summaries;
- display local Trust Graph score annotations through app-service grants;
- demonstrate social/message content format profiles for public-beta app testing.

Boundaries:

- not Freemail;
- not Freetalk/Sone compatibility;
- not encrypted mail transport;
- not global moderation;
- not daemon-core social store;
- not a background crawler;
- not a promise that old social plugins will run unchanged.

Source docs:

- [../social-inbox-reference-app.md](../social-inbox-reference-app.md)
- [../trust-social-content-format-profiles.md](../trust-social-content-format-profiles.md)
- [../legacy-plugin-migration-guide.md](../legacy-plugin-migration-guide.md)

Report Social Inbox rendering or subscription issues with
[support-and-feedback.md](support-and-feedback.md) and `app-specific-feedback.yml`. Include app id,
app version, catalog channel, redacted subscription id when relevant, support bundle digest,
expected result, and actual result. Do not include raw social messages.

## Legacy social and mail boundaries

Former WebOfTrust, Freetalk, Sone, and Freemail plugin authors should start with
[legacy-plugin-authors.md](legacy-plugin-authors.md). The public-beta path is app-based migration
through Platform API capabilities, app-service grants, content subscriptions, durable app data, and
reviewed catalog submission. It is not old plugin ABI, FCP plugin command, toadlet, WebOfTrust,
Freetalk, Sone, or Freemail protocol compatibility.
