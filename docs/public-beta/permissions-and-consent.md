# Public beta app permissions and consent

Use this guide to read app permission prompts, update permission deltas, service grant bundles,
app-data migration consent, security advisory acknowledgement, and audit events.

## Scope

This page is the user-facing summary. Enforcement and audit behavior are defined in
[../app-permissions-and-audit.md](../app-permissions-and-audit.md),
[../user-consent-and-permission-upgrade-ux.md](../user-consent-and-permission-upgrade-ux.md), and
[../app-service-discovery-and-grants.md](../app-service-discovery-and-grants.md).

## Capabilities

Apps request named capabilities such as content fetch, app-owned document insert, durable app data,
content subscriptions, identity/profile use, Trust Graph read/write, and app-service discovery or
calls. Host/operator-only capabilities are not normal third-party app permissions.

Each consent prompt should explain:

- app id and version;
- requested capabilities;
- why each capability is needed;
- whether a capability is new on update;
- whether a service dependency is optional or required;
- whether an app-data migration or backup is part of the change;
- security advisory and review status.

## Consent decisions

You can approve or deny an install, update, service grant, migration, or security acknowledgement.
Approval is bound to the exact consent snapshot. If the app, catalog entry, permission set, service
dependency, migration plan, or security advisory changes, Cryptad should ask again.

Safe decision rules:

- Deny permission requests you do not understand.
- Deny optional grants if you do not need that integration.
- Treat required grants as part of the app's operating model.
- Back up app data before migration consent.
- Do not acknowledge a security warning unless you understand the warning and still want to
  proceed.

## Permission deltas on update

An update can add, remove, or change capabilities. Web Shell should present the delta before apply.
An app that changes from stable Platform API use to experimental use needs explicit review and
compatibility evidence; the stable baseline remains separate from experimental app-facing APIs.

## App-service dependency grants

App-service grants mediate local app-to-app calls. They are not generic RPC, remote discovery,
cross-app app-data access, or old plugin ABI compatibility.

Review:

- provider app id and service id;
- consumer app id;
- requested scopes;
- optional versus required dependency;
- grant expiry, renewal, and revocation;
- provider revalidation status;
- whether the grant is needed for Trust Graph score annotations or another local service.

Grant expiry, renewal, and revocation should appear in audit records and Web Shell summaries without
tokens, raw request bodies, raw subject URIs, provider app data, or local paths.

## App-data migration consent

Migration consent applies when an update changes durable app-data schema. The preview should show
schema versions, action counts, expected backup state, and warnings. It must not expose raw app-data
values or backup payloads in support evidence.

See [../app-upgrade-data-migrations.md](../app-upgrade-data-migrations.md) and
[../app-data-backup-restore-portability.md](../app-data-backup-restore-portability.md).

## Security advisory acknowledgement

Security acknowledgement is a manual decision for a signed advisory warning. It cannot make a
denylisted app installable, and it cannot bypass review, channel, signature, digest, compatibility,
migration, or service dependency gates.

See [../ecosystem-security-advisories.md](../ecosystem-security-advisories.md).

## Audit events

Audit events should record bounded metadata: principal, capability, app id, decision, status,
timestamps, and redaction state. They must not include query strings, request bodies, form
passwords, app tokens, browser session tokens, private insert URIs, raw app data, or local absolute
paths.
