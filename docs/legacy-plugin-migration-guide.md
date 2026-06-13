# Legacy plugin migration guide

This guide explains how legacy plugin-style functionality should move to the Crypta app platform.

## Status and non-goals

The old plugin runtime removed status is intentional and frozen for production RC. See
[legacy-plugin-freeze-policy.md](legacy-plugin-freeze-policy.md) and
[plugin-system.md](plugin-system.md) for the current policy. The Cryptad node no longer implements
the old in-process plugin runtime, `network.crypta.pluginmanager`, plugin toadlets, or old plugin
FCP commands.

Production RC migration work does not restore old plugin ABI compatibility, old FCP plugin command
compatibility, or compatibility shims for WebOfTrust, Freetalk, Sone, or Freemail plugin APIs.
Migration work should use out-of-process apps, signed bundles, signed catalogs, Platform API
routes, AppVault, budgeted USK content subscriptions, durable app data, Trust Graph Local RC, app
review governance, and operator-approved local app-service grants instead of daemon-core plugins.

The migration path also does not change FNP, FCP, Hyphanet/Freenet wire behavior, FProxy browse,
content rendering, or retained legacy admin fallback routes.

## Migration architecture overview

Legacy plugin responsibilities map to existing app-platform mechanisms:

| Legacy plugin concern | New app-platform mechanism |
| --- | --- |
| Plugin UI | App-owned isolated UI, local design system, and browser SDK |
| Plugin configuration/state | App manifest plus app data durable store |
| Plugin identity/secrets | App vault grants and bounded AppVault signing routes |
| Content polling | Budgeted USK content subscriptions |
| Content publishing | App-generated documents plus queue APIs |
| Trust scoring | Trust Graph Preview plus an app-service grant to `trust.score` |
| Social/message board patterns | Social Inbox RC reference app |
| Distribution | Signed bundles, signed catalogs, and trusted review receipts |
| Compatibility/review | Platform API contract verifier and app review governance |

The app platform keeps authority explicit. Apps declare capabilities and rationales in their
manifest, use SDK helpers for Platform API calls, and rely on operator-approved grants when one app
needs a local service from another app.

## Category-specific migration patterns

### WebOfTrust-like trust layer

Map WebOfTrust-like or WoT-like trust behavior to Trust Graph Preview. The current preview gives
apps a local trust graph backend, durable trust graph storage, AppVault-backed trust-statement
signing, budgeted USK content subscriptions for public trust-statement exchange, and a mediated
`trust.score` service that consumers can call only after an operator-approved app-service grant.

A migrated trust app should:

- Keep identity/private material in AppVault.
- Store UI-local draft and filter state in app data.
- Use budgeted USK content subscriptions for public trust-statement follow behavior.
- Publish generated trust documents through app-generated document insert routes.
- Advertise local scoring through app-service metadata instead of direct localhost access.
- Obtain review receipts before catalog distribution.

This is not full WoT, not global moderation, not routing policy, not old WebOfTrust plugin
compatibility, and not an old plugin ABI compatibility layer.

### Freetalk/Sone-like social feed or forum layer

Map Freetalk/Sone-like social feed, forum, profile, or message-board behavior to Social Inbox
Preview, Profile Publisher, Feed Reader, budgeted USK content subscriptions, app-data state, and
Trust Graph score annotations.

Social or forum apps should:

- Use Profile Publisher or AppVault profile-document signing for public author metadata.
- Use Social Inbox-style bounded `crypta.social.message.v1` documents for message-like content.
- Follow public source feeds with durable budgeted USK content subscriptions.
- Persist source summaries, read state, drafts, and imported-message summaries in app data.
- Publish generated outbox or feed documents with app-generated document insert routes.
- Use Trust Graph Local RC score annotations through `trust.score` app-service grants when trust
  context is useful.

This is not old Freetalk/Sone plugin compatibility, not a daemon-core social store, not global
moderation, and not a new social network protocol in daemon core.

### Freemail-like mail/message layer

Treat Social Inbox RC as a bounded mail/social reference app, not as Freemail
compatibility. It proves that message-like workflows can compose AppVault identity use, generated
documents, budgeted USK content subscriptions, app data, and Trust Graph annotations outside
daemon core.

Freemail-like designs should start as app-level designs with their own explicit threat model,
manifest capabilities, catalog review, and user-facing limitations. Future encrypted mail would be
a separate app design that uses app-platform primitives where appropriate. It is not encrypted
email delivery in this PR, not Freemail protocol compatibility, and not a resurrection of core or
plugin mail APIs.

### Content publishing plugins

Map content publishing plugins to Site Publisher, Profile Publisher, generated app documents, and
queue APIs. Apps should stage generated bytes through the app-generated document insert route when
the app creates the document, and should use queue read/write capabilities only for the minimum
publisher workflow they need.

Publishing apps should avoid local source-path authority unless a replacement explicitly covers
that legacy workflow. Release evidence should record document type, content type, queue status,
hashes, counts, and booleans instead of raw document bodies or private insert URIs.

### Queue or insert-helper plugins

Map queue or insert-helper plugins to Queue Manager, Publisher, Site Publisher, Profile Publisher,
or Platform API queue/content routes. Queue integrations should use the SDK queue helpers and
`content.insert.app-document` for app-generated documents. They should not parse legacy queue HTML,
scrape FProxy pages, or call removed plugin FCP commands.

## Developer migration recipe

Use this checklist before proposing an app migration:

- Inventory the legacy plugin's permissions, persisted state, network effects, daemon callbacks,
  UI surfaces, and side effects.
- Choose an app-owned UI flow and SDK helpers instead of a plugin toadlet.
- Map identities, secrets, and signing operations to app vault grants and bounded AppVault routes.
- Map local configuration and mutable state to app data namespaces and records.
- Map polling or follow behavior to budgeted USK content subscriptions with source limits,
  queue-pressure backoff, and shared app-network budgets.
- Map trust dependencies to app-service grants, usually `trust-graph` / `trust.score` for local
  score annotations.
- Add manifest permissions and a rationale for every requested capability.
- Run app UI lint and Platform API compatibility verification.
- Package and sign the app bundle.
- Publish a signed catalog entry when the app is ready for distribution.
- Obtain an independent review receipt or document why review governance is pending.
- Add release-certification evidence that proves the migration path without raw payloads or
  secrets.

## Executable reference app

`apps/social-inbox` is the current executable threaded social inbox reference app. See
[social-inbox-reference-app.md](social-inbox-reference-app.md) for the app contract, manifest
permissions, durable state, and evidence ids.

The app demonstrates:

- App vault identity listing, creation, and bounded profile/social-message signing.
- App data records for UI state, sources, outbox summaries, imported-message summaries,
  channel filters, message/thread read state, and explicit drafts.
- Local threads built from the existing signed `replyTo` field, with bounded search and safe
  author profile links over imported summaries.
- Budgeted USK content subscriptions for bounded social source follow behavior.
- App-generated outbox documents inserted through queue/content Platform API routes.
- Trust Graph Local RC score annotations through the `trust.score` app-service grant path.
- Signed bundle, signed catalog, review receipt, and catalog/review governance flow.

The app deliberately stays outside daemon core and old plugin APIs. It is not full WoT, not
Freetalk/Sone/Freemail compatibility, not encrypted mail transport, not a crawler, and not a
daemon-core message store or protocol.

## Security and privacy boundaries

Migration designs must keep these boundaries:

- No ambient localhost trust. Apps use Platform API routes and mediated app-service grants.
- No private insert URI leakage in docs, app data, logs, diagnostics, release evidence, or bug
  reports.
- No raw message bodies, fetched bodies, trust bodies, request bodies, or signatures in release
  evidence.
- No form passwords, app tokens, browser-session tokens, private keys, cookies, credentials, or
  recovery material in reports or examples.
- App-to-app calls require operator-approved grants and current provider descriptors.
- Browser-visible app UI remains origin-isolated where the platform provides that mode; server-side
  Platform API capability checks remain authoritative.
- Content subscriptions, foreground content fetches, and Trust Graph import-by-URI share
  app-network budgets. Budget exhaustion and queue pressure must produce bounded retry/status
  metadata, not daemon exceptions or raw queue/content output.
- Signed bundles and signed catalogs verify distribution artifacts; review receipts provide
  independent governance evidence and do not replace catalog or bundle signatures.

Do not encourage apps to call arbitrary localhost services, proxy generic RPC, reuse another app's
app data, or bypass AppVault for private material.

## Known limitations

- No plugin ABI compatibility.
- No old FCP plugin command compatibility.
- No full WoT.
- No WebOfTrust, Freetalk, Sone, or Freemail compatibility.
- No encrypted mail transport.
- No daemon-core social or mail store.
- No generic crawler or unbounded subscription polling.
- No network protocol change.
- No generic browser signing API.
- Legacy retained routes remain retained until their replacements are complete and separately
  certified.
