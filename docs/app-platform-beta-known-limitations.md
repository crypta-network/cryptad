# App platform beta known limitations

This page records conservative limits and safety boundaries for the Crypta app ecosystem beta.

## General beta limits

- This is an app ecosystem beta, not a public production app store.
- First-party beta catalog support does not imply automatic app installation.
- Recommended catalog metadata is an onboarding hint, not ranking, endorsement, or trust by itself.
- Developer tooling supports offline and dry-run publication planning. Explicit live USK
  publication depends on existing content and queue mechanisms plus the operator's localhost node
  and secure private insert URI configuration.
- `crypta-app dev`, `crypta-app test`, release self-tests, and docs certification do not depend on
  the public Crypta network.
- The beta does not require Docker, Node.js, npm, external network access, signing secrets, or
  public Crypta network access for its offline tests.
- The beta does not modify FNP, FCP, wire protocol, or Hyphanet/Freenet network compatibility
  behavior.
- FProxy browse remains retained.

## Security boundaries

- App UI origin isolation is based on app-owned origins and browser sessions. It is not permission
  to bypass server-side Platform API capability checks.
- Browser app sessions are local browser credentials for static UI calls. Do not treat them as
  long-lived secrets, do not persist them in app local storage, and do not confuse them with
  AppHost process tokens.
- AppHost process tokens must never be exposed through bootstrap JSON, Web Shell state, app UI,
  release evidence, logs, diagnostics, or bug reports.
- AppVault protects app-owned identity and secret material through bounded routes. It does not
  expose private keys, seed material, or raw signing keys to apps.
- `vault.identities.create` creates app-owned identity material. `vault.identities.use` permits
  bounded signing operations such as profile-document or trust-statement signing without exporting
  private material.
- `content.fetch` is bounded Crypta-content fetch. It is not arbitrary HTTP, LAN, local file, or
  loopback fetch.
- `content.subscribe` is bounded durable USK subscription metadata for app-owned feeds. It is not
  a generic crawler, not arbitrary HTTP/HTTPS fetch support, and not a generic app data store.
  Subscription evidence and summaries must not include raw fetched content, queue HTML, private
  keys, browser-session tokens, app process tokens, form passwords, private insert URIs, or
  absolute paths.
- `app.data.read` and `app.data.write` expose bounded app-owned durable state. They are not a
  filesystem API, database engine, browser storage replacement for secrets, or AppVault bypass.
  Apps can read and write only their own records, and evidence must summarize counts, bytes,
  schema versions, hashes, and booleans instead of raw values.
- App-generated document insert stages bytes under Cryptad control. It must not expose absolute
  staging paths, local source paths, raw request bodies, raw profile/feed/trust documents, or
  private insert URIs.
- Trust Graph Preview has durable local backend storage for anchors and imported public
  statements, but it remains a local preview. It is not full Web of Trust, old plugin
  compatibility, global moderation, routing policy, peer selection, or a background crawler.
- Social Inbox Preview is a social/mail-like migration spike outside daemon core and legacy plugin
  APIs. Its `crypta.social.message.v1` route is bounded social-message signing only; it is not a
  generic browser signing API, full WoT, Freetalk, Sone, Freemail, encrypted mail transport,
  moderation, daemon-core message storage, or a network protocol change.
- Review governance uses local trust configuration plus a local tamper-evident transparency log.
  It is not a global public transparency log.
- Sandbox provider support depends on platform and provider availability. Linux bubblewrap support
  can provide an enforced provider on supported systems, but the docs and evidence must not claim
  hard isolation beyond the implemented provider status, tests, quotas, and runtime checks.

## Update and rollback limits

- Background scheduler behavior is policy-driven.
- Manual update policy detects candidates but does not stage or apply automatically.
- `stage` may stage eligible verified candidates according to policy.
- `apply_when_stopped` may apply only when the app is already stopped and catalog, bundle, review,
  compatibility, permission-delta, and health gates pass.
- Permission additions should block unattended apply unless the current implementation explicitly
  supports a stricter approved path.
- Rollback restores the immutable installed bundle. It does not promise to roll back app data,
  cache, run state, external network state, or every user-visible app state.
- Health checks and rollback records are safety mechanisms, not a guarantee that every update
  failure can be undone.

## Review and catalog limits

- Signed catalog, signed bundle, artifact digest, review receipt, and reviewer trust are separate
  layers.
- A valid catalog signature authenticates catalog bytes and publisher metadata only.
- A valid bundle signature authenticates the extracted app bundle payload only.
- A review receipt is independent reviewer evidence. It is trusted only when it verifies against
  local trusted reviewer-key configuration and policy.
- A catalog listing a reviewer key must not automatically establish local reviewer trust unless the
  local implementation explicitly configures that key as trusted.
- Publisher-advisory `review.status` and `review.note` fields do not replace trusted review
  receipts.
- Unknown, revoked, expired, retired, missing, or mismatched reviewer states must be displayed
  honestly and must not be rendered as trusted positive review.
- `crypta:` catalog transport is not a trust boundary. Catalog bytes, catalog signatures, app
  artifacts, artifact digests, bundle signatures, review receipts, reviewer key lifecycle state,
  and permission/API compatibility still need their own checks.

## Data handling and redaction

Do not paste or commit:

- Private signing keys or reviewer private keys.
- Seed phrases, recovery phrases, or private identity material.
- Private insert URIs.
- Browser session tokens, app process tokens, form passwords, authorization headers, cookies, or
  request bodies.
- Raw feed bodies, raw social message bodies, raw fetched social documents, raw trust documents
  from real users, raw profile documents, raw signatures, or raw receipt signatures.
- Local absolute paths, catalog scratch paths, staging paths, rollback backup paths, or host private
  configuration paths unless they are already redacted.

Safe placeholders include:

```text
<redacted>
<token-redacted>
/abs/path/outside/repo/dev-private.der
crypta:CHK@<artifact-key>
crypta:USK@<catalog-key>/cryptad-app-catalog.properties
```

Release certification and issue templates should record statuses, relative repo paths, digests,
app ids, capability names, evidence ids, and redacted summaries instead of raw payloads.

## Non-goals

The beta does not introduce a live public app store, live public-network test dependency, global
transparency log, full Web of Trust, generic crawling, arbitrary HTTP/HTTPS fetching, a generic
filesystem or database API for apps, Freetalk/Sone/Freemail compatibility, encrypted mail
delivery, daemon-core social or mail protocols, new sandbox provider, new update scheduler policy,
legacy route removal wave 3, or any FNP/FCP/wire protocol change.
