Security
========

Public-beta security reporting starts at
[public-beta/security-reporting.md](public-beta/security-reporting.md). Public-safe beta support
and handoff guidance starts at
[public-beta/support-and-feedback.md](public-beta/support-and-feedback.md). Those pages summarize
what to include, what never to paste publicly, how app/catalog advisories and denylists work, and
how support-bundle redaction should behave.

Freenet requires different security considerations than other projects.

Any security issue that can correlate your activity with easily observable behavior of your node is critical.

This specifically means:

- any way to crash Freenet when accessing some known content is serious.
- if you can get Freenet or the browser opening a site from Freenet to make a request to some clearnet server depending on the content being accessed, this is serious.

More so if the security issue affects the **friend-to-friend** mode.

There are known unfixable attacks against opennet (Sybil attacks cannot be prevented completely, only their impact reduced).

There are no known unfixable identification-attacks against friend-to-friend mode, except if your friends' nodes attack you.

Attacks we know about are detailed on the opennet attacks and the major attacks page: 

- [Attack in General](https://github.com/freenet/wiki/wiki/Major-Attacks)
- [Attacks against Opennet](https://github.com/freenet/wiki/wiki/Opennet-Attacks)


What to report as normal bugs
-----------------------------

Best practices, hardening tips, and similar are not security issues.
Please report them to our regular bugtracker:
https://bugs.freenetproject.org

If you are unsure whether your issue is a security issue, please come
to our IRC channel (#freenet at irc.libera.chat) and talk to an op:
https://web.libera.chat/?nick=FollowingTheRabbit|?#freenet


Reporting Security Issues
-------------------------

Please report security issues to security@freenetproject.org
encrypting to all PGP/gnupg keys from our [Keyring](https://freenetproject.org/assets/keyring.gpg).

Please do not file public reports of security problems that could be
used to connect the pseudonyms of users with the nodes they run. If
you find those, please send them to the email address above so they
can be resolved and the fix released before the vulnerability gets
someone in danger.

We will acknowledge a report within one week. If you do not get a reply
within one week, it most likely got lost: Please send it again!


App bundle, catalog, and UI trust boundaries
--------------------------------------------

Signed AppHost bundles and signed app catalogs use developer-supplied Ed25519 key material during
local build, verification, install, and catalog-refresh flows.

- Do not commit production private keys, keystores, or exported PKCS#8 private key material to this repository.
- Keep local development keys outside the repo and pass them through Gradle properties or environment variables, or point at local files outside the checkout.
- If you generate a development-only key pair for testing signed bundles or catalogs, label it clearly as non-production and rotate or remove it when no longer needed.
- The unsigned-bundle bypass is only for explicit local development. It does not make remote catalogs or remote artifacts trusted.

Catalog installs and updates verify the signed catalog, the advertised artifact size and SHA-256,
and the extracted bundle signature before AppHost installs the app. The catalog signature
authenticates catalog bytes and publisher metadata only. Legacy catalog `review.status` and
`review.note` fields are publisher-advisory metadata and are not a cryptographic review trust
boundary.

Independent app review receipts use a separate trusted reviewer-key registry. A trusted receipt
signature binds the reviewer key id, app id, app version, artifact digest, artifact size, review
policy id/version, reviewer status, timestamps, and optional evidence metadata to canonical receipt
payload bytes. Do not reuse app or catalog signing trust implicitly for review receipts, and do not
commit reviewer private keys. Reviewer-key registry v1 remains supported, but governed deployments
should prefer v2 entries with active, retired, or revoked lifecycle state, strict validity windows,
rotation metadata, and policy-version constraints. Revoked keys fail closed for all receipts;
retired keys can verify only historical receipts inside their configured windows.

Reviewer-key registry v3 can also revoke one exact receipt by `receiptFingerprintSha256`.
Revoked receipts fail closed as `revoked_receipt`; they are not treated as trusted positive,
trusted caution, or trusted rejection evidence. A compromised reviewer key should be marked
`status=revoked` with `revoked.at` and `revocation.reason`; receipts signed by that key fail as
`revoked_reviewer`.

Catalog v4 security policy is signed catalog metadata. It can define catalog-level advisory
records and exact app-version denylist entries. `denylist` blocks install, update, stage, apply,
and automatic policy apply. `warn` requires the independent `securityAcknowledged=true` manual
acknowledgement and blocks unattended automation. Security acknowledgement cannot bypass review,
channel, migration, service dependency, compatibility, digest, signed catalog, or signed bundle
gates. Web Shell may show safe uninstall guidance for installed vulnerable versions, but Cryptad
does not automatically uninstall apps and does not silently migrate replacements.

Production beta incident response for vulnerable app versions, malicious catalog entries, app or
catalog signing-key compromise, reviewer-key compromise, emergency replacement publication, support
bundle intake, and security release notes is defined in
[production-security-response-runbook.md](production-security-response-runbook.md). The runbook is
the release-manager procedure; its required drill artifacts and
`security-drills-summary.json` are release gates, and missing, failed, stale, malformed,
fixture-only production, or redaction-unsafe drills block promotion. This document defines the
trust and redaction boundaries those artifacts must preserve.
Default operator support bundles follow
[privacy-preserving-beta-diagnostics.md](privacy-preserving-beta-diagnostics.md): they are local
until the operator explicitly exports them, and public support should start with digest and summary
fields from [public-beta/support-and-feedback.md](public-beta/support-and-feedback.md). Suspected
support-bundle redaction failures, advisory events, reviewer key compromise, catalog signing key
compromise, or app signing key compromise belong on the private security path. Support bundles
exclude raw content, raw app data, private insert URIs, tokens, identity material, local paths, and
legacy plaintext diagnostics bodies.

Former plugin authors use the public-beta path in
[legacy-plugin-migration-cookbook.md](legacy-plugin-migration-cookbook.md). Migration plans,
examples, review notes, diagnostics, and support bundles must stay summary-only: counts, statuses,
schema versions, digests, app ids, provider ids, service ids, and redaction booleans are acceptable;
raw legacy plugin state, raw social messages, raw trust statements, raw profile/feed documents, raw
app-data values, raw FProxy HTML, private insert URIs, private keys, app or browser tokens, form
passwords, cookies, and local paths are not. The cookbook does not restore old plugin ABI/FCP
compatibility, in-process plugin runtime behavior, plugin toadlets, plugin admin pages, or
WebOfTrust/Freetalk/Sone/Freemail compatibility shims.

The app-review transparency log is local and tamper-evident. It is not a global public log and does
not create trust by itself. Platform API, Web Shell, CLI, and release-certification review surfaces
may expose reviewer key ids, display names, lifecycle status, policy ids/versions, timestamps,
evidence digests, evidence URIs, record counts, and latest hashes, but must not expose reviewer
public key bytes, reviewer private key material, raw receipt signatures, local receipt or evidence
paths, transparency-log paths, catalog scratch paths, staging paths, browser session tokens,
request bodies, form passwords, or AppHost process tokens.

Catalog fetches support local files, `https:`, and loopback-only `http:` sources. Catalog ZIP
extraction drops macOS `__MACOSX/**`, AppleDouble `._*`, and `.DS_Store` metadata entries before
verification; executable app payload still has to match the signed bundle digest.

App-owned static UI routes serve files from the immutable installed bundle. Static apps prefer a
distinct loopback-only browser origin per app, with `/apps/{appId}/` retained as a compatibility
and diagnostics fallback. They do not serve app data, cache, run directories, catalog scratch
directories, or caller staging paths. External URL entries are rejected, app UI listeners bind only
to loopback addresses, and route responses use conservative CSP, `nosniff`, no-referrer, and
non-public no-cache headers.

AppHost process launches are local child processes unless a sandbox provider is selected. AppHost
starts each app with the installed bundle root as its working directory, a minimal environment,
per-app data/cache/run directories, and a per-launch `CRYPTAD_APP_TOKEN` for app-originated
Platform API authentication. App manifests can request `sandbox.mode=none`,
`restricted-process`, or `wasm-preview`, and Platform API/Web Shell surfaces report the requested
mode and actual support level. On Linux hosts with bubblewrap available, `restricted-process` can
run through the `bubblewrap` provider and report `supportLevel=enforced`. That provider enforces
filesystem containment for the installed bundle and AppHost-managed mutable directories, but it
does not enforce CPU, memory, or network limits. When bubblewrap is unavailable and the app does
not require an enforced sandbox, the existing restricted-process provider remains best-effort
launch hygiene, not a container, WASM runtime, seccomp profile, chroot, jail, Windows Job Object
policy, network isolation, or browser UI origin isolation. Browser UI origin isolation is provided
by the app-owned UI loopback listener layer and does not make the child process sandboxed.

AppHost enforces manifest data/cache quotas only when `quota.data.bytes` or `quota.cache.bytes` is
positive. Missing quota fields and explicit `0` values mean unlimited or no explicit app quota for
backward compatibility with existing first-party app manifests. Enforcement is scoped to
AppHost-managed app data and cache directories, uses path-free status warnings for incomplete scans,
and blocks launch or automatic restart for positive quotas when an enforced area cannot be measured
completely. AppHost also bounds each managed `process.log` file on a best-effort basis at lifecycle
and status checkpoints, while retaining a small redaction overlap before the visible tail so log
bounding does not split tokens or known AppHost paths away from the context needed to redact them.
These quotas do not provide CPU, memory, network, container, or full filesystem isolation and do not
replace the sandbox provider model.

App-originated Platform API calls authenticate with the launch token in `X-Crypta-App-Token`.
`Authorization: Bearer` is accepted only when the Bearer value matches a live app token; unrelated
Bearer credentials continue through the host/operator path so reverse proxies and shared clients do
not accidentally convert local management requests into failed app-token attempts. Valid app
principals are denied by default unless the route is covered by manifest-declared capabilities such
as `queue.read`, `queue.write`, `content.fetch`, `content.subscribe`, `content.insert`, or
`content.insert.app-document`. App-facing content fetch is bounded and Crypta-content-only;
content subscriptions are bounded USK metadata only. Neither surface may become local file access,
arbitrary HTTP(S) fetch, generic crawling, or LAN probing. Invalid or stale
`X-Crypta-App-Token` values fail authentication, and missing capabilities fail authorization
without echoing the token.
Foreground content fetches, subscription refresh/polling, and Trust Graph import-by-URI also share
finite app/global app-network budgets. Budget and queue-pressure failures must use stable redacted
status codes and retry metadata rather than daemon exceptions, raw queue output, or raw fetched
content.

App-owned static browser UI uses a separate browser app session. On isolated app origins, the
dynamic bootstrap at `/.well-known/cryptad-bootstrap.json` returns route metadata, the absolute
admin Platform API root, UI origin metadata, an opaque `browserSessionToken`, and an expiry
timestamp. The compatibility `/apps/{appId}/.well-known/cryptad-bootstrap.json` route remains for
explicit same-origin fallback. Static UI sends that token as `X-Crypta-App-Session`; the Platform
API treats the request as an app browser principal and applies the same manifest capability matrix.
Browser sessions are distinct from `CRYPTAD_APP_TOKEN`, are bound to one installed static app and
the expected browser origin, and must not be persisted by app JavaScript. Invalid browser sessions
fail with `401 invalid_app_browser_session`; mismatched isolated origins fail with
`403 origin_mismatch`.

Static app UI responses use an explicit local CSP: `default-src 'none'`, local-only script and
style sources, `connect-src 'self'` plus a validated local Platform API origin when isolated,
`object-src 'none'`, `base-uri 'none'`, `worker-src 'none'`, `frame-src 'none'`, and local
`frame-ancestors`. Platform API and shell origins are inserted only when they are local admin
origins using `127.0.0.1`, `localhost`, `[::1]`, or `[0:0:0:0:0:0:0:1]` without credentials,
query strings, fragments, wildcard bind addresses, or suffix-trap hostnames. CSP is a browser mitigation
for bundled static UI. It does not replace
AppHost process sandboxing, signed bundle verification, app-token authentication, or server-side
capability checks.

Isolated bootstrap token issuance also requires an admin/Web Shell launch proof. Web Shell first
checks that the current browser can read a token-free origin probe from the app loopback listener.
Only then does it send an explicit same-origin compatibility launch request, which redirects to the
isolated origin with a short-lived nonce in the URL fragment. If the probe is not reachable, such as
from a remote browser or a single-port tunnel, the compatibility route remains a same-origin
fallback. The SDK echoes the launch proof as `X-Crypta-App-Bootstrap-Nonce` before the loopback
server returns a browser-session token. Public app-origin URLs and app summaries do not contain this
proof and are not enough to mint browser sessions.

Platform API CORS for app browsers is restricted to active registered app UI origins. It never uses
wildcard `Access-Control-Allow-Origin`, never allows cookies or local-admin credentials, and does
not allow `X-Crypta-App-Token` through app-browser preflight. Requests from registered app origins
without `X-Crypta-App-Session` fail as app-browser requests and cannot silently fall back to
host/operator authentication.

Runtime status and process-log Platform API responses must remain token-free and path-free. Log
tail responses redact the current launch token and obvious `CRYPTAD_APP_TOKEN=...` text before
returning app output to the Web Shell. Process-log truncation keeps enough overlap before the
bounded tail for that redaction step. This is defense in depth for operator visibility; it is not a
general secret scanner for arbitrary app output.

App-originated allowed and denied Platform API decisions are recorded in a bounded process-local
audit log. Audit events keep route family, action, required capabilities, decision, status, and a
short reason code. They also include the token-free authentication source so operators can
distinguish process-token requests from browser-session requests. They must not include raw launch
tokens, raw browser session tokens, query strings, request bodies, form passwords, signatures, or
filesystem paths.

Public-beta release evidence is redacted evidence, not a raw-data export. App audit events,
app-service audit events, trust graph audit events, app-data summaries, review governance reports,
local transparency-log verification responses, live USK publication summaries, AppHost log tails,
and Web Shell summaries may include counts, hashes, policy ids, key ids, lifecycle states, status
codes, and bounded redacted summaries. They must not include private insert URIs, private keys,
raw fetched bodies, raw request bodies, raw trust statements, raw signatures, app or browser
tokens, form passwords, local paths, catalog scratch paths, raw app bundle paths, raw app-data
values, app-service invocation bodies, raw Social Inbox messages, or raw profile/feed documents.

The app secret and identity vault is a local at-rest protection boundary, not a remote KMS,
hardware-backed enclave, OS keychain, or replacement for process sandboxing. Vault records are
encrypted with a host-local wrapping key file protected by local filesystem permissions; that
protects against casual offline disclosure but not malware, a compromised daemon, a debugger, or a
same-user process. App secret values, identity private keys, signing payloads, private insert URIs,
vault storage paths, browser session tokens, app process tokens, form passwords, and absolute
staging paths must not appear in public JSON, Web Shell summaries, app audit events,
release-certification reports, diagnostics, or logs. Profile-document responses may include public
verification material such as `signature.signatureBase64`; app audit events,
release-certification evidence, diagnostics, and logs must not record raw signatures or signing
payloads. App browser principals may create app-owned identities through
`POST /api/v1/app-vault/identities` when authorized by `vault.identities.create`, and Profile
Publisher may use the documented profile-document route when authorized by `vault.identities.read`
plus `vault.identities.use`. Raw secret read/write and broader identity-use operations remain
restricted unless a contract explicitly broadens that surface with tests and docs.

Trust Graph Local RC adds a bounded trust-statement signing route rather than a generic browser-safe
identity-use route. `POST /api/v1/app-vault/identities/{identityId}/trust-statement` requires
`trust.write`, `vault.identities.read`, and `vault.identities.use`; it signs only the canonical
`crypta.trust.statement.v1` payload and must not expose private key material, vault paths, raw
request bodies, app process tokens, browser session tokens, form passwords, or local paths. The
local trust graph API is a durable local RC service, not full WoT, old WebOfTrust plugin
compatibility, moderation, routing policy, or peer-selection policy. Trust anchors are local,
imported statements are non-contributing until anchored and signature-verified, and release
evidence must not record raw trust statement bodies from real users, raw fetched content, private
insert URIs, or raw signature values.

Static UI code should run on its isolated per-app loopback origin when available. Browser app
sessions improve server-side attribution and capability enforcement for SDK/API calls, and the
isolated origin separates app JavaScript from the Web Shell/admin origin. The compatibility
same-origin `/apps/{appId}/` path is for fallback and diagnostics, not the preferred third-party
app UI boundary.

Treat a bypass that serves host files, follows symlink escapes, executes JavaScript while the admin
UI has JavaScript disabled, exposes AppHost launch tokens or browser session tokens to the wrong
surface, binds app UI listeners to wildcard or LAN-visible interfaces, shares one browser origin
across unrelated static apps, authenticates app browser requests as host/operator requests, bypasses
app capability checks, or allows bundled UI to exfiltrate operator-entered data off-node as
security-relevant.

For the detailed runtime boundary, exposed environment variables, restart policy semantics,
permission matrix, audit model, and remaining limitations, see
[apphost-runtime-hardening.md](apphost-runtime-hardening.md) and
[app-permissions-and-audit.md](app-permissions-and-audit.md).
