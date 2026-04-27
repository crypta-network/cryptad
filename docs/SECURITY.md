Security
========

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
and the extracted bundle signature before AppHost installs the app. Catalog fetches support local
files, `https:`, and loopback-only `http:` sources.

App-owned static UI routes serve files from the immutable installed bundle under `/apps/{appId}/`.
They do not serve app data, cache, run directories, catalog scratch directories, or caller staging
paths. Static UI remains same-origin with the local admin UI and Platform API, so external URL
entries are rejected and route responses use conservative CSP, `nosniff`, no-referrer, and
non-public no-cache headers.

AppHost process launches are process isolation, not sandboxing. AppHost starts a local child
process with the installed bundle root as its working directory, a minimal environment, per-app
data/cache/run directories, and a per-launch `CRYPTAD_APP_TOKEN` for app-originated Platform API
authentication. It does not currently provide containers, WASM isolation, seccomp, chroot, jails,
Windows Job Object restrictions, network isolation, or browser-scoped app sessions.

App-originated Platform API calls authenticate with the launch token in `X-Crypta-App-Token`.
`Authorization: Bearer` is accepted only when the Bearer value matches a live app token; unrelated
Bearer credentials continue through the host/operator path so reverse proxies and shared clients do
not accidentally convert local management requests into failed app-token attempts. Valid app
principals are denied by default unless the route is covered by manifest-declared capabilities such
as `queue.read`, `queue.write`, or `content.insert`. Invalid or stale `X-Crypta-App-Token` values
fail authentication, and missing capabilities fail authorization without echoing the token.

Runtime status and process-log Platform API responses must remain token-free and path-free. Log
tail responses redact the current launch token and obvious `CRYPTAD_APP_TOKEN=...` text before
returning app output to the Web Shell. This is defense in depth for operator visibility; it is not a
general secret scanner for arbitrary app output.

App-originated allowed and denied Platform API decisions are recorded in a bounded process-local
audit log. Audit events keep route family, action, required capabilities, decision, status, and a
short reason code. They must not include raw launch tokens, query strings, request bodies, form
passwords, or filesystem paths.

First-party static app UIs can fetch `/apps/{appId}/.well-known/cryptad-bootstrap.json` to discover
local route roots and the existing local-admin form password used for mutating Platform API calls.
That bootstrap is host/operator scoped. It must not contain `CRYPTAD_APP_TOKEN`, AppHost launch
tokens, trusted key material, or installed-bundle/data/cache/run filesystem paths. Static UI code
still runs in the local admin origin until stronger isolation exists, so treat untrusted static UI
JavaScript as having local admin browser-origin access.

Treat a bypass that serves host files, follows symlink escapes, executes JavaScript while the admin
UI has JavaScript disabled, exposes AppHost launch tokens to browser code, or allows bundled UI to
exfiltrate operator-entered data off-node as security-relevant.

For the detailed runtime boundary, exposed environment variables, restart policy semantics,
permission matrix, audit model, and remaining limitations, see
[apphost-runtime-hardening.md](apphost-runtime-hardening.md) and
[app-permissions-and-audit.md](app-permissions-and-audit.md).
