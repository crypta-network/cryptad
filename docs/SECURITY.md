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
non-public no-cache headers. Treat a bypass that serves host files, follows symlink escapes,
executes JavaScript while the admin UI has JavaScript disabled, or allows bundled UI to exfiltrate
operator-entered data off-node as security-relevant.
