# Platform JavaScript SDK

This document describes the browser-side `CryptaPlatform` SDK for app-owned static UI bundles.

## Scope

The SDK is a small, dependency-free JavaScript file for static app pages served under
`/apps/{appId}/`. It wraps the current same-origin bootstrap and Platform API conventions used by
first-party apps. It carries the browser app session token issued by app-owned UI bootstrap, but it
is not the server-side authorization boundary and it is not a sandbox or browser isolation layer.

Static app bundles should load the staged SDK before app-specific JavaScript:

```html
<script src="./crypta-platform.js" defer></script>
<script src="./app.js" defer></script>
```

The first-party Queue Manager and Publisher bundles receive `crypta-platform.js` during their
Gradle `stageApp` tasks. The canonical source lives in
`platform-sdk-js/src/main/resources/network/crypta/platform/sdk/js/crypta-platform.js`.

## Bootstrap

Call `CryptaPlatform.bootstrap.load()` before using API helpers:

```js
await CryptaPlatform.bootstrap.load();
```

The SDK infers the app id from paths such as `/apps/queue-manager/static/`. Tests and unusual local
mounts can pass an explicit app id:

```js
await CryptaPlatform.bootstrap.load({ appId: "queue-manager" });
```

Bootstrap data comes from:

```text
GET /apps/{appId}/.well-known/cryptad-bootstrap.json
```

The SDK keeps a sanitized in-memory copy of the bootstrap fields used by browser apps: `appId`,
`name`, `uiRoot`, `assetRoot`, `platformApiRoot`, `shellRoot`, and `browserSessionExpiresAt`.
It reads `browserSessionToken` into private in-memory state and does not expose it through
`CryptaPlatform.bootstrap.current()`. `CryptaPlatform.app.currentId()` returns the current app id
when it can be inferred or has been loaded.

The SDK does not write the browser session token to `localStorage`, `sessionStorage`, cookies, or
query strings.

## Platform API reads

`CryptaPlatform.api.url(path)` builds a same-origin URL beneath the bootstrap `platformApiRoot`,
falling back to `/api/v1/` when the root is missing or invalid. Invalid roots such as external
URLs, protocol-relative URLs, and roots with query strings or fragments are ignored.

Use `CryptaPlatform.api.get(path, options)` for JSON reads:

```js
const snapshot = await CryptaPlatform.api.get("queue", {
  params: { page: "downloads" },
});
```

Queue-oriented static apps can use the convenience wrapper:

```js
const snapshot = await CryptaPlatform.queue.snapshot({
  page: "downloads",
  sortBy: "identifier",
  reversed: true,
});
```

The SDK sends `Accept: application/json` and `X-Crypta-App-Session` with the in-memory browser
session token. It normalizes common Platform API error bodies into readable `Error` messages.

## Mutations

Mutating helpers submit `application/x-www-form-urlencoded` bodies and authenticate with the same
`X-Crypta-App-Session` header used for reads. They do not add the legacy local-admin
`formPassword` to app-owned UI requests.

```js
await CryptaPlatform.queue.directDownload(new FormData(form));
await CryptaPlatform.queue.mutate("queue/requests/remove", formData);
await CryptaPlatform.content.insertFile(formData);
await CryptaPlatform.content.insertDirectory(formData);
```

`CryptaPlatform.api.postForm(path, formDataOrParams)` and
`CryptaPlatform.api.deleteForm(path, formDataOrParams)` are available for other same-origin
Platform API form mutations. If no browser session token is available, the SDK rejects the call
before it sends a request.

The helper accepts `FormData`, `URLSearchParams`, arrays of pairs, or plain objects. Non-string
`FormData` entries such as `File` values are not submitted because the current Platform API bridge
is text-form oriented.

## Errors

Use `CryptaPlatform.api.errorMessage(error)` when rendering failures:

```js
try {
  await CryptaPlatform.queue.directDownload(new FormData(form));
} catch (error) {
  status.textContent = CryptaPlatform.api.errorMessage(error);
}
```

The SDK recognizes these Platform API response shapes:

```json
{ "error": "message" }
{ "error": { "message": "message" } }
{ "message": "message" }
{ "detail": "message" }
```

When the response body does not contain a message, the SDK falls back to the HTTP status and status
text.

`401 invalid_app_browser_session` means the in-memory browser session is missing, expired, unknown,
or stale. The SDK clears the in-memory token and raises an error marked with
`code="invalid_app_browser_session"` and `sessionRefreshRequired=true`. First-party apps should
surface that as a reload or session-refresh condition.

## HTML fragments

Some queue endpoints still return legacy HTML fragments in JSON. Use
`CryptaPlatform.dom.sanitizeFragment(html)` before inserting those fragments into the page:

```js
const fragment = CryptaPlatform.dom.sanitizeFragment(snapshot.contentHtml);
container.replaceChildren(fragment);
```

The sanitizer removes executable and document-control elements such as `script`, `style`,
`template`, `iframe`, `object`, `embed`, `link`, `meta`, and `base`. It also removes event handler
attributes, inline `style`, `srcdoc`, and cross-origin `href`, `src`, `action`, and `formaction`
values. Relative links, hash links, query-only links, and same-origin absolute paths remain
available for app-owned handlers.

This sanitizer is intentionally small and deterministic. It is only meant for the daemon-provided
legacy fragments used by app-owned UI, not as a general-purpose sanitizer for arbitrary untrusted
HTML.

## Security boundary

The SDK runs in the same local browser origin as the app-owned UI and Platform API. It preserves
the current local-admin Web Shell path while making app-owned UI API calls use app browser
principals. It does not isolate third-party JavaScript or authenticate an app as an AppHost process.

AppHost process launch tokens such as `CRYPTAD_APP_TOKEN` are not exposed to browser apps, SDK
state, app summaries, or bootstrap JSON. Browser code receives route metadata and an app browser
session token. Permission enforcement and audit for app-originated API calls remain server-side
Platform API behavior, not a browser SDK guarantee.

Install static UI bundles only from sources trusted to run JavaScript in the local admin origin
until stronger browser isolation exists.

## First-party examples

Queue Manager loads a snapshot and renders the sanitized legacy fragment:

```js
await CryptaPlatform.bootstrap.load({ appId: "queue-manager" });
const snapshot = await CryptaPlatform.queue.snapshot({ page: "downloads" });
queueContent.replaceChildren(CryptaPlatform.dom.sanitizeFragment(snapshot.contentHtml));
```

Publisher queues a local file insert with the app browser session established by bootstrap:

```js
await CryptaPlatform.bootstrap.load({ appId: "publisher" });
const formData = new FormData(fileForm);
const result = await CryptaPlatform.content.insertFile(formData);
```

Both apps keep their own UI state, sort handling, key export behavior, and legacy form filtering.
The SDK owns only bootstrap, same-origin API transport, mutation form submission, error parsing,
and conservative fragment sanitization.
