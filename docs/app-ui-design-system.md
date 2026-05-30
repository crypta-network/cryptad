# App UI design system

This document describes the canonical local design-system assets for app-owned static UI bundles
and the offline `crypta-app ui lint` checks that app authors should run before signing.

## Scope

The design system is intentionally small. It gives static apps stable CSS tokens, basic layout and
form classes, status styles, and an optional dependency-free JavaScript enhancement file. It is not
a full component framework and it does not change Platform API authentication, app process tokens,
browser-session handling, sandboxing, catalog review policy, or legacy admin routing.

Static app bundles vendor the assets locally under `static/crypta-ui/`. Local vendoring keeps the
same bundle usable from isolated per-app loopback origins and from the `/apps/{appId}/`
compatibility path without allowing remote scripts or stylesheets.

## Asset loading order

Static apps should load the design-system CSS before app-specific CSS:

```html
<link rel="stylesheet" href="./crypta-ui/crypta-ui-tokens.css">
<link rel="stylesheet" href="./crypta-ui/crypta-ui.css">
<link rel="stylesheet" href="./app.css">
```

The staged bundle paths are:

| Bundle path | Purpose |
| --- | --- |
| `static/crypta-ui/crypta-ui-tokens.css` | Color, spacing, radius, border, shadow, typography, status, color-scheme, and reduced-motion tokens. |
| `static/crypta-ui/crypta-ui.css` | Reset scoped to app-owned UI plus stable `cr-*` classes. |
| `static/crypta-ui/crypta-ui-components.js` | Optional progressive enhancement. Apps do not need to load it unless they use it. |

Static app JavaScript should still load the browser SDK before app code:

```html
<script src="./crypta-platform.js"></script>
<script type="module" src="./app.js"></script>
```

The `crypta-app init --template` beta templates vendor these assets automatically and are expected
to pass `crypta-app ui lint --strict` and `crypta-app test --strict` before signing. The mock
development server in `crypta-app dev` serves only staged static assets and does not relax the
local-resource or permission-disclosure rules. See
[developer-beta-toolkit.md](developer-beta-toolkit.md).

## Stable classes

The first stable vocabulary is deliberately narrow:

| Class | Use |
| --- | --- |
| `cr-app` | App-owned page root, usually on `<body>`. |
| `cr-shell` | Width-constrained application workspace. |
| `cr-header` | Top app header with title and primary actions. |
| `cr-card` | Framed content, form, or result panel. |
| `cr-toolbar` | Compact controls such as tabs, filters, and refresh actions. |
| `cr-button`, `cr-button--primary`, `cr-button--secondary` | Local command buttons. |
| `cr-field`, `cr-label`, `cr-input`, `cr-checkbox` | Form layout and controls. |
| `cr-status`, `cr-status--success`, `cr-status--warning`, `cr-status--danger`, `cr-status--info` | Status text and live regions. |
| `cr-empty` | Empty/loading state text. |
| `cr-kv-list`, `cr-kv-row` | Key/value summaries. |
| `cr-permission-summary` | Visible permission disclosure. |
| `cr-sr-only` | Screen-reader-only text. |

App-specific CSS should stay small and token-based. Prefer `var(--cr-space-*)`,
`var(--cr-color-*)`, `var(--cr-border)`, and `var(--cr-radius-*)` over hardcoded repeated values.

## CSP and resource rules

App-owned UI responses are designed for a restrictive local CSP. Static apps should not use:

- remote `<script>` or remote stylesheet URLs;
- inline script content or inline event handlers such as `onclick=`;
- `javascript:` URLs;
- `<base>`, `<object>`, `<embed>`, or remote iframes;
- `eval()` or `new Function()`;
- CDN CSS imports or remote `@import`;
- references to `CRYPTAD_APP_TOKEN`, `formPassword`, `X-Crypta-Form-Password`, or launch-token
  names in browser files;
- persistent browser storage for app/session credential material.

Remote links and images may be blocked by CSP or operator policy. Keep critical UI assets local to
the signed bundle.

First-party reference apps must treat fetched, imported, subscribed, and service-returned content
as untrusted display data. Render feed titles, social message fields, profile text, trust-score
annotations, source labels, and URI summaries with text nodes or `textContent`, not HTML string
interpolation. Import helpers should bound counts and field lengths before app data storage and
must reject or neutralize active markup such as `<script>`, event-handler attributes,
`javascript:` links, SVG script payloads, `srcdoc`, `<base>`, and `<iframe>`.

## Permission disclosure

If `app.permissions` is non-empty, the static UI should show a visible permission summary. The
summary does not need live Platform API access. Use one of these markers so the linter can find it:

```html
<section class="cr-permission-summary" data-crypta-permission-summary>
  <p><strong>Declared permissions</strong></p>
  <ul>
    <li><code>queue.read</code> reads queue snapshots.</li>
  </ul>
</section>
```

The disclosure should mention only permissions declared by the manifest. Rationale text for catalog
entries remains catalog metadata; the in-app disclosure is for local operator visibility.

Vault capabilities are ordinary manifest permissions for linting, but their disclosure text must
stay value-free. A static app may show `vault.secrets.read` or `vault.identities.use` in its
permission summary; it must not include secret values, identity private keys, seed phrases, recovery
phrases, local vault paths, process launch tokens, or browser session tokens. The vault lifecycle
and redaction rules are documented in
[app-secret-and-identity-vault.md](app-secret-and-identity-vault.md).

## Accessibility basics

Static app pages should include:

- `<html lang="...">`;
- `<meta name="viewport" content="width=device-width, initial-scale=1">`;
- a non-empty `<title>`;
- at least one visible heading;
- labels or ARIA labels for inputs;
- visible text or ARIA labels for icon-only buttons;
- focus-visible styling. The canonical `crypta-ui.css` provides this by default.

## UI lint

Run the UI linter before signing or cataloging a static app:

```bash
crypta-app ui lint --bundle-dir build/dev-apps/hello --strict
crypta-app ui lint --bundle-dir build/dev-apps/hello --strict --json build/dev-apps/hello-ui-lint.json
```

`crypta-app ui lint` is offline and dependency-free. It inspects only staged bundle files and writes
relative bundle paths in diagnostics. `app.ui.mode=none` and `app.ui.mode=shell-panel` are reported
as not applicable and pass.

Normal `crypta-app validate --bundle-dir ...` keeps existing behavior. `crypta-app validate
--strict` runs UI lint for static bundles and fails on strict UI errors.

## Warning and failure policy

The linter always treats high-value safety findings as errors: remote scripts/stylesheets, inline
scripts, inline event handlers, `javascript:` URLs, dynamic code evaluation, forbidden token/form
password text, object/embed/base tags, and persistent browser credential storage.

Design-system adoption, SDK bootstrap consistency, permission disclosure, and accessibility issues
are warnings in normal UI lint and errors in `--strict`. Release-candidate certification runs strict
lint for first-party apps. Advisory third-party style warnings are recorded as evidence but are not
a release blocker by default.

## First-party consumption

`:platform-design-system` owns the canonical asset bytes and metadata helpers. `crypta-app init
--ui-mode static` copies those assets into new standalone scaffolds. The repo-owned Queue Manager,
Publisher, Site Publisher, Profile Publisher, Social Inbox Preview, Feed Reader, and Trust Graph
Preview Gradle `stageApp` tasks copy the same assets into `static/crypta-ui/` during staging instead
of duplicating them in `apps/*/src/staged`.

Release certification records three UI-specific evidence ids:

| Evidence id | Meaning |
| --- | --- |
| `app-ui.design-system` | Canonical assets exist and first-party staged bundles contain matching bytes. |
| `app-ui.lint` | `crypta-app ui lint --strict --json ...` passed for first-party staged bundles. |
| `app-ui.first-party-adoption` | First-party source and staged UIs use loading order, `cr-*` classes, and permission disclosure. |
