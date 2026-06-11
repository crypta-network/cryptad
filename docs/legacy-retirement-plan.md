# Legacy admin retirement plan

This document maps Cryptad's legacy admin HTTP pages to their current Web Shell, Platform API, or
first-party app replacements.

## Scope

PR-200 created the replacement map. PR-211 used that map to hide `PRIMARY_REPLACED` admin pages
from primary legacy navigation. Phase 6 PR-8, tracked in release certification as
`legacy-admin.removal-wave-1`, starts the first small execution-policy wave: selected already
replaced legacy admin page routes no longer render the old page by default. They return a
replacement redirect for safe reads or a gone-with-replacement response for mutating requests.
Phase 7 PR-230, tracked as `legacy-admin.removal-wave-2`, expands that execution policy to the
next bounded set of admin/control-plane pages only when the replacement is reachable for the
current request. Phase 8 PR-244, tracked as `legacy-admin.removal-wave-3`, applies the same
policy to the safe-read security-levels route only. Phase 9 PR-254, tracked as
`legacy-admin.removal-wave-4`, applies the same default replacement policy to the diagnostic
export route only while keeping a bounded support fallback.

FProxy browse remains retained. FProxy browse and content-rendering surfaces are explicitly
retained. The browse split under
`:adapter-http-legacy-browse` remains outside deletion scope for this plan. The content filter also
remains retained as browse safety tooling.

Retained and pending legacy routes remain reachable in this batch. They stay available through
direct URLs and any explicit fallback entry points until their Web Shell or app replacements are
complete enough to retire the legacy path.

## Retirement states

| State | Meaning |
| --- | --- |
| `PRIMARY_REPLACED` | Web Shell or a first-party app is now the primary user path. The legacy page remains as fallback or debug surface. |
| `FALLBACK` | The legacy page is reachable and expected to work, but is not the preferred path. |
| `RETAINED` | The legacy surface is intentionally kept as long-term functionality, such as FProxy browse or browse-adjacent tools. |
| `PENDING` | No complete replacement is proven yet. Do not show a strong replacement notice. |
| `INFRASTRUCTURE` | The route supports other pages and is not a standalone user-facing page. |

## Removal modes

Retirement state is the product/status map. Removal mode is the current execution policy in the
legacy HTTP adapter. Do not infer removal from `PRIMARY_REPLACED`: several primary-replaced
surfaces remain renderable until later waves.

| Mode | Current behavior |
| --- | --- |
| `RENDER_LEGACY` | The route still invokes the legacy toadlet. Primary-replaced pages in this mode render the non-blocking replacement notice. |
| `REDIRECT_TO_REPLACEMENT` | When the replacement is available for the current request, `GET` and `HEAD` in the surface's explicit removal scope return `303 See Other` with a safe same-origin replacement URL. Covered mutating requests return `410 Gone` and do not execute legacy behavior; partial legacy-only mutations remain fallback until the replacement is complete. If the replacement is unavailable, the legacy fallback remains reachable. |
| `GONE_WITH_REPLACEMENT` | When the replacement is available for the current request, safe reads in the surface's explicit removal scope return a small `410 Gone` page with a replacement link and covered mutating requests are blocked. If the replacement is unavailable, the legacy fallback remains reachable. |
| `RETAINED` | The route is retained long-term and renders normally. |
| `PENDING` | The route remains reachable because a complete replacement is not proven. |
| `INFRASTRUCTURE` | The route supports another flow and is not treated as a standalone page-removal target. |

## Removal wave 1

Wave 1 applies removal-by-default to the listed canonical page paths and their slashless aliases
when the replacement is reachable for the current request. Queue Manager and Publisher redirects
require full operator access, enabled FProxy JavaScript, and an installed static app UI. Web Shell
peer and connectivity redirects require full operator access and Web Shell to be the advertised
primary UI. If those availability checks fail, the same legacy pages remain reachable as
compatibility fallbacks and diagnostics count them as fallback renders. Wave 1 routes and behavior
remain unchanged by later waves unless a later wave explicitly records a helper-route scope
expansion. No temporary debug fallback flag is implemented in this wave.

| Legacy route | Surface id | Safe read behavior | Mutating behavior | Replacement |
| --- | --- | --- | --- | --- |
| `/downloads/` | `queue-downloads` | `303 See Other` when Queue Manager is available; otherwise legacy fallback | `410 Gone` when Queue Manager is available; otherwise legacy fallback | `/apps/queue-manager/` |
| `/uploads/` | `queue-uploads` | `303 See Other` when Queue Manager is available; otherwise legacy fallback | `410 Gone` when Queue Manager is available; otherwise legacy fallback | `/apps/queue-manager/` |
| `/insertfile/` | `file-insert` | `303 See Other` when Publisher is available; otherwise legacy fallback | `410 Gone` when Publisher is available; otherwise legacy fallback | `/apps/publisher/` |
| `/insert-browse/` | `local-file-insert` | `303 See Other` when Publisher is available; otherwise legacy fallback | `410 Gone` when Publisher is available; otherwise legacy fallback | `/apps/publisher/` |
| `/friends/` | `friends` | `303 See Other` when Web Shell is available; otherwise legacy fallback | `410 Gone` when Web Shell is available; otherwise legacy fallback | `/app/node/#peers` |
| `/addfriend/` | `add-friend` | `303 See Other` when Web Shell is available; otherwise legacy fallback | `410 Gone` when Web Shell is available; otherwise legacy fallback | `/app/node/#peers` |
| `/strangers/` | `strangers` | `303 See Other` when Web Shell is available; otherwise legacy fallback | `410 Gone` when Web Shell is available; otherwise legacy fallback | `/app/node/#peers` |
| `/connectivity/` | `connectivity` | `303 See Other` when Web Shell is available; otherwise legacy fallback | `410 Gone` when Web Shell is available; otherwise legacy fallback | `/app/node/#connectivity` |

## Removal wave 2

Wave 2 applies removal-by-default to the next safe route set when Web Shell or the relevant
first-party app replacement is reachable for the current request. Web Shell routes require full
operator access and Web Shell as the advertised primary UI. Queue helper routes require full
operator access, enabled FProxy JavaScript, and an installed Queue Manager static UI. If the
replacement is unavailable, direct legacy fallback remains available and diagnostics count a
fallback render.

Wave 2 also records route-scope metadata so only the intended page family or explicit helper paths
are affected. It does not match query strings or fragments. Query strings, form fields, option
values, filesystem paths, tokens, peer references, and Freenet/Crypta URIs are never included in
replacement pages, diagnostics, or release-certification evidence.

| Legacy route scope | Surface id | Safe read behavior | Mutating behavior | Replacement |
| --- | --- | --- | --- | --- |
| `/alerts/` canonical path | `alerts` | `303 See Other` when Web Shell alerts are available; otherwise legacy fallback | Legacy POST fallback remains for mutating legacy alert bulk actions and node-message deletion because Platform API currently covers individual dismissals only | `/app/node/#alerts` |
| `/config/` and `/config/{section}` | `config` | `303 See Other` when Web Shell config is available; otherwise legacy fallback | `410 Gone` when Web Shell config and Platform API config override/persist endpoints are available; otherwise legacy fallback | `/app/node/#config` |
| `/core-update/` canonical path | `core-update` | `303 See Other` when Web Shell updates are available; otherwise legacy fallback | Legacy POST fallback remains for download, installer and package-store actions in this wave because the central policy does not yet inspect individual form actions | `/app/node/#updates` |
| `/stats/` and `/stats/requesters.html` | `statistics` | `303 See Other` when Web Shell diagnostics are available; otherwise legacy fallback | No mutating legacy statistics action is removed in this wave | `/app/node/#diagnostics` |
| `/downloads/countRequests.html`, `/downloads/listKeys.txt`, `/uploads/countRequests.html`, and `/uploads/listKeys.txt` | `queue-downloads`, `queue-uploads` | `303 See Other` when Queue Manager is available; otherwise legacy fallback | `410 Gone` when Queue Manager is available; otherwise legacy fallback | `/apps/queue-manager/` |

During Wave 2, the raw diagnostic export remained retained. `/diagnostic/` still rendered the
legacy plain-text diagnostic report because release, interop, and support workflows used that
export and that PR did not add an equivalent explicit Platform API or Web Shell export.
Security-level recovery and confirmation flows remain legacy fallback and are not covered by
Wave 2.

Wave 2 does not remove FProxy browse, key/content rendering, content filter, startup wizard,
node-to-node messages, translation, help, chat/forum discovery, Platform API routes, Web Shell
routes, app-owned UI routes, directory chooser/helper flows, or local file-browser helpers outside
the explicit queue helper paths above.

## Removal wave 3

Wave 3 is tracked in release certification as `legacy-admin.removal-wave-3`. It applies
removal-by-default only to the security-levels canonical route and its slashless alias when Web
Shell security is reachable for the current request. Web Shell security requires full operator
access and Web Shell as the advertised primary UI. If that replacement is unavailable, direct
legacy fallback remains available and diagnostics count a fallback render.

Wave 3 intentionally does not use prefix-family matching for security routes. It does not remove
`/seclevels/` child or recovery flows unless a later audit proves complete replacement coverage.
Query strings, form fields, option values, master passwords, password-file paths, recovery inputs,
tokens, node references, and Freenet/Crypta URIs are never included in replacement pages,
diagnostics, or release-certification evidence.

Web Shell security keeps a bootstrap-resolved explicit fallback link in the Security panel and in
legacy-required error states for physical `HIGH`, master-password, and recovery workflows that
still need the legacy GET page to render their forms. The fallback URL uses the configured
`security-levels` legacy route from the retirement registry, then appends the fixed
`legacyFallback=security-levels` marker. Only that marker bypasses the safe-read redirect;
arbitrary query strings still receive the normal replacement redirect and are not reflected into
responses or evidence.

| Legacy route scope | Surface id | Safe read behavior | Mutating behavior | Replacement |
| --- | --- | --- | --- | --- |
| Configured security-levels canonical path and slashless alias | `security-levels` | `303 See Other` when Web Shell security is available; otherwise legacy fallback; Web Shell can open the exact bootstrap-resolved fallback marker for HIGH/master-password forms | Legacy fallback remains for master-password, database/password-file, high physical security, and recovery flows unless Web Shell/API coverage explicitly covers the action | `/app/node/#security` |

Wave 3 explicitly retains or leaves pending:

- FProxy browse and key/content rendering.
- Content filter.
- Raw diagnostic export, before Wave 4 moves the default diagnostic safe-read path to Web Shell.
- Startup wizard and emergency fallback.
- Node-to-node messages.
- Retained chat/forum discovery.
- Translation and help.
- Local directory/file helper infrastructure outside already-reviewed explicit queue helper paths.

## Removal wave 4

Wave 4 is tracked in release certification as `legacy-admin.removal-wave-4`. It applies
removal-by-default only to the diagnostic canonical route and its slashless alias when Web Shell
diagnostics is reachable for the current request. Web Shell diagnostics requires full operator
access and Web Shell as the advertised primary UI. If that replacement is unavailable, direct
legacy fallback remains available and diagnostics count a fallback render.

Wave 4 intentionally does not use prefix-family matching for diagnostic routes. It does not remove
`/diagnostic/` child paths unless a later audit separately registers and certifies those paths.
Query strings, request bodies, form passwords, browser or app tokens, private insert URIs, raw
diagnostic output, raw fetched content, raw app data, signatures, and local paths are never
included in replacement pages, diagnostics counters, or release-certification evidence.

Web Shell diagnostics is the primary operator status surface. The legacy diagnostic export remains
available only as an explicit support or emergency fallback for operators who need the historical
plain-text output. The fallback URL uses the configured `diagnostic` legacy route from the
retirement registry, then appends the fixed `legacyFallback=diagnostic-export` marker. Only that
exact marker bypasses the safe-read redirect for `GET` and `HEAD`; arbitrary query strings still
receive the normal replacement redirect and are not reflected into responses or evidence.

| Legacy route scope | Surface id | Safe read behavior | Mutating behavior | Replacement |
| --- | --- | --- | --- | --- |
| Configured diagnostic canonical path and slashless alias | `diagnostic` | `303 See Other` to Web Shell diagnostics when reachable; otherwise legacy fallback; Web Shell can open the exact bootstrap-resolved support fallback marker | `410 Gone` when Web Shell diagnostics is reachable; legacy mutation does not execute | `/app/node/#diagnostics` |

Wave 4 explicitly retains or leaves pending:

- FProxy browse and key/content rendering.
- Content filter.
- Startup wizard, first-time wizard, and emergency fallback.
- Security password, recovery, and `legacyFallback=security-levels` fallback behavior from wave 3.
- Node-to-node messages.
- Retained chat/forum discovery.
- Translation and help.
- Local directory/file helper infrastructure outside already-reviewed explicit queue helper paths.

## Current map

| Legacy surface | Legacy path | State | Primary path or reason |
| --- | --- | --- | --- |
| Web Shell bridge | `/app/node/` | `INFRASTRUCTURE` | Hosts the replacement node-management UI. |
| Platform API bridge | `/api/v1/` | `INFRASTRUCTURE` | Hosts the JSON control plane used by Web Shell and apps. |
| App-owned static UI bridge | `/apps/{appId}/` | `INFRASTRUCTURE` | Hosts installed first-party and app-owned static UIs. |
| Alerts | `/alerts/` | `PRIMARY_REPLACED` | Web Shell alerts at `/app/node/#alerts`. |
| Download queue | `/downloads/` | `PRIMARY_REPLACED` | Queue Manager at `/apps/queue-manager/`; Web Shell queue remains a fallback panel; reviewed count/key-list helpers join the removal scope in wave 2. |
| Upload queue | `/uploads/` | `PRIMARY_REPLACED` | Queue Manager at `/apps/queue-manager/`; Publisher covers insert creation; reviewed count/key-list helpers join the removal scope in wave 2. |
| File insert wizard | `/insertfile/` | `PRIMARY_REPLACED` | Publisher at `/apps/publisher/`. |
| Local upload file browser | `/insert-browse/` | `PRIMARY_REPLACED` | Publisher at `/apps/publisher/`; canonical page redirects in wave 1 while helper subpaths remain untouched. |
| Friends | `/friends/` | `PRIMARY_REPLACED` | Web Shell peer control at `/app/node/#peers`. |
| Add friend | `/addfriend/` | `PRIMARY_REPLACED` | Web Shell peer control at `/app/node/#peers`. |
| Strangers / opennet peers | `/strangers/` | `PRIMARY_REPLACED` | Web Shell peer control at `/app/node/#peers`. |
| Connectivity | `/connectivity/` | `PRIMARY_REPLACED` | Web Shell connectivity at `/app/node/#connectivity`. |
| Configuration | `/config/{section}` | `PRIMARY_REPLACED` | Web Shell config at `/app/node/#config`. |
| Security levels | `/seclevels/` | `PRIMARY_REPLACED` | Web Shell security at `/app/node/#security`. |
| Core update actions | `/core-update/` | `PRIMARY_REPLACED` | Web Shell updates at `/app/node/#updates`. |
| Statistics | `/stats/` | `PRIMARY_REPLACED` | Web Shell diagnostics at `/app/node/#diagnostics`. |
| Diagnostic report | `/diagnostic/` | `PRIMARY_REPLACED` | Web Shell diagnostics at `/app/node/#diagnostics`; plain-text export remains available only through the explicit support fallback marker. |
| First-time wizard | `/wizard/` and `/wiz/` | `PENDING` | Web Shell wizard exists at `/app/node/#wizard`, but startup routing still uses the legacy wizard gate. |
| Node-to-node messages | `/send_n2ntm/` | `PENDING` | No complete Web Shell or app replacement is established. |
| Chat and forums | `/chat/` | `RETAINED` | On-network browse-adjacent discovery remains retained. |
| Translation management | `/translation/` | `RETAINED` | No shell-native replacement exists in this plan. |
| Help | `/help/` | `RETAINED` | Kept as a simple support page. |
| Content filter | `/filterfile/` | `RETAINED` | Part of retained FProxy browse safety tooling. |
| FProxy browse root and key/content rendering | `/` and key routes | `RETAINED` | FProxy browse is intentionally kept out of admin-page retirement. |
| Decode, external-link, bookmark, AJAX push, directory browser, symlink, and static helpers | Various support routes | `INFRASTRUCTURE` | Required by retained browse or fallback legacy pages. |

The authoritative code map for admin pages lives in
`LegacyAdminRetirementRegistry` under `:adapter-http-legacy-admin`. Browse-only routes remain owned
by `:adapter-http-legacy-browse`.

## Current execution status

Web Shell is the primary local operator UI for node status, peers, queue and transfers, config,
updates, alerts, diagnostics, installed apps, and first-time setup controls where startup state
allows it. Queue Manager and Publisher are app-owned static UIs under `/apps/queue-manager/` and
`/apps/publisher/`. Site Publisher is also an app-owned static UI under `/apps/site-publisher/`,
but it is a content reference app rather than a legacy admin replacement target.

Primary-replaced legacy admin pages that are not removed by default still render a non-blocking
notice that links to the Web Shell or first-party app replacement. Wave-1 and wave-2 removed
routes, plus the wave-3 `security-levels` safe-read route and the wave-4 `diagnostic` route, do not
render that notice by default when their replacements are reachable because the central request
gate returns the replacement response before the legacy toadlet is invoked.

`PRIMARY_REPLACED` pages are omitted from the Web Shell legacy-link panel and from legacy
page-chrome entry points when a Web Shell or first-party app path is now primary. Wave-1 canonical
URLs now return replacement responses instead of rendering the old page. Wave-2 URLs for alerts,
config, core-update status, statistics, and selected queue helpers do the same under their explicit
route scopes. Wave-3 safe reads for `/seclevels/` redirect to Web Shell security under the
canonical route scope while mutating requests remain legacy fallback. Wave-4 safe reads for
`/diagnostic/` redirect to Web Shell diagnostics under the canonical route scope, while the
plain-text export remains reachable only through the exact support fallback marker. Later-wave
primary-replaced URLs still render the legacy page and replacement notice until a future removal
wave changes their execution mode.

The legacy top-level Queue and Friends category roots no longer fall back to `/downloads/` or
`/friends/` as normal navigation. Queue is shown only when Queue Manager is installed, static, and
usable for the current full-access browser session. Friends is shown only while Web Shell is the
advertised primary UI. Status and Config retain their documented fallbacks for any route or action
not covered by the current removal scope.

Retained browse/FProxy surfaces and `PENDING` admin routes are unchanged by this batch. They remain
available as legacy entry points until a later PR proves a complete replacement and documents the
deletion path. The change is admin/control-plane retirement only; it does not change Freenet,
Hyphanet, FNP, FCP, or wire-protocol interoperability.

## Diagnostics

Legacy admin page visits are counted in memory for known admin surfaces. The recorder stores only:

- Surface id.
- Legacy path.
- Retirement state.
- Replacement URL when one exists.
- Removal mode, removal wave, removed-by-default marker, and fallback policy.
- Removal scope and scope-expanded-in-wave metadata.
- Process-local count.
- Replacement-response, blocked-mutating-request, fallback-render, and retained/pending-render
  counters.
- Latest observed timestamp in epoch milliseconds.

It does not store query strings, form data, tokens, peer references, Freenet/Crypta URIs,
filesystem paths, request bodies, or remote addresses.

`GET /api/v1/diagnostics` includes the counters when the legacy HTTP bridge is the host:

```json
{
  "legacyAdmin": {
    "surfaces": [
      {
        "id": "queue-downloads",
        "title": "Download queue",
        "path": "/downloads/",
        "state": "PRIMARY_REPLACED",
        "replacementUrl": "/apps/queue-manager/",
        "removalMode": "REDIRECT_TO_REPLACEMENT",
        "removalWave": 1,
        "removedByDefaultSince": "phase-6-pr-8",
        "fallbackPolicy": "none",
        "removalScope": "EXPLICIT_CHILDREN",
        "scopeExpandedInWave": 2,
        "count": 0,
        "replacementResponseCount": 12,
        "blockedMutatingRequestCount": 1,
        "fallbackRenderCount": 0,
        "retainedOrPendingRenderCount": 0,
        "lastSeenEpochMillis": 1770000000000
      }
    ]
  }
}
```

The counters reset when the process restarts. They are intended to guide future removal PRs, not to
act as persistent audit logs.

## Future work before deletion

Later PRs must use diagnostics and focused migration checks before deleting any legacy admin page:

1. Confirm that retained FProxy browse routes are not affected.
2. Prove that pending pages have complete Web Shell or app replacements.
3. Keep fallback links or documented manual routes for any remaining debug-only workflows.
4. Check packaged-node and upgrade behavior so bookmarked legacy URLs fail gracefully or redirect.
5. Remove routes in small batches with targeted tests and release notes.
