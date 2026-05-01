# Legacy admin retirement plan

This document maps Cryptad's legacy admin HTTP pages to their current Web Shell, Platform API, or
first-party app replacements.

## Scope

PR-200 created the replacement map. PR-211 uses that existing map to hide `PRIMARY_REPLACED`
admin pages from legacy navigation, but it does not create a new retirement model and does not
delete legacy pages, remove FProxy browse, change FCP, or change network compatibility. Direct
legacy URLs remain reachable for fallback, debug, and deep links until later PRs prove that removal
is safe.

FProxy browse and content-rendering surfaces are explicitly retained. The browse split under
`:adapter-http-legacy-browse` remains outside deletion scope for this plan.

Pending routes also remain pending in this batch. They stay reachable through direct URLs and any
explicit fallback entry points until their Web Shell or app replacements are complete enough to
retire the legacy path.

## Retirement states

| State | Meaning |
| --- | --- |
| `PRIMARY_REPLACED` | Web Shell or a first-party app is now the primary user path. The legacy page remains as fallback or debug surface. |
| `FALLBACK` | The legacy page is reachable and expected to work, but is not the preferred path. |
| `RETAINED` | The legacy surface is intentionally kept as long-term functionality, such as FProxy browse or browse-adjacent tools. |
| `PENDING` | No complete replacement is proven yet. Do not show a strong replacement notice. |
| `INFRASTRUCTURE` | The route supports other pages and is not a standalone user-facing page. |

## Current map

| Legacy surface | Legacy path | State | Primary path or reason |
| --- | --- | --- | --- |
| Web Shell bridge | `/app/node/` | `INFRASTRUCTURE` | Hosts the replacement node-management UI. |
| Platform API bridge | `/api/v1/` | `INFRASTRUCTURE` | Hosts the JSON control plane used by Web Shell and apps. |
| App-owned static UI bridge | `/apps/{appId}/` | `INFRASTRUCTURE` | Hosts installed first-party and app-owned static UIs. |
| Alerts | `/alerts/` | `PRIMARY_REPLACED` | Web Shell alerts at `/app/node/#alerts`. |
| Download queue | `/downloads/` | `PRIMARY_REPLACED` | Queue Manager at `/apps/queue-manager/`; Web Shell queue remains a fallback panel. |
| Upload queue | `/uploads/` | `PRIMARY_REPLACED` | Queue Manager at `/apps/queue-manager/`; Publisher covers insert creation. |
| File insert wizard | `/insertfile/` | `PRIMARY_REPLACED` | Publisher at `/apps/publisher/`. |
| Local upload file browser | `/insert-browse/` | `PRIMARY_REPLACED` | Publisher at `/apps/publisher/`; legacy route remains for old upload forms. |
| Friends | `/friends/` | `PRIMARY_REPLACED` | Web Shell peer control at `/app/node/#peers`. |
| Add friend | `/addfriend/` | `PRIMARY_REPLACED` | Web Shell peer control at `/app/node/#peers`. |
| Strangers / opennet peers | `/strangers/` | `PRIMARY_REPLACED` | Web Shell peer control at `/app/node/#peers`. |
| Connectivity | `/connectivity/` | `PRIMARY_REPLACED` | Web Shell connectivity at `/app/node/#connectivity`. |
| Configuration | `/config/{section}` | `PRIMARY_REPLACED` | Web Shell config at `/app/node/#config`. |
| Security levels | `/seclevels/` | `PRIMARY_REPLACED` | Web Shell security at `/app/node/#security`. |
| Core update actions | `/core-update/` | `PRIMARY_REPLACED` | Web Shell updates at `/app/node/#updates`. |
| Statistics | `/stats/` | `PRIMARY_REPLACED` | Web Shell diagnostics at `/app/node/#diagnostics`. |
| Diagnostic report | `/diagnostic/` | `PRIMARY_REPLACED` | Web Shell diagnostics at `/app/node/#diagnostics`; plain-text export remains useful. |
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
`/apps/publisher/`.

Replaced legacy admin pages render a non-blocking notice that says the page remains available as a
fallback/debug view and links to the Web Shell or first-party app replacement.

PR-211 no longer treats replaced legacy admin pages as legacy navigation targets. `PRIMARY_REPLACED`
pages are omitted from the Web Shell legacy-link panel and from legacy page-chrome entry points
when a Web Shell or first-party app path is now primary. The underlying legacy routes still exist,
so bookmarked or manually entered fallback/debug URLs continue to render the legacy page and its
replacement notice.

The legacy top-level Queue, Friends, Status, and Config category roots prefer
`/apps/queue-manager/`, `/app/node/#peers`, `/app/node/`, and `/app/node/#config` instead of
legacy primary-replaced pages. The Queue root falls back to `/downloads/` when Queue Manager is not
installed or the app route is not usable for the current client, but only for clients that would
already see legacy queue navigation. Public-gateway non-full sessions keep the Queue category
hidden. Shell-backed category roots still render direct legacy fallback URLs when Web Shell is not
the advertised primary UI, such as JavaScript-disabled FProxy sessions.

Retained browse/FProxy surfaces and `PENDING` admin routes are unchanged by this batch. They remain
available as legacy entry points until a later PR proves a complete replacement and documents the
deletion path.

## Diagnostics

Legacy admin page visits are counted in memory for known admin surfaces. The recorder stores only:

- Surface id.
- Legacy path.
- Retirement state.
- Replacement URL when one exists.
- Process-local count.
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
        "path": "/downloads/",
        "state": "PRIMARY_REPLACED",
        "replacementUrl": "/apps/queue-manager/",
        "count": 12,
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
