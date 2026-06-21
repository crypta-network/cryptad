# Legacy HTTP Boundary

`:adapter-http-legacy-admin` owns the shared legacy `network.crypta.clients.http` shell, the
admin toadlets, the `/api/v1/` and `/app/node/` bridge entrypoints, and the matching
`/apps/{appId}/` app-owned static UI entrypoint. It also owns the matching
`network/crypta/clients/http/**` main resources. It does not own the concrete browse/FProxy
implementation classes. The admin leaf is now detached from `:runtime-node`.

`:adapter-http-legacy-browse` owns the concrete browse/FProxy routes, toadlets, helper models,
and browse-only packages under `network.crypta.clients.http`.

`:bridge-http-runtime` owns the concrete runtime-binding bridge implementations under
`network.crypta.clients.http.bridge` plus the legacy HTTP GeoIP helper package under
`network.crypta.clients.http.geoip`. It depends on `:adapter-http-legacy-browse` for concrete
browse construction while keeping the admin-owned shell seams intact.

The dependency direction is one way. `:adapter-http-legacy-browse` may depend on
`:adapter-http-legacy-admin` for shared shell and seam types, but `:adapter-http-legacy-admin`
must not depend on the browse leaf. `:bridge-http-runtime` depends on the browse leaf for concrete
browse construction and still uses admin-owned seams for shell orchestration.

HTTP/admin alert rendering now crosses the detached
`network.crypta.runtime.alerts.UserAlertSurface` owned by `:runtime-alerts`. The concrete
`UserAlertManager` remains runtime-node-owned, while `:adapter-http-legacy-admin` and
`:bridge-http-runtime` consume the narrower alert surface instead of importing that concrete
manager type directly. This keeps `:adapter-http-legacy-admin` detached from `:runtime-node`
without widening `:runtime-spi`.

Admin config classification now also crosses a detached config-owned marker:
`network.crypta.config.DirectorySelectionCallback` in `:foundation-config`. `ConfigToadlet`
uses that marker to recognize directory-selection fields without importing the concrete
runtime-owned `ProgramDirectory` callback types.

The shared shell stays browse-neutral by crossing `LegacyHttpPaths` / `LegacyHttpCategories`
constants and other small seam types instead of importing concrete browse-owned collaborator
classes directly. Route publication, bookmark handling, push handling, and browser-side helpers
stay split across the admin shell, the browse leaf, and the runtime bridge.

App-owned static UI serving stays in the admin adapter as a thin HTTP bridge over `:platform-app-ui`
and `:platform-apphost`. The adapter owns `/apps/` route registration and response writing, while
the platform leaves own installed-app lookup, UI-mode interpretation, path normalization, content
types, and static asset confinement.

Legacy admin retirement metadata also stays in `:adapter-http-legacy-admin`. The registry records
which admin pages are primary-replaced, pending, retained, or infrastructure, and it now carries a
separate removal policy for the current execution wave. Retirement state describes product
ownership; removal mode decides whether the request dispatcher renders the legacy toadlet, returns
a replacement redirect, returns a gone-with-replacement page, or blocks a mutating legacy request.
The retirement plan is documented in [legacy-retirement-plan.md](legacy-retirement-plan.md).
Wave 1, reported as `legacy-admin.removal-wave-1` in release certification, redirects safe reads
for `/downloads/`, `/uploads/`, `/insertfile/`, `/insert-browse/`, `/friends/`, `/addfriend/`,
`/strangers/`, and `/connectivity/` to their Web Shell or first-party app replacements and blocks
mutating requests before old handlers run when those replacements are reachable for the current
request. Queue Manager and Publisher redirects require full operator access, enabled FProxy
JavaScript, and an installed static app UI; Web Shell redirects require full operator access and
Web Shell to be the advertised primary UI. If those checks fail, legacy fallbacks continue to
render and are counted as fallback usage.

Wave 2, reported as `legacy-admin.removal-wave-2`, expands that policy to safe reads for
`/alerts/`, `/config/` and `/config/{section}`, `/core-update/`, `/stats/`, and
`/stats/requesters.html` when Web Shell is reachable. It also expands only the reviewed queue
helper routes `/downloads/countRequests.html`, `/downloads/listKeys.txt`,
`/uploads/countRequests.html`, and `/uploads/listKeys.txt` when Queue Manager is reachable.
Config POST mutations are blocked when Web Shell config and Platform API config write endpoints
are available. Mutating legacy alert bulk actions and core-update installer and package-store
actions remain fallback because their replacements are incomplete or action-specific routing is not
yet part of the central policy. `RETAINED` browse/FProxy surfaces, content filter, and `PENDING`
admin routes stay in their current legacy entry points until a later batch proves a complete
replacement. The diagnostic export remained retained during Wave 2. Queue and Friends category
roots no longer use removed legacy URLs as normal fallbacks.

Wave 3, reported as `legacy-admin.removal-wave-3`, applies the same bounded replacement policy to
the security-levels safe-read route only. `GET` and `HEAD` for the canonical route and slashless
alias redirect to Web Shell security when that replacement is reachable. The legacy
password/recovery page remains available only through the exact safe-read marker
`legacyFallback=security-levels`; arbitrary query strings and mutating requests do not bypass the
normal policy.

Wave 4, reported as `legacy-admin.removal-wave-4`, applies removal-by-default only to the
diagnostic route. Safe reads for `/diagnostic/` and its slashless alias redirect to Web Shell
diagnostics when the shell is reachable. The plaintext diagnostic export remains available as an
explicit support fallback through the exact safe-read marker
`legacyFallback=diagnostic-export`; arbitrary diagnostic query strings, mutating requests, and
diagnostic subpaths do not bypass the removal policy. FProxy browse/content rendering, content
filter, startup wizard/recovery flows, the Wave 3 security fallback, chat, translation, help, and
node-to-node message routes remain retained or pending.

Wave 5, reported as `legacy-admin.removal-wave-5`, is the production-beta final admin surface
readiness wave. It promotes no additional route ids because the remaining surfaces are either
retained, pending, support/emergency fallback, startup/recovery fallback, browse-owned, or
infrastructure. `legacy-admin.final-admin-surface` records that legacy admin is maintenance-only
after Wave 5 and that daily operator workflows are Web Shell or first-party app first. It also
records the retained browse/content route ids, the retained content-filter safety route, the
diagnostic and security fallback markers, wizard/startup fallback status, pending
node-to-node-message status, and infrastructure routes without storing request query strings,
bodies, tokens, private insert URIs, diagnostic output, support-bundle payloads, or local paths.

Production code outside `:adapter-http-legacy-admin`, `:adapter-http-legacy-browse`, and
`:bridge-http-runtime` should keep depending on runtime-owned seams, `:platform-api`, or
`:platform-web-shell` instead of growing new direct dependencies on
`network.crypta.clients.http.*`. The bootstrap-owned binding site remains
`src/main/java/network/crypta/runtime/bootstrap/DefaultNodeRuntimeBridgeFactories.java`, and the
updater-action adapters remain in `:adapter-http-legacy-admin`.

Future browse/FProxy decomposition or replacement remains a separate concern. The concrete browse
leaf is explicitly retained by the retirement plan and remains out of scope for legacy admin page
removal.
