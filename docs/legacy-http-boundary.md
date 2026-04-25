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
which admin pages are primary-replaced, pending, retained, or infrastructure, renders fallback
notices for replaced pages, and feeds process-local usage counters into Platform API diagnostics.
The retirement plan is documented in [legacy-retirement-plan.md](legacy-retirement-plan.md).

Production code outside `:adapter-http-legacy-admin`, `:adapter-http-legacy-browse`, and
`:bridge-http-runtime` should keep depending on runtime-owned seams, `:platform-api`, or
`:platform-web-shell` instead of growing new direct dependencies on
`network.crypta.clients.http.*`. The bootstrap-owned binding site remains
`src/main/java/network/crypta/runtime/bootstrap/DefaultNodeRuntimeBridgeFactories.java`, and the
updater-action adapters remain in `:adapter-http-legacy-admin`.

Future browse/FProxy decomposition or replacement remains a separate concern. The concrete browse
leaf is explicitly retained by the retirement plan and remains out of scope for legacy admin page
removal.
