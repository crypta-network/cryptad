# Legacy HTTP Boundary

`:adapter-http-legacy-admin` owns the boundary-frozen legacy `network.crypta.clients.http` tree
and the matching `network/crypta/clients/http/**` main resources, excluding
`network.crypta.clients.http.bridge` and `network.crypta.clients.http.geoip`.

`:bridge-http-runtime` owns the concrete runtime-binding bridge implementations under
`network.crypta.clients.http.bridge` plus the legacy HTTP GeoIP helper package under
`network.crypta.clients.http.geoip`.

This PR keeps the existing adapter leaf in place and still does not create
`:adapter-http-legacy-browse`, but it removes the last major route-registration blocker for that
future split. The shared shell already crosses browse-neutral bootstrap/context types and shared
`LegacyHttpPaths` / `LegacyHttpCategories` constants instead of pulling those values from
`FProxyToadlet` directly. It also uses neutral bookmark, push, and client-side script seams
instead of importing concrete browse-owned collaborator classes directly.

The new change in this PR is route-registration ownership. Admin-owned startup code now preserves
the historical registration order while delegating browse-owned route publication through a neutral
`LegacyHttpBrowseRouteRegistrar` seam installed by the bridge/runtime-owned HTTP bootstrap path.
That keeps the shared shell browse-neutral, keeps the admin-owned registrar from instantiating the
concrete browse routes directly, and makes the future browse-module move mechanical instead of
another logic refactor.

The boundary remains intentional. Production code outside `:adapter-http-legacy-admin` and
`:bridge-http-runtime` should keep depending on runtime-owned seams, `:platform-api`, or
`:platform-web-shell` instead of growing new direct dependencies on
`network.crypta.clients.http.*`. The bootstrap-owned binding site remains
`src/main/java/network/crypta/runtime/bootstrap/DefaultNodeRuntimeBridgeFactories.java`, and the
updater-action adapters remain in `:adapter-http-legacy-admin` in this PR.

Future browse/FProxy decomposition or replacement is still deferred. This PR only prepares the
later `:adapter-http-legacy-browse` extraction by neutralizing the shared shell seams and splitting
admin-owned versus browse-owned route registration behind that neutral registrar boundary.
