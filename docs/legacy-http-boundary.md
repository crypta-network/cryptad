# Legacy HTTP Boundary

`:adapter-http-legacy-admin` owns the boundary-frozen legacy `network.crypta.clients.http` tree
and the matching `network/crypta/clients/http/**` main resources, excluding
`network.crypta.clients.http.bridge` and `network.crypta.clients.http.geoip`.

`:bridge-http-runtime` owns the concrete runtime-binding bridge implementations under
`network.crypta.clients.http.bridge` plus the legacy HTTP GeoIP helper package under
`network.crypta.clients.http.geoip`.

This PR keeps the existing adapter leaf in place but removes a few browse-specific leaks from the
shared shell surface before the real browse split. The shared shell now uses browse-neutral
bootstrap/context types and shared `LegacyHttpPaths` / `LegacyHttpCategories` constants instead of
pulling those values from `FProxyToadlet` directly. The concrete browse root still lives in the
legacy adapter leaf for now, but the seam exposed to shared-shell and bridge code is no longer
FProxy-shaped.

The boundary remains intentional. Production code outside `:adapter-http-legacy-admin` and
`:bridge-http-runtime` should keep depending on runtime-owned seams, `:platform-api`, or
`:platform-web-shell` instead of growing new direct dependencies on
`network.crypta.clients.http.*`. The bootstrap-owned binding site remains
`src/main/java/network/crypta/runtime/bootstrap/DefaultNodeRuntimeBridgeFactories.java`, and the
updater-action adapters remain in `:adapter-http-legacy-admin` in this PR.

Future browse/FProxy decomposition or replacement is still deferred. This PR only prepares the
shared shell for a later `:adapter-http-legacy-browse` split by neutralizing the route/path
constants and the bootstrap/context seam.
