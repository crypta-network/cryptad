# Legacy HTTP Boundary

`:adapter-http-legacy-admin` owns the boundary-frozen legacy `network.crypta.clients.http` tree
and the matching `network/crypta/clients/http/**` main resources, excluding
`network.crypta.clients.http.bridge` and `network.crypta.clients.http.geoip`.

`:bridge-http-runtime` now owns the concrete runtime-binding bridge implementations under
`network.crypta.clients.http.bridge` plus the legacy HTTP GeoIP helper package under
`network.crypta.clients.http.geoip`.

The adapter leaf still carries three responsibilities:

- the remaining browse and FProxy shell,
- the thin `/api/v1/` bridge that mounts `:platform-api`,
- the thin `/app/node/` bridge that mounts `:platform-web-shell`.

The boundary is intentional. Production code outside `:adapter-http-legacy-admin` and
`:bridge-http-runtime` should keep depending on runtime-owned seams, `:platform-api`, or
`:platform-web-shell` instead of growing new direct dependencies on
`network.crypta.clients.http.*`. The shared shell now routes through an HTTP-local registrar seam
and a top-level refilter policy type, while the bootstrap-owned binding site remains
`src/main/java/network/crypta/runtime/bootstrap/DefaultNodeRuntimeBridgeFactories.java` and now
installs the admin-owned HTTP registrar implementation.

Future browse/FProxy decomposition or replacement is explicitly deferred. This PR does not reopen
that architecture; it only documents the long-term maintenance boundary around the existing legacy
HTTP adapter leaf and the separate bridge leaf. The updater-action adapters remain in
`:adapter-http-legacy-admin` in this PR.
