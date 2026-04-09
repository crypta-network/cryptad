# Legacy HTTP Boundary

`:adapter-http-legacy-admin` owns the boundary-frozen legacy `network.crypta.clients.http` tree
and the matching `network/crypta/clients/http/**` main resources.

This leaf still carries three responsibilities:

- the remaining browse and FProxy shell,
- the thin `/api/v1/` bridge that mounts `:platform-api`,
- the thin `/app/node/` bridge that mounts `:platform-web-shell`.

The boundary is intentional. Production code outside `:adapter-http-legacy-admin` should keep
depending on runtime-owned seams, `:platform-api`, or `:platform-web-shell` instead of growing new
direct dependencies on `network.crypta.clients.http.*`. The bootstrap-owned binding site remains
`src/main/java/network/crypta/runtime/bootstrap/DefaultNodeRuntimeBridgeFactories.java`.

Future browse/FProxy decomposition or replacement is explicitly deferred. This PR does not reopen
that architecture; it only documents the long-term maintenance boundary around the existing legacy
HTTP adapter leaf.
