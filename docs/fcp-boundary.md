# FCP Boundary

`:adapter-fcp` owns the detached protocol-side `network.crypta.clients.fcp` package tree together
with the protocol-side persistent-bucket and filter seams. It must not depend directly on
`:runtime-node`, and it must not claim `network.crypta.clients.fcp.bridge`.

`:bridge-fcp-runtime` owns the concrete runtime-binding bridge package
`network.crypta.clients.fcp.bridge`. It is the only FCP leaf allowed to carry direct bindings to
daemon and client-engine types, including the live persistent-bucket, content-filter,
persistent-request, queue, alert-feed, and endpoint-handle adapters used by the legacy FCP
endpoint.

The dependency direction is one way. `:bridge-fcp-runtime` depends on `:adapter-fcp` for the
protocol-side seams, but `:adapter-fcp` must stay detached from the bridge and from
`:runtime-node`.

`:runtime-spi` stays detached and JDK-only. Shared runtime/config ports live there; concrete FCP
runtime binding stays in `:bridge-fcp-runtime`.

Default production binding still starts in
`src/main/java/network/crypta/runtime/bootstrap/DefaultNodeRuntimeBridgeFactories.java`.

Future browse/FProxy work is on the legacy HTTP side and is unrelated to this FCP boundary page.
