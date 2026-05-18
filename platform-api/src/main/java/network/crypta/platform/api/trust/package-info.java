/**
 * Trust Graph Preview Platform API routes.
 *
 * <p>This package adapts the local {@code :platform-trustgraph} preview model into app-facing
 * Platform API responses. It owns validation of decoded form/query parameters, redacted response
 * shaping, and route-family behavior for {@code /api/v1/trust-graph/*}. Authorization and audit
 * remain centralized in the parent Platform API router and contract descriptors.
 *
 * <p>The routes in this package deliberately expose a small local service surface rather than a
 * daemon-core plugin system. They can import bounded trust statements, manage local anchors, list
 * redacted evidence, and answer deterministic direct-anchor score queries. They do not fetch in the
 * background, publish anchors automatically, alter network routing, or decide content visibility
 * for other daemon subsystems.
 */
package network.crypta.platform.api.trust;
