/**
 * Shared app-network budget model for bounded Platform API network operations.
 *
 * <p>The package owns deterministic rate windows, process-local concurrency leases, and safe
 * metadata stores for foreground content fetches, content subscription polling, manual subscription
 * refresh, and Trust Graph imports. It deliberately does not store request bodies, fetched content,
 * raw content URIs, queue HTML, tokens, signatures, app-data payloads, private insert material, or
 * local filesystem paths.
 *
 * <p>The runtime wires one service instance through app-facing content routes, the content
 * subscription service, and Trust Graph import handlers. That shared instance lets independent
 * workflows charge the same global content-fetch family when they all ultimately use bounded
 * content retrieval. Per-app counters limit one app, while reserved internal scopes hold node-wide
 * and host/operator counters that cannot collide with valid app manifest ids.
 *
 * <p>Implementations are intentionally local and JDK-only. Rate limits use durable fixed windows so
 * restarts keep recent consumption, while concurrency limits are process-local leases that callers
 * must close around network work. Denied decisions expose stable error codes and retry metadata
 * suitable for API responses, subscription status, diagnostics, and release-certification evidence.
 */
package network.crypta.platform.api.networkbudget;
