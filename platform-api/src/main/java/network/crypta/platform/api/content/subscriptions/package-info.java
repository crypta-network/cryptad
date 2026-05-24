/**
 * Durable app-owned USK content subscription scheduling support.
 *
 * <p>This package implements the Platform API content-subscription metadata service, file-backed
 * store, and conservative background scheduler. It is app-scoped and bounded: subscriptions accept
 * only {@code USK@} or {@code crypta:USK@} sources, use detached runtime fetches with byte and time
 * limits, record resolved-edition and digest metadata, and never persist fetched content.
 *
 * <p>The package is deliberately not a crawler or generic app data store. API handlers require an
 * app principal and the appropriate content capabilities before they call the service. Scheduler
 * passes re-check installed app manifests, avoid overlapping ticks, apply per-tick limits, and use
 * stable runtime pressure signals instead of parsing queue HTML. Durable files are keyed by app id
 * and generated subscription id, never by source URI.
 *
 * <p>Objects returned to apps are safe summaries. They may include the owning app id, the app's
 * public source URI, resolved USK metadata, digest, byte length, timing fields, and stable error
 * codes. They must not contain raw fetched content, private insert material, browser or process
 * tokens, absolute store paths, request bodies, queue HTML, or daemon exception messages.
 */
package network.crypta.platform.api.content.subscriptions;
