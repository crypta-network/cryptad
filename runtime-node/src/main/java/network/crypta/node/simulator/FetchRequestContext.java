package network.crypta.node.simulator;

import network.crypta.client.FetchContext;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.node.RequestClient;

/**
 * Bundles the inputs needed to perform a single-block fetch.
 *
 * <p>This record groups the client instance, the mutable {@link FetchContext}, and the {@link
 * RequestClient} that supplies request scheduling metadata. It exists to reduce long parameter
 * lists in the long-term simulator while keeping call sites explicit about which objects are shared
 * across a run. Typical usage is to create one instance in the harness setup, then pass it to
 * helper methods that perform repeated fetches for different URIs. The record is intentionally
 * simple: it does not validate inputs or copy state, and callers remain responsible for configuring
 * the {@code FetchContext} before use.
 *
 * <p>All components are held by reference and may be reused across multiple fetches. The record
 * itself is immutable, but it does not guarantee thread safety because the {@code FetchContext} can
 * be mutated by callers. The harness currently uses it from a single thread and treats the fetch
 * context as read-only once configured.
 *
 * <ul>
 *   <li><b>Responsibility:</b> Provide a concise carrier for fetch-related collaborators.
 *   <li><b>Lifecycle:</b> Construct once per run and reuse for every fetch attempt.
 *   <li><b>Threading:</b> Safe to share only if callers avoid mutating the context.
 * </ul>
 *
 * @param client client used to issue fetch requests; must be non-null and ready to use
 * @param fetchContext fetch context configured for retries, limits, and policies; treated as
 *     mutable by callers
 * @param requestClient request client used to schedule fetch work and provide priority settings;
 *     must be non-null
 * @see FetchRunContext
 */
public record FetchRequestContext(
    HighLevelSimpleClient client, FetchContext fetchContext, RequestClient requestClient) {}
