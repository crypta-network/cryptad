package network.crypta.client.async;

/**
 * Bundles optional flags for creating {@link USKFetcherTag} instances.
 *
 * <p>This record groups the behavioral switches that were historically passed as individual
 * parameters to {@link USKManager#getFetcher}. It carries the values verbatim without validation so
 * callers and the manager retain control over any invariants.
 *
 * @param keepLastData whether to retain the last fetched data for callbacks or inspection
 * @param persistent whether the fetch should be persistent when supported by the client
 * @param realTime whether to use real-time scheduling instead of bulk scheduling
 * @param ownFetchContext whether the caller expects the fetcher to clone the provided context
 * @param context optional client context associated with the caller; may be {@code null}
 * @param checkStoreOnly whether to restrict lookups to the local store
 */
public record USKFetcherTagOptions(
    boolean keepLastData,
    boolean persistent,
    boolean realTime,
    boolean ownFetchContext,
    ClientContext context,
    boolean checkStoreOnly) {}
