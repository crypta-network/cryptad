package network.crypta.clients.http;

import network.crypta.client.FetchContext;
import network.crypta.keys.FreenetURI;

/**
 * Immutable criteria used to locate or create an in-progress FProxy fetch.
 *
 * <p>The criteria pairs a target {@link FreenetURI} with a maximum size constraint and an optional
 * {@link FetchContext} that must be equivalent for reuse. Callers can supply a {@code null} {@code
 * fetchContext} when they intend to match any context.
 */
public record FProxyFetchCriteria(FreenetURI key, long maxSize, FetchContext fetchContext) {}
