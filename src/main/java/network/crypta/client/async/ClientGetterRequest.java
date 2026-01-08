package network.crypta.client.async;

import network.crypta.client.FetchContext;
import network.crypta.keys.FreenetURI;

/**
 * Base request parameters for constructing a {@link ClientGetter}.
 *
 * <p>This record groups the callback, target URI, fetch context, and scheduling priority required
 * to enqueue a client fetch request. It performs no validation and stores the supplied references
 * verbatim so callers retain full control over request setup and lifecycle.
 *
 * @param client callback that receives completion and failure notifications.
 * @param uri target {@link FreenetURI} to fetch.
 * @param ctx fetch configuration including limits and filtering flags.
 * @param priorityClass scheduling priority; smaller values represent higher priority.
 */
public record ClientGetterRequest(
    ClientGetCallback client, FreenetURI uri, FetchContext ctx, short priorityClass) {}
