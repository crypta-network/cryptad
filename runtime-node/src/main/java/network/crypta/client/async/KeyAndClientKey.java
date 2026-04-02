package network.crypta.client.async;

import network.crypta.keys.ClientKey;
import network.crypta.keys.Key;

/**
 * Bundles a resolved node {@link Key} and its optional {@link ClientKey} counterpart.
 *
 * <p>Either component may be {@code null} depending on the request type (for example, insert
 * requests do not necessarily operate on a pre-existing node key).
 *
 * @param key the resolved node-level key; may be {@code null}.
 * @param ckey the client-layer key associated with the operation; may be {@code null}.
 */
public record KeyAndClientKey(Key key, ClientKey ckey) {}
