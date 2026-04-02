package network.crypta.client.async;

import network.crypta.client.FetchContext;
import network.crypta.client.InsertContext;
import network.crypta.config.Config;

/**
 * Encapsulates default contexts and configuration used by {@link ClientContext}.
 *
 * @param defaultPersistentFetchContext template fetch context for persistent requests
 * @param defaultPersistentInsertContext template insert context for persistent requests
 * @param config configuration backing client-layer defaults
 */
public record ClientContextDefaults(
    FetchContext defaultPersistentFetchContext,
    InsertContext defaultPersistentInsertContext,
    Config config) {}
