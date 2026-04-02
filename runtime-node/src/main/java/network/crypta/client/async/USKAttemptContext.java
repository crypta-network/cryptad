package network.crypta.client.async;

import network.crypta.client.FetchContext;
import network.crypta.keys.USK;

/**
 * Shared configuration for creating {@link USKAttempt} instances.
 *
 * <p>This bundles the stable dependencies required to spawn attempt checkers so callers can reuse a
 * single parameter object when scheduling multiple attempts.
 *
 * @param callbacks owning callback handler for lifecycle events
 * @param origUSK base USK used for logging
 * @param ctx base fetch context for scheduling
 * @param ctxNoStore no-store fetch context for probes that bypass the store
 * @param parent parent requester providing scheduling policy
 * @param realTimeFlag whether to use real-time scheduling for the checker
 */
record USKAttemptContext(
    USKAttemptCallbacks callbacks,
    USK origUSK,
    FetchContext ctx,
    FetchContext ctxNoStore,
    ClientRequester parent,
    boolean realTimeFlag) {}
