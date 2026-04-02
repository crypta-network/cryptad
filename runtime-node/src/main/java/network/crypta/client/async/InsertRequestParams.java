package network.crypta.client.async;

import network.crypta.client.InsertContext;
import network.crypta.keys.FreenetURI;

/**
 * Shared request metadata for client-side insert operations.
 *
 * <p>This record groups the callback, target URI, insert context, and scheduling priority required
 * by multiple inserters. It intentionally performs no validation or defensive copying to preserve
 * legacy behavior and caller control over input preparation.
 *
 * @param callback callback receiving progress and completion events; may be {@code null}.
 * @param targetURI destination URI for the insert; should be insert-capable.
 * @param insertContext insert configuration controlling splitfile strategy and scheduling.
 * @param priorityClass scheduling priority class; smaller values represent higher priority.
 */
public record InsertRequestParams(
    ClientPutCallback callback,
    FreenetURI targetURI,
    InsertContext insertContext,
    short priorityClass) {}
