package network.crypta.client.async;

import network.crypta.client.ClientMetadata;
import network.crypta.client.InsertContext;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.RandomAccessBucket;

/**
 * Base request parameters for constructing a {@link ClientPutter}.
 *
 * <p>This record groups the callback, data source, target URI, metadata, insert context, and
 * priority for a single-file insert request. Values are stored as provided and no validation is
 * performed so the caller retains full control over request setup.
 *
 * @param callback callback receiving lifecycle events and final outputs.
 * @param data payload bucket to insert; must remain readable for the insert lifetime.
 * @param targetURI destination URI for the insert; must be insert-capable.
 * @param clientMetadata client-visible metadata such as MIME type; may be {@code null}.
 * @param insertContext insert configuration controlling splitfile strategy and scheduling.
 * @param priorityClass scheduling priority class; smaller values represent higher priority.
 * @param isMetadata whether the payload represents metadata rather than user content.
 */
public record ClientPutterRequest(
    ClientPutCallback callback,
    RandomAccessBucket data,
    FreenetURI targetURI,
    ClientMetadata clientMetadata,
    InsertContext insertContext,
    short priorityClass,
    boolean isMetadata) {}
