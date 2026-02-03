package network.crypta.client.async;

import network.crypta.client.ClientMetadata;
import network.crypta.support.api.RandomAccessBucket;

/**
 * Immutable bundle of inputs for a single-file {@link ClientPutter} request.
 *
 * <p>This record captures the request context, payload source, destination metadata, and scheduling
 * configuration needed to construct a putter. Callers typically create one instance per insert,
 * populate it with the desired references, and hand it to the relevant {@link ClientPutter} entry
 * point. The record performs no validation and stores references verbatim, which preserves legacy
 * behavior and gives the caller full control over how inputs are prepared and validated.
 *
 * <p>The record itself is shallowly immutable, but the referenced objects may be mutable; avoid
 * mutating those references after construction if you need consistent behavior. In particular, the
 * payload bucket must remain readable for the duration of the insert, and the URI/metadata should
 * not change unexpectedly.
 *
 * <ul>
 *   <li>Collects all required inputs for a single-file insert.
 *   <li>Defers validation and normalization to the caller.
 *   <li>Provides a stable, reusable container for scheduling parameters.
 * </ul>
 *
 * @param requestParams shared request context including callback, target URI, and priority.
 * @param data payload bucket to insert; must remain readable for insert lifetime.
 * @param clientMetadata optional client-visible metadata such as MIME type; may be {@code null}.
 * @param isMetadata whether the payload represents metadata rather than user content.
 * @see ClientPutter
 * @see ClientPutterOptions
 */
public record ClientPutterRequest(
    InsertRequestParams requestParams,
    RandomAccessBucket data,
    ClientMetadata clientMetadata,
    boolean isMetadata) {}
