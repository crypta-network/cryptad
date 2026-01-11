package network.crypta.clients.fcp;

import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.keys.FreenetURI;

/**
 * Groups persistent insert request identity and queue metadata for FCP-based inserts.
 *
 * <p>The record captures the URI, identifier, verbosity, priority, and persistence settings needed
 * to wire a {@link ClientPutBase}-derived request into the persistent queue while also retaining
 * optional charset and client token hints for metadata construction and status reporting.
 *
 * @param client persistent request owner used for queue bookkeeping
 * @param uri target insert URI requested by the client
 * @param identifier client-supplied identifier echoed back in status updates
 * @param verbosity verbosity bitmask for progress messages
 * @param charset optional charset hint for metadata generation; may be {@code null}
 * @param priorityClass scheduler priority to apply to the insert
 * @param persistence persistence mode for the insert lifecycle
 * @param clientToken optional client token echoed back to external observers; may be {@code null}
 * @param global whether the request participates in the global queue
 */
public record FcpInsertRequest(
    PersistentRequestClient client,
    FreenetURI uri,
    String identifier,
    int verbosity,
    String charset,
    short priorityClass,
    Persistence persistence,
    String clientToken,
    boolean global) {}
