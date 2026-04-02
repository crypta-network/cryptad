package network.crypta.clients.fcp;

import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.keys.FreenetURI;

/**
 * Immutable request metadata shared across FCP client request constructors.
 *
 * <p>This record groups the core scheduling and identification fields that are common to all {@link
 * ClientRequest} variants. It keeps constructors concise while preserving the exact semantics of
 * the original parameter list.
 *
 * @param uri target URI being fetched or inserted on behalf of the client
 * @param identifier unique identifier string supplied by the FCP client for correlation
 * @param verbosity requested verbosity level for progress and status messages
 * @param priorityClass initial priority class used by the scheduler to order work
 * @param persistence persistence mode controlling lifetime across disconnects and restarts
 * @param realTime whether the request is scheduled as real-time instead of background bulk
 * @param clientToken optional opaque token echoed back to the client in notifications
 * @param global whether the request belongs to the shared global queue rather than a client
 */
public record ClientRequestParams(
    FreenetURI uri,
    String identifier,
    int verbosity,
    short priorityClass,
    Persistence persistence,
    boolean realTime,
    String clientToken,
    boolean global) {}
