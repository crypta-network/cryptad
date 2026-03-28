package network.crypta.clients.fcp;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import network.crypta.client.async.persistence.PersistentRequestClientHandle;
import network.crypta.client.async.persistence.PersistentRequestCoordinator;
import network.crypta.client.async.persistence.PersistentRequestHandle;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Coordinates the in-memory registry of {@link PersistentRequestClient} instances that own
 * long-lived FCP requests.
 *
 * <p>The root is reconstructed at node startup from the set of persisted requests and does not
 * store any data by itself. Callers resolve clients via their connection handler or by the
 * per-client name, and the root keeps a dedicated {@code globalForeverClient} for requests that are
 * not associated with an individual FCP session. Synchronization on {@code this} guards map
 * updates, while read paths avoid holding the lock longer than necessary so request lookups remain
 * responsive to network traffic.
 *
 * <p>Typical usage:
 *
 * <ul>
 *   <li>During client login, call {@link #registerForeverClient(String, FCPConnectionHandler)} to
 *       reuse or create the durable client context.
 *   <li>On resume, call {@link #resumePersistentRequest(PersistentRequestHandle, boolean, String)}
 *       to attach a reloaded request to its owning client.
 *   <li>Periodically call {@link #maybeUnregisterClient(PersistentRequestClient)} to release empty,
 *       non-global clients.
 * </ul>
 *
 * <p>Thread-safety: the registry is mutable but guarded; returned {@link PersistentRequestClient}
 * instances are still responsible for their own internal synchronization and request bookkeeping.
 *
 * @author toad
 * @see PersistentRequestClient
 * @see ClientRequest
 */
public class PersistentRequestRoot implements PersistentRequestCoordinator {
  private static final Logger LOG = LoggerFactory.getLogger(PersistentRequestRoot.class);

  final PersistentRequestClient globalForeverClient;
  private final Map<String, PersistentRequestClient> clients;

  // Legacy threshold callback removed.

  /**
   * Builds a new registry with an always-present global queue client.
   *
   * <p>The constructor eagerly creates {@code globalForeverClient} so callers can immediately
   * attach requests that are not tied to a specific FCP connection. No IO or persistence is
   * performed here; population of per-client queues is expected to happen during startup replay or
   * on-demand registration by FCP handlers.
   */
  public PersistentRequestRoot() {
    globalForeverClient =
        new PersistentRequestClient("Global Queue", null, true, null, Persistence.FOREVER, this);
    clients = new TreeMap<>();
  }

  /**
   * Get a persistent client, creating it if missing, and bind it to the provided connection.
   *
   * <p>This method is idempotent per {@code name} and safe to call concurrently from multiple
   * threads. It keeps the global registry synchronized while looking up or inserting the client,
   * then associates the optional {@link FCPConnectionHandler} outside the lock to avoid blocking
   * other lookups. The returned client remains valid even if the handler later disconnects; callers
   * should ensure later request operations honor that lifecycle.
   *
   * @param name stable client identifier used as the registry key; must not be blank or null.
   * @param handler connection used to deliver replies and state callbacks; may be {@code null} when
   *     recovering from disk.
   * @return persistent client instance tied to {@code name}; shared across repeated calls until
   *     explicitly removed.
   */
  public PersistentRequestClient registerForeverClient(
      final String name, FCPConnectionHandler handler) {
    if (LOG.isDebugEnabled()) LOG.debug("Registering forever-client for {}", name);
    PersistentRequestClient client;
    synchronized (this) {
      client = clients.get(name);
      if (client == null)
        client = new PersistentRequestClient(name, handler, false, null, Persistence.FOREVER, this);
      clients.put(name, client);
    }
    if (handler != null) client.setConnection(handler);
    return client;
  }

  /**
   * Retrieve an existing persistent client and optionally refresh its connection binding.
   *
   * <p>The registry is not mutated when the client does not yet exist; in that case the method
   * returns {@code null} so callers can decide whether to register a new client or reject the
   * request. When a handler is supplied, the method updates the client outside the synchronized
   * block, keeping lock contention low while still ensuring consistent lookup semantics.
   *
   * @param name registry key that identifies the persistent client to fetch; must match the value
   *     used during registration.
   * @param handler optional FCP connection to attach to the client for reply routing; may be {@code
   *     null} to leave the existing connection unchanged.
   * @return previously registered client or {@code null} when no client with that name is known to
   *     the root at the time of the call.
   */
  public PersistentRequestClient getForeverClient(final String name, FCPConnectionHandler handler) {
    PersistentRequestClient client;
    synchronized (this) {
      client = clients.get(name);
      if (client == null) return null;
    }
    if (handler != null) client.setConnection(handler);
    return client;
  }

  /**
   * Remove a non-global client from the registry when it no longer owns any persistent requests.
   *
   * <p>This helper prevents the client map from accumulating inactive entries after requests have
   * been canceled or completed. The global queue client is never removed. Callers should invoke
   * this after request teardown to keep memory usage predictable; the method itself performs an
   * inexpensive state check and synchronized removal.
   *
   * @param client persistent client to consider for removal; ignored when {@code null} or when the
   *     instance represents the shared global queue.
   */
  public void maybeUnregisterClient(PersistentRequestClient client) {
    if (!client.isGlobalQueue && !client.hasPersistentRequests()) {
      synchronized (this) {
        clients.remove(client.name);
      }
    }
  }

  /**
   * Collect all currently tracked persistent requests across the global queue and per-client queues
   * in registration order.
   *
   * <p>The returned array is a snapshot; later request additions or removals are not reflected. The
   * method delegates to {@link PersistentRequestClient#addPersistentRequests(List, boolean)} for
   * each client and therefore includes only requests marked as persistent. Consumers should not
   * mutate the returned request objects unless they hold the appropriate synchronization required
   * by {@link PersistentRequestClient}.
   *
   * @return array of persistent requests currently registered in the node; may be empty but never
   *     {@code null}.
   */
  public ClientRequest[] getPersistentRequests() {
    List<ClientRequest> requests = new ArrayList<>();
    globalForeverClient.addPersistentRequests(requests, true);
    for (PersistentRequestClient client : clients.values())
      client.addPersistentRequests(requests, true);
    return requests.toArray(new ClientRequest[0]);
  }

  @Override
  public PersistentRequestClientHandle getOrCreateClientHandle(boolean global, String clientName) {
    return makeClient(global, clientName);
  }

  @Override
  public PersistentRequestClientHandle resumePersistentRequest(
      PersistentRequestHandle request, boolean global, String clientName) {
    return resume(requireClientRequest(request), global, clientName);
  }

  PersistentRequestClient resume(ClientRequest clientRequest, boolean global, String clientName) {
    PersistentRequestClient client = makeClient(global, clientName);
    client.resume(clientRequest);
    return client;
  }

  PersistentRequestClient makeClient(boolean global, String clientName) {
    if (global) {
      return globalForeverClient;
    } else {
      return registerForeverClient(clientName, null);
    }
  }

  /**
   * Determine whether a request identifier refers to an active persistent request.
   *
   * <p>The lookup first resolves the owning client (global queue or named client) and then queries
   * the client for the request by its identifier. The method holds the registry lock only during
   * client resolution, allowing concurrent lookups to proceed. It does not verify the request state
   * beyond existence; callers must perform further validation if they need status or ownership
   * checks.
   *
   * @param req request identifier that includes the client name and whether the global queue is
   *     targeted; must not be {@code null}.
   * @return {@code true} when a matching persistent request is currently registered; {@code false}
   *     otherwise.
   */
  public synchronized boolean hasRequest(RequestIdentifier req) {
    PersistentRequestClient client;
    if (req.globalQueue) client = globalForeverClient;
    else client = getForeverClient(req.clientName, null);
    if (client == null) return false;
    return client.getRequest(req.identifier) != null;
  }

  /**
   * Accessor for the shared global persistent client used by queue-independent requests.
   *
   * <p>The instance is created during construction and never removed. It is intended for system
   * requests or client operations that outlive a specific FCP session.
   *
   * @return always-present global persistent client instance suitable for storing long-lived
   *     requests.
   */
  public PersistentRequestClient getGlobalForeverClient() {
    return globalForeverClient;
  }

  private static ClientRequest requireClientRequest(PersistentRequestHandle request) {
    if (request == null) {
      throw new IllegalArgumentException("Persistent request handle must not be null");
    }
    if (request instanceof ClientRequest clientRequest) {
      return clientRequest;
    }
    throw new IllegalArgumentException(
        "Persistent request handle is not a ClientRequest: " + request.getClass().getName());
  }
}
