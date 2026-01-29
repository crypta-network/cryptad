package network.crypta.clients.fcp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientRequester;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.clients.fcp.ListPersistentRequestsMessage.PersistentListJob;
import network.crypta.clients.fcp.ListPersistentRequestsMessage.TransientListJob;
import network.crypta.keys.FreenetURI;
import network.crypta.node.RequestClient;
import network.crypta.support.api.Bucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Coordinates all persistent requests issued by a single FCP client connection. The client is
 * identified by the {@link #name} exchanged during {@code ClientHello}, and the instance maintains
 * the authoritative view of running and completed requests for either {@code PERSISTENCE_REBOOT} or
 * {@code PERSISTENCE_FOREVER} lifetimes.
 *
 * <p>Typical usage wires this class between the raw {@link FCPConnectionHandler} and request
 * objects. Callers register new {@link ClientRequest} instances, forward completion callbacks, and
 * relay pending protocol messages whenever connections drop and reconnect. The class keeps a
 * consistent mapping from request identifiers to the corresponding request objects and mirrors each
 * request into running or completed queues so reconnection and listing operations can efficiently
 * stream status to peers.
 *
 * <p>Instances are inherently stateful and synchronized on {@code this} when mutating internal
 * collections. All methods expect to be invoked from the FCP server thread that owns the client;
 * concurrent calls are serialized by method-level synchronization. Requests persist for the
 * selected lifetime only: reboot-persistent entries are meant to vanish after restart, while
 * forever-persistent entries rely on a {@link PersistentRequestRoot} to reload backing data from
 * disk.
 *
 * <ul>
 *   <li>Tracks request life cycle (queued, running, completed/unacknowledged) and exposes
 *       reconnection helpers.
 *   <li>Fan-outs watch lists so the global queue can mirror updates to per-client queues.
 *   <li>Integrates with {@link RequestStatusCache} so UI and API callers can query progress without
 *       polling individual requests.
 * </ul>
 *
 * @see FCPConnectionHandler
 * @see RequestStatusCache
 */
public class PersistentRequestClient {
  private static final Logger LOG = LoggerFactory.getLogger(PersistentRequestClient.class);

  /**
   * Builds a new persistent request coordinator bound to a single named FCP client.
   *
   * <p>The constructor seeds the per-client queues, establishes the low-level request clients for
   * real-time and bulk traffic, and optionally hooks an initial completion callback. In {@code
   * PERSISTENCE_FOREVER} mode the provided {@link PersistentRequestRoot} is retained so completed
   * requests can be rehydrated from disk across restarts; reboot-persistent instances do not keep a
   * root reference. Callers should provide the current connection handler when available so
   * outbound messages can be delivered immediately.
   *
   * @param name2 stable name sent during {@code ClientHello}; must be non-null and unique per
   *     client.
   * @param handler current {@link FCPConnectionHandler} used for message delivery, or {@code null}
   *     if the client is disconnected.
   * @param isGlobalQueue whether this instance mirrors the global queue rather than a user session.
   * @param cb optional {@link RequestCompletionCallback} invoked when requests succeed, fail, or
   *     are removed.
   * @param persistence request lifetime policy; only {@code FOREVER} and {@code REBOOT} are
   *     accepted.
   * @param root backing root used to reload forever-persistent requests; required when persistence
   *     is {@code FOREVER} and ignored otherwise.
   * @throws NullPointerException if the provided name is {@code null}.
   * @throws IllegalArgumentException if the persistence mode is unsupported or the root is missing
   *     when required.
   */
  public PersistentRequestClient(
      String name2,
      FCPConnectionHandler handler,
      boolean isGlobalQueue,
      RequestCompletionCallback cb,
      Persistence persistence,
      PersistentRequestRoot root) {
    this.name = name2;
    if (name == null) throw new NullPointerException();
    this.currentConnection = handler;
    final boolean forever = (persistence == Persistence.FOREVER);
    runningPersistentRequests = new ArrayList<>();
    completedUnackedRequests = new ArrayList<>();
    clientRequestsByIdentifier = new HashMap<>();
    this.isGlobalQueue = isGlobalQueue;
    this.persistence = persistence;
    if (persistence != Persistence.FOREVER && persistence != Persistence.REBOOT) {
      throw new IllegalArgumentException("Unsupported persistence mode: " + persistence);
    }
    watchGlobalVerbosityMask = Integer.MAX_VALUE;
    lowLevelClient = new FCPClientRequestClient(this, forever, false);
    lowLevelClientRT = new FCPClientRequestClient(this, forever, true);
    completionCallbacks = new ArrayList<>();
    if (cb != null) completionCallbacks.add(cb);
    if (persistence == Persistence.FOREVER) {
      if (root == null) {
        throw new IllegalArgumentException("Persistent root must be provided for FOREVER mode");
      }
      this.root = root;
    } else this.root = null;
    if (isGlobalQueue) statusCache = new RequestStatusCache();
    else statusCache = null;
  }

  /** The persistent root object, null if persistence is PERSIST_REBOOT */
  final PersistentRequestRoot root;

  /** The client's Name sent in the ClientHello message */
  final String name;

  /** The current connection handler, if any. */
  private FCPConnectionHandler currentConnection;

  /** Currently running persistent requests */
  private final List<ClientRequest> runningPersistentRequests;

  /** Completed unacknowledged persistent requests */
  private final List<ClientRequest> completedUnackedRequests;

  /** ClientRequest's by identifier */
  private final Map<String, ClientRequest> clientRequestsByIdentifier;

  /** Are we the global queue? */
  public final boolean isGlobalQueue;

  /** Are we watching the global queue? */
  boolean watchGlobal;

  int watchGlobalVerbosityMask;

  /** FCPClients watching us. Lazy init, sync on clientsWatchingLock */
  private List<PersistentRequestClient> clientsWatching;

  private final Object clientsWatchingLock = new Object();
  private final RequestClient lowLevelClient;
  private final RequestClient lowLevelClientRT;
  private List<RequestCompletionCallback> completionCallbacks;

  /** The cache where ClientRequests report their progress */
  private final RequestStatusCache statusCache;

  /** Connection mode */
  final Persistence persistence;

  // Legacy threshold callback removed.

  /**
   * Returns the currently attached FCP connection handler.
   *
   * <p>The returned handler is mutable over the lifetime of the client and may be {@code null} when
   * the peer is disconnected. Callers should snapshot the value once and avoid reusing it after
   * reconnection events to prevent sending on a stale socket.
   *
   * @return active {@link FCPConnectionHandler} for this client, or {@code null} when disconnected.
   */
  public synchronized FCPConnectionHandler getConnection() {
    return currentConnection;
  }

  /**
   * Replaces the current connection handler with a freshly established one.
   *
   * <p>This method should be invoked immediately after a client reconnects so queued messages can
   * flow again. The previous handler, if any, is not closed here; the caller is responsible for
   * lifecycle management and should ensure {@link #onLostConnection(FCPConnectionHandler)} is
   * called when the socket drops.
   *
   * @param handler new {@link FCPConnectionHandler} to associate with this client; may be {@code
   *     null} to clear the link.
   */
  public synchronized void setConnection(FCPConnectionHandler handler) {
    this.currentConnection = handler;
  }

  /**
   * Notifies the client that a connection has been lost and frees related resources.
   *
   * <p>The handler passed in is asked to release any deferred DDA jobs, and if it matches the
   * currently active connection reference, the reference is cleared. Use this when the underlying
   * transport closes unexpectedly so reconnection logic can proceed cleanly.
   *
   * @param handler connection instance that was closed; only clears state when it equals the active
   *     handler.
   */
  public synchronized void onLostConnection(FCPConnectionHandler handler) {
    handler.freeDDAJobs();
    if (currentConnection == handler) currentConnection = null;
  }

  /**
   * Marks a persistent request as finished and stages it for acknowledgment.
   *
   * <p>This method moves the request from the running list into the completed-but-unacknowledged
   * list so the client can emit completion messages on reconnect. It also updates the {@link
   * RequestStatusCache} with the final download or upload status. Callers must only invoke this for
   * requests whose {@link ClientRequest#persistence} matches the client; mixing lifetimes is
   * treated as a programmer error. The operation is idempotent for already-moved requests but still
   * replays status caching.
   *
   * @param get finished {@link ClientRequest} that has not yet been acknowledged by the peer; must
   *     belong to this client and have matching persistence.
   * @throws IllegalStateException if the request persistence does not match the client settings or
   *     if the request type is unexpected when updating the cache.
   */
  public void finishedClientRequest(ClientRequest get) {
    if (LOG.isDebugEnabled()) LOG.debug("Finished client request");
    if (get.persistence != persistence) {
      throw new IllegalStateException("Persistence mismatch for request " + get.identifier);
    }
    synchronized (this) {
      if (runningPersistentRequests.remove(get)) {
        completedUnackedRequests.add(get);
      }
    }
    if (statusCache != null) {
      switch (get) {
        case ClientGet download -> handleDownloadCompletion(download);
        case ClientPutBase upload -> handleUploadCompletion(upload);
        default -> throw new IllegalStateException("Unexpected request type: " + get.getClass());
      }
    }
  }

  private void handleUploadCompletion(ClientPutBase upload) {
    PutFailedMessage msg = upload.getFailureMessage();
    InsertExceptionMode failureCode = null;
    String shortFailMessage = null;
    String longFailMessage = null;
    if (msg != null) {
      failureCode = msg.failureMode;
      shortFailMessage = msg.getShortFailedMessage();
      longFailMessage = msg.getLongFailedMessage();
    }
    statusCache.finishedUpload(
        upload.getIdentifier(),
        upload.hasSucceeded(),
        upload.getGeneratedURI(),
        failureCode,
        shortFailMessage,
        longFailMessage);
  }

  private void handleDownloadCompletion(ClientGet download) {
    GetFailedMessage msg = download.getFailureMessage();
    FetchExceptionMode failureCode = null;
    String shortFailMessage = null;
    String longFailMessage = null;
    if (msg != null) {
      failureCode = msg.failureMode;
      shortFailMessage = msg.getShortFailedMessage();
      longFailMessage = msg.getLongFailedMessage();
    }
    Bucket shadow = download.getBucket();
    if (shadow != null) shadow = shadow.createShadow();
    DownloadOutcomeInfo outcome =
        new DownloadOutcomeInfo(
            download.getDataSize(),
            download.getMIMEType(),
            failureCode,
            shortFailMessage,
            longFailMessage,
            shadow,
            download.filterData());
    statusCache.finishedDownload(download.getIdentifier(), download.hasSucceeded(), outcome);
  }

  /**
   * Asynchronously queues pending messages for replay after a connection restart.
   *
   * <p>Depending on the persistence mode, this spins up either a {@link PersistentListJob} or a
   * {@link TransientListJob} to enumerate requests and emit the necessary responses. The job is run
   * immediately on the provided {@link ClientContext} but does not block the caller. Completion is
   * intentionally a no-op because this helper is used during reconnection flows that already manage
   * lifecycle events.
   *
   * @param outputHandler handler used to enqueue outgoing FCP messages on the revived connection;
   *     must remain valid for the duration of the listing job.
   * @param context execution context supplying thread pools and cancellation signals for the
   *     listing job; must not be {@code null}.
   */
  public void queuePendingMessagesOnConnectionRestartAsync(
      FCPConnectionOutputHandler outputHandler, ClientContext context) {
    if (persistence == Persistence.FOREVER) {
      PersistentListJob job =
          new PersistentListJob(this, outputHandler, context, null) {

            @Override
            void complete(ClientContext context) {
              // Do nothing.
            }
          };
      job.run(context);
    } else {
      TransientListJob job =
          new TransientListJob(this, outputHandler, context, null) {

            @Override
            void complete(ClientContext context) {
              // Do nothing.
            }
          };
      job.run(context);
    }
  }

  /**
   * Queues pending protocol messages for completed, unacknowledged requests after a restart.
   *
   * <p>The method snapshots the completed list, iterates from {@code offset} up to {@code max}
   * items, and asks each request to emit any waiting messages through the supplied output handler.
   * It returns the index position reached so callers can page through large queues. No locking is
   * held while sending messages, minimizing contention with request state updates.
   *
   * @param outputHandler destination for messages to be sent immediately on the reconnected
   *     channel; must accept messages for this client.
   * @param listRequestIdentifier identifier supplied to the request when composing response bodies;
   *     typically the caller’s list request id.
   * @param offset zero-based starting position within the completed list to resume dispatching.
   * @param max maximum number of entries to process in this call; values beyond list size are
   *     clamped.
   * @return index of the first unprocessed entry (i.e., offset plus items sent), enabling paged
   *     iteration across multiple invocations.
   */
  public int queuePendingMessagesOnConnectionRestart(
      FCPConnectionOutputHandler outputHandler, String listRequestIdentifier, int offset, int max) {
    Object[] reqs;
    synchronized (this) {
      reqs = completedUnackedRequests.toArray();
    }
    int i;
    for (i = offset; i < Math.min(reqs.length, offset + max); i++) {
      ClientRequest req = (ClientRequest) reqs[i];
      req.sendPendingMessages(outputHandler, listRequestIdentifier, false, false);
    }
    return i;
  }

  /**
   * Queues pending protocol messages for active running requests.
   *
   * <p>Unlike the restart helper, this operates on the live running list so callers can stream
   * partial updates on demand. The method paginates using {@code offset} and {@code max}, sends
   * each request’s pending messages, and returns the position reached. Callers may iterate until
   * the return value equals the current running size to flush all buffered traffic.
   *
   * @param outputHandler destination handler that will transmit the queued messages immediately.
   * @param listRequestIdentifier identifier echoed back in message bodies to correlate with the
   *     originating list request.
   * @param offset zero-based index into the running list from which to begin sending.
   * @param max maximum number of requests to process; negative values are treated as zero-length
   *     dispatches.
   * @return index of the first running request not yet processed after this invocation.
   */
  public int queuePendingMessagesFromRunningRequests(
      FCPConnectionOutputHandler outputHandler, String listRequestIdentifier, int offset, int max) {
    Object[] reqs;
    synchronized (this) {
      reqs = runningPersistentRequests.toArray();
    }
    int i;
    for (i = offset; i < Math.min(reqs.length, offset + max); i++) {
      ClientRequest req = (ClientRequest) reqs[i];
      req.sendPendingMessages(outputHandler, listRequestIdentifier, false, false);
    }
    return i;
  }

  /**
   * Registers a newly created persistent request with this client.
   *
   * <p>The request is added to the running or completed list depending on its current state and is
   * indexed by identifier for later lookups. The method enforces that the request’s persistence
   * matches the client and that no other distinct request already uses the same identifier. Status
   * caching is updated to include the new request’s initial state.
   *
   * @param cg request to register; must carry a unique identifier for this client and matching
   *     persistence.
   * @throws IllegalArgumentException if the persistence differs from the client policy.
   * @throws IdentifierCollisionException if another request with the same identifier already exists
   *     in the mapping.
   */
  public void register(ClientRequest cg) throws IdentifierCollisionException {
    if (cg.persistence != persistence) {
      throw new IllegalArgumentException("Persistence mismatch for request " + cg.getIdentifier());
    }
    if (LOG.isDebugEnabled()) LOG.debug("Registering {}", cg.getIdentifier());
    synchronized (this) {
      String ident = cg.getIdentifier();
      ClientRequest old = clientRequestsByIdentifier.get(ident);
      if ((old != null) && (old != cg)) throw new IdentifierCollisionException();
      if (cg.hasFinished()) {
        completedUnackedRequests.add(cg);
      } else {
        runningPersistentRequests.add(cg);
      }
      clientRequestsByIdentifier.put(ident, cg);
    }
    if (statusCache != null) {
      if (cg instanceof ClientGet) {
        statusCache.addDownload((DownloadRequestStatus) cg.getStatus());
      } else if (cg instanceof ClientPutBase) {
        statusCache.addUpload((UploadRequestStatus) cg.getStatus());
      }
    }
  }

  /**
   * Removes and optionally cancels a request by its identifier.
   *
   * <p>The method updates the status cache, unlinks the request from internal maps and lists, and
   * notifies registered completion callbacks. When {@code kill} is true the request is cancelled
   * before removal. It returns {@code false} if no request with the supplied identifier exists,
   * leaving internal state unchanged. When a server is not provided a warning is logged because the
   * caller may miss ancillary cleanup.
   *
   * @param identifier unique request identifier belonging to this client; must not be {@code null}.
   * @param kill whether to cancel the request before removal to stop any in-flight work.
   * @param server owning {@link FCPServer}; used for logging and may be {@code null}.
   * @param context execution context passed to cancellation and request removal hooks.
   * @return {@code true} if a matching request was found and removed; {@code false} otherwise.
   */
  public boolean removeByIdentifier(
      String identifier, boolean kill, FCPServer server, ClientContext context) {
    if (server == null) {
      LOG.warn("removeByIdentifier invoked without server instance for {}", identifier);
    }
    if (LOG.isDebugEnabled()) LOG.debug("removeByIdentifier({},{})", identifier, kill);
    if (statusCache != null) statusCache.removeByIdentifier(identifier);
    ClientRequest req = removeTrackedRequest(identifier);
    if (req == null) return false;
    if (kill) {
      if (LOG.isDebugEnabled()) LOG.debug("Killing request {}", req);
      req.cancel(context);
    }
    req.requestWasRemoved(context);
    RequestCompletionCallback[] callbacks = null;
    synchronized (this) {
      if (completionCallbacks != null)
        callbacks = completionCallbacks.toArray(new RequestCompletionCallback[0]);
    }
    if (callbacks != null) {
      for (RequestCompletionCallback cb : callbacks) cb.onRemove(req);
    }
    return true;
  }

  private ClientRequest removeTrackedRequest(String identifier) {
    synchronized (this) {
      ClientRequest req = clientRequestsByIdentifier.get(identifier);
      if (req != null) {
        if (removeFromRequestLists(req)) {
          clientRequestsByIdentifier.remove(identifier);
          return req;
        }
        LOG.error(
            "Removing {}: in clientRequestsByIdentifier but not in running/completed maps!",
            identifier);
        return null;
      }
      ClientRequest fromCompleted = findAndRemoveById(completedUnackedRequests, identifier);
      if (fromCompleted != null) {
        LOG.error(
            "Found completed unacked request {} for identifier {} but not in"
                + " clientRequestsByIdentifier!!",
            fromCompleted,
            fromCompleted.getIdentifier());
        return fromCompleted;
      }
      ClientRequest fromRunning = findAndRemoveById(runningPersistentRequests, identifier);
      if (fromRunning != null) {
        LOG.error(
            "Found running request {} for identifier {} but not in clientRequestsByIdentifier!!",
            fromRunning,
            fromRunning.getIdentifier());
        return fromRunning;
      }
      return null;
    }
  }

  private boolean removeFromRequestLists(ClientRequest req) {
    return runningPersistentRequests.remove(req) || completedUnackedRequests.remove(req);
  }

  private ClientRequest findAndRemoveById(List<ClientRequest> requests, String identifier) {
    Iterator<ClientRequest> iterator = requests.iterator();
    while (iterator.hasNext()) {
      ClientRequest request = iterator.next();
      if (request.getIdentifier().equals(identifier)) {
        iterator.remove();
        return request;
      }
    }
    return null;
  }

  /**
   * Indicates whether any persistent requests are currently tracked.
   *
   * <p>Returns {@code true} when either the running list or the completed-but-unacknowledged list
   * contains entries. No locking is needed beyond the internal synchronization used by the lists.
   *
   * @return {@code true} if at least one persistent request is present; {@code false} otherwise.
   */
  public boolean hasPersistentRequests() {
    return !(runningPersistentRequests.isEmpty() && completedUnackedRequests.isEmpty());
  }

  /**
   * Adds all tracked requests to the supplied list for external processing.
   *
   * <p>The method iterates over running and completed queues and appends requests matching the
   * provided filter. When {@code onlyForever} is {@code true}, reboot-persistent requests are
   * skipped. The supplied list is modified in place; callers should provide an initially empty
   * collection to avoid mixing unrelated entries.
   *
   * @param v destination list that will receive the matching {@link ClientRequest} instances.
   * @param onlyForever whether to include only {@code PERSISTENCE_FOREVER} requests, excluding
   *     reboot-persistent entries.
   */
  public void addPersistentRequests(List<ClientRequest> v, boolean onlyForever) {
    synchronized (this) {
      for (ClientRequest req : runningPersistentRequests) {
        if (req == null) {
          LOG.error(
              "Request is null on runningPersistentRequests for {} - database corruption??", this);
          continue;
        }
        if (req.isPersistentForever() || !onlyForever) v.add(req);
      }
      v.addAll(completedUnackedRequests);
    }
  }

  /** From database */
  private void addPersistentRequestStatusFromDatabase(List<RequestStatus> status) {
    // Merging with addPersistentRequests would require revisiting locking semantics.
    List<ClientRequest> reqs = new ArrayList<>();
    addPersistentRequests(reqs, true);
    for (ClientRequest req : reqs) {
      try {
        status.add(req.getStatus());
      } catch (Exception t) {
        // Try to load the rest.
        LOG.error("BROKEN REQUEST LOADING PERSISTENT REQUEST STATUS: {}", t.getMessage(), t);
        // Consider surfacing this to the user if it becomes frequent.
      }
      // Deactivation policy depends on callers; keep current behavior.
    }
  }

  /**
   * Adds cached status snapshots for all tracked requests to the supplied list.
   *
   * <p>Unlike {@link #addPersistentRequestStatusFromDatabase(List)}, this relies on the in-memory
   * {@link RequestStatusCache} populated during the current runtime. It appends to the provided
   * list, preserving any existing entries, and does not clear the cache.
   *
   * @param status destination list that will receive status objects for both uploads and downloads;
   *     must be mutable and non-null.
   */
  public void addPersistentRequestStatus(List<RequestStatus> status) {
    statusCache.addTo(status);
  }

  /**
   * Enables or disables mirroring of the global persistent request queue.
   *
   * <p>When enabled, this client subscribes to both the reboot and forever global queues so it
   * receives broadcast messages that match its persistence mode. A verbosity mask can be supplied
   * to filter messages relayed to watchers. Disabling unsubscribes and stops further propagation.
   * The method is a no-op for the global queue itself.
   *
   * @param enabled whether to start or stop global watch behavior for this client.
   * @param verbosityMask bitmask applied to verbosity levels when forwarding messages from the
   *     global queue; only messages matching the mask are relayed.
   * @param server owning {@link FCPServer} used to access the global queue instances; must not be
   *     {@code null} when enabling watch.
   * @return {@code true} when the requested state change was applied or already in effect; {@code
   *     false} if the operation is invalid (e.g., called on the global queue itself or when no
   *     global forever client exists).
   */
  public boolean setWatchGlobal(boolean enabled, int verbosityMask, FCPServer server) {
    if (isGlobalQueue) {
      LOG.warn("Set watch global on global queue!: {}", this);
      return false;
    }
    if (server.getGlobalForeverClient() == null) return false;
    if (watchGlobal && !enabled) {
      server.getGlobalRebootClient().unwatch(this);
      server.getGlobalForeverClient().unwatch(this);
      watchGlobal = false;
    } else if (enabled && !watchGlobal) {
      server.getGlobalRebootClient().watch(this);
      server.getGlobalForeverClient().watch(this);
      FCPConnectionHandler connHandler = getConnection();
      if (connHandler != null) {
        if (persistence == Persistence.REBOOT)
          server
              .getGlobalRebootClient()
              .queuePendingMessagesOnConnectionRestartAsync(
                  connHandler.getOutputHandler(), server.getCore().getClientContext());
        else
          server
              .getGlobalForeverClient()
              .queuePendingMessagesOnConnectionRestartAsync(
                  connHandler.getOutputHandler(), server.getCore().getClientContext());
      }
      watchGlobal = true;
    }
    // Otherwise the status is unchanged.
    this.watchGlobalVerbosityMask = verbosityMask;
    return true;
  }

  /**
   * Queues a single message for this client, honoring verbosity controls.
   *
   * <p>Messages are sent immediately to the attached connection and optionally mirrored to clients
   * watching the global queue. This overload always uses the client-local verbosity mask.
   *
   * @param msg message to deliver; must be appropriate for the client’s persistence mode.
   * @param verbosityLevel verbosity associated with the message; compared against masks when
   *     relaying to watchers.
   */
  public void queueClientRequestMessage(FCPMessage msg, int verbosityLevel) {
    queueClientRequestMessage(msg, verbosityLevel, false);
  }

  /**
   * Queues a message and optionally applies the global verbosity mask when relaying.
   *
   * <p>The message is sent to the current connection if present. When invoked on the global queue
   * and {@code useGlobalMask} is true, the {@link #watchGlobalVerbosityMask} is applied to filter
   * propagation to watchers that share the same persistence policy.
   *
   * @param msg message to send; must not be {@code null}.
   * @param verbosityLevel verbosity level of the message; used for filtering when mirroring.
   * @param useGlobalMask whether to apply the global watch verbosity mask before forwarding to
   *     subscribers.
   */
  public void queueClientRequestMessage(FCPMessage msg, int verbosityLevel, boolean useGlobalMask) {
    if (useGlobalMask && (verbosityLevel & watchGlobalVerbosityMask) != verbosityLevel) return;
    sendToConnection(msg);
    if (!isGlobalQueue) {
      return;
    }
    for (PersistentRequestClient client : snapshotWatchingClients()) {
      if (client.persistence == persistence) {
        client.queueClientRequestMessage(msg, verbosityLevel, true);
      }
    }
  }

  private void sendToConnection(FCPMessage msg) {
    FCPConnectionHandler conn = getConnection();
    if (conn != null) {
      conn.send(msg);
    }
  }

  private PersistentRequestClient[] snapshotWatchingClients() {
    synchronized (clientsWatchingLock) {
      if (clientsWatching == null) {
        return new PersistentRequestClient[0];
      }
      return clientsWatching.toArray(new PersistentRequestClient[0]);
    }
  }

  private void unwatch(PersistentRequestClient client) {
    if (!isGlobalQueue) return;
    synchronized (clientsWatchingLock) {
      if (clientsWatching != null) clientsWatching.remove(client);
    }
  }

  private void watch(PersistentRequestClient client) {
    if (!isGlobalQueue) return;
    synchronized (clientsWatchingLock) {
      if (clientsWatching == null) clientsWatching = new ArrayList<>();
      clientsWatching.add(client);
    }
  }

  /**
   * Looks up a tracked request by its identifier without altering state.
   *
   * @param identifier request identifier previously registered with this client; must not be {@code
   *     null}.
   * @return matching {@link ClientRequest} or {@code null} if none is tracked under that name.
   */
  public synchronized ClientRequest getRequest(String identifier) {
    return clientRequestsByIdentifier.get(identifier);
  }

  @Override
  public String toString() {
    return super.toString() + ':' + name;
  }

  /**
   * Notifies registered completion callbacks that a request has succeeded.
   *
   * <p>The request must belong to this client and share its persistence policy. All registered
   * {@link RequestCompletionCallback callbacks} are invoked with the supplied request; any
   * exceptions they throw propagate to the caller.
   *
   * @param req request that completed successfully; must have matching persistence and identifier
   *     ownership.
   * @throws IllegalArgumentException if the request persistence does not match the client policy.
   */
  public void notifySuccess(ClientRequest req) {
    if (req.persistence != persistence) {
      throw new IllegalArgumentException("Persistence mismatch for request " + req.getIdentifier());
    }
    RequestCompletionCallback[] callbacks = null;
    synchronized (this) {
      if (completionCallbacks != null)
        callbacks = completionCallbacks.toArray(new RequestCompletionCallback[0]);
    }
    if (callbacks != null) {
      for (RequestCompletionCallback cb : callbacks) cb.notifySuccess(req);
    }
  }

  /**
   * Notifies registered completion callbacks that a request has failed.
   *
   * <p>As with {@link #notifySuccess(ClientRequest)}, the request must belong to this client. The
   * method does not alter internal state; it only forwards the failure to listeners. Callers
   * typically pair this with subsequent removal or retry logic.
   *
   * @param req request that ended in failure; must match this client’s persistence policy.
   * @throws IllegalArgumentException if the request persistence does not match the client policy.
   */
  public void notifyFailure(ClientRequest req) {
    if (req.persistence != persistence) {
      throw new IllegalArgumentException("Persistence mismatch for request " + req.getIdentifier());
    }
    RequestCompletionCallback[] callbacks = null;
    synchronized (this) {
      if (completionCallbacks != null)
        callbacks = completionCallbacks.toArray(new RequestCompletionCallback[0]);
    }
    if (callbacks != null) {
      for (RequestCompletionCallback cb : callbacks) cb.notifyFailure(req);
    }
  }

  /**
   * Registers a listener to be notified when requests succeed, fail, or are removed.
   *
   * @param cb callback to add; must not be {@code null}. Duplicate registrations are preserved and
   *     will result in multiple notifications.
   */
  public synchronized void addRequestCompletionCallback(RequestCompletionCallback cb) {
    if (completionCallbacks == null)
      completionCallbacks = new ArrayList<>(); // it is transient so it might be null
    completionCallbacks.add(cb);
  }

  /**
   * Deregisters a previously added completion callback.
   *
   * @param cb callback instance to remove; if not present, the method returns silently.
   */
  @SuppressWarnings("unused")
  public synchronized void removeRequestCompletionCallback(RequestCompletionCallback cb) {
    if (completionCallbacks != null) completionCallbacks.remove(cb);
  }

  /**
   * Clears all tracked requests and status cache entries for this client.
   *
   * <p>Both running and completed queues are emptied and the identifier map is reset. The operation
   * does not cancel in-flight work; callers should cancel or disconnect separately if required.
   */
  public void removeAll() {
    if (statusCache != null) statusCache.clear();
    synchronized (this) {
      runningPersistentRequests.clear();
      completedUnackedRequests.clear();
      clientRequestsByIdentifier.clear();
    }
  }

  /**
   * Finds a completed download request for the specified key.
   *
   * <p>Searches only the completed-but-unacknowledged list and returns the first matching {@link
   * ClientGet}. Running requests are ignored to keep lookups deterministic.
   *
   * @param key URI of the desired completed request; must not be {@code null}.
   * @return matching {@link ClientGet} instance or {@code null} if no completed request with the
   *     same URI is present.
   */
  public ClientGet getCompletedRequest(FreenetURI key) {
    // Potential optimization: a transient hashmap keyed by URI could speed lookups.
    for (ClientRequest req : completedUnackedRequests) {
      if (!(req instanceof ClientGet getter)) continue;
      if (getter.getURI().equals(key)) {
        return getter;
      }
    }
    return null;
  }

  /**
   * Returns the status cache tracking upload and download progress for this client.
   *
   * @return live {@link RequestStatusCache} instance or {@code null} when the client is not
   *     configured as the global queue.
   */
  public RequestStatusCache getRequestStatusCache() {
    return statusCache;
  }

  /**
   * Reloads the status cache from persistent storage when operating in forever mode.
   *
   * <p>This is typically called during startup to repopulate progress indicators from disk-backed
   * request state. No effect occurs for reboot-persistent clients.
   */
  public void updateRequestStatusCache() {
    updateRequestStatusCache(statusCache);
  }

  private void updateRequestStatusCache(RequestStatusCache cache) {
    if (persistence == Persistence.FOREVER) {
      LOG.info("Loading cache of request statuses...");
      ArrayList<RequestStatus> statuses = new ArrayList<>();
      addPersistentRequestStatusFromDatabase(statuses);
      for (RequestStatus status : statuses) {
        if (status instanceof DownloadRequestStatus requestStatus) cache.addDownload(requestStatus);
        else cache.addUpload((UploadRequestStatus) status);
      }
    }
  }

  /**
   * Returns the low-level request client matching the desired latency profile.
   *
   * @param realTime when {@code true}, returns the real-time oriented client; otherwise returns the
   *     standard client.
   * @return {@link RequestClient} configured for this client’s persistence and latency preference.
   */
  public RequestClient lowLevelClient(boolean realTime) {
    if (realTime) return lowLevelClientRT;
    else return lowLevelClient;
  }

  /**
   * Appends the {@link ClientRequester} objects for all tracked requests to the supplied list.
   *
   * @param requesters destination list that will be populated with requesters from running and
   *     completed requests; must not be {@code null}.
   */
  @SuppressWarnings("unused")
  public void addPersistentRequesters(List<ClientRequester> requesters) {
    for (ClientRequest req : runningPersistentRequests) requesters.add(req.getClientRequest());
    for (ClientRequest req : completedUnackedRequests) requesters.add(req.getClientRequest());
  }

  /**
   * Reattaches a deserialized or resumed request to this client.
   *
   * <p>The request is placed into the appropriate queue based on completion state and added to the
   * identifier map. If an entry with the same identifier already exists and refers to a different
   * instance, an exception is thrown to prevent corruption.
   *
   * @param clientRequest request recovered from persistence or another source; must carry a unique
   *     identifier for this client.
   * @throws IllegalArgumentException if the identifier already maps to a different request
   *     instance.
   */
  public void resume(ClientRequest clientRequest) {
    if (clientRequest.hasFinished()) completedUnackedRequests.add(clientRequest);
    else runningPersistentRequests.add(clientRequest);
    String identifier = clientRequest.identifier;
    if (clientRequestsByIdentifier.get(identifier) != null) {
      if (clientRequest != clientRequestsByIdentifier.get(identifier))
        throw new IllegalArgumentException(
            "Adding new client request "
                + clientRequest
                + " with same name \""
                + identifier
                + "\" as "
                + clientRequestsByIdentifier.get(identifier));
      else {
        LOG.error("Adding the same identifier twice: {}", identifier);
      }
    } else {
      clientRequestsByIdentifier.put(identifier, clientRequest);
    }
  }
}
