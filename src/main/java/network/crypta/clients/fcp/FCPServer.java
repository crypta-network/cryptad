package network.crypta.clients.fcp;

import java.io.File;
import java.io.IOException;
import java.util.UUID;
import network.crypta.client.FetchResult;
import network.crypta.client.async.CacheFetchResult;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.DownloadCache;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.config.Config;
import network.crypta.io.AllowedHosts;
import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.pluginmanager.FredPluginFCPMessageHandler.ClientSideFCPMessageHandler;
import network.crypta.pluginmanager.PluginNotFoundException;
import network.crypta.pluginmanager.PluginRespirator;
import network.crypta.support.api.Bucket;

/**
 * Server endpoint for the Freenet Client Protocol (FCP).
 *
 * <p>This class owns the inbound network listener for FCP, accepts new socket connections, and
 * coordinates request lifecycle management for both external clients and in-process plugins. It
 * wires persistent request queues, plugin-to-plugin messaging via {@link FCPPluginConnection}, and
 * the download cache so clients can resume work across node restarts. The server is created from
 * configured defaults, started lazily through {@link #maybeStart()}, and runs a dedicated accept
 * loop on a daemon thread so shutdown does not block. Concurrency is managed through the executor
 * supplied by {@link Node}, request jobs are marshalled onto the {@link ClientContext} job runner,
 * and weakly referenced plugin connections are cleaned up automatically by {@link
 * FCPPluginConnectionTracker} to avoid leaks.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Binding the configured interface/port and enforcing the allowed-hosts lists.
 *   <li>Exposing intra-node plugin connection helpers with direction-aware adapters.
 *   <li>Managing global persistent request queues for reboot and forever persistence classes.
 *   <li>Providing cache lookups that avoid extra copies when callers permit zero-copy access.
 * </ul>
 *
 * <p>Instances are not thread-safe for direct field mutation; the class instead encapsulates the
 * mutable state (bind address, allowed hosts, queues) and uses synchronized sections or
 * thread-confined startup hooks. Network listeners are long-lived, while plugin connection trackers
 * start regardless of network enablement so non-networked plugins can still talk over FCP.
 */
public class FCPServer implements Runnable, DownloadCache {

  /**
   * Default TCP port (9481) exposed by the FCP listener so clients can auto-discover the node
   * without extra configuration.
   */
  public static final int DEFAULT_FCP_PORT = 9481;

  /* It’s not the field that is deprecated but accessing it directly is. */
  private final NodeClientCore core;

  /* It’s not the field that is deprecated but accessing it directly is. */
  private final Node node;

  final int port;

  /* It’s not the field that is deprecated but accessing it directly is. */
  final boolean enabled;

  String bindTo;
  final AllowedHosts allowedHostsFullAccess;

  private final FcpServerListener listener;
  private final FcpServerPluginConnections pluginConnections;
  private final FcpServerPersistentOps persistentOps;

  /**
   * Sentinel value used when building {@link ClientRequest} instances to permit unlimited retry
   * attempts instead of enforcing a cap.
   */
  public static final int QUEUE_MAX_RETRIES = -1;

  /**
   * Upper bound for data sizes in queued requests. The value {@link Long#MAX_VALUE} effectively
   * disables front-end size restrictions while still threading through validation APIs.
   */
  public static final long QUEUE_MAX_DATA_SIZE = Long.MAX_VALUE;

  boolean assumeDownloadDDAIsAllowed;
  boolean assumeUploadDDAIsAllowed;
  boolean neverDropAMessage;
  int maxMessageQueueLength;

  /**
   * Constructs a server instance from precomputed configuration and dependencies.
   *
   * @param config immutable configuration values for the FCP server.
   * @param dependencies node services required by the server.
   */
  public FCPServer(FcpServerConfig config, FcpServerDependencies dependencies) {
    this.bindTo = config.bindTo();
    this.allowedHostsFullAccess = new AllowedHosts(config.allowedHostsFullAccess());
    this.port = config.port();
    this.enabled = config.enabled();
    this.node = dependencies.node();
    this.core = dependencies.core();
    this.assumeDownloadDDAIsAllowed = config.assumeDownloadDDAAllowed();
    this.assumeUploadDDAIsAllowed = config.assumeUploadDDAAllowed();
    this.neverDropAMessage = config.neverDropAMessage();
    this.maxMessageQueueLength = config.maxMessageQueueLength();
    this.listener = new FcpServerListener(this, node, config);
    this.pluginConnections = new FcpServerPluginConnections(node);
    this.persistentOps = new FcpServerPersistentOps(this, core, dependencies.persistentRoot());
  }

  /**
   * Constructs a server instance wired to the provided node components and policy flags.
   *
   * <p>This constructor captures immutable configuration such as the bind address, allow-lists,
   * port, and persistence roots; runtime toggles only adjust the dedicated mutable fields. It does
   * not bind sockets or start background threads, so callers must invoke {@link #maybeStart()} to
   * begin accepting connections.
   *
   * @param ipToBindTo textual bind address; use {@code 0.0.0.0} to listen on all interfaces.
   * @param allowedHosts comma-separated allow-list enforced for standard FCP sockets.
   * @param allowedHostsFullAccess allow-list used for privileged operations that bypass some
   *     client-side restrictions.
   * @param port TCP port number for the FCP listener.
   * @param node owning {@link Node} providing executors, plugin management, and lifecycle hooks.
   * @param core node client core exposing persistence, download directories, and cache factories.
   * @param isEnabled whether networked FCP should start; intra-node plugin communication may still
   *     be enabled when {@code false}.
   * @param assumeDDADownloadAllowed flag to treat download DDA as preapproved.
   * @param assumeDDAUploadAllowed flag to treat upload DDA as preapproved.
   * @param neverDropAMessage whether outbound queues retain messages rather than dropping when
   *     limits are reached.
   * @param maxMessageQueueLength maximum messages buffered per connection before applying
   *     backpressure.
   * @param persistentRoot persistence root used to access global clients and caches.
   */
  @SuppressWarnings("java:S107")
  public FCPServer(
      String ipToBindTo,
      String allowedHosts,
      String allowedHostsFullAccess,
      int port,
      Node node,
      NodeClientCore core,
      boolean isEnabled,
      boolean assumeDDADownloadAllowed,
      boolean assumeDDAUploadAllowed,
      boolean neverDropAMessage,
      int maxMessageQueueLength,
      PersistentRequestRoot persistentRoot) {
    this(
        new FcpServerConfig(
            ipToBindTo,
            allowedHosts,
            allowedHostsFullAccess,
            port,
            isEnabled,
            assumeDDADownloadAllowed,
            assumeDDAUploadAllowed,
            neverDropAMessage,
            maxMessageQueueLength),
        new FcpServerDependencies(node, core, persistentRoot));
  }

  /**
   * Rebuilds cached request status for the forever-persistent client prior to serving queries.
   *
   * <p>This call is typically used during node startup so request state is readily available to FCP
   * clients without requiring additional disk scans.
   */
  public void load() {
    persistentOps.load();
  }

  /**
   * Starts the network listener and plugin connection tracker when configuration allows.
   *
   * <p>If {@link #enabled} is {@code true}, the method binds the configured interface, logs
   * startup, and launches the accept loop on a daemon thread. When disabled, it skips binding but
   * still starts {@link FCPPluginConnectionTracker} so intra-node plugin messaging remains
   * available. Repeated invocations are safe; only the first call performs initialization.
   */
  public void maybeStart() {
    listener.maybeStart();
    pluginConnections.startTrackerIfEnabled();
  }

  @Override
  public void run() {
    listener.run();
  }

  public static FCPServer maybeCreate(
      Node node, NodeClientCore core, Config config, PersistentRequestRoot root) {
    return FcpServerConfigRegistrar.maybeCreate(node, core, config, root);
  }

  /**
   * Indicates whether outbound message queues should avoid dropping entries under pressure.
   *
   * @return {@code true} when messages must be retained even if queues grow large; otherwise drop
   *     policies may apply.
   */
  public boolean neverDropAMessage() {
    return neverDropAMessage;
  }

  /**
   * Returns the maximum number of messages buffered per connection.
   *
   * @return queue length limit used before enforcing backpressure or drop behavior.
   */
  public int maxMessageQueueLength() {
    return maxMessageQueueLength;
  }

  /**
   * Creates and registers a plugin connection for a networked FCP client.
   *
   * <p>The returned {@link FCPPluginConnectionImpl} represents a connection where the client lives
   * outside the node and communicates over the TCP listener. It is stored inside {@link
   * FCPPluginConnectionTracker} using a weak reference so callers do not need to explicitly
   * unregister; holding a strong reference keeps the connection alive. When the last strong
   * reference is dropped, the tracker will automatically recycle the entry and subsequent lookups
   * via {@link #getPluginConnectionByID(UUID)} will fail.
   *
   * @param serverPluginName plugin name that should receive messages on the server side.
   * @param messageHandler handler associated with the network connection driving message flow.
   * @return connection wrapper bound to the tracker for the specified plugin.
   * @throws PluginNotFoundException if the plugin cannot be located or instantiated.
   */
  final FCPPluginConnectionImpl createFCPPluginConnectionForNetworkedFCP(
      String serverPluginName, FCPConnectionHandler messageHandler) throws PluginNotFoundException {
    return pluginConnections.createFCPPluginConnectionForNetworkedFCP(
        serverPluginName, messageHandler);
  }

  /**
   * Creates and registers an intra-node {@link FCPPluginConnection} for plugin-to-plugin traffic.
   *
   * <p>This shortcut is used by {@link PluginRespirator#connectToOtherPlugin(String,
   * ClientSideFCPMessageHandler)} to establish a logical FCP link without leaving the process. The
   * connection is inserted into {@link FCPPluginConnectionTracker} and stays reachable as long as
   * the caller keeps a strong reference. To match the client perspective, the returned adapter
   * defaults the send direction to {@link FCPPluginConnection.SendDirection#TO_SERVER}.
   *
   * @param serverPluginName name of the server-side plugin that will receive the messages.
   * @param messageHandler handler on the client-side plugin that processes responses.
   * @return connection adapter configured for server-directed sends.
   * @throws PluginNotFoundException if the target plugin cannot be found or instantiated.
   */
  public final FCPPluginConnection createFCPPluginConnectionForIntraNodeFCP(
      String serverPluginName, ClientSideFCPMessageHandler messageHandler)
      throws PluginNotFoundException {
    return pluginConnections.createFCPPluginConnectionForIntraNodeFCP(
        serverPluginName, messageHandler);
  }

  /**
   * Retrieves a plugin connection by identifier and adapts it for server-originated traffic.
   *
   * <p>The lookup delegates to {@link FCPPluginConnectionTracker#getConnection(UUID)} and wraps the
   * result so the default send direction points to the client side. The connection must still be
   * strongly referenced elsewhere; once only weakly reachable it will be absent from the tracker.
   *
   * @param connectionID identifier returned when the corresponding connection was created.
   * @return connection adapted to default-send toward the client side.
   * @throws IOException if the connection metadata cannot be resolved or underlying state is
   *     inaccessible.
   */
  public final FCPPluginConnection getPluginConnectionByID(UUID connectionID) throws IOException {
    return pluginConnections.getPluginConnectionByID(connectionID);
  }

  /**
   * Registers or replaces a reboot-persistent client associated with the given name.
   *
   * @param name stable client identifier kept across reconnects.
   * @param handler active connection handler for the client.
   * @return existing client after handler replacement, or a newly created client when absent.
   */
  public PersistentRequestClient registerRebootClient(String name, FCPConnectionHandler handler) {
    return persistentOps.registerRebootClient(name, handler);
  }

  /**
   * Registers a forever-persistent client and returns the associated queue owner.
   *
   * @param name identifier used for persistence and status reporting.
   * @param handler current connection handler, or {@code null} when registering headless.
   * @return client instance tied to the forever queue.
   */
  public PersistentRequestClient registerForeverClient(String name, FCPConnectionHandler handler) {
    return persistentOps.registerForeverClient(name, handler);
  }

  /**
   * Retrieves or creates a forever-persistent client for the provided name and handler.
   *
   * @param name client name to look up.
   * @param handler handler representing the active connection; may be {@code null} when resuming.
   * @return existing or newly created client.
   */
  public PersistentRequestClient getForeverClient(String name, FCPConnectionHandler handler) {
    return persistentOps.getForeverClient(name, handler);
  }

  /**
   * Unregisters the given persistent client from its queue.
   *
   * @param client client to remove; reboot clients are removed from the local map, forever clients
   *     delegate to {@link PersistentRequestRoot} for cleanup.
   */
  public void unregisterClient(PersistentRequestClient client) {
    persistentOps.unregisterClient(client);
  }

  /**
   * Returns a snapshot of global persistent requests across reboot and forever queues.
   *
   * @return array of request status entries; never {@code null}.
   * @throws PersistenceDisabledException if persistence is unavailable while reading status.
   */
  public RequestStatus[] getGlobalRequests() throws PersistenceDisabledException {
    return persistentOps.getGlobalRequests();
  }

  /**
   * Removes a single global request by identifier, blocking until the operation completes.
   *
   * @param identifier identifier of the request to remove.
   * @return {@code true} if the request existed and removal was attempted; {@code false} if no
   *     matching request was found.
   * @throws PersistenceDisabledException if persistence is disabled during removal.
   */
  @SuppressWarnings("UnusedReturnValue")
  public boolean removeGlobalRequestBlocking(final String identifier)
      throws PersistenceDisabledException {
    return persistentOps.removeGlobalRequestBlocking(identifier);
  }

  /**
   * Removes all global requests, blocking until the forever queue has been cleared.
   *
   * @return {@code true} if both reboot and forever queues were cleared successfully; {@code false}
   *     otherwise.
   * @throws PersistenceDisabledException if persistence is unavailable during removal.
   */
  @SuppressWarnings("unused")
  public boolean removeAllGlobalRequestsBlocking() throws PersistenceDisabledException {
    return persistentOps.removeAllGlobalRequestsBlocking();
  }

  /**
   * Enqueues a global persistent fetch and waits for registration to finish.
   *
   * <p>The request is created on the persistence job runner so database consistency is preserved;
   * this caller then blocks on a latch to surface any {@link NotAllowedException} or {@link
   * IOException} produced during setup. Disk return types allocate filenames under {@code
   * downloadsDir} with collision avoidance. Real-time and filtering flags are forwarded unchanged
   * to the underlying {@link ClientGet}.
   *
   * @param params request parameters describing the fetch.
   * @throws NotAllowedException if policy or security checks reject the request.
   * @throws IOException if preparing disk output fails.
   * @throws PersistenceDisabledException if persistence layers are not available.
   */
  public void makePersistentGlobalRequestBlocking(PersistentGlobalRequestParams params)
      throws NotAllowedException, IOException, PersistenceDisabledException {
    persistentOps.makePersistentGlobalRequestBlocking(params);
  }

  @SuppressWarnings("unused")
  public void makePersistentGlobalRequestBlocking(
      FreenetURI fetchURI,
      boolean filterData,
      String expectedMimeType,
      String persistenceTypeString,
      String returnTypeString,
      boolean realTimeFlag,
      File downloadsDir)
      throws NotAllowedException, IOException, PersistenceDisabledException {
    persistentOps.makePersistentGlobalRequestBlocking(
        fetchURI,
        filterData,
        expectedMimeType,
        persistenceTypeString,
        returnTypeString,
        realTimeFlag,
        downloadsDir);
  }

  /**
   * Updates the token and priority of a global request, blocking until the change is applied.
   *
   * @param identifier request identifier to modify; must correspond to an existing request.
   * @param newToken replacement token value stored with the request.
   * @param newPriority updated priority class; larger values typically move the request sooner.
   * @return {@code true} if the request existed and an update path executed; {@code false}
   *     otherwise.
   * @throws PersistenceDisabledException if persistence is unavailable while attempting the update.
   */
  @SuppressWarnings("UnusedReturnValue")
  public boolean modifyGlobalRequestBlocking(
      final String identifier, final String newToken, final short newPriority)
      throws PersistenceDisabledException {
    return persistentOps.modifyGlobalRequestBlocking(identifier, newToken, newPriority);
  }

  /**
   * Creates a persistent globally queued fetch request with explicit return handling.
   *
   * @param params request parameters describing the persistent fetch.
   * @throws NotAllowedException if local policy forbids creating the request.
   * @throws IOException if disk output setup fails or the downloads directory is invalid.
   */
  @SuppressWarnings("unused")
  public void makePersistentGlobalRequest(PersistentGlobalRequestParams params)
      throws NotAllowedException, IOException {
    persistentOps.makePersistentGlobalRequest(params);
  }

  /**
   * Convenience overload that enqueues a persistent request using the default downloads directory.
   *
   * <p>All parameters mirror {@link #makePersistentGlobalRequest(PersistentGlobalRequestParams)},
   * substituting {@link NodeClientCore#getDownloadsDir()} for the target directory. The request is
   * created synchronously but does not block on completion.
   *
   * @param fetchURI URI to fetch from the network.
   * @param filterData whether content should be filtered prior to delivery.
   * @param expectedMimeType MIME hint used when choosing output filenames.
   * @param persistenceTypeString persistence mode string (e.g., {@code reboot} or {@code forever}).
   * @param returnTypeString return handling string (e.g., {@code disk} or {@code direct}).
   * @param realTimeFlag whether to mark the request as real-time.
   * @throws NotAllowedException if download permissions deny the request.
   * @throws IOException if disk preparation fails while resolving the downloads directory.
   */
  @SuppressWarnings({"java:S107", "unused"})
  public void makePersistentGlobalRequest(
      FreenetURI fetchURI,
      boolean filterData,
      String expectedMimeType,
      String persistenceTypeString,
      String returnTypeString,
      boolean realTimeFlag)
      throws NotAllowedException, IOException {
    persistentOps.makePersistentGlobalRequest(
        fetchURI,
        filterData,
        expectedMimeType,
        persistenceTypeString,
        returnTypeString,
        realTimeFlag);
  }

  /**
   * Creates a persistent globally queued fetch request with explicit return handling.
   *
   * <p>The method chooses an identifier derived from the URI or a random Base64 suffix to avoid
   * collisions, configures retries and data limits using {@link #QUEUE_MAX_RETRIES} and {@link
   * #QUEUE_MAX_DATA_SIZE}, and registers the resulting {@link ClientGet} on the appropriate
   * persistent client. Disk return types derive filenames from {@link
   * FreenetURI#getPreferredFilename} while deduplicating existing files in {@code downloadsDir}.
   *
   * @param fetchURI URI representing the resource to fetch.
   * @param filterData whether to filter the fetched data before exposure to the client.
   * @param expectedMimeType MIME type hint for selecting output file extensions; may be {@code
   *     null}.
   * @param persistenceTypeString string describing the persistence policy; {@code reboot} limits to
   *     reboot persistence while other values select forever persistence.
   * @param returnTypeString string describing where the result should be delivered, mapped to
   *     {@link ReturnType} values.
   * @param realTimeFlag whether to request real-time handling of the fetch.
   * @param downloadsDir directory where disk results are stored when {@code returnTypeString}
   *     resolves to disk output.
   * @throws NotAllowedException if local policy forbids creating the request.
   * @throws IOException if disk output setup fails or the downloads directory is invalid.
   */
  @SuppressWarnings("unused")
  public void makePersistentGlobalRequest(
      FreenetURI fetchURI,
      boolean filterData,
      String expectedMimeType,
      String persistenceTypeString,
      String returnTypeString,
      boolean realTimeFlag,
      File downloadsDir)
      throws NotAllowedException, IOException {
    persistentOps.makePersistentGlobalRequest(
        fetchURI,
        filterData,
        expectedMimeType,
        persistenceTypeString,
        returnTypeString,
        realTimeFlag,
        downloadsDir);
  }

  /**
   * Returns the forever-persistent global client used by this server instance.
   *
   * @return client reference for the forever queue; may be {@code null} when persistence is
   *     disabled.
   */
  public PersistentRequestClient getGlobalForeverClient() {
    return persistentOps.getGlobalForeverClient();
  }

  /**
   * Retrieves a global request by identifier from either persistence class.
   *
   * @param identifier request identifier to search for.
   * @return matching request from the reboot or forever queue, or {@code null} if none exist.
   */
  public ClientRequest getGlobalRequest(String identifier) {
    return persistentOps.getGlobalRequest(identifier);
  }

  /**
   * Indicates whether download DDA permissions are assumed to be granted globally.
   *
   * @return {@code true} if downloads are treated as preauthorized for direct directory access.
   */
  protected boolean isDownloadDDAAlwaysAllowed() {
    return assumeDownloadDDAIsAllowed;
  }

  /**
   * Indicates whether upload DDA permissions are assumed to be granted globally.
   *
   * @return {@code true} if uploads are treated as preauthorized for direct directory access.
   */
  protected boolean isUploadDDAAlwaysAllowed() {
    return assumeUploadDDAIsAllowed;
  }

  /**
   * Registers a completion callback that will be invoked when persistent requests finish.
   *
   * @param cb callback to notify on completion events for both reboot and forever queues.
   */
  public void setCompletionCallback(RequestCompletionCallback cb) {
    persistentOps.setCompletionCallback(cb);
  }

  /**
   * Starts a persistent request on the global queue, blocking until scheduled.
   *
   * <p>For reboot-persistent requests the method registers and starts immediately on the caller's
   * thread. Forever-persistent requests are enqueued onto the persistence job runner and awaited
   * via a latch to ensure registration succeeded before returning. Collisions are propagated to
   * callers so they can pick a new identifier.
   *
   * @param req request to start; must already be fully configured and not yet registered.
   * @throws IdentifierCollisionException if another request with the same identifier exists.
   * @throws PersistenceDisabledException if persistence is unavailable while registering the
   *     request.
   */
  public void startBlocking(final ClientRequest req)
      throws IdentifierCollisionException, PersistenceDisabledException {
    persistentOps.startBlocking(req);
  }

  /**
   * Restarts a global request identified by {@code identifier}, blocking until restart dispatches.
   *
   * @param identifier request identifier to restart.
   * @param disableFilterData when {@code true}, restarts the request without data filtering even if
   *     the original requested filtering.
   * @return {@code true} if a matching request was found and restart attempted; {@code false}
   *     otherwise.
   * @throws PersistenceDisabledException if persistence is unavailable during restart.
   */
  @SuppressWarnings("UnusedReturnValue")
  public boolean restartBlocking(final String identifier, final boolean disableFilterData)
      throws PersistenceDisabledException {
    return persistentOps.restartBlocking(identifier, disableFilterData);
  }

  /**
   * Retrieves a completed request result for the given key, blocking if necessary.
   *
   * <p>The method first checks reboot-persistent completions, then forever-queue shadow buckets,
   * and finally schedules a lookup job when data is not immediately present. Buckets returned to
   * callers are wrapped to avoid premature freeing.
   *
   * @param key key originally requested by the client.
   * @return fetch result containing metadata and data buckets, or {@code null} if not found.
   * @throws PersistenceDisabledException if persistence access fails during lookup.
   */
  @SuppressWarnings("unused")
  public FetchResult getCompletedRequestBlocking(final FreenetURI key)
      throws PersistenceDisabledException {
    return persistentOps.getCompletedRequestBlocking(key);
  }

  /**
   * Attempts an immediate cache fetch without scheduling new work.
   *
   * <p>The method inspects completed reboot-persistent requests first, then consults the forever
   * queue's shadow cache. Callers may request filtered or raw data and choose zero-copy access by
   * setting {@code mustCopy} to {@code false}. When copying is requested, data is duplicated into
   * the preferred bucket if supplied.
   *
   * @param key key associated with the original request.
   * @param noFilter {@code true} to bypass filtering guardrails and return raw data when available.
   * @param mustCopy {@code true} to force a defensive copy of the data before returning.
   * @param preferred optional preallocated bucket used as the copy target.
   * @return cache fetch result when present; {@code null} if no completed request is available.
   */
  @Override
  public CacheFetchResult lookupInstant(
      FreenetURI key, boolean noFilter, boolean mustCopy, Bucket preferred) {
    return persistentOps.lookupInstant(key, noFilter, mustCopy, preferred);
  }

  /**
   * Performs a cache lookup scoped to the forever queue, optionally copying results.
   *
   * @param key key originally requested by the client.
   * @param noFilter {@code true} to request unfiltered data even when stored as filtered.
   * @param context client context used to resolve shadow buckets; currently unused directly.
   * @param mustCopy {@code true} to force cloning data into a separate bucket before returning.
   * @param preferred optional bucket to reuse for copies; otherwise a new temporary bucket is
   *     created.
   * @return cache result when data exists in the forever queue; {@code null} otherwise.
   */
  @Override
  public CacheFetchResult lookup(
      FreenetURI key, boolean noFilter, ClientContext context, boolean mustCopy, Bucket preferred) {
    return persistentOps.lookup(key, noFilter, context, mustCopy, preferred);
  }

  /**
   * Exposes the backing {@link NodeClientCore} for callers needing lower-level services.
   *
   * @return node client core instance used by this server.
   */
  public NodeClientCore getCore() {
    return core;
  }

  /**
   * Returns the owning {@link Node} instance.
   *
   * @return node that created and manages this server.
   */
  public Node getNode() {
    return node;
  }

  AllowedHosts getAllowedHostsFullAccess() {
    return allowedHostsFullAccess;
  }

  FcpServerListener listener() {
    return listener;
  }

  /**
   * Reports whether the FCP network listener is configured to start.
   *
   * @return {@code true} when networked FCP is enabled in configuration.
   */
  public boolean isEnabled() {
    return enabled;
  }

  /**
   * Returns the reboot-persistent global client used by this server instance.
   *
   * @return client reference for the reboot queue.
   */
  public PersistentRequestClient getGlobalRebootClient() {
    return persistentOps.getGlobalRebootClient();
  }
}
