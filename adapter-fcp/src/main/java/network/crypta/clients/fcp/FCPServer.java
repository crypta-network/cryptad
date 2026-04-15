package network.crypta.clients.fcp;

import java.io.File;
import java.io.IOException;
import network.crypta.client.FetchResult;
import network.crypta.client.async.CacheFetchResult;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.client.async.persistence.PersistentRequestRuntimeContext;
import network.crypta.config.Config;
import network.crypta.io.AllowedHosts;
import network.crypta.keys.FreenetURI;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.support.api.Bucket;

/**
 * Server endpoint for the Freenet Client Protocol (FCP).
 *
 * <p>This class owns the inbound network listener for FCP, accepts new socket connections, and
 * coordinates request lifecycle management for external clients. It wires persistent request queues
 * and the download cache so clients can resume work across node restarts. The server is created
 * from configured defaults, started lazily through {@link #maybeStart()}, and runs a dedicated
 * accept-loop on a daemon thread so shutdown does not block. Runtime-facing listener work is
 * scheduled through {@link RuntimePorts#execution()}, and persistence-affecting work is routed
 * through the server runtime-support seam.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Binding the configured interface/port and enforcing the allowed-hosts lists.
 *   <li>Managing global persistent request queues for reboot and forever persistence classes.
 *   <li>Providing cache lookups that avoid extra copies when callers permit zero-copy access.
 * </ul>
 *
 * <p>Instances are not thread-safe for direct field mutation; the class instead encapsulates the
 * mutable state (bind address, allowed hosts, queues) and uses synchronized sections or
 * thread-confined startup hooks. Network listeners are long-lived and started only when enabled by
 * configuration.
 */
public class FCPServer implements Runnable, FcpDownloadCache {

  /**
   * Default TCP port (9481) exposed by the FCP listener for network clients.
   *
   * <p>This value is used as the configuration default when a node does not override the port
   * explicitly. It does not imply that the listener is enabled or bound; callers still decide when
   * to create and start the server based on configuration and lifecycle state.
   */
  public static final int DEFAULT_FCP_PORT = 9481;

  private final FcpServerRuntimeSupport serverRuntimeSupport;
  private final FcpMessageRuntimeSupport messageRuntimeSupport;
  private final FcpFetchRuntimeSupport fetchRuntimeSupport;
  private final FcpFetchRuntimeSupport messageFetchRuntimeSupport;
  private final FcpInsertRuntimeSupport insertRuntimeSupport;

  private final RuntimePorts runtime;

  final int port;

  /* It’s not the field that is deprecated, but accessing it directly is. */
  final boolean enabled;

  String bindTo;
  final AllowedHosts allowedHostsFullAccess;

  private final FcpServerListener listener;
  private final FcpServerPersistentOps persistentOps;

  /**
   * Sentinel value used when building {@link ClientRequest} instances to permit unlimited retries.
   *
   * <p>Passing this constant tells the request pipeline not to enforce a retry cap. It is treated
   * as a special value by request builders rather than a literal retry count, so callers should not
   * interpret the value numerically beyond its sentinel meaning.
   */
  public static final int QUEUE_MAX_RETRIES = -1;

  /**
   * Upper bound for data sizes in queued requests. The value {@link Long#MAX_VALUE} effectively
   * disables front-end size restrictions while still threading through validation APIs.
   *
   * <p>Use this constant when the server layer should enforce no explicit size limit. The request
   * logic still accepts the value as a legitimate maximum, allowing validation and logging code
   * paths to treat the setting uniformly.
   */
  public static final long QUEUE_MAX_DATA_SIZE = Long.MAX_VALUE;

  boolean assumeDownloadDDAIsAllowed;
  boolean assumeUploadDDAIsAllowed;
  boolean neverDropAMessage;
  int maxMessageQueueLength;

  /**
   * Constructs a server instance from precomputed configuration and dependencies.
   *
   * <p>The constructor copies the immutable configuration fields, initializes the mutable runtime
   * flags, and wires helper components such as the listener and persistence operations. It does not
   * bind sockets or spawn threads; callers must invoke {@link #maybeStart()} to begin accepting
   * network connections.
   *
   * @param config immutable configuration values used to initialize server state.
   * @param dependencies node services required to satisfy listener and persistence wiring.
   */
  public FCPServer(FcpServerConfig config, FcpServerDependencies dependencies) {
    this.bindTo = config.bindTo();
    this.allowedHostsFullAccess = new AllowedHosts(config.allowedHostsFullAccess());
    this.port = config.port();
    this.enabled = config.enabled();
    this.runtime = dependencies.runtimePorts();
    this.serverRuntimeSupport = dependencies.serverRuntimeSupport();
    this.messageRuntimeSupport = dependencies.messageRuntimeSupport();
    this.fetchRuntimeSupport = dependencies.fetchRuntimeSupport();
    this.messageFetchRuntimeSupport = dependencies.messageFetchRuntimeSupport();
    this.insertRuntimeSupport = dependencies.insertRuntimeSupport();
    dependencies.persistentRoot().setFetchRuntimeSupport(this.fetchRuntimeSupport);
    this.assumeDownloadDDAIsAllowed = config.assumeDownloadDDAAllowed();
    this.assumeUploadDDAIsAllowed = config.assumeUploadDDAAllowed();
    this.neverDropAMessage = config.neverDropAMessage();
    this.maxMessageQueueLength = config.maxMessageQueueLength();
    this.listener = new FcpServerListener(this, runtime, config);
    this.persistentOps =
        new FcpServerPersistentOps(this, serverRuntimeSupport, dependencies.persistentRoot());
  }

  /**
   * Rebuilds cached request status for the forever-persistent client before serving queries.
   *
   * <p>This call is typically used during node startup, so the request state is readily available
   * to FCP clients without requiring additional disk scans. The implementation delegates to the
   * persistence helper, which updates internal caches and prepares lookup state before clients
   * start querying the queues. It performs no network activity and is safe to call multiple times,
   * although repeated calls may incur extra disk or database work.
   */
  public void load() {
    persistentOps.load();
  }

  /**
   * Starts the network listener when configuration allows.
   *
   * <p>If {@link #enabled} is {@code true}, the method binds the configured interface, logs
   * startup, and launches the accept-loop on a daemon thread. When disabled, it skips binding.
   * Repeated invocations are safe; only the first call performs initialization. The method does not
   * block on socket acceptance, so callers can continue startup immediately after invoking it.
   */
  public void maybeStart() {
    listener.maybeStart();
  }

  /**
   * Runs the FCP server listener loop on the current thread.
   *
   * <p>This method delegates to the listener implementation and typically blocks until the listener
   * is shut down. It is generally invoked by the daemon thread created in {@link #maybeStart()},
   * but may also be executed directly in tests or controlled environments. It performs no
   * scheduling by itself and returns only after the listener stops.
   */
  @Override
  public void run() {
    listener.run();
  }

  /**
   * Builds an {@link FCPServer} instance using configuration registered in the provided config.
   *
   * <p>This factory wires the FCP-related settings into the {@code fcp} configuration subtree and
   * constructs the server with immutable values derived from that configuration. It does not start
   * network listeners; callers still invoke {@link #maybeStart()} at the appropriate lifecycle
   * point. The returned server is fully wired to the supplied dependencies, so it can immediately
   * serve FCP traffic once started.
   *
   * @param dependencies prebuilt FCP runtime and persistence dependencies.
   * @param config configuration registry where the {@code fcp} subsection is registered.
   * @return configured server instance ready to be started by the caller.
   */
  public static FCPServer maybeCreate(FcpServerDependencies dependencies, Config config) {
    return FcpServerConfigRegistrar.maybeCreate(dependencies, config);
  }

  /**
   * Indicates whether outbound message queues should avoid dropping entries under pressure.
   *
   * <p>This is a policy flag that affects how connection handlers apply backpressure. When the
   * value is {@code true}, handlers prefer retaining queued messages even if the queue grows large,
   * which may increase memory usage but preserves message ordering and delivery. When {@code
   * false}, implementations may drop older or lower-priority messages to maintain bounded queues.
   *
   * @return {@code true} when messages must be retained even if queues grow large.
   */
  public boolean neverDropAMessage() {
    return neverDropAMessage;
  }

  /**
   * Returns the maximum number of messages buffered per connection.
   *
   * <p>The limit is applied by connection handlers that maintain outbound queues. It represents a
   * hard cap used for backpressure decisions and is interpreted as a count of messages, not bytes.
   * Callers can use this value to size buffers or to report the configuration state to clients.
   *
   * @return queue length limit used before enforcing backpressure or drop behavior.
   */
  public int maxMessageQueueLength() {
    return maxMessageQueueLength;
  }

  /**
   * Registers or replaces a reboot-persistent client associated with the given name.
   *
   * <p>The registration updates the reboot queue in memory so that reconnecting clients can resume
   * in-flight work. If a client already exists for the provided name, the handler is replaced with
   * the new connection. The method does not start any queued requests; it only updates ownership
   * and tracking structures managed by the persistence helper.
   *
   * @param name stable client identifier kept across reconnections and status queries.
   * @param handler active connection handler for the client; may be {@code null}.
   * @return existing client after handler replacement, or a newly created client.
   */
  public PersistentRequestClient registerRebootClient(String name, FCPConnectionHandler handler) {
    return persistentOps.registerRebootClient(name, handler);
  }

  /**
   * Registers a forever-persistent client and returns the associated queue owner.
   *
   * <p>This method ensures that the provided name maps to a forever queue entry, creating it if
   * needed. The handler may be {@code null} to represent a headless client; in that case, queued
   * requests remain associated with the name but no active connection is attached. The returned
   * client object is a live reference to the persistence helper's bookkeeping.
   *
   * @param name identifier used for persistence and status reporting across restarts.
   * @param handler current connection handler, or {@code null} when registering headless.
   * @return client instance tied to the forever queue and its request list.
   */
  public PersistentRequestClient registerForeverClient(String name, FCPConnectionHandler handler) {
    return persistentOps.registerForeverClient(name, handler);
  }

  /**
   * Retrieves or creates a forever-persistent client for the provided name and handler.
   *
   * <p>If a client already exists for the name, its handler is updated to the supplied value. When
   * no client exists, a new entry is created and associated with the provided handler. The method
   * does not start requests; it only ensures that ownership and connection references are current.
   *
   * @param name client name to look up, used as the persistent queue identifier.
   * @param handler handler representing the active connection; may be {@code null} when resuming.
   * @return existing or newly created client bound to the forever queue.
   */
  public PersistentRequestClient getForeverClient(String name, FCPConnectionHandler handler) {
    return persistentOps.getForeverClient(name, handler);
  }

  /**
   * Unregisters the given persistent client from its queue.
   *
   * <p>The behavior depends on the client type. Reboot-persistent clients are removed from the
   * in-memory map, while forever clients delegate to {@link PersistentRequestRoot} for cleanup and
   * persistence updates. The method does not cancel running requests; it only removes the client
   * association from future lookups.
   *
   * @param client client to remove; reboot clients are removed locally, forever clients are
   *     deregistered through persistence.
   */
  public void unregisterClient(PersistentRequestClient client) {
    persistentOps.unregisterClient(client);
  }

  /**
   * Returns a snapshot of global persistent requests across reboot and forever queues.
   *
   * <p>The returned array is a point-in-time view for status reporting. It may include entries from
   * both persistence classes, and callers should not mutate the returned objects. If persistence is
   * unavailable, the method throws, allowing callers to surface the error to clients.
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
   * <p>The method consults both reboot and forever queues and attempts to remove a matching
   * request. The call blocks until the persistence layer finishes processing the removal so that
   * callers can report accurate status to clients. When no request matches the identifier, no
   * removal work is attempted.
   *
   * @param identifier identifier of the request to remove, as stored in persistence.
   * @return {@code true} if the request existed and removal was attempted.
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
   * <p>This call clears both reboot and forever queues and blocks until persistence has completed
   * the operation. It provides a synchronous way for admin or testing clients to reset the global
   * request state. Errors in persistence are surfaced through {@link PersistenceDisabledException}.
   *
   * @return {@code true} if both reboot and forever queues were cleared successfully.
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
   * @param params request parameters describing the fetch, return mode, and persistence class.
   * @throws NotAllowedException if policy or security checks reject the request.
   * @throws IOException if preparing disk output fails.
   * @throws PersistenceDisabledException if persistence layers are not available.
   */
  public void makePersistentGlobalRequestBlocking(PersistentGlobalRequestParams params)
      throws NotAllowedException, IOException, PersistenceDisabledException {
    persistentOps.makePersistentGlobalRequestBlocking(params);
  }

  /**
   * Enqueues a global persistent fetch using explicit parameter values and blocks for registration.
   *
   * <p>This overload mirrors the structured parameter version but exposes the raw fields used by
   * FCP clients. It validates the persistence and return type strings, resolves the downloads
   * directory for disk outputs, and ensures the request is registered before returning. The method
   * does not wait for the fetch to complete; it only waits for the request to be safely enqueued.
   *
   * @param fetchURI URI representing the resource to fetch from the network.
   * @param filterData whether content should be filtered prior to delivery.
   * @param expectedMimeType MIME hint used when choosing output filenames; may be {@code null}.
   * @param persistenceTypeString persistence mode string such as {@code reboot} or {@code forever}.
   * @param returnTypeString return handling string such as {@code disk} or {@code direct}.
   * @param realTimeFlag whether to mark the request as real-time for scheduling.
   * @param downloadsDir directory used for disk outputs when the return type is disk.
   * @throws NotAllowedException if policy or security checks reject the request.
   * @throws IOException if preparing disk output fails or directory validation fails.
   * @throws PersistenceDisabledException if persistence layers are not available.
   */
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
   * <p>The method locates the request by identifier and updates its metadata in the persistence
   * layer. It blocks until the update has been committed so callers can report success reliably. If
   * no matching request exists, no update is performed and the method returns {@code false}.
   *
   * @param identifier request identifier to modify; must correspond to an existing request.
   * @param newToken replacement token value stored with the request for reporting.
   * @param newPriority updated priority class; larger values typically move the request sooner.
   * @return {@code true} if the request existed and an update path executed.
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
   * <p>The request is created asynchronously and added to the appropriate persistence queue. This
   * method does not block for completion; it only schedules the work. Disk return types will create
   * output files under the configured downloads directory when the request completes.
   *
   * @param params request parameters describing the persistent fetch and return handling.
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
   * substituting the downloads directory exposed through {@link RuntimePorts#transferAccess()} for
   * the target directory. The request is created synchronously but does not block on completion.
   * This method is suitable for callers that rely on the node's configured downloads directory and
   * do not require fine-grained output path selection.
   *
   * @param fetchURI URI to fetch from the network.
   * @param filterData whether content should be filtered prior to delivery.
   * @param expectedMimeType MIME hint used when choosing output filenames; may be {@code null}.
   * @param persistenceTypeString persistence mode string such as {@code reboot} or {@code forever}.
   * @param returnTypeString return handling string such as {@code disk} or {@code direct}.
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
   * This overload allows callers to select a custom downloads directory while retaining the
   * server's default queue behavior.
   *
   * @param fetchURI URI representing the resource to fetch.
   * @param filterData whether to filter the fetched data before exposure to the client.
   * @param expectedMimeType MIME type hint for selecting output file extensions; may be {@code
   *     null}.
   * @param persistenceTypeString string describing the persistence policy; {@code reboot} limits to
   *     reboot persistence while other values select forever persistence.
   * @param returnTypeString string describing where the result should be delivered, mapped to
   *     {@code ReturnType} values.
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
   * <p>The returned client represents the global forever queue and may be {@code null} if
   * persistence is disabled or not initialized. Callers should treat the reference as read-only and
   * avoid storing it beyond the lifecycle of the owning server, because the persistence subsystem
   * may replace or tear down the client during shutdown.
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
   * <p>The lookup checks both reboot and forever queues and returns the first matching request
   * found. The method does not trigger any network activity or state transitions; it only returns a
   * reference to the tracked request if present. The returned request should be treated as a
   * mutable state owned by the persistence layer.
   *
   * @param identifier request identifier to search for, as stored in persistence.
   * @return matching request from the reboot or forever queue, or {@code null} if none exist.
   */
  public ClientRequest getGlobalRequest(String identifier) {
    return persistentOps.getGlobalRequest(identifier);
  }

  /**
   * Indicates whether download DDA permissions are assumed to be granted globally.
   *
   * <p>This flag influences whether the server asks for explicit DDA permissions before allowing
   * direct directory access for downloads. It does not bypass any per-request security checks
   * beyond the global policy setting. Callers should read this value to determine the default
   * behavior for new requests.
   *
   * @return {@code true} if downloads are treated as preauthorized for direct directory access.
   */
  protected boolean isDownloadDDAAlwaysAllowed() {
    return assumeDownloadDDAIsAllowed;
  }

  /**
   * Indicates whether upload DDA permissions are assumed to be granted globally.
   *
   * <p>This flag informs the server's decision on whether to prompt or enforce explicit DDA
   * permission checks for upload operations. It does not grant access by itself; it only controls
   * the default assumption used by request setup. Clients should still validate the effective
   * permissions for each request.
   *
   * @return {@code true} if uploads are treated as preauthorized for direct directory access.
   */
  protected boolean isUploadDDAAlwaysAllowed() {
    return assumeUploadDDAIsAllowed;
  }

  /**
   * Registers a completion callback that will be invoked when persistent requests finish.
   *
   * <p>The callback is stored in the persistence helper and invoked when requests transition into
   * terminal states. It may be called from worker threads associated with the persistence job
   * runner, so implementations should be thread-safe and avoid blocking. Passing {@code null}
   * clears any previously registered callback.
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
   * <p>The request must already be fully configured. For reboot-persistent requests, the start
   * occurs on the caller's thread; forever-persistent requests are enqueued to the persistence job
   * runner and awaited with a latch. The method throws if the identifier collides with an existing
   * request or if persistence is disabled.
   *
   * @param req request to start; must already be configured and not yet registered.
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
   * <p>This method locates the request in either persistence queue and schedules a restart. When
   * {@code disableFilterData} is {@code true}, the restarted request disables filtering even if the
   * original request requested it. The method blocks until the restart is queued and reports
   * whether a matching request was found.
   *
   * @param identifier request identifier to restart, as stored in persistence.
   * @param disableFilterData when {@code true}, restarts the request without data filtering.
   * @return {@code true} if a matching request was found and restart attempted.
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
   * <p>The lookup checks reboot completions, then forever-queue shadow buckets, and finally
   * enqueues a lookup job if the data is not immediately present. Returned buckets are wrapped to
   * prevent premature freeing while the caller inspects them.
   *
   * @param key key originally requested by the client, used as the lookup identifier.
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
   * <p>The method inspects completed reboot-persistent requests first, then consults the forever
   * queue's shadow cache. Callers may request filtered or raw data and choose zero-copy access by
   * setting {@code mustCopy} to {@code false}. When copying is requested, data is duplicated into
   * the preferred bucket if supplied.
   *
   * @param key key associated with the original request, used for lookup.
   * @param noFilter {@code true} to bypass filtering guardrails and return raw data.
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
   * <p>The lookup is restricted to the forever persistence queue and does not consult the reboot
   * state. When {@code mustCopy} is {@code true}, the data is cloned into the preferred bucket if
   * provided, or into a new temporary bucket otherwise. The {@code context} parameter is currently
   * passed through for compatibility with the cache interface.
   *
   * @param key key originally requested by the client, used for lookup.
   * @param noFilter {@code true} to request unfiltered data even when stored as filtered.
   * @param context client context used to resolve shadow buckets; not directly mutated.
   * @param mustCopy {@code true} to force cloning data into a separate bucket before returning.
   * @param preferred optional bucket to reuse for copies; otherwise a new temporary bucket.
   * @return cache result when data exists in the forever queue; {@code null} otherwise.
   */
  @Override
  public CacheFetchResult lookup(
      FreenetURI key,
      boolean noFilter,
      PersistentRequestRuntimeContext context,
      boolean mustCopy,
      Bucket preferred) {
    return persistentOps.lookup(key, noFilter, context, mustCopy, preferred);
  }

  /**
   * Returns runtime support for residual message-level FCP infrastructure concerns.
   *
   * <p>This package-local seam keeps message execution code independent of direct daemon-core
   * access while preserving the current runtime behavior. It now also owns the detached
   * content-filter bridge used by {@link FilterMessage}. It is an internal wiring detail of {@code
   * clients.fcp}, not a public server API.
   *
   * @return message runtime support backing the remaining message-level FCP operations
   */
  FcpMessageRuntimeSupport messageRuntimeSupport() {
    return messageRuntimeSupport;
  }

  /**
   * Returns runtime support for server-owned FCP infrastructure concerns.
   *
   * <p>This package-local seam keeps connection handling, persistent request plumbing, and inbound
   * message parsing independent of direct daemon-core access while preserving current behavior. It
   * is an internal wiring detail of {@code clients.fcp}, not a public server API.
   *
   * @return server runtime support backing infrastructure-level FCP operations
   */
  FcpServerRuntimeSupport serverRuntimeSupport() {
    return serverRuntimeSupport;
  }

  /**
   * Returns the package-local runtime support used by the FCP GET/fetch path.
   *
   * <p>This seam keeps fetch request construction and getter setup independent of direct
   * daemon-core access while preserving current runtime behavior. This accessor is used for the
   * server-owned persistent/global GET flow, so its transfer policy stays aligned with {@link
   * #runtime()}. It is package-private because it is an internal wiring detail of {@code
   * clients.fcp}, not a public server API.
   *
   * @return fetch runtime support backing GET request construction and execution
   */
  FcpFetchRuntimeSupport fetchRuntimeSupport() {
    return fetchRuntimeSupport;
  }

  /**
   * Returns the package-local runtime support used by the FCP insert and USK path.
   *
   * <p>This seam keeps put request construction, upload bucket allocation, and USK subscription
   * wiring independent of direct daemon-core access while preserving current runtime behavior.
   * Insert validation historically consulted the core runtime's transfer policy for both live
   * message puts and queued local-file inserts, so this seam keeps upload checks aligned with the
   * core runtime ports. It is package-private because it is an internal wiring detail of {@code
   * clients.fcp}, not a public server API.
   *
   * @return insert runtime support backing put construction and USK subscriptions
   */
  FcpInsertRuntimeSupport insertRuntimeSupport() {
    return insertRuntimeSupport;
  }

  /**
   * Returns fetch runtime support for GET requests created directly from inbound FCP messages.
   *
   * <p>Socket/message request validation historically consulted the core runtime's transfer policy,
   * even when the enclosing {@link FCPServer} was constructed with a different {@link RuntimePorts}
   * facade. Preserving that behavior keeps connection, reboot, and forever message-based GETs on
   * the same DDA policy they used before the GET seam refactor.
   *
   * @return fetch runtime support that uses the core runtime's transfer policy for message flows
   */
  FcpFetchRuntimeSupport messageFetchRuntimeSupport() {
    return messageFetchRuntimeSupport;
  }

  /**
   * Returns the runtime SPI bridge used by FCP infrastructure code.
   *
   * <p>The returned {@link RuntimePorts} instance is the same adapter supplied during server
   * construction. It exposes execution, randomness, transfer policy, lifecycle metadata, and
   * configuration management without forcing infrastructure classes to depend directly on
   * daemon-internal types.
   *
   * @return runtime SPI bridge backing this server instance.
   */
  public RuntimePorts runtime() {
    return runtime;
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
   * <p>This flag reflects the configuration value captured at construction time. It does not
   * indicate whether the listener has actually been started, only whether it is configured to do so
   * when {@link #maybeStart()} is invoked.
   *
   * @return {@code true} when networked FCP is enabled in configuration.
   */
  public boolean isEnabled() {
    return enabled;
  }

  /**
   * Returns the reboot-persistent global client used by this server instance.
   *
   * <p>The returned client represents the reboot queue and is always present when persistence is
   * enabled. Callers should treat the reference as read-only and avoid persisting it beyond the
   * server's lifecycle, because the persistence helper owns its management.
   *
   * @return client reference for the reboot queue.
   */
  public PersistentRequestClient getGlobalRebootClient() {
    return persistentOps.getGlobalRebootClient();
  }
}
