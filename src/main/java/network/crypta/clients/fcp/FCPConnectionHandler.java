package network.crypta.clients.fcp;

import java.io.Closeable;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.client.async.PersistentJob;
import network.crypta.client.async.TooManyFilesInsertException;
import network.crypta.node.RequestClient;
import network.crypta.node.RequestClientBuilder;
import network.crypta.pluginmanager.PluginNotFoundException;
import network.crypta.support.HexUtil;
import network.crypta.support.io.NativeThread;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Manages the full lifecycle of a single Freenet Client Protocol (FCP) connection, routing inbound
 * client commands to the appropriate request primitives while asynchronously streaming responses
 * back to the peer.
 *
 * <p>Each handler instance encapsulates socket ownership, request registries, DDA authorizations,
 * and plugin bridge state so that transient failures stay isolated to the originating client. It
 * collaborates with {@link FCPConnectionInputHandler} and {@link FCPConnectionOutputHandler} to
 * parse framed commands, validate identifiers, and dispatch I/O without blocking the acceptor
 * threads. Callers typically create the handler through {@link FCPServer} once a socket has been
 * authenticated, then invoke {@link #start()} to spin up the paired reader/writer threads.
 *
 * <p>The handler enforces persistence policies (connection, reboot, forever) by wiring requests to
 * different {@link PersistentRequestClient}s and ensuring identifier uniqueness across the entire
 * node. All mutation of connection-scoped data structures is serialized through the handler's
 * intrinsic lock, while outbound queueing is guarded inside {@link FCPConnectionOutputHandler} to
 * keep contention manageable.
 *
 * <ul>
 *   <li>Receives FCP messages, validates them, and instantiates {@link ClientRequest}s.
 *   <li>Persists or replays pending work via job runners when clients reconnect.
 *   <li>Tracks plugin bridge usage, DDA permissions, and subscription bookkeeping.
 * </ul>
 *
 * @see FCPConnectionInputHandler
 * @see FCPConnectionOutputHandler
 * @see PersistentRequestClient
 */
public class FCPConnectionHandler implements Closeable {
  private static final Logger LOG = LoggerFactory.getLogger(FCPConnectionHandler.class);
  private static final String COLLISION_LOG_TEMPLATE = "Identifier collision on {}";
  private static final String PERSISTENCE_DISABLED_TEXT = "Persistence is disabled";
  private static final String LEGACY_LZMA_REPLACEMENT = "LZMA_NEW";

  /** Ensure we warn about legacy LZMA at most once per connection/client. */
  private final AtomicBoolean warnedLegacyLzma = new AtomicBoolean(false);

  private final FCPServer server;
  private final Socket sock;

  final FCPConnectionInputHandler inputHandler;
  final Map<String, SubscribeUSK> uskSubscriptions;

  private final FCPConnectionOutputHandler outputHandler;
  private boolean isClosed;
  private boolean inputClosed;
  private boolean outputClosed;
  private String clientName;
  private PersistentRequestClient rebootClient;
  private PersistentRequestClient foreverClient;
  final HashMap<String, ClientRequest> requestsByIdentifier;

  private final PluginConnectionRegistry pluginConnectionRegistry = new PluginConnectionRegistry();

  private static final class CloseSnapshot {
    final ClientRequest[] requests;
    final SubscribeUSK[] subscriptions;
    final boolean duplicateKilled;

    CloseSnapshot(ClientRequest[] requests, SubscribeUSK[] subscriptions, boolean duplicateKilled) {
      this.requests = requests;
      this.subscriptions = subscriptions;
      this.duplicateKilled = duplicateKilled;
    }
  }

  private enum RegistrationResult {
    REGISTERED,
    DUPLICATE,
    CLOSED
  }

  /**
   * Legacy 16-byte hexadecimal identifier mirrored from older protocol versions so existing client
   * libraries can continue to correlate reconnect attempts and queue state without having to
   * understand UUIDs. The value is immutable and scoped to this connection instance only.
   */
  public final String connectionIdentifier;

  /**
   * Deterministic UUID derived from the same random bytes as {@link #connectionIdentifier}, giving
   * modern code a stable, strongly typed identifier for metrics, plugin bridges, and logs while
   * keeping interop with legacy peers.
   */
  protected final UUID connectionIdentifierUUID;

  private boolean killedDupe;

  private final DdaAccessController ddaAccessController;

  /**
   * Request client tuned for bulk traffic; used when a caller opts out of realtime delivery so the
   * node can batch IO and reduce scheduler churn.
   */
  public final RequestClient connectionRequestClientBulk = new RequestClientBuilder().build();

  /**
   * Request client configured for realtime latency expectations, ensuring minimal queueing delays
   * when the peer explicitly marks an operation as realtime.
   */
  public final RequestClient connectionRequestClientRT =
      new RequestClientBuilder().realTime().build();

  DdaAccessController ddaAccessController() {
    return ddaAccessController;
  }

  /**
   * Returns the UUID associated with this connection so that callers can tag metrics or correlate
   * asynchronous callbacks without relying on the legacy hexadecimal identifier.
   *
   * <p>The value is thread-safe, never {@code null}, and suitable for use as a map key or log
   * correlation id. Because it is derived deterministically from the original 16 bytes, operators
   * can bridge stats that still expect the legacy hex value.
   *
   * @return Immutable UUID derived from the random seed assigned during construction; it never
   *     changes for the lifetime of this handler.
   */
  public UUID getConnectionIdentifierUUID() {
    return connectionIdentifierUUID;
  }

  /**
   * Creates a handler bound to the provided socket and owning server, generating the random
   * identifiers, request registries, and IO helpers needed to start processing messages.
   *
   * <p>The constructor wires up paired input/output handlers, instantiates connection-scoped
   * request maps, configures DDA access control, and seeds both the legacy hexadecimal identifier
   * and UUID from the node's secure RNG. No IO occurs yet; call {@link #start()} after the handler
   * is fully configured to spawn its worker threads.
   *
   * @param s Connected socket for the peer; must already be authenticated and not null.
   * @param server Owning {@link FCPServer} providing node services, persistent clients, and
   *     configuration knobs for this handler.
   */
  public FCPConnectionHandler(Socket s, FCPServer server) {
    this.sock = s;
    this.server = server;
    isClosed = false;
    requestsByIdentifier = new HashMap<>();
    uskSubscriptions = new HashMap<>();
    this.inputHandler = new FCPConnectionInputHandler(this);
    this.outputHandler = new FCPConnectionOutputHandler(this);
    this.ddaAccessController = new DdaAccessController(server, LOG);

    byte[] identifier = new byte[16];
    server.getNode().getRandom().nextBytes(identifier);
    this.connectionIdentifier = HexUtil.bytesToHex(identifier);

    // The random 16-byte identifier was used before we added the UUID. Luckily, UUIDs are also
    // 16 bytes, so we can re-use the bytes.
    // When removing the legacy connectionIdentifier field, use UUID.randomUUID() instead.
    this.connectionIdentifierUUID = UUID.nameUUIDFromBytes(identifier);
  }

  /**
   * Enqueues an {@link FCPMessage} for asynchronous transmission via the paired {@link
   * FCPConnectionOutputHandler} and returns immediately.
   *
   * <p>The method only synchronizes long enough to place the message into the bounded outbound
   * queue, respecting the server's drop policy when limits are exceeded. Because the actual socket
   * write happens on the output thread, callers must treat this method as fire-and-forget: a return
   * value simply means queuing succeeded, not that the peer received or acknowledged anything. Use
   * the handler's logging output when diagnosing queue pressure or dropped messages.
   *
   * @param message Non-null message that has already been fully constructed and validated for
   *     network serialization.
   */
  public final void send(final FCPMessage message) {
    if (LOG.isTraceEnabled()) LOG.trace("Queueing {}", message);
    if (message == null) throw new NullPointerException();
    boolean neverDropAMessage = server.neverDropAMessage();
    int maxQueueLength = server.maxMessageQueueLength();
    synchronized (outputHandler.outQueue) {
      if (outputHandler.closedOutputQueue) {
        LOG.error("Closed already: {} queueing message {}", this, message);
        return;
      }
      if (outputHandler.outQueue.size() >= maxQueueLength) {
        if (neverDropAMessage) {
          LOG.error(
              "FCP message queue length is {} for {} - not dropping message as configured...",
              outputHandler.outQueue.size(),
              this);
        } else {
          LOG.error(
              "Dropping FCP message to {} : {} messages queued - maybe client died?",
              this,
              outputHandler.outQueue.size(),
              new Exception("debug"));
          return;
        }
      }
      outputHandler.outQueue.add(message);
      outputHandler.outQueue.notifyAll();
    }
  }

  void start() {
    inputHandler.start();
    outputHandler.start();
  }

  /**
   * Closes the handler by notifying persistent clients, cancelling outstanding requests, and
   * shutting down the socket once both streams are drained.
   *
   * <p>The shutdown sequence prepares a snapshot under synchronization to ensure no new requests
   * slip in, marks the handler as closed, and then iterates over the outstanding {@link
   * ClientRequest}s outside the lock so callbacks can run without reentrancy hazards. When a
   * duplicate connection forced this handler to exit early, client cleanup is skipped to avoid
   * double-unregistration. The method is idempotent and safe to call multiple times.
   */
  @Override
  public void close() {
    if (rebootClient != null) {
      rebootClient.onLostConnection(this);
    }
    if (foreverClient != null) {
      foreverClient.onLostConnection(this);
    }
    CloseSnapshot snapshot = prepareCloseSnapshot();
    if (snapshot == null) {
      return;
    }
    notifyLostRequests(snapshot.requests);
    unsubscribeAll(snapshot.subscriptions);
    if (!snapshot.duplicateKilled) {
      enqueueClientCleanup();
    }
    outputHandler.onClosed();
  }

  private CloseSnapshot prepareCloseSnapshot() {
    synchronized (this) {
      if (isClosed) {
        return null;
      }
      isClosed = true;
      ClientRequest[] requests = requestsByIdentifier.values().toArray(new ClientRequest[0]);
      requestsByIdentifier.clear();
      SubscribeUSK[] subscriptions = uskSubscriptions.values().toArray(new SubscribeUSK[0]);
      return new CloseSnapshot(requests, subscriptions, killedDupe);
    }
  }

  private void notifyLostRequests(ClientRequest[] requests) {
    for (ClientRequest request : requests) {
      request.onLostConnection(server.getCore().getClientContext());
    }
  }

  private void unsubscribeAll(SubscribeUSK[] subscriptions) {
    for (SubscribeUSK subscription : subscriptions) {
      subscription.unsubscribe();
    }
  }

  private void enqueueClientCleanup() {
    try {
      server
          .getCore()
          .getClientContext()
          .jobRunner
          .queue(
              (PersistentJob)
                  context -> {
                    if ((rebootClient != null) && !rebootClient.hasPersistentRequests()) {
                      server.unregisterClient(rebootClient);
                    }
                    if ((foreverClient != null) && !foreverClient.hasPersistentRequests()) {
                      server.unregisterClient(foreverClient);
                    }
                    return false;
                  },
              NativeThread.PriorityLevel.NORM_PRIORITY.value);
    } catch (PersistenceDisabledException _) {
      // Ignore: cleanup already best-effort.
    }
  }

  synchronized void setKilledDupe() {
    killedDupe = true;
  }

  /**
   * Indicates whether the handler has transitioned into the closed state, meaning it will reject
   * new requests and is in the process of unwinding outstanding work.
   *
   * <p>This synchronized check is inexpensive and safe to invoke from any thread; callers should
   * treat a {@code true} response as a signal that no further messages should be enqueued and that
   * socket-level operations are either complete or imminently shutting down.
   *
   * @return {@code true} once {@link #close()} has taken effect and the handler stops accepting new
   *     work, otherwise {@code false}.
   */
  public synchronized boolean isClosed() {
    return isClosed;
  }

  /**
   * Marks the input side of the socket as closed and, when both directions are drained, closes the
   * underlying socket.
   *
   * <p>Called by {@link FCPConnectionInputHandler} once it detects EOF or a fatal read error. The
   * method suppresses IOExceptions because they only indicate the peer has already disconnected.
   */
  public void closedInput() {
    try {
      sock.shutdownInput();
    } catch (IOException _) {
      // Ignore
    }
    synchronized (this) {
      inputClosed = true;
      if (!outputClosed) return;
    }
    try {
      sock.close();
    } catch (IOException _) {
      // Ignore
    }
  }

  /**
   * Marks the output side of the socket as closed and finalizes the connection once the input side
   * also shuts down.
   *
   * <p>Invoked by {@link FCPConnectionOutputHandler} when no further writes are possible. It
   * ensures {@link Socket#close()} happens once and tolerates IOExceptions from half-closed
   * sockets.
   */
  public void closedOutput() {
    try {
      sock.shutdownOutput();
    } catch (IOException _) {
      // Ignore
    }
    synchronized (this) {
      outputClosed = true;
      if (!inputClosed) return;
    }
    try {
      sock.close();
    } catch (IOException _) {
      // Ignore
    }
  }

  /**
   * Associates this connection with the supplied client name, wiring or creating the corresponding
   * persistent {@link PersistentRequestClient}s and replaying any queued messages.
   *
   * <p>The method registers reboot- and forever-scope clients on demand, kicks off asynchronous
   * replays of pending messages back to the peer, and caches the chosen name for diagnostics. It is
   * safe to call once per connection handshake before any request scheduling occurs.
   *
   * @param name Logical identifier supplied by the peer; should be non-null and consistent across
   *     reconnects to benefit from persistence.
   */
  public void setClientName(final String name) {
    this.clientName = name;
    rebootClient = server.registerRebootClient(name, this);
    rebootClient.queuePendingMessagesOnConnectionRestartAsync(
        outputHandler, server.getCore().getClientContext());
    // Create foreverClient lazily. Everything that needs it (especially creating ClientGet's etc.)
    // runs on a database job.
    if (LOG.isDebugEnabled()) LOG.debug("Set client name: {}", name);
    PersistentRequestClient client = server.getForeverClient(name, this);
    if (client != null) {
      synchronized (this) {
        foreverClient = client;
      }
      foreverClient.queuePendingMessagesOnConnectionRestartAsync(
          outputHandler, server.getCore().getClientContext());
    }
  }

  /**
   * Lazily creates or retrieves the forever-scope {@link PersistentRequestClient} associated with
   * the supplied name, ensuring only one instance exists per handler.
   *
   * <p>Synchronization occurs twice: initially to short-circuit when a client already exists and
   * again after registration so any waiters observing {@link #foreverClient} get notified. The
   * returned client immediately begins replaying pending messages on the current connection.
   *
   * @param name Identifier shared across reconnections so persistent requests remain addressable.
   * @return Initialized persistent client ready to accept forever-scope requests.
   */
  protected PersistentRequestClient createForeverClient(String name) {
    synchronized (FCPConnectionHandler.this) {
      if (foreverClient != null) return foreverClient;
    }
    PersistentRequestClient client = server.registerForeverClient(name, FCPConnectionHandler.this);
    synchronized (FCPConnectionHandler.this) {
      foreverClient = client;
      FCPConnectionHandler.this.notifyAll();
    }
    client.queuePendingMessagesOnConnectionRestartAsync(
        outputHandler, server.getCore().getClientContext());
    return foreverClient;
  }

  /**
   * Returns the client-supplied identifier previously registered through {@link
   * #setClientName(String)}.
   *
   * <p>The value may be {@code null} until the handshake completes, so callers should defensively
   * handle that case when logging or composing error messages. Once set, the name remains stable
   * for the connection and is used when looking up persistent request queues or plugin bridges.
   *
   * @return Current client name or {@code null} if the connection has not announced one.
   */
  public String getClientName() {
    return clientName;
  }

  /**
   * Starts a {@link ClientGet} according to the persistence requested by the peer, scheduling it
   * immediately for connection scope or deferring through the persistent job runner.
   *
   * <p>The method instantiates a {@link ClientGet}, attempts to register it under the provided
   * identifier, and handles collisions by sending {@link IdentifierCollisionMessage}s without
   * throwing back to the caller. FOREVER requests are enqueued on a background job so disk-backed
   * state can be opened safely, while reboot and connection scopes run inline.
   *
   * @param message Parsed {@code ClientGetMessage} received from the peer; must contain a unique
   *     identifier, persistence policy, and routing metadata.
   */
  public void startClientGet(final ClientGetMessage message) {
    switch (message.persistence) {
      case FOREVER:
        startForeverClientGet(message);
        break;
      case REBOOT:
        startRebootClientGet(message);
        break;
      case CONNECTION:
      default:
        startConnectionClientGet(message);
        break;
    }
  }

  private void startConnectionClientGet(ClientGetMessage message) {
    if (isClosed()) {
      return;
    }
    ClientGet request = buildClientGet(message);
    if (request == null) {
      return;
    }
    RegistrationResult registration = registerConnectionScopedRequest(message.identifier, request);
    if (registration == RegistrationResult.DUPLICATE) {
      request.freeData();
      handleIdentifierCollision(message.identifier, message.global);
      return;
    }
    if (registration == RegistrationResult.CLOSED) {
      request.freeData();
      return;
    }
    request.start(server.getCore().getClientContext());
  }

  private void startRebootClientGet(ClientGetMessage message) {
    ClientGet request = buildClientGet(message);
    if (request == null) {
      return;
    }
    if (!registerPersistentRequest(request, message.identifier, message.global)) {
      return;
    }
    request.start(server.getCore().getClientContext());
  }

  private void startForeverClientGet(ClientGetMessage message) {
    queuePersistentJob(
        context -> {
          ClientGet request = buildClientGet(message);
          if (request == null) {
            return false;
          }
          if (!registerPersistentRequest(request, message.identifier, message.global)) {
            request.freeData();
            return false;
          }
          request.start(context);
          return true;
        },
        message.identifier,
        message.global);
  }

  private ClientGet buildClientGet(ClientGetMessage message) {
    try {
      return new ClientGet(this, message, server.getCore());
    } catch (IdentifierCollisionException _) {
      handleIdentifierCollision(message.identifier, message.global);
    } catch (MessageInvalidException e) {
      sendProtocolError(e);
    }
    return null;
  }

  /**
   * Begins processing a {@link ClientPut} insert, validating compression descriptors, registering
   * the request under the desired persistence scope, and launching the actual insert on the proper
   * execution context.
   *
   * <p>Legacy LZMA usage triggers a one-time warning so operators know to update their codec list.
   * Requests scoped to FOREVER are dispatched through the persistent job runner to avoid blocking
   * the caller thread, while REBOOT and CONNECTION inserts start immediately. Identifier collisions
   * are resolved deterministically and never leak to the caller as exceptions.
   *
   * @param message Parsed {@code ClientPutMessage} describing the insert parameters, target key,
   *     and persistence choice supplied by the client.
   */
  public void startClientPut(final ClientPutMessage message) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("Starting insert ID=\"{}\"", message.identifier);
    }
    warnLegacyLzmaIfNeeded(
        message.compressorDescriptor, "ClientPut", message.identifier, message.clientToken);
    switch (message.persistence) {
      case FOREVER:
        startForeverClientPut(message);
        break;
      case REBOOT:
        startRebootClientPut(message);
        break;
      case CONNECTION:
      default:
        startConnectionClientPut(message);
        break;
    }
  }

  private void startConnectionClientPut(ClientPutMessage message) {
    if (isClosed()) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Connection is closed");
      }
      return;
    }
    ClientPut request = buildClientPut(message, true);
    if (request == null) {
      return;
    }
    RegistrationResult registration = registerConnectionScopedRequest(message.identifier, request);
    if (registration == RegistrationResult.DUPLICATE) {
      request.freeData();
      handleIdentifierCollision(message.identifier, message.global);
      return;
    }
    if (registration == RegistrationResult.CLOSED) {
      request.freeData();
      return;
    }
    request.start(server.getCore().getClientContext());
  }

  private void startRebootClientPut(ClientPutMessage message) {
    ClientPut request = buildClientPut(message, true);
    if (request == null) {
      return;
    }
    if (!registerPersistentRequest(request, message.identifier, message.global)) {
      request.freeData();
      return;
    }
    request.start(server.getCore().getClientContext());
  }

  private void startForeverClientPut(ClientPutMessage message) {
    queuePersistentJob(
        context -> {
          ClientPut request = buildClientPut(message, false);
          if (request == null) {
            return false;
          }
          if (!registerPersistentRequest(request, message.identifier, message.global)) {
            request.freeData();
            return false;
          }
          request.start(context);
          return true;
        },
        message.identifier,
        message.global);
  }

  /**
   * Initiates a directory insert, wiring each bucket of content into a {@link ClientPutDir} and
   * routing it through the requested persistence tier.
   *
   * <p>The handler optionally reuses disk-backed buckets when {@code wasDiskPut} is {@code true},
   * validates identifier uniqueness, and mirrors the same queuing semantics as {@link
   * #startClientPut(ClientPutMessage)}. Drops and collisions generate protocol errors rather than
   * unchecked exceptions.
   *
   * @param message Client-supplied directory insert descriptor referencing metadata and codecs.
   * @param buckets Map of bucket identifiers to either {@link network.crypta.support.api.Bucket}
   *     instances or literal data blobs that the insert will stream.
   * @param wasDiskPut {@code true} when the source content already resides on disk, allowing the
   *     insert to skip redundant buffering.
   */
  public void startClientPutDir(
      final ClientPutDirMessage message,
      final Map<String, Object> buckets,
      final boolean wasDiskPut) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("Start ClientPutDir");
    }
    warnLegacyLzmaIfNeeded(
        message.compressorDescriptor, "ClientPutDir", message.identifier, message.clientToken);
    switch (message.persistence) {
      case FOREVER:
        startForeverClientPutDir(message, buckets, wasDiskPut);
        break;
      case REBOOT:
        startRebootClientPutDir(message, buckets, wasDiskPut);
        break;
      case CONNECTION:
      default:
        startConnectionClientPutDir(message, buckets, wasDiskPut);
        break;
    }
  }

  private void startConnectionClientPutDir(
      ClientPutDirMessage message, Map<String, Object> buckets, boolean wasDiskPut) {
    if (isClosed()) {
      return;
    }
    ClientPutDir request = buildClientPutDir(message, buckets, wasDiskPut, true);
    if (request == null) {
      return;
    }
    RegistrationResult registration = registerConnectionScopedRequest(message.identifier, request);
    if (registration == RegistrationResult.DUPLICATE) {
      request.cancel(server.getCore().getClientContext());
      handleIdentifierCollision(message.identifier, message.global);
      return;
    }
    if (registration == RegistrationResult.CLOSED) {
      request.cancel(server.getCore().getClientContext());
      return;
    }
    request.start(server.getCore().getClientContext());
  }

  private void startRebootClientPutDir(
      ClientPutDirMessage message, Map<String, Object> buckets, boolean wasDiskPut) {
    ClientPutDir request = buildClientPutDir(message, buckets, wasDiskPut, true);
    if (request == null) {
      return;
    }
    if (!registerPersistentRequest(request, message.identifier, message.global)) {
      request.cancel(server.getCore().getClientContext());
      return;
    }
    request.start(server.getCore().getClientContext());
  }

  private void startForeverClientPutDir(
      ClientPutDirMessage message, Map<String, Object> buckets, boolean wasDiskPut) {
    queuePersistentJob(
        context -> {
          ClientPutDir request = buildClientPutDir(message, buckets, wasDiskPut, false);
          if (request == null) {
            return false;
          }
          if (!registerPersistentRequest(request, message.identifier, message.global)) {
            request.cancel(server.getCore().getClientContext());
            return false;
          }
          request.start(context);
          return true;
        },
        message.identifier,
        message.global);
  }

  private ClientPut buildClientPut(ClientPutMessage message, boolean includeErrorDetail) {
    try {
      return new ClientPut(this, message, server);
    } catch (IdentifierCollisionException _) {
      handleIdentifierCollision(message.identifier, message.global);
    } catch (MessageInvalidException e) {
      sendProtocolError(e);
    } catch (MalformedURLException e) {
      sendUriParseError(
          includeErrorDetail ? e.getMessage() : null, message.identifier, message.global);
    } catch (IOException e) {
      sendIoError(includeErrorDetail ? e.getMessage() : null, message.identifier, message.global);
    }
    message.freeData();
    return null;
  }

  private ClientPutDir buildClientPutDir(
      ClientPutDirMessage message,
      Map<String, Object> buckets,
      boolean wasDiskPut,
      boolean includeErrorDetail) {
    try {
      return new ClientPutDir(this, message, buckets, wasDiskPut, server);
    } catch (MalformedURLException e) {
      sendUriParseError(
          includeErrorDetail ? e.getMessage() : null, message.identifier, message.global);
    } catch (TooManyFilesInsertException _) {
      sendTooManyFilesError(message.identifier, message.global);
    }
    return null;
  }

  private RegistrationResult registerConnectionScopedRequest(
      String identifier, ClientRequest request) {
    synchronized (this) {
      if (isClosed) {
        return RegistrationResult.CLOSED;
      }
      if (requestsByIdentifier.containsKey(identifier)) {
        return RegistrationResult.DUPLICATE;
      }
      requestsByIdentifier.put(identifier, request);
      return RegistrationResult.REGISTERED;
    }
  }

  @SuppressWarnings("BooleanMethodIsAlwaysInverted")
  private boolean registerPersistentRequest(
      ClientRequest request, String identifier, boolean global) {
    try {
      request.register(false);
      return true;
    } catch (IdentifierCollisionException _) {
      handleIdentifierCollision(identifier, global);
      return false;
    }
  }

  private void handleIdentifierCollision(String identifier, boolean global) {
    LOG.info(COLLISION_LOG_TEMPLATE, this);
    send(new IdentifierCollisionMessage(identifier, global));
  }

  private void sendPersistenceDisabled(String identifier, boolean global) {
    send(
        new ProtocolErrorMessage(
            ProtocolErrorMessage.PERSISTENCE_DISABLED,
            false,
            PERSISTENCE_DISABLED_TEXT,
            identifier,
            global));
  }

  private void sendProtocolError(MessageInvalidException e) {
    send(new ProtocolErrorMessage(e.protocolCode, false, e.getMessage(), e.ident, e.global));
  }

  private void sendUriParseError(String detail, String identifier, boolean global) {
    send(
        new ProtocolErrorMessage(
            ProtocolErrorMessage.FREENET_URI_PARSE_ERROR, true, detail, identifier, global));
  }

  private void sendIoError(String detail, String identifier, boolean global) {
    send(new ProtocolErrorMessage(ProtocolErrorMessage.IO_ERROR, true, detail, identifier, global));
  }

  private void sendTooManyFilesError(String identifier, boolean global) {
    send(
        new ProtocolErrorMessage(
            ProtocolErrorMessage.TOO_MANY_FILES_IN_INSERT, true, null, identifier, global));
  }

  private void queuePersistentJob(PersistentJob job, String identifier, boolean global) {
    try {
      server
          .getCore()
          .getClientContext()
          .jobRunner
          .queue(job, NativeThread.PriorityLevel.HIGH_PRIORITY.value - 1);
    } catch (PersistenceDisabledException _) {
      sendPersistenceDisabled(identifier, global);
    }
  }

  private boolean containsLegacyLzma(String descriptor) {
    if (descriptor == null || descriptor.isBlank()) {
      return false;
    }
    String[] tokens = descriptor.split(",");
    for (String token : tokens) {
      if ("LZMA".equalsIgnoreCase(token.trim())) {
        return true;
      }
    }
    return false;
  }

  private void warnLegacyLzmaIfNeeded(
      String descriptor, String requestKind, String identifier, String clientToken) {
    if (!containsLegacyLzma(descriptor)) {
      return;
    }
    if (!warnedLegacyLzma.compareAndSet(false, true)) {
      return;
    }
    Socket socket = getSocket();
    Object remote = (socket != null) ? socket.getRemoteSocketAddress() : "unknown";
    LOG.warn(
        "FCP {} uses legacy LZMA in Codecs; advise {} instead. id={}, token={}, client={},"
            + " remote={}",
        requestKind,
        LEGACY_LZMA_REPLACEMENT,
        identifier,
        clientToken,
        getClientName(),
        remote);
  }

  /**
   * Returns the reboot-scope {@link PersistentRequestClient} backing this connection, creating it
   * lazily when {@link #setClientName(String)} is first invoked.
   *
   * <p>Reboot clients persist on disk between node restarts but are scoped per client name. This
   * accessor allows callers to query or manipulate persistent state without repeating registration
   * logic; however, it can return {@code null} prior to the initial handshake completing.
   *
   * @return Persistent client that survives node restarts but not manual deletion; may be {@code
   *     null} until a client name is registered.
   */
  public PersistentRequestClient getRebootClient() {
    return rebootClient;
  }

  /**
   * @return The {@link FCPPluginConnection} for the given serverPluginName. Atomically creates and
   *     stores it if there does not exist one yet. This ensures that for each FCPConnectionHandler,
   *     there can be only one {@link FCPPluginConnection} for a given serverPluginName.
   * @throws PluginNotFoundException If the specified plugin is not loaded or does not provide an
   *     FCP server.
   */
  FCPPluginConnection getFCPPluginConnection(String serverPluginName)
      throws PluginNotFoundException {
    return pluginConnectionRegistry.get(serverPluginName, server, this);
  }

  /**
   * Provides access to this handler's forever-scope {@link PersistentRequestClient}, instantiating
   * it if necessary so new inserts can reuse previously stored state.
   *
   * <p>Forever clients live across reboots and reconnections, so this accessor synchronizes and, if
   * needed, invokes {@link #createForeverClient(String)} to populate {@link #foreverClient}. The
   * returned instance queues pending messages back to the output handler automatically.
   *
   * @return Non-null persistent client once the connection has an assigned name; the reference is
   *     cached for subsequent calls.
   */
  public PersistentRequestClient getForeverClient() {
    synchronized (this) {
      if (foreverClient == null) {
        foreverClient = createForeverClient(clientName);
      }
      return foreverClient;
    }
  }

  /**
   * Removes the supplied {@link ClientRequest} from the connection-scoped registry once it has
   * completed, freeing the identifier for reuse.
   *
   * <p>Callers should invoke this exactly once per request completion path so the handler can
   * detect future identifier collisions accurately.
   *
   * @param get Request that triggered a completion callback; must not be {@code null}.
   */
  public void finishedClientRequest(ClientRequest get) {
    synchronized (this) {
      requestsByIdentifier.remove(get.getIdentifier());
    }
  }

  /**
   * Reports whether the reboot-scope persistent client currently watches the global queue, meaning
   * it receives broadcasts rather than only this connection's identifiers.
   *
   * <p>This is primarily surfaced for diagnostics and tests so they can assert that a connection is
   * subscribed before sending synthetic updates.
   *
   * @return {@code true} when {@link #rebootClient} is configured for global traffic, otherwise
   *     {@code false}. Primarily used by diagnostic commands.
   */
  @SuppressWarnings("unused")
  public boolean isGlobalSubscribed() {
    return rebootClient.watchGlobal;
  }

  /**
   * Evaluates whether the remote socket is included in the server's full-access host list, allowing
   * privileged DDA operations and unrestricted commands.
   *
   * <p>This check delegates to {@link network.crypta.io.AllowedHosts#allowed(java.net.InetAddress)}
   * so allowlist changes take effect immediately without restarting the connection.
   *
   * @return {@code true} when the peer's IP matches the configured full-access mask.
   */
  public boolean hasFullAccess() {
    return server.allowedHostsFullAccess.allowed(sock.getInetAddress());
  }

  /**
   * Records the outcome of a DDA test initiated by {@code TestDdaCompleteMessage}, allowing the
   * access controller to short-circuit future checks on the same path.
   *
   * <p>Only test harnesses should call this; production paths learn results through {@link
   * #enqueueDDACheck(String, boolean, boolean)}.
   *
   * @param path Absolute or canonical path that was probed during the DDA test.
   * @param read {@code true} when read permissions were confirmed for {@code path}.
   * @param write {@code true} when write permissions were confirmed for {@code path}.
   */
  protected void registerTestDDAResult(String path, boolean read, boolean write) {
    ddaAccessController.registerTestDDAResult(path, read, write);
  }

  /**
   * Registers a deferred direct-disk-access (DDA) permission check for the supplied path and
   * returns the job handle that was queued.
   *
   * <p>Callers typically invoke this before asking the peer for confirmation so the eventual
   * acknowledgement can resume the request. Each job tracks whether read and/or write permissions
   * need confirmation and records temporary files that must later be deleted via {@link
   * #freeDDAJobs()}.
   *
   * @param path Canonical path whose permissions need to be verified; must pass safety validation.
   * @param read {@code true} to test read capability; {@code false} skips read probing.
   * @param write {@code true} to test write capability; {@code false} keeps the check read-only.
   * @return Non-null {@link DdaCheckJob} enqueued on the controller, representing the pending work.
   * @throws IllegalArgumentException If the path falls outside allowed roots or violates validation
   *     constraints enforced by {@link DdaAccessController}.
   */
  protected DdaCheckJob enqueueDDACheck(String path, boolean read, boolean write)
      throws IllegalArgumentException {
    return ddaAccessController.enqueueDDACheck(path, read, write);
  }

  /**
   * Retrieves and removes the pending DDA check for the specified path if one exists.
   *
   * <p>This is typically called once the peer has responded so we can resume the original request
   * using the recorded permissions.
   *
   * @param path Path originally used to queue the DDA job; must match exactly.
   * @return Matching {@link DdaCheckJob} if it remains queued; {@code null} otherwise.
   * @throws IllegalArgumentException If the path fails validation or the controller rejects it.
   */
  protected DdaCheckJob popDDACheck(String path) throws IllegalArgumentException {
    return ddaAccessController.popDDACheck(path);
  }

  /**
   * Deletes any temporary files left behind by outstanding DDA tests and clears the tracking
   * structures so the handler can be safely closed or recycled between reconnects.
   *
   * <p>Invoke this after the peer completes DDA verification or when the handler disconnects so
   * background checks do not leak disk state.
   */
  protected void freeDDAJobs() {
    ddaAccessController.freeDDAJobs();
  }

  /**
   * Removes and optionally cancels the {@link ClientRequest} currently registered under the given
   * identifier.
   *
   * <p>If {@code kill} is {@code true}, the request receives a cancel callback before the handler
   * notifies it about removal, which lets callers align cleanup with de-registration.
   *
   * @param identifier Unique token previously provided by the client; must not be {@code null}.
   * @param kill {@code true} to cancel the request before removal, {@code false} otherwise.
   * @return Removed request or {@code null} when no matching identifier was registered.
   */
  public ClientRequest removeRequestByIdentifier(String identifier, boolean kill) {
    ClientRequest req;
    synchronized (this) {
      req = requestsByIdentifier.remove(identifier);
    }
    if (req != null) {
      if (kill) req.cancel(server.getCore().getClientContext());
      req.requestWasRemoved(server.getCore().getClientContext());
    }
    return req;
  }

  ClientRequest getRebootRequest(boolean global, FCPConnectionHandler handler, String identifier) {
    if (global) return handler.getServer().getGlobalRebootClient().getRequest(identifier);
    else return handler.getRebootClient().getRequest(identifier);
  }

  ClientRequest getForeverRequest(boolean global, FCPConnectionHandler handler, String identifier) {
    if (global) return handler.getServer().getGlobalForeverClient().getRequest(identifier);
    else return handler.getForeverClient().getRequest(identifier);
  }

  ClientRequest removePersistentRebootRequest(boolean global, String identifier) {
    PersistentRequestClient client = global ? server.getGlobalRebootClient() : getRebootClient();
    ClientRequest req = client.getRequest(identifier);
    if (req != null) {
      client.removeByIdentifier(identifier, true, server, server.getCore().getClientContext());
    }
    return req;
  }

  ClientRequest removePersistentForeverRequest(boolean global, String identifier) {
    PersistentRequestClient client = global ? server.getGlobalForeverClient() : getForeverClient();
    ClientRequest req = client.getRequest(identifier);
    if (req != null) {
      client.removeByIdentifier(identifier, true, server, server.getCore().getClientContext());
    }
    return req;
  }

  /**
   * Registers a {@link SubscribeUSK} under the provided identifier, enforcing uniqueness across the
   * connection.
   *
   * <p>The subscription map is guarded by this handler's monitor so concurrent add/remove
   * operations stay consistent even when clients open many subscriptions at once.
   *
   * @param identifier Token supplied by the client to track the subscription lifecycle.
   * @param subscribeUSK Subscription wrapper coordinating callbacks to the requester.
   * @throws IdentifierCollisionException If another subscription already uses the same identifier.
   */
  public synchronized void addUSKSubscription(String identifier, SubscribeUSK subscribeUSK)
      throws IdentifierCollisionException {
    if (uskSubscriptions.containsKey(identifier)) throw new IdentifierCollisionException();
    uskSubscriptions.put(identifier, subscribeUSK);
  }

  /**
   * Cancels the USK subscription bound to the supplied identifier and notifies the subscription of
   * the change.
   *
   * <p>The removal is synchronized with {@link #addUSKSubscription(String, SubscribeUSK)} so no
   * updates race while the unsubscribe runs.
   *
   * @param identifier Subscription token previously registered via {@link
   *     #addUSKSubscription(String, SubscribeUSK)}.
   * @throws MessageInvalidException If no subscription exists for the identifier.
   */
  public void unsubscribeUSK(String identifier) throws MessageInvalidException {
    SubscribeUSK sub;
    synchronized (this) {
      sub = uskSubscriptions.remove(identifier);
      if (sub == null)
        throw new MessageInvalidException(
            ProtocolErrorMessage.NO_SUCH_IDENTIFIER,
            "No such identifier unsubscribing",
            identifier,
            false);
    }
    sub.unsubscribe();
  }

  /**
   * Returns the connection-scoped {@link RequestClient} tuned either for realtime or bulk
   * scheduling, depending on the caller's hint.
   *
   * <p>Realtime clients minimize latency and skip batching, whereas bulk clients favor throughput
   * and larger queues. The choice affects how requests compete for resources on the node.
   *
   * @param realTime {@code true} for low-latency handling, {@code false} for throughput-optimized
   *     handling.
   * @return Either {@link #connectionRequestClientRT} or {@link #connectionRequestClientBulk}.
   */
  public RequestClient connectionRequestClient(boolean realTime) {
    if (realTime) return connectionRequestClientRT;
    else return connectionRequestClientBulk;
  }

  /**
   * Returns the owning {@link FCPServer} used to look up persistent clients and configuration.
   *
   * <p>APIs outside the handler often need this pointer to access the global client context or
   * shared job runners, so exposing it avoids tightly coupling helper classes to the handler.
   *
   * @return Non-null server reference that created this handler.
   */
  public FCPServer getServer() {
    return server;
  }

  /**
   * Provides the underlying {@link Socket} used for network IO so auxiliary routines can inspect it
   * for diagnostics.
   *
   * <p>The caller must not close the socket directly; use {@link #close()} so the handler can wind
   * down gracefully.
   *
   * @return Socket passed during construction; may be {@code null} if the connection is torn down.
   */
  public Socket getSocket() {
    return sock;
  }

  /**
   * Returns the {@link FCPConnectionOutputHandler} responsible for serializing outbound messages.
   *
   * <p>External helpers use this to enqueue protocol responses or flush pending data when
   * performing maintenance operations.
   *
   * @return Non-null output handler that was instantiated alongside this connection.
   */
  public FCPConnectionOutputHandler getOutputHandler() {
    return outputHandler;
  }
}
