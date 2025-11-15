package network.crypta.clients.fcp;

import java.io.IOException;
import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
import java.util.EnumMap;
import java.util.Objects;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import network.crypta.clients.fcp.FCPPluginMessage.ClientPermissions;
import network.crypta.node.NodeStarter;
import network.crypta.node.PrioRunnable;
import network.crypta.pluginmanager.FredPluginFCPMessageHandler;
import network.crypta.pluginmanager.FredPluginFCPMessageHandler.ClientSideFCPMessageHandler;
import network.crypta.pluginmanager.FredPluginFCPMessageHandler.PrioritizedMessageHandler;
import network.crypta.pluginmanager.FredPluginFCPMessageHandler.ServerSideFCPMessageHandler;
import network.crypta.pluginmanager.PluginManager;
import network.crypta.pluginmanager.PluginNotFoundException;
import network.crypta.pluginmanager.PluginRespirator;
import network.crypta.support.PooledExecutor;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.io.NativeThread;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implements {@link FCPPluginConnection} for both networked and intra-node plugin interactions,
 * providing routing, lifecycle tracking, and synchronous reply coordination.
 *
 * <p>The implementation bridges {@link FCPConnectionHandler} instances, plugin-side handlers, and
 * {@link PriorityAwareExecutor} workers so that plugins can exchange {@link FCPPluginMessage}
 * objects with strict ordering guarantees. Each connection keeps weak references to plugins where
 * required, and callers are expected to obtain {@link DefaultSendDirectionAdapter} instances via
 * {@link #getDefaultSendDirectionAdapter(SendDirection)} instead of storing a raw connection. That
 * indirection prevents leaking strong references, which would break garbage-collection-based
 * disconnect detection.
 *
 * <p>Internally the class maintains synchronized maps of outstanding synchronous calls, guards
 * every wait with a timeout, and turns handler failures into structured {@code InternalError}
 * replies so dispatcher threads never die silently. Send paths accept both remote clients (messages
 * arrive via {@link FCPPluginClientMessage} from {@link FCPServer}) and intra-node clients (bound
 * through {@link PluginRespirator}). Regardless of origin, messages ultimately reach {@link
 * ServerSideFCPMessageHandler#handlePluginFCPMessage(FCPPluginConnection, FCPPluginMessage)}.
 *
 * <p>Key behaviors that plugin developers should remember:
 *
 * <ul>
 *   <li>Always call {@link #getDefaultSendDirectionAdapter(SendDirection)} and interact with the
 *       adapter, otherwise direction-less sends throw immediately and the tracker cannot reclaim
 *       the connection.
 *   <li>Synchronous waits are expensive; prefer asynchronous handlers when possible, and use
 *       generous timeouts that reflect remote workload.
 *   <li>The connection UUID is stable for the lifetime of the transport and can be cached by
 *       servers to send unsolicited replies via {@link
 *       PluginRespirator#getPluginConnectionByID(UUID)}.
 * </ul>
 *
 * <p>The remainder of this file documents the dispatcher paths so maintainers can reason about
 * prioritization, failure handling, and GC-triggered disconnects.
 */
final class FCPPluginConnectionImpl implements FCPPluginConnection {
  private static final Logger LOG = LoggerFactory.getLogger(FCPPluginConnectionImpl.class);

  /**
   * Unique identifier among all {@link FCPPluginConnection}s.
   *
   * @see #getID()
   */
  private final UUID id = UUID.randomUUID();

  /**
   * Executor upon which we run threads of the send functions.<br>
   * Since the send functions can be called very often, it would be inefficient to create a new
   * {@link Thread} for each one. An {@link PriorityAwareExecutor} prevents this by having a pool of
   * Threads which will be recycled.
   */
  private final PriorityAwareExecutor executor;

  /** The class name of the plugin to which this FCPPluginConnectionImpl is connected. */
  private final String serverPluginName;

  /**
   * The FCP server plugin to which this connection is connected.
   *
   * <p>Design note: Monitor this with a {@link ReferenceQueue} and if it becomes nulled, remove
   * this FCPPluginConnectionImpl from the internal {@code pluginConnectionsByServerName} map held
   * by {@link FCPConnectionHandler}.<br>
   * Currently, it seems not necessary:<br>
   * - It can only become null if the server plugin is unloaded / reloaded. Plugin unloading /
   * reloading requires user interaction or auto update and shouldn't happen frequently.<br>
   * - It would only leak one WeakReference per plugin per client network connection. That won't be
   * much until we have very many network connections. The memory usage of having one thread per
   * {@link FCPConnectionHandler} to monitor the ReferenceQueue would probably outweigh the savings.
   * <br>
   * - We already opportunistically clean the table at FCPConnectionHandler: If the client
   * application which is behind the {@link FCPConnectionHandler} tries to send a message using a
   * FCPPluginConnectionImpl whose server WeakReference is null, it is purged from the said table at
   * FCPConnectionHandler. So memory will not leak as long as the clients keep trying to send
   * messages to the nulled server plugin - which they probably will do because they did already in
   * the past.<br>
   * NOTICE: If you do implement this, make sure to not rewrite the ReferenceQueue polling thread
   * but instead base it upon {@link FCPPluginConnectionTracker}. You should probably extract a
   * generic class WeakValueMap from that one and use it to power both the existing class and the
   * one which deals with this variable here.<br>
   * Also, once you've implemented ReferenceQueue monitoring, remove {@link #isServerDead()} as it
   * only was added for the opportunistic cleaning due to lack of a ReferenceQueue and is an ugly
   * function besides that.
   *
   * @see #isServerDead() Use isServerDead() to check whether this WeakReference is nulled.
   */
  private final WeakReference<ServerSideFCPMessageHandler> server;

  /**
   * For intra-node plugin connections, this is the connecting client. For networked plugin
   * connections, this is null.
   */
  private final ClientSideFCPMessageHandler client;

  /**
   * For networked plugin connections, this is the network connection to which this
   * FCPPluginConnectionImpl belongs. For intra-node connections to plugins, this is null. For each
   * {@link FCPConnectionHandler}, there can only be one FCPPluginConnectionImpl for each {@link
   * #serverPluginName}.
   */
  private final FCPConnectionHandler clientConnection;

  /**
   * @see FCPPluginConnectionImpl#synchronousSends An overview of how synchronous sends and
   *     especially their threading work internally is provided at the map which stores them.
   */
  private static final class SynchronousSend {
    /**
     * {@link FCPPluginConnectionImpl#send(SendDirection, FCPPluginMessage)} shall call {@link
     * Condition#signal()} upon this once the reply message has been stored to {@link #reply} to
     * wake up the sleeping {@link FCPPluginConnectionImpl#sendSynchronous( SendDirection,
     * FCPPluginMessage, long)} thread which is waiting for the reply to arrive.
     */
    private final Condition completionSignal;

    private FCPPluginMessage reply;

    public SynchronousSend(Condition completionSignal) {
      this.completionSignal = completionSignal;
    }
  }

  /**
   * For each message sent with the <i>blocking</i> send function {@link
   * #sendSynchronous(SendDirection, FCPPluginMessage, long)} this contains a {@link
   * SynchronousSend} object which shall be used to signal the completion of the synchronous send to
   * the blocking sendSynchronous() thread. Signaling the completion tells the blocking
   * sendSynchronous() function that the remote side has sent a reply message to acknowledge that
   * the original message was processed and sendSynchronous() may return now. In addition, the reply
   * is added to the SynchronousSend object so that sendSynchronous() can return it to the caller.
   * <br>
   * <br>
   * The key is the identifier {@link FCPPluginMessage#identifier} of the original message which was
   * sent by sendSynchronous().<br>
   * <br>
   * An entry shall be added by sendSynchronous() when a new synchronous send is started, and then
   * it shall wait for the Condition {@link SynchronousSend#completionSignal} to be signaled.<br>
   * When the reply message is received, the node will always dispatch it via {@link
   * #send(SendDirection, FCPPluginMessage)}. Thus, that function is obliged to check this map for
   * whether there is an entry for each received reply. If it contains a SynchronousSend for the
   * identifier of a given reply, send() shall store the reply message in it, and then call {@link
   * Condition#signal()} upon the SynchronousSend's Condition to cause the blocking
   * sendSynchronous() function to return.<br>
   * The sendSynchronous() shall take the job of removing the entry from this map.<br>
   * <br>
   * Thread safety is to be guaranteed by the {@link #synchronousSendsLock}.<br>
   * <br>
   * When implementing the mechanisms which use this map, please be aware of the fact that bogus
   * remote implementations could:<br>
   * - Not sent a reply message at all, even though they should. This shall be compensated by
   * sendSynchronous() always specifying a timeout when waiting upon the Conditions.<br>
   * - Send <i>multiple</i> reply messages for the same identifier even though they should only send
   * one. This probably won't matter though:<br>
   * * The first arriving reply will complete the matching sendSynchronous() call.<br>
   * * Any subsequent replies will not find a matching entry in this table, which is the same
   * situation as if the reply was to a <i>non</i>-synchronous send. Non-synchronous sends are a
   * normal thing, and thus handling their replies is implemented. It will cause the reply to be
   * shipped to the message handler interface of the server/client instead of being returned by
   * sendSynchronous() though, which could confuse it. But in that case it will probably just log an
   * error message and continue working as normal. <br>
   * <br>
   * Design note: We do not need the order of the map, and thus this could be a HashMap instead of a
   * TreeMap. We do not use a HashMap for scalability: Java HashMaps never shrink, they only grow.
   * As we cannot predict how much parallel synchronous sends server/client implementations will
   * run, we do need a shrinking map. So we use TreeMap until we have an automatically shrinking
   * HashMap. This is also documented <a href="https://bugs.freenetproject.org/view.php?id=6320">in
   * the bugtracker</a>.
   */
  private final TreeMap<String, SynchronousSend> synchronousSends = new TreeMap<>();

  /**
   * Shall be used to ensure thread-safety of {@link #synchronousSends}. <br>
   * (Please read its JavaDoc before continuing to read this JavaDoc: It explains the mechanism of
   * synchronous sends, and it is assumed that you understand it in what follows here.)<br>
   * <br>
   * It is a {@link ReadWriteLock} because synchronous sends shall by design be used infrequently,
   * and thus there will be more reads checking for an existing synchronous send than writes to
   * terminate one. (It is a {@link ReentrantReadWriteLock} because that is currently the only
   * implementation of ReadWriteLock, the re-entrancy is probably not needed by the actual code.)
   */
  private final ReadWriteLock synchronousSendsLock = new ReentrantReadWriteLock();

  /**
   * A {@link DefaultSendDirectionAdapter} is an adapter which encapsulates a
   * FCPPluginConnectionImpl object with a default {@link SendDirection} to implement the send
   * functions which don't require a direction parameter:<br>
   * - {@link FCPPluginConnection#send(FCPPluginMessage)}<br>
   * - {@link FCPPluginConnection#sendSynchronous(FCPPluginMessage, long)}<br>
   * <br>
   * For each possible {@link SendDirection}, this map keeps the responsible adapter.
   */
  private final EnumMap<SendDirection, DefaultSendDirectionAdapter> defaultSendDirectionAdapters =
      new EnumMap<>(SendDirection.class);

  /**
   * Creates an implementation for the case where the server plugin executes inside the node and the
   * client communicates over the network via {@link FCPConnectionHandler}.
   *
   * <p>The constructor wires the executor, stores the weak reference to the {@link
   * ServerSideFCPMessageHandler}, registers the connection with the tracker—notably before creating
   * the client adapter—and attaches the inbound {@link FCPConnectionHandler}. Public callers should
   * prefer {@link #constructForNetworkedFCP(FCPPluginConnectionTracker, PriorityAwareExecutor,
   * PluginManager, String, FCPConnectionHandler)} so registration and validation remain consistent.
   *
   * @param tracker tracker responsible for garbage-collection-based disconnect detection
   * @param executor shared executor on which handler calls run with priority awareness
   * @param serverPluginName human-readable server identifier that appears in logs
   * @param serverPlugin concrete server-side handler that consumes the routed messages
   * @param clientConnection inbound handler bound to the network socket for this client
   */
  private FCPPluginConnectionImpl(
      FCPPluginConnectionTracker tracker,
      PriorityAwareExecutor executor,
      String serverPluginName,
      ServerSideFCPMessageHandler serverPlugin,
      FCPConnectionHandler clientConnection) {

    assert (tracker != null);
    assert (executor != null);
    assert (serverPlugin != null);
    assert (serverPluginName != null);
    assert (clientConnection != null);

    this.executor = executor;
    this.serverPluginName = serverPluginName;
    this.server = new WeakReference<>(serverPlugin);
    this.client = null;
    this.clientConnection = clientConnection;
    this.defaultSendDirectionAdapters.put(SendDirection.TO_SERVER, new SendToServerAdapter(this));
    // new SendToClientAdapter() will need to query this connection from the tracker already.
    // Thus, we have to register before constructing it.
    tracker.registerConnection(this);
    this.defaultSendDirectionAdapters.put(
        SendDirection.TO_CLIENT, new SendToClientAdapter(tracker, id));
  }

  /**
   * Factory for networked FCP conversations where the server stays local and the client connects
   * through {@link FCPConnectionHandler}.
   *
   * <p>The method locates the server plug-in via {@link PluginManager}, registers the resulting
   * connection with the tracker, and returns an instance whose default direction adapters can be
   * given to plugins. Always hand out adapters rather than this raw instance so GC-based disconnect
   * logic remains effective.
   *
   * @param tracker tracker that observes created connections and provides GC notifications
   * @param executor execution pool shared by plugin dispatchers, honoring {@link
   *     PrioritizedMessageHandler} hints
   * @param serverPluginManager plugin registry used to look up the server-side handler
   * @param serverPluginName canonical server identifier passed to the plugin manager
   * @param clientConnection network-side handler representing the remote client
   * @return fully initialized connection ready for adapter exposure
   * @throws PluginNotFoundException if the requested server plug-in is not loaded or lacks an FCP
   *     handler
   */
  static FCPPluginConnectionImpl constructForNetworkedFCP(
      FCPPluginConnectionTracker tracker,
      PriorityAwareExecutor executor,
      PluginManager serverPluginManager,
      String serverPluginName,
      FCPConnectionHandler clientConnection)
      throws PluginNotFoundException {

    assert (tracker != null);
    assert (executor != null);
    assert (serverPluginManager != null);
    assert (serverPluginName != null);
    assert (clientConnection != null);

    return new FCPPluginConnectionImpl(
        tracker,
        executor,
        serverPluginName,
        serverPluginManager.getPluginFCPServer(serverPluginName),
        clientConnection);
  }

  /**
   * Creates an implementation for intra-node connections where both sides execute inside the same
   * JVM and expose handler interfaces directly.
   *
   * <p>This variant stores both handler references strongly, registers the connection before
   * building the {@link SendToClientAdapter}, and omits any {@link FCPConnectionHandler} because
   * the client lives in-process. The tracker registration ensures GC monitoring is active from the
   * moment the connection exists.
   *
   * @param tracker tracker responsible for monitoring connection lifetimes
   * @param executor executor pool powering message dispatch
   * @param serverPluginName canonical server identifier used for logging and lookups
   * @param server concrete server-side handler implementation
   * @param client concrete client-side handler implementation
   */
  private FCPPluginConnectionImpl(
      FCPPluginConnectionTracker tracker,
      PriorityAwareExecutor executor,
      String serverPluginName,
      ServerSideFCPMessageHandler server,
      ClientSideFCPMessageHandler client) {

    assert (tracker != null);
    assert (executor != null);
    assert (serverPluginName != null);
    assert (server != null);
    assert (client != null);

    this.executor = executor;
    this.serverPluginName = serverPluginName;
    this.server = new WeakReference<>(server);
    this.client = client;
    this.clientConnection = null;
    this.defaultSendDirectionAdapters.put(SendDirection.TO_SERVER, new SendToServerAdapter(this));
    // new SendToClientAdapter() will need to query this connection from the tracker already.
    // Thus, we have to register before constructing it.
    tracker.registerConnection(this);
    this.defaultSendDirectionAdapters.put(
        SendDirection.TO_CLIENT, new SendToClientAdapter(tracker, id));
  }

  /**
   * Factory for intra-node plug-in conversations where both handlers run inside the same JVM.
   *
   * <p>The method looks up the server from the {@link PluginManager}, registers the connection with
   * the tracker, and returns an instance whose adapters can safely be handed to plugins. Default
   * direction adapters should again be used instead of exposing the raw connection to avoid strong
   * references leaking beyond the tracker.
   *
   * @param tracker tracker that keeps weak references and observes garbage-collection events
   * @param executor executor powering message dispatch threads
   * @param serverPluginManager plugin registry that exposes server handlers
   * @param serverPluginName canonical server name used for lookups and logging
   * @param client client-side handler owned by the requesting plug-in
   * @return initialized connection with adapters for both directions
   * @throws PluginNotFoundException if the requested server plug-in cannot be resolved
   */
  static FCPPluginConnectionImpl constructForIntraNodeFCP(
      FCPPluginConnectionTracker tracker,
      PriorityAwareExecutor executor,
      PluginManager serverPluginManager,
      String serverPluginName,
      ClientSideFCPMessageHandler client)
      throws PluginNotFoundException {

    assert (executor != null);
    assert (serverPluginManager != null);
    assert (serverPluginName != null);
    assert (client != null);

    return new FCPPluginConnectionImpl(
        tracker,
        executor,
        serverPluginName,
        serverPluginManager.getPluginFCPServer(serverPluginName),
        client);
  }

  /**
   * Creates a lightweight connection pair for unit tests where both handlers are supplied directly.
   *
   * <p>The helper mirrors an intra-node setup: both handlers run in-process, the tracker is started
   * automatically, and a {@link PooledExecutor} provides the necessary threading. It does
   * <em>not</em> instantiate a {@link PluginRespirator}, so code that depends on {@link
   * PluginRespirator#getPluginConnectionByID(UUID)} should instead spin up a full {@link
   * NodeStarter#createTestNode(NodeStarter.TestNodeParameters)} instance to exercise the same code
   * paths as production.
   *
   * @param server server-side handler implementation under test
   * @param client client-side handler used to capture replies inside the unit test
   * @return connection wired to the supplied handlers and backed by a fresh tracker
   */
  public static FCPPluginConnectionImpl constructForUnitTest(
      ServerSideFCPMessageHandler server, ClientSideFCPMessageHandler client) {

    Objects.requireNonNull(server, "server");
    Objects.requireNonNull(client, "client");
    FCPPluginConnectionTracker tracker = new FCPPluginConnectionTracker();
    tracker.start();
    return new FCPPluginConnectionImpl(
        tracker, new PooledExecutor(), server.toString(), server, client);
  }

  /**
   * Returns the stable UUID assigned to this connection when it was created.
   *
   * <p>The identifier remains valid for the lifetime of the transport and is used by {@link
   * PluginRespirator#getPluginConnectionByID(UUID)} so plugins can send unsolicited messages later.
   * Treat it as opaque; callers should not attempt to parse any structure from the UUID.
   *
   * @return immutable identifier unique among all live {@link FCPPluginConnection} instances
   */
  @Override
  public UUID getID() {
    return id;
  }

  /**
   * ATTENTION: Only for internal use in {@link FCPConnectionHandler#getFCPPluginConnection(
   * String)}.<br>
   * Server / client code should instead always send messages, for example via {@link
   * #send(SendDirection, FCPPluginMessage)}, to check whether the connection is alive. This is to
   * ensure that the implementation of this class could safely be changed to allow the server to be
   * attached by network instead of always running locally in the same node as it currently is. Also
   * see below.<br>
   *
   * @return
   *     <p>True if the server plugin has been unloaded. Once this returns true, this
   *     FCPPluginConnectionImpl <b>cannot</b> be repaired, even if the server plugin is loaded
   *     again. Then you should discard this connection and create a fresh one.
   *     <p><b>ATTENTION:</b> Future implementations of {@link FCPPluginConnection} might allow the
   *     server plugin to reside in a different node, and only be attached by network. Due to the
   *     unreliability of network connections, then this function will not be able to reliably
   *     detect whether the server is dead.<br>
   *     To prepare for that, you <b>must not</b> assume that the connection to the server is still
   *     fine just because this returns false = server is alive. Consider false / server is alive
   *     merely an indication, true / server is dead as the definite truth.<br>
   *     If you need to validate a connection to be alive, send periodic pings.
   */
  boolean isServerDead() {
    return server.get() == null;
  }

  /**
   * @return The permission level of the client, depending on things such as its IP address.<br>
   *     For intra-node connections, it is {@link ClientPermissions#ACCESS_DIRECT}.<br>
   *     <br>
   *     <b>ATTENTION:</b> The return value can change at any point in time, so you should check
   *     this before deploying each FCP message.<br>
   *     This is because the user is free to reconfigure IP-address restrictions on the node's web
   *     interface whenever he wants to.
   */
  private ClientPermissions getCurrentClientPermissions() {
    if (clientConnection != null) { // Networked FCP
      return clientConnection.hasFullAccess()
          ? ClientPermissions.ACCESS_FCP_FULL
          : ClientPermissions.ACCESS_FCP_RESTRICTED;
    } else { // Intra-node FCP
      assert (client != null);
      return ClientPermissions.ACCESS_DIRECT;
    }
  }

  /**
   * Sends a message in the specified direction without waiting for a reply.
   *
   * <p>The method stamps the correct {@link ClientPermissions}, pushes the payload onto either the
   * network connection or the local handler, and logs a warning if callers attempt to reuse the
   * same {@link FCPPluginMessage} instance twice. It is safe to invoke concurrently from multiple
   * threads; prioritization is determined by {@link PrioritizedMessageHandler} implementations.
   *
   * @param direction direction to deliver the message; determines which adapter or connection is
   *     used
   * @param message immutable payload created through {@link FCPPluginMessage} helpers; must not be
   *     reused
   * @throws IOException if the underlying transport closes or cannot accept more data
   */
  @Override
  public void send(final SendDirection direction, FCPPluginMessage message) throws IOException {
    if (!message.markSent()) {
      LOG.error(
          "send(): Attempted to send FCPPluginMessage {} twice on {}. "
              + "Re-sending the same instance is unsupported.",
          message.identifier,
          direction);
    }
    // We first have to compute the message.permissions field ourselves - we shall ignore what
    // caller said for security.
    ClientPermissions currentClientPermissions =
        (direction == SendDirection.TO_CLIENT)
            ? null // Server-to-client messages do not have permissions.
            : getCurrentClientPermissions();

    // We set the permissions by creating a fresh FCPPluginMessage object so the caller cannot
    // overwrite what we compute.
    message =
        FCPPluginMessage.constructRawMessage(
            currentClientPermissions,
            message.identifier,
            message.params,
            message.data,
            message.success,
            message.errorCode,
            message.errorMessage);

    // Now that the message is completely initialized, we can dump it to the logfile.
    if (LOG.isTraceEnabled()) {
      LOG.trace("send(): direction = {}; message = {}", direction, message);
    }

    // True if the target server or client message handler is running in this VM.
    // This means that we can call its message handling function in a thread instead of
    // sending a message over the network.
    // Notice that we do not check for server != null because that is not allowed by this class.
    final boolean messageHandlerExistsLocally =
        (direction == SendDirection.TO_SERVER)
            || (direction == SendDirection.TO_CLIENT && client != null);

    if (!messageHandlerExistsLocally) {
      dispatchMessageByNetwork(direction, message);
      return;
    }

    // The message handler is determined to be local at this point. There are two possible
    // types of local message handlers:
    // 1) An object provided by the server/client which implements FredPluginFCPMessageHandler.
    //    The message is delivered by executing a callback on that object, with the message
    //    as parameter.
    // 2) A call to sendSynchronous() which is blocking because it is waiting for a reply
    //    to the message it sent so it can return the reply message to the caller.
    //    The reply message is delivered by passing it to the sendSynchronous() thread through
    //    an internal table of this class.
    //
    // The following function call checks for whether case 2 applies, and handles it if yes:
    // If there is such a waiting sendSynchronous() thread, it delivers the message to it, and
    // returns true, and we are done: By contract, messages are preferably delivered to
    // sendSynchronous().
    // If there was no sendSynchronous() thread, it returns false, and we must continue to
    // handle case 1.
    if (dispatchMessageLocallyToSendSynchronousThreadIfExisting(message)) {
      return;
    }

    // We now know that the message handler is not attached by network, and that it is not a
    // sendSynchronous() thread. So the only thing it can be is a FredPluginFCPMessageHandler,
    // and we now determine whether it is the one of the client or the server.
    final FredPluginFCPMessageHandler messageHandler =
        (direction == SendDirection.TO_SERVER) ? server.get() : client;

    if (messageHandler == null) {
      // server is a WeakReference which can be nulled if the server plugin was unloaded.
      // client is not a WeakReference, we already checked for it to be non-null.
      // Thus, in this case here, the server plugin has been unloaded so we can have
      // an error message which specifically talks about the *server* plugin.
      throw new IOException("The server plugin has been unloaded.");
    }

    // We now have the right FredPluginFCPMessageHandler, it is still alive, and so we can
    // pass the message to it.
    dispatchMessageLocallyToMessageHandler(messageHandler, direction, message);
  }

  /**
   * Backend for {@link #send(SendDirection, FCPPluginMessage)} to dispatch messages which need to
   * be transported by network.<br>
   * <br>
   * This shall only be called for messages for which it was determined that the message handler is
   * not a plugin running in the local VM.
   */
  private void dispatchMessageByNetwork(
      final SendDirection direction, final FCPPluginMessage message) throws IOException {

    // The message handler is attached by network.
    // In theory, we could construct a mock FredPluginFCPMessagehandler object for it to
    // pretend it was a local message. But then we wouldn't know the reply message immediately
    // because the messages take time to travel over the network. This wouldn't work with the
    // local message dispatching code as it needs to know the reply immediately so it can send
    // it out. To get the reply, we would have to create a thread which would exist until the
    // reply arrives over the network.
    // So instead, for simplicity and reduced thread count, we just queue the message directly
    // to the network queue here and return.

    assert (direction == SendDirection.TO_CLIENT)
        : "By design, this class always shall execute in the same VM as the server plugin. "
            + "So for networked messages, we should always be sending to the client.";

    assert (clientConnection != null)
        : "Trying to send a message over the network to the client. "
            + "So the network connection to it should not be null.";

    if (clientConnection.isClosed())
      throw new IOException("Connection to client closed for " + this);

    clientConnection.send(new FCPPluginServerMessage(serverPluginName, message));
  }

  /**
   * Backend for {@link #send(SendDirection, FCPPluginMessage)} to dispatch messages to a thread
   * waiting in {@link #sendSynchronous(SendDirection, FCPPluginMessage, long)} for the message.
   * <br>
   * <br>
   * This shall only be called for messages for which it was determined that the message handler is
   * a plugin running in the local VM.
   *
   * @return True if there was a thread waiting for the message and the message was dispatched to
   *     it. You <b>must not</b> dispatch it to the {@link FredPluginFCPMessageHandler} then.<br>
   *     <br>
   *     False if there was no thread waiting for the message. You <b>must<b/> dispatch it to the
   *     {@link FredPluginFCPMessageHandler} then.<br>
   *     <br>
   *     (Both these rules are specified in the documentation of sendSynchronous().)
   * @see FCPPluginConnectionImpl#synchronousSends An overview of how synchronous sends and
   *     especially their threading work internally is provided at the map which stores them.
   */
  private boolean dispatchMessageLocallyToSendSynchronousThreadIfExisting(
      final FCPPluginMessage message) {

    // Since the message handler is determined to be local at this point, we now must check
    // whether it is a blocking sendSynchronous() thread instead of a regular
    // FredPluginFCPMessageHandler.
    // sendSynchronous() does the following: It sends a message and then blocks its thread
    // waiting for a message replying to it to arrive so it can return it to the caller.
    // If the message we are processing here is a reply, it might be the one which a
    // sendSynchronous() is waiting for.
    // So it is our job to pass the reply to a possibly existing sendSynchronous() thread.
    // We do this through the Map FCPPluginConnectionImpl.synchronousSends, which is guarded by
    // FCPPluginConnectionImpl.synchronousSendsLock. Also see the JavaDoc of the Map for an
    // overview of this mechanism.

    if (!message.isReplyMessage()) {
      return false;
    }

    // Since the JavaDoc of sendSynchronous() tells people to use it not very often due to
    // the impact upon thread count, we assume that the percentage of messages which pass
    // through here for which there is an actual sendSynchronous() thread waiting is small.
    // Thus, a ReadWriteLock is used, and we here only take the ReadLock, which can be taken
    // by *multiple* threads at once. We then read the map to check whether there is a
    //  waiter, and if there is, take the write lock to hand the message to it.
    // (The implementation of ReentrantReadWritelock does not allow upgrading a readLock()
    // to a writeLock(), so we must release it in between and re-check afterward.)
    // Performance note: If this turns out to be a bottleneck, add a
    // "Synchronous={True, False}" flag to messages so we only have to check the table if
    // Synchronous=True, and can return false immediately otherwise. (If Synchronous=True, we
    // still will have to check the table whether a waiter is existing because it might have
    // timed out already)

    synchronousSendsLock.readLock().lock();
    try {
      if (!synchronousSends.containsKey(message.identifier)) {
        return false;
      }
    } finally {
      synchronousSendsLock.readLock().unlock();
    }

    synchronousSendsLock.writeLock().lock();
    try {
      SynchronousSend synchronousSend = synchronousSends.get(message.identifier);
      if (synchronousSend == null) {
        // The waiting sendSynchronous() has probably returned already because its
        // timeout expired.
        // So by returning false, we ask the caller to deliver the message to the
        // regular message handling interface to make sure that it is not lost.
        return false;
      }

      if (synchronousSend.reply != null) {
        throw new IllegalStateException(
            "One identifier should not be used for multiple messages or replies");
      }

      synchronousSend.reply = message;
      // Wake up the waiting synchronousSend() thread
      synchronousSend.completionSignal.signal();

      return true;
    } finally {
      synchronousSendsLock.writeLock().unlock();
    }
  }

  /**
   * Backend for {@link #send(SendDirection, FCPPluginMessage)} to dispatch messages to a {@link
   * FredPluginFCPMessageHandler}.<br>
   * <br>
   * This shall only be called for messages for which it was determined that the message handler is
   * a plugin running in the local VM.<br>
   * <br>
   * The message will be dispatched in a separate thread so this function can return quickly.
   */
  private void dispatchMessageLocallyToMessageHandler(
      final FredPluginFCPMessageHandler messageHandler,
      final SendDirection direction,
      final FCPPluginMessage message) {

    final Runnable messageDispatcher =
        new PrioRunnable() {
          @Override
          public void run() {
            FCPPluginMessage reply =
                validateReply(
                    direction, message, invokeHandlerForReply(messageHandler, direction, message));

            if (reply == null) {
              warnAboutMissingReply(direction, message);
              return;
            }

            sendReplyFromHandler(direction, message, reply);
          }

          @Override
          @SuppressWarnings("java:S1181")
          public int getPriority() {
            NativeThread.PriorityLevel priority = NativeThread.PriorityLevel.NORM_PRIORITY;

            if (messageHandler instanceof PrioritizedMessageHandler handler) {
              try {
                priority = handler.getPriority(message);
              } catch (Throwable t) {
                LOG.error("Message handler's getPriority() threw!", t);
              }
            }

            return priority.value;
          }

          /**
           * @return A suitable {@link String} for use as the name of this thread
           */
          @Override
          public String toString() {
            // Don't use FCPPluginConnection.toString() as it would be too long to fit in
            // the thread list on the Freenet FProxy web interface.
            return "FCPPluginConnection for " + serverPluginName;
          }
        };

    executor.execute(messageDispatcher, messageDispatcher.toString());
  }

  @SuppressWarnings("java:S1181")
  private FCPPluginMessage invokeHandlerForReply(
      FredPluginFCPMessageHandler messageHandler,
      SendDirection direction,
      FCPPluginMessage message) {
    try {
      return messageHandler.handlePluginFCPMessage(
          getDefaultSendDirectionAdapter(direction.invert()), message);
    } catch (Throwable t) {
      return handleHandlerFailure(direction, message, t);
    }
  }

  private FCPPluginMessage handleHandlerFailure(
      SendDirection direction, FCPPluginMessage message, Throwable error) {
    String errorMessage =
        "CryptadPluginFCPMessageHandler threw."
            + " See JavaDoc of its member interfaces for how signal errors properly."
            + " connection = "
            + this
            + "; SendDirection = "
            + direction
            + "; message = "
            + message;

    LOG.error(errorMessage, error);

    if (message.isReplyMessage()) {
      return null;
    }

    return FCPPluginMessage.constructReplyMessage(
        message, null, null, false, "InternalError", errorMessage + "; Throwable = " + error);
  }

  private FCPPluginMessage validateReply(
      SendDirection direction, FCPPluginMessage original, FCPPluginMessage reply) {
    if (reply == null) {
      return null;
    }

    // Performance note: The below checks might be converted to assert() or be prefixed with if
    // (LOG.isDebugEnabled()). They are intentionally kept active for clarity because the newer
    // API is still easy to misuse.

    if (original.isReplyMessage()) {
      LOG.error(
          "CryptadPluginFCPMessageHandler tried to send a reply to a reply. Discarding it. See"
              + " JavaDoc of its member interfaces for how to do this properly. connection = {};"
              + " original message SendDirection = {}; original message = {}; reply = {}",
          this,
          direction,
          original,
          reply);
      return null;
    }

    if (!reply.isReplyMessage()) {
      LOG.error(
          "CryptadPluginFCPMessageHandler tried to send a non-reply message as reply. See JavaDoc"
              + " of its member interfaces for how to do this properly. connection = {}; original"
              + " message SendDirection = {}; original message = {}; reply = {}",
          this,
          direction,
          original,
          reply);
      return null;
    }

    if (!reply.identifier.equals(original.identifier)) {
      LOG.error(
          "CryptadPluginFCPMessageHandler tried to send a reply with different identifier than the"
              + " original message. connection = {}; original message SendDirection = {}; original"
              + " message = {}; reply = {}",
          this,
          direction,
          original,
          reply);

      return null;
    }

    return reply;
  }

  private void warnAboutMissingReply(SendDirection direction, FCPPluginMessage message) {
    if (message.isReplyMessage()) {
      return;
    }

    LOG.warn(
        "Cryptad did not receive a reply from the message handler even though it was allowed to"
            + " reply. This would cause sendSynchronous() to timeout! connection = {};"
            + " SendDirection = {}; message = {}",
        this,
        direction,
        message);
  }

  private void sendReplyFromHandler(
      SendDirection direction, FCPPluginMessage message, FCPPluginMessage reply) {
    try {
      send(direction.invert(), reply);
    } catch (IOException e) {
      LOG.warn(
          "Sending reply from CryptadPluginFCPMessageHandler failed, the connection was closed"
              + " already. connection = {}; original message SendDirection = {}; original message"
              + " = {}; reply = {}",
          this,
          direction,
          message,
          reply,
          e);
    }
  }

  /**
   * Sends a request and blocks until its paired reply arrives or the timeout elapses.
   *
   * <p>The method installs a {@link SynchronousSend} record keyed by the message identifier, sends
   * the payload using {@link #send(SendDirection, FCPPluginMessage)}, then waits on a {@link
   * Condition}. Spurious wakeups are tolerated by re-checking the reply slot, and every code path
   * removes its entry to avoid leaking memory. Timeouts raise {@link IOException} so callers can
   * rebuild the connection. Reply messages are forbidden because they would deadlock the handshake.
   *
   * <pre>{@code
   * var reply = connection.sendSynchronous(
   *     SendDirection.TO_SERVER,
   *     request,
   *     TimeUnit.SECONDS.toNanos(30));
   * }</pre>
   *
   * @param direction direction to deliver the outbound request
   * @param message immutable request that must not already represent a reply
   * @param timeoutNanoSeconds positive wait duration expressed in nanoseconds
   * @return reply returned by the remote endpoint; {@link FCPPluginMessage#success} may be false
   * @throws IOException if the timeout expires or the transport closes mid-flight
   * @throws InterruptedException if the calling thread is interrupted while waiting
   */
  @Override
  public FCPPluginMessage sendSynchronous(
      SendDirection direction, FCPPluginMessage message, long timeoutNanoSeconds)
      throws IOException, InterruptedException {

    if (message.isReplyMessage()) {
      throw new IllegalArgumentException(
          "sendSynchronous() cannot send reply messages: "
              + "If it did send a reply message, it would not get another reply back. "
              + "But a reply is needed for sendSynchronous() to determine when to return.");
    }

    if (timeoutNanoSeconds <= 0) {
      throw new IllegalArgumentException("Timeout should be positive");
    }

    synchronousSendsLock.writeLock().lock();
    try {
      final Condition completionSignal = synchronousSendsLock.writeLock().newCondition();
      final SynchronousSend synchronousSend = new SynchronousSend(completionSignal);

      // An assert() instead of a throwing is fine:
      // - The constructor of FCPPluginMessage which we tell the user to use in the JavaDoc
      //   does generate a random identifier, so collisions will only happen if the user
      //   ignores the JavaDoc or changes the constructor.
      // - If the assertion is not true, then the following put() will replace the old
      //   SynchronousSend, so its Condition will never get signaled, and its
      //   thread waiting in sendSynchronous() will timeout safely. It IS possible that this
      //   thread will then get a reply which does not belong to it. But the wrong reply will
      //   only affect the caller, the FCPPluginConnectionImpl will keep working fine,
      //   especially no threads will become stalled forever. As the caller is at fault for
      //   the issue, it is fine if he breaks his own stuff :) The JavaDoc also documents this

      if (synchronousSends.containsKey(message.identifier)) {
        throw new IllegalStateException("FCPPluginMessage.identifier should be unique");
      }

      synchronousSends.put(message.identifier, synchronousSend);

      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "sendSynchronous(): Started for identifier {}; synchronousSends table size: {}",
            message.identifier,
            synchronousSends.size());
      }

      send(direction, message);

      // Message is sent, now we wait for the reply message to be put into the SynchronousSend
      // object by the thread which receives the reply message.
      // - That usually happens at FCPPluginConnectionImpl.send().
      // Once it has put it into the SynchronousSend object, it will call signal() upon
      // our Condition completionSignal.
      // This will make the following awaitNanos() wake up and return true, which causes this
      // function to be able to return the reply.
      do {
        // The compleditionSignal is a Condition which was created from the
        // synchronousSendsLock.writeLock(), so it will be released by the awaitNanos()
        // while it is blocking, and re-acquired when it returns.
        timeoutNanoSeconds = completionSignal.awaitNanos(timeoutNanoSeconds);
        if (timeoutNanoSeconds <= 0) {
          // Include the FCPPluginMessage in the Exception so the developer can determine
          // whether it is an issue of the remote side taking a long time to execute
          // for certain messages.
          throw new IOException(
              "sendSynchronous() timed out waiting for reply! "
                  + " connection = "
                  + FCPPluginConnectionImpl.this
                  + "; SendDirection = "
                  + direction
                  + "; message = "
                  + message);
        }

        // The thread which sets synchronousSend.reply to be non-null calls
        // completionSignal.signal() only after synchronousSend.reply has been set.
        // So the naive assumption would be that at this point of code,
        // synchronousSend.reply would be non-null because awaitNanos() should only return
        // true after signal() was called.
        // However, Condition.awaitNanos() can wake up "spuriously", i.e. wake up without
        // actually having been signal()ed. See the JavaDoc of Condition.
        // So after awaitNanos() has returned true to indicate that it might have been
        // signaled we still need to check whether the semantic condition which would
        // trigger signaling is *really* met, which we do with this if:
        if (synchronousSend.reply != null) {
          if (!synchronousSend.reply.identifier.equals(message.identifier)) {
            throw new IllegalStateException(
                "Reply identifier does not match the original message identifier");
          }

          return synchronousSend.reply;
        }

        // A spurious wakeup occurred, so loop again and continue waiting.
      } while (true);
    } finally {
      // We MUST always remove the SynchronousSend object which we added to the map,
      // otherwise it will leak memory eternally.
      synchronousSends.remove(message.identifier);

      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "sendSynchronous(): Done for identifier {}; synchronousSends table size: {}",
            message.identifier,
            synchronousSends.size());
      }

      synchronousSendsLock.writeLock().unlock();
    }
  }

  /**
   * Encapsulates a FCPPluginConnectionImpl object and a default {@link SendDirection} to implement
   * the send functions which don't require a direction parameter:<br>
   * - {@link FCPPluginConnection#send(FCPPluginMessage)}<br>
   * - {@link FCPPluginConnection#sendSynchronous(FCPPluginMessage, long)}<br>
   * <br>
   * An adapter is needed instead of storing this as a member variable in FCPPluginConnectionImpl
   * because a single FCPPluginConnectionImpl object is used by both to the server AND the client
   * which it connects, and their default send direction will be different:<br>
   * A server will want to send to the client by default, but the client will want to default to
   * sending to the server.<br>
   * <br>
   * Is abstract and has two implementing child classes (to implement differing internal
   * requirements, see {@link #getConnection()}):<br>
   * - {@link SendToClientAdapter} for default direction {@link SendDirection#TO_CLIENT}.<br>
   * - {@link SendToServerAdapter} for default direction {@link SendDirection#TO_SERVER}.<br>
   * <br>
   * NOTICE: Server plugins must not keep a strong reference to the FCPPluginConnectionImpl to
   * ensure that the client disconnection mechanism of monitoring garbage collection works. This
   * class also serves the purpose of preventing servers from keeping a strong reference:<br>
   * Uses of class FCPPluginConnectionImpl are told by the documentation to never hand out a
   * FCPPluginConnectionImpl itself to servers, but only give them adapters. Since the {@link
   * SendToClientAdapter} only keeps a {@link WeakReference} to the FCPPluginConnectionImpl, by only
   * handing out the adapter, servers are prevented from keeping a strong reference to the
   * FCPPluginConnectionImpl.
   */
  private abstract static class DefaultSendDirectionAdapter implements FCPPluginConnection {

    private final SendDirection defaultDirection;

    DefaultSendDirectionAdapter(SendDirection defaultDirection) {
      this.defaultDirection = defaultDirection;
    }

    /**
     * Returns the encapsulated backend FCPPluginConnection which shall be used for sending.<br>
     * <br>
     * Abstract because storage of a FCPPluginConnection object is different for servers and clients
     * and thus must be implemented in separate child classes:<br>
     * - Clients may and must store a FCPPluginConnection with a hard reference because a connection
     * is considered as closed once there is no more hard reference to it.<br>
     * Disconnection is detected by monitoring the FCPluginConnection for garbage collection. <br>
     * - Servers must store a FCPPluginConnection with a {@link WeakReference} (or always query it
     * by UUID from the node) to ensure that they will get garbage connected once the client decides
     * to disconnect by dropping all strong references.
     */
    protected abstract FCPPluginConnection getConnection() throws IOException;

    @Override
    public void send(FCPPluginMessage message) throws IOException {
      send(defaultDirection, message);
    }

    @Override
    public FCPPluginMessage sendSynchronous(FCPPluginMessage message, long timeoutNanoSeconds)
        throws IOException, InterruptedException {
      return sendSynchronous(defaultDirection, message, timeoutNanoSeconds);
    }

    @Override
    public void send(SendDirection direction, FCPPluginMessage message) throws IOException {
      getConnection().send(direction, message);
    }

    @Override
    public FCPPluginMessage sendSynchronous(
        SendDirection direction, FCPPluginMessage message, long timeoutNanoSeconds)
        throws IOException, InterruptedException {
      return getConnection().sendSynchronous(direction, message, timeoutNanoSeconds);
    }
  }

  /**
   * Encapsulates a FCPPluginConnectionImpl object with a default {@link SendDirection} of {@link
   * SendDirection#TO_CLIENT} to implement the send functions which don't require a direction
   * parameter:<br>
   * - {@link FCPPluginConnection#send(FCPPluginMessage)}<br>
   * - {@link FCPPluginConnection#sendSynchronous(FCPPluginMessage, long)}<br>
   * <br>
   * ATTENTION: Must only be used by the server, not by the client: Clients must keep a strong
   * reference to the connection to prevent its garbage collection (= disconnection), but this does
   * not keep a strong reference.<br>
   * See section "Disconnecting properly" at {@link PluginRespirator#connectToOtherPlugin( String,
   * ClientSideFCPMessageHandler)}.<br>
   * <br>
   * NOTICE: Server plugins must not keep a strong reference to the FCPPluginConnectionImpl to
   * ensure that the client disconnection mechanism of monitoring garbage collection works. This
   * class also serves the purpose of preventing servers from keeping a strong reference:<br>
   * Uses of class FCPPluginConnectionImpl are told by the documentation to never hand out a
   * FCPPluginConnectionImpl itself to servers, but only give them adapters. Since the
   * SendToClientAdapter only keeps a {@link WeakReference} to the FCPPluginConnectionImpl, by only
   * handing out the adapter, servers are prevented from keeping a strong reference to the
   * FCPPluginConnectionImpl.<br>
   * As a consequence, please do never change this class to keep a strong reference to the
   * FCPPluginConnectionImpl.
   */
  private static final class SendToClientAdapter extends DefaultSendDirectionAdapter {

    /**
     * {@link WeakReference} to the underlying FCPPluginConnectionImpl.<br>
     * Once this becomes null, the connection is definitely dead - see {@link
     * FCPPluginConnectionTracker}.<br>
     * Notice: The ConnectionWeakReference child class of {@link WeakReference} is used because it
     * also stores the connection ID, which is needed for {@link #getID()}.
     */
    private final FCPPluginConnectionTracker.ConnectionWeakReference connectionRef;

    /**
     * For CPU performance of not calling {@link
     * FCPPluginConnectionTracker#getConnectionWeakReference(UUID)} for every {@link
     * #send(FCPPluginMessage)}, please use {@link
     * FCPPluginConnectionImpl#getDefaultSendDirectionAdapter(SendDirection)} whenever possible to
     * reuse adapters instead of creating new ones with this constructor.
     */
    SendToClientAdapter(FCPPluginConnectionTracker tracker, UUID connectionID) {
      super(SendDirection.TO_CLIENT);

      // Reuse the WeakReference from the FCPPluginConnectionTracker instead of creating our
      // own one since it has to keep a WeakReference for every connection anyway, and
      // WeakReferences might be expensive to maintain for the VM.
      try {
        this.connectionRef = tracker.getConnectionWeakReference(connectionID);
      } catch (IOException e) {
        // This function should only be used during construction of the underlying
        // FCPPluginConnectionImpl. While it is being constructed, it should not be
        // considered as disconnected already, and thus the FCPPluginConnectionTracker
        // should never throw IOException.
        throw new IllegalStateException("Tracker unexpectedly reported a disconnect", e);
      }
    }

    @Override
    protected FCPPluginConnection getConnection() throws IOException {
      FCPPluginConnection connection = connectionRef.get();
      if (connection == null) {
        throw new IOException(
            "Client has closed the connection. " + "Connection ID = " + connectionRef.connectionID);
      }
      return connection;
    }

    @Override
    public UUID getID() {
      return connectionRef.connectionID;
    }

    @Override
    public String toString() {
      String prefix = "SendToClientAdapter for ";
      try {
        return prefix + getConnection();
      } catch (IOException e) {
        return prefix + " FCPPluginConnectionImpl (" + e.getMessage() + ")";
      }
    }
  }

  /**
   * Encapsulates a FCPPluginConnectionImpl object with a default {@link SendDirection} of {@link
   * SendDirection#TO_SERVER} to implement the send functions which don't require a direction
   * parameter:<br>
   * - {@link FCPPluginConnection#send(FCPPluginMessage)}<br>
   * - {@link FCPPluginConnection#sendSynchronous(FCPPluginMessage, long)}<br>
   * <br>
   * ATTENTION: Must only be used by the client, not by the server: Client disconnection is
   * implemented by monitoring the garbage collection of their FCPPluginConnectionImpl objects -
   * once the connection is not strong referenced anymore, it is considered as closed. As this class
   * keeps a strong reference to the connection, if servers did use it, they would prevent client
   * disconnection.<br>
   * See section "Disconnecting properly" at {@link PluginRespirator#connectToOtherPlugin( String,
   * ClientSideFCPMessageHandler)}.
   */
  private static final class SendToServerAdapter extends DefaultSendDirectionAdapter {

    private final FCPPluginConnection parent;

    /**
     * For CPU performance of not constructing objects for every {@link #send(FCPPluginMessage)}
     * please use {@link FCPPluginConnectionImpl#getDefaultSendDirectionAdapter(SendDirection)}
     * whenever possible to reuse adapters instead of creating new ones with this constructor.
     */
    SendToServerAdapter(FCPPluginConnectionImpl parent) {
      super(SendDirection.TO_SERVER);
      this.parent = parent;
    }

    @Override
    protected FCPPluginConnection getConnection() {
      return parent;
    }

    @Override
    public UUID getID() {
      return parent.getID();
    }

    @Override
    public String toString() {
      return "SendToServerAdapter for " + parent;
    }
  }

  /**
   * Returns an adapter that locks the default {@link SendDirection} for callers lacking explicit
   * routing.
   *
   * <p>Adapters keep weak references when facing server plugins so garbage-collection-based
   * disconnects still work. Callers must use these adapters instead of caching {@code
   * FCPPluginConnectionImpl} directly; otherwise synchronous send restrictions and lifecycle
   * monitoring are bypassed.
   *
   * @param direction direction the adapter should target for all direction-less calls
   * @return adapter implementing {@link FCPPluginConnection} with the requested default direction
   */
  public FCPPluginConnection getDefaultSendDirectionAdapter(SendDirection direction) {
    return defaultSendDirectionAdapters.get(direction);
  }

  /**
   * @throws NoSendDirectionSpecifiedException Is always thrown since this function is only
   *     implemented for FCPPluginConnectionImpl objects which are wrapped inside a {@link
   *     DefaultSendDirectionAdapter}.<br>
   *     Objects of type FCPPluginConnectionImpl will never be handed out directly to the server or
   *     client application code, they will always be wrapped in such an adapter - so this function
   *     will work for servers and clients.
   */
  @Override
  public void send(FCPPluginMessage message) {
    throw new NoSendDirectionSpecifiedException();
  }

  /**
   * @throws NoSendDirectionSpecifiedException Is always thrown since this function is only
   *     implemented for FCPPluginConnectionImpl objects which are wrapped inside a {@link
   *     DefaultSendDirectionAdapter}.<br>
   *     Objects of type FCPPluginConnectionImpl will never be handed out directly to the server or
   *     client application code, they will always be wrapped in such an adapter - so this function
   *     will work for servers and clients.
   */
  @Override
  public FCPPluginMessage sendSynchronous(FCPPluginMessage message, long timeoutNanoSeconds) {
    throw new NoSendDirectionSpecifiedException();
  }

  /**
   * @see FCPPluginConnectionImpl#send(FCPPluginMessage)
   * @see FCPPluginConnectionImpl#sendSynchronous(FCPPluginMessage, long)
   */
  private static final class NoSendDirectionSpecifiedException
      extends UnsupportedOperationException {

    public NoSendDirectionSpecifiedException() {
      super(
          "You must obtain a FCPPluginConnectionImpl with a default SendDirection via "
              + "getDefaultSendDirectionAdapter() before you may use this function!");
    }
  }

  @Override
  public String toString() {
    return "FCPPluginConnectionImpl (ID: "
        + id
        + "; server class: "
        + serverPluginName
        + "; server: "
        + (server != null ? server.get() : null)
        + "; client: "
        + client
        + "; clientConnection: "
        + clientConnection
        + ")";
  }

  /**
   * ATTENTION: For unit test use only.
   *
   * @return The size of the backend table {@link #synchronousSends} of {@link
   *     #sendSynchronous(SendDirection, FCPPluginMessage, long)}
   */
  int getSendSynchronousCount() {
    synchronousSendsLock.readLock().lock();
    try {
      return synchronousSends.size();
    } finally {
      synchronousSendsLock.readLock().unlock();
    }
  }
}
