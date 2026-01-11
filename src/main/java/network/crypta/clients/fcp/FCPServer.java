package network.crypta.clients.fcp;

import java.io.File;
import java.io.IOException;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.WeakHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.client.ClientMetadata;
import network.crypta.client.DefaultMIMETypes;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchResult;
import network.crypta.client.async.CacheFetchResult;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.DownloadCache;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.client.async.PersistentJob;
import network.crypta.clients.fcp.ClientGet.ReturnType;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.clients.fcp.FCPPluginConnection.SendDirection;
import network.crypta.config.Config;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.SubConfig;
import network.crypta.crypt.SSL;
import network.crypta.io.AllowedHosts;
import network.crypta.io.NetworkInterface;
import network.crypta.io.SSLNetworkInterface;
import network.crypta.keys.FreenetURI;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestStarter;
import network.crypta.pluginmanager.FredPluginFCPMessageHandler.ClientSideFCPMessageHandler;
import network.crypta.pluginmanager.PluginNotFoundException;
import network.crypta.pluginmanager.PluginRespirator;
import network.crypta.support.Base64;
import network.crypta.support.api.BooleanCallback;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.IntCallback;
import network.crypta.support.api.StringCallback;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.NativeThread;
import network.crypta.support.io.NoFreeBucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.tanukisoftware.wrapper.WrapperManager;

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
  private static final Logger LOG = LoggerFactory.getLogger(FCPServer.class);

  private final PersistentRequestRoot persistentRoot;

  /**
   * Default TCP port (9481) exposed by the FCP listener so clients can auto-discover the node
   * without extra configuration.
   */
  public static final int DEFAULT_FCP_PORT = 9481;

  private static final String FPROXY_PREFIX = "FProxy:";
  NetworkInterface networkInterface;

  /* It’s not the field that is deprecated but accessing it directly is. */
  private final NodeClientCore core;

  /* It’s not the field that is deprecated but accessing it directly is. */
  private final Node node;

  final int port;
  private static boolean ssl = false;

  /* It’s not the field that is deprecated but accessing it directly is. */
  private final boolean enabled;

  String bindTo;
  private final String allowedHosts;
  AllowedHosts allowedHostsFullAccess;

  /**
   * Stores {@link FCPPluginConnectionImpl} objects by ID and automatically garbage collects them so
   * we don't have to bloat this class with that.
   */
  final FCPPluginConnectionTracker pluginConnectionTracker;

  final WeakHashMap<String, PersistentRequestClient> rebootClientsByName;

  /* It’s not the field that is deprecated but accessing it directly is. */
  private final PersistentRequestClient globalRebootClient;

  /* It’s not the field that is deprecated but accessing it directly is. */
  private final PersistentRequestClient globalForeverClient;

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

  private boolean assumeDownloadDDAIsAllowed;
  private boolean assumeUploadDDAIsAllowed;
  private boolean neverDropAMessage;
  private int maxMessageQueueLength;

  /**
   * Constructs a server instance from precomputed configuration and dependencies.
   *
   * @param config immutable configuration values for the FCP server.
   * @param dependencies node services required by the server.
   */
  public FCPServer(FcpServerConfig config, FcpServerDependencies dependencies) {
    this.bindTo = config.bindTo();
    this.allowedHosts = config.allowedHosts();
    this.allowedHostsFullAccess = new AllowedHosts(config.allowedHostsFullAccess());
    this.port = config.port();
    this.enabled = config.enabled();
    this.node = dependencies.node();
    this.core = dependencies.core();
    this.assumeDownloadDDAIsAllowed = config.assumeDownloadDDAAllowed();
    this.assumeUploadDDAIsAllowed = config.assumeUploadDDAAllowed();
    this.neverDropAMessage = config.neverDropAMessage();
    this.maxMessageQueueLength = config.maxMessageQueueLength();
    rebootClientsByName = new WeakHashMap<>();
    this.persistentRoot = dependencies.persistentRoot();
    globalForeverClient = persistentRoot.globalForeverClient;

    pluginConnectionTracker = new FCPPluginConnectionTracker();
    // pluginConnectionTracker.start() is called in maybeStart()

    globalRebootClient =
        new PersistentRequestClient("Global Queue", null, true, null, Persistence.REBOOT, null);

    // Debug flag derives from SLF4J directly when needed
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
    globalForeverClient.updateRequestStatusCache();
  }

  private void maybeGetNetworkInterface() {
    if (this.networkInterface != null) return;

    NetworkInterface tempNetworkInterface;
    if (ssl) {
      tempNetworkInterface =
          SSLNetworkInterface.create(port, bindTo, allowedHosts, node.network().executor(), true);
    } else {
      tempNetworkInterface =
          NetworkInterface.create(port, bindTo, allowedHosts, node.network().executor(), true);
    }

    this.networkInterface = tempNetworkInterface;
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
    if (this.enabled) {
      maybeGetNetworkInterface();

      LOG.info("Starting FCP server on {}:{}.", bindTo, port);

      if (this.networkInterface != null) {
        Thread t = new Thread(this, "FCP server");
        t.setDaemon(true);
        t.start();
      }
    } else {
      LOG.info("Not starting FCP server as it's disabled");
      this.networkInterface = null;
    }

    if (node.services().pluginManager().isEnabled()) {
      // We need to start the FCPPluginConnectionTracker no matter whether this.enabled == true:
      // If networked FCP is disabled, plugins might still communicate via non-networked
      // intra-node FCP.
      pluginConnectionTracker.start();
    }
  }

  @Override
  public void run() {
    while (true) {
      try {
        networkInterface.waitBound();
        realRun();
      } catch (Exception e) {
        LOG.error("Caught {}", e, e);
      }
      if (WrapperManager.hasShutdownHookBeenTriggered()) return;
    }
  }

  private void realRun() {
    if (!node.isHasStarted()) return;
    // Accept a connection
    Socket s = networkInterface.accept();
    FCPConnectionHandler ch = new FCPConnectionHandler(s, this);
    ch.start();
  }

  static class FCPPortNumberCallback extends IntCallback {

    private final NodeClientCore node;

    FCPPortNumberCallback(NodeClientCore node) {
      this.node = node;
    }

    @Override
    public Integer get() {
      return node.getEndpoints().getFCPServer().port;
    }

    @Override
    public void set(Integer val) throws InvalidConfigValueException {
      if (!get().equals(val)) {
        throw new InvalidConfigValueException("Cannot change FCP port number on the fly");
      }
    }

    @Override
    public boolean isReadOnly() {
      return true;
    }
  }

  static class FCPEnabledCallback extends BooleanCallback {

    final NodeClientCore node;

    FCPEnabledCallback(NodeClientCore node) {
      this.node = node;
    }

    @Override
    public Boolean get() {
      return node.getEndpoints().getFCPServer().enabled;
    }

    // Changing the enabled flag at runtime is not supported.
    @Override
    public void set(Boolean val) throws InvalidConfigValueException {
      if (!get().equals(val)) {
        throw new InvalidConfigValueException(
            NodeL10n.getBase().getString("FcpServer.cannotStartOrStopOnTheFly"));
      }
    }

    @Override
    public boolean isReadOnly() {
      return true;
    }
  }

  static class FCPSSLCallback extends BooleanCallback {

    private static void updateSslFlag(boolean val) throws InvalidConfigValueException {
      if (ssl == val) {
        return;
      }
      if (!SSL.available()) {
        throw new InvalidConfigValueException("Enable SSL support before use ssl with FCP");
      }
      ssl = val;
      throw new InvalidConfigValueException("Cannot change SSL on the fly, please restart freenet");
    }

    @Override
    public Boolean get() {
      return ssl;
    }

    @Override
    public void set(Boolean val) throws InvalidConfigValueException {
      updateSslFlag(val);
    }

    @Override
    public boolean isReadOnly() {
      return true;
    }
  }

  // Configuration callbacks remain for bindTo to allow runtime updates; other fields are set in the
  // constructor.

  static class FCPBindtoCallback extends StringCallback {

    final NodeClientCore node;

    FCPBindtoCallback(NodeClientCore node) {
      this.node = node;
    }

    @Override
    public String get() {
      return node.getEndpoints().getFCPServer().bindTo;
    }

    @Override
    public void set(String val) throws InvalidConfigValueException {
      String oldValue = get();
      if (!val.equals(oldValue)) {
        FCPServer server = node.getEndpoints().getFCPServer();

        String[] failedAddresses = server.networkInterface.setBindTo(val, true);
        if (failedAddresses != null) {
          // This is an advanced option for reasons of reducing clutter,
          // but it is expected to be used by regular users, not devs.
          // So we translate the error messages.
          server.networkInterface.setBindTo(oldValue, true);
          throw new InvalidConfigValueException(
              NodeL10n.getBase()
                  .getString(
                      "FcpServer.couldNotChangeBindTo",
                      "failedInterfaces",
                      Arrays.toString(failedAddresses)));
        }

        server.networkInterface.setBindTo(val, true);
        server.bindTo = val;
      }
    }
  }

  static class FCPAllowedHostsCallback extends StringCallback {

    private final NodeClientCore node;

    public FCPAllowedHostsCallback(NodeClientCore node) {
      this.node = node;
    }

    @Override
    public String get() {
      FCPServer server = node.getEndpoints().getFCPServer();
      if (server == null) return NetworkInterface.DEFAULT_BIND_TO;
      NetworkInterface netIface = server.networkInterface;
      return (netIface == null ? NetworkInterface.DEFAULT_BIND_TO : netIface.getAllowedHosts());
    }

    @Override
    public void set(String val) throws InvalidConfigValueException {
      if (!val.equals(get())) {
        try {
          node.getEndpoints().getFCPServer().networkInterface.setAllowedHosts(val);
        } catch (IllegalArgumentException e) {
          throw new InvalidConfigValueException(e);
        }
      }
    }
  }

  static class FCPAllowedHostsFullAccessCallback extends StringCallback {
    private final NodeClientCore node;

    public FCPAllowedHostsFullAccessCallback(NodeClientCore node) {
      this.node = node;
    }

    @Override
    public String get() {
      return node.getEndpoints().getFCPServer().allowedHostsFullAccess.getAllowedHosts();
    }

    @Override
    public void set(String val) throws InvalidConfigValueException {
      if (!val.equals(get())) {
        try {
          node.getEndpoints().getFCPServer().allowedHostsFullAccess.setAllowedHosts(val);
        } catch (IllegalArgumentException e) {
          throw new InvalidConfigValueException(e);
        }
      }
    }
  }

  static class AssumeDDADownloadIsAllowedCallback extends BooleanCallback {
    FCPServer server;

    @Override
    public Boolean get() {
      return server.assumeDownloadDDAIsAllowed;
    }

    @Override
    public void set(Boolean val) throws InvalidConfigValueException {
      if (get().equals(val)) return;
      server.assumeDownloadDDAIsAllowed = val;
    }
  }

  static class AssumeDDAUploadIsAllowedCallback extends BooleanCallback {
    FCPServer server;

    @Override
    public Boolean get() {
      return server.assumeUploadDDAIsAllowed;
    }

    @Override
    public void set(Boolean val) throws InvalidConfigValueException {
      if (get().equals(val)) return;
      server.assumeUploadDDAIsAllowed = val;
    }
  }

  static class NeverDropAMessageCallback extends BooleanCallback {
    FCPServer server;

    @Override
    public Boolean get() {
      return server.neverDropAMessage;
    }

    @Override
    public void set(Boolean val) throws InvalidConfigValueException {
      if (get().equals(val)) return;
      server.neverDropAMessage = val;
    }
  }

  static class MaxMessageQueueLengthCallback extends IntCallback {
    FCPServer server;

    @Override
    public Integer get() {
      return server.maxMessageQueueLength;
    }

    @Override
    public void set(Integer val) throws InvalidConfigValueException {
      if (get().equals(val)) return;
      server.maxMessageQueueLength = val;
    }
  }

  /**
   * Registers FCP configuration keys and constructs a server instance wired to those settings.
   *
   * <p>The method derives the <code>fcp</code> subconfig, installs callbacks for mutable options
   * such as bind address and allowed hosts, applies persisted SSL and DDA flags when present, and
   * finally builds the {@link FCPServer}. Callers should invoke {@link #maybeStart()} after
   * creation to begin listening for connections.
   *
   * @param node owning {@link Node} providing executors, plugin access, and lifecycle hooks.
   * @param core client core exposing persistence utilities, job runners, and random sources.
   * @param config root configuration object used to create and populate the FCP subconfig.
   * @param root persistent request root shared across global clients.
   * @return fully initialized server respecting the current configuration values.
   */
  public static FCPServer maybeCreate(
      Node node, NodeClientCore core, Config config, PersistentRequestRoot root) {
    SubConfig fcpConfig = config.createSubConfig("fcp");
    short sortOrder = 0;
    fcpConfig.register(
        "enabled",
        true,
        sortOrder++,
        true,
        false,
        "FcpServer.isEnabled",
        "FcpServer.isEnabledLong",
        new FCPEnabledCallback(core));
    fcpConfig.register(
        "ssl",
        false,
        sortOrder++,
        true,
        true,
        "FcpServer.ssl",
        "FcpServer.sslLong",
        new FCPSSLCallback());
    fcpConfig.register(
        "port",
        FCPServer.DEFAULT_FCP_PORT /* anagram of 1984, and 1000 up from old number */,
        2,
        true,
        true,
        "FcpServer.portNumber",
        "FcpServer.portNumberLong",
        new FCPPortNumberCallback(core),
        false);
    fcpConfig.register(
        "bindTo",
        NetworkInterface.DEFAULT_BIND_TO,
        sortOrder++,
        true,
        true,
        "FcpServer.bindTo",
        "FcpServer.bindToLong",
        new FCPBindtoCallback(core));
    fcpConfig.register(
        "allowedHosts",
        NetworkInterface.DEFAULT_BIND_TO,
        sortOrder++,
        true,
        true,
        "FcpServer.allowedHosts",
        "FcpServer.allowedHostsLong",
        new FCPAllowedHostsCallback(core));
    fcpConfig.register(
        "allowedHostsFullAccess",
        NetworkInterface.DEFAULT_BIND_TO,
        sortOrder++,
        true,
        true,
        "FcpServer.allowedHostsFullAccess",
        "FcpServer.allowedHostsFullAccessLong",
        new FCPAllowedHostsFullAccessCallback(core));

    AssumeDDADownloadIsAllowedCallback cb4 = new AssumeDDADownloadIsAllowedCallback();
    AssumeDDAUploadIsAllowedCallback cb5 = new AssumeDDAUploadIsAllowedCallback();
    NeverDropAMessageCallback cb6 = new NeverDropAMessageCallback();
    MaxMessageQueueLengthCallback cb7 = new MaxMessageQueueLengthCallback();
    fcpConfig.register(
        "assumeDownloadDDAIsAllowed",
        false,
        sortOrder++,
        true,
        false,
        "FcpServer.assumeDownloadDDAIsAllowed",
        "FcpServer.assumeDownloadDDAIsAllowedLong",
        cb4);
    fcpConfig.register(
        "assumeUploadDDAIsAllowed",
        false,
        sortOrder++,
        true,
        false,
        "FcpServer.assumeUploadDDAIsAllowed",
        "FcpServer.assumeUploadDDAIsAllowedLong",
        cb5);
    fcpConfig.register(
        "maxMessageQueueLength",
        1024,
        sortOrder++,
        true,
        false,
        "FcpServer.maxMessageQueueLength",
        "FcpServer.maxMessageQueueLengthLong",
        cb7,
        false);
    fcpConfig.register(
        "neverDropAMessage",
        false,
        sortOrder,
        true,
        false,
        "FcpServer.neverDropAMessage",
        "FcpServer.neverDropAMessageLong",
        cb6);

    if (SSL.available()) {
      ssl = fcpConfig.getBoolean("ssl");
    }

    FcpServerConfig serverConfig =
        new FcpServerConfig(
            fcpConfig.getString("bindTo"),
            fcpConfig.getString("allowedHosts"),
            fcpConfig.getString("allowedHostsFullAccess"),
            fcpConfig.getInt("port"),
            fcpConfig.getBoolean("enabled"),
            fcpConfig.getBoolean("assumeDownloadDDAIsAllowed"),
            fcpConfig.getBoolean("assumeUploadDDAIsAllowed"),
            fcpConfig.getBoolean("neverDropAMessage"),
            fcpConfig.getInt("maxMessageQueueLength"));
    FcpServerDependencies dependencies = new FcpServerDependencies(node, core, root);
    FCPServer fcp = new FCPServer(serverConfig, dependencies);

    cb4.server = fcp;
    cb5.server = fcp;
    cb6.server = fcp;
    cb7.server = fcp;

    fcpConfig.finishedInitialization();
    return fcp;
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
    return FCPPluginConnectionImpl.constructForNetworkedFCP(
        pluginConnectionTracker,
        node.network().executor(),
        node.services().pluginManager(),
        serverPluginName,
        messageHandler);
  }

  /**
   * Creates and registers an intra-node {@link FCPPluginConnection} for plugin-to-plugin traffic.
   *
   * <p>This shortcut is used by {@link PluginRespirator#connectToOtherPlugin(String,
   * ClientSideFCPMessageHandler)} to establish a logical FCP link without leaving the process. The
   * connection is inserted into {@link FCPPluginConnectionTracker} and stays reachable as long as
   * the caller keeps a strong reference. To match the client perspective, the returned adapter
   * defaults the send direction to {@link SendDirection#TO_SERVER}.
   *
   * @param serverPluginName name of the server-side plugin that will receive the messages.
   * @param messageHandler handler on the client-side plugin that processes responses.
   * @return connection adapter configured for server-directed sends.
   * @throws PluginNotFoundException if the target plugin cannot be found or instantiated.
   */
  public final FCPPluginConnection createFCPPluginConnectionForIntraNodeFCP(
      String serverPluginName, ClientSideFCPMessageHandler messageHandler)
      throws PluginNotFoundException {

    FCPPluginConnectionImpl connection =
        FCPPluginConnectionImpl.constructForIntraNodeFCP(
            pluginConnectionTracker,
            node.network().executor(),
            node.services().pluginManager(),
            serverPluginName,
            messageHandler);
    return connection.getDefaultSendDirectionAdapter(SendDirection.TO_SERVER);
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
    return pluginConnectionTracker
        .getConnection(connectionID)
        .getDefaultSendDirectionAdapter(SendDirection.TO_CLIENT);
  }

  /**
   * Registers or replaces a reboot-persistent client associated with the given name.
   *
   * @param name stable client identifier kept across reconnects.
   * @param handler active connection handler for the client.
   * @return existing client after handler replacement, or a newly created client when absent.
   */
  public PersistentRequestClient registerRebootClient(String name, FCPConnectionHandler handler) {
    PersistentRequestClient oldClient;
    synchronized (this) {
      oldClient = rebootClientsByName.get(name);
      if (oldClient == null) {
        // Create new client
        PersistentRequestClient client =
            new PersistentRequestClient(name, handler, false, null, Persistence.REBOOT, null);
        rebootClientsByName.put(name, client);
        return client;
      } else {
        FCPConnectionHandler oldConn = oldClient.getConnection();
        // Have existing client
        if (oldConn != null) {
          // Kill old connection
          oldConn.setKilledDupe();
          oldConn.send(new CloseConnectionDuplicateClientNameMessage());
          oldConn.close();
        }
        oldClient.setConnection(handler);
        return oldClient;
      }
    }
  }

  /**
   * Registers a forever-persistent client and returns the associated queue owner.
   *
   * @param name identifier used for persistence and status reporting.
   * @param handler current connection handler, or {@code null} when registering headless.
   * @return client instance tied to the forever queue.
   */
  public PersistentRequestClient registerForeverClient(String name, FCPConnectionHandler handler) {
    return persistentRoot.registerForeverClient(name, handler);
  }

  /**
   * Retrieves or creates a forever-persistent client for the provided name and handler.
   *
   * @param name client name to look up.
   * @param handler handler representing the active connection; may be {@code null} when resuming.
   * @return existing or newly created client.
   */
  public PersistentRequestClient getForeverClient(String name, FCPConnectionHandler handler) {
    return persistentRoot.getForeverClient(name, handler);
  }

  /**
   * Unregisters the given persistent client from its queue.
   *
   * @param client client to remove; reboot clients are removed from the local map, forever clients
   *     delegate to {@link PersistentRequestRoot} for cleanup.
   */
  public void unregisterClient(PersistentRequestClient client) {
    if (client.persistence == Persistence.REBOOT) {
      synchronized (this) {
        String name = client.name;
        rebootClientsByName.remove(name);
      }
    } else {
      persistentRoot.maybeUnregisterClient(client);
    }
  }

  /**
   * Returns a snapshot of global persistent requests across reboot and forever queues.
   *
   * @return array of request status entries; never {@code null}.
   * @throws PersistenceDisabledException if persistence is unavailable while reading status.
   */
  public RequestStatus[] getGlobalRequests() throws PersistenceDisabledException {
    if (core.killedDatabase()) throw new PersistenceDisabledException();
    List<RequestStatus> v = new ArrayList<>();
    globalRebootClient.addPersistentRequestStatus(v);
    if (globalForeverClient != null) globalForeverClient.addPersistentRequestStatus(v);
    return v.toArray(new RequestStatus[0]);
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
    if (!globalRebootClient.removeByIdentifier(identifier, true, this, core.getClientContext())) {
      final CountDownLatch done = new CountDownLatch(1);
      final AtomicBoolean success = new AtomicBoolean();
      core.getClientContext()
          .jobRunner
          .queue(
              new PersistentJob() {

                @Override
                public String toString() {
                  return "FCP removeGlobalRequestBlocking";
                }

                @Override
                public boolean run(ClientContext context) {
                  boolean succeeded = false;
                  try {
                    succeeded =
                        globalForeverClient.removeByIdentifier(
                            identifier, true, FCPServer.this, core.getClientContext());
                  } catch (Exception e) {
                    LOG.error("Caught removing identifier {}: {}", identifier, e, e);
                  } finally {
                    success.set(succeeded);
                    done.countDown();
                  }
                  return true;
                }
              },
              NativeThread.PriorityLevel.HIGH_PRIORITY.value);
      try {
        done.await();
      } catch (InterruptedException _) {
        Thread.currentThread().interrupt();
        return success.get();
      }
      return success.get();
    } else return true;
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
    globalRebootClient.removeAll();
    final CountDownLatch done = new CountDownLatch(1);
    final AtomicBoolean success = new AtomicBoolean();
    core.getClientContext()
        .jobRunner
        .queue(
            new PersistentJob() {

              @Override
              public String toString() {
                return "FCP removeAllGlobalRequestsBlocking";
              }

              @Override
              public boolean run(ClientContext context) {
                boolean succeeded = false;
                try {
                  globalForeverClient.removeAll();
                  succeeded = true;
                } catch (Exception e) {
                  LOG.error("Caught while processing panic: {}", e, e);
                } finally {
                  success.set(succeeded);
                  done.countDown();
                }
                return true;
              }
            },
            NativeThread.PriorityLevel.HIGH_PRIORITY.value);
    try {
      done.await();
    } catch (InterruptedException _) {
      Thread.currentThread().interrupt();
      return success.get();
    }
    return success.get();
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
    final CountDownLatch done = new CountDownLatch(1);
    final AtomicReference<NotAllowedException> notAllowed = new AtomicReference<>();
    final AtomicReference<IOException> ioException = new AtomicReference<>();
    core.getClientContext()
        .jobRunner
        .queue(
            new PersistentJob() {

              @Override
              public String toString() {
                return "FCP makePersistentGlobalRequestBlocking";
              }

              @Override
              public boolean run(ClientContext context) {
                try {
                  makePersistentGlobalRequest(params);
                  return true;
                } catch (NotAllowedException e) {
                  notAllowed.set(e);
                  return false;
                } catch (IOException e) {
                  ioException.set(e);
                  return false;
                } catch (Exception t) {
                  // Unexpected and severe, might even be OOM, just log it.
                  LOG.error("Failed to make persistent request: {}", t, t);
                  return false;
                } finally {
                  done.countDown();
                }
              }
            },
            NativeThread.PriorityLevel.HIGH_PRIORITY.value);

    try {
      done.await();
    } catch (InterruptedException _) {
      Thread.currentThread().interrupt();
    }
    if (ioException.get() != null) throw ioException.get();
    if (notAllowed.get() != null) throw notAllowed.get();
  }

  public void makePersistentGlobalRequestBlocking(
      FreenetURI fetchURI,
      boolean filterData,
      String expectedMimeType,
      String persistenceTypeString,
      String returnTypeString,
      boolean realTimeFlag,
      File downloadsDir)
      throws NotAllowedException, IOException, PersistenceDisabledException {
    makePersistentGlobalRequestBlocking(
        new PersistentGlobalRequestParams(
            fetchURI,
            filterData,
            expectedMimeType,
            persistenceTypeString,
            returnTypeString,
            realTimeFlag,
            downloadsDir));
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
    ClientRequest req = this.globalRebootClient.getRequest(identifier);
    if (req != null) {
      req.modifyRequest(newToken, newPriority, this);
      return true;
    } else {
      class OutputWrapper {
        boolean success;
        boolean done;
      }
      final OutputWrapper ow = new OutputWrapper();
      core.getClientContext()
          .jobRunner
          .queue(
              new PersistentJob() {

                @Override
                public String toString() {
                  return "FCP modifyGlobalRequestBlocking";
                }

                @Override
                public boolean run(ClientContext context) {
                  boolean success = false;
                  try {
                    ClientRequest req = globalForeverClient.getRequest(identifier);
                    if (req != null) req.modifyRequest(newToken, newPriority, FCPServer.this);
                    success = true;
                  } finally {
                    synchronized (ow) {
                      ow.success = success;
                      ow.done = true;
                      ow.notifyAll();
                    }
                  }
                  return true;
                }
              },
              NativeThread.PriorityLevel.HIGH_PRIORITY.value);

      synchronized (ow) {
        while (true) {
          if (!ow.done) {
            try {
              ow.wait();
            } catch (InterruptedException _) {
              Thread.currentThread().interrupt();
              return ow.success;
            }
            continue;
          }
          return ow.success;
        }
      }
    }
  }

  /**
   * Creates a persistent globally queued fetch request with explicit return handling.
   *
   * @param params request parameters describing the persistent fetch.
   * @throws NotAllowedException if local policy forbids creating the request.
   * @throws IOException if disk output setup fails or the downloads directory is invalid.
   */
  public void makePersistentGlobalRequest(PersistentGlobalRequestParams params)
      throws NotAllowedException, IOException {
    boolean persistence = params.persistenceType().equalsIgnoreCase("reboot");
    ReturnType returnType = ReturnType.valueOf(params.returnType().toUpperCase());
    File returnFilename = null;
    if (returnType == ReturnType.DISK) {
      returnFilename =
          makeReturnFilename(params.fetchURI(), params.expectedMimeType(), params.downloadsDir());
    }
    List<String> candidateIds = new ArrayList<>();
    candidateIds.add(FPROXY_PREFIX + params.fetchURI().getPreferredFilename());
    candidateIds.add(FPROXY_PREFIX + params.fetchURI().getDocName());
    candidateIds.add(FPROXY_PREFIX + params.fetchURI().toString(false, false));
    candidateIds.add("FProxy (" + System.currentTimeMillis() + ')');

    for (String candidateId : candidateIds) {
      if (candidateId == null) {
        continue;
      }
      PersistentGlobalRequestSpec spec =
          new PersistentGlobalRequestSpec(
              params.fetchURI(),
              params.filterData(),
              persistence,
              returnType,
              candidateId,
              returnFilename,
              params.realTimeFlag());
      if (tryPersistentGlobalRequest(spec)) {
        return;
      }
    }

    while (true) {
      byte[] buf = new byte[8];
      core.getRandom().nextBytes(buf);
      String id = FPROXY_PREFIX + Base64.encode(buf);
      PersistentGlobalRequestSpec spec =
          new PersistentGlobalRequestSpec(
              params.fetchURI(),
              params.filterData(),
              persistence,
              returnType,
              id,
              returnFilename,
              params.realTimeFlag());
      if (tryPersistentGlobalRequest(spec)) {
        return;
      }
    }
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
    makePersistentGlobalRequest(
        new PersistentGlobalRequestParams(
            fetchURI,
            filterData,
            expectedMimeType,
            persistenceTypeString,
            returnTypeString,
            realTimeFlag,
            core.getDownloadsDir()));
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
  public void makePersistentGlobalRequest(
      FreenetURI fetchURI,
      boolean filterData,
      String expectedMimeType,
      String persistenceTypeString,
      String returnTypeString,
      boolean realTimeFlag,
      File downloadsDir)
      throws NotAllowedException, IOException {
    makePersistentGlobalRequest(
        new PersistentGlobalRequestParams(
            fetchURI,
            filterData,
            expectedMimeType,
            persistenceTypeString,
            returnTypeString,
            realTimeFlag,
            downloadsDir));
  }

  private boolean tryPersistentGlobalRequest(PersistentGlobalRequestSpec spec)
      throws NotAllowedException, IOException {
    try {
      innerMakePersistentGlobalRequest(spec);
      return true;
    } catch (IdentifierCollisionException _) {
      return false;
    }
  }

  private File makeReturnFilename(FreenetURI uri, String expectedMimeType, File downloadsDir) {
    String ext;
    if ((expectedMimeType != null)
        && !expectedMimeType.isEmpty()
        && !expectedMimeType.equals(DefaultMIMETypes.DEFAULT_MIME_TYPE)) {
      ext = DefaultMIMETypes.getExtension(expectedMimeType);
    } else ext = null;
    String extAdd = (ext == null ? "" : '.' + ext);
    String preferred = uri.getPreferredFilename();
    String preferredWithExt = preferred;
    if (!(ext != null && preferredWithExt.endsWith(ext))) preferredWithExt += extAdd;
    File f = new File(downloadsDir, preferredWithExt);
    int x = 0;
    StringBuilder sb = new StringBuilder();
    for (; f.exists(); sb.setLength(0)) {
      sb.append(preferred);
      sb.append('-');
      sb.append(x);
      sb.append(extAdd);
      f = new File(downloadsDir, sb.toString());
      x++;
    }
    return f;
  }

  private void innerMakePersistentGlobalRequest(PersistentGlobalRequestSpec spec)
      throws IdentifierCollisionException, NotAllowedException, IOException {
    FetchContext defaultFetchContext = core.getClientContext().getDefaultPersistentFetchContext();
    ClientGet.GlobalRequestConfig requestConfig =
        new ClientGet.GlobalRequestConfig(
            defaultFetchContext.getLocalRequestOnly(),
            defaultFetchContext.getIgnoreStore(),
            spec.filterData(),
            QUEUE_MAX_RETRIES,
            QUEUE_MAX_RETRIES,
            QUEUE_MAX_DATA_SIZE,
            spec.returnType(),
            spec.persistRebootOnly(),
            spec.identifier(),
            Integer.MAX_VALUE,
            RequestStarter.BULK_SPLITFILE_PRIORITY_CLASS,
            spec.returnFilename(),
            null,
            false,
            spec.realTimeFlag(),
            false);
    final ClientGet cg =
        new ClientGet(
            spec.persistRebootOnly() ? globalRebootClient : globalForeverClient,
            spec.fetchURI(),
            requestConfig,
            core);
    cg.register(false);
    cg.start(core.getClientContext());
  }

  /**
   * Returns the forever-persistent global client used by this server instance.
   *
   * @return client reference for the forever queue; may be {@code null} when persistence is
   *     disabled.
   */
  public PersistentRequestClient getGlobalForeverClient() {
    return globalForeverClient;
  }

  /**
   * Retrieves a global request by identifier from either persistence class.
   *
   * @param identifier request identifier to search for.
   * @return matching request from the reboot or forever queue, or {@code null} if none exist.
   */
  public ClientRequest getGlobalRequest(String identifier) {
    ClientRequest req = globalRebootClient.getRequest(identifier);
    if (req == null) req = globalForeverClient.getRequest(identifier);
    return req;
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
    if (globalForeverClient != null) globalForeverClient.addRequestCompletionCallback(cb);
    globalRebootClient.addRequestCompletionCallback(cb);
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
    if (req.persistence == Persistence.REBOOT) {
      req.start(core.getClientContext());
    } else {
      final CountDownLatch done = new CountDownLatch(1);
      final AtomicReference<IdentifierCollisionException> collision = new AtomicReference<>();
      core.getClientContext()
          .jobRunner
          .queue(
              new PersistentJob() {

                @Override
                public String toString() {
                  return "FCP startBlocking";
                }

                @Override
                public boolean run(ClientContext context) {
                  // Don't activate, it may not be stored yet.
                  try {
                    req.register(false);
                    req.start(context);
                  } catch (IdentifierCollisionException e) {
                    collision.set(e);
                  } finally {
                    done.countDown();
                  }
                  return true;
                }
              },
              NativeThread.PriorityLevel.HIGH_PRIORITY.value);

      try {
        done.await();
      } catch (InterruptedException _) {
        Thread.currentThread().interrupt();
      }
      if (collision.get() != null) {
        throw collision.get();
      }
    }
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
    ClientRequest req = globalRebootClient.getRequest(identifier);
    if (req != null) {
      req.restart(core.getClientContext(), disableFilterData);
      return true;
    } else {
      final CountDownLatch done = new CountDownLatch(1);
      final AtomicBoolean success = new AtomicBoolean();
      if (LOG.isDebugEnabled()) LOG.debug("Queueing restart of {}", identifier);
      core.getClientContext()
          .jobRunner
          .queue(
              new PersistentJob() {

                @Override
                public String toString() {
                  return "FCP restartBlocking";
                }

                @Override
                public boolean run(ClientContext context) {
                  boolean restarted = false;
                  try {
                    ClientRequest req = globalForeverClient.getRequest(identifier);
                    if (LOG.isDebugEnabled()) LOG.debug("Restarting {} for {}", req, identifier);
                    if (req != null) {
                      req.restart(context, disableFilterData);
                      restarted = true;
                    }
                  } catch (PersistenceDisabledException e) {
                    LOG.error("Failed to restart {}: {}", identifier, e.getMessage(), e);
                  } finally {
                    success.set(restarted);
                    done.countDown();
                  }
                  return true;
                }
              },
              NativeThread.PriorityLevel.HIGH_PRIORITY.value);

      try {
        done.await();
      } catch (InterruptedException _) {
        Thread.currentThread().interrupt();
      }
      return success.get();
    }
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
    ClientGet get = globalRebootClient.getCompletedRequest(key);
    if (get != null) {
      // Potential race with free(); refcounting would avoid losing data here.
      return new FetchResult(
          new ClientMetadata(get.getMIMEType()), new NoFreeBucket(get.getBucket()));
    }

    FetchResult result = globalForeverClient.getRequestStatusCache().getShadowBucket(key, false);
    if (result != null) {
      return result;
    }

    final CountDownLatch done = new CountDownLatch(1);
    final AtomicReference<FetchResult> resultRef = new AtomicReference<>();
    core.getClientContext()
        .jobRunner
        .queue(
            new PersistentJob() {

              @Override
              public String toString() {
                return "FCP getCompletedRequestBlocking";
              }

              @Override
              public boolean run(ClientContext context) {
                try {
                  resultRef.set(lookup(key, false, context, false, null));
                } finally {
                  done.countDown();
                }
                return false;
              }
            },
            NativeThread.PriorityLevel.HIGH_PRIORITY.value);

    try {
      done.await();
    } catch (InterruptedException _) {
      Thread.currentThread().interrupt();
    }
    return resultRef.get();
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
    ClientGet get = globalRebootClient.getCompletedRequest(key);

    Bucket origData = null;
    String mime = null;
    boolean filtered = false;

    if (get != null) {
      boolean requestFiltered = get.filterData();
      if ((!noFilter) || (!requestFiltered)) {
        filtered = requestFiltered;
        origData = new NoFreeBucket(get.getBucket());
        mime = get.getMIMEType();
      }
    }

    if (origData == null && globalForeverClient != null) {
      CacheFetchResult result =
          globalForeverClient.getRequestStatusCache().getShadowBucket(key, noFilter);
      if (result != null) {
        mime = result.getMimeType();
        origData = result.asBucket();
        filtered = result.alreadyFiltered;
      }
    }

    if (origData == null) return null;

    if (!mustCopy) return new CacheFetchResult(new ClientMetadata(mime), origData, filtered);

    Bucket newData = preferred;
    try {
      if (newData == null) newData = core.getTempBucketFactory().makeBucket(origData.size());
      BucketTools.copy(origData, newData);
      if (origData.size() != newData.size()) {
        LOG.info("Maybe it disappeared under us?");
        newData.free();
        return null;
      }
      return new CacheFetchResult(new ClientMetadata(mime), newData, filtered);
    } catch (IOException e) {
      // Maybe it was freed?
      LOG.info("Unable to copy data: {}", e, e);
      return null;
    }
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
    if (globalForeverClient == null) return null;
    ClientGet get = globalForeverClient.getCompletedRequest(key);
    if (get != null) {
      boolean filtered = get.filterData();
      Bucket origData = get.getBucket();
      Bucket newData = null;
      if (!mustCopy) newData = origData.createShadow();
      if (newData == null) {
        try {
          if (preferred != null) newData = preferred;
          else newData = core.getTempBucketFactory().makeBucket(origData.size());
          BucketTools.copy(origData, newData);
        } catch (IOException e) {
          LOG.error("Unable to copy data: {}", e, e);
          return null;
        }
      }
      return new CacheFetchResult(new ClientMetadata(get.getMIMEType()), newData, filtered);
    }
    return null;
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
    return globalRebootClient;
  }
}
