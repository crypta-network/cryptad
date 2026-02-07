package network.crypta.clients.fcp;

import java.net.Socket;
import network.crypta.io.NetworkInterface;
import network.crypta.io.SSLNetworkInterface;
import network.crypta.node.Node;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.tanukisoftware.wrapper.WrapperManager;

/**
 * Runs the FCP listener loop and manages the active {@link NetworkInterface} binding.
 *
 * <p>This helper encapsulates the network-facing responsibilities of {@link FCPServer}, including
 * creating the listening {@link NetworkInterface}, binding it to the configured addresses, and
 * accepting incoming connections. Callers typically construct the listener during server
 * initialization and invoke {@link #maybeStart()} once; the accept-loop then runs on a daemon
 * thread, dispatching sockets to {@link FCPConnectionHandler} instances. Configuration updates such
 * as {@link #updateBindTo(String)} and {@link #setAllowedHosts(String)} are delegated to the
 * underlying interface when available, while SSL mode is tracked via static flag accessors.
 *
 * <p>The listener is intentionally conservative about re-binding: it caches the created interface
 * and only creates a new one once per instance. Shutdown handling relies on the Tanuki Wrapper
 * shutdown hook check to exit the accept-loop safely. The class is not thread-safe for arbitrary
 * mutation; it assumes a single initialization path and a single accept-loop thread.
 *
 * <ul>
 *   <li>Creates the appropriate {@link NetworkInterface} or {@link SSLNetworkInterface}.
 *   <li>Starts the accept-loop and hands sockets to {@link FCPConnectionHandler}.
 *   <li>Exposes helpers for bind address and allowlist updates.
 * </ul>
 *
 * @see FCPServer
 * @see NetworkInterface
 */
final class FcpServerListener implements Runnable {
  /** Logger scoped to the listener lifecycle and accept loop. */
  private static final Logger LOG = LoggerFactory.getLogger(FcpServerListener.class);

  /** Tracks whether SSL should be used when creating the network interface. */
  private static boolean ssl = false;

  /** Owning server used to construct connection handlers for accepted sockets. */
  private final FCPServer server;

  /** Node used to get executors and startup lifecycle information. */
  private final Node node;

  /** TCP port to bind when creating the network interface. */
  private final int port;

  /** Whether the listener should start based on configuration. */
  private final boolean enabled;

  /** Allowed-hosts filter string provided at initialization time. */
  private final String allowedHosts;

  /** Current bind address string used when initializing the interface. */
  private String bindTo;

  /** Active network interface, lazily created when the listener starts. */
  private NetworkInterface networkInterface;

  /**
   * Creates a listener bound to the provided server, node, and configuration snapshot.
   *
   * <p>The constructor captures immutable configuration such as port, bind address, and allowed
   * hosts. It does not create sockets or start threads; callers must invoke {@link #maybeStart()}
   * to initialize the {@link NetworkInterface} and begin accepting connections.
   *
   * @param server the owning server that constructs connection handlers for clients.
   * @param node node supplying executors and lifecycle state used by the accept-loop.
   * @param config snapshot of listener configuration values at construction time.
   */
  FcpServerListener(FCPServer server, Node node, FcpServerConfig config) {
    this.server = server;
    this.node = node;
    this.port = config.port();
    this.enabled = config.enabled();
    this.allowedHosts = config.allowedHosts();
    this.bindTo = config.bindTo();
  }

  /**
   * Reports whether SSL is enabled for later network interface creation.
   *
   * <p>This flag is static because the SSL setting is global to the FCP listener. It affects only
   * newly created {@link NetworkInterface} instances; existing interfaces remain unchanged.
   *
   * @return {@code true} when SSL should be used for future binds, {@code false} otherwise.
   */
  static boolean isSslEnabled() {
    return ssl;
  }

  /**
   * Updates the global SSL enablement flag for future interface creation.
   *
   * <p>Callers should treat this as a configuration hook rather than a live toggle. Changing the
   * value does not rebind existing sockets; it only influences the next call to {@link
   * NetworkInterface#create(int, String, String, network.crypta.support.PriorityAwareExecutor,
   * boolean)} or {@link SSLNetworkInterface#create(int, String, String,
   * network.crypta.support.PriorityAwareExecutor, boolean)}.
   *
   * @param enabled {@code true} to create SSL interfaces, {@code false} otherwise.
   */
  static void setSslEnabled(boolean enabled) {
    ssl = enabled;
  }

  /**
   * Delegates to the underlying {@link NetworkInterface} to update binding addresses.
   *
   * <p>This method assumes a listener has already been started and will throw a {@link
   * NullPointerException} if the interface has not been initialized. It forwards the raw bind
   * string to {@link NetworkInterface#setBindTo(String, boolean)} and returns any failed addresses.
   *
   * @param value comma-separated bind addresses or {@code null} to use defaults.
   * @param update whether to update acceptors immediately for the new bindings.
   * @return array of failed addresses, or {@code null} when all bindings succeed.
   */
  @SuppressWarnings("SameParameterValue")
  String[] setBindTo(String value, boolean update) {
    return networkInterface.setBindTo(value, update);
  }

  /**
   * Updates the cached bind address string used for future interface creation.
   *
   * <p>This method does not rebind sockets or modify the active interface. It simply updates the
   * stored value used when {@link #maybeStart()} or a future rebinding occurs.
   *
   * @param value new bind address string, typically a comma-separated list.
   */
  void updateBindTo(String value) {
    this.bindTo = value;
  }

  /**
   * Returns the allowed-hosts string from the active interface, or the default when absent.
   *
   * <p>If the listener has not yet created its {@link NetworkInterface}, this method returns {@link
   * NetworkInterface#DEFAULT_BIND_TO} to preserve legacy behavior during configuration discovery.
   *
   * @return current allowlist string, or the default bind list when no interface exists.
   */
  String getAllowedHosts() {
    NetworkInterface netIface = networkInterface;
    return netIface == null ? NetworkInterface.DEFAULT_BIND_TO : netIface.getAllowedHosts();
  }

  /**
   * Applies a new allowed-hosts string to the active network interface.
   *
   * <p>The method assumes the listener has been initialized and delegates to {@link
   * NetworkInterface#setAllowedHosts(String)}. It does not validate the input beyond the interface
   * implementation.
   *
   * @param value new allowlist string for filtering inbound connections.
   */
  void setAllowedHosts(String value) {
    networkInterface.setAllowedHosts(value);
  }

  /**
   * Lazily constructs the {@link NetworkInterface} if it has not been created yet.
   *
   * <p>The method chooses between SSL and plain interfaces based on the static SSL flag, binds to
   * the configured addresses, and caches the created instance. Subsequent calls are no-ops.
   */
  private void maybeGetNetworkInterface() {
    if (this.networkInterface != null) return;

    NetworkInterface tempNetworkInterface;
    if (ssl) {
      tempNetworkInterface =
          SSLNetworkInterface.createSsl(
              port, bindTo, allowedHosts, node.network().executor(), true);
    } else {
      tempNetworkInterface =
          NetworkInterface.create(port, bindTo, allowedHosts, node.network().executor(), true);
    }

    this.networkInterface = tempNetworkInterface;
  }

  /**
   * Starts the listener thread when enabled, creating the network interface if needed.
   *
   * <p>When disabled, the method clears the cached interface so no sockets are bound. When enabled,
   * it creates the interface if absent, logs startup, and launches the accept-loop on a daemon
   * thread. Repeated calls are safe and will not recreate the interface once initialized.
   */
  void maybeStart() {
    if (this.enabled) {
      maybeGetNetworkInterface();

      LOG.info("Starting FCP server on {}:{}.", bindTo, port);

      if (this.networkInterface != null) {
        Thread t = new Thread(server, "FCP server");
        t.setDaemon(true);
        t.start();
      }
    } else {
      LOG.info("Not starting FCP server as it's disabled");
      this.networkInterface = null;
    }
  }

  /**
   * Runs the accept-loop until shutdown is requested.
   *
   * <p>The loop waits for the network interface to bind, accepts incoming sockets, and delegates
   * each to {@link FCPConnectionHandler}. Any exception during binding or accept is logged, and the
   * loop retries unless the Wrapper shutdown hook has been triggered.
   */
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

  /**
   * Accepts a single connection and starts a handler when the node is running.
   *
   * <p>If the node has not yet started, the method returns without accepting. Otherwise, it accepts
   * one socket and dispatches it to a new {@link FCPConnectionHandler} instance.
   */
  private void realRun() {
    if (!node.isHasStarted()) return;
    Socket s = networkInterface.accept();
    FCPConnectionHandler ch = new FCPConnectionHandler(s, server);
    ch.start();
  }
}
