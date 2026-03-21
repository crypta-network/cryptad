package network.crypta.clients.fcp;

import java.io.IOException;
import java.net.Socket;
import java.util.Objects;
import network.crypta.io.NetworkInterface;
import network.crypta.io.SSLNetworkInterface;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.support.PriorityAwareExecutor;
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
 * thread, dispatching sockets to {@link FCPConnectionHandler} instances. Runtime lifecycle and
 * execution concerns are consumed through {@link RuntimePorts} so the listener does not depend on
 * daemon executor implementations directly. Configuration updates such as {@link
 * #updateBindTo(String)}, {@link #setBindTo(String, boolean)}, and {@link #setAllowedHosts(String)}
 * are delegated to the underlying interface when available and otherwise cached for later startup,
 * while SSL mode is tracked via static flag accessors.
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
  private static volatile boolean ssl = false;

  /** Owning server used to construct connection handlers for accepted sockets. */
  private final FCPServer server;

  /** Runtime SPI bridge supplying execution and lifecycle views for listener infrastructure. */
  private final RuntimePorts runtime;

  /** Executor adapter expected by the legacy network-interface factories. */
  private final PriorityAwareExecutor executor;

  /** Factory used to build short-lived interfaces for pre-start bind validation. */
  private final ValidationInterfaceFactory validationInterfaceFactory;

  /** TCP port to bind when creating the network interface. */
  private final int port;

  /** Whether the listener should start based on configuration. */
  private final boolean enabled;

  /** Allowed-hosts filter string provided at initialization time. */
  private String allowedHosts;

  /** Current bind address string used when initializing the interface. */
  private String bindTo;

  /** Active network interface, lazily created when the listener starts. */
  private NetworkInterface networkInterface;

  /**
   * Creates a listener bound to the provided server, runtime SPI bridge, and configuration
   * snapshot.
   *
   * <p>The constructor captures immutable configuration such as port, bind address, and allowed
   * hosts. It does not create sockets or start threads; callers must invoke {@link #maybeStart()}
   * to initialize the {@link NetworkInterface} and begin accepting connections.
   *
   * @param server the owning server that constructs connection handlers for clients.
   * @param runtime runtime SPI bridge supplying execution and lifecycle state used by the
   *     accept-loop.
   * @param config snapshot of listener configuration values at construction time.
   */
  FcpServerListener(FCPServer server, RuntimePorts runtime, FcpServerConfig config) {
    this(server, runtime, config, FcpServerListener::createValidationInterface);
  }

  /**
   * Creates a listener with an explicit factory for pre-start bind validation.
   *
   * <p>This overload exists so tests can supply deterministic validation interfaces without
   * touching the real network stack. Production callers should use {@link
   * #FcpServerListener(FCPServer, RuntimePorts, FcpServerConfig)}.
   *
   * @param server the owning server that constructs connection handlers for clients.
   * @param runtime runtime SPI bridge supplying execution and lifecycle state used by the
   *     accept-loop.
   * @param config snapshot of listener configuration values at construction time.
   * @param validationInterfaceFactory factory for temporary interfaces used to validate pre-start
   *     bind changes.
   */
  FcpServerListener(
      FCPServer server,
      RuntimePorts runtime,
      FcpServerConfig config,
      ValidationInterfaceFactory validationInterfaceFactory) {
    this.server = server;
    this.runtime = runtime;
    this.executor = FcpRuntimeAdapters.priorityAwareExecutor(runtime);
    this.validationInterfaceFactory = Objects.requireNonNull(validationInterfaceFactory);
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
   * Applies a new bind address to the active {@link NetworkInterface}, or validates it for startup.
   *
   * <p>If the listener has not yet created its {@link NetworkInterface}, this method validates the
   * provided bind string against a short-lived interface instance before caching it. Invalid
   * addresses are returned to the caller and are not retained. Once the interface exists, the
   * method forwards the raw bind string to {@link NetworkInterface#setBindTo(String, boolean)} and
   * returns any failed addresses.
   *
   * @param value comma-separated bind addresses or {@code null} to use defaults.
   * @param ignoreUnbindableIp6 whether IPv6 bind failures should be ignored when validating or
   *     applying the new bindings.
   * @return array of failed addresses, or {@code null} when all bindings succeed.
   */
  @SuppressWarnings({"SameParameterValue", "java:S1168"})
  String[] setBindTo(String value, boolean ignoreUnbindableIp6) {
    NetworkInterface netIface = networkInterface;
    if (netIface == null) {
      return validatePreStartBindTo(value, ignoreUnbindableIp6);
    }
    return netIface.setBindTo(value, ignoreUnbindableIp6);
  }

  @SuppressWarnings("java:S1168")
  private String[] validatePreStartBindTo(String value, boolean ignoreUnbindableIp6) {
    NetworkInterface validationInterface =
        validationInterfaceFactory.create(port, allowedHosts, executor);
    String[] failedAddresses = validationInterface.setBindTo(value, ignoreUnbindableIp6);
    boolean closed = closeValidationInterface(validationInterface, value);
    if (failedAddresses == null && closed) {
      bindTo = value;
      return null;
    }
    return failedAddresses == null ? validationFailure(value) : failedAddresses;
  }

  private boolean closeValidationInterface(NetworkInterface validationInterface, String value) {
    try {
      validationInterface.close();
      return true;
    } catch (IOException e) {
      LOG.warn("Failed to close temporary FCP bind validator for {}:{}", value, port, e);
      return false;
    }
  }

  private static String[] validationFailure(String value) {
    return new String[] {normalizeBindTo(value)};
  }

  private static String normalizeBindTo(String value) {
    return value == null || value.isEmpty() ? NetworkInterface.DEFAULT_BIND_TO : value;
  }

  private static NetworkInterface createValidationInterface(
      int port, String allowedHosts, PriorityAwareExecutor executor) {
    return ssl
        ? new ValidationSslNetworkInterface(port, allowedHosts, executor)
        : new ValidationNetworkInterface(port, allowedHosts, executor);
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
   * Returns the allowed-hosts string from the active interface, or the configured value when
   * absent.
   *
   * <p>If the listener has not yet created its {@link NetworkInterface}, this method returns the
   * listener's configured allowlist value so configuration callbacks can expose the current
   * in-memory setting before the socket is active.
   *
   * @return current allowlist string, or the configured value when no interface exists.
   */
  String getAllowedHosts() {
    NetworkInterface netIface = networkInterface;
    return netIface == null ? allowedHosts : netIface.getAllowedHosts();
  }

  /**
   * Applies a new allowed-hosts string to the active network interface and caches it for future
   * binds.
   *
   * <p>The method caches the value even when the interface has not yet been created, so later
   * listener initialization sees the latest configured allowlist. When the interface is active, it
   * delegates to {@link NetworkInterface#setAllowedHosts(String)}.
   *
   * @param value new allowlist string for filtering inbound connections.
   */
  void setAllowedHosts(String value) {
    this.allowedHosts = value;
    NetworkInterface netIface = networkInterface;
    if (netIface != null) {
      netIface.setAllowedHosts(value);
    }
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
          SSLNetworkInterface.createSsl(port, bindTo, allowedHosts, executor, true);
    } else {
      tempNetworkInterface = NetworkInterface.create(port, bindTo, allowedHosts, executor, true);
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
   * Accepts a single connection and starts a handler when the runtime is running.
   *
   * <p>If the runtime has not yet started, the method returns without accepting. Otherwise, it
   * accepts one socket and dispatches it to a new {@link FCPConnectionHandler} instance.
   */
  private void realRun() {
    if (!runtime.lifecycle().hasStarted()) return;
    Socket s = networkInterface.accept();
    FCPConnectionHandler ch = new FCPConnectionHandler(s, server);
    ch.start();
  }

  @FunctionalInterface
  interface ValidationInterfaceFactory {
    NetworkInterface create(int port, String allowedHosts, PriorityAwareExecutor executor);
  }

  private static final class ValidationNetworkInterface extends NetworkInterface {
    private ValidationNetworkInterface(
        int port, String allowedHosts, PriorityAwareExecutor executor) {
      super(port, allowedHosts, executor);
    }
  }

  private static final class ValidationSslNetworkInterface extends SSLNetworkInterface {
    private ValidationSslNetworkInterface(
        int port, String allowedHosts, PriorityAwareExecutor executor) {
      super(port, allowedHosts, executor);
    }
  }
}
