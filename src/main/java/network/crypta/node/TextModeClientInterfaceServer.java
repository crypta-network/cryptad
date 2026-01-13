package network.crypta.node;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketException;
import java.util.Arrays;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.config.Config;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.Option;
import network.crypta.config.SubConfig;
import network.crypta.crypt.RandomSource;
import network.crypta.crypt.SSL;
import network.crypta.io.NetworkInterface;
import network.crypta.io.SSLNetworkInterface;
import network.crypta.support.api.BooleanCallback;
import network.crypta.support.api.IntCallback;
import network.crypta.support.api.StringCallback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Text‑mode client interface (TMCI) server that accepts inbound TCP connections and dispatches each
 * session to a {@link TextModeClientInterface} handler.
 *
 * <p>This server is created from node configuration (the {@code console} section) and can be
 * enabled for local administration or remote access, subject to the {@code bindTo} and {@code
 * allowedHosts} constraints. When SSL support is available and enabled, the server binds using an
 * {@link SSLNetworkInterface}; otherwise it uses a plain {@link NetworkInterface}. The main loop
 * runs on the node's executor and performs a non-blocking accept with a short socket timeout to
 * allow responsive shutdown and reconfiguration checks.
 *
 * <p>A single instance maintains its listening parameters ({@code port}, {@code bindTo}, and {@code
 * allowedHosts}). Changes to these values are observed by the accept loop and will cause it to exit
 * so callers can reinitialize bindings as needed. Existing sessions continue to run on their
 * dedicated handler threads. The server itself is lightweight and intended to be started early in
 * the node lifecycle and stopped during shutdown.
 *
 * <ul>
 *   <li>Listens on a configured host/port with optional SSL.
 *   <li>Accepts each connection and runs a per-connection TMCI handler.
 *   <li>Uses short timeouts to remain responsive to configuration changes.
 * </ul>
 *
 * @see TextModeClientInterface
 * @see NetworkInterface
 * @see SSLNetworkInterface
 * @see Node
 * @see NodeClientCore
 */
public class TextModeClientInterfaceServer implements Runnable {
  private static final Logger LOG = LoggerFactory.getLogger(TextModeClientInterfaceServer.class);

  final RandomSource r;
  final Node n;
  final NodeClientCore core;
  final File downloadsDir;
  int port;
  String bindTo;
  String allowedHosts;
  boolean isEnabled;
  private static boolean ssl = false;
  final NetworkInterface networkInterface;

  /**
   * Result returned from {@link #maybeCreate(Node, NodeClientCore, Config)}.
   *
   * <p>The returned direct TMCI is created but not started. Callers should register it with {@link
   * ClientEndpoints#setDirectTMCI(TextModeClientInterface)} and schedule it on the node executor
   * only after {@link NodeClientCore#getEndpoints()} is fully initialized.
   *
   * @param server TMCI server instance, or {@code null} when TMCI is disabled.
   * @param directTMCI direct text-mode interface instance, or {@code null} when disabled.
   */
  public record InitResult(
      TextModeClientInterfaceServer server, TextModeClientInterface directTMCI) {}

  TextModeClientInterfaceServer(
      Node node, NodeClientCore core, int port, String bindTo, String allowedHosts) {
    this.n = node;
    this.core = n.services().clientCore();
    this.r = n.bootstrap().random();
    this.downloadsDir = core.getDownloadsDir();
    this.port = port;
    this.bindTo = bindTo;
    this.allowedHosts = allowedHosts;
    this.isEnabled = true;
    if (ssl) {
      networkInterface =
          SSLNetworkInterface.create(port, bindTo, allowedHosts, n.network().executor(), true);
    } else {
      networkInterface =
          NetworkInterface.create(port, bindTo, allowedHosts, n.network().executor(), true);
    }
  }

  void start() {
    LOG.info("TMCI started on {}:{}", networkInterface.getAllowedHosts(), port);
    TextModeClientInterfaceConsole.print(
        "TMCI started on " + networkInterface.getAllowedHosts() + ':' + port);

    n.network().executor().execute(this, "Text mode client interface");
  }

  /**
   * Creates TMCI endpoints according to the provided configuration.
   *
   * <p>This method wires the {@code console} sub-configuration, registers relevant options ({@code
   * enabled}, {@code ssl}, {@code bindTo}, {@code allowedHosts}, {@code port}, and {@code
   * directEnabled}), and conditionally instantiates the network-backed server. The returned init
   * result includes a server instance when TMCI is enabled, or {@code null} when disabled. When
   * {@code directEnabled} is set, a direct in-process text interface is created using the process
   * input/output streams; callers are responsible for registering and starting it after the core
   * endpoints are assigned. The returned server is not started automatically; callers should invoke
   * {@link #start()} when a non-null value is returned.
   *
   * <pre>{@code
   * var init = TextModeClientInterfaceServer.maybeCreate(node, core, config);
   * if (init.server() != null) {
   *   init.server().start();
   * }
   * }</pre>
   *
   * @param node the owning {@link Node}; provides the executor and random source used by handlers;
   *     must not be {@code null}.
   * @param core the {@link NodeClientCore} for constructing clients and accessing configuration;
   *     must not be {@code null}.
   * @param config the root {@link Config} used to obtain the {@code console} sub-config and read
   *     options that control TMCI behavior; must not be {@code null}.
   * @return a result containing the configured server and optional direct TMCI instance.
   */
  public static InitResult maybeCreate(Node node, NodeClientCore core, Config config) {

    TextModeClientInterfaceServer server = null;
    TextModeClientInterface directTMCI = null;

    SubConfig tmciConfig = config.createSubConfig("console");

    tmciConfig.register(
        "enabled",
        false,
        new Option.Meta(
            1,
            true,
            true /* only because can't be changed on the fly */,
            "TextModeClientInterfaceServer.enabled",
            "TextModeClientInterfaceServer.enabledLong"),
        new TMCIEnabledCallback(core));
    tmciConfig.register(
        "ssl",
        false,
        new Option.Meta(
            1,
            true,
            true,
            "TextModeClientInterfaceServer.ssl",
            "TextModeClientInterfaceServer.sslLong"),
        new TMCISSLCallback());
    tmciConfig.register(
        "bindTo",
        NetworkInterface.DEFAULT_BIND_TO,
        new Option.Meta(
            2,
            true,
            false,
            "TextModeClientInterfaceServer.bindTo",
            "TextModeClientInterfaceServer.bindToLong"),
        new TMCIBindtoCallback(core));
    tmciConfig.register(
        "allowedHosts",
        NetworkInterface.DEFAULT_BIND_TO,
        new Option.Meta(
            2,
            true,
            false,
            "TextModeClientInterfaceServer.allowedHosts",
            "TextModeClientInterfaceServer.allowedHostsLong"),
        new TMCIAllowedHostsCallback(core));
    tmciConfig.register(
        "port",
        2323,
        new Option.Meta(
            1,
            true,
            false,
            "TextModeClientInterfaceServer.telnetPortNumber",
            "TextModeClientInterfaceServer.telnetPortNumberLong"),
        new TCMIPortNumberCallback(core),
        false);
    tmciConfig.register(
        "directEnabled",
        false,
        new Option.Meta(
            1,
            true,
            false,
            "TextModeClientInterfaceServer.enableInputOutput",
            "TextModeClientInterfaceServer.enableInputOutputLong"),
        new TMCIDirectEnabledCallback(core));

    boolean tmciEnabled = tmciConfig.getBoolean("enabled");
    int port = tmciConfig.getInt("port");
    String bindIp = tmciConfig.getString("bindTo");
    String allowedHosts = tmciConfig.getString("allowedHosts");
    boolean direct = tmciConfig.getBoolean("directEnabled");
    if (SSL.available()) {
      ssl = tmciConfig.getBoolean("ssl");
    }

    if (tmciEnabled)
      server = new TextModeClientInterfaceServer(node, core, port, bindIp, allowedHosts);

    if (direct) {
      HighLevelSimpleClient client =
          core.makeClient(RequestStarter.INTERACTIVE_PRIORITY_CLASS, true, false);
      directTMCI =
          new TextModeClientInterface(
              node,
              core,
              client,
              core.getDownloadsDir(),
              TextModeClientInterfaceConsole.in(),
              TextModeClientInterfaceConsole.out());
    }

    tmciConfig.finishedInitialization();

    return new InitResult(server, directTMCI); // caller must call start()
  }

  static class TMCIEnabledCallback extends BooleanCallback {

    final NodeClientCore core;

    TMCIEnabledCallback(NodeClientCore core) {
      this.core = core;
    }

    @Override
    public Boolean get() {
      ClientEndpoints endpoints = core.getEndpoints();
      return endpoints != null && endpoints.getTextModeClientInterface() != null;
    }

    @Override
    public void set(Boolean val) throws InvalidConfigValueException {
      if (get().equals(val)) return;
      // Not supported: cannot be updated on the fly (see bug #122)
      throw new InvalidConfigValueException("Cannot be updated on the fly");
    }

    @Override
    public boolean isReadOnly() {
      return true;
    }
  }

  static class TMCISSLCallback extends BooleanCallback {

    @Override
    public Boolean get() {
      return ssl;
    }

    @Override
    public void set(Boolean val) throws InvalidConfigValueException {
      if (get().equals(val)) return;
      if (!SSL.available()) {
        throw new InvalidConfigValueException("Enable SSL support before use ssl with TMCI");
      }
      setSsl(val);
      throw new InvalidConfigValueException("Cannot change SSL on the fly, please restart freenet");
    }

    @Override
    public boolean isReadOnly() {
      return true;
    }

    private static synchronized void setSsl(boolean value) {
      ssl = value;
    }
  }

  static class TMCIDirectEnabledCallback extends BooleanCallback {

    final NodeClientCore core;

    TMCIDirectEnabledCallback(NodeClientCore core) {
      this.core = core;
    }

    @Override
    public Boolean get() {
      ClientEndpoints endpoints = core.getEndpoints();
      return endpoints != null && endpoints.getDirectTMCI() != null;
    }

    @Override
    public void set(Boolean val) throws InvalidConfigValueException {
      if (get().equals(val)) return;
      // Not supported: cannot be updated on the fly (see bug #122)
      throw new InvalidConfigValueException("Cannot be updated on the fly");
    }

    @Override
    public boolean isReadOnly() {
      return true;
    }
  }

  static class TMCIBindtoCallback extends StringCallback {

    final NodeClientCore core;

    TMCIBindtoCallback(NodeClientCore core) {
      this.core = core;
    }

    @Override
    public String get() {
      ClientEndpoints endpoints = core.getEndpoints();
      TextModeClientInterfaceServer server =
          endpoints == null ? null : endpoints.getTextModeClientInterface();
      if (server != null) {
        return server.bindTo;
      }
      return NetworkInterface.DEFAULT_BIND_TO;
    }

    @Override
    public void set(String val) throws InvalidConfigValueException {
      if (val.equals(get())) return;
      String[] failedAddresses =
          core.getEndpoints().getTextModeClientInterface().networkInterface.setBindTo(val, false);
      if (failedAddresses != null) {
        // This is an advanced option for reasons of reducing clutter,
        // but it is expected to be used by regular users, not devs.
        // So we translate the error messages.
        throw new InvalidConfigValueException(
            "could not change bind to: " + Arrays.toString(failedAddresses));
      }
      core.getEndpoints().getTextModeClientInterface().bindTo = val;
    }
  }

  static class TMCIAllowedHostsCallback extends StringCallback {

    private final NodeClientCore core;

    public TMCIAllowedHostsCallback(NodeClientCore core) {
      this.core = core;
    }

    @Override
    public String get() {
      ClientEndpoints endpoints = core.getEndpoints();
      TextModeClientInterfaceServer server =
          endpoints == null ? null : endpoints.getTextModeClientInterface();
      if (server != null) {
        return server.allowedHosts;
      }
      return NetworkInterface.DEFAULT_BIND_TO;
    }

    @Override
    public void set(String val) throws InvalidConfigValueException {
      if (!val.equals(get())) {
        TextModeClientInterfaceServer server = core.getEndpoints().getTextModeClientInterface();
        if (server != null) {
          try {
            server.networkInterface.setAllowedHosts(val);
          } catch (IllegalArgumentException e) {
            throw new InvalidConfigValueException(e);
          }
          server.allowedHosts = val;
        } else
          throw new InvalidConfigValueException(
              "Setting allowedHosts for TMCI (console) server when TMCI is disabled");
      }
    }
  }

  static class TCMIPortNumberCallback extends IntCallback {

    final NodeClientCore core;

    TCMIPortNumberCallback(NodeClientCore core) {
      this.core = core;
    }

    @Override
    public Integer get() {
      ClientEndpoints endpoints = core.getEndpoints();
      TextModeClientInterfaceServer server =
          endpoints == null ? null : endpoints.getTextModeClientInterface();
      if (server != null) {
        return server.port;
      }
      return 2323;
    }

    // Not implemented: port updates handled elsewhere
    @Override
    public void set(Integer val) throws InvalidConfigValueException {
      if (get().equals(val)) return;
      core.getEndpoints().getTextModeClientInterface().setPort(val);
    }
  }

  /**
   * Runs the accept loop for the TMCI server until disabled or interrupted.
   *
   * <p>The loop uses a short socket timeout to periodically check for configuration changes and the
   * enabled flag. When {@code port} or {@code bindTo} differ from the values used to initialize the
   * current listener, the loop exits, closes the network interface, and immediately re-enters from
   * the top to observe the updated parameters. Each accepted socket is handed off to a {@link
   * TextModeClientInterface} that is executed on the node's executor.
   */
  @Override
  public void run() {
    while (true) {
      int curPort = port;
      String tempBindTo = this.bindTo;
      if (!configureTimeout()) {
        return;
      }
      acceptLoop(curPort, tempBindTo);
      closeNetworkInterfaceQuietly();
    }
  }

  private boolean configureTimeout() {
    try {
      networkInterface.setSoTimeout(1000);
      return true;
    } catch (SocketException e1) {
      LOG.error("Could not set timeout: {}", e1.getMessage(), e1);
      return false;
    }
  }

  private void acceptLoop(int curPort, String tempBindTo) {
    while (isEnabled) {
      if (port != curPort || !(this.bindTo.equals(tempBindTo))) break;
      try {
        Socket s = networkInterface.accept();
        if (s != null) { // non-timeout
          handleAcceptedSocket(s);
        }
      } catch (SocketException e) {
        LOG.error("Socket error : {}", e.getMessage(), e);
      } catch (IOException e) {
        LOG.error("TMCI failed to accept socket: {}", e.getMessage(), e);
      }
    }
  }

  private void handleAcceptedSocket(Socket s) throws IOException {
    InputStream in = s.getInputStream();
    OutputStream out = s.getOutputStream();
    TextModeClientInterface tmci = new TextModeClientInterface(this, in, out);
    n.network().executor().execute(tmci, "Text mode client interface handler for " + s.getPort());
  }

  private void closeNetworkInterfaceQuietly() {
    try {
      networkInterface.close();
    } catch (IOException e) {
      LOG.error("Error shuting down TMCI", e);
    }
  }

  /**
   * Sets the TCP port number used when accepting new TMCI connections.
   *
   * <p>The change is observed by the accept loop; existing client sessions are not affected. The
   * provided value should be a valid TCP port in the range 1–65535. No validation is performed by
   * this method.
   *
   * @param val the new listening port number to use for future accepts; typical values are in the
   *     unprivileged range (>= 1024).
   */
  public void setPort(int val) {
    port = val;
  }
}
