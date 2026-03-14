package network.crypta.clients.fcp;

import java.util.Arrays;
import network.crypta.config.Config;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.Option;
import network.crypta.config.SubConfig;
import network.crypta.crypt.SSL;
import network.crypta.io.NetworkInterface;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.support.api.BooleanCallback;
import network.crypta.support.api.IntCallback;
import network.crypta.support.api.StringCallback;

/**
 * Registers FCP server configuration options and constructs a configured {@link FCPServer}.
 *
 * <p>This helper centralizes the wiring between the {@code fcp} {@link SubConfig} and the runtime
 * components that back the FCP listener and request lifecycle. It installs callbacks for mutable
 * configuration values (such as bind address and allowed hosts), preserves the immutable defaults
 * captured in {@link FcpServerConfig}, and creates the server instance that other subsystems use.
 * The method is typically invoked during node startup or endpoint initialization and is expected to
 * run once per process. It performs no network binding or background thread creation; callers still
 * invoke {@link FCPServer#maybeStart()} to begin accepting connections.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Registering the {@code fcp} option set with deterministic ordering and defaults.
 *   <li>Binding config callbacks that guard runtime changes and apply validation.
 *   <li>Building the {@link FCPServer} with dependencies from the owning {@link Node}.
 * </ul>
 *
 * @see FCPServer
 * @see FcpServerConfig
 * @see FcpServerListener
 */
final class FcpServerConfigRegistrar {
  /** Creates a registrar utility; instances are not used. */
  private FcpServerConfigRegistrar() {}

  /**
   * Registers the FCP sub-configuration and returns a fully wired {@link FCPServer} instance.
   *
   * <p>The method creates (or retrieves) a {@link SubConfig} named {@code fcp}, registers all FCP
   * options with their defaults, and attaches callbacks that enforce non-mutable fields such as the
   * port and SSL toggle. If SSL support is available, the persisted SSL value is applied to the
   * listener state; otherwise the setting remains disabled until restart. After building the {@link
   * FcpServerConfig} and dependency container, the returned server is created and the config is
   * marked initialized so later user changes trigger callbacks.
   *
   * <pre>{@code
   * Config config = new Config();
   * FCPServer server = FcpServerConfigRegistrar.maybeCreate(node, core, runtimePorts, config,
   * root);
   * server.maybeStart();
   * }</pre>
   *
   * @param node the owning node providing executors and core services for the server.
   * @param core client core used for endpoint access and persisted settings lookups.
   * @param runtimePorts runtime SPI bridge passed to the created server.
   * @param config root configuration registry where the {@code fcp} subsection is registered.
   * @param root persistent request root used to wire global request queues.
   * @return configured {@link FCPServer} instance ready for {@link FCPServer#maybeStart()}.
   */
  static FCPServer maybeCreate(
      Node node,
      NodeClientCore core,
      RuntimePorts runtimePorts,
      Config config,
      PersistentRequestRoot root) {
    SubConfig fcpConfig = config.createSubConfig("fcp");
    short sortOrder = 0;
    fcpConfig.register(
        "enabled",
        true,
        new Option.Meta(sortOrder++, true, false, "FcpServer.isEnabled", "FcpServer.isEnabledLong"),
        new FCPEnabledCallback(core));
    fcpConfig.register(
        "ssl",
        false,
        new Option.Meta(sortOrder++, true, true, "FcpServer.ssl", "FcpServer.sslLong"),
        new FCPSSLCallback());
    fcpConfig.register(
        "port",
        FCPServer.DEFAULT_FCP_PORT /* anagram of 1984, and 1000 up from the old number */,
        new Option.Meta(2, true, true, "FcpServer.portNumber", "FcpServer.portNumberLong"),
        new FCPPortNumberCallback(core),
        false);
    fcpConfig.register(
        "bindTo",
        NetworkInterface.DEFAULT_BIND_TO,
        new Option.Meta(sortOrder++, true, true, "FcpServer.bindTo", "FcpServer.bindToLong"),
        new FCPBindtoCallback(core));
    fcpConfig.register(
        "allowedHosts",
        NetworkInterface.DEFAULT_BIND_TO,
        new Option.Meta(
            sortOrder++, true, true, "FcpServer.allowedHosts", "FcpServer.allowedHostsLong"),
        new FCPAllowedHostsCallback(core));
    fcpConfig.register(
        "allowedHostsFullAccess",
        NetworkInterface.DEFAULT_BIND_TO,
        new Option.Meta(
            sortOrder++,
            true,
            true,
            "FcpServer.allowedHostsFullAccess",
            "FcpServer.allowedHostsFullAccessLong"),
        new FCPAllowedHostsFullAccessCallback(core));

    AssumeDDADownloadIsAllowedCallback cb4 = new AssumeDDADownloadIsAllowedCallback();
    AssumeDDAUploadIsAllowedCallback cb5 = new AssumeDDAUploadIsAllowedCallback();
    NeverDropAMessageCallback cb6 = new NeverDropAMessageCallback();
    MaxMessageQueueLengthCallback cb7 = new MaxMessageQueueLengthCallback();
    fcpConfig.register(
        "assumeDownloadDDAIsAllowed",
        false,
        new Option.Meta(
            sortOrder++,
            true,
            false,
            "FcpServer.assumeDownloadDDAIsAllowed",
            "FcpServer.assumeDownloadDDAIsAllowedLong"),
        cb4);
    fcpConfig.register(
        "assumeUploadDDAIsAllowed",
        false,
        new Option.Meta(
            sortOrder++,
            true,
            false,
            "FcpServer.assumeUploadDDAIsAllowed",
            "FcpServer.assumeUploadDDAIsAllowedLong"),
        cb5);
    fcpConfig.register(
        "maxMessageQueueLength",
        1024,
        new Option.Meta(
            sortOrder++,
            true,
            false,
            "FcpServer.maxMessageQueueLength",
            "FcpServer.maxMessageQueueLengthLong"),
        cb7,
        false);
    fcpConfig.register(
        "neverDropAMessage",
        false,
        new Option.Meta(
            sortOrder,
            true,
            false,
            "FcpServer.neverDropAMessage",
            "FcpServer.neverDropAMessageLong"),
        cb6);

    if (SSL.available()) {
      FcpServerListener.setSslEnabled(fcpConfig.getBoolean("ssl"));
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
    FcpServerDependencies dependencies = new FcpServerDependencies(node, core, runtimePorts, root);
    FCPServer fcp = new FCPServer(serverConfig, dependencies);

    cb4.server = fcp;
    cb5.server = fcp;
    cb6.server = fcp;
    cb7.server = fcp;

    fcpConfig.finishedInitialization();
    return fcp;
  }

  /** Callback that exposes the read-only FCP port configuration. */
  static class FCPPortNumberCallback extends IntCallback {

    /** Node core used to access the active endpoint configuration. */
    private final NodeClientCore node;

    /**
     * Creates a callback bound to the provided node client core.
     *
     * @param node client core supplying the current endpoint configuration.
     */
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

  /** Callback that exposes the read-only enabled flag for networked FCP. */
  static class FCPEnabledCallback extends BooleanCallback {

    /** Node core used to access the endpoint state for the enabled flag. */
    final NodeClientCore node;

    /**
     * Creates a callback bound to the provided node client core.
     *
     * @param node client core supplying the current endpoint configuration.
     */
    FCPEnabledCallback(NodeClientCore node) {
      this.node = node;
    }

    @Override
    public Boolean get() {
      return node.getEndpoints().getFCPServer().enabled;
    }

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

  /** Callback that reports and guards the SSL enablement flag for FCP. */
  static class FCPSSLCallback extends BooleanCallback {

    /** Creates a callback instance for SSL configuration handling. */
    FCPSSLCallback() {}

    /**
     * Updates the SSL flag when available and refuses runtime changes.
     *
     * @param val desired SSL enablement state for the listener.
     * @throws InvalidConfigValueException when SSL is unavailable or a restart is required.
     */
    private static void updateSslFlag(boolean val) throws InvalidConfigValueException {
      if (FcpServerListener.isSslEnabled() == val) {
        return;
      }
      if (!SSL.available()) {
        throw new InvalidConfigValueException("Enable SSL support before use ssl with FCP");
      }
      FcpServerListener.setSslEnabled(val);
      throw new InvalidConfigValueException("Cannot change SSL on the fly, please restart freenet");
    }

    @Override
    public Boolean get() {
      return FcpServerListener.isSslEnabled();
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

  /** Callback that exposes the bind address and updates the listener when modified. */
  static class FCPBindtoCallback extends StringCallback {

    /** Node core used to resolve the active FCP server instance. */
    final NodeClientCore node;

    /**
     * Creates a callback bound to the provided node client core.
     *
     * @param node client core supplying the current endpoint configuration.
     */
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

        String[] failedAddresses = server.listener().setBindTo(val, true);
        if (failedAddresses != null) {
          server.listener().setBindTo(oldValue, true);
          throw new InvalidConfigValueException(
              NodeL10n.getBase()
                  .getString(
                      "FcpServer.couldNotChangeBindTo",
                      "failedInterfaces",
                      Arrays.toString(failedAddresses)));
        }

        server.listener().setBindTo(val, true);
        server.listener().updateBindTo(val);
        server.bindTo = val;
      }
    }
  }

  /** Callback that reads or updates the allowed-hosts list for the FCP listener. */
  static class FCPAllowedHostsCallback extends StringCallback {

    /** Node core used to resolve the active FCP server instance. */
    private final NodeClientCore node;

    /**
     * Creates a callback bound to the provided node client core.
     *
     * @param node client core supplying the current endpoint configuration.
     */
    public FCPAllowedHostsCallback(NodeClientCore node) {
      this.node = node;
    }

    @Override
    public String get() {
      FCPServer server = node.getEndpoints().getFCPServer();
      if (server == null) return NetworkInterface.DEFAULT_BIND_TO;
      return server.listener().getAllowedHosts();
    }

    @Override
    public void set(String val) throws InvalidConfigValueException {
      if (!val.equals(get())) {
        try {
          node.getEndpoints().getFCPServer().listener().setAllowedHosts(val);
        } catch (IllegalArgumentException e) {
          throw new InvalidConfigValueException(e);
        }
      }
    }
  }

  /** Callback that manages the full-access allowlist for privileged operations. */
  static class FCPAllowedHostsFullAccessCallback extends StringCallback {
    /** Node core used to resolve the active FCP server instance. */
    private final NodeClientCore node;

    /**
     * Creates a callback bound to the provided node client core.
     *
     * @param node client core supplying the current endpoint configuration.
     */
    public FCPAllowedHostsFullAccessCallback(NodeClientCore node) {
      this.node = node;
    }

    @Override
    public String get() {
      return node.getEndpoints().getFCPServer().getAllowedHostsFullAccess().getAllowedHosts();
    }

    @Override
    public void set(String val) throws InvalidConfigValueException {
      if (!val.equals(get())) {
        try {
          node.getEndpoints().getFCPServer().getAllowedHostsFullAccess().setAllowedHosts(val);
        } catch (IllegalArgumentException e) {
          throw new InvalidConfigValueException(e);
        }
      }
    }
  }

  /** Callback that toggles whether download DDA is treated as pre-approved. */
  static class AssumeDDADownloadIsAllowedCallback extends BooleanCallback {
    /** Server instance that owns the download DDA policy flag. */
    FCPServer server;

    /** Creates a callback instance for download DDA defaults. */
    AssumeDDADownloadIsAllowedCallback() {}

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

  /** Callback that toggles whether upload DDA is treated as pre-approved. */
  static class AssumeDDAUploadIsAllowedCallback extends BooleanCallback {
    /** Server instance that owns the upload DDA policy flag. */
    FCPServer server;

    /** Creates a callback instance for upload DDA defaults. */
    AssumeDDAUploadIsAllowedCallback() {}

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

  /** Callback that controls whether outbound message queues may drop entries. */
  static class NeverDropAMessageCallback extends BooleanCallback {
    /** Server instance that owns the queue retention flag. */
    FCPServer server;

    /** Creates a callback instance for queue retention defaults. */
    NeverDropAMessageCallback() {}

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

  /** Callback that exposes the maximum number of messages queued per connection. */
  static class MaxMessageQueueLengthCallback extends IntCallback {
    /** Server instance that owns the queue length limit. */
    FCPServer server;

    /** Creates a callback instance for queue length defaults. */
    MaxMessageQueueLengthCallback() {}

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
}
