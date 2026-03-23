package network.crypta.clients.fcp;

import java.util.Arrays;
import network.crypta.config.BooleanCallback;
import network.crypta.config.Config;
import network.crypta.config.IntCallback;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.Option;
import network.crypta.config.StringCallback;
import network.crypta.config.SubConfig;
import network.crypta.io.NetworkInterface;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.runtime.SSL;

/**
 * Registers FCP server configuration options and constructs a configured {@link FCPServer}.
 *
 * <p>This helper centralizes the wiring between the {@code fcp} {@link SubConfig} and the runtime
 * components that back the FCP listener and request lifecycle. It installs callbacks for mutable
 * configuration values, preserves the configured defaults until the server is available, and
 * creates the server instance that other subsystems use. The method is typically invoked during
 * node startup or endpoint initialization and is expected to run once per process. It performs no
 * network binding or background thread creation; callers still invoke {@link
 * FCPServer#maybeStart()} to begin accepting connections.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Registering the {@code fcp} option set with deterministic ordering and defaults.
 *   <li>Binding config callbacks directly to the created {@link FCPServer}.
 *   <li>Building the server with the already-constructed dependency bundle.
 * </ul>
 *
 * @see FCPServer
 * @see FcpServerConfig
 * @see FcpServerListener
 */
final class FcpServerConfigRegistrar {
  private static final String ENABLED_OPTION = "enabled";
  private static final String BIND_TO_OPTION = "bindTo";
  private static final String ALLOWED_HOSTS_OPTION = "allowedHosts";
  private static final String ALLOWED_HOSTS_FULL_ACCESS_OPTION = "allowedHostsFullAccess";

  /** Creates a registrar utility; instances are not used. */
  private FcpServerConfigRegistrar() {}

  /**
   * Registers the FCP sub-configuration and returns a fully wired {@link FCPServer} instance.
   *
   * <p>The method creates (or retrieves) a {@link SubConfig} named {@code fcp}, registers all FCP
   * options with their defaults, and attaches callbacks that guard runtime changes. If SSL support
   * is available, the persisted SSL value is applied to the listener state; otherwise the setting
   * remains disabled until restart. After building the {@link FcpServerConfig} and server
   * dependency bundle, the returned server is created and the config is marked initialized so later
   * user changes trigger callbacks.
   *
   * @param dependencies pre-built runtime and persistence dependencies for the server.
   * @param config root configuration registry where the {@code fcp} subsection is registered.
   * @return configured {@link FCPServer} instance ready for {@link FCPServer#maybeStart()}.
   */
  static FCPServer maybeCreate(FcpServerDependencies dependencies, Config config) {
    SubConfig fcpConfig = config.createSubConfig("fcp");
    short sortOrder = 0;

    FCPEnabledCallback enabledCallback = new FCPEnabledCallback(false);
    fcpConfig.register(
        ENABLED_OPTION,
        true,
        new Option.Meta(sortOrder++, true, false, "FcpServer.isEnabled", "FcpServer.isEnabledLong"),
        enabledCallback);
    enabledCallback.setInitialEnabled(fcpConfig.getBoolean(ENABLED_OPTION));

    fcpConfig.register(
        "ssl",
        false,
        new Option.Meta(sortOrder++, true, true, "FcpServer.ssl", "FcpServer.sslLong"),
        new FCPSSLCallback());
    FCPPortNumberCallback portCallback = new FCPPortNumberCallback(FCPServer.DEFAULT_FCP_PORT);
    fcpConfig.register(
        "port",
        FCPServer.DEFAULT_FCP_PORT /* anagram of 1984, and 1000 up from the old number */,
        new Option.Meta(2, true, true, "FcpServer.portNumber", "FcpServer.portNumberLong"),
        portCallback,
        false);
    portCallback.setInitialPort(fcpConfig.getInt("port"));

    FCPBindtoCallback bindToCallback = new FCPBindtoCallback(NetworkInterface.DEFAULT_BIND_TO);
    fcpConfig.register(
        BIND_TO_OPTION,
        NetworkInterface.DEFAULT_BIND_TO,
        new Option.Meta(sortOrder++, true, true, "FcpServer.bindTo", "FcpServer.bindToLong"),
        bindToCallback);
    bindToCallback.setInitialBindTo(fcpConfig.getString(BIND_TO_OPTION));

    FCPAllowedHostsCallback allowedHostsCallback =
        new FCPAllowedHostsCallback(NetworkInterface.DEFAULT_BIND_TO);
    fcpConfig.register(
        ALLOWED_HOSTS_OPTION,
        NetworkInterface.DEFAULT_BIND_TO,
        new Option.Meta(
            sortOrder++, true, true, "FcpServer.allowedHosts", "FcpServer.allowedHostsLong"),
        allowedHostsCallback);
    allowedHostsCallback.setInitialAllowedHosts(fcpConfig.getString(ALLOWED_HOSTS_OPTION));

    FCPAllowedHostsFullAccessCallback allowedHostsFullAccessCallback =
        new FCPAllowedHostsFullAccessCallback(NetworkInterface.DEFAULT_BIND_TO);
    fcpConfig.register(
        ALLOWED_HOSTS_FULL_ACCESS_OPTION,
        NetworkInterface.DEFAULT_BIND_TO,
        new Option.Meta(
            sortOrder++,
            true,
            true,
            "FcpServer.allowedHostsFullAccess",
            "FcpServer.allowedHostsFullAccessLong"),
        allowedHostsFullAccessCallback);
    allowedHostsFullAccessCallback.setInitialAllowedHostsFullAccess(
        fcpConfig.getString(ALLOWED_HOSTS_FULL_ACCESS_OPTION));

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
            fcpConfig.getString(BIND_TO_OPTION),
            fcpConfig.getString(ALLOWED_HOSTS_OPTION),
            fcpConfig.getString(ALLOWED_HOSTS_FULL_ACCESS_OPTION),
            fcpConfig.getInt("port"),
            fcpConfig.getBoolean(ENABLED_OPTION),
            fcpConfig.getBoolean("assumeDownloadDDAIsAllowed"),
            fcpConfig.getBoolean("assumeUploadDDAIsAllowed"),
            fcpConfig.getBoolean("neverDropAMessage"),
            fcpConfig.getInt("maxMessageQueueLength"));
    FCPServer fcp = new FCPServer(serverConfig, dependencies);

    portCallback.bind(fcp);
    enabledCallback.bind(fcp);
    bindToCallback.bind(fcp);
    allowedHostsCallback.bind(fcp);
    allowedHostsFullAccessCallback.bind(fcp);
    cb4.bind(fcp);
    cb5.bind(fcp);
    cb6.bind(fcp);
    cb7.bind(fcp);

    fcpConfig.finishedInitialization();
    return fcp;
  }

  /** Callback that exposes the read-only FCP port configuration. */
  static class FCPPortNumberCallback extends IntCallback {
    private int initialPort;
    private FCPServer server;

    FCPPortNumberCallback(int initialPort) {
      this.initialPort = initialPort;
    }

    void setInitialPort(int initialPort) {
      this.initialPort = initialPort;
    }

    void bind(FCPServer server) {
      this.server = server;
    }

    @Override
    public Integer get() {
      return server == null ? initialPort : server.port;
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
    private boolean initialEnabled;
    private FCPServer server;

    FCPEnabledCallback(boolean initialEnabled) {
      this.initialEnabled = initialEnabled;
    }

    void setInitialEnabled(boolean initialEnabled) {
      this.initialEnabled = initialEnabled;
    }

    void bind(FCPServer server) {
      this.server = server;
    }

    @Override
    public Boolean get() {
      return server == null ? initialEnabled : server.enabled;
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
    private String initialBindTo;
    private FCPServer server;

    FCPBindtoCallback(String initialBindTo) {
      this.initialBindTo = initialBindTo;
    }

    void setInitialBindTo(String initialBindTo) {
      this.initialBindTo = initialBindTo;
    }

    void bind(FCPServer server) {
      this.server = server;
      server.listener().updateBindTo(initialBindTo);
      server.bindTo = initialBindTo;
    }

    @Override
    public String get() {
      return server == null ? initialBindTo : server.bindTo;
    }

    @Override
    public void set(String val) throws InvalidConfigValueException {
      if (server == null) {
        initialBindTo = val;
        return;
      }
      String oldValue = get();
      if (!val.equals(oldValue)) {
        FCPServer currentServer = server;

        String[] failedAddresses = currentServer.listener().setBindTo(val, true);
        if (failedAddresses != null) {
          currentServer.listener().setBindTo(oldValue, true);
          throw new InvalidConfigValueException(
              NodeL10n.getBase()
                  .getString(
                      "FcpServer.couldNotChangeBindTo",
                      "failedInterfaces",
                      Arrays.toString(failedAddresses)));
        }

        currentServer.listener().updateBindTo(val);
        currentServer.bindTo = val;
        initialBindTo = val;
      }
    }
  }

  /** Callback that reads or updates the allowed-hosts list for the FCP listener. */
  static class FCPAllowedHostsCallback extends StringCallback {
    private String initialAllowedHosts;
    private FCPServer server;

    FCPAllowedHostsCallback(String initialAllowedHosts) {
      this.initialAllowedHosts = initialAllowedHosts;
    }

    void setInitialAllowedHosts(String initialAllowedHosts) {
      this.initialAllowedHosts = initialAllowedHosts;
    }

    void bind(FCPServer server) {
      this.server = server;
      server.listener().setAllowedHosts(initialAllowedHosts);
    }

    @Override
    public String get() {
      return server == null ? initialAllowedHosts : server.listener().getAllowedHosts();
    }

    @Override
    public void set(String val) throws InvalidConfigValueException {
      if (!val.equals(get())) {
        try {
          if (server != null) {
            server.listener().setAllowedHosts(val);
          }
          initialAllowedHosts = val;
        } catch (IllegalArgumentException e) {
          throw new InvalidConfigValueException(e);
        }
      }
    }
  }

  /** Callback that manages the full-access allowlist for privileged operations. */
  static class FCPAllowedHostsFullAccessCallback extends StringCallback {
    private String initialAllowedHostsFullAccess;
    private FCPServer server;

    FCPAllowedHostsFullAccessCallback(String initialAllowedHostsFullAccess) {
      this.initialAllowedHostsFullAccess = initialAllowedHostsFullAccess;
    }

    void setInitialAllowedHostsFullAccess(String initialAllowedHostsFullAccess) {
      this.initialAllowedHostsFullAccess = initialAllowedHostsFullAccess;
    }

    void bind(FCPServer server) {
      this.server = server;
      server.getAllowedHostsFullAccess().setAllowedHosts(initialAllowedHostsFullAccess);
    }

    @Override
    public String get() {
      return server == null
          ? initialAllowedHostsFullAccess
          : server.getAllowedHostsFullAccess().getAllowedHosts();
    }

    @Override
    public void set(String val) throws InvalidConfigValueException {
      if (!val.equals(get())) {
        try {
          if (server != null) {
            server.getAllowedHostsFullAccess().setAllowedHosts(val);
          }
          initialAllowedHostsFullAccess = val;
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

    void bind(FCPServer server) {
      this.server = server;
    }

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

    void bind(FCPServer server) {
      this.server = server;
    }

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

    void bind(FCPServer server) {
      this.server = server;
    }

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

    void bind(FCPServer server) {
      this.server = server;
    }

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
