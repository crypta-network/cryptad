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
import network.crypta.support.api.BooleanCallback;
import network.crypta.support.api.IntCallback;
import network.crypta.support.api.StringCallback;

final class FcpServerConfigRegistrar {
  private FcpServerConfigRegistrar() {}

  static FCPServer maybeCreate(
      Node node, NodeClientCore core, Config config, PersistentRequestRoot root) {
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
        FCPServer.DEFAULT_FCP_PORT /* anagram of 1984, and 1000 up from old number */,
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
    FcpServerDependencies dependencies = new FcpServerDependencies(node, core, root);
    FCPServer fcp = new FCPServer(serverConfig, dependencies);

    cb4.server = fcp;
    cb5.server = fcp;
    cb6.server = fcp;
    cb7.server = fcp;

    fcpConfig.finishedInitialization();
    return fcp;
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

  static class FCPAllowedHostsCallback extends StringCallback {

    private final NodeClientCore node;

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

  static class FCPAllowedHostsFullAccessCallback extends StringCallback {
    private final NodeClientCore node;

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
}
