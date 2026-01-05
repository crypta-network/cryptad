package network.crypta.node.subsystem;

import java.io.File;
import network.crypta.clients.http.SimpleToadletServer;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.PersistentConfig;
import network.crypta.config.SubConfig;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.Node;
import network.crypta.node.NodeInitException;
import network.crypta.node.useralerts.JVMVersionAlert;
import network.crypta.node.useralerts.MeaningfulNodeNameUserAlert;
import network.crypta.node.useralerts.NotEnoughNiceLevelsUserAlert;
import network.crypta.node.useralerts.PeersOffersUserAlert;
import network.crypta.node.useralerts.SimpleUserAlert;
import network.crypta.node.useralerts.TimeSkewDetectedUserAlert;
import network.crypta.node.useralerts.UserAlert;
import network.crypta.support.JVMVersion;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.Ticker;
import network.crypta.support.api.BooleanCallback;
import network.crypta.support.io.ArrayBucketFactory;

/** Services wiring (web UI, plugins, diagnostics, updater). */
public final class NodeServicesSubsystem {
  private final Node node;
  private SimpleToadletServer toadlets;
  private network.crypta.node.NodeClientCore clientCore;
  private network.crypta.node.updater.NodeUpdateManager nodeUpdater;
  private network.crypta.node.diagnostics.DefaultNodeDiagnostics nodeDiagnostics;
  private network.crypta.pluginmanager.PluginManager pluginManager;
  private network.crypta.node.SecurityLevels securityLevels;
  private MeaningfulNodeNameUserAlert nodeNameUserAlert;
  private boolean showFriendsVisibilityAlert;
  private UserAlert visibilityAlert;
  private boolean peersOffersDismissed;
  private TimeSkewDetectedUserAlert timeSkewDetectedUserAlert;

  public NodeServicesSubsystem(Node node) {
    this.node = node;
  }

  public void startWebInterface(PersistentConfig config, PriorityAwareExecutor executor)
      throws NodeInitException {
    SubConfig fproxyConfig = config.createSubConfig("fproxy");
    try {
      toadlets = new SimpleToadletServer(fproxyConfig, new ArrayBucketFactory(), executor, node);
      fproxyConfig.finishedInitialization();
      toadlets.start();
    } catch (InvalidConfigValueException e4) {
      throw new NodeInitException(
          NodeInitException.EXIT_COULD_NOT_START_FPROXY, "Could not start FProxy: " + e4);
    }
  }

  public SimpleToadletServer toadlets() {
    return toadlets;
  }

  public void setClientCore(network.crypta.node.NodeClientCore clientCore) {
    this.clientCore = clientCore;
  }

  public network.crypta.node.NodeClientCore clientCore() {
    return clientCore;
  }

  public void setNodeUpdater(network.crypta.node.updater.NodeUpdateManager nodeUpdater) {
    this.nodeUpdater = nodeUpdater;
  }

  public network.crypta.node.updater.NodeUpdateManager nodeUpdater() {
    return nodeUpdater;
  }

  public void initUpdater(PersistentConfig config) throws InvalidConfigValueException {
    setNodeUpdater(network.crypta.node.updater.NodeUpdateManager.maybeCreate(node, config));
  }

  public void setNodeDiagnostics(
      network.crypta.node.diagnostics.DefaultNodeDiagnostics diagnostics) {
    this.nodeDiagnostics = diagnostics;
  }

  public network.crypta.node.diagnostics.DefaultNodeDiagnostics nodeDiagnostics() {
    return nodeDiagnostics;
  }

  public void initDiagnostics(NodeNetworkSubsystem network) {
    Ticker ticker = network.ticker();
    this.nodeDiagnostics =
        new network.crypta.node.diagnostics.DefaultNodeDiagnostics(network.stats(), ticker);
  }

  public void setPluginManager(network.crypta.pluginmanager.PluginManager pluginManager) {
    this.pluginManager = pluginManager;
  }

  public network.crypta.pluginmanager.PluginManager pluginManager() {
    return pluginManager;
  }

  public void setSecurityLevels(network.crypta.node.SecurityLevels securityLevels) {
    this.securityLevels = securityLevels;
  }

  public network.crypta.node.SecurityLevels securityLevels() {
    return securityLevels;
  }

  public void initNodeNameUserAlert() {
    this.nodeNameUserAlert = new MeaningfulNodeNameUserAlert(node);
  }

  public MeaningfulNodeNameUserAlert nodeNameUserAlert() {
    return nodeNameUserAlert;
  }

  public boolean isShowFriendsVisibilityAlert() {
    return showFriendsVisibilityAlert;
  }

  public void setShowFriendsVisibilityAlert(boolean showFriendsVisibilityAlert) {
    this.showFriendsVisibilityAlert = showFriendsVisibilityAlert;
  }

  public void registerJvmVersionAlertIfNeeded() {
    if (clientCore == null) return;
    if (JVMVersion.isEOL()) {
      clientCore.getAlerts().register(new JVMVersionAlert());
    }
  }

  public void registerNotEnoughNiceLevelsAlert() {
    if (clientCore == null) return;
    clientCore.getAlerts().register(new NotEnoughNiceLevelsUserAlert());
  }

  public void warnIfNotUsingWrapper(boolean isUsingWrapper, boolean skipWrapperWarning) {
    if (clientCore == null) return;
    if (isUsingWrapper || skipWrapperWarning) return;
    clientCore
        .getAlerts()
        .register(
            new SimpleUserAlert(
                true,
                NodeL10n.getBase().getString("Node.notUsingWrapperTitle"),
                NodeL10n.getBase().getString("Node.notUsingWrapper"),
                NodeL10n.getBase().getString("Node.notUsingWrapperShort"),
                UserAlert.WARNING));
  }

  public void registerCantDeletePasswordFileAlert(File masterKeysFile) {
    if (clientCore == null) return;
    clientCore
        .getAlerts()
        .register(
            new SimpleUserAlert(
                true,
                NodeL10n.getBase().getString("SecurityLevels.cantDeletePasswordFileTitle"),
                NodeL10n.getBase().getString("SecurityLevels.cantDeletePasswordFile"),
                NodeL10n.getBase().getString("SecurityLevels.cantDeletePasswordFileTitle"),
                UserAlert.CRITICAL_ERROR));
  }

  public void configurePeersOffersFrefFiles(SubConfig nodeConfig, int sortOrder) {
    nodeConfig.register(
        "peersOffersDismissed",
        false,
        sortOrder,
        true,
        true,
        "Node.peersOffersDismissed",
        "Node.peersOffersDismissedLong",
        new BooleanCallback() {
          @Override
          public Boolean get() {
            return peersOffersDismissed;
          }

          @Override
          public void set(Boolean val) {
            boolean dismissed = Boolean.TRUE.equals(val);
            if (dismissed) {
              for (UserAlert alert : clientCore.getAlerts().getAlerts()) {
                if (alert instanceof PeersOffersUserAlert) {
                  clientCore.getAlerts().unregister(alert);
                }
              }
            } else {
              PeersOffersUserAlert.createAlert(node);
            }
            peersOffersDismissed = dismissed;
          }
        });
    peersOffersDismissed = nodeConfig.getBoolean("peersOffersDismissed");
  }

  public void maybeCreatePeersOffersAlertIfNeeded(boolean hasPeersOffersFiles) {
    if (!peersOffersDismissed && hasPeersOffersFiles) {
      PeersOffersUserAlert.createAlert(node);
    }
  }

  public synchronized void setTimeSkewDetectedUserAlert() {
    if (timeSkewDetectedUserAlert == null) {
      timeSkewDetectedUserAlert = new TimeSkewDetectedUserAlert();
      if (clientCore != null) {
        clientCore.getAlerts().register(timeSkewDetectedUserAlert);
      }
    }
  }

  public void createVisibilityAlert() {
    if (showFriendsVisibilityAlert) return;
    showFriendsVisibilityAlert = true;
    node.network().ticker().queueTimedJob(node.getConfig()::store, 0);
    registerFriendsVisibilityAlert();
  }

  public void maybeRegisterVisibilityAlert() {
    if (showFriendsVisibilityAlert) registerFriendsVisibilityAlert();
  }

  public void clearVisibilityAlert() {
    showFriendsVisibilityAlert = false;
    unregisterFriendsVisibilityAlert();
  }

  private void registerFriendsVisibilityAlert() {
    if (clientCore == null || clientCore.getAlerts() == null) {
      node.network().ticker().queueTimedJob(this::registerFriendsVisibilityAlert, 0);
      return;
    }
    clientCore.getAlerts().register(visibilityAlert());
  }

  private void unregisterFriendsVisibilityAlert() {
    if (clientCore == null || clientCore.getAlerts() == null) return;
    clientCore.getAlerts().unregister(visibilityAlert());
  }

  private UserAlert visibilityAlert() {
    if (visibilityAlert == null) {
      visibilityAlert =
          new SimpleUserAlert(
              true,
              l10n("pleaseSetPeersVisibilityAlertTitle"),
              l10n("pleaseSetPeersVisibilityAlert"),
              l10n("pleaseSetPeersVisibilityAlert"),
              UserAlert.ERROR) {

            @Override
            public void onDismiss() {
              showFriendsVisibilityAlert = false;
              node.getConfig().store();
              unregisterFriendsVisibilityAlert();
            }
          };
    }
    return visibilityAlert;
  }

  private String l10n(String key) {
    return NodeL10n.getBase().getString("Node." + key);
  }
}
