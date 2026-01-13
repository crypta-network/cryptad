package network.crypta.node.subsystem;

import java.io.File;
import network.crypta.clients.http.SimpleToadletServer;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.Option;
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

/**
 * Wires node-facing services such as the web UI, diagnostics, updater, and alert helpers.
 *
 * <p>This subsystem is a lightweight coordinator used during node startup and runtime to connect
 * service implementations to the {@link Node} lifecycle. Callers typically construct it once from
 * the node, then invoke initialization methods as each dependency becomes available (for example,
 * start the web interface after configuration is loaded, attach the updater and diagnostics once
 * network services exist, and register user alerts after the client core is ready). Most fields are
 * nullable until set, and the class intentionally performs null checks so callers can wire it in
 * stages without complex ordering constraints.
 *
 * <p>The class is mutable and not thread-safe by itself; it relies on the node's startup sequence
 * to serialize most interactions. The only synchronized method is the time-skew alert registration
 * to ensure single instantiation. Some alert registrations may be deferred via a {@link Ticker}
 * when dependencies are not yet available.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Starting and exposing the FProxy web interface.
 *   <li>Wiring updater, diagnostics, and plugin manager instances.
 *   <li>Managing user alerts and persisted visibility flags.
 * </ul>
 *
 * @see Node
 * @see NodeNetworkSubsystem
 * @see network.crypta.node.NodeClientCore
 */
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

  /**
   * Creates a services subsystem bound to a specific node instance.
   *
   * <p>The new instance starts with all service references unset and should be populated by the
   * node's startup sequence. The {@code node} reference is used to access configuration, network
   * components, and storage when alert or service wiring occurs. This constructor performs no I/O
   * and does not start any services.
   *
   * @param node owning node used for configuration, storage, and service wiring; must be non-null.
   */
  public NodeServicesSubsystem(Node node) {
    this.node = node;
  }

  /**
   * Starts the FProxy web interface using the provided configuration and executor.
   *
   * <p>This method creates a dedicated {@link SimpleToadletServer} instance, finalizes the
   * corresponding {@code fproxy} sub-configuration, and starts the HTTP listener. It is expected to
   * be called once during startup; repeated calls replace the stored reference but may leak
   * resources if an existing server is still running. Configuration errors are wrapped into a
   * {@link NodeInitException} with an exit code suitable for the launcher.
   *
   * @param config persistent configuration root used to create the {@code fproxy} sub-config.
   * @param executor executor that backs web requests and background scheduling tasks.
   * @throws NodeInitException when the FProxy configuration is invalid or startup fails.
   */
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

  /**
   * Returns the current FProxy toadlet server instance, if one has been started.
   *
   * <p>The reference is assigned by {@link #startWebInterface(PersistentConfig,
   * PriorityAwareExecutor)} and remains {@code null} until that method succeeds. Callers should
   * treat the returned object as node-owned and avoid modifying its lifecycle directly. This
   * accessor performs no synchronization, so callers should handle {@code null} during early
   * startup.
   *
   * @return the active {@link SimpleToadletServer}, or {@code null} if not started yet.
   */
  public SimpleToadletServer toadlets() {
    return toadlets;
  }

  /**
   * Assigns the client core used for alert registration and client wiring.
   *
   * <p>This method stores the provided reference without validation. Call it once the node client
   * core has been constructed. Subsequent calls overwrite the reference and may affect alert
   * routing, so they should be reserved for tests or controlled reconfiguration. This setter does
   * not register alerts or otherwise modify the client core's internal state.
   *
   * @param clientCore client core instance to store; may be {@code null} to clear it.
   */
  public void setClientCore(network.crypta.node.NodeClientCore clientCore) {
    this.clientCore = clientCore;
  }

  /**
   * Returns the current client core reference.
   *
   * <p>The value is {@code null} until {@link #setClientCore(network.crypta.node.NodeClientCore)}
   * is called. The returned instance is shared with other subsystems and should not be shut down
   * directly by callers. Callers should check for {@code null} if startup is still in progress.
   *
   * @return the configured client core, or {@code null} if it has not been set.
   */
  public network.crypta.node.NodeClientCore clientCore() {
    return clientCore;
  }

  /**
   * Assigns the node updater used for core and plugin update coordination.
   *
   * <p>This setter stores the updater reference without initiating any background work. It is
   * commonly called from {@link #initUpdater(PersistentConfig)} once configuration is available,
   * but can also be used directly in tests to inject a stub. This method does not start any
   * downloads or background tasks on its own.
   *
   * @param nodeUpdater updater instance to store; may be {@code null} to clear it.
   */
  public void setNodeUpdater(network.crypta.node.updater.NodeUpdateManager nodeUpdater) {
    this.nodeUpdater = nodeUpdater;
  }

  /**
   * Returns the current node updater instance.
   *
   * <p>The updater reference is {@code null} until it is set by {@link #setNodeUpdater} or {@link
   * #initUpdater(PersistentConfig)}. The returned instance is owned by the node and should not be
   * stopped directly by callers. It may be {@code null} if the updater is not configured.
   *
   * @return the configured {@link network.crypta.node.updater.NodeUpdateManager} or {@code null}.
   */
  public network.crypta.node.updater.NodeUpdateManager nodeUpdater() {
    return nodeUpdater;
  }

  /**
   * Initializes the node updater from configuration.
   *
   * <p>This method calls {@link network.crypta.node.updater.NodeUpdateManager} to create or reuse
   * an updater instance and stores the resulting reference. The method does not force the updater
   * to start downloads; it only wires the instance into this subsystem so other components can
   * access it later. The stored updater may be {@code null} when the updater is disabled.
   *
   * @param config persistent configuration root used to create updater settings.
   * @throws InvalidConfigValueException if configuration values are invalid or inconsistent.
   */
  public void initUpdater(PersistentConfig config) throws InvalidConfigValueException {
    setNodeUpdater(network.crypta.node.updater.NodeUpdateManager.maybeCreate(node, config));
  }

  /**
   * Sets the diagnostics instance used for node health reporting.
   *
   * <p>This setter overwrites the stored diagnostics reference and performs no additional wiring.
   * It is primarily used by tests or specialized bootstrap code that wants to provide a pre-built
   * diagnostics instance instead of calling {@link #initDiagnostics(NodeNetworkSubsystem)}. It
   * replaces any previously stored diagnostics reference without further coordination.
   *
   * @param diagnostics diagnostics instance to store; may be {@code null} to clear it.
   */
  @SuppressWarnings("unused")
  public void setNodeDiagnostics(
      network.crypta.node.diagnostics.DefaultNodeDiagnostics diagnostics) {
    this.nodeDiagnostics = diagnostics;
  }

  /**
   * Returns the configured diagnostics instance.
   *
   * <p>The reference is {@code null} until initialized via {@link #initDiagnostics} or {@link
   * #setNodeDiagnostics}. Callers should treat the returned diagnostics as node-owned state and
   * avoid managing its lifecycle directly. The reference may change if initialization is repeated.
   *
   * @return the current diagnostics instance, or {@code null} if not initialized.
   */
  public network.crypta.node.diagnostics.DefaultNodeDiagnostics nodeDiagnostics() {
    return nodeDiagnostics;
  }

  /**
   * Initializes diagnostics from the network subsystem.
   *
   * <p>This method extracts the {@link network.crypta.node.NodeStats} and {@link Ticker} from the
   * network subsystem and constructs a new diagnostics instance. It should be called once the
   * network subsystem is available but before diagnostics are consumed by other components. Calling
   * it again replaces the stored diagnostics instance with a new one.
   *
   * @param network network subsystem providing stats and a ticker for diagnostics scheduling.
   */
  public void initDiagnostics(NodeNetworkSubsystem network) {
    Ticker ticker = network.ticker();
    this.nodeDiagnostics =
        new network.crypta.node.diagnostics.DefaultNodeDiagnostics(network.stats(), ticker);
  }

  /**
   * Stores the plugin manager used for plugin lifecycle coordination.
   *
   * <p>The stored reference is used by other subsystems to query or interact with plugins. This
   * method does not start or stop any plugins; it only wires the instance into this subsystem. Use
   * this setter after the plugin manager has been constructed and configured by the node.
   *
   * @param pluginManager plugin manager to store; may be {@code null} to clear it.
   */
  public void setPluginManager(network.crypta.pluginmanager.PluginManager pluginManager) {
    this.pluginManager = pluginManager;
  }

  /**
   * Returns the configured plugin manager instance.
   *
   * <p>The reference is {@code null} until {@link #setPluginManager} is called. Callers should not
   * manage the lifecycle of the returned manager directly, as it is owned by the node. Callers
   * should handle {@code null} during early startup.
   *
   * @return the current plugin manager, or {@code null} if not set.
   */
  public network.crypta.pluginmanager.PluginManager pluginManager() {
    return pluginManager;
  }

  /**
   * Stores the security levels configuration helper.
   *
   * <p>This method records the reference used by other components to determine current security
   * settings. It performs no validation and does not trigger updates to any on-disk configuration.
   * This setter only stores the reference for later access by other components.
   *
   * @param securityLevels security levels instance to store; may be {@code null} to clear it.
   */
  public void setSecurityLevels(network.crypta.node.SecurityLevels securityLevels) {
    this.securityLevels = securityLevels;
  }

  /**
   * Returns the configured security levels instance.
   *
   * <p>The returned reference is {@code null} until {@link #setSecurityLevels} is invoked. Treat
   * the returned instance as shared, mutable configuration owned by the node. It may be {@code
   * null} until security levels are initialized.
   *
   * @return the current security levels instance, or {@code null} if not initialized.
   */
  public network.crypta.node.SecurityLevels securityLevels() {
    return securityLevels;
  }

  /**
   * Initializes the "meaningful node name" user alert.
   *
   * <p>This method constructs a {@link MeaningfulNodeNameUserAlert} and stores it for later use. It
   * does not register the alert with the alert manager; registration is handled elsewhere as part
   * of client-core setup. Repeated calls overwrite the stored alert instance without checking for
   * an existing registration.
   */
  public void initNodeNameUserAlert() {
    this.nodeNameUserAlert = new MeaningfulNodeNameUserAlert(node);
  }

  /**
   * Returns the cached "meaningful node name" user alert.
   *
   * <p>The alert is created by {@link #initNodeNameUserAlert()} and remains {@code null} until that
   * method is called. The returned alert should be treated as node-owned state. Callers should not
   * mutate it directly unless they control alert registration elsewhere.
   *
   * @return the node-name alert instance, or {@code null} if not initialized.
   */
  public MeaningfulNodeNameUserAlert nodeNameUserAlert() {
    return nodeNameUserAlert;
  }

  /**
   * Returns whether the friends-visibility alert is currently marked as shown.
   *
   * <p>This flag is a persisted, user-facing state that indicates whether the user should be
   * reminded to set peer visibility. It is toggled by {@link #createVisibilityAlert()} and {@link
   * #clearVisibilityAlert()} and also updated when the alert is dismissed. The flag is stored in
   * memory and persisted by explicit store operations.
   *
   * @return {@code true} if the visibility alert should be shown, otherwise {@code false}.
   */
  public boolean isShowFriendsVisibilityAlert() {
    return showFriendsVisibilityAlert;
  }

  /**
   * Sets the persisted flag indicating whether the friends-visibility alert should be shown.
   *
   * <p>This method only updates the in-memory flag; it does not register or unregister the alert
   * itself. Use {@link #createVisibilityAlert()} or {@link #clearVisibilityAlert()} when you want
   * to update the flag and synchronize alert registration behavior. This setter does not persist
   * the value; persistence is handled elsewhere.
   *
   * @param showFriendsVisibilityAlert {@code true} to mark the alert visible, {@code false} to
   *     clear the flag without registering or unregistering alerts.
   */
  public void setShowFriendsVisibilityAlert(boolean showFriendsVisibilityAlert) {
    this.showFriendsVisibilityAlert = showFriendsVisibilityAlert;
  }

  /**
   * Registers an alert if the current JVM version is end-of-life.
   *
   * <p>If the client core has not been set, this method returns immediately. Otherwise, it checks
   * {@link JVMVersion#isEOL()} and, when the JVM is end-of-life, registers a {@link
   * JVMVersionAlert} with the alert manager. The method is idempotent for alert registration as
   * long as the manager handles duplicate alerts in a stable way. It performs no work when the JVM
   * is not end-of-life.
   */
  public void registerJvmVersionAlertIfNeeded() {
    if (clientCore == null) return;
    if (JVMVersion.isEOL()) {
      clientCore.getAlerts().register(new JVMVersionAlert());
    }
  }

  /**
   * Registers an alert indicating that the process has insufficient nice levels.
   *
   * <p>If the client core is not set, this method is a no-op. Otherwise, it registers a new {@link
   * NotEnoughNiceLevelsUserAlert} with the alert manager. This method performs no additional
   * checks; it simply surfaces the warning when called by the node startup logic. Repeated calls
   * register multiple alerts if the manager does not de-duplicate them.
   */
  public void registerNotEnoughNiceLevelsAlert() {
    if (clientCore == null) return;
    clientCore.getAlerts().register(new NotEnoughNiceLevelsUserAlert());
  }

  /**
   * Emits a warning alert when the node is not running under the wrapper.
   *
   * <p>The method is a no-op if the client core is unset, if the node is already using the wrapper,
   * or if wrapper warnings are explicitly skipped. When it does register an alert, it uses
   * localized strings and categorizes the alert as a warning for display in the UI. The alert text
   * is derived from localization keys under {@code Node.notUsingWrapper*}.
   *
   * @param isUsingWrapper {@code true} when running under the wrapper; {@code false} otherwise.
   * @param skipWrapperWarning {@code true} to suppress the warning even without the wrapper.
   */
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

  /**
   * Registers a critical alert when the master keys file could not be deleted.
   *
   * <p>This method uses the current storage location to include the absolute master keys path in
   * the localized message. If the client core is unset, it returns immediately. The alert is marked
   * as critical, reflecting the security impact of leaving sensitive material on disk. When the
   * file path is unavailable, the message uses an empty replacement value.
   */
  public void registerCantDeletePasswordFileAlert() {
    if (clientCore == null) return;
    File masterKeysFile = node.storage().getMasterKeysFile();
    String filename = masterKeysFile != null ? masterKeysFile.getAbsolutePath() : "";
    clientCore
        .getAlerts()
        .register(
            new SimpleUserAlert(
                true,
                NodeL10n.getBase().getString("SecurityLevels.cantDeletePasswordFileTitle"),
                NodeL10n.getBase()
                    .getString("SecurityLevels.cantDeletePasswordFile", "filename", filename),
                NodeL10n.getBase().getString("SecurityLevels.cantDeletePasswordFileTitle"),
                UserAlert.CRITICAL_ERROR));
  }

  /**
   * Registers configuration for peer-offers FREF file alerts.
   *
   * <p>This method registers a boolean option that toggles whether peer-offer alerts are dismissed.
   * The callback updates the in-memory flag and registers or unregisters alerts accordingly. It
   * should be called during configuration initialization so the persisted flag is restored and
   * alert state is consistent with user preferences. The client core must already be set because
   * the callback interacts with the alert manager.
   *
   * @param nodeConfig configuration section used to register the dismissal option.
   * @param sortOrder ordering value used when presenting the option in configuration UIs.
   */
  public void configurePeersOffersFrefFiles(SubConfig nodeConfig, int sortOrder) {
    nodeConfig.register(
        "peersOffersDismissed",
        false,
        new Option.Meta(
            sortOrder, true, true, "Node.peersOffersDismissed", "Node.peersOffersDismissedLong"),
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

  /**
   * Creates a peer-offers alert if files are present and the user has not dismissed it.
   *
   * <p>This method is a lightweight guard around {@link PeersOffersUserAlert#createAlert(Node)}. It
   * only triggers the alert when peer-offer files exist and the dismissal flag is {@code false}.
   * The method does not change the dismissal state or persist configuration updates.
   *
   * @param hasPeersOffersFiles {@code true} if peer-offer files are available on disk.
   */
  public void maybeCreatePeersOffersAlertIfNeeded(boolean hasPeersOffersFiles) {
    if (!peersOffersDismissed && hasPeersOffersFiles) {
      PeersOffersUserAlert.createAlert(node);
    }
  }

  /**
   * Ensures that a time-skew detected alert is created and registered at most once.
   *
   * <p>This method is synchronized to prevent duplicate alert construction from concurrent callers.
   * It lazily creates a {@link TimeSkewDetectedUserAlert} and registers it with the alert manager
   * when the client core is available. Subsequent calls are no-ops and do not re-register alerts.
   */
  public synchronized void setTimeSkewDetectedUserAlert() {
    if (timeSkewDetectedUserAlert == null) {
      timeSkewDetectedUserAlert = new TimeSkewDetectedUserAlert();
      if (clientCore != null) {
        clientCore.getAlerts().register(timeSkewDetectedUserAlert);
      }
    }
  }

  /**
   * Marks the friends-visibility alert as shown and registers it with the alert manager.
   *
   * <p>If the alert is already marked as shown, the method returns immediately. Otherwise, it sets
   * the flag, queues a configuration store on the node ticker, and registers the alert. If the
   * alert manager is not yet ready, registration is deferred by the internal helper. This method is
   * safe to call multiple times but will only act on the first invocation.
   */
  public void createVisibilityAlert() {
    if (showFriendsVisibilityAlert) return;
    showFriendsVisibilityAlert = true;
    node.network().ticker().queueTimedJob(node.getConfig()::store, 0);
    registerFriendsVisibilityAlert();
  }

  /**
   * Registers the friends-visibility alert if the flag indicates it should be shown.
   *
   * <p>This is a convenience method used during startup when configuration is loaded before the
   * alert system is fully wired. It delegates to the internal registration helper, which may
   * requeue registration if the alert manager is not yet available. This method does not modify the
   * underlying flag.
   */
  public void maybeRegisterVisibilityAlert() {
    if (showFriendsVisibilityAlert) registerFriendsVisibilityAlert();
  }

  /**
   * Clears the friends-visibility alert flag and unregisters any active alert.
   *
   * <p>This method updates the in-memory flag and attempts to remove the alert from the alert
   * manager if it is available. It does not persist configuration directly; persistence is handled
   * when the alert is dismissed or through other configuration flows. Unregistration is best-effort
   * and is skipped when the alert manager is unavailable.
   */
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
