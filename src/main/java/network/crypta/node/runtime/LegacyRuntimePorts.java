package network.crypta.node.runtime;

import java.io.File;
import java.util.Random;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.runtime.admin.AdminRuntimePortsBundle;
import network.crypta.runtime.admin.AdminRuntimePortsFactory;
import network.crypta.runtime.spi.ConfigPort;
import network.crypta.runtime.spi.ConnectionsPagePort;
import network.crypta.runtime.spi.ConnectionsSupportPort;
import network.crypta.runtime.spi.ConnectivityPort;
import network.crypta.runtime.spi.CoreUpdateActionPort;
import network.crypta.runtime.spi.DarknetConnectionsPort;
import network.crypta.runtime.spi.DarknetMessagingPort;
import network.crypta.runtime.spi.DiagnosticPort;
import network.crypta.runtime.spi.ExecutionPort;
import network.crypta.runtime.spi.FirstTimeWizardPort;
import network.crypta.runtime.spi.LifecyclePort;
import network.crypta.runtime.spi.NodeInfoPort;
import network.crypta.runtime.spi.PageChromePort;
import network.crypta.runtime.spi.PeerPort;
import network.crypta.runtime.spi.QueueCompletionPort;
import network.crypta.runtime.spi.QueueDownloadPort;
import network.crypta.runtime.spi.QueueInsertPort;
import network.crypta.runtime.spi.QueueMutationPort;
import network.crypta.runtime.spi.QueuePagePort;
import network.crypta.runtime.spi.QueueSupportPort;
import network.crypta.runtime.spi.RandomnessPort;
import network.crypta.runtime.spi.RequestQueuePort;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.runtime.spi.SecurityLevelsPort;
import network.crypta.runtime.spi.StatisticsPort;
import network.crypta.runtime.spi.ToadletSymlinkPort;
import network.crypta.runtime.spi.TransferAccessPort;
import network.crypta.runtime.spi.WelcomeActionPort;
import network.crypta.runtime.spi.WelcomePagePort;

/**
 * Bridges the current daemon implementation into the JDK-only runtime SPI.
 *
 * <p>This adapter is the conservative compatibility layer for the first runtime SPI extraction. It
 * captures the existing {@link Node} and {@link NodeClientCore} instances and exposes their
 * already-available capabilities through the smaller {@link RuntimePorts} surface. The class adds
 * no policy of its own; each sub-port delegates directly to the legacy implementation, so behavior,
 * timing, file-access semantics, configuration-management semantics, and node-info exports remain
 * aligned with the daemon that existed before the SPI was introduced.
 *
 * <p>The adapter is immutable after construction. It is safe to share the instance anywhere the
 * daemon currently threads runtime dependencies, but callers should remember that the returned
 * ports remain live views over mutable daemon state rather than detached snapshots.
 */
public final class LegacyRuntimePorts implements RuntimePorts {
  private final Node node;
  private final NodeClientCore core;
  private final ExecutionPort executionPort;
  private final RandomnessPort randomnessPort;
  private final TransferAccessPort transferAccessPort;
  private final LifecyclePort lifecyclePort;
  private final ConfigPort configPort;
  private final ConnectivityPort connectivityPort;
  private final ConnectionsPagePort connectionsPagePort;
  private final ConnectionsSupportPort connectionsSupportPort;
  private final DarknetConnectionsPort darknetConnectionsPort;
  private final DarknetMessagingPort darknetMessagingPort;
  private final DiagnosticPort diagnosticPort;
  private final PageChromePort pageChromePort;
  private final CoreUpdateActionPort coreUpdateActionPort;
  private final QueueCompletionPort queueCompletionPort;
  private final QueuePagePort queuePagePort;
  private final QueueDownloadPort queueDownloadPort;
  private final QueueInsertPort queueInsertPort;
  private final QueueMutationPort queueMutationPort;
  private final QueueSupportPort queueSupportPort;
  private final StatisticsPort statisticsPort;
  private final SecurityLevelsPort securityLevelsPort;
  private final FirstTimeWizardPort firstTimeWizardPort;
  private final ToadletSymlinkPort toadletSymlinkPort;
  private final WelcomePagePort welcomePagePort;
  private final WelcomeActionPort welcomeActionPort;
  private final RequestQueuePort requestQueuePort;
  private final NodeInfoPort nodeInfoPort;
  private final PeerPort peerPort;

  /**
   * Creates a runtime SPI adapter backed by the current daemon internals.
   *
   * <p>The constructed adapter keeps direct references to {@code node} and {@code core} and uses
   * them to implement each runtime sub-port with thin delegation only. No data is copied and no
   * validation or normalization is introduced here, so existing daemon semantics remain the source
   * of truth for execution, randomness, transfer policy, lifecycle state, configuration management,
   * and node-info exports.
   *
   * @param node live daemon node that provides execution, randomness, and lifecycle behavior
   * @param core live client core that provides transfer-policy checks and directory access
   */
  public LegacyRuntimePorts(Node node, NodeClientCore core) {
    this.node = node;
    this.core = core;
    this.executionPort =
        (task, name) -> LegacyRuntimePorts.this.node.network().executor().execute(task, name);
    this.randomnessPort =
        new RandomnessPort() {
          @Override
          public void fillSecureRandom(byte[] target) {
            LegacyRuntimePorts.this.node.bootstrap().random().nextBytes(target);
          }

          @Override
          public Random fastWeakRandom() {
            return LegacyRuntimePorts.this.node.bootstrap().fastWeakRandom();
          }
        };
    this.transferAccessPort =
        new TransferAccessPort() {
          @Override
          public boolean allowUploadFrom(File file) {
            return LegacyRuntimePorts.this.core.allowUploadFrom(file);
          }

          @Override
          public boolean allowDownloadTo(File file) {
            return LegacyRuntimePorts.this.core.allowDownloadTo(file);
          }

          @Override
          public File downloadsDir() {
            return LegacyRuntimePorts.this.core.getDownloadsDir();
          }

          @Override
          public File persistentTempDir() {
            return LegacyRuntimePorts.this.core.getPersistentTempDir();
          }

          @Override
          public File[] allowedUploadDirs() {
            return LegacyRuntimePorts.this.core.getAllowedUploadDirs();
          }

          @Override
          public File[] allowedDownloadDirs() {
            return LegacyRuntimePorts.this.core.getAllowedDownloadDirs();
          }
        };
    this.lifecyclePort =
        new LifecyclePort() {
          @Override
          public boolean hasStarted() {
            return LegacyRuntimePorts.this.node.isHasStarted();
          }

          @Override
          public boolean isStopping() {
            return LegacyRuntimePorts.this.node.isStopping();
          }

          @Override
          public boolean isUsingWrapper() {
            return LegacyRuntimePorts.this.node.isUsingWrapper();
          }

          @Override
          public long startupTimeMillis() {
            return LegacyRuntimePorts.this.node.getStartupTime();
          }
        };
    this.configPort = new LegacyConfigPort(node, core);
    this.connectivityPort = new LegacyConnectivityPort(node);
    this.coreUpdateActionPort = new LegacyCoreUpdateActionPort(node);
    this.securityLevelsPort = new LegacySecurityLevelsPort(node);
    this.requestQueuePort = new LegacyRequestQueuePort(core);
    this.nodeInfoPort = new LegacyNodeInfoPort(node);
    this.peerPort = new LegacyPeerPort(node);

    AdminRuntimePortsBundle adminRuntimePorts = AdminRuntimePortsFactory.create(node, core);
    this.connectionsPagePort = adminRuntimePorts.connectionsPage();
    this.connectionsSupportPort = adminRuntimePorts.connectionsSupport();
    this.darknetConnectionsPort = adminRuntimePorts.darknetConnections();
    this.darknetMessagingPort = adminRuntimePorts.darknetMessaging();
    this.diagnosticPort = adminRuntimePorts.diagnostic();
    this.pageChromePort = adminRuntimePorts.pageChrome();
    this.queueCompletionPort = adminRuntimePorts.queueCompletion();
    this.queuePagePort = adminRuntimePorts.queuePage();
    this.queueDownloadPort = adminRuntimePorts.queueDownload();
    this.queueInsertPort = adminRuntimePorts.queueInsert();
    this.queueMutationPort = adminRuntimePorts.queueMutation();
    this.queueSupportPort = adminRuntimePorts.queueSupport();
    this.statisticsPort = adminRuntimePorts.statistics();
    this.firstTimeWizardPort = adminRuntimePorts.firstTimeWizard();
    this.toadletSymlinkPort = adminRuntimePorts.toadletSymlinks();
    this.welcomePagePort = adminRuntimePorts.welcomePage();
    this.welcomeActionPort = adminRuntimePorts.welcomeAction();
  }

  /**
   * {@inheritDoc}
   *
   * <p>The returned port delegates to the node's existing network executor without adding another
   * scheduling layer.
   */
  @Override
  public ExecutionPort execution() {
    return executionPort;
  }

  /**
   * {@inheritDoc}
   *
   * <p>The returned port delegates to the node bootstrap's secure and weak random services.
   */
  @Override
  public RandomnessPort randomness() {
    return randomnessPort;
  }

  /**
   * {@inheritDoc}
   *
   * <p>The returned port delegates to {@link NodeClientCore} for current file-transfer policy and
   * directory state.
   */
  @Override
  public TransferAccessPort transferAccess() {
    return transferAccessPort;
  }

  /**
   * {@inheritDoc}
   *
   * <p>The returned port exposes the node's current lifecycle flags and startup timestamp directly.
   */
  @Override
  public LifecyclePort lifecycle() {
    return lifecyclePort;
  }

  /**
   * {@inheritDoc}
   *
   * <p>The returned port keeps all legacy configuration traversals and persistence inside the
   * daemon root module while exposing only SPI-local DTOs upstream.
   */
  @Override
  public ConfigPort config() {
    return configPort;
  }

  /**
   * {@inheritDoc}
   *
   * <p>The returned port keeps all legacy connectivity tracking, listener-port exports, and
   * connection-type notice collection inside the daemon root module while exposing only detached
   * SPI-local snapshots upstream.
   */
  @Override
  public ConnectivityPort connectivity() {
    return connectivityPort;
  }

  /**
   * {@inheritDoc}
   *
   * <p>The returned port keeps the legacy connections-page traversal, peer sorting, and detached
   * HTML fragment rendering inside the daemon root module while exposing only SPI-local snapshots
   * upstream.
   */
  @Override
  public ConnectionsPagePort connectionsPage() {
    return connectionsPagePort;
  }

  /**
   * {@inheritDoc}
   *
   * <p>The returned port keeps the remaining legacy opennet-enabled check and peer-offer file
   * traversal inside the daemon root module while exposing only JDK-only support values upstream.
   */
  @Override
  public ConnectionsSupportPort connectionsSupport() {
    return connectionsSupportPort;
  }

  /**
   * {@inheritDoc}
   *
   * <p>The returned port keeps the legacy darknet friends-page selection-token traversal and
   * peer-specific noderef export inside the daemon root module while exposing only detached
   * SPI-local snapshots upstream.
   */
  @Override
  public DarknetConnectionsPort darknetConnections() {
    return darknetConnectionsPort;
  }

  /**
   * {@inheritDoc}
   *
   * <p>The returned port keeps legacy N2NTM peer resolution, file-offer adaptation, and sends
   * status mapping inside the daemon root module while exposing only detached SPI-local values
   * upstream.
   */
  @Override
  public DarknetMessagingPort darknetMessaging() {
    return darknetMessagingPort;
  }

  /**
   * {@inheritDoc}
   *
   * <p>The returned port keeps all legacy diagnostic traversal, queue aggregation, and thread
   * formatting inside the daemon root module while exposing only detached report sections upstream.
   */
  @Override
  public DiagnosticPort diagnostic() {
    return diagnosticPort;
  }

  /**
   * {@inheritDoc}
   *
   * <p>The returned port keeps the remaining shared status-bar security-level and peer-count reads
   * inside the daemon root module while exposing only detached SPI-local values upstream.
   */
  @Override
  public PageChromePort pageChrome() {
    return pageChromePort;
  }

  /**
   * {@inheritDoc}
   *
   * <p>The returned port keeps the remaining core-updater availability checks, UI-triggered
   * download start, and downloaded-installer path validation inside the daemon root module while
   * exposing only JDK-only values upstream.
   */
  @Override
  public CoreUpdateActionPort coreUpdateAction() {
    return coreUpdateActionPort;
  }

  /**
   * {@inheritDoc}
   *
   * <p>The returned port keeps the remaining queue backend-enabled check, persistence-support state
   * reads, and panic actions inside the daemon root module while exposing only JDK-only values
   * upstream.
   */
  @Override
  public QueueSupportPort queueSupport() {
    return queueSupportPort;
  }

  /**
   * {@inheritDoc}
   *
   * <p>The returned port keeps legacy queue-completion callback registration, persisted completed
   * request recovery, and completion-alert registration inside the daemon root module while
   * exposing only an idempotent startup hook upstream.
   */
  @Override
  public QueueCompletionPort queueCompletion() {
    return queueCompletionPort;
  }

  /**
   * {@inheritDoc}
   *
   * <p>The returned port keeps the legacy queue-page traversal, partitioning, sorting, and detached
   * HTML-template generation inside the daemon root module while exposing only SPI-local snapshots
   * and plain-text exports upstream.
   */
  @Override
  public QueuePagePort queuePage() {
    return queuePagePort;
  }

  /**
   * {@inheritDoc}
   *
   * <p>The returned port keeps the remaining new-download queue registration inside the daemon root
   * module while exposing only a narrow JDK-only request surface upstream.
   */
  @Override
  public QueueDownloadPort queueDownload() {
    return queueDownloadPort;
  }

  /**
   * {@inheritDoc}
   *
   * <p>The returned port keeps the remaining new-upload and local-insert queue registration inside
   * the daemon root module while exposing only narrow JDK-only request shapes upstream.
   */
  @Override
  public QueueInsertPort queueInsert() {
    return queueInsertPort;
  }

  /**
   * {@inheritDoc}
   *
   * <p>The returned port keeps the remaining existing-request queue mutations inside the daemon
   * root module while exposing only a narrow JDK-only mutation surface upstream.
   */
  @Override
  public QueueMutationPort queueMutation() {
    return queueMutationPort;
  }

  /**
   * {@inheritDoc}
   *
   * <p>The returned port keeps the legacy statistics-page traversal and HTML-template generation
   * inside the daemon root module while exposing only detached SPI-local snapshots upstream.
   */
  @Override
  public StatisticsPort statistics() {
    return statisticsPort;
  }

  /**
   * {@inheritDoc}
   *
   * <p>The returned port keeps legacy security-level reads, confirmation-warning rendering, and
   * master-password-file mutation handling inside the daemon root module while exposing only
   * detached SPI-local values upstream.
   */
  @Override
  public SecurityLevelsPort securityLevels() {
    return securityLevelsPort;
  }

  /**
   * {@inheritDoc}
   *
   * <p>The returned port keeps the legacy JavaScript first-time wizard defaults, validation bounds,
   * and submission-side daemon writes inside the root module while exposing only detached SPI-local
   * values upstream.
   */
  @Override
  public FirstTimeWizardPort firstTimeWizard() {
    return firstTimeWizardPort;
  }

  /**
   * {@inheritDoc}
   *
   * <p>The returned port keeps the remaining symlinker configuration load and persistence behavior
   * inside the daemon root module while exposing only detached JDK-only alias entries upstream.
   */
  @Override
  public ToadletSymlinkPort toadletSymlinks() {
    return toadletSymlinkPort;
  }

  /**
   * {@inheritDoc}
   *
   * <p>The returned port keeps the remaining welcome-page config reads and latest-log tail
   * selection inside the daemon root module while exposing only detached read-only values upstream.
   */
  @Override
  public WelcomePagePort welcomePage() {
    return welcomePagePort;
  }

  /**
   * {@inheritDoc}
   *
   * <p>The returned port keeps the remaining welcome-page update, restart, shutdown, and
   * bandwidth-upgrade actions inside the daemon root module while exposing only the narrow legacy
   * action surface upstream.
   */
  @Override
  public WelcomeActionPort welcomeAction() {
    return welcomeActionPort;
  }

  /**
   * {@inheritDoc}
   *
   * <p>The returned port keeps all legacy persistence-runner and ticker traversals inside the
   * daemon root module while exposing only queue-control semantics upstream.
   */
  @Override
  public RequestQueuePort requestQueue() {
    return requestQueuePort;
  }

  /**
   * {@inheritDoc}
   *
   * <p>The returned port keeps all legacy greeting metadata and node-reference export logic inside
   * the daemon root module while exposing only SPI-local snapshots upstream.
   */
  @Override
  public NodeInfoPort nodeInfo() {
    return nodeInfoPort;
  }

  /**
   * {@inheritDoc}
   *
   * <p>The returned port keeps all legacy peer export and mutation logic inside the daemon root
   * module while exposing only SPI-local snapshots, DTOs, and exceptions upstream.
   */
  @Override
  public PeerPort peer() {
    return peerPort;
  }
}
