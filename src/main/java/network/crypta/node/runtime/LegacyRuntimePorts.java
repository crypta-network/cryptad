package network.crypta.node.runtime;

import java.io.File;
import java.util.Random;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.runtime.spi.ConfigPort;
import network.crypta.runtime.spi.ConnectionsPagePort;
import network.crypta.runtime.spi.ConnectionsSupportPort;
import network.crypta.runtime.spi.ConnectivityPort;
import network.crypta.runtime.spi.DarknetConnectionsPort;
import network.crypta.runtime.spi.DarknetMessagingPort;
import network.crypta.runtime.spi.DiagnosticPort;
import network.crypta.runtime.spi.ExecutionPort;
import network.crypta.runtime.spi.FirstTimeWizardPort;
import network.crypta.runtime.spi.LifecyclePort;
import network.crypta.runtime.spi.NodeInfoPort;
import network.crypta.runtime.spi.PeerPort;
import network.crypta.runtime.spi.RandomnessPort;
import network.crypta.runtime.spi.RequestQueuePort;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.runtime.spi.SecurityLevelsPort;
import network.crypta.runtime.spi.StatisticsPort;
import network.crypta.runtime.spi.TransferAccessPort;

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
  private final StatisticsPort statisticsPort;
  private final SecurityLevelsPort securityLevelsPort;
  private final FirstTimeWizardPort firstTimeWizardPort;
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
    this.connectionsPagePort = new LegacyConnectionsPagePort(node, core);
    this.connectionsSupportPort = new LegacyConnectionsSupportPort(node);
    this.darknetConnectionsPort = new LegacyDarknetConnectionsPort(node);
    this.darknetMessagingPort = new LegacyDarknetMessagingPort(node);
    this.diagnosticPort = new LegacyDiagnosticPort(node, core);
    this.statisticsPort = new LegacyStatisticsPort(node, core);
    this.securityLevelsPort = new LegacySecurityLevelsPort(node);
    this.firstTimeWizardPort = new LegacyFirstTimeWizardPort(node, core);
    this.requestQueuePort = new LegacyRequestQueuePort(core);
    this.nodeInfoPort = new LegacyNodeInfoPort(node);
    this.peerPort = new LegacyPeerPort(node);
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
