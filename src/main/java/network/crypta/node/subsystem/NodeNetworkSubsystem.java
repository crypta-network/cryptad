package network.crypta.node.subsystem;

import static java.util.concurrent.TimeUnit.SECONDS;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.client.FetchContext;
import network.crypta.config.Dimension;
import network.crypta.config.EnumerableOptionCallback;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.NodeNeedRestartException;
import network.crypta.config.PersistentConfig;
import network.crypta.config.SubConfig;
import network.crypta.io.comm.AsyncMessageFilterCallback;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.DisconnectedException;
import network.crypta.io.comm.FreenetInetAddress;
import network.crypta.io.comm.IOStatisticCollector;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageCore;
import network.crypta.io.comm.MessageFilter;
import network.crypta.io.comm.Peer;
import network.crypta.io.comm.PeerContext;
import network.crypta.io.comm.PeerParseException;
import network.crypta.io.comm.ReferenceSignatureVerificationException;
import network.crypta.io.comm.TrafficClass;
import network.crypta.io.comm.UdpSocketHandler;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.BandwidthManager;
import network.crypta.node.DNSRequester;
import network.crypta.node.DarknetPeerNode;
import network.crypta.node.FSParseException;
import network.crypta.node.LocationManager;
import network.crypta.node.Node;
import network.crypta.node.NodeCrypto;
import network.crypta.node.NodeCryptoConfig;
import network.crypta.node.NodeDispatcher;
import network.crypta.node.NodeIPDetector;
import network.crypta.node.NodeInitException;
import network.crypta.node.NodeStats;
import network.crypta.node.NodeStatsConfig;
import network.crypta.node.OpennetDisabledException;
import network.crypta.node.OpennetManager;
import network.crypta.node.OpennetPeerNode;
import network.crypta.node.PacketSender;
import network.crypta.node.PeerManager;
import network.crypta.node.PeerNode;
import network.crypta.node.PeerTooOldException;
import network.crypta.node.ProgramDirectory;
import network.crypta.node.SecurityLevels;
import network.crypta.node.SeedServerTestPeerNode;
import network.crypta.node.SemiOrderedShutdownHook;
import network.crypta.node.UptimeEstimator;
import network.crypta.node.probe.Listener;
import network.crypta.node.probe.Type;
import network.crypta.node.useralerts.SimpleUserAlert;
import network.crypta.node.useralerts.UserAlert;
import network.crypta.pluginmanager.ForwardPort;
import network.crypta.support.OutputThrottle;
import network.crypta.support.PooledExecutor;
import network.crypta.support.PrioritizedTicker;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.ShortBuffer;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.Ticker;
import network.crypta.support.api.BooleanCallback;
import network.crypta.support.api.IntCallback;
import network.crypta.support.api.LongCallback;
import network.crypta.support.api.StringCallback;
import network.crypta.support.transport.ip.HostnameSyntaxException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Network subsystem facade that wires together peer management, message dispatch, sockets, and
 * network-related configuration.
 *
 * <p>This class owns the lifecycle of the networking components that sit underneath the node: it
 * constructs and starts cryptographic transport, manages the dispatcher and message core, and
 * exposes peer and opennet operations for the rest of the node. Typical usage is sequential:
 * initialize configuration and crypto, load persisted peer state, then start transport and
 * scheduling. Callers generally interact through the getters and small helper methods rather than
 * manipulating fields directly.
 *
 * <p>Most state is initialized in discrete phases. Methods are not inherently thread-safe; callers
 * should follow the node startup ordering and avoid concurrent mutation while initialization is in
 * progress. Once started, the subsystem delegates to other components that manage their own
 * concurrency. Invariants include: the message core must be initialized before dispatch use, and
 * opennet operations are only valid when opennet has been enabled.
 *
 * <ul>
 *   <li><b>Responsibilities:</b> configuration registration, transport wiring, peer lifecycle, and
 *       accessors for networking state.
 *   <li><b>Notable behaviors:</b> conditional opennet enablement, bandwidth limit enforcement, and
 *       exposing forwardable ports for NAT traversal.
 * </ul>
 *
 * @see Node
 * @see PeerManager
 * @see NodeCrypto
 * @see MessageCore
 */
public final class NodeNetworkSubsystem {
  private static final Logger LOG = LoggerFactory.getLogger(NodeNetworkSubsystem.class);

  private final Node node;
  private FetchContext arkFetcherContext;
  private NodeStats nodeStats;
  private LocationManager locationManager;
  private PeerManager peers;
  private MessageCore usm;
  private NodeIPDetector ipDetector;
  private IOStatisticCollector collector;
  private PacketSender packetSender;
  private PrioritizedTicker ticker;
  private DNSRequester dnsRequester;
  private NodeDispatcher dispatcher;
  private UptimeEstimator uptimeEstimator;
  private OutputThrottle outputThrottle;
  private TrafficClass trafficClass;
  private NodeCrypto darknetCrypto;
  private OpennetManager opennet;
  private NodeCryptoConfig opennetCryptoConfig;
  private FreenetInetAddress freenetLocalhostAddress;
  private int maxOpennetPeers;
  private boolean acceptSeedConnections;
  private boolean isAllowedToConnectToSeednodes;
  private boolean passOpennetRefsThroughDarknet;
  private boolean throttleLocalData;
  private int outputBandwidthLimit;
  private int inputBandwidthLimit;
  private boolean inputLimitDefault;
  private long amountOfDataToCheckCompressionRatio;
  private int minimumCompressionPercentage;
  private boolean connectionSpeedDetection;

  /**
   * Creates a new network subsystem facade tied to a specific node instance.
   *
   * <p>The constructor stores the node reference and does not perform any initialization work.
   * Callers must invoke the appropriate init* methods in the expected order to configure crypto,
   * messaging, and peer state. This object is mutable and intended to be configured once during
   * node startup; it should not be shared across nodes or reused after shutdown.
   *
   * @param node owning node used to access configuration, services, and executors; must be non-null
   */
  public NodeNetworkSubsystem(Node node) {
    this.node = node;
  }

  /**
   * Initializes node statistics tracking and returns the next configuration sort order.
   *
   * <p>This method constructs the {@link NodeStats} instance from the provided persistent config
   * and binds it to the owning node. The returned sort order is identical to the input and is
   * intended to be threaded through other configuration registrations. The method performs no I/O
   * and does not start the stats threads; callers should invoke {@link #startStats()} after
   * initialization is complete.
   *
   * @param config persistent configuration root used to build the node load sub-config; non-null
   * @param sortOrder current configuration sort order, returned unchanged for chaining
   * @return the next sort order for subsequent configuration registration calls
   * @throws NodeInitException if node statistics fail to initialize with the provided config
   */
  public int initNodeStats(PersistentConfig config, int sortOrder) throws NodeInitException {
    NodeStatsConfig nodeStatsConfig = new NodeStatsConfig(config.createSubConfig("node.load"));
    nodeStats = new NodeStats(node, sortOrder, nodeStatsConfig);
    return sortOrder;
  }

  /**
   * Starts the node statistics component if it has been initialized.
   *
   * <p>This method is idempotent in the sense that it will only attempt to start stats when the
   * component exists; it performs no action if {@link #initNodeStats} has not been called yet. The
   * underlying {@link NodeStats} implementation handles its own threading and timing. Callers
   * should invoke this during the normal startup sequence after the configuration phase completes.
   */
  public void startStats() {
    if (nodeStats != null) nodeStats.start();
  }

  /**
   * Starts the dispatcher using the initialized node stats.
   *
   * <p>This method assumes the dispatcher was created via {@link #initDispatcher()} and that the
   * node stats instance is available. It forwards the stats reference to allow request accounting.
   * Callers should use this once during startup; repeated calls are delegated to the dispatcher
   * implementation and are expected to be safe but unnecessary.
   */
  public void startDispatcher() {
    dispatcher.start(nodeStats);
  }

  /**
   * Starts the packet sender using the initialized node stats.
   *
   * <p>This method assumes the packet sender has been constructed during crypto/transport
   * initialization. It supplies stats for bandwidth and throughput tracking. Callers typically
   * invoke this before networking begins so outgoing traffic is accounted for from the start.
   */
  public void startPacketSender() {
    packetSender.start(nodeStats);
  }

  /**
   * Exports a volatile field set describing current load and routing statistics.
   *
   * <p>The returned field set is produced by {@link NodeStats} and contains transient values
   * suitable for status reporting. It is not persisted and may change between calls. The caller
   * receives a new {@link SimpleFieldSet} instance and may read it without further synchronization.
   *
   * @return a snapshot field set of volatile node statistics
   */
  public SimpleFieldSet exportVolatileFieldSet() {
    return nodeStats.exportVolatileFieldSet();
  }

  /**
   * Enables or disables new load management modes on the stats component.
   *
   * <p>If the stats component is not yet available, this method logs an error and returns {@code
   * false} to signal that the request could not be applied. When stats are present, the request is
   * delegated to {@link NodeStats#enableNewLoadManagement(boolean)} and the result is returned
   * verbatim. The method does not perform any additional validation.
   *
   * @param realTimeFlag whether to enable real-time load management mode
   * @return {@code true} if the mode change was accepted, {@code false} otherwise
   */
  public boolean enableNewLoadManagement(boolean realTimeFlag) {
    if (nodeStats == null) {
      LOG.error(
          "Calling enableNewLoadManagement before Node constructor completes! FIX THIS!",
          new Exception("error"));
      return false;
    }
    return nodeStats.enableNewLoadManagement(realTimeFlag);
  }

  /**
   * Initializes the location manager used for routing and swap operations.
   *
   * <p>This method constructs a new {@link LocationManager} using the node's bootstrap random
   * source and binds it to the owning node. It does not start background processing; callers must
   * invoke {@link #startLocationManager()} to begin periodic location work. The method overwrites
   * any previous instance without attempting to shut it down.
   */
  public void initLocationManager() {
    locationManager = new LocationManager(node.bootstrap().random(), node);
  }

  /**
   * Starts the location manager.
   *
   * <p>The location manager performs background swaps and location updates. This method assumes
   * {@link #initLocationManager()} has been called. It simply delegates to {@link
   * LocationManager#start()} and performs no synchronization. Callers should call this once during
   * normal startup.
   */
  public void startLocationManager() {
    locationManager.start();
  }

  /**
   * Initializes the message core and IP detector components.
   *
   * <p>This method creates a {@link MessageCore} bound to the provided executor and a {@link
   * NodeIPDetector} associated with the owning node. It does not start either component; callers
   * must invoke {@link #startIpDetector()} and {@link MessageCore#start(Ticker)} when appropriate.
   *
   * @param executor executor used by the message core for prioritized processing; must be non-null
   */
  public void initMessagingCore(PriorityAwareExecutor executor) {
    usm = new MessageCore(executor);
    ipDetector = new NodeIPDetector(node);
  }

  /**
   * Registers IP detection configuration and returns the updated sort order.
   *
   * <p>The IP detector exposes configuration options that must be registered with the node config
   * system. This method delegates to {@link NodeIPDetector#registerConfigs(SubConfig, int)} and
   * returns the resulting sort order so callers can continue registering options. The detector must
   * already be initialized via {@link #initMessagingCore(PriorityAwareExecutor)}.
   *
   * @param nodeConfig node configuration section used for IP detector settings; must be non-null
   * @param sortOrder current configuration sort order for chained registration
   * @return updated sort order after registering IP detector options
   */
  public int registerIpDetectorConfigs(SubConfig nodeConfig, int sortOrder) {
    return ipDetector.registerConfigs(nodeConfig, sortOrder);
  }

  /**
   * Records the previously known IP address for the detector.
   *
   * <p>This method is typically called during startup when loading a stored node reference so that
   * the detector can avoid redundant checks or notify listeners of changes. The address is stored
   * as-is without validation beyond the type. The detector must be initialized before this call.
   *
   * @param address previously known address for the node's UDP socket; must be non-null
   */
  public void setOldIPAddress(FreenetInetAddress address) {
    ipDetector.setOldIPAddress(address);
  }

  /**
   * Returns the minimum detected MTU from the IP detector.
   *
   * <p>If the detector has not been initialized, this method returns {@link Integer#MAX_VALUE} as a
   * safe default indicating no constraint. Otherwise, it returns the detector's current minimum
   * value. The return value is in bytes and reflects the smallest MTU observed since startup.
   *
   * @return minimum detected MTU in bytes, or {@code Integer.MAX_VALUE} when unknown
   */
  public int minimumDetectedMtu() {
    if (ipDetector == null) return Integer.MAX_VALUE;
    return ipDetector.getMinimumDetectedMTU();
  }

  /**
   * Starts the IP detector component.
   *
   * <p>This method delegates directly to {@link NodeIPDetector#start()} and assumes the detector
   * has already been created by {@link #initMessagingCore(PriorityAwareExecutor)}. It does not
   * block for results and should be invoked during startup after configuration is registered.
   */
  public void startIpDetector() {
    ipDetector.start();
  }

  /**
   * Initializes the I/O statistics collector used for network metrics.
   *
   * <p>The collector tracks byte counters and I/O statistics for the node. This method simply
   * creates the instance and does not register it with any other component; downstream subsystems
   * reference it via {@link #collector()} once created.
   */
  public void initCollector() {
    collector = new IOStatisticCollector();
  }

  /**
   * Initializes the localhost address used by networking helpers.
   *
   * <p>This method resolves the loopback IPv4 address and stores it as a {@link
   * FreenetInetAddress}. If resolution fails (which is unexpected for {@code 127.0.0.1}), it throws
   * an {@link IllegalStateException}. The stored address is later exposed by {@link
   * #freenetLocalhostAddress()}.
   */
  public void initLocalhost() {
    try {
      InetAddress localhostAddress = InetAddress.getByName("127.0.0.1");
      freenetLocalhostAddress = new FreenetInetAddress(localhostAddress);
    } catch (java.net.UnknownHostException e3) {
      throw new IllegalStateException(e3);
    }
  }

  /**
   * Registers and resolves the traffic class configuration.
   *
   * <p>This method registers a {@code trafficClass} option with the provided configuration and
   * resolves the current value immediately. Invalid values are logged and reset to the default. The
   * returned sort order is incremented for the caller's next registration. A change to traffic
   * class requires a restart and is enforced by the callback.
   *
   * @param nodeConfig node configuration section where the traffic class is registered; non-null
   * @param sortOrder current configuration sort order for option registration
   * @return updated sort order after registering the traffic class option
   */
  public int initTrafficClass(SubConfig nodeConfig, int sortOrder) {
    class TrafficClassCallback extends StringCallback implements EnumerableOptionCallback {
      @Override
      public String get() {
        return trafficClass.name();
      }

      @Override
      public void set(String tcName) throws InvalidConfigValueException, NodeNeedRestartException {
        try {
          trafficClass = TrafficClass.fromNameOrValue(tcName);
        } catch (IllegalArgumentException e) {
          throw new InvalidConfigValueException(e);
        }
        throw new NodeNeedRestartException("TrafficClass cannot change on the fly");
      }

      @Override
      public String[] getPossibleValues() {
        ArrayList<String> array = new ArrayList<>();
        for (TrafficClass tc : TrafficClass.values()) array.add(tc.name());
        return array.toArray(new String[0]);
      }
    }
    nodeConfig.register(
        "trafficClass",
        TrafficClass.getDefault().name(),
        sortOrder++,
        true,
        false,
        "Node.trafficClass",
        "Node.trafficClassLong",
        new TrafficClassCallback());
    String trafficClassValue = nodeConfig.getString("trafficClass");
    try {
      trafficClass = TrafficClass.fromNameOrValue(trafficClassValue);
    } catch (IllegalArgumentException e) {
      LOG.error("Invalid trafficClass:{} resetting the value to default.", trafficClassValue, e);
      trafficClass = TrafficClass.getDefault();
    }
    return sortOrder;
  }

  /**
   * Initializes cryptography, DNS, packet sending, and ticker infrastructure.
   *
   * <p>This method validates configuration sanity, constructs the darknet crypto component, and
   * creates DNS requester, packet sender, and prioritized ticker instances. It also registers
   * shutdown hooks for opennet and darknet crypto. The method does not start networking; callers
   * should invoke {@link #startNetworking()} after other subsystems are ready.
   *
   * @param params bundled initialization inputs including config, executor, shutdown hook, and
   *     security levels; must be non-null and contain non-null fields
   * @param sortOrder current configuration sort order for subsequent registration
   * @return updated sort order after registering crypto configuration options
   * @throws NodeInitException if configuration is invalid or crypto cannot be initialized
   */
  public int initCryptoAndTransport(CryptoAndTransportParams params, int sortOrder)
      throws NodeInitException {
    SubConfig nodeConfig = params.nodeConfig();
    SimpleFieldSet oldConfig = params.oldConfig();
    PriorityAwareExecutor executor = params.executor();
    SemiOrderedShutdownHook shutdownHook = params.shutdownHook();
    SecurityLevels securityLevels = params.securityLevels();
    long startupTime = params.startupTime();
    boolean enableARKs = params.enableARKs();
    if (oldConfig != null && "-1".equals(oldConfig.get("node.listenPort")))
      throw new NodeInitException(
          NodeInitException.EXIT_COULD_NOT_BIND_USM,
          "Your freenet.ini file is corrupted! 'listenPort=-1'");
    NodeCryptoConfig darknetConfig =
        new NodeCryptoConfig(nodeConfig, sortOrder, false, securityLevels);
    sortOrder += NodeCryptoConfig.OPTION_COUNT;

    darknetCrypto = new NodeCrypto(node, false, darknetConfig, startupTime, enableARKs);
    dnsRequester = new DNSRequester(node);
    packetSender = new PacketSender(node);
    ticker = new PrioritizedTicker(executor, darknetCrypto.getPortNumber());
    if (executor instanceof PooledExecutor pooledExecutor) pooledExecutor.setTicker(ticker);

    LOG.info("Creating node...");

    shutdownHook.addEarlyJob(
        new Thread(
            () -> {
              if (opennet != null) opennet.stop(false);
            }));

    shutdownHook.addEarlyJob(new Thread(darknetCrypto::stop));

    return sortOrder;
  }

  /**
   * Registers and applies bandwidth-related configuration.
   *
   * <p>This method registers output and input bandwidth limits, compression thresholds, connection
   * speed detection, and local traffic throttling options. It validates configured values, clamps
   * to the provided minimum bandwidth where appropriate, and initializes the output throttle. The
   * returned sort order reflects all registrations performed within this method.
   *
   * @param nodeConfig node configuration section where bandwidth options are registered; non-null
   * @param sortOrder current configuration sort order for option registration
   * @param minimumBandwidth minimum allowable bandwidth in bytes per second for clamps and defaults
   * @return updated sort order after registering bandwidth and compression options
   * @throws NodeInitException if any bandwidth limit is invalid or throttle creation fails
   */
  public int initBandwidthConfig(SubConfig nodeConfig, int sortOrder, int minimumBandwidth)
      throws NodeInitException {
    sortOrder = registerOutputBandwidthLimit(nodeConfig, sortOrder);
    int outputLimit = initOutputBandwidthLimit(nodeConfig, minimumBandwidth);
    sortOrder = registerInputBandwidthLimit(nodeConfig, sortOrder);
    initInputBandwidthLimit(nodeConfig, minimumBandwidth, outputLimit);
    sortOrder = registerCompressionConfig(nodeConfig, sortOrder);
    initCompressionConfig(nodeConfig);
    sortOrder = registerConnectionSpeedDetection(nodeConfig, sortOrder);
    sortOrder = registerThrottleLocalTraffic(nodeConfig, sortOrder);
    return sortOrder;
  }

  private int registerOutputBandwidthLimit(SubConfig nodeConfig, int sortOrder) {
    nodeConfig.register(
        "outputBandwidthLimit",
        "15K",
        sortOrder++,
        false,
        true,
        "Node.outBWLimit",
        "Node.outBWLimitLong",
        new IntCallback() {
          @Override
          public Integer get() {
            return outputBandwidthLimit;
          }

          @Override
          public void set(Integer obwLimit) throws InvalidConfigValueException {
            BandwidthManager.checkOutputBandwidthLimit(obwLimit);
            try {
              outputThrottle.changeNanosAndBucketSize(SECONDS.toNanos(1) / obwLimit, obwLimit / 2);
            } catch (IllegalArgumentException e) {
              throw new InvalidConfigValueException(e);
            }
            outputBandwidthLimit = obwLimit;
          }
        });
    return sortOrder;
  }

  private int initOutputBandwidthLimit(SubConfig nodeConfig, int minimumBandwidth)
      throws NodeInitException {
    int obwLimit = nodeConfig.getInt("outputBandwidthLimit");
    if (obwLimit < minimumBandwidth) {
      obwLimit = minimumBandwidth;
      LOG.info(
          "Output bandwidth was lower than minimum bandwidth. Increased to minimum bandwidth.");
    }

    outputBandwidthLimit = obwLimit;
    try {
      BandwidthManager.checkOutputBandwidthLimit(outputBandwidthLimit);
    } catch (InvalidConfigValueException e) {
      throw new NodeInitException(NodeInitException.EXIT_BAD_BWLIMIT, e.getMessage());
    }

    int bucketSize = obwLimit / 2;
    try {
      outputThrottle = new OutputThrottle(bucketSize, SECONDS.toNanos(1) / obwLimit, obwLimit / 2);
    } catch (IllegalArgumentException e) {
      throw new NodeInitException(NodeInitException.EXIT_BAD_BWLIMIT, e.getMessage());
    }
    return obwLimit;
  }

  private int registerInputBandwidthLimit(SubConfig nodeConfig, int sortOrder) {
    nodeConfig.register(
        "inputBandwidthLimit",
        "-1",
        sortOrder++,
        false,
        true,
        "Node.inBWLimit",
        "Node.inBWLimitLong",
        new IntCallback() {
          @Override
          public Integer get() {
            if (inputLimitDefault) return -1;
            return inputBandwidthLimit;
          }

          @Override
          public void set(Integer ibwLimit) throws InvalidConfigValueException {
            BandwidthManager.checkInputBandwidthLimit(ibwLimit);
            if (ibwLimit == -1) {
              inputLimitDefault = true;
              ibwLimit = outputBandwidthLimit * 4;
            } else {
              inputLimitDefault = false;
            }
            inputBandwidthLimit = ibwLimit;
          }
        });
    return sortOrder;
  }

  private void initInputBandwidthLimit(SubConfig nodeConfig, int minimumBandwidth, int outputLimit)
      throws NodeInitException {
    int ibwLimit = nodeConfig.getInt("inputBandwidthLimit");
    if (ibwLimit == -1) {
      inputLimitDefault = true;
      ibwLimit = outputLimit * 4;
    } else if (ibwLimit < minimumBandwidth) {
      ibwLimit = minimumBandwidth;
      LOG.info("Input bandwidth was lower than minimum bandwidth. Increased to minimum bandwidth.");
    }
    inputBandwidthLimit = ibwLimit;
    try {
      BandwidthManager.checkInputBandwidthLimit(inputBandwidthLimit);
    } catch (InvalidConfigValueException e) {
      throw new NodeInitException(NodeInitException.EXIT_BAD_BWLIMIT, e.getMessage());
    }
  }

  private int registerCompressionConfig(SubConfig nodeConfig, int sortOrder) {
    nodeConfig.register(
        "amountOfDataToCheckCompressionRatio",
        "8MiB",
        sortOrder++,
        true,
        true,
        "Node.amountOfDataToCheckCompressionRatio",
        "Node.amountOfDataToCheckCompressionRatioLong",
        new LongCallback() {
          @Override
          public Long get() {
            return amountOfDataToCheckCompressionRatio;
          }

          @Override
          public void set(Long amountOfDataToCheckCompressionRatio) {
            if (amountOfDataToCheckCompressionRatio < 0
                || amountOfDataToCheckCompressionRatio > 100 * 1024 * 1024) {
              LOG.info(
                  "Amount of data to check for compression should be 100 MiB max, {} bytes"
                      + " selected",
                  amountOfDataToCheckCompressionRatio);
              return;
            }
            NodeNetworkSubsystem.this.amountOfDataToCheckCompressionRatio =
                amountOfDataToCheckCompressionRatio;
          }
        },
        true);

    nodeConfig.register(
        "minimumCompressionPercentage",
        "10",
        sortOrder++,
        true,
        true,
        "Node.minimumCompressionPercentage",
        "Node.minimumCompressionPercentageLong",
        new IntCallback() {
          @Override
          public Integer get() {
            return minimumCompressionPercentage;
          }

          @Override
          public void set(Integer minimumCompressionPercentage) {
            if (minimumCompressionPercentage < 0 || minimumCompressionPercentage > 100) {
              LOG.info(
                  "Wrong minimum compression percentage: must be between 0 and 100, but is {}",
                  minimumCompressionPercentage);
              return;
            }

            NodeNetworkSubsystem.this.minimumCompressionPercentage = minimumCompressionPercentage;
          }
        },
        Dimension.NOT);
    return sortOrder;
  }

  private void initCompressionConfig(SubConfig nodeConfig) {
    amountOfDataToCheckCompressionRatio = nodeConfig.getLong("amountOfDataToCheckCompressionRatio");
    minimumCompressionPercentage = nodeConfig.getInt("minimumCompressionPercentage");
    nodeConfig.registerIgnoredOption("maxTimeForSingleCompressor");
  }

  private int registerConnectionSpeedDetection(SubConfig nodeConfig, int sortOrder) {
    nodeConfig.register(
        "connectionSpeedDetection",
        true,
        sortOrder++,
        true,
        true,
        "Node.connectionSpeedDetection",
        "Node.connectionSpeedDetectionLong",
        new BooleanCallback() {
          @Override
          public Boolean get() {
            return connectionSpeedDetection;
          }

          @Override
          public void set(Boolean connectionSpeedDetection) {
            NodeNetworkSubsystem.this.connectionSpeedDetection = connectionSpeedDetection;
          }
        });

    connectionSpeedDetection = nodeConfig.getBoolean("connectionSpeedDetection");
    return sortOrder;
  }

  private int registerThrottleLocalTraffic(SubConfig nodeConfig, int sortOrder) {
    nodeConfig.register(
        "throttleLocalTraffic",
        false,
        sortOrder++,
        true,
        false,
        "Node.throttleLocalTraffic",
        "Node.throttleLocalTrafficLong",
        new BooleanCallback() {

          @Override
          public Boolean get() {
            return throttleLocalData;
          }

          @Override
          public void set(Boolean val) {
            throttleLocalData = val;
          }
        });

    throttleLocalData = nodeConfig.getBoolean("throttleLocalTraffic");
    return sortOrder;
  }

  /**
   * Registers and initializes opennet configuration and runtime state.
   *
   * <p>This method creates an opennet sub-config, registers enablement and peer-count settings,
   * constructs opennet crypto configuration, and conditionally starts the opennet manager. It also
   * installs a threat-level listener that enables or disables opennet dynamically and updates
   * forwarding state. Callers should invoke this during node startup before peers are loaded.
   *
   * @param config persistent configuration root used to create the opennet sub-config; non-null
   * @param nodeConfig main node configuration section used for pass-through settings; non-null
   * @param sortOrder current configuration sort order for option registration
   * @return updated sort order after registering opennet-related options
   * @throws NodeInitException if opennet initialization fails due to configuration or crypto errors
   */
  public int initOpennet(PersistentConfig config, SubConfig nodeConfig, int sortOrder)
      throws NodeInitException {
    final SubConfig opennetConfig = config.createSubConfig("node.opennet");
    registerSeednodeConfig(opennetConfig);
    isAllowedToConnectToSeednodes = opennetConfig.getBoolean("connectToSeednodes");

    registerOpennetEnabledConfig(opennetConfig);
    boolean opennetEnabled = opennetConfig.getBoolean("enabled");

    registerMaxOpennetPeers(opennetConfig);
    initMaxOpennetPeers(opennetConfig);

    opennetCryptoConfig =
        new NodeCryptoConfig(opennetConfig, 2, true, node.services().securityLevels());
    initOpennetManager(opennetEnabled);
    registerThreatLevelListener();

    registerAcceptSeedConnections(opennetConfig);
    acceptSeedConnections = opennetConfig.getBoolean("acceptSeedConnections");
    applyAcceptSeedConnections();

    opennetConfig.finishedInitialization();

    sortOrder = registerPassOpennetPeers(nodeConfig, sortOrder);
    passOpennetRefsThroughDarknet = nodeConfig.getBoolean("passOpennetPeersThroughDarknet");

    return sortOrder;
  }

  private void registerSeednodeConfig(SubConfig opennetConfig) {
    opennetConfig.register(
        "connectToSeednodes",
        true,
        0,
        true,
        false,
        "Node.withAnnouncement",
        "Node.withAnnouncementLong",
        new BooleanCallback() {
          @Override
          public Boolean get() {
            return isAllowedToConnectToSeednodes;
          }

          @Override
          public void set(Boolean val) throws NodeNeedRestartException {
            if (get().equals(val)) return;
            if (opennet != null)
              throw new NodeNeedRestartException(
                  l10n("connectToSeednodesCannotBeChangedMustDisableOpennetOrReboot"));
            isAllowedToConnectToSeednodes = val;
          }
        });
  }

  private void registerOpennetEnabledConfig(SubConfig opennetConfig) {
    opennetConfig.register(
        "enabled",
        false,
        0,
        true,
        true,
        "Node.opennetEnabled",
        "Node.opennetEnabledLong",
        new BooleanCallback() {
          @Override
          public Boolean get() {
            return opennet != null;
          }

          @Override
          public void set(Boolean val) throws InvalidConfigValueException {
            OpennetManager o;
            boolean enable = Boolean.TRUE.equals(val);
            if (enable == (opennet != null)) return;
            if (enable) {
              try {
                o =
                    opennet =
                        new OpennetManager(
                            node,
                            opennetCryptoConfig,
                            System.currentTimeMillis(),
                            isAllowedToConnectToSeednodes);
              } catch (NodeInitException e) {
                opennet = null;
                throw new InvalidConfigValueException(e.getMessage());
              }
            } else {
              o = opennet;
              opennet = null;
            }
            if (enable) o.start();
            else o.stop(true);
            ipDetector.notifyPortChange(publicInterfacePorts());
          }
        });
  }

  private void registerMaxOpennetPeers(SubConfig opennetConfig) {
    opennetConfig.register(
        "maxOpennetPeers",
        OpennetManager.MAX_PEERS_FOR_SCALING,
        1,
        true,
        false,
        "Node.maxOpennetPeers",
        "Node.maxOpennetPeersLong",
        new IntCallback() {
          @Override
          public Integer get() {
            return maxOpennetPeers;
          }

          @Override
          public void set(Integer inputMaxOpennetPeers) throws InvalidConfigValueException {
            if (inputMaxOpennetPeers < 0)
              throw new InvalidConfigValueException(l10n("mustBePositive"));
            if (inputMaxOpennetPeers > OpennetManager.MAX_PEERS_FOR_SCALING)
              throw new InvalidConfigValueException(
                  l10n(
                      "maxOpennetPeersMustBeTwentyOrLess",
                      "maxpeers",
                      Integer.toString(OpennetManager.MAX_PEERS_FOR_SCALING)));
            maxOpennetPeers = inputMaxOpennetPeers;
          }
        },
        false);
  }

  private void initMaxOpennetPeers(SubConfig opennetConfig) {
    maxOpennetPeers = opennetConfig.getInt("maxOpennetPeers");
    if (maxOpennetPeers > OpennetManager.MAX_PEERS_FOR_SCALING) {
      LOG.error("maxOpennetPeers may not be over {}", OpennetManager.MAX_PEERS_FOR_SCALING);
      maxOpennetPeers = OpennetManager.MAX_PEERS_FOR_SCALING;
    }
  }

  private void initOpennetManager(boolean opennetEnabled) throws NodeInitException {
    if (opennetEnabled) {
      opennet =
          new OpennetManager(
              node, opennetCryptoConfig, System.currentTimeMillis(), isAllowedToConnectToSeednodes);
    } else {
      opennet = null;
    }
  }

  private void registerThreatLevelListener() {
    node.services()
        .securityLevels()
        .addNetworkThreatLevelListener(
            (_, newLevel) -> {
              if (newLevel == SecurityLevels.NETWORK_THREAT_LEVEL.HIGH
                  || newLevel == SecurityLevels.NETWORK_THREAT_LEVEL.MAXIMUM) {
                handleHighThreatLevel();
              } else if (newLevel == SecurityLevels.NETWORK_THREAT_LEVEL.NORMAL
                  || newLevel == SecurityLevels.NETWORK_THREAT_LEVEL.LOW) {
                handleNormalThreatLevel();
              }
              node.getConfig().store();
            });
  }

  private void handleHighThreatLevel() {
    OpennetManager om = opennet;
    if (om != null) {
      opennet = null;
      om.stop(true);
      ipDetector.notifyPortChange(publicInterfacePorts());
    }
  }

  private void handleNormalThreatLevel() {
    OpennetManager o = null;
    if (opennet == null) {
      try {
        o =
            opennet =
                new OpennetManager(
                    node,
                    opennetCryptoConfig,
                    System.currentTimeMillis(),
                    isAllowedToConnectToSeednodes);
      } catch (NodeInitException e) {
        opennet = null;
        LOG.error("UNABLE TO ENABLE OPENNET: {}", e, e);
        node.services()
            .clientCore()
            .getAlerts()
            .register(
                new SimpleUserAlert(
                    false,
                    l10n("enableOpennetFailedTitle"),
                    l10n("enableOpennetFailed", "message", e.getLocalizedMessage()),
                    l10n("enableOpennetFailed", "message", e.getLocalizedMessage()),
                    UserAlert.ERROR));
      }
    }
    if (o != null) {
      o.start();
      ipDetector.notifyPortChange(publicInterfacePorts());
    }
  }

  private void registerAcceptSeedConnections(SubConfig opennetConfig) {
    opennetConfig.register(
        "acceptSeedConnections",
        false,
        2,
        true,
        true,
        "Node.acceptSeedConnectionsShort",
        "Node.acceptSeedConnections",
        new BooleanCallback() {

          @Override
          public Boolean get() {
            return acceptSeedConnections;
          }

          @Override
          public void set(Boolean val) {
            acceptSeedConnections = val;
          }
        });
  }

  private void applyAcceptSeedConnections() {
    if (acceptSeedConnections && opennet != null)
      opennet.getCrypto().getSocket().getAddressTracker().setHugeTracker();
  }

  private int registerPassOpennetPeers(SubConfig nodeConfig, int sortOrder) {
    nodeConfig.register(
        "passOpennetPeersThroughDarknet",
        true,
        sortOrder++,
        true,
        false,
        "Node.passOpennetPeersThroughDarknet",
        "Node.passOpennetPeersThroughDarknetLong",
        new BooleanCallback() {

          @Override
          public Boolean get() {
            return passOpennetRefsThroughDarknet;
          }

          @Override
          public void set(Boolean val) {
            passOpennetRefsThroughDarknet = val;
          }
        });
    return sortOrder;
  }

  private String l10n(String key) {
    return NodeL10n.getBase().getString("Node." + key);
  }

  private String l10n(String key, String pattern, String value) {
    return NodeL10n.getBase().getString("Node." + key, pattern, value);
  }

  /**
   * Initializes the peer manager with the provided shutdown hook.
   *
   * <p>This method constructs a new {@link PeerManager} instance and associates it with the owning
   * node and shutdown hook. It does not load peer references or start background work; callers are
   * expected to invoke {@link #readPeers(ProgramDirectory)} and {@link #startPeers()} during
   * startup. The manager reference is replaced without attempting to stop any previous instance.
   *
   * @param shutdownHook hook used for orderly shutdown of peer components; must be non-null
   */
  public void initPeers(SemiOrderedShutdownHook shutdownHook) {
    peers = new PeerManager(node, shutdownHook);
  }

  /**
   * Attempts to read persisted peer references from disk.
   *
   * <p>This method builds the expected peers filename from the current darknet port and delegates
   * loading to the {@link PeerManager}. It does not throw on missing files and does not start any
   * network activity. Callers typically invoke this early in startup after crypto initialization so
   * the peer manager can rebuild its state from the stored files.
   *
   * @param nodeDir program directory used to locate the peers file; must be non-null
   */
  public void readPeers(ProgramDirectory nodeDir) {
    peers.tryReadPeers(
        nodeDir.file("peers-" + darknetPortNumber()).getPath(), darknetCrypto, null, false, false);
  }

  /**
   * Starts the peer manager's background processing.
   *
   * <p>Starting peers activates scheduled tasks, connection management, and peer status tracking.
   * This method assumes {@link #initPeers(SemiOrderedShutdownHook)} was called and does not perform
   * any additional validation. It delegates directly to {@link PeerManager#start()}.
   */
  public void startPeers() {
    peers.start();
  }

  /**
   * Updates the peer manager's user alert status.
   *
   * <p>This method requests the peer manager to refresh any user-facing alerts related to peer
   * connectivity or health. It is a lightweight delegation intended for UI or periodic status
   * updates. The method performs no synchronization and expects the peer manager to be initialized.
   */
  public void updatePeerManagerUserAlert() {
    peers.updatePMUserAlert();
  }

  /**
   * Loads additional peer metadata stored separately from the main peers file.
   *
   * <p>The peer manager may persist auxiliary data (such as counters or transient state) in
   * separate files. This method delegates the read to {@link PeerManager#readExtraPeerData()} and
   * performs no error handling beyond that. It should be called after {@link #readPeers}.
   */
  public void readExtraPeerData() {
    peers.readExtraPeerData();
  }

  /**
   * Reports whether any peers are currently connected.
   *
   * <p>This method delegates to the peer manager and returns {@code true} if at least one peer is
   * connected at the time of the call. The value may change immediately after the method returns,
   * and callers should treat it as a snapshot rather than a stable state indicator.
   *
   * @return {@code true} if any connected peers exist, {@code false} otherwise
   */
  public boolean anyConnectedPeers() {
    return peers.anyConnectedPeers();
  }

  /**
   * Returns a human-readable peer status string.
   *
   * <p>If the peer manager is not yet initialized, this method returns a fixed fallback message.
   * Otherwise, it delegates to {@link PeerManager#getStatus()} which may include counts and health
   * indicators. The returned string is intended for UI display and is not guaranteed to be stable
   * across releases.
   *
   * @return status text summarizing current peer state
   */
  public String peerStatus() {
    return peers != null ? peers.getStatus() : "No peers yet";
  }

  /**
   * Returns the peer list formatted for the text mode client interface.
   *
   * <p>This method returns an empty string when peers have not been initialized. When available,
   * the value is produced by {@link PeerManager#getTMCIPeerList()} and may include multiple lines.
   * It is intended for display and should not be parsed for program logic.
   *
   * @return formatted peer list for TMCI, or an empty string if unavailable
   */
  public String tmciPeerList() {
    return peers != null ? peers.getTMCIPeerList() : "";
  }

  /**
   * Initializes the node dispatcher and binds it to the message core.
   *
   * <p>This method constructs a new {@link NodeDispatcher} and registers it with the message core
   * so inbound messages are routed correctly. It does not start the dispatcher; callers should
   * invoke {@link #startDispatcher()} after initialization is complete.
   */
  public void initDispatcher() {
    dispatcher = new NodeDispatcher(node);
    usm.setDispatcher(dispatcher);
  }

  /**
   * Initializes the uptime estimator.
   *
   * <p>The uptime estimator uses a file under the runtime directory and the current node identity
   * to estimate uptime and restarts. This method constructs the estimator but does not start its
   * periodic updates; callers should invoke {@link #startNetworking()} which starts it as part of
   * network startup.
   *
   * @param runDir runtime directory used for uptime tracking files; must be non-null
   */
  public void initUptime(ProgramDirectory runDir) {
    uptimeEstimator = new UptimeEstimator(runDir, ticker, darknetCrypto.getIdentityHash());
  }

  /**
   * Registers a callback hook on the dispatcher.
   *
   * <p>This method is intended for instrumentation and testing, allowing callers to observe or
   * intercept dispatch events. The hook is stored in the dispatcher and can influence routing
   * behavior depending on dispatcher implementation. Passing {@code null} clears the hook.
   *
   * @param cb dispatcher callback to install, or {@code null} to remove an existing hook
   */
  public void setDispatcherHook(NodeDispatcher.NodeDispatcherCallback cb) {
    dispatcher.setHook(cb);
  }

  /**
   * Reads darknet crypto state from a field set.
   *
   * <p>This method delegates to {@link NodeCrypto#readCrypto(SimpleFieldSet)} and expects the field
   * set to contain serialized cryptographic state. It performs no validation beyond the underlying
   * implementation. Callers should pass the previously stored private fields for the darknet node
   * reference.
   *
   * @param fs field set containing serialized crypto state; must be non-null
   * @throws IOException if the crypto state cannot be parsed or applied
   */
  public void readDarknetCrypto(SimpleFieldSet fs) throws IOException {
    darknetCrypto.readCrypto(fs);
  }

  /**
   * Applies UDP address hints from a field set to the IP detector.
   *
   * <p>This method scans {@code physical.udp} entries, parses each as a peer address, and if a
   * parsed entry matches the current darknet port, it records the address as the old IP for
   * detection purposes. Unknown hosts or syntax errors are logged and ignored. The method returns
   * after the first matching address.
   *
   * @param fs field set that may contain {@code physical.udp} entries; must be non-null
   * @throws IOException if a peer entry is malformed beyond recoverable parsing errors
   */
  public void applyUdpFromFieldSet(SimpleFieldSet fs) throws IOException {
    String[] udp = fs.getAll("physical.udp");
    if (udp == null) return;
    for (String udpAddr : udp) {
      Peer p;
      try {
        p = new Peer(udpAddr, false, true);
      } catch (UnknownHostException _) {
        LOG.info(
            "Unknown host while parsing our darknet node reference: {} (likely host-local scope or"
                + " transient DNS)",
            udpAddr);
        p = null;
      } catch (HostnameSyntaxException _) {
        LOG.error(
            "Invalid hostname or IP Address syntax error while parsing our darknet node reference:"
                + " {}",
            udpAddr);
        p = null;
      } catch (PeerParseException e) {
        throw new IOException(e);
      }
      if (p != null && p.getPort() == darknetPortNumber()) {
        // DNSRequester doesn't deal with our own node
        setOldIPAddress(p.getFreenetAddress());
        return;
      }
    }
  }

  /**
   * Initializes the darknet cryptographic component.
   *
   * <p>This method delegates to {@link NodeCrypto#initCrypto()} and should be called after
   * configuration has been registered but before using any cryptographic output. It does not start
   * networking, and it assumes the crypto instance was created via {@link
   * #initCryptoAndTransport(CryptoAndTransportParams, int)}.
   */
  public void initDarknetCrypto() {
    darknetCrypto.initCrypto();
  }

  /**
   * Returns the hash of the darknet identity hash.
   *
   * <p>The returned byte array is owned by the underlying crypto component and should be treated as
   * immutable by callers. It is typically used for identification and routing purposes. The value
   * is available after crypto initialization.
   *
   * @return byte array containing the hash of the identity hash
   */
  public byte[] darknetIdentityHashHash() {
    return darknetCrypto.getIdentityHashHash();
  }

  /**
   * Writes opennet state to disk if opennet is enabled.
   *
   * <p>If opennet is not enabled, this method performs no action. When enabled, it delegates to
   * {@link OpennetManager#writeFile()} to persist opennet cryptographic state. Callers may invoke
   * this during shutdown or periodic maintenance.
   */
  public void writeOpennetFile() {
    if (opennet != null) opennet.writeFile();
  }

  /**
   * Starts networking components in a defined order.
   *
   * <p>This method starts the DNS requester, uptime estimator, darknet crypto, opennet (if
   * enabled), ticker, and finally the message core. It assumes all corresponding init methods have
   * been called. The method does not block for readiness and returns immediately after starting
   * each component.
   */
  public void startNetworking() {
    dnsRequester.start();
    uptimeEstimator.start();
    darknetCrypto.start();
    if (opennet != null) opennet.start();
    ticker.start();
    usm.start(ticker);
  }

  /**
   * Returns the current size of the unclaimed message FIFO.
   *
   * <p>The message core uses an internal FIFO for messages that have not yet been claimed by a
   * handler. This method provides a snapshot count for diagnostics. The returned value may change
   * immediately after the call, and it should not be used for strict flow control.
   *
   * @return number of messages currently in the unclaimed FIFO
   */
  public int unclaimedFifoSize() {
    return usm.getUnclaimedFIFOSize();
  }

  /**
   * Returns the current peer manager instance.
   *
   * <p>The returned instance is the internal peer manager used by the node. It may be {@code null}
   * before {@link #initPeers(SemiOrderedShutdownHook)} is called. Callers should not replace or
   * stop this instance directly; use the subsystem methods to manage peers.
   *
   * @return the peer manager, or {@code null} if not initialized
   */
  public PeerManager peers() {
    return peers;
  }

  /**
   * Returns the node statistics instance.
   *
   * <p>The stats object is initialized by {@link #initNodeStats(PersistentConfig, int)} and may be
   * {@code null} beforehand. Callers should treat the returned instance as owned by the subsystem
   * and avoid modifying its internal state except through its public API.
   *
   * @return node statistics instance, or {@code null} if not initialized
   */
  public NodeStats stats() {
    return nodeStats;
  }

  /**
   * Returns the node's priority-aware executor.
   *
   * <p>This method delegates to {@link Node#getExecutor()} and provides a convenient access point
   * for components that need to schedule prioritized work. The executor is shared across the node
   * and should not be shut down by callers.
   *
   * @return priority-aware executor associated with the node
   */
  public PriorityAwareExecutor executor() {
    return node.getExecutor();
  }

  /**
   * Returns the darknet cryptographic component.
   *
   * <p>The returned instance is created during crypto initialization and is owned by the subsystem.
   * Callers may use it to access keys or sockets but should avoid altering its internal
   * configuration directly. The value is {@code null} before {@link
   * #initCryptoAndTransport(CryptoAndTransportParams, int)}.
   *
   * @return darknet crypto component, or {@code null} if not initialized
   */
  public NodeCrypto darknetCrypto() {
    return darknetCrypto;
  }

  /**
   * Returns the packet sender used for outbound traffic.
   *
   * <p>The packet sender is created during crypto/transport initialization and started via {@link
   * #startPacketSender()}. The returned instance is shared; callers should not manage its lifecycle
   * directly. It may be {@code null} before initialization.
   *
   * @return packet sender instance, or {@code null} if not initialized
   */
  public PacketSender packetSender() {
    return packetSender;
  }

  /**
   * Returns the output bandwidth throttle.
   *
   * <p>The throttle is created as part of bandwidth configuration and is used to enforce the
   * configured output limit. The returned instance is mutable and shared; callers should treat it
   * as an internal implementation detail and avoid changing it outside configuration callbacks.
   *
   * @return output throttle instance, or {@code null} if bandwidth config not initialized
   */
  public OutputThrottle outputThrottle() {
    return outputThrottle;
  }

  /**
   * Returns the I/O statistics collector.
   *
   * <p>The collector gathers byte counters and other transport metrics. It is initialized via
   * {@link #initCollector()} and may be {@code null} before that point. The returned instance is
   * owned by the subsystem and should be treated as read-only by callers.
   *
   * @return I/O statistics collector, or {@code null} if not initialized
   */
  public IOStatisticCollector collector() {
    return collector;
  }

  /**
   * Returns the DNS requester component.
   *
   * <p>The DNS requester is created during crypto initialization and started in {@link
   * #startNetworking()}. It handles asynchronous DNS lookups for networking. The returned instance
   * may be {@code null} before initialization.
   *
   * @return DNS requester instance, or {@code null} if not initialized
   */
  public DNSRequester dnsRequester() {
    return dnsRequester;
  }

  /**
   * Returns the uptime estimator.
   *
   * <p>The uptime estimator is created via {@link #initUptime(ProgramDirectory)} and started as
   * part of {@link #startNetworking()}. It can be used to query the node's estimated uptime and
   * restart behavior. The instance may be {@code null} before initialization.
   *
   * @return uptime estimator, or {@code null} if not initialized
   */
  public UptimeEstimator uptimeEstimator() {
    return uptimeEstimator;
  }

  /**
   * Returns the node dispatcher.
   *
   * <p>The dispatcher is responsible for routing messages through the node's protocol stack. It is
   * created by {@link #initDispatcher()} and started by {@link #startDispatcher()}. The returned
   * instance is owned by the subsystem and may be {@code null} before initialization.
   *
   * @return dispatcher instance, or {@code null} if not initialized
   */
  public NodeDispatcher dispatcher() {
    return dispatcher;
  }

  /**
   * Returns the opennet manager when opennet is enabled.
   *
   * <p>If opennet is disabled or could not be initialized, this method returns {@code null}. The
   * returned instance is managed by the subsystem and may be started or stopped based on security
   * threat levels. Callers should treat it as read-only and avoid lifecycle control.
   *
   * @return opennet manager, or {@code null} if opennet is disabled
   */
  public OpennetManager opennet() {
    return opennet;
  }

  /**
   * Returns the location manager.
   *
   * <p>The location manager tracks and updates node location for routing. It is created by {@link
   * #initLocationManager()} and started by {@link #startLocationManager()}. The instance may be
   * {@code null} if initialization has not occurred.
   *
   * @return location manager, or {@code null} if not initialized
   */
  public LocationManager locationManager() {
    return locationManager;
  }

  /**
   * Returns the message core used for protocol messaging.
   *
   * <p>The message core is created in {@link #initMessagingCore(PriorityAwareExecutor)} and started
   * by {@link #startNetworking()}. It is central to message routing and should not be stopped or
   * replaced by callers. The instance may be {@code null} before initialization.
   *
   * @return message core instance, or {@code null} if not initialized
   */
  public MessageCore usm() {
    return usm;
  }

  /**
   * Returns the IP detector.
   *
   * <p>The IP detector observes connectivity to determine external addresses and MTU constraints.
   * It is created by {@link #initMessagingCore(PriorityAwareExecutor)} and started by {@link
   * #startIpDetector()}. The returned instance may be {@code null} before initialization.
   *
   * @return IP detector instance, or {@code null} if not initialized
   */
  public NodeIPDetector ipDetector() {
    return ipDetector;
  }

  /**
   * Returns the prioritized ticker used for scheduling.
   *
   * <p>The ticker is created during crypto/transport initialization and started as part of {@link
   * #startNetworking()}. It provides timed callbacks for networking components. The returned
   * instance may be {@code null} before initialization.
   *
   * @return ticker instance, or {@code null} if not initialized
   */
  public Ticker ticker() {
    return ticker;
  }

  /**
   * Returns the darknet port number in use by the crypto component.
   *
   * <p>This value is read from the initialized {@link NodeCrypto} instance. It reflects the UDP
   * port configured for darknet transport and is used to construct filenames and peer addresses.
   * The value is undefined if crypto has not been initialized.
   *
   * @return darknet UDP port number
   */
  public int darknetPortNumber() {
    return darknetCrypto.getPortNumber();
  }

  /**
   * Returns the stored localhost address as a {@link FreenetInetAddress}.
   *
   * <p>This value is set by {@link #initLocalhost()} and represents the loopback address used for
   * local networking checks. The returned object is immutable. It may be {@code null} if localhost
   * initialization has not yet occurred.
   *
   * @return localhost address wrapper, or {@code null} if not initialized
   */
  public FreenetInetAddress freenetLocalhostAddress() {
    return freenetLocalhostAddress;
  }

  /**
   * Returns the current array of darknet peer connections.
   *
   * <p>The returned array is provided by the peer manager's roster and represents currently known
   * darknet peers. The array contents may change after the call as peers connect or disconnect. The
   * returned array is owned by the roster and should not be modified by callers.
   *
   * @return array of darknet peer nodes, possibly empty but never {@code null}
   */
  public DarknetPeerNode[] darknetConnections() {
    return peers.roster().getDarknetPeers();
  }

  /**
   * Returns all peer nodes known to the peer manager.
   *
   * <p>This method delegates to {@link PeerManager#myPeers()} and returns the array directly. The
   * returned array may include both darknet and opennet peers depending on configuration. The
   * contents are a snapshot and may change immediately after the call.
   *
   * @return array of peer nodes, possibly empty but never {@code null}
   */
  public PeerNode[] peerNodes() {
    return peers.myPeers();
  }

  /**
   * Returns the array of currently connected peer nodes.
   *
   * <p>The peer manager determines connected state based on its internal connection tracking. The
   * returned array reflects a snapshot at the time of the call and may change immediately
   * afterward. Callers should treat the array as read-only.
   *
   * @return array of connected peers, possibly empty but never {@code null}
   */
  public PeerNode[] connectedPeers() {
    return peers.connectedPeers();
  }

  /**
   * Resolves a peer node by identity, address, or darknet name.
   *
   * <p>This method iterates over known peers and compares the provided identifier to the peer's
   * identity string, rendered network address, and (for darknet peers) configured nickname. The
   * first match is returned. If no peers match, the method returns {@code null}. The matching is
   * case-sensitive and performs no normalization.
   *
   * @param nodeIdentifier identity string, peer address, or darknet name to match; must be non-null
   * @return matching peer node, or {@code null} if no peer matches
   */
  public PeerNode getPeerNode(String nodeIdentifier) {
    for (PeerNode pn : peers.myPeers()) {
      Peer peer = pn.getPeer();
      String nodeIpAndPort = "";
      if (peer != null) {
        nodeIpAndPort = peer.toString();
      }
      String identity = pn.getIdentityString();
      if (pn instanceof DarknetPeerNode dpn) {
        String name = dpn.getName();
        if (identity.equals(nodeIdentifier)
            || nodeIpAndPort.equals(nodeIdentifier)
            || name.equals(nodeIdentifier)) {
          return pn;
        }
      } else {
        if (identity.equals(nodeIdentifier) || nodeIpAndPort.equals(nodeIdentifier)) {
          return pn;
        }
      }
    }
    return null;
  }

  /**
   * Sends a routed ping and waits for a routed pong response.
   *
   * <p>This method constructs a routed ping message using a random UID and counter, dispatches it
   * via the node dispatcher, and waits up to five seconds for a matching routed pong. If the wait
   * fails, disconnects, or a rejection is received, it returns {@code -1}. On success, it returns
   * the counter delta reported by the responder.
   *
   * @param loc2 target location for the ping, expressed as a routing location
   * @param pubKeyHash public key hash of the target, used for routing and verification; non-null
   * @return counter delta from the pong, or {@code -1} on timeout or rejection
   */
  public int routedPing(double loc2, byte[] pubKeyHash) {
    long uid = node.bootstrap().random().nextLong();
    int initialX = node.bootstrap().random().nextInt();
    Message m = DMT.createFNPRoutedPing(uid, loc2, node.maxHTL(), initialX, pubKeyHash);
    LOG.info("Message: {}", m);

    MessageFilter filter =
        MessageFilter.create().setField(DMT.UID, uid).setType(DMT.FNPRoutedPong).setTimeout(5000);
    CountDownLatch latch = new CountDownLatch(1);
    AtomicReference<Message> replyRef = new AtomicReference<>();
    AsyncMessageFilterCallback callback =
        new AsyncMessageFilterCallback() {
          @Override
          public void onMatched(Message msg) {
            replyRef.set(msg);
            latch.countDown();
          }

          @Override
          public boolean shouldTimeout() {
            return false;
          }

          @Override
          public void onTimeout() {
            latch.countDown();
          }

          @Override
          public void onDisconnect(PeerContext ctx) {
            latch.countDown();
          }

          @Override
          public void onRestarted(PeerContext ctx) {
            latch.countDown();
          }
        };
    try {
      usm().addAsyncFilter(filter, callback, null);
    } catch (DisconnectedException _) {
      LOG.info("Disconnected while registering pong filter");
      return -1;
    }

    dispatcher().handleRouted(m, null);
    try {
      if (!latch.await(5, SECONDS)) return -1;
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      return -1;
    }
    m = replyRef.get();
    if (m == null) return -1;
    if (m.getSpec() == DMT.FNPRoutedRejected) return -1;
    return m.getInt(DMT.COUNTER) - initialX;
  }

  /**
   * Broadcasts a disconnect message to all peers.
   *
   * <p>This method constructs a disconnect message and asks the peer messenger to broadcast it. Any
   * exceptions are caught and logged because this method is typically called during shutdown and
   * should not interfere with exit processing. The method makes no guarantees that all peers
   * receive the message.
   */
  public void broadcastDisconnect() {
    try {
      Message msg = DMT.createFNPDisconnect(false, false, -1, new ShortBuffer(new byte[0]));
      peers.messenger().localBroadcast(msg, true, false, peers.messenger().getDisconnCounter());
    } catch (Exception t) {
      try {
        LOG.error("Failed to tell peers we are going down: {}", t, t);
      } catch (Exception _) {
        // Ignore. We don't want to mess up the exit process!
      }
    }
  }

  /**
   * Sets the fetch context used for ARK (address resolution key) fetches.
   *
   * <p>The provided context is stored and later returned by {@link #arkFetcherContext()}. This
   * method does not clone or validate the context and does not start any network activity. Callers
   * typically provide a shared {@link FetchContext} configured for lightweight fetches. Passing
   * {@code null} clears the stored reference.
   *
   * @param ctx fetch context to store for ARK fetchers, or {@code null} to clear
   */
  public void setArkFetcherContext(FetchContext ctx) {
    this.arkFetcherContext = ctx;
  }

  /**
   * Returns the current ARK fetcher context.
   *
   * <p>This method simply returns the stored context reference. The returned instance is owned by
   * the caller that configured it and may be mutable. It may be {@code null} if no context has been
   * set yet.
   *
   * @return fetch context used for ARK fetchers, or {@code null} if unset
   */
  public FetchContext arkFetcherContext() {
    return arkFetcherContext;
  }

  /**
   * Returns the configured output bandwidth limit.
   *
   * <p>The value is derived during {@link #initBandwidthConfig(SubConfig, int, int)} and stored in
   * bytes per second. It reflects any minimum-bandwidth clamping and validation. The returned value
   * is a snapshot and may change if configuration callbacks are triggered at runtime.
   *
   * @return output bandwidth limit in bytes per second
   */
  public int outputBandwidthLimit() {
    return outputBandwidthLimit;
  }

  /**
   * Returns the configured input bandwidth limit.
   *
   * <p>The value is set during bandwidth initialization and may represent a default derived from
   * the output limit when the config uses {@code -1}. The returned value is in bytes per second and
   * may change if configuration callbacks adjust it during runtime.
   *
   * @return input bandwidth limit in bytes per second
   */
  public int inputBandwidthLimit() {
    return inputBandwidthLimit;
  }

  /**
   * Reports whether local traffic throttling is enabled.
   *
   * <p>This flag is configured via the {@code throttleLocalTraffic} option and controls whether
   * local loopback traffic is subject to bandwidth throttling. It is read as a simple boolean and
   * does not perform any additional checks. The value may be updated by configuration callbacks.
   *
   * @return {@code true} if local traffic throttling is enabled, {@code false} otherwise
   */
  public boolean isThrottleLocalData() {
    return throttleLocalData;
  }

  /**
   * Returns the configured traffic class for network sockets.
   *
   * <p>The traffic class is determined by the {@code trafficClass} config option and reflects the
   * last successfully parsed value. It indicates how sockets should be configured for QoS/DSCP. The
   * returned enum is never {@code null} once initialization completes.
   *
   * @return configured traffic class for network sockets
   */
  public TrafficClass trafficClass() {
    return trafficClass;
  }

  /**
   * Returns the node's current routing location.
   *
   * <p>This value is maintained by the {@link LocationManager} and reflects the node's location in
   * the routing keyspace. The value is updated over time through swap operations and should be
   * treated as a snapshot for diagnostics and routing heuristics.
   *
   * @return current routing location as a double
   */
  public double location() {
    return locationManager.getLocation();
  }

  /**
   * Returns the cumulative location change for the current session.
   *
   * <p>This value is provided by the location manager and represents how much the node's location
   * has shifted since the current session started. It is used for diagnostics and may help detect
   * instability or swap behavior anomalies.
   *
   * @return session location change metric
   */
  public double locationChangeSession() {
    return locationManager.getLocChangeSession();
  }

  /**
   * Returns the average outgoing swap time.
   *
   * <p>The returned value is computed by the location manager and represents the average time in
   * milliseconds (or internal units) for outgoing swaps. It is intended for monitoring and tuning
   * and may change as more swaps are recorded.
   *
   * @return average outgoing swap time, as reported by the location manager
   */
  public int averageOutgoingSwapTime() {
    return locationManager.getAverageSwapTime();
  }

  /**
   * Returns the current swap send interval.
   *
   * <p>This interval is managed by the location manager and controls how frequently swap attempts
   * are initiated. The value is in milliseconds and may be adjusted dynamically based on network
   * conditions. Callers should treat it as a snapshot.
   *
   * @return swap send interval in milliseconds
   */
  public long sendSwapInterval() {
    return locationManager.getSendSwapInterval();
  }

  /**
   * Returns the number of remote peer locations observed during swaps.
   *
   * <p>This metric is maintained by the location manager and reflects how many distinct remote
   * locations have been seen through swap interactions. It is intended for diagnostics and trend
   * monitoring rather than strict logic.
   *
   * @return count of remote peer locations observed in swaps
   */
  public int numberOfRemotePeerLocationsSeenInSwaps() {
    return locationManager.getNumberOfRemotePeerLocationsSeenInSwaps();
  }

  /**
   * Sets the node's routing location.
   *
   * <p>This method delegates to {@link LocationManager#setLocation(double)} and updates the node's
   * current location in the routing keyspace. It should only be used during controlled
   * initialization or testing, as it can affect routing behavior. The input value is taken as-is.
   *
   * @param loc new routing location to set
   */
  public void setLocation(double loc) {
    locationManager.setLocation(loc);
  }

  /**
   * Returns the total number of swaps performed.
   *
   * <p>This is a static counter maintained by {@link LocationManager} and reflects all swaps
   * observed since process start. It is intended for diagnostics and may be used for monitoring
   * swap activity levels.
   *
   * @return total number of swaps recorded
   */
  public int swaps() {
    return LocationManager.getSwaps();
  }

  /**
   * Returns the number of failed or absent swap attempts.
   *
   * <p>This value is a static counter from {@link LocationManager} indicating how often swaps were
   * not performed when expected. It is intended for diagnostics and may reflect connectivity or
   * policy constraints.
   *
   * @return count of no-swap outcomes
   */
  public int noSwaps() {
    return LocationManager.getNoSwaps();
  }

  /**
   * Returns the number of swaps that were started.
   *
   * <p>This static counter is maintained by {@link LocationManager} and reflects how many swap
   * operations have been initiated. It may be higher than completed swaps due to rejections or
   * failures. The value is intended for monitoring only.
   *
   * @return count of swaps started
   */
  public int startedSwaps() {
    return LocationManager.getStartedSwaps();
  }

  /**
   * Returns the count of swaps rejected because a lock was already held.
   *
   * <p>This static counter tracks swap rejections due to local locking constraints. It is a
   * diagnostic metric from {@link LocationManager} and does not perform any computation beyond
   * returning the stored count.
   *
   * @return count of swaps rejected due to existing lock
   */
  public int swapsRejectedAlreadyLocked() {
    return LocationManager.getSwapsRejectedAlreadyLocked();
  }

  /**
   * Returns the count of swaps rejected because no suitable target was available.
   *
   * <p>This static counter from {@link LocationManager} indicates how often swap routing could not
   * find a destination. It is intended for monitoring swap routing health rather than strict
   * control flow.
   *
   * @return count of swaps rejected due to lack of targets
   */
  public int swapsRejectedNowhereToGo() {
    return LocationManager.getSwapsRejectedNowhereToGo();
  }

  /**
   * Returns the count of swaps rejected due to rate limiting.
   *
   * <p>This static counter reflects how often swap attempts were suppressed by rate limits. It is
   * maintained by {@link LocationManager} and is provided for diagnostics and tuning.
   *
   * @return count of swaps rejected due to rate limiting
   */
  public int swapsRejectedRateLimit() {
    return LocationManager.getSwapsRejectedRateLimit();
  }

  /**
   * Returns the count of swaps rejected because the peer was already recognized.
   *
   * <p>This static counter from {@link LocationManager} indicates swap attempts that were rejected
   * because the peer ID was already known or did not meet uniqueness constraints.
   *
   * @return count of swaps rejected due to recognized peer IDs
   */
  public int swapsRejectedRecognizedID() {
    return LocationManager.getSwapsRejectedRecognizedID();
  }

  /**
   * Returns the configured maximum number of opennet peers.
   *
   * <p>This value is derived from the opennet configuration and may be clamped to the maximum
   * supported by {@link OpennetManager}. It represents the target limit for opennet peer count and
   * may be used by admission and pruning logic.
   *
   * @return maximum opennet peers configured for this node
   */
  public int maxOpennetPeers() {
    return maxOpennetPeers;
  }

  /**
   * Counts the number of peers currently fetching ARKs.
   *
   * <p>This method iterates the peer list and counts peers that report {@link
   * PeerNode#isFetchingARK()}. It provides a snapshot and may change immediately after the call.
   * The method performs no synchronization beyond the peer manager's own behavior.
   *
   * @return number of peers currently fetching ARKs
   */
  public int numArkFetchers() {
    int x = 0;
    for (PeerNode p : peers.myPeers()) {
      if (p.isFetchingARK()) x++;
    }
    return x;
  }

  /**
   * Starts a routing probe through the dispatcher.
   *
   * <p>This method delegates to {@link NodeDispatcher#startProbe(byte, long, Type, Listener)} to
   * initiate a probe for diagnostics or measurement. The probe parameters are forwarded as-is and
   * no validation is performed here. The listener will be notified asynchronously by the
   * dispatcher.
   *
   * @param htl hop-to-live value controlling probe propagation
   * @param uid unique identifier for correlating probe events
   * @param type probe type controlling the probe behavior; must be non-null
   * @param listener listener for probe callbacks; must be non-null
   */
  public void startProbe(final byte htl, final long uid, final Type type, final Listener listener) {
    dispatcher.startProbe(htl, uid, type, listener);
  }

  /**
   * Adds a peer connection and writes the peers file urgently.
   *
   * <p>This method delegates to {@link PeerManager#addPeer(PeerNode)} and then requests an urgent
   * peers file write to persist the new peer. The result indicates whether the peer was accepted.
   * The peer's opennet status determines which file or policy applies.
   *
   * @param pn peer node to add; must be non-null
   * @return {@code true} if the peer was added, {@code false} if rejected
   */
  public boolean addPeerConnection(PeerNode pn) {
    boolean retval = peers.addPeer(pn);
    peers.writePeersUrgent(pn.isOpennet());
    return retval;
  }

  /**
   * Disconnects and removes a peer connection.
   *
   * <p>This method delegates to the peer messenger to disconnect and remove the peer, requesting a
   * clean shutdown. It does not perform null checks and assumes the peer is managed by the peer
   * manager. The removal may be asynchronous depending on messenger implementation.
   *
   * @param pn peer node to disconnect and remove; must be non-null
   */
  public void removePeerConnection(PeerNode pn) {
    peers.messenger().disconnectAndRemove(pn, true, false, false);
  }

  /**
   * Notifies the IP detector that a peer connection was established.
   *
   * <p>This method is a light-weight hook used to trigger address detection logic after new
   * connectivity is observed. It is safe to call even when the detector is not initialized; in that
   * case it performs no action.
   */
  public void onConnectedPeer() {
    if (ipDetector != null) ipDetector.onConnectedPeer();
  }

  /**
   * Reports whether the node is considered outdated.
   *
   * <p>This method delegates to the peer manager, which may evaluate protocol compatibility or
   * update status based on peer feedback. The returned value is a snapshot and may change as peer
   * state changes.
   *
   * @return {@code true} if the node is considered outdated, {@code false} otherwise
   */
  public boolean isOutdated() {
    return peers.isOutdated();
  }

  /**
   * Returns the FNP port for the darknet transport.
   *
   * <p>This is a convenience alias for {@link #darknetPortNumber()} and is used in contexts where
   * the FNP port is needed for display or configuration. The value is undefined if crypto is not
   * initialized.
   *
   * @return darknet FNP port number
   */
  public int fnpPort() {
    return darknetPortNumber();
  }

  /**
   * Adds a seednode connection to the peer manager.
   *
   * <p>This method delegates to the peer manager to add the seed server peer without writing it to
   * disk. It is intended for test or bootstrap scenarios where a seed server connection is needed
   * temporarily. The peer is treated as a non-opennet connection by the manager call.
   *
   * @param node seed server peer node to add; must be non-null
   */
  public void connectToSeednode(SeedServerTestPeerNode node) {
    peers.addPeer(node, false, false);
  }

  /**
   * Initiates a connection to a darknet peer using exported public fields.
   *
   * <p>This method uses the peer manager's connector to create a connection based on the local
   * node's exported darknet public field set. It does not persist the peer by itself and delegates
   * error handling to the connector. The trust and visibility parameters control how the peer is
   * classified in the darknet.
   *
   * @param node node whose exported darknet public field set will be used; must be non-null
   * @param trust trust level to assign to the peer connection; must be non-null
   * @param visibility visibility level to assign to the peer connection; must be non-null
   * @throws FSParseException if the exported field set cannot be parsed
   * @throws PeerParseException if the peer reference is malformed
   * @throws ReferenceSignatureVerificationException if the reference signature is invalid
   * @throws PeerTooOldException if the peer version is too old to connect
   */
  public void connect(
      Node node, DarknetPeerNode.FRIEND_TRUST trust, DarknetPeerNode.FRIEND_VISIBILITY visibility)
      throws FSParseException,
          PeerParseException,
          ReferenceSignatureVerificationException,
          PeerTooOldException {
    peers.connector().connect(node.network().exportDarknetPublicFieldSet(), trust, visibility);
  }

  /**
   * Creates a new opennet peer node from a field set.
   *
   * <p>This method requires opennet to be enabled. It constructs an {@link OpennetPeerNode} using
   * the provided field set, node, and opennet crypto configuration. The peer is not automatically
   * added to the peer manager; callers can decide whether and how to add it.
   *
   * @param fs field set describing the opennet peer; must be non-null
   * @return new opennet peer node instance
   * @throws FSParseException if the field set cannot be parsed
   * @throws OpennetDisabledException if opennet is not currently enabled
   * @throws PeerParseException if peer fields are invalid
   * @throws ReferenceSignatureVerificationException if the reference signature fails validation
   * @throws PeerTooOldException if the peer version is too old
   */
  public OpennetPeerNode createNewOpennetNode(SimpleFieldSet fs)
      throws FSParseException,
          OpennetDisabledException,
          PeerParseException,
          ReferenceSignatureVerificationException,
          PeerTooOldException {
    if (opennet() == null) throw new OpennetDisabledException("Opennet is not currently enabled");
    return new OpennetPeerNode(fs, node, opennet().getCrypto(), opennet(), false, peers);
  }

  /**
   * Creates a new darknet peer node from a field set.
   *
   * <p>This method constructs a {@link DarknetPeerNode} using the local darknet crypto component
   * and the provided trust/visibility settings. The peer is not automatically added to the peer
   * manager; callers may choose to add it via {@link #addPeerConnection(PeerNode)} or other
   * mechanisms.
   *
   * @param fs field set describing the darknet peer; must be non-null
   * @param trust trust level to assign to the new peer; must be non-null
   * @param visibility visibility level to assign to the new peer; must be non-null
   * @return newly constructed darknet peer node
   * @throws FSParseException if the field set cannot be parsed
   * @throws PeerParseException if peer fields are invalid
   * @throws ReferenceSignatureVerificationException if the reference signature fails validation
   * @throws PeerTooOldException if the peer version is too old
   */
  public DarknetPeerNode createNewDarknetNode(
      SimpleFieldSet fs,
      DarknetPeerNode.FRIEND_TRUST trust,
      DarknetPeerNode.FRIEND_VISIBILITY visibility)
      throws FSParseException,
          PeerParseException,
          ReferenceSignatureVerificationException,
          PeerTooOldException {
    return new DarknetPeerNode(fs, node, darknetCrypto, false, trust, visibility, peers);
  }

  /**
   * Creates a new seed server test peer node from a field set.
   *
   * <p>This method requires opennet to be enabled and uses the opennet crypto component to build a
   * {@link SeedServerTestPeerNode}. The node is configured as a seed server test peer and is not
   * automatically added to the peer manager. Callers can use this for test or bootstrap flows.
   *
   * @param fs field set describing the seed server peer; must be non-null
   * @return new seed server test peer node instance
   * @throws FSParseException if the field set cannot be parsed
   * @throws OpennetDisabledException if opennet is not currently enabled
   * @throws PeerParseException if peer fields are invalid
   * @throws ReferenceSignatureVerificationException if the reference signature fails validation
   * @throws PeerTooOldException if the peer version is too old
   */
  public SeedServerTestPeerNode createNewSeedServerTestPeerNode(SimpleFieldSet fs)
      throws FSParseException,
          OpennetDisabledException,
          PeerParseException,
          ReferenceSignatureVerificationException,
          PeerTooOldException {
    if (opennet() == null) throw new OpennetDisabledException("Opennet is not currently enabled");
    return new SeedServerTestPeerNode(fs, node, opennet().getCrypto(), true, peers);
  }

  /**
   * Adds a new opennet peer node via the opennet manager.
   *
   * <p>If opennet is disabled, this method returns {@code null} without side effects. Otherwise, it
   * delegates to {@link OpennetManager#addNewOpennetNode(SimpleFieldSet,
   * OpennetManager.ConnectionType, boolean)} to create and register the peer. The connection type
   * indicates the origin of the peer reference.
   *
   * @param fs field set describing the peer to add; must be non-null
   * @param connectionType how the peer reference was obtained; must be non-null
   * @return created opennet peer node, or {@code null} if opennet is disabled
   * @throws FSParseException if the field set cannot be parsed
   * @throws PeerParseException if peer fields are invalid
   * @throws ReferenceSignatureVerificationException if the reference signature fails validation
   */
  public OpennetPeerNode addNewOpennetNode(
      SimpleFieldSet fs, OpennetManager.ConnectionType connectionType)
      throws FSParseException, PeerParseException, ReferenceSignatureVerificationException {
    if (opennet() == null) return null;
    return opennet().addNewOpennetNode(fs, connectionType, false);
  }

  /**
   * Returns the opennet public key hash.
   *
   * <p>This value is derived from the opennet crypto component and identifies the opennet key pair.
   * The returned byte array is owned by the crypto component and should be treated as immutable by
   * callers.
   *
   * @return opennet public key hash bytes
   */
  public byte[] opennetPubKeyHash() {
    return opennet().getCrypto().getEcdsaPubKeyHash();
  }

  /**
   * Returns the darknet public key hash.
   *
   * <p>This value is derived from the darknet crypto component and identifies the darknet key pair.
   * The returned byte array is owned by the crypto component and should be treated as immutable by
   * callers.
   *
   * @return darknet public key hash bytes
   */
  public byte[] darknetPubKeyHash() {
    return darknetCrypto.getEcdsaPubKeyHash();
  }

  /**
   * Reports whether opennet is currently enabled.
   *
   * <p>This method returns {@code true} if an {@link OpennetManager} instance is present. Opennet
   * may be enabled or disabled dynamically based on configuration and threat level changes. The
   * value is a snapshot at the time of the call.
   *
   * @return {@code true} if opennet is enabled, {@code false} otherwise
   */
  public boolean isOpennetEnabled() {
    return opennet() != null;
  }

  /**
   * Exports the darknet public field set.
   *
   * <p>This method delegates to the darknet crypto component to produce the public portion of the
   * node reference. The returned field set is suitable for sharing with peers and does not include
   * private key material. The caller receives a new field set instance.
   *
   * @return public darknet field set for peer sharing
   */
  public SimpleFieldSet exportDarknetPublicFieldSet() {
    return darknetCrypto.exportPublicFieldSet();
  }

  /**
   * Exports the opennet public field set.
   *
   * <p>This method delegates to the opennet crypto component to produce the public portion of the
   * opennet node reference. The returned field set is suitable for sharing and does not include
   * private data. Opennet must be enabled for this call to succeed.
   *
   * @return public opennet field set for peer sharing
   */
  public SimpleFieldSet exportOpennetPublicFieldSet() {
    return opennet().getCrypto().exportPublicFieldSet();
  }

  /**
   * Exports the darknet private field set.
   *
   * <p>The returned field set includes private cryptographic material and should be handled
   * securely. It is used for persistence of the node's darknet identity. The caller receives a new
   * field set instance and is responsible for secure storage.
   *
   * @return private darknet field set containing sensitive information
   */
  public SimpleFieldSet exportDarknetPrivateFieldSet() {
    return darknetCrypto.exportPrivateFieldSet();
  }

  /**
   * Exports the opennet private field set.
   *
   * <p>The returned field set includes private cryptographic material for opennet and should be
   * handled securely. It is used to persist opennet identity information. Opennet must be enabled
   * for this call to succeed.
   *
   * @return private opennet field set containing sensitive information
   */
  public SimpleFieldSet exportOpennetPrivateFieldSet() {
    return opennet().getCrypto().exportPrivateFieldSet();
  }

  /**
   * Determines whether IP detection should be suppressed based on bind addresses.
   *
   * <p>This method checks whether the darknet bind address is a real internet address; if not, it
   * returns {@code false} to indicate detection should continue. If darknet is real and opennet is
   * enabled, the opennet bind address must also be real to avoid detection suppression. When
   * opennet is disabled, a real darknet address results in {@code true}.
   *
   * @return {@code true} if IP detection should be suppressed, {@code false} otherwise
   */
  public boolean dontDetect() {
    if (!darknetCrypto.getBindTo().isRealInternetAddress(false, true, false)) return false;
    if (opennet() != null) {
      return !opennet().getCrypto().getBindTo().isRealInternetAddress(false, true, false);
    }
    return true;
  }

  /**
   * Returns the opennet FNP port number if opennet is enabled.
   *
   * <p>If opennet is disabled, this method returns {@code -1}. When enabled, it returns the UDP
   * port number from the opennet crypto component. The value is used for diagnostics and port
   * forwarding.
   *
   * @return opennet FNP port number, or {@code -1} if opennet is disabled
   */
  public int opennetFnpPort() {
    if (opennet() == null) return -1;
    return opennet().getCrypto().getPortNumber();
  }

  /**
   * Reports whether opennet references should be passed through darknet.
   *
   * <p>This flag is configured via the node configuration and controls whether opennet peer
   * references are transmitted over darknet connections. The value may change via configuration
   * updates and is returned as a snapshot.
   *
   * @return {@code true} if opennet refs are passed through darknet, {@code false} otherwise
   */
  public boolean passOpennetRefsThroughDarknet() {
    return passOpennetRefsThroughDarknet;
  }

  /**
   * Returns the set of public-facing ports that may require forwarding.
   *
   * <p>The returned set always includes the darknet UDP port and additionally includes the opennet
   * UDP port when opennet is enabled. The set is newly constructed on each call and can be modified
   * by the caller without affecting internal state.
   *
   * @return set of forwardable port descriptors for current network configuration
   */
  public Set<ForwardPort> publicInterfacePorts() {
    HashSet<ForwardPort> set = new HashSet<>();
    set.add(
        new ForwardPort(
            "darknet", false, ForwardPort.PROTOCOL_UDP_IPV4, darknetCrypto.getPortNumber()));
    if (opennet() != null) {
      var crypto = opennet().getCrypto();
      if (crypto != null) {
        set.add(
            new ForwardPort(
                "opennet", false, ForwardPort.PROTOCOL_UDP_IPV4, crypto.getPortNumber()));
      }
    }
    return set;
  }

  /**
   * Returns the uptime of the message core in milliseconds.
   *
   * <p>The uptime is calculated as the difference between the current time and the message core
   * start time. It reflects how long the message core has been running, not necessarily overall
   * node uptime. The value is computed at call time.
   *
   * @return uptime in milliseconds since the message core started
   */
  public long uptime() {
    return System.currentTimeMillis() - usm().getStartedTime();
  }

  /**
   * Returns the active UDP socket handlers for networking.
   *
   * <p>The returned array includes the darknet socket and, when opennet is enabled, the opennet
   * socket. The array is newly allocated on each call and can be modified by the caller without
   * affecting internal state. The sockets are owned by their respective crypto components.
   *
   * @return array of UDP socket handlers in use by the node
   */
  public UdpSocketHandler[] packetSocketHandlers() {
    if (opennet() != null) {
      return new UdpSocketHandler[] {darknetCrypto.getSocket(), opennet().getCrypto().getSocket()};
    }
    return new UdpSocketHandler[] {darknetCrypto.getSocket()};
  }

  /**
   * Notifies opennet announcer after a valid external IP is added.
   *
   * <p>If opennet and its announcer are present, this method requests that the announcer evaluate
   * whether a new announcement should be sent. The call is asynchronous and intended for use after
   * IP discovery events. No action is taken when opennet is disabled.
   */
  public void onAddedValidIP() {
    OpennetManager om = opennet();
    if (om != null) {
      var announcer = om.getAnnouncer();
      if (announcer != null) {
        announcer.maybeSendAnnouncementOffThread();
      }
    }
  }

  /**
   * Reports whether this node accepts seed connections.
   *
   * <p>This reflects the {@code acceptSeedConnections} configuration and indicates whether the node
   * should act as a seed for other peers. It is a simple boolean flag and does not validate other
   * opennet state.
   *
   * @return {@code true} if seed connections are accepted, {@code false} otherwise
   */
  public boolean isSeednode() {
    return acceptSeedConnections;
  }

  /**
   * Indicates whether anonymous authentication is desired for a connection type.
   *
   * <p>For opennet connections, anonymous authentication is requested only when opennet is enabled
   * and seed connections are accepted. For darknet connections, this method always returns {@code
   * false}. The logic is a simple policy check with no side effects.
   *
   * @param isOpennet {@code true} when evaluating an opennet connection, {@code false} for darknet
   * @return {@code true} if anonymous authentication should be used, {@code false} otherwise
   */
  public boolean wantAnonAuth(boolean isOpennet) {
    if (isOpennet) return opennet() != null && acceptSeedConnections;
    else return false;
  }

  /**
   * Indicates whether anonymous authentication should change IP handling.
   *
   * <p>This policy is currently fixed: it returns {@code true} for darknet connections and {@code
   * false} for opennet connections. The method exists to centralize policy and may be referenced by
   * authentication flows.
   *
   * @param isOpennet {@code true} for opennet connections, {@code false} for darknet
   * @return {@code true} if IP change behavior is desired, {@code false} otherwise
   */
  public boolean wantAnonAuthChangeIP(boolean isOpennet) {
    return !isOpennet;
  }

  /**
   * Reports whether opennet is definitely port forwarded.
   *
   * <p>This method checks the opennet manager and its crypto component to determine whether
   * port-forwarding is confirmed. If opennet or its crypto component is absent, it returns {@code
   * false}. The result reflects the crypto component's internal detection logic.
   *
   * @return {@code true} if opennet is definitely port forwarded, {@code false} otherwise
   */
  public boolean opennetDefinitelyPortForwarded() {
    OpennetManager om = opennet();
    if (om == null) return false;
    var crypto = om.getCrypto();
    if (crypto == null) return false;
    return crypto.definitelyPortForwarded();
  }

  /**
   * Reports whether darknet is definitely port forwarded.
   *
   * <p>If the darknet crypto component is not available, this method returns {@code false}. When
   * available, it delegates to {@link NodeCrypto#definitelyPortForwarded()} to indicate whether
   * port forwarding is confirmed for the darknet socket.
   *
   * @return {@code true} if darknet is definitely port forwarded, {@code false} otherwise
   */
  public boolean darknetDefinitelyPortForwarded() {
    var crypto = darknetCrypto;
    if (crypto == null) return false;
    return crypto.definitelyPortForwarded();
  }

  /**
   * Requests MTU recalculation for darknet and opennet sockets.
   *
   * <p>This method calls {@link UdpSocketHandler#calculateMaxPacketSize()} on the darknet socket
   * and on the opennet socket when opennet is enabled. It does not block for completion beyond the
   * immediate recalculation and does not handle exceptions here.
   */
  public void updateMTU() {
    darknetCrypto.getSocket().calculateMaxPacketSize();
    OpennetManager om = opennet();
    if (om != null) {
      om.getCrypto().getSocket().calculateMaxPacketSize();
    }
  }

  /**
   * Logs the current FNP port and bind address.
   *
   * <p>This method emits an informational log line including the darknet bind address and port
   * number. It performs no computation beyond reading the values from the crypto component and is
   * intended for startup diagnostics.
   */
  public void logFnpPort() {
    LOG.info("FNP port is on {}:{}", darknetCrypto.getBindTo(), darknetPortNumber());
  }

  /**
   * Reports whether an update should be considered urgent.
   *
   * <p>The method returns {@code true} if the opennet announcer is waiting for the updater or if
   * the peer manager reports too many too-new peers beyond a threshold. It provides a quick
   * heuristic used for UI signaling and does not trigger any updates itself.
   *
   * @return {@code true} when update urgency is detected, {@code false} otherwise
   */
  public boolean updateIsUrgent() {
    if (opennet != null
        && opennet.getAnnouncer() != null
        && opennet.getAnnouncer().isWaitingForUpdater()) return true;
    return peers.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_TOO_NEW, true)
        > PeerManager.OUTDATED_MIN_TOO_NEW_DARKNET;
  }
}
