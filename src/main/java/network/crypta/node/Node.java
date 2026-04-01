/* Freenet 0.7 node. */
package network.crypta.node;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.RandomAccessFile;
import java.io.Serial;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Locale;
import java.util.Objects;
import network.crypta.client.FetchContext;
import network.crypta.config.BooleanCallback;
import network.crypta.config.FreenetFilePersistentConfig;
import network.crypta.config.IntCallback;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.LongCallback;
import network.crypta.config.NodeNeedRestartException;
import network.crypta.config.Option;
import network.crypta.config.PersistentConfig;
import network.crypta.config.ShortCallback;
import network.crypta.config.StringCallback;
import network.crypta.config.SubConfig;
import network.crypta.crypt.MasterSecret;
import network.crypta.crypt.PersistentRandomSource;
import network.crypta.crypt.RandomSource;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.SecurityLevels.NETWORK_THREAT_LEVEL;
import network.crypta.node.SecurityLevels.PHYSICAL_THREAT_LEVEL;
import network.crypta.node.subsystem.CryptoAndTransportParams;
import network.crypta.node.subsystem.NodeMessagingSubsystem;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.node.subsystem.NodeRoutingSubsystem;
import network.crypta.node.subsystem.NodeStorageSubsystem;
import network.crypta.runtime.bootstrap.NodeBootstrap;
import network.crypta.runtime.bootstrap.NodeConfigManager;
import network.crypta.runtime.bootstrap.NodeRuntimeBridgeFactories;
import network.crypta.runtime.bootstrap.NodeStarter;
import network.crypta.runtime.endpoints.NodeClientCoreInit;
import network.crypta.runtime.http.HttpShellContainer;
import network.crypta.runtime.http.HttpShellContainerFactory;
import network.crypta.runtime.http.HttpShellRuntimeSupportFactory;
import network.crypta.runtime.http.security.PasswordFormPageRenderer;
import network.crypta.runtime.services.NodeServicesSubsystem;
import network.crypta.support.Fields;
import network.crypta.support.HexUtil;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.io.FileUtil;
import network.crypta.support.io.NativeThread;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.tanukisoftware.wrapper.WrapperManager;

import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.SECONDS;

/**
 * Core node implementation coordinating all major subsystems (routing, storage, peers, and
 * services).
 *
 * <p>The {@code Node} class wires together the network stack (darknet/opennet crypto and sockets),
 * request/insert schedulers, datastores and caches (CHK/SSK/public key), the HTTP UI (FProxy), and
 * diagnostics. A typical lifecycle is: create a {@code Node} via {@link NodeStarter}, call {@link
 * #start(boolean)} to initialize active components, interact with the node (e.g., enqueue
 * requests/inserts), and finally call {@link #park()} to quiesce and shut down. Most methods are
 * designed for internal coordination and are not stable APIs for external callers; public methods
 * are documented for their observable effects.
 *
 * <p>Invariants and state model:
 *
 * <ul>
 *   <li>The node owns multiple persistent stores plus short‑lived caches; sizing and placement are
 *       configured at startup and may change only through well‑defined callbacks.
 *   <li>Networking is asynchronous; dispatchers, tickers, and executors coordinate background work.
 *       Many operations complete later on the ticker thread.
 *   <li>Security levels (network/physical) influence routing, caching, and persistence behavior at
 *       runtime.
 * </ul>
 *
 * <p>Concurrency: the node uses thread‑safe helpers (executors, synchronized fields) and avoids
 * blocking I/O on critical routing threads. Methods explicitly state when they may block or when
 * they trigger background activity. Mutability is confined to configuration/state holders and
 * caches; key objects and block payloads are treated as immutable once published.
 *
 * @author amphibian
 */
public final class Node implements TimeSkewDetectorCallback {
  private static final Logger LOG = LoggerFactory.getLogger(Node.class);

  /** String literal for the salted-hash store/client-cache type. */
  public static final String TYPE_SALT_HASH = "salt-hash";

  /** Prefix for node file names (e.g., node-<port>). */
  private static final String NODE_FILE_PREFIX = "node-";

  /** Config key name used to control datastore preallocation. */
  private static final String STORE_PREALLOCATE_KEY = "storePreallocate";

  /** SimpleFieldSet key for a Node-to-Node message type. */
  public static final String N2N_TYPE_KEY = "n2nType";

  /** System property to override the hardware RNG device path. */
  public static final String HWRNG_PATH_PROPERTY = "crypta.hwrng.path";

  /** Default hardware RNG device path for Unix-like systems. */
  public static final String DEFAULT_HWRNG_PATH = "/dev/hwrng";

  /** Config object for the whole node. */
  private final PersistentConfig config;

  // Static stuff related to logger
  /** Number of packets per transfer block used in link‑layer processing. */
  public static final int PACKETS_IN_BLOCK = 32;

  /** Default transport packet payload size in bytes. */
  public static final int PACKET_SIZE = 1024;

  /** Minimum UDP MTU accepted for packet size configuration. */
  private static final int MIN_UDP_MTU = 576;

  /** Probability of decrementing at the minimum HTL boundary. */
  public static final double DECREMENT_AT_MIN_PROB = 0.25;

  /** Probability of decrementing at the maximum HTL boundary. */
  public static final double DECREMENT_AT_MAX_PROB = 0.5;

  // Send keepalives every 7-14 seconds. Will be acked and if necessary, resent.
  // Old behavior was keepalives every 14-28. Even that was adequate for a 30-second
  // timeout. Most nodes don't need to send keepalives because they are constantly busy,
  // this is only an issue for disabled darknet connections, very quiet private networks,
  // etc.
  /** Interval for sending keep‑alive packets on idle connections (milliseconds). */
  public static final long KEEPALIVE_INTERVAL = SECONDS.toMillis(7);

  // If no activity for 30 seconds, the node is dead
  // 35 seconds allows plenty of time for resends etc. even if the above is 14 sec as it is on older
  // nodes.
  /** Inactivity timeout after which a peer is considered dead (milliseconds). */
  public static final long MAX_PEER_INACTIVITY = SECONDS.toMillis(35);

  /** Time budget in milliseconds for completing a handshake exchange. */
  public static final int HANDSHAKE_TIMEOUT =
      (int) 4800L; // Keep the below within the 30-second assumed timeout.

  // Inter-handshake time must be at least 2x handshake timeout
  /** Minimum interval between handshake attempts (milliseconds). */
  public static final int MIN_TIME_BETWEEN_HANDSHAKE_SENDS = HANDSHAKE_TIMEOUT * 2; // 10-20 secs

  /** Randomized extra delay between handshake attempts (milliseconds). */
  public static final int RANDOMIZED_TIME_BETWEEN_HANDSHAKE_SENDS =
      HANDSHAKE_TIMEOUT * 2; // avoid overlap when the two handshakes are at the same time

  /** Minimum interval between version probes (milliseconds). */
  public static final int MIN_TIME_BETWEEN_VERSION_PROBES = HANDSHAKE_TIMEOUT * 4;

  /** Randomized extra delay between version probes (milliseconds). */
  public static final int RANDOMIZED_TIME_BETWEEN_VERSION_PROBES =
      HANDSHAKE_TIMEOUT * 2; // 20-30 secs

  /** Minimum interval between sending version announcements (milliseconds). */
  public static final int MIN_TIME_BETWEEN_VERSION_SENDS = HANDSHAKE_TIMEOUT * 4;

  /** Randomized extra delay between version announcements (milliseconds). */
  public static final int RANDOMIZED_TIME_BETWEEN_VERSION_SENDS =
      HANDSHAKE_TIMEOUT * 2; // 20-30 secs

  /** Minimum interval between grouped handshake bursts (milliseconds). */
  public static final int MIN_TIME_BETWEEN_BURSTING_HANDSHAKE_BURSTS =
      HANDSHAKE_TIMEOUT * 24; // 2-5 minutes

  /** Randomized extra delay between grouped handshake bursts (milliseconds). */
  public static final int RANDOMIZED_TIME_BETWEEN_BURSTING_HANDSHAKE_BURSTS =
      HANDSHAKE_TIMEOUT * 36;

  /** Minimum count of handshakes sent per burst. */
  public static final int MIN_BURSTING_HANDSHAKE_BURST_SIZE = 1; // 1-4 handshake sends per burst

  /** Additional randomized count added to bursting handshake size. */
  public static final int RANDOMIZED_BURSTING_HANDSHAKE_BURST_SIZE = 3;

  // If we don't receive any packets at all in this period, from any node, tell the user
  /** Time without any traffic that triggers a user‑visible alarm (milliseconds). */
  public static final long ALARM_TIME = MINUTES.toMillis(1);

  static final long MIN_INTERVAL_BETWEEN_INCOMING_SWAP_REQUESTS = 900L;
  static final long MIN_INTERVAL_BETWEEN_INCOMING_PROBE_REQUESTS = 1000L;

  /** Length in bytes for symmetric keys used by the node (e.g., AES‑256). */
  public static final int SYMMETRIC_KEY_LENGTH =
      32; // 256 bits - note that this isn't used everywhere to determine it

  /**
   * For debugging/testing, set this to true to stop the probabilistic decrement at the edges of the
   * HTLs.
   */
  private boolean disableProbabilisticHTLs;

  /**
   * Semi-unique ID for swap requests. Used to identify us so that the topology can be
   * reconstructed.
   */
  private long swapIdentifier;

  /**
   * Returns the semi‑unique identifier used for swap requests so that the topology can be
   * reconstructed. The value is derived from the node's identity hash and may change when identity
   * material changes.
   *
   * <p>The identifier is intended only for correlating swap activity within a running cohort and is
   * not guaranteed to be globally unique or stable across restarts if identity material changes.
   *
   * @return the current swap identifier value used in swap routing and diagnostics.
   */
  @SuppressWarnings("unused")
  public long getSwapIdentifier() {
    return swapIdentifier;
  }

  private String myName;

  /** Node-reference directory (node identity, peers, etc.) */
  private final ProgramDirectory nodeDir;

  /** Config directory (l10n overrides, etc.) */
  final ProgramDirectory cfgDir;

  /** User data directory (bookmarks, download lists, etc.) */
  final ProgramDirectory userDir;

  /** Run-time state directory (bootID, PRNG seed, etc.) */
  final ProgramDirectory runDir;

  /** Directory to put extra peer data into */
  final File extraPeerDataDir;

  private volatile boolean hasPanicked;

  // General stuff

  private final PriorityAwareExecutor executor;

  private final boolean enableARKs;

  private final boolean enablePerNodeFailureTables;

  private final boolean enableULPRDataPropagation;

  private final boolean enableSwapping;

  private volatile boolean publishOurPeersLocation;
  private volatile boolean routeAccordingToOurPeersLocation;

  private boolean enableSwapQueueing;

  private boolean enablePacketCoalescing;

  /** Default maximum hop‑to‑live (HTL) used when no explicit value is configured. */
  public static final short DEFAULT_MAX_HTL = (short) 18;

  private short maxHTL;
  private boolean skipWrapperWarning;
  private volatile int maxPacketSize;

  /** Default policy for ignoring low backoff during inserts. */
  public static final boolean IGNORE_LOW_BACKOFF_DEFAULT = false;

  /** Threshold in milliseconds defining a "low" backoff period for inserts. */
  public static final long LOW_BACKOFF = SECONDS.toMillis(30);

  /** Default policy for prioritizing inserts on acceptance. */
  public static final boolean PREFER_INSERT_DEFAULT = false;

  /** Default policy for forking insert when an item becomes cacheable. */
  public static final boolean FORK_ON_CACHEABLE_DEFAULT = true;

  /** Node‑to‑node message category used for FProxy messages. */
  public static final int N2N_MESSAGE_TYPE_FPROXY = 1;

  /** Node‑to‑node message category for differential node references. */
  public static final int N2N_MESSAGE_TYPE_DIFFNODEREF = 2;

  /** FProxy text sub‑type for user alerts. */
  public static final int N2N_TEXT_MESSAGE_TYPE_USERALERT = 1;

  /** FProxy text sub‑type for a file offer. */
  public static final int N2N_TEXT_MESSAGE_TYPE_FILE_OFFER = 2;

  /** FProxy text sub‑type signaling a file‑offer acceptance. */
  public static final int N2N_TEXT_MESSAGE_TYPE_FILE_OFFER_ACCEPTED = 3;

  /** FProxy text sub‑type signaling a file‑offer rejection. */
  public static final int N2N_TEXT_MESSAGE_TYPE_FILE_OFFER_REJECTED = 4;

  /** FProxy text sub‑type recommending a bookmark. */
  public static final int N2N_TEXT_MESSAGE_TYPE_BOOKMARK = 5;

  /** FProxy text sub‑type recommending a file download. */
  public static final int N2N_TEXT_MESSAGE_TYPE_DOWNLOAD = 6;

  /** Extra‑peer‑data category for node‑to‑node message payloads. */
  public static final int EXTRA_PEER_DATA_TYPE_N2NTM = 1;

  /** Extra‑peer‑data category for peer notes. */
  public static final int EXTRA_PEER_DATA_TYPE_PEER_NOTE = 2;

  /** Extra‑peer‑data category for queued outbound node‑to‑node messages. */
  public static final int EXTRA_PEER_DATA_TYPE_QUEUED_TO_SEND_N2NM = 3;

  /** Extra‑peer‑data category for bookmarked content. */
  public static final int EXTRA_PEER_DATA_TYPE_BOOKMARK = 4;

  /** Extra‑peer‑data category for download metadata. */
  public static final int EXTRA_PEER_DATA_TYPE_DOWNLOAD = 5;

  /** Peer‑note sub‑type for private darknet comments. */
  public static final int PEER_NOTE_TYPE_PRIVATE_DARKNET_COMMENT = 1;

  /**
   * The bootID of the last time the node booted up. Or -1 if we don't know due to permissions
   * problems, or we suspect that the node has been booted and not written the file e.g., if we
   * can't write it. So if we want to compare data gathered in the last session and only recorded to
   * disk on a clean shutdown to data we have now, we just include the lastBootID.
   */
  private final long lastBootID;

  private final long bootID;

  private final long startupTime;

  // ULPRs, RecentlyFailed, per node failure tables, are all managed by FailureTable.

  /** The version we were before we restarted. */
  private int lastVersion;

  // The node starter
  private final NodeStarter nodeStarter;
  private final NodeMessagingSubsystem messaging;
  private final NodeBootstrap bootstrap;
  private final NodeServicesSubsystem services;
  private final NodeNetworkSubsystem network;
  private final NodeStorageSubsystem storage;
  private final NodeRoutingSubsystem routing;

  // The watchdog will be silenced until it's true
  private volatile boolean hasStarted;
  private boolean isStopping = false;

  /**
   * Minimum uptime for us to consider a node an acceptable place to store a key. We store a key to
   * the datastore only if it's from an insert, and we are a sink, but when calculating whether we
   * are a sink, we ignore nodes which have less uptime (percentage) than this parameter.
   */
  static final int MIN_UPTIME_STORE_KEY = 40;

  private boolean enableRoutedPing;

  private boolean enableNodeDiagnostics;

  private int datastoreTooSmallDismissed;

  /**
   * Minimum bandwidth limit in bytes considered usable: 10 KiB. If there is an attempt to set a
   * limit below this - excluding the reserved -1 for input bandwidth - the callback will throw. See
   * the callbacks for outputBandwidthLimit and inputBandwidthLimit. 10 KiB is equivalent to 50 GiB
   * traffic per month.
   */
  private static final int MINIMUM_BANDWIDTH = 10 * 1024;

  /**
   * Returns the minimum usable bandwidth limit in bytes per second.
   *
   * <p>This accessor exposes the hard floor enforced by bandwidth configuration callbacks. Values
   * below this threshold are treated as invalid because they would effectively stall node traffic.
   * The threshold does not apply to the reserved input-bandwidth sentinel value {@code -1}, which
   * is handled separately by the configuration logic. The method is pure and side-effect-free.
   *
   * @return minimum acceptable bandwidth limit, expressed in bytes per second.
   * @see #MINIMUM_BANDWIDTH
   */
  public static int getMinimumBandwidth() {
    return MINIMUM_BANDWIDTH;
  }

  /**
   * Read all storable settings (identity etc.) from the node file.
   *
   * @param filename The name of the file to read from.
   * @throws IOException throw when I/O error occur
   */
  private void readNodeFile(String filename) throws IOException {
    try (FileInputStream fis = new FileInputStream(filename);
        InputStreamReader isr = new InputStreamReader(fis, StandardCharsets.UTF_8);
        BufferedReader br = new BufferedReader(isr)) {
      SimpleFieldSet fs = new SimpleFieldSet(br, false, true);
      network.applyUdpFromFieldSet(fs);
      network.readDarknetCrypto(fs);
      swapIdentifier = Fields.bytesToLong(network.darknetIdentityHashHash());
      applyLocationAndNameFromFieldSet(fs);
      applyVersionFromFieldSet(fs);
    }
  }

  private void applyLocationAndNameFromFieldSet(SimpleFieldSet fs) throws IOException {
    String loc = fs.get("location");
    double locD = Location.getLocation(loc);
    if (locD == -1.0) throw new IOException("Invalid location: " + loc);
    network.setLocation(locD);
    myName = fs.get("myName");
    if (myName == null) myName = newName();
  }

  private void applyVersionFromFieldSet(SimpleFieldSet fs) {
    String verString = fs.get("version");
    if (verString == null) {
      LOG.error("No version!");
    } else {
      lastVersion = Version.parseBuildNumberFromVersionStr(verString, -1);
    }
  }

  private String newName() {
    return "Crypta node with no name #" + bootstrap.random().nextLong();
  }

  private final Object writeNodeFileSync = new Object();

  /**
   * Writes the node identity file to disk using a backup-and-rename workflow.
   *
   * <p>The method serializes the current darknet identity field set to a {@code .bak} file, then
   * moves the backup into place. Calls are serialized using an internal lock to avoid concurrent
   * writes. Any I/O failures are logged and the method returns without throwing, so callers should
   * not rely on it for transactional guarantees beyond the best-effort backup move.
   */
  public void writeNodeFile() {
    synchronized (writeNodeFileSync) {
      writeNodeFile(
          nodeDir.file(NODE_FILE_PREFIX + network.darknetPortNumber()),
          nodeDir.file(NODE_FILE_PREFIX + network.darknetPortNumber() + ".bak"));
    }
  }

  /**
   * Persists the opennet reference file through the network subsystem.
   *
   * <p>This is a convenience wrapper around {@link NodeNetworkSubsystem#writeOpennetFile()}. It
   * emits no additional synchronization and assumes the underlying subsystem manages its own
   * concurrency. Errors are handled within the network subsystem and are logged there.
   */
  public void writeOpennetFile() {
    network.writeOpennetFile();
  }

  private void writeNodeFile(File orig, File backup) {
    SimpleFieldSet fs = network.exportDarknetPrivateFieldSet();

    if (orig.exists()) {
      try {
        Files.delete(backup.toPath());
      } catch (IOException e) {
        LOG.info("Failed to delete backup {}: {}", backup, e.getMessage(), e);
      }
    }

    try (FileOutputStream fos = new FileOutputStream(backup)) {
      fs.writeTo(fos);
    } catch (IOException ioe) {
      LOG.error("IOE :{}", ioe.getMessage(), ioe);
      return;
    }
    if (!FileUtil.moveTo(backup, orig)) {
      LOG.error("Failed to replace node file {} with backup {}", orig, backup);
    }
  }

  private static long parseBootIdFromHex(String s) {
    try {
      return Fields.bytesToLong(HexUtil.hexToBytes(s));
    } catch (NumberFormatException _) {
      return -1;
    }
  }

  private void initNodeFileSettings() {
    LOG.info("Creating new node file from scratch");
    // Don't need to set getDarknetPortNumber()
    // Use a real IP address.
    network.initDarknetCrypto();
    swapIdentifier = Fields.bytesToLong(network.darknetIdentityHashHash());
    myName = newName();
  }

  /**
   * Process entry point for launching the node under the wrapper.
   *
   * <p>This method forwards arguments to {@link NodeStarter#main(String[])}, which handles wrapper
   * integration, config parsing, and JVM lifecycle callbacks. It performs no validation locally and
   * returns only after the wrapper has taken control of startup sequencing. Use this entry point in
   * packaged distributions rather than constructing {@link Node} directly.
   *
   * @param args command-line arguments forwarded to the wrapper-managed launcher; may be empty.
   */
  public static void main(String[] args) {
    NodeStarter.main(args);
  }

  /**
   * Returns whether the node is running under the native Tanuki wrapper.
   *
   * <p>The check combines the presence of a {@link NodeStarter} instance with the wrapper runtime
   * indicator. This is used to warn operators when the process is started in a way that bypasses
   * wrapper supervision. The value can change only if the wrapper runtime state changes, which is
   * not expected during normal operation.
   *
   * @return {@code true} when controlled by the native wrapper; {@code false} otherwise.
   */
  public boolean isUsingWrapper() {
    return nodeStarter != null && WrapperManager.isControlledByNativeWrapper();
  }

  /**
   * Returns the {@link NodeStarter} associated with this node, if any.
   *
   * <p>The starter coordinates wrapper lifecycle callbacks and may be {@code null} in tests or
   * custom bootstrap scenarios. Callers should treat the returned instance as node-owned and avoid
   * invoking lifecycle methods directly unless they are part of the startup/shutdown flow.
   *
   * @return the associated {@link NodeStarter}, or {@code null} if not initialized.
   */
  public NodeStarter getNodeStarter() {
    return nodeStarter;
  }

  /**
   * Creates a node instance for the runtime bootstrap layer.
   *
   * <p>This factory preserves the historical construction path after {@link NodeStarter} moved out
   * of {@code network.crypta.node}. It keeps the constructor package-local while allowing the
   * bootstrap package to instantiate nodes without reflective access.
   *
   * @param config the persisted node configuration
   * @param r the primary random source, or {@code null} to use the default secure source
   * @param weakRandom the fast random source, or {@code null} to derive one from the secure source
   * @param ns the associated starter, or {@code null} for test bootstrap
   * @param executor the executor used by the node runtime
   * @param runtimeBridgeFactories bootstrap-selected runtime bridge factories
   * @return a newly constructed node instance
   * @throws NodeInitException if the node initialization fails
   */
  public static Node createForBootstrap(
      PersistentConfig config,
      RandomSource r,
      RandomSource weakRandom,
      NodeStarter ns,
      PriorityAwareExecutor executor,
      NodeRuntimeBridgeFactories runtimeBridgeFactories)
      throws NodeInitException {
    return new Node(config, r, weakRandom, ns, executor, runtimeBridgeFactories);
  }

  /**
   * Create a Node from a Config object.
   *
   * @param config The Config object for this node.
   * @param r The random number generator for this node. Passed in because we may want to use a
   *     non-secure RNG for e.g., one-JVM live-code simulations. Should be a Yarrow in a production
   *     node. Yarrow will be used if that parameter is null
   * @param weakRandom The fast random number generator the node will use. If null, an MT instance
   *     will be used, seeded from the secure PRNG.
   * @param ns NodeStarter
   * @param executor Executor
   * @param runtimeBridgeFactories Bootstrap-selected runtime bridge factories
   * @throws NodeInitException If the node initialization fails.
   */
  Node(
      PersistentConfig config,
      RandomSource r,
      RandomSource weakRandom,
      NodeStarter ns,
      PriorityAwareExecutor executor,
      NodeRuntimeBridgeFactories runtimeBridgeFactories)
      throws NodeInitException {
    NodeRuntimeBridgeFactories nodeRuntimeBridgeFactories =
        Objects.requireNonNull(runtimeBridgeFactories, "runtimeBridgeFactories");
    HttpShellRuntimeSupportFactory httpShellRuntimeSupportFactory =
        nodeRuntimeBridgeFactories.httpShellRuntimeSupportFactory();
    HttpShellContainerFactory httpShellContainerFactory =
        nodeRuntimeBridgeFactories.httpShellContainerFactory();
    PasswordFormPageRenderer passwordFormPageRenderer =
        nodeRuntimeBridgeFactories.passwordFormPageRenderer();
    this.executor = executor;
    this.nodeStarter = ns;
    this.messaging = new NodeMessagingSubsystem();
    this.bootstrap = new NodeBootstrap(this);
    this.services = new NodeServicesSubsystem(this, httpShellContainerFactory);
    NodeConfigManager configManager = new NodeConfigManager(this);
    this.network = new NodeNetworkSubsystem(this);
    this.storage = new NodeStorageSubsystem(this, passwordFormPageRenderer);
    this.routing = new NodeRoutingSubsystem(this);
    network.initCollector();
    bootstrap.logStartupInfo();
    startupTime = System.currentTimeMillis();
    SimpleFieldSet oldConfig = config.getSimpleFieldSet();
    final SubConfig nodeConfig = config.createSubConfig("node");
    final SubConfig installConfig = config.createSubConfig("node.install");

    int sortOrder = 0;

    NodeBootstrap.NodeProgramDirs pd = bootstrap.setupProgramDirectories(installConfig);
    this.userDir = pd.userDir();
    this.cfgDir = pd.cfgDir();
    this.nodeDir = pd.nodeDir();
    this.runDir = pd.runDir();
    sortOrder = configManager.configureLocalization(nodeConfig, cfgDir, sortOrder);
    this.config = config;
    initializeServicesAndRandom(config, r, weakRandom);

    sortOrder = registerMasterKeyFileConfig(nodeConfig, sortOrder);

    sortOrder = registerShowFriendsVisibilityAlert(nodeConfig, sortOrder);

    MasterKeyState masterKeyState = initializeMasterKeysAndDatabase();
    byte[] clientCacheKey = masterKeyState.clientCacheKey();
    MasterSecret persistentSecret = masterKeyState.persistentSecret();

    BootIdState bootIdState = initializeBootId();
    bootID = bootIdState.bootId();
    lastBootID = bootIdState.lastBootId();

    sortOrder = registerProbabilisticHtlConfig(nodeConfig, sortOrder);
    sortOrder = registerMaxHtlConfig(nodeConfig, sortOrder);

    sortOrder = network.initTrafficClass(nodeConfig, sortOrder);

    // These should maybe persist; they need to be private.
    routing.initDecrementPolicy();

    // Determine where to bind to

    network.initMessagingCore(executor);

    // Consider whether these configs should be under a node.ip subconfig.
    sortOrder = network.registerIpDetectorConfigs(nodeConfig, sortOrder);

    // ARKs enabled?

    sortOrder = registerArkAndRoutingConfigs(nodeConfig, sortOrder);
    enableARKs = nodeConfig.getBoolean("enableARKs");
    enablePerNodeFailureTables = nodeConfig.getBoolean("enablePerNodeFailureTables");
    enableULPRDataPropagation = nodeConfig.getBoolean("enableULPRDataPropagation");
    enableSwapping = nodeConfig.getBoolean("enableSwapping");

    /*
     * Publish our peers' locations is enabled, even in MAXIMUM network security and/or HIGH friends security,
     * because a node which doesn't publish its peers' locations will get dramatically less traffic.
     *
     * Publishing our peers' locations does make us slightly more vulnerable to some attacks, but I don't think
     * it's a big difference: swapping reveals the same information, it just doesn't update as quickly. This
     * may help slightly, but probably not dramatically against a clever attacker.
     *
     * Review this decision.
     */
    sortOrder = registerPeerLocationAndSwapConfigs(nodeConfig, sortOrder);

    sortOrder =
        network.initCryptoAndTransport(
            new CryptoAndTransportParams(
                nodeConfig,
                oldConfig,
                executor,
                SemiOrderedShutdownHook.get(),
                services.securityLevels(),
                startupTime,
                enableARKs),
            sortOrder);

    // Bandwidth limit

    sortOrder = network.initBandwidthConfig(nodeConfig, sortOrder, MINIMUM_BANDWIDTH);

    String s =
"""
Testnet mode DISABLED. You may have some level of anonymity. :)
Note that this version of Crypta is still a very early alpha, and may well have numerous bugs and design flaws.
In particular: YOU ARE WIDE OPEN TO YOUR IMMEDIATE PEERS! They can eavesdrop on your requests with relatively little difficulty at present (correlation attacks etc).\
""";
    LOG.info(s);

    File nodeFile = nodeDir.file(NODE_FILE_PREFIX + network.darknetPortNumber());
    File nodeFileBackup = nodeDir.file(NODE_FILE_PREFIX + network.darknetPortNumber() + ".bak");
    loadOrInitNodeFile(nodeFile, nodeFileBackup);

    // Then read the peers
    network.initPeers(SemiOrderedShutdownHook.get());

    routing.init();

    network.initDispatcher();
    network.initUptime(runDir);

    // ULPRs

    network.initNodeStats(config, sortOrder);

    // clientCore needs new load management and other settings from stats.
    NodeClientCoreInit clientCoreInit =
        new NodeClientCoreInit(config, nodeConfig, installConfig, services.toadlets());
    NodeClientCore clientCoreLocal =
        new NodeClientCore(
            this,
            nodeRuntimeBridgeFactories,
            clientCoreInit,
            network.darknetPortNumber(),
            sortOrder,
            storage.getDatabaseKey(),
            persistentSecret);
    services.setClientCore(clientCoreLocal);
    HttpShellContainer toadlets = services.toadlets();
    toadlets.setRuntimeSupport(httpShellRuntimeSupportFactory.create(clientCoreLocal));

    services.registerJvmVersionAlertIfNeeded();

    services.maybeRegisterVisibilityAlert();

    initUpdaterOrThrow(config);

    // Opennet
    sortOrder = network.initOpennet(config, nodeConfig, sortOrder);

    extraPeerDataDir = ensureExtraPeerDataDirExists();

    // Name
    nodeConfig.register(
        "name",
        myName,
        new Option.Meta(sortOrder++, false, true, "Node.nodeName", "Node.nodeNameLong"),
        configManager.new NodeNameCallback());
    myName = nodeConfig.getString("name");

    // Datastore
    nodeConfig.register(
        "storeForceBigShrinks",
        false,
        new Option.Meta(sortOrder++, true, false, "Node.forceBigShrink", "Node.forceBigShrinkLong"),
        new BooleanCallback() {

          @Override
          public Boolean get() {
            return storage.isStoreForceBigShrinks();
          }

          @Override
          public void set(Boolean val) {
            storage.setStoreForceBigShrinks(val);
          }
        });

    // Datastore

    nodeConfig.register(
        "storeType",
        "ram",
        new Option.Meta(sortOrder++, true, true, "Node.storeType", "Node.storeTypeLong"),
        configManager.new StoreTypeCallback());

    storage.setStoreType(nodeConfig.getString("storeType"));

    /*
     * Very small initial store size, since the node will preallocate it when starting up for the first time,
     * BLOCKING STARTUP, and since everyone goes through the wizard anyway...
     */
    nodeConfig.register(
        "storeSize",
        NodeStorageSubsystem.DEFAULT_STORE_SIZE,
        new Option.Meta(sortOrder++, false, true, "Node.storeSize", "Node.storeSizeLong"),
        new LongCallback() {

          @Override
          public Long get() {
            return storage.getDatastoreSize();
          }

          @Override
          public void set(Long storeSize) throws InvalidConfigValueException {
            storage.resizeDatastore(storeSize);
          }
        },
        true);

    storage.initializeDatastoreSize(nodeConfig.getLong("storeSize"));

    nodeConfig.register(
        "storeUseSlotFilters",
        true,
        new Option.Meta(
            sortOrder++, true, false, "Node.storeUseSlotFilters", "Node.storeUseSlotFiltersLong"),
        new BooleanCallback() {

          @Override
          public Boolean get() {
            return storage.isStoreUseSlotFilters();
          }

          @Override
          public void set(Boolean val) throws NodeNeedRestartException {
            storage.setStoreUseSlotFilters(val);
          }
        });

    storage.initializeStoreUseSlotFilters(nodeConfig.getBoolean("storeUseSlotFilters"));

    nodeConfig.register(
        "storeSaltHashSlotFilterPersistenceTime",
        NodeStorageSubsystem.DEFAULT_SALT_HASH_SLOT_FILTER_PERSISTENCE_TIME,
        new Option.Meta(
            sortOrder++,
            true,
            false,
            "Node.storeSaltHashSlotFilterPersistenceTime",
            "Node.storeSaltHashSlotFilterPersistenceTimeLong"),
        new IntCallback() {

          @Override
          public Integer get() {
            return storage.getStoreSaltHashSlotFilterPersistenceTime();
          }

          @Override
          public void set(Integer val) throws InvalidConfigValueException {
            storage.setStoreSaltHashSlotFilterPersistenceTime(val);
          }
        },
        false);
    storage.initializeStoreSaltHashSlotFilterPersistenceTime(
        nodeConfig.getInt("storeSaltHashSlotFilterPersistenceTime"));

    nodeConfig.register(
        "storeSaltHashResizeOnStart",
        false,
        new Option.Meta(
            sortOrder++,
            true,
            false,
            "Node.storeSaltHashResizeOnStart",
            "Node.storeSaltHashResizeOnStartLong"),
        new BooleanCallback() {
          @Override
          public Boolean get() {
            return storage.isStoreSaltHashResizeOnStart();
          }

          @Override
          public void set(Boolean val) {
            storage.setStoreSaltHashResizeOnStart(val);
          }
        });
    storage.initializeStoreSaltHashResizeOnStart(
        nodeConfig.getBoolean("storeSaltHashResizeOnStart"));

    // Determine the default database again for storeDir (separate from earlier setup)
    Path defaultDataBase = storage.defaultStoreBaseDir();

    storage.setStoreDir(
        setupProgramDir(
            installConfig,
            "storeDir",
            defaultDataBase.toString(),
            "Node.storeDirectory",
            "Node.storeDirectoryLong"));
    installConfig.finishedInitialization();

    // Store suffix resolved lazily by factory methods where required.

    /*
     * On Windows, setting the file length normally involves writing lots of zeros.
     * So it's an uninterruptible system call that takes a long time. On OS/X,
     * presumably the same is true. If the RNG is fast enough, this means that
     * setting the length and writing random data take exactly the same amount
     * of time. On most versions of Unix, holes can be created. However, on all
     * systems, predictable disk usage is a good thing. So let's turn it on by
     * default for now, on all systems. The datastore can be read but mostly not
     * written while the random data is being written.
     */
    nodeConfig.register(
        STORE_PREALLOCATE_KEY,
        true,
        new Option.Meta(
            sortOrder++, true, true, "Node.storePreallocate", "Node.storePreallocateLong"),
        new BooleanCallback() {
          @Override
          public Boolean get() {
            return storage.isStorePreallocate();
          }

          @Override
          public void set(Boolean val) {
            storage.setStorePreallocate(val);
          }
        });
    storage.setStorePreallocate(nodeConfig.getBoolean(STORE_PREALLOCATE_KEY));

    registerStorePreallocateThreatListener(nodeConfig);

    registerPhysicalThreatLevelListener();

    handleMaximumPhysicalThreatLevelOnStartup();

    long defaultCacheSize = getDefaultCacheSize();

    nodeConfig.register(
        "cachingFreenetStoreMaxSize",
        defaultCacheSize,
        new Option.Meta(
            sortOrder++,
            true,
            false,
            "Node.cachingCryptaStoreMaxSize",
            "Node.cachingCryptaStoreMaxSizeLong"),
        new LongCallback() {
          @Override
          public Long get() {
            return storage.getCachingFreenetStoreMaxSize();
          }

          @Override
          public void set(Long val) throws InvalidConfigValueException, NodeNeedRestartException {
            storage.setCachingFreenetStoreMaxSize(val);
          }
        },
        true);

    storage.initializeCachingFreenetStoreMaxSize(nodeConfig.getLong("cachingFreenetStoreMaxSize"));

    nodeConfig.register(
        "cachingFreenetStorePeriod",
        "300k",
        new Option.Meta(
            sortOrder++,
            true,
            false,
            "Node.cachingCryptaStorePeriod",
            "Node.cachingCryptaStorePeriod"),
        new LongCallback() {
          @Override
          public Long get() {
            return storage.getCachingFreenetStorePeriod();
          }

          @Override
          public void set(Long val) throws NodeNeedRestartException {
            storage.setCachingFreenetStorePeriod(val);
          }
        },
        true);

    storage.initializeCachingFreenetStorePeriod(nodeConfig.getLong("cachingFreenetStorePeriod"));
    storage.initializeCachingFreenetStoreTracker();

    boolean shouldWriteConfig = initializeStoreBackends();

    // Client cache

    // Default is 10MB, in memory only. The wizard will change this.

    nodeConfig.register(
        "clientCacheType",
        "ram",
        new Option.Meta(
            sortOrder++, true, true, "Node.clientCacheType", "Node.clientCacheTypeLong"),
        configManager.new ClientCacheTypeCallback());

    storage.setClientCacheType(nodeConfig.getString("clientCacheType"));

    nodeConfig.register(
        "clientCacheSize",
        NodeStorageSubsystem.DEFAULT_CLIENT_CACHE_SIZE,
        new Option.Meta(
            sortOrder++, false, true, "Node.clientCacheSize", "Node.clientCacheSizeLong"),
        new LongCallback() {

          @Override
          public Long get() {
            return storage.getClientCacheSize();
          }

          @Override
          public void set(Long storeSize) throws InvalidConfigValueException {
            storage.resizeClientCache(storeSize);
          }
        },
        true);

    storage.initializeClientCacheSize(nodeConfig.getLong("clientCacheSize"));

    initializeClientCache(clientCacheKey);
    setupDatabaseIfNeeded();

    nodeConfig.register(
        "useSlashdotCache",
        true,
        new Option.Meta(
            sortOrder++, true, false, "Node.useSlashdotCache", "Node.useSlashdotCacheLong"),
        new BooleanCallback() {

          @Override
          public Boolean get() {
            return storage.isUseSlashdotCache();
          }

          @Override
          public void set(Boolean val) {
            storage.setUseSlashdotCache(val);
          }
        });
    storage.setUseSlashdotCache(nodeConfig.getBoolean("useSlashdotCache"));

    nodeConfig.register(
        "writeLocalToDatastore",
        false,
        new Option.Meta(
            sortOrder++,
            true,
            false,
            "Node.writeLocalToDatastore",
            "Node.writeLocalToDatastoreLong"),
        new BooleanCallback() {

          @Override
          public Boolean get() {
            return storage.isWriteLocalToDatastore();
          }

          @Override
          public void set(Boolean val) {
            storage.setWriteLocalToDatastore(val);
          }
        });

    storage.setWriteLocalToDatastore(nodeConfig.getBoolean("writeLocalToDatastore"));

    // This is dangerous on opennet, but was enabled by default before if both security levels
    // were LOW. Upgrade to safe value; this setting only makes sense on small darknets.
    enforceWriteLocalToDatastorePolicy();

    nodeConfig.register(
        "slashdotCacheLifetime",
        MINUTES.toMillis(30),
        new Option.Meta(
            sortOrder++,
            true,
            false,
            "Node.slashdotCacheLifetime",
            "Node.slashdotCacheLifetimeLong"),
        new LongCallback() {

          @Override
          public Long get() {
            return storage.getSlashdotCacheLifetime();
          }

          @Override
          public void set(Long val) throws InvalidConfigValueException {
            storage.setSlashdotCacheLifetime(val);
          }
        },
        false);

    long slashdotCacheLifetime = nodeConfig.getLong("slashdotCacheLifetime");

    nodeConfig.register(
        "slashdotCacheSize",
        NodeStorageSubsystem.DEFAULT_SLASHDOT_CACHE_SIZE,
        new Option.Meta(
            sortOrder++, false, true, "Node.slashdotCacheSize", "Node.slashdotCacheSizeLong"),
        new LongCallback() {

          @Override
          public Long get() {
            return storage.getSlashdotCacheSize();
          }

          @Override
          public void set(Long storeSize) throws InvalidConfigValueException {
            storage.resizeSlashdotCache(storeSize);
          }
        },
        true);

    storage.initializeSlashdotCacheSize(nodeConfig.getLong("slashdotCacheSize"));
    storage.initializeSlashdotCaches(slashdotCacheLifetime);

    // MAXIMUM seclevel = no slashdot cache.

    registerSlashdotCacheThreatListener();

    sortOrder = registerSkipWrapperWarning(nodeConfig, sortOrder);

    sortOrder = registerMaxPacketSize(nodeConfig, sortOrder);
    sortOrder = registerRoutedPingConfig(nodeConfig, sortOrder);
    sortOrder = registerNodeDiagnosticsConfig(nodeConfig, sortOrder);
    sortOrder = registerDatastoreTooSmallConfig(nodeConfig, sortOrder);

    network.updateMTU();

    // peers-offers/*.fref files
    services.configurePeersOffersFrefFiles(nodeConfig, sortOrder);
    services.maybeCreatePeersOffersAlertIfNeeded(checkPeersOffersFrefFiles());

    /* Take care that no configuration options are registered after this point; they will not persist
     * between restarts.
     */
    nodeConfig.finishedInitialization();
    persistConfigIfNeeded(config, shouldWriteConfig);
    writeNodeFile();

    // Note:
    // Short timeouts and JVM timeouts with nothing more said than the above have been seen...
    // I don't know why... need a stack dump...
    // For now just give it an extra 2 minutes. If it doesn't start in that time,
    // it's likely (from reports so far) that a restart will fix it.
    WrapperManager.signalStarting((int) MINUTES.toMillis(2));

    FetchContext ctx = services.clientCore().makeClient((short) 0, true, false).getFetchContext();

    ctx.setAllowSplitfiles(false);
    ctx.setDontEnterImplicitArchives(true);
    ctx.setMaxArchiveRestarts(0);
    ctx.setMaxMetadataSize(256);
    ctx.setMaxNonSplitfileRetries(10);
    ctx.setMaxOutputLength(4096);
    ctx.setMaxRecursionLevel(2);
    ctx.setMaxTempLength(4096);

    network.setArkFetcherContext(ctx);

    // Keep track of the fileNumber so we can potentially delete the extra peer data file
    // later, the file is authoritative
    // Shouldn't happen
    registerNodeToNodeMessageListeners();

    // Note: this is a hack
    // toadlet server should start after all initialized
    // to see NodeClientCore line 437
    finishToadletsIfEnabled();

    LOG.info("Node constructor completed");

    new BandwidthManager(this).start();

    services.initDiagnostics(network);
  }

  private void initializeServicesAndRandom(
      PersistentConfig config, RandomSource r, RandomSource weakRandom) throws NodeInitException {
    services.startWebInterface(config, executor);
    NativeThread entropyGatheringThread = bootstrap.createEntropyGatheringThread();
    HttpShellContainer toadlets = services.toadlets();
    bootstrap.setupRandomSources(r, weakRandom, toadlets, entropyGatheringThread, userDir);
    services.initNodeNameUserAlert();
    network.initLocationManager();
    network.initLocalhost();
    services.setSecurityLevels(new SecurityLevels(this, config));
  }

  private int registerMasterKeyFileConfig(SubConfig nodeConfig, int sortOrder)
      throws NodeInitException {
    // Location of the master key
    nodeConfig.register(
        "masterKeyFile",
        "master.keys",
        new Option.Meta(sortOrder++, true, true, "Node.masterKeyFile", "Node.masterKeyFileLong"),
        new StringCallback() {

          @Override
          public String get() {
            if (storage.getMasterKeysFile() == null) return "none";
            else return storage.getMasterKeysFile().getPath();
          }

          @Override
          public void set(String val) throws InvalidConfigValueException {
            // Localization may be needed to Wipe the old one and move
            throw new InvalidConfigValueException(
                "Node.masterKeyFile cannot be changed on the fly, you must shutdown, wipe the old"
                    + " file and reconfigure");
          }
        });
    File masterKeysFile = resolveMasterKeysFile(nodeConfig.getString("masterKeyFile"));
    storage.setMasterKeysFile(masterKeysFile);
    FileUtil.setOwnerRW(storage.getMasterKeysFile());
    return sortOrder;
  }

  private File resolveMasterKeysFile(String value) throws NodeInitException {
    if (value.equalsIgnoreCase("none")) {
      return null;
    }
    File file = new File(value);
    if (file.exists() && !(file.canWrite() && file.canRead())) {
      throw new NodeInitException(
          NodeInitException.EXIT_CANT_WRITE_MASTER_KEYS,
          "Cannot read from and write to master keys file " + file);
    }
    return file;
  }

  private int registerShowFriendsVisibilityAlert(SubConfig nodeConfig, int sortOrder) {
    nodeConfig.register(
        "showFriendsVisibilityAlert",
        false,
        new Option.Meta(
            sortOrder++,
            true,
            false,
            "Node.showFriendsVisibilityAlert",
            "Node.showFriendsVisibilityAlert"),
        new BooleanCallback() {

          @Override
          public Boolean get() {
            return services.isShowFriendsVisibilityAlert();
          }

          @Override
          public void set(Boolean val) {
            boolean requested = Boolean.TRUE.equals(val);
            if (requested == services.isShowFriendsVisibilityAlert()) return;
            if (requested) return;
            services.clearVisibilityAlert();
          }
        });

    services.setShowFriendsVisibilityAlert(nodeConfig.getBoolean("showFriendsVisibilityAlert"));
    return sortOrder;
  }

  private int registerProbabilisticHtlConfig(SubConfig nodeConfig, int sortOrder) {
    nodeConfig.register(
        "disableProbabilisticHTLs",
        false,
        new Option.Meta(sortOrder++, true, false, "Node.disablePHTLS", "Node.disablePHTLSLong"),
        new BooleanCallback() {

          @Override
          public Boolean get() {
            return disableProbabilisticHTLs;
          }

          @Override
          public void set(Boolean val) {
            disableProbabilisticHTLs = val;
          }
        });

    disableProbabilisticHTLs = nodeConfig.getBoolean("disableProbabilisticHTLs");
    return sortOrder;
  }

  private int registerMaxHtlConfig(SubConfig nodeConfig, int sortOrder) {
    nodeConfig.register(
        "maxHTL",
        DEFAULT_MAX_HTL,
        new Option.Meta(sortOrder++, true, false, "Node.maxHTL", "Node.maxHTLLong"),
        new ShortCallback() {

          @Override
          public Short get() {
            return maxHTL;
          }

          @Override
          public void set(Short val) throws InvalidConfigValueException {
            if (val < 0) throw new InvalidConfigValueException("Impossible max HTL");
            maxHTL = val;
          }
        },
        false);

    maxHTL = nodeConfig.getShort("maxHTL");
    return sortOrder;
  }

  private int registerArkAndRoutingConfigs(SubConfig nodeConfig, int sortOrder) {
    nodeConfig.register(
        "enableARKs",
        true,
        new Option.Meta(sortOrder++, true, false, "Node.enableARKs", "Node.enableARKsLong"),
        new BooleanCallback() {

          @Override
          public Boolean get() {
            return enableARKs;
          }

          @Override
          public void set(Boolean val) throws InvalidConfigValueException {
            throw new InvalidConfigValueException("Cannot change on the fly");
          }

          @Override
          public boolean isReadOnly() {
            return true;
          }
        });
    nodeConfig.register(
        "enablePerNodeFailureTables",
        true,
        new Option.Meta(
            sortOrder++,
            true,
            false,
            "Node.enablePerNodeFailureTables",
            "Node.enablePerNodeFailureTablesLong"),
        new BooleanCallback() {

          @Override
          public Boolean get() {
            return enablePerNodeFailureTables;
          }

          @Override
          public void set(Boolean val) throws InvalidConfigValueException {
            throw new InvalidConfigValueException("Cannot change on the fly");
          }

          @Override
          public boolean isReadOnly() {
            return true;
          }
        });
    nodeConfig.register(
        "enableULPRDataPropagation",
        true,
        new Option.Meta(
            sortOrder++,
            true,
            false,
            "Node.enableULPRDataPropagation",
            "Node.enableULPRDataPropagationLong"),
        new BooleanCallback() {

          @Override
          public Boolean get() {
            return enableULPRDataPropagation;
          }

          @Override
          public void set(Boolean val) throws InvalidConfigValueException {
            throw new InvalidConfigValueException("Cannot change on the fly");
          }

          @Override
          public boolean isReadOnly() {
            return true;
          }
        });
    nodeConfig.register(
        "enableSwapping",
        true,
        new Option.Meta(sortOrder++, true, false, "Node.enableSwapping", "Node.enableSwappingLong"),
        new BooleanCallback() {

          @Override
          public Boolean get() {
            return enableSwapping;
          }

          @Override
          public void set(Boolean val) throws InvalidConfigValueException {
            throw new InvalidConfigValueException("Cannot change on the fly");
          }

          @Override
          public boolean isReadOnly() {
            return true;
          }
        });
    return sortOrder;
  }

  private int registerPeerLocationAndSwapConfigs(SubConfig nodeConfig, int sortOrder) {
    nodeConfig.register(
        "publishOurPeersLocation",
        true,
        new Option.Meta(
            sortOrder++,
            true,
            false,
            "Node.publishOurPeersLocation",
            "Node.publishOurPeersLocationLong"),
        new BooleanCallback() {

          @Override
          public Boolean get() {
            return publishOurPeersLocation;
          }

          @Override
          public void set(Boolean val) {
            publishOurPeersLocation = val;
          }
        });
    publishOurPeersLocation = nodeConfig.getBoolean("publishOurPeersLocation");

    nodeConfig.register(
        "routeAccordingToOurPeersLocation",
        true,
        new Option.Meta(
            sortOrder++,
            true,
            false,
            "Node.routeAccordingToOurPeersLocation",
            "Node.routeAccordingToOurPeersLocation"),
        new BooleanCallback() {

          @Override
          public Boolean get() {
            return routeAccordingToOurPeersLocation;
          }

          @Override
          public void set(Boolean val) {
            routeAccordingToOurPeersLocation = val;
          }
        });
    routeAccordingToOurPeersLocation = nodeConfig.getBoolean("routeAccordingToOurPeersLocation");

    nodeConfig.register(
        "enableSwapQueueing",
        true,
        new Option.Meta(
            sortOrder++, true, false, "Node.enableSwapQueueing", "Node.enableSwapQueueingLong"),
        new BooleanCallback() {
          @Override
          public Boolean get() {
            return enableSwapQueueing;
          }

          @Override
          public void set(Boolean val) {
            enableSwapQueueing = val;
          }
        });
    enableSwapQueueing = nodeConfig.getBoolean("enableSwapQueueing");

    nodeConfig.register(
        "enablePacketCoalescing",
        true,
        new Option.Meta(
            sortOrder++,
            true,
            false,
            "Node.enablePacketCoalescing",
            "Node.enablePacketCoalescingLong"),
        new BooleanCallback() {
          @Override
          public Boolean get() {
            return enablePacketCoalescing;
          }

          @Override
          public void set(Boolean val) {
            enablePacketCoalescing = val;
          }
        });
    enablePacketCoalescing = nodeConfig.getBoolean("enablePacketCoalescing");
    return sortOrder;
  }

  private void initUpdaterOrThrow(PersistentConfig config) throws NodeInitException {
    // Node updater support
    LOG.info("Initializing Node Updater");
    try {
      services.initUpdater(config);
    } catch (InvalidConfigValueException e) {
      throw new NodeInitException(
          NodeInitException.EXIT_COULD_NOT_START_UPDATER, "Could not create Updater: " + e);
    }
  }

  private void registerPhysicalThreatLevelListener() {
    services
        .securityLevels()
        .addPhysicalThreatLevelListener(
            new SecurityLevelListener<>() {

              @Override
              public void onChange(PHYSICAL_THREAT_LEVEL oldLevel, PHYSICAL_THREAT_LEVEL newLevel) {
                if (newLevel == PHYSICAL_THREAT_LEVEL.MAXIMUM) {
                  storage.clearAwaitingPasswords();
                  try {
                    storage.killMasterKeysFile();
                    services.clientCore().getClientLayerPersister().disableWrite();
                    services.clientCore().getClientLayerPersister().waitForNotWriting();
                    services.clientCore().getClientLayerPersister().deleteAllFiles();
                  } catch (IOException _) {
                    try {
                      Files.delete(storage.getMasterKeysFile().toPath());
                    } catch (IOException ioe) {
                      LOG.warn(
                          "Fallback Files.delete() failed for {}: {}",
                          storage.getMasterKeysFile(),
                          ioe.getMessage(),
                          ioe);
                    }
                    LOG.error("Unable to securely delete {}", storage.getMasterKeysFile());
                    LOG.error(
                        NodeL10n.getBase()
                            .getString(
                                "SecurityLevels.cantDeletePasswordFile",
                                "filename",
                                storage.getMasterKeysFile().getAbsolutePath()));
                    services.registerCantDeletePasswordFileAlert();
                  }
                }
                if (oldLevel == PHYSICAL_THREAT_LEVEL.MAXIMUM
                    && newLevel != PHYSICAL_THREAT_LEVEL.HIGH) {
                  // Not passworded.
                  // Create the master.keys.
                  // Keys must exist.
                  try {
                    MasterKeys currentKeys;
                    synchronized (this) {
                      currentKeys = storage.getKeys();
                    }
                    currentKeys.changePassword(
                        storage.getMasterKeysFile(), "", bootstrap.secureRandom());
                  } catch (IOException e) {
                    LOG.error(
                        "Unable to create encryption keys file: {}",
                        storage.getMasterKeysFile(),
                        e);
                  }
                }
              }
            });
  }

  private void registerSlashdotCacheThreatListener() {
    services
        .securityLevels()
        .addNetworkThreatLevelListener(
            (oldLevel, newLevel) -> {
              if (newLevel == NETWORK_THREAT_LEVEL.MAXIMUM) {
                storage.setUseSlashdotCache(false);
              } else if (oldLevel == NETWORK_THREAT_LEVEL.MAXIMUM) {
                storage.setUseSlashdotCache(true);
              }
            });
  }

  private int registerSkipWrapperWarning(SubConfig nodeConfig, int sortOrder) {
    nodeConfig.register(
        "skipWrapperWarning",
        false,
        new Option.Meta(
            sortOrder++, true, false, "Node.skipWrapperWarning", "Node.skipWrapperWarningLong"),
        new BooleanCallback() {

          @Override
          public void set(Boolean value) {
            skipWrapperWarning = value;
          }

          @Override
          public Boolean get() {
            return skipWrapperWarning;
          }
        });

    skipWrapperWarning = nodeConfig.getBoolean("skipWrapperWarning");
    return sortOrder;
  }

  private int registerMaxPacketSize(SubConfig nodeConfig, int sortOrder) {
    nodeConfig.register(
        "maxPacketSize",
        1280,
        new Option.Meta(sortOrder++, true, true, "Node.maxPacketSize", "Node.maxPacketSizeLong"),
        new IntCallback() {

          @Override
          public Integer get() {
            synchronized (Node.this) {
              return maxPacketSize;
            }
          }

          @Override
          public void set(Integer val) throws InvalidConfigValueException {
            synchronized (Node.this) {
              if (val == maxPacketSize) return;
              if (val < MIN_UDP_MTU) throw new InvalidConfigValueException("Must be over 576");
              if (val > 1492)
                throw new InvalidConfigValueException(
                    "Larger than Ethernet frame size unlikely to work!");
              maxPacketSize = val;
            }
            network.updateMTU();
          }
        },
        true);

    maxPacketSize = nodeConfig.getInt("maxPacketSize");
    return sortOrder;
  }

  private int registerRoutedPingConfig(SubConfig nodeConfig, int sortOrder) {
    nodeConfig.register(
        "enableRoutedPing",
        false,
        new Option.Meta(
            sortOrder++, true, false, "Node.enableRoutedPing", "Node.enableRoutedPingLong"),
        new BooleanCallback() {

          @Override
          public Boolean get() {
            synchronized (Node.this) {
              return enableRoutedPing;
            }
          }

          @Override
          public void set(Boolean val) {
            synchronized (Node.this) {
              enableRoutedPing = val;
            }
          }
        });
    enableRoutedPing = nodeConfig.getBoolean("enableRoutedPing");
    return sortOrder;
  }

  private int registerNodeDiagnosticsConfig(SubConfig nodeConfig, int sortOrder) {
    nodeConfig.register(
        "enableNodeDiagnostics",
        false,
        new Option.Meta(
            sortOrder++, true, false, "Node.enableDiagnostics", "Node.enableDiagnosticsLong"),
        new BooleanCallback() {
          @Override
          public Boolean get() {
            synchronized (Node.this) {
              return enableNodeDiagnostics;
            }
          }

          @Override
          public void set(Boolean val) {
            synchronized (Node.this) {
              enableNodeDiagnostics = val;
              services.nodeDiagnostics().stop();

              if (enableNodeDiagnostics) {
                services.nodeDiagnostics().start();
              }
            }
          }
        });
    enableNodeDiagnostics = nodeConfig.getBoolean("enableNodeDiagnostics");
    return sortOrder;
  }

  private int registerDatastoreTooSmallConfig(SubConfig nodeConfig, int sortOrder) {
    nodeConfig.register(
        "datastoreTooSmallDismissed",
        -1,
        new Option.Meta(
            sortOrder++,
            true,
            false,
            "Node.datastoreTooSmallDismissed",
            "Node.datastoreTooSmallDismissedLong"),
        new IntCallback() {

          @Override
          public Integer get() {
            return datastoreTooSmallDismissed;
          }

          @Override
          public void set(Integer val) {
            datastoreTooSmallDismissed = val;
          }
        });
    datastoreTooSmallDismissed = nodeConfig.getInt("datastoreTooSmallDismissed");
    return sortOrder;
  }

  private void persistConfigIfNeeded(PersistentConfig config, boolean shouldWriteConfig) {
    if (shouldWriteConfig) {
      config.store();
    }
  }

  @SuppressWarnings({"java:S6206", "ClassCanBeRecord"})
  private static final class MasterKeyState {
    private final byte[] clientCacheKey;
    private final MasterSecret persistentSecret;

    private MasterKeyState(byte[] clientCacheKey, MasterSecret persistentSecret) {
      this.clientCacheKey = clientCacheKey;
      this.persistentSecret = persistentSecret;
    }

    private byte[] clientCacheKey() {
      return clientCacheKey;
    }

    private MasterSecret persistentSecret() {
      return persistentSecret;
    }

    @Override
    public boolean equals(Object o) {
      if (o == this) {
        return true;
      }
      if (!(o instanceof MasterKeyState state)) {
        return false;
      }
      return Arrays.equals(clientCacheKey, state.clientCacheKey)
          && Objects.equals(persistentSecret, state.persistentSecret);
    }

    @Override
    public int hashCode() {
      int result = Arrays.hashCode(clientCacheKey);
      result = 31 * result + Objects.hashCode(persistentSecret);
      return result;
    }

    @Override
    public @NotNull String toString() {
      String secretLabel =
          persistentSecret == null ? "null" : persistentSecret.getClass().getSimpleName();
      return "MasterKeyState[clientCacheKey="
          + Arrays.toString(clientCacheKey)
          + ", persistentSecret="
          + secretLabel
          + "]";
    }
  }

  private MasterKeyState initializeMasterKeysAndDatabase() {
    byte[] clientCacheKey = null;
    MasterSecret persistentSecret = null;
    int attempts = 0;
    boolean done = false;
    while (attempts < 2 && !done) {
      try {
        if (services.securityLevels().physicalThreatLevel == PHYSICAL_THREAT_LEVEL.MAXIMUM) {
          storage.setKeys(MasterKeys.createRandom(bootstrap.secureRandom()));
        } else {
          storage.setKeys(
              MasterKeys.read(storage.getMasterKeysFile(), bootstrap.secureRandom(), ""));
        }
        clientCacheKey = storage.getKeys().clientCacheMasterKey;
        persistentSecret = storage.getKeys().getPersistentMasterSecret();
        storage.setDatabaseKey(storage.getKeys().createDatabaseKey());
        if (services.securityLevels().getPhysicalThreatLevel() == PHYSICAL_THREAT_LEVEL.HIGH) {
          LOG.warn(
              "Physical threat level is set to HIGH but no password, resetting to NORMAL - probably"
                  + " timing glitch");
          services.securityLevels().resetPhysicalThreatLevel(PHYSICAL_THREAT_LEVEL.NORMAL);
        }
        done = true;
      } catch (MasterKeysFileSizeException e) {
        LOG.error(
            "Impossible: master keys file {} too {}! Deleting to enable startup, but you will lose"
                + " your client cache.",
            storage.getMasterKeysFile(),
            e.sizeToString());
        try {
          Files.delete(storage.getMasterKeysFile().toPath());
        } catch (IOException ioe) {
          LOG.warn(
              "Failed to delete master keys file {}: {}",
              storage.getMasterKeysFile(),
              ioe.getMessage(),
              ioe);
        }
      } catch (MasterKeysWrongPasswordException | IOException _) {
        done = true;
      } finally {
        attempts++;
      }
    }
    return new MasterKeyState(clientCacheKey, persistentSecret);
  }

  private record BootIdState(long bootId, long lastBootId) {}

  private BootIdState initializeBootId() {
    // Boot ID
    long bootId = bootstrap.random().nextLong();
    // Fixed the length file containing boot ID. Accessed with a random access file. So hopefully it
    // will
    // always be written. Note that we set the lastBootID to -1 if we can't _write_ our ID as well
    // as if
    // we can't read it, because if we can't write it, then we probably couldn't write it on the
    // last bootup either.
    File bootIDFile = runDir.file("bootID");
    int bootFileLength = 64 / 4; // A long in padded hex bytes
    long oldBootID;

    try (RandomAccessFile raf = new RandomAccessFile(bootIDFile, "rw")) {
      if (raf.length() < bootFileLength) {
        oldBootID = -1;
      } else {
        byte[] buf = new byte[bootFileLength];
        raf.readFully(buf);
        String s = new String(buf, StandardCharsets.ISO_8859_1);
        oldBootID = parseBootIdFromHex(s);
        raf.seek(0);
      }
      String s = HexUtil.bytesToHex(Fields.longToBytes(bootId));
      byte[] buf = s.getBytes(StandardCharsets.ISO_8859_1);
      if (buf.length != bootFileLength) LOG.warn("Not 16 bytes for boot ID {} - WTF??", bootId);
      raf.write(buf);
    } catch (IOException _) {
      oldBootID = -1;
      // If we have an error in reading, *or in writing*, we don't reliably know the last boot ID.
    }
    return new BootIdState(bootId, oldBootID);
  }

  private void loadOrInitNodeFile(File nodeFile, File nodeFileBackup) {
    // After we have set up the testnet and IP address, load the node file
    try {
      // May take the file directly in the future.
      readNodeFile(nodeFile.getPath());
    } catch (IOException e) {
      try {
        LOG.info("Trying to read node file backup ...");
        readNodeFile(nodeFileBackup.getPath());
      } catch (IOException e1) {
        if (nodeFile.exists() || nodeFileBackup.exists()) {
          LOG.error("No node file or cannot read, (re)initialising crypto etc", e1);
          LOG.error("After:", e);
        } else {
          LOG.info("Creating new cryptographic keys...");
        }
        initNodeFileSettings();
      }
    }
  }

  private File ensureExtraPeerDataDirExists() throws NodeInitException {
    File extraPeerData = userDir.file("extra-peer-data-" + network.darknetPortNumber());
    if (!((extraPeerData.exists() && extraPeerData.isDirectory()) || extraPeerData.mkdir())) {
      String msg = "Could not find or create extra peer data directory";
      throw new NodeInitException(NodeInitException.EXIT_BAD_DIR, msg);
    }
    return extraPeerData;
  }

  private void registerStorePreallocateThreatListener(SubConfig nodeConfig) {
    if (File.separatorChar == '/' && !bootstrap.isMac()) {
      services
          .securityLevels()
          .addPhysicalThreatLevelListener(
              (_, newLevel) -> {
                try {
                  nodeConfig.set(STORE_PREALLOCATE_KEY, newLevel != PHYSICAL_THREAT_LEVEL.LOW);
                } catch (NodeNeedRestartException | InvalidConfigValueException _) {
                  // Ignore
                }
              });
    }
  }

  private void handleMaximumPhysicalThreatLevelOnStartup() throws NodeInitException {
    if (services.securityLevels().physicalThreatLevel == PHYSICAL_THREAT_LEVEL.MAXIMUM) {
      try {
        storage.killMasterKeysFile();
      } catch (IOException _) {
        String msg =
            "Unable to securely delete old master.keys file when switching to MAXIMUM seclevel!!";
        LOG.error(msg);
        throw new NodeInitException(NodeInitException.EXIT_CANT_WRITE_MASTER_KEYS, msg);
      }
    }
  }

  private boolean initializeStoreBackends() throws NodeInitException {
    boolean shouldWriteConfig = false;

    if (storage.getStoreType().equals("bdb-index")) {
      LOG.warn("Old format Berkeley DB datastore detected.");
      LOG.warn("This datastore format is no longer supported.");
      LOG.warn("The old datastore will be securely deleted.");
      storage.setStoreType(TYPE_SALT_HASH);
      shouldWriteConfig = true;
      deleteOldBDBIndexStoreFiles();
    }
    if (storage.getStoreType().equals(TYPE_SALT_HASH)) {
      storage.initRAMFS();
      storage.initSaltHashFS(false, null);
    } else {
      storage.initRAMFS();
    }

    if (storage.isDatabaseAwaitingPassword()) storage.createPasswordUserAlert();
    return shouldWriteConfig;
  }

  private void initializeClientCache(byte[] clientCacheKey) throws NodeInitException {
    boolean startedClientCache = false;

    if (storage.getClientCacheType().equals(TYPE_SALT_HASH)) {
      if (clientCacheKey == null) {
        LOG.warn("Cannot open client-cache, it is passworded");
        storage.setClientCacheAwaitingPassword();
      } else {
        storage.initSaltHashClientCacheFS(false, clientCacheKey);
        startedClientCache = true;
      }
    } else if (storage.getClientCacheType().equals("none")) {
      storage.initNoClientCacheFS();
      startedClientCache = true;
    } else { // ram
      storage.initRAMClientCacheFS();
      startedClientCache = true;
    }
    if (!startedClientCache) storage.initRAMClientCacheFS();
  }

  private void setupDatabaseIfNeeded() {
    if (!services.clientCore().loadedDatabase() && storage.getDatabaseKey() != null) {
      storage.lateSetupDatabase(storage.getDatabaseKey());
    }
  }

  private void enforceWriteLocalToDatastorePolicy() {
    if (network.isOpennetEnabled()) {
      storage.setWriteLocalToDatastore(false);
    }
  }

  private void registerNodeToNodeMessageListeners() {
    messaging.registerNodeToNodeMessageListener(
        N2N_MESSAGE_TYPE_FPROXY, createFproxyN2NMListener());
    messaging.registerNodeToNodeMessageListener(
        Node.N2N_MESSAGE_TYPE_DIFFNODEREF, createDiffNoderefListener());
  }

  private NodeToNodeMessageListener createFproxyN2NMListener() {
    return (data, fromDarknet, src, type) -> {
      if (!fromDarknet) {
        LOG.error("Got N2NTM from non-darknet node ?!?!?!: from {}", src);
        return;
      }
      DarknetPeerNode darkSource = (DarknetPeerNode) src;
      LOG.info("Received N2NTM from '{}'", darkSource.getPeer());
      SimpleFieldSet fs;
      try {
        fs = new SimpleFieldSet(new String(data, StandardCharsets.UTF_8), false, true, false);
      } catch (IOException e) {
        LOG.error("IOException while parsing node to node message data", e);
        return;
      }
      fs.putOverwrite(N2N_TYPE_KEY, Integer.toString(type));
      fs.putOverwrite("receivedTime", Long.toString(System.currentTimeMillis()));
      fs.putOverwrite("receivedAs", "nodeToNodeMessage");
      int fileNumber = darkSource.writeNewExtraPeerDataFile(fs, EXTRA_PEER_DATA_TYPE_N2NTM);
      if (fileNumber == -1) {
        LOG.error(
            "Failed to write N2NTM to extra peer data file for peer {}", darkSource.getPeer());
      }
      // Keep track of the fileNumber so we can potentially delete the extra peer data file
      // later, the file is authoritative
      try {
        messaging.handleNodeToNodeTextMessageSimpleFieldSet(fs, darkSource, fileNumber);
      } catch (FSParseException e) {
        // Shouldn't happen
        throw new IllegalStateException(e);
      }
    };
  }

  private NodeToNodeMessageListener createDiffNoderefListener() {
    return (data, _, src, _) -> {
      LOG.info("Received differential node reference node to node message from {}", src.getPeer());
      SimpleFieldSet fs;
      try {
        fs = new SimpleFieldSet(new String(data, StandardCharsets.UTF_8), false, true, false);
      } catch (IOException e) {
        LOG.error("IOException while parsing node to node message data", e);
        return;
      }
      if (fs.get(N2N_TYPE_KEY) != null) {
        fs.removeValue(N2N_TYPE_KEY);
      }
      try {
        src.processDiffNoderef(fs);
      } catch (FSParseException e) {
        LOG.error("FSParseException while parsing node to node message data", e);
      }
    };
  }

  private void finishToadletsIfEnabled() {
    // Note: this is a hack
    // toadlet server should start after all initialized
    // to see NodeClientCore line 437
    HttpShellContainer toadlets = services.toadlets();
    if (toadlets.isEnabled()) {
      toadlets.finishStart();
      toadlets.createFproxy();
      toadlets.removeStartupToadlet();
    }
  }

  private static long getDefaultCacheSize() {
    long defaultCacheSize;
    long memoryLimit = NodeStarter.getMemoryLimitBytes();
    // This is tricky because systems with low memory probably also have slow disks, but using
    // up too much memory can be catastrophic...
    // Heuristic; subject to tuning.
    if (memoryLimit == Long.MAX_VALUE || memoryLimit < 0) defaultCacheSize = 1024L * 1024;
    else if (memoryLimit <= 128 * 1024 * 1024)
      defaultCacheSize = 0; // Turn off completely for very small memory.
    else {
      // 9 stores, total should be 5% of memory, up to a maximum of 1MB per store at 308MB+
      defaultCacheSize = Math.min(1024L * 1024, (memoryLimit - 128L * 1024 * 1024) / (20 * 9));
    }
    return defaultCacheSize;
  }

  private boolean checkPeersOffersFrefFiles() {
    File[] files = runDir.file("peers-offers").listFiles();
    if (files != null) {
      for (File file : files) {
        if (file.isFile()) {
          String filename = file.getName();
          if (filename.endsWith(".fref")) return true;
        }
      }
    }
    return false;
  }

  /** Delete files from the old BDB-index datastore. */
  private void deleteOldBDBIndexStoreFiles() {
    File dbDir = storage.getStoreProgramDir().file("database-" + network.darknetPortNumber());
    FileUtil.removeAll(dbDir);
    File dir = storage.getStoreProgramDir().dir();
    File[] list = dir.listFiles();
    if (list == null) return;
    for (File f : list) {
      String name = f.getName();
      if (f.isFile()
          && name.toLowerCase(Locale.ROOT)
              .matches("((chk)|(ssk)|(pubkey))-\\d*\\.((store)|(cache))(\\.((keys)|(lru)))?")) {
        LOG.info("Deleting old datastore file \"{}\"", f);
        try {
          FileUtil.secureDelete(f);
        } catch (IOException e) {
          LOG.warn("Failed to delete old datastore file \"{}\"", f, e);
        }
      }
    }
  }

  /**
   * Sets up a program directory from configuration.
   *
   * <p>This method wires a directory option into the installation configuration, applies a default
   * when the option is absent, and resolves the on-disk location. The option is persisted
   * immediately (forced write) because directory locations cannot be changed at runtime and
   * installers rely on stable paths. The method then attempts to move or create the directory.
   * Failures to create, move, or resolve the location are converted into {@link NodeInitException}
   * with a user-facing message. It is safe to call once per directory option during startup.
   *
   * @param installConfig configuration section to register and read the directory option from.
   * @param cfgKey option key under which the directory path is stored.
   * @param defaultValue the default path used when the option is unset; may be absolute or
   *     relative.
   * @param shortdesc i18n key for a short description shown to users.
   * @param longdesc i18n key for a longer description shown to users.
   * @param moveErrMsg message used when emitting errors during directory creation/move; may be
   *     {@code null}.
   * @return a {@link ProgramDirectory} bound to the resolved path and callbacks.
   * @throws NodeInitException if the directory cannot be created or set up.
   */
  public ProgramDirectory setupProgramDir(
      SubConfig installConfig,
      String cfgKey,
      String defaultValue,
      String shortdesc,
      String longdesc,
      String moveErrMsg)
      throws NodeInitException {
    ProgramDirectory dir = new ProgramDirectory(moveErrMsg);
    int sortOrder = ProgramDirectory.nextOrder();
    // forceWrite=true because currently it can't be changed on the fly, also for packages
    installConfig.register(
        cfgKey,
        defaultValue,
        new Option.Meta(sortOrder, true, true, shortdesc, longdesc),
        (StringCallback) dir.getStringCallback());
    String dirName = installConfig.getString(cfgKey);
    try {
      dir.move(dirName);
    } catch (IOException _) {
      throw new NodeInitException(
          NodeInitException.EXIT_BAD_DIR, "could not set up directory: " + longdesc);
    }
    return dir;
  }

  /**
   * Convenience overload for {@link #setupProgramDir(SubConfig, String, String, String, String,
   * String)} with a default move error message.
   *
   * <p>This variant is used when no customized directory-move failure text is needed. It delegates
   * to the full overload with a {@code null} move-error message, preserving the same persistence
   * behavior and on-disk validation. Callers should still treat {@link NodeInitException} as fatal
   * because it indicates the directory could not be created or validated.
   *
   * @param installConfig configuration section to register and read the directory option from.
   * @param cfgKey option key under which the directory path is stored.
   * @param defaultValue the default path used when the option is unset; may be absolute or
   *     relative.
   * @param shortdesc i18n key for a short description shown to users.
   * @param longdesc i18n key for a longer description shown to users.
   * @return a {@link ProgramDirectory} bound to the resolved path and callbacks.
   * @throws NodeInitException if the directory cannot be created or set up.
   */
  public ProgramDirectory setupProgramDir(
      SubConfig installConfig,
      String cfgKey,
      String defaultValue,
      String shortdesc,
      String longdesc)
      throws NodeInitException {
    return setupProgramDir(installConfig, cfgKey, defaultValue, shortdesc, longdesc, null);
  }

  /**
   * Starts the node's runtime subsystems and services.
   *
   * <p>This method transitions the node from initialized to running by starting network
   * dispatchers, peers, routing maintenance, and service layers. It also starts the updater,
   * applies startup logging, and persists the configuration state. The call is not idempotent;
   * callers should invoke it exactly once after construction. Startup ordering is significant,
   * particularly for peer loading and dispatcher setup, so the method should not be interrupted or
   * run concurrently.
   *
   * @param noSwaps when {@code true}, suppresses swap activity even if configured otherwise.
   * @throws NodeInitException if a required subsystem fails to initialize or start.
   */
  public void start(boolean noSwaps) throws NodeInitException {
    if (LOG.isTraceEnabled()) {
      LOG.trace("start(noSwaps={})", noSwaps);
    }

    // IMPORTANT: Read the peers only after we have finished initializing Node.
    // Peer constructors are complex and can call methods on Node.
    network.readPeers(nodeDir);
    network.updatePeerManagerUserAlert();

    network.startDispatcher(); // must be before usm
    network.startPeers(); // must be before usm
    network.startStats();
    routing.failureTable().start();

    network.startPacketSender();
    network.startNetworking();

    if (isUsingWrapper()) {
      LOG.info("Using wrapper correctly: {}", nodeStarter);
    } else {
      LOG.error(
          "NOT using wrapper (at least not correctly). Please ensure wrapper.jar and wrapper.conf"
              + " are current.");
    }
    if (LOG.isInfoEnabled()) {
      LOG.info("Crypta v{}+{}", Version.currentBuildNumber(), Version.gitRevision());
      network.logFnpPort();
    }
    // Start services

    network.startIpDetector();

    // Start sending swaps
    network.startLocationManager();

    // Node Updater
    try {
      LOG.info("Starting the node updater");
      services.nodeUpdater().start();
    } catch (Exception e) {
      throw new NodeInitException(
          NodeInitException.EXIT_COULD_NOT_START_UPDATER, "Could not start Updater: " + e);
    }

    services.warnIfNotUsingWrapper(isUsingWrapper(), skipWrapperWarning);

    if (!NativeThread.HAS_ENOUGH_NICE_LEVELS) {
      services.registerNotEnoughNiceLevelsAlert();
    }

    this.services.clientCore().start();

    routing.tracker().startDeadUIDChecker();

    // After everything has been created, write the config file back to disk.
    if (config instanceof FreenetFilePersistentConfig cfg) {
      cfg.finishedInit(network.ticker());
      cfg.setHasNodeStarted();
    }
    config.store();

    // Process any data in the extra peer data directory
    network.readExtraPeerData();

    if (enableNodeDiagnostics) {
      services.nodeDiagnostics().start();
    }

    LOG.info("Started node");

    hasStarted = true;
  }

  /**
   * Returns a human‑readable summary of the current node status.
   *
   * <p>The summary includes peer connectivity information and the current number of transferring
   * request senders. The exact formatting is intended for diagnostics or operator output rather
   * than stable parsing. The method is read-only and performs no synchronization beyond the
   * underlying subsystem accessors, so callers should tolerate minor race conditions in reported
   * values.
   *
   * @return a multi-line textual summary including peer and transfer information.
   */
  public String getStatus() {
    return network.peerStatus() + routing.tracker().getNumTransferringRequestSenders() + '\n';
  }

  /**
   * Returns a textual list of peers formatted for TMCI.
   *
   * <p>The output is intended for human consumption via TMCI and may be empty. When there are no
   * peers, a placeholder string is returned to clarify the state. The method allocates a new string
   * each call and should not be used as a high-frequency polling interface.
   *
   * @return a string containing the current TMCI peer listing, or a "No peers yet" placeholder.
   */
  public String getTMCIPeerList() {
    StringBuilder sb = new StringBuilder();
    String list = network.tmciPeerList();
    if (list.isEmpty()) sb.append("No peers yet");
    else sb.append(list);
    return sb.toString();
  }

  /**
   * Attempts a graceful shutdown and then exits the JVM with the given code.
   *
   * <p>The method invokes {@link #park()} to quiesce subsystems, logs the shutdown reason, and then
   * unconditionally terminates the JVM. Because it always calls {@link System#exit(int)} in a
   * {@code finally} block, callers should assume the process will exit even if shutdown steps
   * throw. This method should not be called from within shutdown hooks.
   *
   * @param reason exit status code to return to the OS; use {@code 0} for success.
   */
  @SuppressWarnings("finally")
  public void exit(int reason) {
    try {
      this.park();
      LOG.info("Goodbye. ({})", reason);
    } finally {
      System.exit(reason);
    }
  }

  /**
   * Attempts a graceful shutdown and then exits the JVM (status 0).
   *
   * <p>This overload logs the provided reason string and always exits with status {@code 0}. It is
   * intended for operator-initiated shutdowns where a human-readable reason is useful in logs. The
   * method calls {@link #park()} and terminates the process in a {@code finally} block, so it does
   * not return.
   *
   * @param reason textual reason recorded in logs; must be non-null for clarity.
   */
  @SuppressWarnings("finally")
  public void exit(String reason) {
    try {
      this.park();
      LOG.info("Goodbye. from {} ({})", this, reason);
    } finally {
      System.exit(0);
    }
  }

  /**
   * Reports whether the node is in the process of shutting down.
   *
   * <p>Once this flag becomes {@code true}, callers should avoid scheduling new background work or
   * relying on ongoing network operations. The value transitions to {@code true} during {@link
   * #park()} and is not reset.
   *
   * @return {@code true} when shutdown has begun and new work should not be scheduled.
   */
  public boolean isStopping() {
    return isStopping;
  }

  /**
   * Quiesces the node so it can be stopped safely.
   *
   * <p>The method is idempotent and may be called multiple times, including during wrapper-driven
   * shutdown sequences. It broadcasts, disconnects to peers, persists configuration, and flushes
   * any persistent random seed data. It does not block for full subsystem shutdown and should be
   * used as a best-effort transition into a safe-to-exit state rather than a full stop barrier.
   */
  public void park() {
    synchronized (this) {
      if (isStopping) return;
      isStopping = true;
    }

    network.stopPacketSender();
    network.broadcastDisconnect();

    config.store();

    if (bootstrap.random() instanceof PersistentRandomSource source) {
      source.writeSeed(true);
    }
  }

  /**
   * Returns whether the node has completed startup and entered the running state.
   *
   * <p>The flag is set to {@code true} at the end of {@link #start(boolean)} and remains true for
   * the remainder of the process lifetime. Callers can use it to gate UI updates or avoid
   * displaying startup-specific warnings once the node is fully running.
   *
   * @return {@code true} if startup has completed; {@code false} otherwise.
   */
  public boolean isHasStarted() {
    return hasStarted;
  }

  /**
   * Returns the filesystem path used to store extra peer data.
   *
   * <p>This directory is created during startup and contains queued node-to-node messages, peer
   * notes, and related metadata. The path is returned as a string for display or logging purposes;
   * callers that need file operations should convert it to a {@link File} or {@link Path}.
   *
   * @return absolute or resolved path string for the extra peer data directory.
   */
  public String getExtraPeerDataDir() {
    return extraPeerDataDir.getPath();
  }

  /**
   * Indicates whether the node currently has any connected peers.
   *
   * <p>The returned value reflects a momentary snapshot of the peer manager state and may change
   * immediately after the call. It is intended for UI or alert logic that needs to detect "no
   * peers" conditions rather than for strict synchronization.
   *
   * @return {@code true} when no peers are connected; {@code false} otherwise.
   */
  public boolean noConnectedPeers() {
    return !network.anyConnectedPeers();
  }

  /**
   * Returns whether advanced mode is enabled in the client UI.
   *
   * <p>Advanced mode controls the visibility of expert settings and diagnostics. If the client core
   * is not yet initialized, this method returns {@code false}. The value reflects the current UI
   * configuration and does not affect underlying networking behavior directly.
   *
   * @return {@code true} when advanced mode is enabled; {@code false} otherwise.
   */
  public boolean isAdvancedModeEnabled() {
    if (services.clientCore() == null) return false;
    return services.clientCore().isAdvancedModeEnabled();
  }

  /**
   * Returns whether FProxy JavaScript is enabled for this node.
   *
   * <p>The value is read from the client core configuration and reflects the current UI preference.
   * It does not verify runtime policy enforcement, so callers should treat it as a configuration
   * flag rather than a security boundary.
   *
   * @return {@code true} when FProxy JavaScript is enabled; {@code false} otherwise.
   */
  public boolean isFProxyJavascriptEnabled() {
    return services.clientCore().isFProxyJavascriptEnabled();
  }

  // Consider converting these kinds of threads to Checkpointed and implement a handler
  // using the PacketSender/Ticker. Would save a few threads.

  // Consider moving this elsewhere
  private final Object statsSync = new Object();

  /**
   * Total number of bytes of payload data sent by the node.
   *
   * <p>The counter tracks only real payload data and excludes protocol overhead. Updates are
   * synchronized on a dedicated lock to avoid race conditions with reporting. The value is
   * monotonic over the process lifetime and is not persisted across restarts.
   */
  private long totalPayloadSent;

  /**
   * Accumulates payload bytes sent by the node.
   *
   * <p>Callers should supply the number of payload bytes (not including protocol overhead) for a
   * completed sending. The method performs a synchronized increment and does not validate the
   * value, so callers must ensure the length is non-negative. It has no return value and is safe
   * for concurrent use.
   *
   * @param len number of payload bytes sent; must be non-negative.
   */
  public void sentPayload(int len) {
    synchronized (statsSync) {
      totalPayloadSent += len;
    }
  }

  /**
   * Returns the total number of payload bytes sent by the node.
   *
   * <p>The value reflects the cumulative sum of {@link #sentPayload(int)} calls and therefore
   * represents payload only, not protocol overhead. It is a snapshot that may change immediately
   * after the call due to concurrent sends. The counter is not persisted and resets on restart.
   *
   * @return total payload sent in bytes since process start.
   */
  public long getTotalPayloadSent() {
    synchronized (statsSync) {
      return totalPayloadSent;
    }
  }

  /**
   * Updates the node's configured display name in persistent configuration.
   *
   * <p>The new name is validated by the configuration option. Some changes may require a node
   * restart to take effect, in which case a {@link NodeNeedRestartException} is thrown. The method
   * does not update the in-memory name field directly; it delegates to the configuration system
   * which may apply additional constraints or notify listeners.
   *
   * @param key new node name value; must meet configuration validation rules.
   * @throws InvalidConfigValueException if the provided value fails validation.
   * @throws NodeNeedRestartException if the change requires a node restart to apply.
   */
  public void setName(String key) throws InvalidConfigValueException, NodeNeedRestartException {
    config.get("node").getOption("name").setValue(key);
  }

  /**
   * Returns the current maximum hop-to-live (HTL) value.
   *
   * <p>The value is derived from configuration and applies to routed requests that do not specify
   * an explicit HTL. It is read-only from the callers' perspective and does not perform
   * synchronization because updates are serialized through configuration callbacks.
   *
   * @return maximum HTL value used by default for routing decisions.
   */
  public short maxHTL() {
    return maxHTL;
  }

  /**
   * Returns the configured total datastore size in bytes.
   *
   * @return total byte capacity allocated for all persistent stores combined.
   */
  public synchronized long getStoreSize() {
    return storage.getDatastoreSize();
  }

  /**
   * Requests that a user-facing time-skew alert be shown.
   *
   * <p>This method is invoked when time-skew detection logic identifies a likely clock problem. It
   * delegates alert creation to the services subsystem and is synchronized to avoid duplicate
   * registration races. Callers should treat it as a best-effort signal; it does not guarantee a
   * visible alert if the client core is not yet available.
   */
  @Override
  public synchronized void setTimeSkewDetectedUserAlert() {
    services.setTimeSkewDetectedUserAlert();
  }

  /**
   * Returns the node directory root (identity and peer files).
   *
   * <p>This directory holds the node identity file, peer references, and other core states tied to
   * the node's network identity. The value is derived from startup configuration and is stable for
   * the lifetime of the process. Callers should not mutate the directory structure while the node
   * is running.
   *
   * @return node directory path.
   */
  public File getNodeDir() {
    return nodeDir.dir();
  }

  /**
   * Returns the configuration directory root.
   *
   * <p>The configuration directory contains localization overrides and configuration files. The
   * path is resolved during startup and is not expected to change at runtime. Callers should use
   * this only for read-only access unless they coordinate with the configuration subsystem.
   *
   * @return configuration directory path.
   */
  @SuppressWarnings("unused")
  public File getCfgDir() {
    return cfgDir.dir();
  }

  /**
   * Returns the user data directory root.
   *
   * <p>User data includes client state such as bookmarks and download lists. The returned path is
   * resolved during startup and should be treated as read/write by the client core only. External
   * callers should avoid modifying its contents while the node is active.
   *
   * @return user data directory path.
   */
  public File getUserDir() {
    return userDir.dir();
  }

  /**
   * Returns the runtime state directory root.
   *
   * <p>The runtime directory stores ephemeral state such as boot identifiers and PRNG seeds. It is
   * intended for mutable, restart-safe data and may be cleaned or regenerated on startup. Callers
   * should treat the returned directory as node-owned.
   *
   * @return runtime state directory path.
   */
  public File getRunDir() {
    return runDir.dir();
  }

  /**
   * Returns the datastore base directory.
   *
   * <p>This is the root for persistent store files, including salted-hash stores and caches. The
   * directory is created and managed by the storage subsystem. Callers should not alter its
   * contents directly because that can corrupt store metadata.
   *
   * @return datastore base directory path.
   */
  public File getStoreDir() {
    return storage.getStoreDir();
  }

  /**
   * ProgramDirectory handle for the node directory.
   *
   * <p>This returns the {@link ProgramDirectory} wrapper that exposes callbacks for config-driven
   * directory changes. It is primarily used by subsystems during initialization. External callers
   * should prefer {@link #getNodeDir()} for a plain {@link File} unless they need the wrapper.
   *
   * @return program directory handle.
   */
  public ProgramDirectory nodeDir() {
    return nodeDir;
  }

  /**
   * ProgramDirectory handle for the configuration directory.
   *
   * <p>Use this accessor when you need the wrapper's change callbacks or metadata. For plain file
   * access, prefer {@link #getCfgDir()}.
   *
   * @return program directory handle.
   */
  public ProgramDirectory cfgDir() {
    return cfgDir;
  }

  /**
   * ProgramDirectory handle for the user data directory.
   *
   * <p>Use this when calling APIs that expect a {@link ProgramDirectory}. For basic file access,
   * {@link #getUserDir()} is sufficient.
   *
   * @return program directory handle.
   */
  public ProgramDirectory userDir() {
    return userDir;
  }

  /**
   * ProgramDirectory handle for the runtime state directory.
   *
   * <p>This accessor is typically used by persistence helpers that operate on {@link
   * ProgramDirectory} rather than raw file paths.
   *
   * @return program directory handle.
   */
  public ProgramDirectory runDir() {
    return runDir;
  }

  /**
   * ProgramDirectory handle for the datastore base directory.
   *
   * <p>Use this when passing the store directory into storage helpers that expect the wrapper type.
   * For file path access, {@link #getStoreDir()} is more direct.
   *
   * @return program directory handle.
   */
  public ProgramDirectory storeDir() {
    return storage.getStoreProgramDir();
  }

  /**
   * Returns the configured maximum number of opennet peers.
   *
   * <p>The value is sourced from configuration and enforced by the peer manager. It represents an
   * upper bound, not a guarantee of connected peers. The method is a simple delegate and performs
   * no synchronization.
   *
   * @return maximum allowed opennet peer count.
   */
  @SuppressWarnings("unused")
  public int getMaxOpennetPeers() {
    return network.maxOpennetPeers();
  }

  /**
   * Indicates whether opennet references are allowed to pass through darknet peers.
   *
   * <p>This setting affects how peer references are forwarded between networks. The method returns
   * a snapshot of the current configuration and is synchronized to align with updates from config
   * callbacks.
   *
   * @return {@code true} if opennet references may pass through darknet; {@code false} otherwise.
   */
  public synchronized boolean passOpennetRefsThroughDarknet() {
    return network.passOpennetRefsThroughDarknet();
  }

  /**
   * Returns whether this node is running as a seed node.
   *
   * <p>Seed nodes use a distinct configuration for initial peer discovery and do not participate in
   * the network like regular peers. This method delegates to the network subsystem and returns the
   * current mode flag.
   *
   * @return {@code true} if the node is configured as a seed node.
   */
  @SuppressWarnings("unused")
  public boolean isSeednode() {
    return network.isSeednode();
  }

  @SuppressWarnings("unused")
  private final RequestClient nonPersistentClientBulk = new RequestClientBuilder().build();

  private final RequestClient nonPersistentClientRT = new RequestClientBuilder().realTime().build();

  /**
   * Indicates whether the node should publish peer locations.
   *
   * <p>This flag is derived from security-level and configuration decisions. It determines whether
   * the node includes peer-location information in announcements. The value is read without
   * synchronization because it is updated through serialized configuration callbacks.
   *
   * @return {@code true} when peer locations may be published; {@code false} otherwise.
   */
  public boolean shallWePublishOurPeersLocation() {
    return publishOurPeersLocation;
  }

  /**
   * Indicates whether routing should consider peer locations for a given HTL.
   *
   * <p>The decision depends on both the configuration flag and the provided hop-to-live value. The
   * method returns {@code false} for {@code htl <= 1} to avoid unnecessary routing heuristics on
   * near-terminal hops. It is a pure check and does not modify the state.
   *
   * @param htl hop-to-live value for the current request; must be non-negative.
   * @return {@code true} if peer-location routing should be applied; {@code false} otherwise.
   */
  public boolean shallWeRouteAccordingToOurPeersLocation(int htl) {
    return routeAccordingToOurPeersLocation && htl > 1;
  }

  boolean hasPanicked() {
    return hasPanicked;
  }

  /**
   * Immediately enters panic mode and attempts to remove sensitive persisted data.
   *
   * <p>Panic mode is a one-way transition that halts persistent client storage and deletes the
   * master keys file to prevent recovery of sensitive data. The method logs warnings if cleanup
   * fails but does not throw. After calling this method, the node remains in a panicked state until
   * restart, and persistent temporary files are cleaned on the next startup.
   */
  public void panic() {
    hasPanicked = true;
    services.clientCore().getClientLayerPersister().panic();
    services.clientCore().getClientLayerPersister().killAndWaitForNotRunning();
    try {
      storage.killMasterKeysFile();
    } catch (IOException _) {
      LOG.warn(
          "Unable to wipe master passwords key file! Please delete {} to ensure that nobody can"
              + " recover your old downloads.",
          storage.getMasterKeysFile());
    }
    // persistent-temp will be cleaned on restart.
  }

  /**
   * Requests a wrapper restart after a panic and exits the current JVM.
   *
   * <p>This method triggers a wrapper-managed restart and immediately terminates the process with
   * exit code {@code 0}. It should be invoked only after {@link #panic()} has completed its cleanup
   * steps and the node is in a consistent shutdown state.
   */
  public void finishPanic() {
    WrapperManager.restart();
    System.exit(0);
  }

  /**
   * Thrown when a master password is already configured and a new one is set.
   *
   * <p>This exception signals that an attempt was made to set a master password when one already
   * exists. Callers should surface a clear message to the user and avoid retrying without explicit
   * confirmation, as overwriting the existing password can make previously encrypted data
   * inaccessible.
   */
  public static class AlreadySetPasswordException extends Exception {

    @Serial private static final long serialVersionUID = -7328456475029374032L;

    /**
     * Constructs the exception with no detail message.
     *
     * <p>This explicit constructor mirrors the implicit default constructor and exists to provide
     * Javadoc for doclint. It does not change behavior or add side effects.
     */
    public AlreadySetPasswordException() {
      super();
    }
  }

  /**
   * Indicates whether the node is awaiting a password to unlock client materials.
   *
   * @return {@code true} when either the client cache or database requires a password.
   */
  public boolean awaitingPassword() {
    return storage.isClientCacheAwaitingPassword() || storage.isDatabaseAwaitingPassword();
  }

  /**
   * Indicates whether the database should be encrypted based on physical threat level.
   *
   * <p>This is a policy check derived from security-level configuration. It does not confirm that
   * encryption is currently active; it only states the desired policy at this moment. Callers
   * should use it for UI hints or configuration decisions.
   *
   * @return {@code true} when encryption is desired; {@code false} when cleartext is acceptable.
   */
  public boolean wantEncryptedDatabase() {
    return this.services.securityLevels().getPhysicalThreatLevel() != PHYSICAL_THREAT_LEVEL.LOW;
  }

  /**
   * Indicates whether persistent database storage should be disabled.
   *
   * <p>The decision is based on the current physical threat level. When {@code true}, the node
   * should avoid writing persistent client data to disk. This method is a policy check and does not
   * itself change persistence behavior.
   *
   * @return {@code true} if no persistent database should be used; {@code false} otherwise.
   */
  public boolean wantNoPersistentDatabase() {
    return this.services.securityLevels().getPhysicalThreatLevel() == PHYSICAL_THREAT_LEVEL.MAXIMUM;
  }

  /**
   * Indicates whether a client database is currently available.
   *
   * <p>This is a runtime status check that queries the client layer persister. A return value of
   * {@code false} means the database is not loaded or has been explicitly killed, which can occur
   * after panic or when persistence is disabled.
   *
   * @return {@code true} if a client database is loaded; {@code false} otherwise.
   */
  public boolean hasDatabase() {
    return !services.clientCore().getClientLayerPersister().isKilledOrNotLoaded();
  }

  /**
   * Returns the canonical path of the currently active database file.
   *
   * @return absolute canonical path string for the node database in use.
   */
  public String getDatabasePath() {
    return services.clientCore().getClientLayerPersister().getWriteFilename().toString();
  }

  /**
   * Returns whether locally originated data may be written to the datastore.
   *
   * <p>This flag controls whether the node stores locally generated content in the main store. It
   * is a policy decision driven by configuration and security levels and is checked by storage
   * operations when deciding whether to persist inserts.
   *
   * @return {@code true} if local data may be stored; {@code false} otherwise.
   */
  public boolean getWriteLocalToDatastore() {
    return storage.isWriteLocalToDatastore();
  }

  /**
   * Returns whether the Slashdot cache is enabled.
   *
   * <p>The Slashdot cache is a transient cache layer for frequently accessed blocks. When disabled,
   * the node still operates normally but may serve less effectively under load. This method is a
   * configuration snapshot with no side effects.
   *
   * @return {@code true} if the Slashdot cache is enabled; {@code false} otherwise.
   */
  @SuppressWarnings("unused")
  public boolean getUseSlashdotCache() {
    return storage.isUseSlashdotCache();
  }

  /**
   * Returns the minimum effective MTU used for packet sizing decisions.
   *
   * <p>The returned value is the minimum of the configured maximum packet size and the minimum MTU
   * detected by the network subsystem. This ensures the node does not exceed the smallest viable
   * MTU for its current environment. The calculation is a snapshot and may change as detection
   * updates.
   *
   * @return minimum MTU in bytes used for packet sizing.
   */
  public int getMinimumMTU() {
    int mtu;
    synchronized (this) {
      mtu = maxPacketSize;
    }
    int detected = network.minimumDetectedMtu();
    return Math.min(detected, mtu);
  }

  private static final boolean TESTNET_ENABLED = false;

  /**
   * Indicates whether testnet mode is enabled in this build.
   *
   * <p>This is a compile-time or build-time flag and does not change at runtime. It is primarily
   * used to gate behavior and logging for test deployments.
   *
   * @return {@code true} if testnet mode is enabled; {@code false} otherwise.
   */
  public static boolean isTestnetEnabled() {
    return TESTNET_ENABLED;
  }

  /**
   * Indicates whether routed pings are enabled on this node.
   *
   * @return {@code true} when routed probes are allowed; {@code false} otherwise.
   */
  public boolean enableRoutedPing() {
    return enableRoutedPing;
  }

  /**
   * Indicates whether diagnostics gathering is enabled.
   *
   * @return {@code true} when diagnostics are enabled.
   */
  public boolean isNodeDiagnosticsEnabled() {
    return enableNodeDiagnostics;
  }

  /**
   * Returns the persistent configuration entry point.
   *
   * @return persistent config instance.
   */
  public PersistentConfig getConfig() {
    return config;
  }

  /**
   * Returns the configured node display name.
   *
   * @return node display name.
   */
  public String getMyName() {
    return myName;
  }

  /**
   * Sets the node display name without additional validation.
   *
   * @param name new node display name.
   */
  public void setMyNameInternal(String name) {
    this.myName = name;
  }

  /**
   * Returns the maximum total key count across stores.
   *
   * @return max total key count.
   */
  public long getMaxTotalKeys() {
    return storage.getMaxTotalKeys();
  }

  /**
   * Indicates whether the peer set is considered outdated.
   *
   * @return {@code true} if the peers are outdated.
   */
  @SuppressWarnings("unused")
  public boolean isOutdated() {
    return network.isOutdated();
  }

  /**
   * Indicates whether probabilistic HTL decrementing is disabled.
   *
   * @return {@code true} when disabled.
   */
  public boolean isDisableProbabilisticHTLs() {
    return disableProbabilisticHTLs;
  }

  /**
   * Returns the node-to-node messaging subsystem.
   *
   * <p>This accessor exposes the dispatcher responsible for node-to-node message routing and
   * listener registration. The returned instance is owned by the node and is initialized during
   * construction. Callers should avoid reconfiguring it after startup except through its public
   * APIs.
   *
   * @return messaging subsystem instance.
   */
  public NodeMessagingSubsystem messaging() {
    return messaging;
  }

  /**
   * Returns the bootstrap helper that manages early startup state.
   *
   * <p>The bootstrap component coordinates program directory setup and random source initialization
   * and remains available after startup for access to shared random sources. The returned instance
   * is node-owned and thread-safe for the access patterns provided by the bootstrap API.
   *
   * @return bootstrap helper instance.
   */
  public NodeBootstrap bootstrap() {
    return bootstrap;
  }

  /**
   * Returns the services subsystem responsible for client-facing services.
   *
   * <p>This subsystem wires the HTTP interface, updater, alerts, and related services. The instance
   * is created during node construction and persists for the node lifetime. Callers should use the
   * subsystem's public methods rather than manipulating internal state directly.
   *
   * @return services subsystem instance.
   */
  public NodeServicesSubsystem services() {
    return services;
  }

  /**
   * Returns the network subsystem that manages peer connections and transport.
   *
   * <p>The network subsystem owns peer managers, packet dispatchers, and transport configuration.
   * It is initialized during construction and started via {@link #start(boolean)}. Callers should
   * treat the returned instance as a node-owned shared state.
   *
   * @return network subsystem instance.
   */
  public NodeNetworkSubsystem network() {
    return network;
  }

  /**
   * Returns the storage subsystem responsible for datastores and caches.
   *
   * <p>The storage subsystem manages persistent stores, cache sizing, and encryption keys. It is
   * initialized during node construction. Callers should interact with storage through its public
   * API and avoid touching store files directly.
   *
   * @return storage subsystem instance.
   */
  public NodeStorageSubsystem storage() {
    return storage;
  }

  /**
   * Returns the routing subsystem responsible for request scheduling and routing logic.
   *
   * <p>The routing subsystem coordinates request queues, failure tables, and routing heuristics. It
   * is initialized during construction and started as part of {@link #start(boolean)}.
   *
   * @return routing subsystem instance.
   */
  public NodeRoutingSubsystem routing() {
    return routing;
  }

  /**
   * Returns the node's strong random source.
   *
   * <p>The returned {@link RandomSource} is initialized during bootstrap and is safe for
   * cryptographic use within the node. Callers should not attempt to reseed or replace it.
   *
   * @return strong random source.
   */
  public RandomSource getRandom() {
    return bootstrap.random();
  }

  /**
   * Returns the primary executor used for background work.
   *
   * <p>The executor is used by multiple subsystems for background tasks and should be treated as
   * shared infrastructure. Callers may submit tasks but should avoid long blocking work that could
   * starve critical node activities.
   *
   * @return executor instance.
   */
  public PriorityAwareExecutor getExecutor() {
    return executor;
  }

  /**
   * Indicates whether ARKs are enabled.
   *
   * @return {@code true} when ARKs are enabled.
   */
  public boolean isEnableARKs() {
    return enableARKs;
  }

  /**
   * Indicates whether per‑node failure tables are enabled.
   *
   * @return {@code true} when enabled.
   */
  public boolean isEnablePerNodeFailureTables() {
    return enablePerNodeFailureTables;
  }

  /**
   * Indicates whether ULPR data propagation is enabled.
   *
   * @return {@code true} when enabled.
   */
  public boolean isEnableULPRDataPropagation() {
    return enableULPRDataPropagation;
  }

  /**
   * Indicates whether swapping is enabled.
   *
   * @return {@code true} when enabled.
   */
  public boolean isEnableSwapping() {
    return enableSwapping;
  }

  /**
   * Indicates whether swap queueing is enabled.
   *
   * @return {@code true} when enabled.
   */
  public boolean isEnableSwapQueueing() {
    return enableSwapQueueing;
  }

  /**
   * Indicates whether packet coalescing is enabled.
   *
   * @return {@code true} when enabled.
   */
  public boolean isEnablePacketCoalescing() {
    return enablePacketCoalescing;
  }

  /**
   * Returns the build number recorded when the node last ran.
   *
   * <p>This value is populated from the stored node file at startup and may be {@code -1} if the
   * previous version could not be parsed. It is intended for diagnostics and upgrade workflows, not
   * for runtime feature checks.
   *
   * @return last recorded build number, or {@code -1} when unavailable.
   */
  @SuppressWarnings("unused")
  public int getLastVersion() {
    return lastVersion;
  }

  /**
   * Returns the active {@link SecurityLevels} configuration.
   *
   * <p>The returned instance is owned by the node and may be mutated by configuration callbacks.
   * Callers should treat it as a shared mutable state and avoid storing long-lived references
   * unless they can tolerate updates.
   *
   * @return current security levels configuration instance.
   */
  public SecurityLevels getSecurityLevels() {
    return services.securityLevels();
  }

  /**
   * Returns the boot identifier of the previous clean start (or -1 when unknown).
   *
   * @return last recorded boot identifier, or -1 if unavailable.
   */
  public long getLastBootId() {
    return lastBootID;
  }

  /**
   * Returns the randomly generated boot identifier for this process start.
   *
   * @return boot identifier value.
   */
  public long getBootId() {
    return bootID;
  }

  /**
   * Returns the wall-clock startup timestamp for this node instance.
   *
   * <p>The value is captured during construction and represents {@link System#currentTimeMillis()}
   * at that moment. It is useful for uptime calculations or logging. The value is not adjusted for
   * clock skew changes after startup.
   *
   * @return startup time in milliseconds since the epoch.
   */
  public long getStartupTime() {
    return startupTime;
  }

  /**
   * Returns the non-persistent bulk request client.
   *
   * <p>The returned client issues bulk-priority requests that do not use persistent state. It is
   * intended for short-lived or ephemeral operations. Callers should not retain it across shutdown
   * because it is owned by the node and does not manage persistence for retries.
   *
   * @return non-persistent bulk request client instance.
   */
  public RequestClient getNonPersistentClientBulk() {
    return nonPersistentClientBulk;
  }

  /**
   * Returns the non-persistent real-time request client.
   *
   * <p>This client issues real-time priority requests and does not persist state. It is suited for
   * interactive operations where latency matters. The node owns the client; callers should treat it
   * as shared and not attempt to close it directly.
   *
   * @return non-persistent real-time request client instance.
   */
  public RequestClient getNonPersistentClientRT() {
    return nonPersistentClientRT;
  }
}
