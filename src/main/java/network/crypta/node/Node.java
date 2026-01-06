/* Freenet 0.7 node. */
package network.crypta.node;

import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.SECONDS;

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
import network.crypta.client.FetchContext;
import network.crypta.config.FreenetFilePersistentConfig;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.NodeNeedRestartException;
import network.crypta.config.PersistentConfig;
import network.crypta.config.SubConfig;
import network.crypta.crypt.MasterSecret;
import network.crypta.crypt.PersistentRandomSource;
import network.crypta.crypt.RandomSource;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.SecurityLevels.NETWORK_THREAT_LEVEL;
import network.crypta.node.SecurityLevels.PHYSICAL_THREAT_LEVEL;
import network.crypta.node.subsystem.CryptoAndTransportParams;
import network.crypta.node.subsystem.NodeBootstrap;
import network.crypta.node.subsystem.NodeConfigManager;
import network.crypta.node.subsystem.NodeMessagingSubsystem;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.node.subsystem.NodeRoutingSubsystem;
import network.crypta.node.subsystem.NodeServicesSubsystem;
import network.crypta.node.subsystem.NodeStorageSubsystem;
import network.crypta.pluginmanager.PluginManager;
import network.crypta.store.saltedhash.ResizablePersistentIntBuffer;
import network.crypta.support.Fields;
import network.crypta.support.HexUtil;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.BooleanCallback;
import network.crypta.support.api.IntCallback;
import network.crypta.support.api.LongCallback;
import network.crypta.support.api.ShortCallback;
import network.crypta.support.api.StringCallback;
import network.crypta.support.io.FileUtil;
import network.crypta.support.io.NativeThread;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.tanukisoftware.wrapper.WrapperManager;

/**
 * Core node implementation coordinating all major subsystems (routing, storage, peers, and
 * services).
 *
 * <p>The {@code Node} class wires together the network stack (darknet/opennet crypto and sockets),
 * request/insert schedulers, datastores and caches (CHK/SSK/public key), the HTTP UI (FProxy),
 * plugins, and diagnostics. A typical lifecycle is: create a {@code Node} via {@link NodeStarter},
 * call {@link #start(boolean)} to initialize active components, interact with the node (e.g.,
 * enqueue requests/inserts), and finally call {@link #park()} to quiesce and shut down. Most
 * methods are designed for internal coordination and are not stable APIs for external callers;
 * public methods are documented for their observable effects.
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
public class Node implements TimeSkewDetectorCallback {
  private static final Logger LOG = LoggerFactory.getLogger(Node.class);

  /** String literal for the salted-hash store/client-cache type. */
  public static final String TYPE_SALT_HASH = "salt-hash";

  /** Prefix for node file names (e.g., node-<port>). */
  private static final String NODE_FILE_PREFIX = "node-";

  /** Config key name used to control datastore preallocation. */
  private static final String STORE_PREALLOCATE_KEY = "storePreallocate";

  /** SimpleFieldSet key for Node-to-Node message type. */
  public static final String N2N_TYPE_KEY = "n2nType";

  /** System property to override the hardware RNG device path. */
  public static final String HWRNG_PATH_PROPERTY = "crypta.hwrng.path";

  /** Default hardware RNG device path for Unix-like systems. */
  public static final String DEFAULT_HWRNG_PATH = "/dev/hwrng";

  // Static initializer not required

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

  // Send keepalives every 7-14 seconds. Will be acked and if necessary resent.
  // Old behaviour was keepalives every 14-28. Even that was adequate for a 30-second
  // timeout. Most nodes don't need to send keepalives because they are constantly busy,
  // this is only an issue for disabled darknet connections, very quiet private networks
  // etc.
  /** Interval for sending keep‑alive packets on idle connections (milliseconds). */
  public static final long KEEPALIVE_INTERVAL = SECONDS.toMillis(7);

  // If no activity for 30 seconds, node is dead
  // 35 seconds allows plenty of time for resends etc. even if above is 14 sec as it is on older
  // nodes.
  /** Inactivity timeout after which a peer is considered dead (milliseconds). */
  public static final long MAX_PEER_INACTIVITY = SECONDS.toMillis(35);

  /** Time budget in milliseconds for completing a handshake exchange. */
  public static final int HANDSHAKE_TIMEOUT =
      (int) MILLISECONDS.toMillis(4800); // Keep the below within the 30-second assumed timeout.

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

  static final long MIN_INTERVAL_BETWEEN_INCOMING_SWAP_REQUESTS = MILLISECONDS.toMillis(900);
  static final long MIN_INTERVAL_BETWEEN_INCOMING_PROBE_REQUESTS = MILLISECONDS.toMillis(1000);

  /** Length in bytes for symmetric keys used by the node (e.g., AES‑256). */
  public static final int SYMMETRIC_KEY_LENGTH =
      32; // 256 bits - note that this isn't used everywhere to determine it

  private final SemiOrderedShutdownHook shutdownHook;

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

  // location manager and peers live in network subsystem

  /** Node-reference directory (node identity, peers, etc.) */
  private final ProgramDirectory nodeDir;

  /** Config directory (l10n overrides, etc) */
  final ProgramDirectory cfgDir;

  /** User data directory (bookmarks, download lists, etc.) */
  final ProgramDirectory userDir;

  /** Run-time state directory (bootID, PRNG seed, etc.) */
  final ProgramDirectory runDir;

  /** Plugin directory */
  final ProgramDirectory pluginDir;

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
  private int maxPacketSize;

  /** Default policy for ignoring low backoff during inserts. */
  public static final boolean IGNORE_LOW_BACKOFF_DEFAULT = false;

  /** Threshold in milliseconds defining a "low" backoff period for inserts. */
  public static final long LOW_BACKOFF = SECONDS.toMillis(30);

  /** Default policy for prioritizing inserts on accept. */
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
   * problems, or we suspect that the node has been booted and not written the file e.g. if we can't
   * write it. So if we want to compare data gathered in the last session and only recorded to disk
   * on a clean shutdown to data we have now, we just include the lastBootID.
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
  private final NodeConfigManager configManager;
  private final NodeNetworkSubsystem network;
  private final NodeStorageSubsystem storage;
  private final NodeRoutingSubsystem routing;

  // The watchdog will be silenced until it's true
  private boolean hasStarted;
  private boolean isStopping = false;

  /**
   * Minimum uptime for us to consider a node an acceptable place to store a key. We store a key to
   * the datastore only if it's from an insert, and we are a sink, but when calculating whether we
   * are a sink we ignore nodes which have less uptime (percentage) than this parameter.
   */
  static final int MIN_UPTIME_STORE_KEY = 40;

  private boolean enableRoutedPing;

  private boolean enableNodeDiagnostics;

  private int datastoreTooSmallDismissed;

  /**
   * Minimum bandwidth limit in bytes considered usable: 10 KiB. If there is an attempt to set a
   * limit below this - excluding the reserved -1 for input bandwidth - the callback will throw. See
   * the callbacks for outputBandwidthLimit and inputBandwidthLimit. 10 KiB are equivalent to 50 GiB
   * traffic per month.
   */
  private static final int MINIMUM_BANDWIDTH = 10 * 1024;

  /*
   * Gets minimum bandwidth in bytes considered usable.
   *
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

  public void writeNodeFile() {
    synchronized (writeNodeFileSync) {
      writeNodeFile(
          nodeDir.file(NODE_FILE_PREFIX + network.darknetPortNumber()),
          nodeDir.file(NODE_FILE_PREFIX + network.darknetPortNumber() + ".bak"));
    }
  }

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
      FileUtil.moveTo(backup, orig);
    } catch (IOException ioe) {
      LOG.error("IOE :{}", ioe.getMessage(), ioe);
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
   * Entry point delegating to {@link NodeStarter}. Parses CLI arguments and boots the wrapper‑
   * managed node process.
   *
   * @param args command‑line arguments passed to the node launcher. Unknown options are forwarded
   *     to {@link NodeStarter} and may control wrapper behavior, config paths, or startup mode.
   */
  public static void main(String[] args) {
    NodeStarter.main(args);
  }

  public boolean isUsingWrapper() {
    return nodeStarter != null && WrapperManager.isControlledByNativeWrapper();
  }

  public NodeStarter getNodeStarter() {
    return nodeStarter;
  }

  /**
   * Create a Node from a Config object.
   *
   * @param config The Config object for this node.
   * @param r The random number generator for this node. Passed in because we may want to use a
   *     non-secure RNG for e.g. one-JVM live-code simulations. Should be a Yarrow in a production
   *     node. Yarrow will be used if that parameter is null
   * @param weakRandom The fast random number generator the node will use. If null an MT instance
   *     will be used, seeded from the secure PRNG.
   * @param ns NodeStarter
   * @param executor Executor
   * @throws NodeInitException If the node initialization fails.
   */
  @SuppressWarnings("java:S3776")
  Node(
      PersistentConfig config,
      RandomSource r,
      RandomSource weakRandom,
      NodeStarter ns,
      PriorityAwareExecutor executor)
      throws NodeInitException {
    this.shutdownHook = SemiOrderedShutdownHook.get();
    this.executor = executor;
    this.nodeStarter = ns;
    this.messaging = new NodeMessagingSubsystem();
    this.bootstrap = new NodeBootstrap(this);
    this.services = new NodeServicesSubsystem(this);
    this.configManager = new NodeConfigManager(this);
    this.network = new NodeNetworkSubsystem(this);
    this.storage = new NodeStorageSubsystem(this);
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
    this.pluginDir = pd.pluginDir();
    sortOrder = configManager.configureLocalization(nodeConfig, cfgDir, sortOrder);
    services.startWebInterface(config, executor);
    NativeThread entropyGatheringThread = bootstrap.createEntropyGatheringThread();
    bootstrap.setupRandomSources(
        r, weakRandom, services.toadlets(), entropyGatheringThread, userDir);

    services.initNodeNameUserAlert();
    this.config = config;
    network.initLocationManager();

    network.initLocalhost();

    services.setSecurityLevels(new SecurityLevels(this, config));

    // Location of master key
    nodeConfig.register(
        "masterKeyFile",
        "master.keys",
        sortOrder++,
        true,
        true,
        "Node.masterKeyFile",
        "Node.masterKeyFileLong",
        new StringCallback() {

          @Override
          public String get() {
            if (storage.getMasterKeysFile() == null) return "none";
            else return storage.getMasterKeysFile().getPath();
          }

          @Override
          public void set(String val) throws InvalidConfigValueException {
            // Localization may be needed
            // Wipe the old one and move
            throw new InvalidConfigValueException(
                "Node.masterKeyFile cannot be changed on the fly, you must shutdown, wipe the old"
                    + " file and reconfigure");
          }
        });
    String value = nodeConfig.getString("masterKeyFile");
    File f;
    if (value.equalsIgnoreCase("none")) {
      f = null;
    } else {
      f = new File(value);

      if (f.exists() && !(f.canWrite() && f.canRead()))
        throw new NodeInitException(
            NodeInitException.EXIT_CANT_WRITE_MASTER_KEYS,
            "Cannot read from and write to master keys file " + f);
    }
    storage.setMasterKeysFile(f);
    FileUtil.setOwnerRW(storage.getMasterKeysFile());

    nodeConfig.register(
        "showFriendsVisibilityAlert",
        false,
        sortOrder++,
        true,
        false,
        "Node.showFriendsVisibilityAlert",
        "Node.showFriendsVisibilityAlert",
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

    // Boot ID
    bootID = bootstrap.random().nextLong();
    // Fixed length file containing boot ID. Accessed with random access file. So hopefully it will
    // always be
    // written. Note that we set lastBootID to -1 if we can't _write_ our ID as well as if we can't
    // read it,
    // because if we can't write it then we probably couldn't write it on the last bootup either.
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
      String s = HexUtil.bytesToHex(Fields.longToBytes(bootID));
      byte[] buf = s.getBytes(StandardCharsets.ISO_8859_1);
      if (buf.length != bootFileLength) LOG.warn("Not 16 bytes for boot ID {} - WTF??", bootID);
      raf.write(buf);
    } catch (IOException _) {
      oldBootID = -1;
      // If we have an error in reading, *or in writing*, we don't reliably know the last boot ID.
    }
    lastBootID = oldBootID;

    nodeConfig.register(
        "disableProbabilisticHTLs",
        false,
        sortOrder++,
        true,
        false,
        "Node.disablePHTLS",
        "Node.disablePHTLSLong",
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

    nodeConfig.register(
        "maxHTL",
        DEFAULT_MAX_HTL,
        sortOrder++,
        true,
        false,
        "Node.maxHTL",
        "Node.maxHTLLong",
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

    sortOrder = network.initTrafficClass(nodeConfig, sortOrder);

    // These should maybe persist; they need to be private.
    routing.initDecrementPolicy();

    // Determine where to bind to

    network.initMessagingCore(executor);

    // Consider whether these configs should be under a node.ip subconfig.
    sortOrder = network.registerIpDetectorConfigs(nodeConfig, sortOrder);

    // ARKs enabled?

    nodeConfig.register(
        "enableARKs",
        true,
        sortOrder++,
        true,
        false,
        "Node.enableARKs",
        "Node.enableARKsLong",
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
    enableARKs = nodeConfig.getBoolean("enableARKs");

    nodeConfig.register(
        "enablePerNodeFailureTables",
        true,
        sortOrder++,
        true,
        false,
        "Node.enablePerNodeFailureTables",
        "Node.enablePerNodeFailureTablesLong",
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
    enablePerNodeFailureTables = nodeConfig.getBoolean("enablePerNodeFailureTables");

    nodeConfig.register(
        "enableULPRDataPropagation",
        true,
        sortOrder++,
        true,
        false,
        "Node.enableULPRDataPropagation",
        "Node.enableULPRDataPropagationLong",
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
    enableULPRDataPropagation = nodeConfig.getBoolean("enableULPRDataPropagation");

    nodeConfig.register(
        "enableSwapping",
        true,
        sortOrder++,
        true,
        false,
        "Node.enableSwapping",
        "Node.enableSwappingLong",
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
    nodeConfig.register(
        "publishOurPeersLocation",
        true,
        sortOrder++,
        true,
        false,
        "Node.publishOurPeersLocation",
        "Node.publishOurPeersLocationLong",
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
        sortOrder++,
        true,
        false,
        "Node.routeAccordingToOurPeersLocation",
        "Node.routeAccordingToOurPeersLocation",
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
        sortOrder++,
        true,
        false,
        "Node.enableSwapQueueing",
        "Node.enableSwapQueueingLong",
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
        sortOrder++,
        true,
        false,
        "Node.enablePacketCoalescing",
        "Node.enablePacketCoalescingLong",
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

    sortOrder =
        network.initCryptoAndTransport(
            new CryptoAndTransportParams(
                nodeConfig,
                oldConfig,
                executor,
                shutdownHook,
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
    // After we have set up testnet and IP address, load the node file
    try {
      // May take file directly in the future.
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

    // Then read the peers
    network.initPeers(shutdownHook);

    routing.init();

    network.initDispatcher();
    network.initUptime(runDir);

    // ULPRs

    sortOrder = network.initNodeStats(config, sortOrder);

    // clientCore needs new load management and other settings from stats.
    NodeClientCoreInit clientCoreInit =
        new NodeClientCoreInit(config, nodeConfig, installConfig, services.toadlets());
    NodeClientCore clientCoreLocal =
        new NodeClientCore(
            this,
            clientCoreInit,
            network.darknetPortNumber(),
            sortOrder,
            storage.getDatabaseKey(),
            persistentSecret);
    services.setClientCore(clientCoreLocal);
    services.toadlets().setCore(clientCoreLocal);

    services.registerJvmVersionAlertIfNeeded();

    services.maybeRegisterVisibilityAlert();

    // Node updater support

    LOG.info("Initializing Node Updater");
    try {
      services.initUpdater(config);
    } catch (InvalidConfigValueException e) {
      throw new NodeInitException(
          NodeInitException.EXIT_COULD_NOT_START_UPDATER, "Could not create Updater: " + e);
    }

    // Opennet
    sortOrder = network.initOpennet(config, nodeConfig, sortOrder);

    this.extraPeerDataDir = userDir.file("extra-peer-data-" + network.darknetPortNumber());
    if (!((extraPeerDataDir.exists() && extraPeerDataDir.isDirectory())
        || (extraPeerDataDir.mkdir()))) {
      String msg = "Could not find or create extra peer data directory";
      throw new NodeInitException(NodeInitException.EXIT_BAD_DIR, msg);
    }

    // Name
    nodeConfig.register(
        "name",
        myName,
        sortOrder++,
        false,
        true,
        "Node.nodeName",
        "Node.nodeNameLong",
        configManager.new NodeNameCallback());
    myName = nodeConfig.getString("name");

    // Datastore
    nodeConfig.register(
        "storeForceBigShrinks",
        false,
        sortOrder++,
        true,
        false,
        "Node.forceBigShrink",
        "Node.forceBigShrinkLong",
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
        sortOrder++,
        true,
        true,
        "Node.storeType",
        "Node.storeTypeLong",
        configManager.new StoreTypeCallback());

    storage.setStoreType(nodeConfig.getString("storeType"));

    /*
     * Very small initial store size, since the node will preallocate it when starting up for the first time,
     * BLOCKING STARTUP, and since everyone goes through the wizard anyway...
     */
    nodeConfig.register(
        "storeSize",
        NodeStorageSubsystem.DEFAULT_STORE_SIZE,
        sortOrder++,
        false,
        true,
        "Node.storeSize",
        "Node.storeSizeLong",
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
        sortOrder++,
        true,
        false,
        "Node.storeUseSlotFilters",
        "Node.storeUseSlotFiltersLong",
        new BooleanCallback() {

          public Boolean get() {
            return storage.isStoreUseSlotFilters();
          }

          public void set(Boolean val) throws NodeNeedRestartException {
            storage.setStoreUseSlotFilters(val);
          }
        });

    storage.initializeStoreUseSlotFilters(nodeConfig.getBoolean("storeUseSlotFilters"));

    nodeConfig.register(
        "storeSaltHashSlotFilterPersistenceTime",
        ResizablePersistentIntBuffer.DEFAULT_PERSISTENCE_TIME,
        sortOrder++,
        true,
        false,
        "Node.storeSaltHashSlotFilterPersistenceTime",
        "Node.storeSaltHashSlotFilterPersistenceTimeLong",
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
        sortOrder++,
        true,
        false,
        "Node.storeSaltHashResizeOnStart",
        "Node.storeSaltHashResizeOnStartLong",
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

    // Determine default data base again for storeDir (separate from earlier setup)
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
     * So it's an uninterruptible system call that takes a loooong time. On OS/X,
     * presumably the same is true. If the RNG is fast enough, this means that
     * setting the length and writing random data take exactly the same amount
     * of time. On most versions of Unix, holes can be created. However on all
     * systems, predictable disk usage is a good thing. So lets turn it on by
     * default for now, on all systems. The datastore can be read but mostly not
     * written while the random data is being written.
     */
    nodeConfig.register(
        STORE_PREALLOCATE_KEY,
        true,
        sortOrder++,
        true,
        true,
        "Node.storePreallocate",
        "Node.storePreallocateLong",
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

    if (File.separatorChar == '/' && !bootstrap.isMac()) {
      services
          .securityLevels()
          .addPhysicalThreatLevelListener(
              (oldLevel, newLevel) -> {
                try {
                  nodeConfig.set(STORE_PREALLOCATE_KEY, newLevel != PHYSICAL_THREAT_LEVEL.LOW);
                } catch (NodeNeedRestartException | InvalidConfigValueException _) {
                  // Ignore
                }
              });
    }

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

    long defaultCacheSize = getDefaultCacheSize();

    nodeConfig.register(
        "cachingFreenetStoreMaxSize",
        defaultCacheSize,
        sortOrder++,
        true,
        false,
        "Node.cachingCryptaStoreMaxSize",
        "Node.cachingCryptaStoreMaxSizeLong",
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
        sortOrder++,
        true,
        false,
        "Node.cachingCryptaStorePeriod",
        "Node.cachingCryptaStorePeriod",
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

    // Client cache

    // Default is 10MB, in memory only. The wizard will change this.

    nodeConfig.register(
        "clientCacheType",
        "ram",
        sortOrder++,
        true,
        true,
        "Node.clientCacheType",
        "Node.clientCacheTypeLong",
        configManager.new ClientCacheTypeCallback());

    storage.setClientCacheType(nodeConfig.getString("clientCacheType"));

    nodeConfig.register(
        "clientCacheSize",
        NodeStorageSubsystem.DEFAULT_CLIENT_CACHE_SIZE,
        sortOrder++,
        false,
        true,
        "Node.clientCacheSize",
        "Node.clientCacheSizeLong",
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

    if (!services.clientCore().loadedDatabase() && storage.getDatabaseKey() != null) {
      storage.lateSetupDatabase(storage.getDatabaseKey());
    }

    nodeConfig.register(
        "useSlashdotCache",
        true,
        sortOrder++,
        true,
        false,
        "Node.useSlashdotCache",
        "Node.useSlashdotCacheLong",
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
        sortOrder++,
        true,
        false,
        "Node.writeLocalToDatastore",
        "Node.writeLocalToDatastoreLong",
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
    if (network.isOpennetEnabled()) {
      storage.setWriteLocalToDatastore(false);
    }

    nodeConfig.register(
        "slashdotCacheLifetime",
        MINUTES.toMillis(30),
        sortOrder++,
        true,
        false,
        "Node.slashdotCacheLifetime",
        "Node.slashdotCacheLifetimeLong",
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
        sortOrder++,
        false,
        true,
        "Node.slashdotCacheSize",
        "Node.slashdotCacheSizeLong",
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

    nodeConfig.register(
        "skipWrapperWarning",
        false,
        sortOrder++,
        true,
        false,
        "Node.skipWrapperWarning",
        "Node.skipWrapperWarningLong",
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

    nodeConfig.register(
        "maxPacketSize",
        1280,
        sortOrder++,
        true,
        true,
        "Node.maxPacketSize",
        "Node.maxPacketSizeLong",
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
                    "Larger than ethernet frame size unlikely to work!");
              maxPacketSize = val;
            }
            network.updateMTU();
          }
        },
        true);

    maxPacketSize = nodeConfig.getInt("maxPacketSize");

    nodeConfig.register(
        "enableRoutedPing",
        false,
        sortOrder++,
        true,
        false,
        "Node.enableRoutedPing",
        "Node.enableRoutedPingLong",
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

    nodeConfig.register(
        "enableNodeDiagnostics",
        false,
        sortOrder++,
        true,
        false,
        "Node.enableDiagnostics",
        "Node.enableDiagnosticsLong",
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

    nodeConfig.register(
        "datastoreTooSmallDismissed",
        -1,
        sortOrder++,
        true,
        false,
        "Node.datastoreTooSmallDismissed",
        "Node.datastoreTooSmallDismissedLong",
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

    network.updateMTU();

    // peers-offers/*.fref files
    services.configurePeersOffersFrefFiles(nodeConfig, sortOrder);
    services.maybeCreatePeersOffersAlertIfNeeded(checkPeersOffersFrefFiles());

    /* Take care that no configuration options are registered after this point; they will not persist
     * between restarts.
     */
    nodeConfig.finishedInitialization();
    if (shouldWriteConfig) config.store();
    writeNodeFile();

    // Initialize the plugin manager
    LOG.info("Initializing Plugin Manager");
    services.setPluginManager(PluginManager.create(this, lastVersion));

    shutdownHook.addEarlyJob(
        new NativeThread("Shutdown plugins", NativeThread.PriorityLevel.HIGH_PRIORITY.value, true) {
          @Override
          public void realRun() {
            services.pluginManager().stop(SECONDS.toMillis(30)); // Consider making it configurable.
          }
        });

    // Note:
    // Short timeouts and JVM timeouts with nothing more said than the above have been seen...
    // I don't know why... need a stack dump...
    // For now just give it an extra 2 minutes. If it doesn't start in that time,
    // it's likely (on reports so far) that a restart will fix it.
    // And we have to get a build out because ALL plugins are now failing to load,
    // including the absolutely essential (for most nodes) JSTUN and UPnP.
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
    NodeToNodeMessageListener fproxyN2NMListener =
        (data, fromDarknet, src, type) -> {
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
    messaging.registerNodeToNodeMessageListener(N2N_MESSAGE_TYPE_FPROXY, fproxyN2NMListener);
    NodeToNodeMessageListener diffNoderefListener =
        (data, fromDarknet, src, type) -> {
          LOG.info(
              "Received differential node reference node to node message from {}", src.getPeer());
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
    messaging.registerNodeToNodeMessageListener(
        Node.N2N_MESSAGE_TYPE_DIFFNODEREF, diffNoderefListener);

    // Note: this is a hack
    // toadlet server should start after all initialized
    // see NodeClientCore line 437
    if (services.toadlets().isEnabled()) {
      services.toadlets().finishStart();
      services.toadlets().createFproxy();
      services.toadlets().removeStartupToadlet();
    }

    LOG.info("Node constructor completed");

    new BandwidthManager(this).start();

    services.initDiagnostics(network);
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
      // 9 stores, total should be 5% of memory, up to maximum of 1MB per store at 308MB+
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

  /** Delete files from old BDB-index datastore. */
  private void deleteOldBDBIndexStoreFiles() {
    File dbDir = storage.getStoreProgramDir().file("database-" + network.darknetPortNumber());
    FileUtil.removeAll(dbDir);
    File dir = storage.getStoreProgramDir().dir();
    File[] list = dir.listFiles();
    if (list == null) return;
    for (File f : list) {
      String name = f.getName();
      if (f.isFile()
          && name.toLowerCase()
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
   * <p>Registers a path option in the provided {@link SubConfig}, applies defaults when the option
   * is missing, and attempts to move/create the directory on disk. The option is persisted (forced
   * write) so installers and first‑run wizards can pin locations reliably. Failures to create or
   * move the directory surface as {@link NodeInitException} with a user‑oriented message.
   *
   * @param installConfig configuration section to register and read the directory option from.
   * @param cfgKey option key under which the directory path is stored.
   * @param defaultValue default path used when the option is unset; may be absolute or relative.
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
        cfgKey, defaultValue, sortOrder, true, true, shortdesc, longdesc, dir.getStringCallback());
    String dirName = installConfig.getString(cfgKey);
    try {
      dir.move(dirName);
    } catch (IOException _) {
      throw new NodeInitException(
          NodeInitException.EXIT_BAD_DIR, "could not set up directory: " + longdesc);
    }
    return dir;
  }

  public ProgramDirectory setupProgramDir(
      SubConfig installConfig,
      String cfgKey,
      String defaultValue,
      String shortdesc,
      String longdesc)
      throws NodeInitException {
    return setupProgramDir(installConfig, cfgKey, defaultValue, shortdesc, longdesc, null);
  }

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
   * Exports volatile runtime metrics and state as a {@link SimpleFieldSet}.
   *
   * @return a snapshot of node statistics suitable for lightweight diagnostics and UI display.
   */
  /**
   * Returns a human‑readable summary of current node status.
   *
   * @return a multi‑line textual summary including peer and transfer information.
   */
  public String getStatus() {
    StringBuilder sb = new StringBuilder();
    sb.append(network.peerStatus());
    sb.append(routing.tracker().getNumTransferringRequestSenders());
    sb.append('\n');
    return sb.toString();
  }

  /**
   * Returns a textual list of peers formatted for TMCI.
   *
   * @return a string containing the current TMCI peer listing.
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
   * @param reason exit status code to return to the OS.
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
   * @param reason textual reason recorded in logs.
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
   * @return {@code true} when shutdown has begun and new work should not be scheduled.
   */
  public boolean isStopping() {
    return isStopping;
  }

  /**
   * Get the node into a state where it can be stopped safely May be called twice - once in exit
   * (above) and then again from the wrapper triggered by calling System.exit(). Beware!
   */
  public void park() {
    synchronized (this) {
      if (isStopping) return;
      isStopping = true;
    }

    network.broadcastDisconnect();

    config.store();

    if (bootstrap.random() instanceof PersistentRandomSource source) {
      source.writeSeed(true);
    }
  }

  public boolean isHasStarted() {
    return hasStarted;
  }

  public String getExtraPeerDataDir() {
    return extraPeerDataDir.getPath();
  }

  public boolean noConnectedPeers() {
    return !network.anyConnectedPeers();
  }

  public boolean isAdvancedModeEnabled() {
    if (services.clientCore() == null) return false;
    return services.clientCore().isAdvancedModeEnabled();
  }

  public boolean isFProxyJavascriptEnabled() {
    return services.clientCore().isFProxyJavascriptEnabled();
  }

  // Consider converting these kinds of threads to Checkpointed and implement a handler
  // using the PacketSender/Ticker. Would save a few threads.

  // Consider moving this elsewhere
  private final Object statsSync = new Object();

  /** The total number of bytes of real data i.e.&nbsp;payload sent by the node */
  private long totalPayloadSent;

  public void sentPayload(int len) {
    synchronized (statsSync) {
      totalPayloadSent += len;
    }
  }

  /**
   * Get the total number of bytes of payload (real data) sent by the node
   *
   * @return Total payload sent in bytes
   */
  public long getTotalPayloadSent() {
    synchronized (statsSync) {
      return totalPayloadSent;
    }
  }

  public void setName(String key) throws InvalidConfigValueException, NodeNeedRestartException {
    config.get("node").getOption("name").setValue(key);
  }

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

  @Override
  public synchronized void setTimeSkewDetectedUserAlert() {
    services.setTimeSkewDetectedUserAlert();
  }

  /**
   * Returns the node directory root (identity and peer files).
   *
   * @return node directory path.
   */
  public File getNodeDir() {
    return nodeDir.dir();
  }

  /**
   * Returns the configuration directory root.
   *
   * @return configuration directory path.
   */
  public File getCfgDir() {
    return cfgDir.dir();
  }

  /**
   * Returns the user data directory root.
   *
   * @return user data directory path.
   */
  public File getUserDir() {
    return userDir.dir();
  }

  /**
   * Returns the runtime state directory root.
   *
   * @return runtime state directory path.
   */
  public File getRunDir() {
    return runDir.dir();
  }

  /**
   * Returns the datastore base directory.
   *
   * @return datastore base directory path.
   */
  public File getStoreDir() {
    return storage.getStoreDir();
  }

  /**
   * Returns the plugin directory root.
   *
   * @return plugin directory path.
   */
  public File getPluginDir() {
    return pluginDir.dir();
  }

  /**
   * ProgramDirectory handle for the node directory.
   *
   * @return program directory handle.
   */
  public ProgramDirectory nodeDir() {
    return nodeDir;
  }

  /**
   * ProgramDirectory handle for the configuration directory.
   *
   * @return program directory handle.
   */
  public ProgramDirectory cfgDir() {
    return cfgDir;
  }

  /**
   * ProgramDirectory handle for the user data directory.
   *
   * @return program directory handle.
   */
  public ProgramDirectory userDir() {
    return userDir;
  }

  /**
   * ProgramDirectory handle for the runtime state directory.
   *
   * @return program directory handle.
   */
  public ProgramDirectory runDir() {
    return runDir;
  }

  /**
   * ProgramDirectory handle for the datastore base directory.
   *
   * @return program directory handle.
   */
  public ProgramDirectory storeDir() {
    return storage.getStoreProgramDir();
  }

  /**
   * ProgramDirectory handle for the plugin directory.
   *
   * @return program directory handle.
   */
  public ProgramDirectory pluginDir() {
    return pluginDir;
  }

  public int getMaxOpennetPeers() {
    return network.maxOpennetPeers();
  }

  public synchronized boolean passOpennetRefsThroughDarknet() {
    return network.passOpennetRefsThroughDarknet();
  }

  public boolean isSeednode() {
    return network.isSeednode();
  }

  @SuppressWarnings("unused")
  private final RequestClient nonPersistentClientBulk = new RequestClientBuilder().build();

  private final RequestClient nonPersistentClientRT = new RequestClientBuilder().realTime().build();

  public boolean shallWePublishOurPeersLocation() {
    return publishOurPeersLocation;
  }

  public boolean shallWeRouteAccordingToOurPeersLocation(int htl) {
    return routeAccordingToOurPeersLocation && htl > 1;
  }

  boolean hasPanicked() {
    return hasPanicked;
  }

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

  /** Requests a wrapper restart after a panic and exits the current JVM. */
  public void finishPanic() {
    WrapperManager.restart();
    System.exit(0);
  }

  /** Thrown when a master password is already configured and a new one is set. */
  public static class AlreadySetPasswordException extends Exception {

    @Serial private static final long serialVersionUID = -7328456475029374032L;
  }

  /**
   * Indicates whether the node is awaiting a password to unlock client materials.
   *
   * @return {@code true} when either the client cache or database requires a password.
   */
  public boolean awaitingPassword() {
    return storage.isClientCacheAwaitingPassword() || storage.isDatabaseAwaitingPassword();
  }

  public boolean wantEncryptedDatabase() {
    return this.services.securityLevels().getPhysicalThreatLevel() != PHYSICAL_THREAT_LEVEL.LOW;
  }

  public boolean wantNoPersistentDatabase() {
    return this.services.securityLevels().getPhysicalThreatLevel() == PHYSICAL_THREAT_LEVEL.MAXIMUM;
  }

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

  public boolean getWriteLocalToDatastore() {
    return storage.isWriteLocalToDatastore();
  }

  @SuppressWarnings("unused")
  public boolean getUseSlashdotCache() {
    return storage.isUseSlashdotCache();
  }

  public int getMinimumMTU() {
    int mtu;
    synchronized (this) {
      mtu = maxPacketSize;
    }
    int detected = network.minimumDetectedMtu();
    if (detected < mtu) return detected;
    return mtu;
  }

  private static final boolean TESTNET_ENABLED = false;

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
   * Returns the aggregate node statistics collector.
   *
   * @return node statistics.
   */
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
  public boolean isOutdated() {
    return network.isOutdated();
  }

  /**
   * Returns the helper responsible for public‑key caching and retrieval.
   *
   * @return pubkey helper.
   */

  /**
   * Indicates whether probabilistic HTL decrementing is disabled.
   *
   * @return {@code true} when disabled.
   */
  public boolean isDisableProbabilisticHTLs() {
    return disableProbabilisticHTLs;
  }

  public NodeMessagingSubsystem messaging() {
    return messaging;
  }

  public NodeBootstrap bootstrap() {
    return bootstrap;
  }

  public NodeServicesSubsystem services() {
    return services;
  }

  public NodeNetworkSubsystem network() {
    return network;
  }

  public NodeStorageSubsystem storage() {
    return storage;
  }

  public NodeRoutingSubsystem routing() {
    return routing;
  }

  /**
   * Returns the shutdown hook used to order shutdown tasks.
   *
   * @return shutdown hook coordinator
   */
  public SemiOrderedShutdownHook getShutdownHook() {
    return shutdownHook;
  }

  /**
   * Returns the node's strong random source.
   *
   * @return strong random source.
   */
  public RandomSource getRandom() {
    return bootstrap.random();
  }

  /**
   * Returns the primary executor used for background work.
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

  public int getLastVersion() {
    return lastVersion;
  }

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

  public long getStartupTime() {
    return startupTime;
  }

  public RequestClient getNonPersistentClientBulk() {
    return nonPersistentClientBulk;
  }

  public RequestClient getNonPersistentClientRT() {
    return nonPersistentClientRT;
  }
}
