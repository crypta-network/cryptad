package network.crypta.node;

import static java.util.concurrent.TimeUnit.SECONDS;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashSet;
import network.crypta.client.ArchiveManager;
import network.crypta.client.FECCodec;
import network.crypta.client.FetchContext;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.HighLevelSimpleClientImpl;
import network.crypta.client.InsertContext;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientLayerPersister;
import network.crypta.client.async.ClientRequestScheduler;
import network.crypta.client.async.DatastoreChecker;
import network.crypta.client.async.HealingDecisionSupplier;
import network.crypta.client.async.HealingQueue;
import network.crypta.client.async.PersistentStatsPutter;
import network.crypta.client.async.SimpleHealingQueue;
import network.crypta.client.async.USKManager;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.client.filter.FilterCallback;
import network.crypta.client.filter.FoundURICallback;
import network.crypta.client.filter.GenericReadFilterCallback;
import network.crypta.client.filter.LinkFilterExceptionProvider;
import network.crypta.clients.fcp.ClientRequest;
import network.crypta.clients.fcp.FCPServer;
import network.crypta.clients.fcp.PersistentRequestRoot;
import network.crypta.clients.http.FProxyToadlet;
import network.crypta.clients.http.SimpleToadletServer;
import network.crypta.clients.http.bookmark.BookmarkManager;
import network.crypta.config.Config;
import network.crypta.config.Dimension;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.NodeNeedRestartException;
import network.crypta.config.SubConfig;
import network.crypta.crypt.MasterSecret;
import network.crypta.crypt.RandomSource;
import network.crypta.fs.AppDirs;
import network.crypta.fs.AppEnv;
import network.crypta.fs.Resolved;
import network.crypta.fs.ServiceDirs;
import network.crypta.io.xfer.AbortedException;
import network.crypta.io.xfer.PartiallyReceivedBlock;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.CHKVerifyException;
import network.crypta.keys.ClientCHK;
import network.crypta.keys.ClientCHKBlock;
import network.crypta.keys.ClientKey;
import network.crypta.keys.ClientKeyBlock;
import network.crypta.keys.ClientSSK;
import network.crypta.keys.ClientSSKBlock;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.Key;
import network.crypta.keys.KeyBlock;
import network.crypta.keys.NodeSSK;
import network.crypta.keys.SSKBlock;
import network.crypta.keys.SSKVerifyException;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.SecurityLevels.PHYSICAL_THREAT_LEVEL;
import network.crypta.node.useralerts.DatastoreTooSmallAlert;
import network.crypta.node.useralerts.DiskSpaceUserAlert;
import network.crypta.node.useralerts.SimpleUserAlert;
import network.crypta.node.useralerts.UserAlert;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.pluginmanager.PluginRespirator;
import network.crypta.pluginmanager.PluginStores;
import network.crypta.store.KeyCollisionException;
import network.crypta.support.Base64;
import network.crypta.support.HTMLNode;
import network.crypta.support.MemoryLimitedJobRunner;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.SizeUtil;
import network.crypta.support.Ticker;
import network.crypta.support.api.BooleanCallback;
import network.crypta.support.api.IntCallback;
import network.crypta.support.api.LongCallback;
import network.crypta.support.api.StringArrCallback;
import network.crypta.support.compress.Compressor;
import network.crypta.support.compress.RealCompressor;
import network.crypta.support.io.DiskSpaceCheckingRandomAccessBufferFactory;
import network.crypta.support.io.FileUtil;
import network.crypta.support.io.FilenameGenerator;
import network.crypta.support.io.MaybeEncryptedRandomAccessBufferFactory;
import network.crypta.support.io.NativeThread;
import network.crypta.support.io.PersistentTempBucketFactory;
import network.crypta.support.io.PooledFileRandomAccessBufferFactory;
import network.crypta.support.io.TempBucketFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Bridges the {@link Node} and the client layer.
 *
 * <p>This component wires and coordinates client-facing services such as request scheduling,
 * client-layer persistence, USK management, healing, FCP/TMCI endpoints, and the HTTP toadlet
 * container. It owns factories for temporary and persistent buckets, exposes a {@link
 * ClientContext} for higher-level APIs, and reports per-request costs to {@link NodeStats}.
 *
 * <p>Threading: methods are generally invoked from the node's executor threads; selected getters
 * are synchronized where they expose mutable state. Startup is multiphased: the constructor
 * performs wiring, {@link #start()} activates services and resumes persistent requests on a
 * background task.
 */
public class NodeClientCore implements Persistable {
  private static final Logger LOG = LoggerFactory.getLogger(NodeClientCore.class);
  private static final String CFG_ENCRYPT_PERSISTENT_TEMP_BUCKETS = "encryptPersistentTempBuckets";
  private static final String DOWNLOADS_DIR_NAME = "downloads";
  private static final String LOG_BYTES_OPEN = " bytes (";
  private static final String MSG_CANNOT_LOCK_UID = "Could not lock UID just randomly generated: ";
  private static final String MSG_BROKEN_PRNG = " - probably indicates broken PRNG";
  private static final String LOG_DOES_NOT_VERIFY = "Does not verify: ";

  // Maximum number of healing inserts. If a 320 MiB file barely succeeds,
  // it has ~10,000 blocks eligible for healing (10,000 × 32 KiB).
  // Large-file lifetime is currently 7–14 days; with a 10,000-key cap a 320 MiB file
  // stays alive if one person accesses it every 10 days, and a 3 GiB file if one person
  // downloads it per day. 8k inserts can require up to ~250 MiB when large files just
  // barely succeed.
  private static final int MAX_RUNNING_HEALING_INSERTS = 8192;

  /** Puts persistent bandwidth statistics. Access via {@link #getBandwidthStatsPutter()}. */
  private final PersistentStatsPutter bandwidthStatsPutter;

  /** Manages USK state. Access via {@link #getUskManager()}. */
  private final USKManager uskManager;

  /**
   * Manages archive handlers and caches to read container formats efficiently. Immutable after
   * construction.
   */
  public final ArchiveManager archiveManager;

  /** Request starter group. Access via {@link #getRequestStarters()}. */
  private final RequestStarterGroup requestStarters;

  private final HealingQueue healingQueue;

  /**
   * Runs memory-bound background jobs (e.g., FEC decode) within a configured capacity and thread
   * limit. Exposed for components that need to schedule such work explicitly.
   */
  public final MemoryLimitedJobRunner memoryLimitedJobRunner;

  /**
   * Anti-CSRF token used by the HTTP UI.
   *
   * <p>Include this value as a hidden field in any POST that changes server-side state and verify
   * it on receipt. To render a form that includes the token use {@link
   * PluginRespirator#addFormChild(HTMLNode, String, String)}. To verify a request use {@code
   * WebInterfaceToadlet.isFormPassword(HTTPRequest)}.
   */
  private final String formPassword;

  final ProgramDirectory downloadsDir;
  private File[] downloadAllowedDirs;
  private boolean includeDownloadDir;
  private boolean downloadAllowedEverywhere;
  private boolean downloadDisabled;
  private File[] uploadAllowedDirs;
  private boolean uploadAllowedEverywhere;

  /** Temp filename generator. Access via {@link #getTempFilenameGenerator()}. */
  private final FilenameGenerator tempFilenameGenerator;

  /** Persistent filename generator. Access via {@link #getPersistentFilenameGenerator()}. */
  private final FilenameGenerator persistentFilenameGenerator;

  /** Temp bucket factory. Access via {@link #getTempBucketFactory()}. */
  private final TempBucketFactory tempBucketFactory;

  /** Persistent temp bucket factory. Access via {@link #getPersistentTempBucketFactory()}. */
  private final PersistentTempBucketFactory persistentTempBucketFactory;

  private final DiskSpaceCheckingRandomAccessBufferFactory persistentDiskChecker;

  /**
   * RandomAccessBuffer factory for persistent storage that can transparently enable encryption
   * based on the current security level and configuration.
   */
  public final MaybeEncryptedRandomAccessBufferFactory persistentRAFFactory;

  /** Persists and reloads client-layer state such as throttles and pending requests. */
  private final ClientLayerPersister clientLayerPersister;

  /** Back-reference to the owning {@link Node}. Access via {@link #getNode()}. */
  private final Node node;

  /** Tracks request UIDs and related lifecycle events used by senders and listeners. */
  public final RequestTracker tracker;

  private final NodeStats nodeStats;

  /** Random source for request IDs and other non-cryptographic needs. */
  private final RandomSource random;

  final ProgramDirectory tempDir; // Temporary buckets (non-persistent)
  final ProgramDirectory persistentTempDir;

  /** User alert manager. Access via {@link #getAlerts()}. */
  private final UserAlertManager alerts;

  final TextModeClientInterfaceServer tmci;

  /** Direct Text Mode Client Interface. Access via {@link #getDirectTMCI()}. */
  private TextModeClientInterface directTMCI;

  private final PersistentRequestRoot fcpPersistentRoot;
  final FCPServer fcpServer;
  FProxyToadlet fproxyServlet;
  final SimpleToadletServer toadletContainer;

  /** Compressor implementation used for network transfers and storage. */
  public final RealCompressor compressor;

  /** Persists client throttles and schedules resume at startup. */
  private final Persister persister;

  /** Datastore consistency checker. Access via {@link #getStoreChecker()}. */
  private final DatastoreChecker storeChecker;

  /**
   * How much disk space must be free when starting a long-term, unpredictable duration job such as
   * a big download?
   */
  private long minDiskFreeLongTerm;

  /**
   * How much disk space must be free when starting a quick but disk-heavy job such as completing a
   * download?
   */
  private long minDiskFreeShortTerm;

  /** Client context. Access via {@link #getClientContext()}. */
  private final ClientContext clientContext;

  private static int maxBackgroundUSKFetchers; // Client configuration item
  static final int MAX_ARCHIVE_HANDLERS = 200; // don't take up much RAM
  static final long MAX_CACHED_ARCHIVE_DATA =
      32L * 1024 * 1024; // consider proportional to store size by default
  static final long MAX_ARCHIVED_FILE_SIZE = 1024L * 1024; // arbitrary
  static final int MAX_CACHED_ELEMENTS =
      256 * 1024; // equally arbitrary; hopefully we can cache many of these though
  private final UserAlert startingUpAlert;
  private boolean alwaysCommit;
  private final PluginStores pluginStores;
  private boolean lazyStartDatastoreChecker;

  private boolean finishedInitStorage;
  private boolean finishingInitStorage;

  NodeClientCore(
      Node node,
      Config config,
      SubConfig nodeConfig,
      SubConfig installConfig,
      int portNumber,
      int sortOrder,
      SimpleToadletServer toadlets,
      DatabaseKey databaseKey,
      MasterSecret persistentSecret)
      throws NodeInitException {
    this.node = node;
    this.tracker = node.getTracker();
    this.nodeStats = node.getNodeStats();
    this.random = node.getRandom();
    this.pluginStores = new PluginStores(node, installConfig);

    sortOrder = registerLazyStartDatastoreChecker(nodeConfig, sortOrder);

    storeChecker =
        new DatastoreChecker(
            node, lazyStartDatastoreChecker, node.getExecutor(), "Datastore checker");
    byte[] pwdBuf = new byte[16];
    random.nextBytes(pwdBuf);
    compressor = new RealCompressor();
    this.formPassword = Base64.encode(pwdBuf);
    alerts = new UserAlertManager(this);
    persister =
        new ConfigurablePersister(
            this,
            nodeConfig,
            "clientThrottleFile",
            "client-throttle.dat",
            sortOrder++,
            true,
            false,
            "NodeClientCore.fileForClientStats",
            "NodeClientCore.fileForClientStatsLong",
            node.getTicker(),
            node.getRunDir());

    SimpleFieldSet throttleFS = persister.read();
    if (LOG.isDebugEnabled()) LOG.debug("Read throttleFS:\n{}", throttleFS);

    if (LOG.isDebugEnabled()) LOG.debug("Serializing RequestStarterGroup from:\n{}", throttleFS);

    // Temp files

    // Adaptive default: cacheDir/tmp
    Path defaultCacheDir = resolveDefaultCacheDir();
    Path defaultDataDir = resolveDefaultDataDir();

    this.tempDir =
        node.setupProgramDir(
            installConfig,
            "tempDir",
            defaultCacheDir.resolve("tmp").toString(),
            "NodeClientCore.tempDir",
            "NodeClientCore.tempDirLong");

    // Note: remove back compatibility hack when safe.
    deleteLegacyTempDirIfPresent(node);

    FileUtil.setOwnerRWX(getTempDir());

    tempFilenameGenerator = createTempFilenameGeneratorOrThrow();

    uskManager = new USKManager(this);

    // Persistent temp files
    sortOrder = registerEncryptPersistentTempBuckets(nodeConfig, sortOrder);

    this.persistentTempDir =
        node.setupProgramDir(
            installConfig,
            "persistentTempDir",
            defaultCacheDir.resolve("persistent-temp").toString(),
            "NodeClientCore.persistentTempDir",
            "NodeClientCore.persistentTempDirLong");

    fcpPersistentRoot = new PersistentRequestRoot();
    PersistentTempBucketFactory ptbf = createPersistentTempBucketFactory(nodeConfig);
    this.persistentTempBucketFactory = ptbf;
    this.persistentFilenameGenerator = ptbf.fg;

    // Remove legacy persistent-blob file to reclaim space for migration.
    deleteOldPersistentBlobIfPresent();

    // Allocate ~10% of available memory to the RAM bucket pool by default.
    int defaultRamBucketPoolSize = computeDefaultRamBucketPoolSize(NodeStarter.getMemoryLimitMB());

    // Max bucket size is 5% of the pool, minimum 32 KiB (one block; typical case).
    long maxBucketSize = Math.max(32768, (defaultRamBucketPoolSize * 1024 * 1024) / 20);

    sortOrder = registerMaxRamBucketSize(nodeConfig, sortOrder, maxBucketSize);

    sortOrder = registerRamBucketPoolSize(nodeConfig, sortOrder, defaultRamBucketPoolSize);

    sortOrder = registerEncryptTempBuckets(nodeConfig, sortOrder);

    initDiskSpaceLimits(nodeConfig, sortOrder);

    MasterSecret cryptoSecretTransient = new MasterSecret();
    tempBucketFactory =
        new TempBucketFactory(
            node.getExecutor(),
            tempFilenameGenerator,
            nodeConfig.getLong("maxRAMBucketSize"),
            nodeConfig.getLong("RAMBucketPoolSize"),
            nodeConfig.getBoolean("encryptTempBuckets"),
            minDiskFreeShortTerm,
            cryptoSecretTransient);

    bandwidthStatsPutter = new PersistentStatsPutter();

    clientLayerPersister =
        new ClientLayerPersister(
            node.getExecutor(),
            node.getTicker(),
            node,
            this,
            persistentTempBucketFactory,
            tempBucketFactory,
            bandwidthStatsPutter);

    SemiOrderedShutdownHook shutdownHook = SemiOrderedShutdownHook.get();
    installCoreShutdownHooks(shutdownHook);

    archiveManager = createArchiveManager();
    healingQueue = createHealingQueue();

    PooledFileRandomAccessBufferFactory raff =
        new PooledFileRandomAccessBufferFactory(persistentFilenameGenerator);
    persistentDiskChecker =
        new DiskSpaceCheckingRandomAccessBufferFactory(
            raff, persistentTempDir.dir(), minDiskFreeLongTerm + tempBucketFactory.getMaxRamUsed());
    persistentRAFFactory =
        new MaybeEncryptedRandomAccessBufferFactory(
            persistentDiskChecker, nodeConfig.getBoolean(CFG_ENCRYPT_PERSISTENT_TEMP_BUCKETS));
    persistentTempBucketFactory.setDiskSpaceChecker(persistentDiskChecker);
    HighLevelSimpleClient client = makeClient((short) 0, false, false);
    FetchContext defaultFetchContext = client.getFetchContext();
    InsertContext defaultInsertContext = client.getInsertContext(false);
    int maxMemoryLimitedJobThreads = computeMaxMemoryLimitedJobThreads();
    sortOrder =
        registerMemoryLimitedJobThreadLimit(nodeConfig, sortOrder, maxMemoryLimitedJobThreads);
    long overallMemoryLimit = NodeStarter.getMemoryLimitBytes();
    long defaultMemoryLimitedJobMemoryLimit =
        computeDefaultMemoryLimitedJobMemoryLimit(overallMemoryLimit);
    sortOrder =
        registerMemoryLimitedJobMemoryLimit(
            nodeConfig, sortOrder, defaultMemoryLimitedJobMemoryLimit);
    memoryLimitedJobRunner =
        new MemoryLimitedJobRunner(
            nodeConfig.getLong("memoryLimitedJobMemoryLimit"),
            nodeConfig.getInt("memoryLimitedJobThreadLimit"),
            node.getExecutor(),
            RequestStarter.NUMBER_OF_PRIORITY_CLASSES);
    installFecShutdownHooks(shutdownHook);
    clientContext =
        new ClientContext(
            node.getBootId(),
            clientLayerPersister,
            node.getExecutor(),
            archiveManager,
            persistentTempBucketFactory,
            tempBucketFactory,
            persistentTempBucketFactory,
            healingQueue,
            uskManager,
            random,
            node.getFastWeakRandom(),
            node.getTicker(),
            memoryLimitedJobRunner,
            tempFilenameGenerator,
            persistentFilenameGenerator,
            tempBucketFactory,
            persistentRAFFactory,
            tempBucketFactory.getUnderlyingRAFFactory(),
            persistentDiskChecker,
            compressor,
            storeChecker,
            fcpPersistentRoot,
            cryptoSecretTransient,
            toadlets,
            defaultFetchContext,
            defaultInsertContext,
            config);
    compressor.setClientContext(getClientContext());
    storeChecker.setContext(getClientContext());
    getClientLayerPersister().start(getClientContext());

    requestStarters = createRequestStarters(node, portNumber, config, throttleFS);

    clientContext.init(requestStarters, alerts);

    setupSecretAndInitStorage(databaseKey, persistentSecret);

    installPhysicalThreatLevelListener();

    // Downloads directory

    this.downloadsDir =
        node.setupProgramDir(
            nodeConfig,
            "downloadsDir",
            defaultDataDir.resolve(DOWNLOADS_DIR_NAME).toString(),
            "NodeClientCore.downloadsDir",
            "NodeClientCore.downloadsDirLong",
            l10n("couldNotFindOrCreateDir"));

    // Downloads allowed, uploads allowed

    sortOrder = registerDownloadAllowedDirs(nodeConfig, sortOrder);

    sortOrder = registerUploadAllowedDirs(nodeConfig, sortOrder);

    LOG.info("Initializing USK Manager");
    uskManager.init(getClientContext());

    sortOrder = registerMaxBackgroundUSKFetchers(nodeConfig, sortOrder);

    // This is all part of construction, not of start().
    // Some plugins depend on it, so it needs to be *created* before they are started.

    // TMCI and FCP (including persistent requests so needs to start before FProxy)
    tmci = initTmci(config);
    fcpServer = initFcp(node);

    // FProxy
    // Note: This wiring is a stopgap; plugins should handle this in the future.
    startingUpAlert = createStartingUpAlert();
    registerFProxyAlerts();
    toadletContainer = toadlets;
    toadletContainer.setBucketFactory(tempBucketFactory);

    registerAlwaysCommit(nodeConfig, sortOrder);
    alwaysCommit = nodeConfig.getBoolean("alwaysCommit");
    alerts.register(new DiskSpaceUserAlert(this));
    alerts.register(new DatastoreTooSmallAlert(this));
  }

  /**
   * Recomputes the minimum free-disk threshold for the persistent RAF factory.
   *
   * <p>Includes RAM-backed temp usage in the persistent threshold to account for possible migration
   * of temporary data to disk.
   */
  protected void updatePersistentRAFSpaceLimit() {
    // The temp bucket factory may have to migrate everything to disk.
    // So we add the RAM limit for the temp factory to the disk limit for the persistent one.
    if (persistentRAFFactory != null) {
      long size;
      synchronized (this) {
        size = minDiskFreeLongTerm;
      }
      size += tempBucketFactory.getMaxRamUsed();
      persistentDiskChecker.setMinDiskSpace(size);
    }
  }

  private void initDiskSpaceLimits(SubConfig nodeConfig, int sortOrder) {
    nodeConfig.register(
        "minDiskFreeLongTerm",
        "1G",
        sortOrder++,
        true,
        true,
        "NodeClientCore.minDiskFreeLongTerm",
        "NodeClientCore.minDiskFreeLongTermLong",
        new LongCallback() {

          @Override
          public Long get() {
            synchronized (NodeClientCore.this) {
              return minDiskFreeLongTerm;
            }
          }

          @Override
          public void set(Long val) throws InvalidConfigValueException {
            synchronized (NodeClientCore.this) {
              if (val < 0) throw new InvalidConfigValueException(l10n("minDiskFreeMustBePositive"));
              minDiskFreeLongTerm = val;
            }
            updatePersistentRAFSpaceLimit();
          }
        },
        true);
    minDiskFreeLongTerm = nodeConfig.getLong("minDiskFreeLongTerm");

    nodeConfig.register(
        "minDiskFreeShortTerm",
        "512M",
        sortOrder + 1,
        true,
        true,
        "NodeClientCore.minDiskFreeShortTerm",
        "NodeClientCore.minDiskFreeShortTermLong",
        new LongCallback() {

          @Override
          public Long get() {
            synchronized (NodeClientCore.this) {
              return minDiskFreeShortTerm;
            }
          }

          @Override
          public void set(Long val) throws InvalidConfigValueException {
            synchronized (NodeClientCore.this) {
              if (val < 0) throw new InvalidConfigValueException(l10n("minDiskFreeMustBePositive"));
              minDiskFreeShortTerm = val;
            }
            tempBucketFactory.setMinDiskSpace(val);
          }
        },
        true);
    minDiskFreeShortTerm = nodeConfig.getLong("minDiskFreeShortTerm");
    // Do not register the UserAlert yet, since we haven't finished constructing stuff it uses.
  }

  boolean lateInitDatabase(DatabaseKey databaseKey) {
    LOG.info("Late database initialisation: starting middle phase");
    try {
      initStorage(databaseKey);
    } catch (MasterKeysWrongPasswordException _) {
      LOG.warn(
          "Late database initialisation failed: wrong master key/password provided (hasKey={}).",
          databaseKey != null);
      return false;
    }
    // Don't actually start the database thread yet, messy concurrency issues.
    fcpServer.load();
    LOG.info("Late database initialisation completed.");
    return true;
  }

  /**
   * Give ClientLayerPersister a filename and possibly an encryption key. May cause it to load, but
   * can also be called afterward to change where to write to.
   *
   * @param databaseKey The encryption key.
   * @throws MasterKeysWrongPasswordException If it needs an encryption key.
   */
  private void initStorage(DatabaseKey databaseKey) throws MasterKeysWrongPasswordException {
    getClientLayerPersister()
        .setFilesAndLoad(
            node.getNodeDir(),
            "client.dat",
            node.wantEncryptedDatabase(),
            node.wantNoPersistentDatabase(),
            databaseKey,
            requestStarters);
  }

  /** Must only be called after we have loaded master.keys */
  private void finishInitStorage() {
    boolean success = false;
    synchronized (this) {
      if (finishedInitStorage || finishingInitStorage) return;
      finishingInitStorage = true;
    }
    try {
      persistentTempBucketFactory
          .completedInit(); // Only GC persistent-temp after a successful load.
      success = true;
    } finally {
      synchronized (this) {
        finishingInitStorage = false;
        if (success) finishedInitStorage = true;
      }
    }
  }

  private static String l10n(String key) {
    return NodeL10n.getBase().getString("NodeClientCore." + key);
  }

  // Note: Use NodeL10n.getBase().getString("NodeClientCore.<key>", pattern, value) directly
  // when parameter substitution is needed.

  private void handleAsyncGetFinished(
      boolean isSSK,
      RequestCompletionListener listener,
      long startTime,
      Key key,
      boolean realTimeFlag,
      RequestSender rs,
      boolean rejectedOverload) {
    int status = rs.getStatus();
    if (status == RequestSender.NOT_FINISHED) {
      LOG.error("Bogus status in onRequestSenderFinished for {}", rs, new Exception("error"));
      listener.onFailed(new LowLevelGetException(LowLevelGetException.INTERNAL_ERROR));
      return;
    }

    if (isNonErrorStatus(status)) reportFetchCosts(isSSK, rs, status);

    if (status == RequestSender.TIMED_OUT || status == RequestSender.GENERATED_REJECTED_OVERLOAD) {
      handleTimeoutOrRejected(isSSK, realTimeFlag, startTime, key, rejectedOverload);
    } else if (rs.hasForwarded() && isForwardedTerminalStatus(status)) {
      handleForwardedStatuses(isSSK, realTimeFlag, startTime, key, status);
    }

    if (status == RequestSender.SUCCESS) {
      listener.onSucceeded();
      return;
    }
    handleStatusResult(isSSK, listener, rs, status);
  }

  private boolean isNonErrorStatus(int status) {
    return status != RequestSender.TIMED_OUT
        && status != RequestSender.GENERATED_REJECTED_OVERLOAD
        && status != RequestSender.INTERNAL_ERROR;
  }

  private void reportFetchCosts(boolean isSSK, RequestSender rs, int status) {
    if (LOG.isDebugEnabled())
      LOG.debug(
          "{} fetch cost {}/{}" + LOG_BYTES_OPEN + "{})",
          isSSK ? "SSK" : "CHK",
          rs.getTotalSentBytes(),
          rs.getTotalReceivedBytes(),
          status);
    (isSSK ? nodeStats.localSskFetchBytesSentAverage : nodeStats.localChkFetchBytesSentAverage)
        .report(rs.getTotalSentBytes());
    (isSSK
            ? nodeStats.localSskFetchBytesReceivedAverage
            : nodeStats.localChkFetchBytesReceivedAverage)
        .report(rs.getTotalReceivedBytes());
    if (status == RequestSender.SUCCESS)
      (isSSK
              ? nodeStats.successfulSskFetchBytesReceivedAverage
              : nodeStats.successfulChkFetchBytesReceivedAverage)
          .report(rs.getTotalReceivedBytes());
  }

  private boolean isForwardedTerminalStatus(int status) {
    return status == RequestSender.DATA_NOT_FOUND
        || status == RequestSender.RECENTLY_FAILED
        || status == RequestSender.SUCCESS
        || status == RequestSender.ROUTE_NOT_FOUND
        || status == RequestSender.VERIFY_FAILURE
        || status == RequestSender.GET_OFFER_VERIFY_FAILURE;
  }

  private FilenameGenerator createTempFilenameGeneratorOrThrow() throws NodeInitException {
    try {
      return new FilenameGenerator(random, true, getTempDir(), "temp-");
    } catch (IOException _) {
      String msg = "Could not find or create temporary directory (filename generator)";
      throw new NodeInitException(NodeInitException.EXIT_BAD_DIR, msg);
    }
  }

  private PersistentTempBucketFactory createPersistentTempBucketFactory(SubConfig nodeConfig)
      throws NodeInitException {
    try {
      return new PersistentTempBucketFactory(
          persistentTempDir.dir(),
          "freenet-temp-",
          node.getFastWeakRandom(),
          nodeConfig.getBoolean(CFG_ENCRYPT_PERSISTENT_TEMP_BUCKETS));
    } catch (IOException e) {
      String msg = "Could not find or create persistent temporary directory: " + e;
      LOG.error(msg, e);
      throw new NodeInitException(NodeInitException.EXIT_BAD_DIR, msg);
    }
  }

  private void deleteOldPersistentBlobIfPresent() {
    File oldBlobFile = new File(persistentTempDir.dir(), "persistent-blob.tmp");
    if (oldBlobFile.exists()) {
      LOG.info("Deleting {}", oldBlobFile);
      if (persistentTempBucketFactory.isEncrypting()) {
        try {
          FileUtil.secureDelete(oldBlobFile);
        } catch (IOException e) {
          LOG.warn("Unable to securely delete old blob file {}: {}", oldBlobFile, e.toString());
          LOG.warn("Please delete {} manually if it remains.", oldBlobFile);
        }
      } else {
        try {
          Files.delete(oldBlobFile.toPath());
        } catch (IOException e) {
          LOG.warn("Unable to delete old blob file {}: {}", oldBlobFile, e.toString());
        }
      }
    }
  }

  private int computeDefaultRamBucketPoolSize(long maxMemoryMb) {
    if (maxMemoryMb < 0) return 10;
    // 10% of memory above 64MB, with a minimum of 1MB.
    int sz = (int) Math.min(Integer.MAX_VALUE, ((maxMemoryMb - 64) / 10));
    if (sz <= 0) sz = 1;
    return sz;
  }

  private void handleTimeoutOrRejected(
      boolean isSSK, boolean realTimeFlag, long startTime, Key key, boolean rejectedOverload) {
    if (rejectedOverload) return;
    requestStarters.rejectedOverload(isSSK, false, realTimeFlag);
    long rtt = System.currentTimeMillis() - startTime;
    double targetLocation = key.toNormalizedDouble();
    if (isSSK) node.getNodeStats().reportSSKOutcome(rtt, false, realTimeFlag);
    else node.getNodeStats().reportCHKOutcome(rtt, false, targetLocation, realTimeFlag);
  }

  private void handleForwardedStatuses(
      boolean isSSK, boolean realTimeFlag, long startTime, Key key, int status) {
    long rtt = System.currentTimeMillis() - startTime;
    double targetLocation = key.toNormalizedDouble();
    requestStarters.requestCompleted(isSSK, false, key, realTimeFlag);
    requestStarters.getThrottle(isSSK, false, realTimeFlag).successfulCompletion(rtt);
    if (isSSK)
      node.getNodeStats().reportSSKOutcome(rtt, status == RequestSender.SUCCESS, realTimeFlag);
    else
      node.getNodeStats()
          .reportCHKOutcome(rtt, status == RequestSender.SUCCESS, targetLocation, realTimeFlag);
    if (status == RequestSender.SUCCESS) {
      LOG.debug("Successful {} fetch took {}", isSSK ? "SSK" : "CHK", rtt);
    }
  }

  private void handleStatusResult(
      boolean isSSK, RequestCompletionListener listener, RequestSender rs, int status) {
    switch (status) {
      case RequestSender.NOT_FINISHED:
        LOG.error("RS still running in get{}!: {}", isSSK ? "SSK" : "CHK", rs);
        listener.onFailed(new LowLevelGetException(LowLevelGetException.INTERNAL_ERROR));
        return;
      case RequestSender.DATA_NOT_FOUND:
        listener.onFailed(new LowLevelGetException(LowLevelGetException.DATA_NOT_FOUND));
        return;
      case RequestSender.RECENTLY_FAILED:
        listener.onFailed(new LowLevelGetException(LowLevelGetException.RECENTLY_FAILED));
        return;
      case RequestSender.ROUTE_NOT_FOUND:
        listener.onFailed(new LowLevelGetException(LowLevelGetException.ROUTE_NOT_FOUND));
        return;
      case RequestSender.TRANSFER_FAILED, RequestSender.GET_OFFER_TRANSFER_FAILED:
        listener.onFailed(new LowLevelGetException(LowLevelGetException.TRANSFER_FAILED));
        return;
      case RequestSender.VERIFY_FAILURE, RequestSender.GET_OFFER_VERIFY_FAILURE:
        listener.onFailed(new LowLevelGetException(LowLevelGetException.VERIFY_FAILED));
        return;
      case RequestSender.GENERATED_REJECTED_OVERLOAD, RequestSender.TIMED_OUT:
        listener.onFailed(new LowLevelGetException(LowLevelGetException.REJECTED_OVERLOAD));
        return;
      case RequestSender.INTERNAL_ERROR:
        listener.onFailed(new LowLevelGetException(LowLevelGetException.INTERNAL_ERROR));
        return;
      default:
        LOG.error(
            "Unknown RequestSender code in get{}: {} on {}", isSSK ? "SSK" : "CHK", status, rs);
        listener.onFailed(new LowLevelGetException(LowLevelGetException.INTERNAL_ERROR));
    }
  }

  private ArchiveManager createArchiveManager() {
    return new ArchiveManager(
        MAX_ARCHIVE_HANDLERS,
        MAX_CACHED_ARCHIVE_DATA,
        MAX_ARCHIVED_FILE_SIZE,
        MAX_CACHED_ELEMENTS,
        tempBucketFactory);
  }

  private HealingQueue createHealingQueue() {
    return new SimpleHealingQueue(
        new InsertContext(
            0,
            2,
            0,
            0,
            new SimpleEventProducer(),
            false,
            Node.FORK_ON_CACHEABLE_DEFAULT,
            false,
            Compressor.DEFAULT_COMPRESSORDESCRIPTOR,
            0,
            0,
            InsertContext.CompatibilityMode.COMPAT_DEFAULT),
        RequestStarter.PREFETCH_PRIORITY_CLASS,
        MAX_RUNNING_HEALING_INSERTS,
        new HealingDecisionSupplier(node::getLocation, node::isOpennetEnabled));
  }

  private int computeMaxMemoryLimitedJobThreads() {
    int maxThreads = Runtime.getRuntime().availableProcessors() / 2;
    maxThreads = Math.min(maxThreads, node.getNodeStats().getThreadLimit() / 20);
    return Math.max(1, maxThreads);
  }

  private long computeDefaultMemoryLimitedJobMemoryLimit(long overallMemoryLimit) {
    long limit = FECCodec.MIN_MEMORY_ALLOCATION;
    if (overallMemoryLimit > 512L * 1024 * 1024) {
      limit += (overallMemoryLimit - 512L * 1024 * 1024) / 20;
    }
    return limit;
  }

  private RequestStarterGroup createRequestStarters(
      Node node, int portNumber, Config config, SimpleFieldSet throttleFS)
      throws NodeInitException {
    try {
      return new RequestStarterGroup(
          node, this, portNumber, random, config, throttleFS, clientContext);
    } catch (InvalidConfigValueException e1) {
      throw new NodeInitException(NodeInitException.EXIT_BAD_CONFIG, e1.toString());
    }
  }

  private void setupSecretAndInitStorage(DatabaseKey databaseKey, MasterSecret persistentSecret) {
    if (persistentSecret != null) {
      setupMasterSecret(persistentSecret);
    }
    try {
      initStorage(databaseKey);
    } catch (MasterKeysWrongPasswordException _) {
      LOG.warn("Cannot load persistent requests, awaiting password ...");
      node.setDatabaseAwaitingPassword();
    }
  }

  private void installPhysicalThreatLevelListener() {
    node.getSecurityLevels()
        .addPhysicalThreatLevelListener(
            (oldLevel, newLevel) -> onPhysicalThreatLevelChanged(newLevel));
  }

  private void onPhysicalThreatLevelChanged(PHYSICAL_THREAT_LEVEL newLevel) {
    applyEncryptionForLevel(newLevel);
    maybeReloadStorageAfterThreatChange();
  }

  private void applyEncryptionForLevel(PHYSICAL_THREAT_LEVEL newLevel) {
    final boolean enable = (newLevel != PHYSICAL_THREAT_LEVEL.LOW);
    if (tempBucketFactory.isEncrypting() != enable) {
      tempBucketFactory.setEncryption(enable);
    }
    if (persistentTempBucketFactory != null
        && persistentTempBucketFactory.isEncrypting() != enable) {
      persistentTempBucketFactory.setEncryption(enable);
    }
    persistentRAFFactory.setEncryption(enable);
  }

  private void maybeReloadStorageAfterThreatChange() {
    if (!getClientLayerPersister().hasLoaded()) return;
    try {
      // May need to change filenames for client.dat* or even create them.
      initStorage(NodeClientCore.this.getNode().getDatabaseKey());
    } catch (MasterKeysWrongPasswordException _) {
      NodeClientCore.this.getNode().setDatabaseAwaitingPassword();
    }
  }

  private void installFecShutdownHooks(SemiOrderedShutdownHook shutdownHook) {
    shutdownHook.addEarlyJob(
        new NativeThread("Shutdown FEC", NativeThread.PriorityLevel.HIGH_PRIORITY.value, true) {

          @Override
          public void realRun() {
            LOG.info("Stopping FEC decode threads...");
            memoryLimitedJobRunner.shutdown();
          }
        });
    shutdownHook.addLateJob(
        new NativeThread("Shutdown FEC", NativeThread.PriorityLevel.HIGH_PRIORITY.value, true) {

          @Override
          public void realRun() {
            memoryLimitedJobRunner.waitForShutdown();
            LOG.info("FEC decoding threads finished.");
          }
        });
  }

  private void installCoreShutdownHooks(SemiOrderedShutdownHook shutdownHook) {
    shutdownHook.addEarlyJob(
        new NativeThread(
            "Shutdown RealCompressor", NativeThread.PriorityLevel.HIGH_PRIORITY.value, true) {
          @Override
          public void realRun() {
            compressor.shutdown();
          }
        });

    shutdownHook.addEarlyJob(
        new NativeThread(
            "Shutdown database", NativeThread.PriorityLevel.HIGH_PRIORITY.value, true) {

          @Override
          public void realRun() {
            LOG.warn("Stopping database jobs...");
            getClientLayerPersister().shutdown();
          }
        });

    shutdownHook.addLateJob(
        new NativeThread("Close database", NativeThread.PriorityLevel.HIGH_PRIORITY.value, true) {

          @Override
          public void realRun() {
            if (NodeClientCore.this.getNode().hasPanicked()) return;
            LOG.info("Waiting for jobs to finish");
            getClientLayerPersister().waitForIdleAndCheckpoint();
            LOG.info("Saved persistent requests to disk");
          }
        });
  }

  private SimpleUserAlert createStartingUpAlert() {
    return new SimpleUserAlert(
        true,
        l10n("startingUpTitle"),
        l10n("startingUp"),
        l10n("startingUpShort"),
        UserAlert.ERROR);
  }

  private void registerFProxyAlerts() {
    this.alerts.register(startingUpAlert);
    this.alerts.register(
        new SimpleUserAlert(
            true,
            NodeL10n.getBase().getString("QueueToadlet.persistenceBrokenTitle"),
            NodeL10n.getBase()
                .getString(
                    "QueueToadlet.persistenceBroken",
                    new String[] {"TEMPDIR", "DBFILE"},
                    new String[] {
                      new File(FileUtil.getCanonicalFile(getPersistentTempDir()), File.separator)
                          .toString(),
                      new File(FileUtil.getCanonicalFile(node.getUserDir()), "client.dat")
                          .toString()
                    }),
            NodeL10n.getBase().getString("QueueToadlet.persistenceBrokenShortAlert"),
            UserAlert.CRITICAL_ERROR) {
          @Override
          public boolean isValid() {
            synchronized (NodeClientCore.this) {
              if (!killedDatabase()) return false;
            }
            if (NodeClientCore.this.node.awaitingPassword()) return false;
            return !NodeClientCore.this.node.isStopping();
          }

          @Override
          public boolean userCanDismiss() {
            return false;
          }
        });
  }

  private TextModeClientInterfaceServer initTmci(Config config) {
    return TextModeClientInterfaceServer.maybeCreate(node, this, config);
  }

  private FCPServer initFcp(Node node) throws NodeInitException {
    FCPServer server = FCPServer.maybeCreate(node, this, node.getConfig(), fcpPersistentRoot);
    getClientContext().setDownloadCache(server);
    if (!killedDatabase()) server.load();
    return server;
  }

  private static int registerMaxBackgroundUSKFetchers(SubConfig nodeConfig, int sortOrder) {
    nodeConfig.register(
        "maxBackgroundUSKFetchers",
        "64",
        sortOrder,
        true,
        false,
        "NodeClientCore.maxUSKFetchers",
        "NodeClientCore.maxUSKFetchersLong",
        new IntCallback() {

          @Override
          public Integer get() {
            return maxBackgroundUSKFetchers;
          }

          @Override
          public void set(Integer uskFetch) throws InvalidConfigValueException {
            if (uskFetch <= 0)
              throw new InvalidConfigValueException(l10n("maxUSKFetchersMustBeGreaterThanZero"));
            maxBackgroundUSKFetchers = uskFetch;
          }
        },
        Dimension.NOT);
    maxBackgroundUSKFetchers = nodeConfig.getInt("maxBackgroundUSKFetchers");
    return sortOrder + 1;
  }

  private int registerDownloadAllowedDirs(SubConfig nodeConfig, int sortOrder) {
    nodeConfig.register(
        "downloadAllowedDirs",
        new String[] {"all"},
        sortOrder,
        true,
        true,
        "NodeClientCore.downloadAllowedDirs",
        "NodeClientCore.downloadAllowedDirsLong",
        new StringArrCallback() {

          @Override
          public String[] get() {
            synchronized (NodeClientCore.this) {
              if (downloadAllowedEverywhere) return new String[] {"all"};
              String[] dirs = new String[downloadAllowedDirs.length + (includeDownloadDir ? 1 : 0)];
              for (int i = 0; i < downloadAllowedDirs.length; i++)
                dirs[i] = downloadAllowedDirs[i].getPath();
              if (includeDownloadDir) dirs[downloadAllowedDirs.length] = DOWNLOADS_DIR_NAME;
              return dirs;
            }
          }

          @Override
          public void set(String[] val) {
            setDownloadAllowedDirs(val);
          }
        });
    setDownloadAllowedDirs(nodeConfig.getStringArr("downloadAllowedDirs"));
    return sortOrder + 1;
  }

  private int registerUploadAllowedDirs(SubConfig nodeConfig, int sortOrder) {
    nodeConfig.register(
        "uploadAllowedDirs",
        new String[] {"all"},
        sortOrder,
        true,
        true,
        "NodeClientCore.uploadAllowedDirs",
        "NodeClientCore.uploadAllowedDirsLong",
        new StringArrCallback() {

          @Override
          public String[] get() {
            synchronized (NodeClientCore.this) {
              if (uploadAllowedEverywhere) return new String[] {"all"};
              String[] dirs = new String[uploadAllowedDirs.length];
              for (int i = 0; i < uploadAllowedDirs.length; i++)
                dirs[i] = uploadAllowedDirs[i].getPath();
              return dirs;
            }
          }

          @Override
          public void set(String[] val) {
            setUploadAllowedDirs(val);
          }
        });
    setUploadAllowedDirs(nodeConfig.getStringArr("uploadAllowedDirs"));
    return sortOrder + 1;
  }

  private int registerMemoryLimitedJobThreadLimit(
      SubConfig nodeConfig, int sortOrder, int maxMemoryLimitedJobThreads) {
    nodeConfig.register(
        "memoryLimitedJobThreadLimit",
        maxMemoryLimitedJobThreads,
        sortOrder,
        true,
        false,
        "NodeClientCore.memoryLimitedJobThreadLimit",
        "NodeClientCore.memoryLimitedJobThreadLimitLong",
        new IntCallback() {

          @Override
          public Integer get() {
            return memoryLimitedJobRunner.getMaxThreads();
          }

          @Override
          public void set(Integer val) throws InvalidConfigValueException {
            if (val < 1)
              throw new InvalidConfigValueException(l10n("memoryLimitedJobThreadLimitMustBe1Plus"));
            memoryLimitedJobRunner.setMaxThreads(val);
          }
        },
        false);
    return sortOrder + 1;
  }

  private int registerMemoryLimitedJobMemoryLimit(
      SubConfig nodeConfig, int sortOrder, long defaultMemoryLimitedJobMemoryLimit) {
    nodeConfig.register(
        "memoryLimitedJobMemoryLimit",
        defaultMemoryLimitedJobMemoryLimit,
        sortOrder,
        true,
        false,
        "NodeClientCore.memoryLimitedJobMemoryLimit",
        "NodeClientCore.memoryLimitedJobMemoryLimitLong",
        new LongCallback() {

          @Override
          public Long get() {
            return memoryLimitedJobRunner.getCapacity();
          }

          @Override
          public void set(Long val) throws InvalidConfigValueException {
            if (val < FECCodec.MIN_MEMORY_ALLOCATION)
              throw new InvalidConfigValueException(
                  NodeL10n.getBase()
                      .getString(
                          "NodeClientCore.memoryLimitedJobMemoryLimitMustBeAtLeast",
                          "min",
                          SizeUtil.formatSize(FECCodec.MIN_MEMORY_ALLOCATION)));
            memoryLimitedJobRunner.setCapacity(val);
          }
        },
        true);
    return sortOrder + 1;
  }

  @SuppressWarnings("UnusedReturnValue")
  private int registerAlwaysCommit(SubConfig nodeConfig, int sortOrder) {
    nodeConfig.register(
        "alwaysCommit",
        false,
        sortOrder,
        true,
        false,
        "NodeClientCore.alwaysCommit",
        "NodeClientCore.alwaysCommitLong",
        new BooleanCallback() {

          @Override
          public Boolean get() {
            return alwaysCommit;
          }

          @Override
          public void set(Boolean val) {
            alwaysCommit = val;
          }
        });
    return sortOrder + 1;
  }

  private int registerMaxRamBucketSize(SubConfig nodeConfig, int sortOrder, long maxBucketSize) {
    nodeConfig.register(
        "maxRAMBucketSize",
        SizeUtil.formatSizeWithoutSpace(maxBucketSize),
        sortOrder,
        true,
        false,
        "NodeClientCore.maxRAMBucketSize",
        "NodeClientCore.maxRAMBucketSizeLong",
        new LongCallback() {

          @Override
          public Long get() {
            return (tempBucketFactory == null ? 0 : tempBucketFactory.getMaxRAMBucketSize());
          }

          @Override
          public void set(Long val) {
            if (get().equals(val) || (tempBucketFactory == null)) return;
            tempBucketFactory.setMaxRAMBucketSize(val);
          }
        },
        true);
    return sortOrder + 1;
  }

  private int registerRamBucketPoolSize(
      SubConfig nodeConfig, int sortOrder, int defaultRamBucketPoolSize) {
    nodeConfig.register(
        "RAMBucketPoolSize",
        defaultRamBucketPoolSize + "MiB",
        sortOrder,
        true,
        false,
        "NodeClientCore.ramBucketPoolSize",
        "NodeClientCore.ramBucketPoolSizeLong",
        new LongCallback() {

          @Override
          public Long get() {
            return (tempBucketFactory == null ? 0 : tempBucketFactory.getMaxRamUsed());
          }

          @Override
          public void set(Long val) {
            if (get().equals(val) || (tempBucketFactory == null)) return;
            tempBucketFactory.setMaxRamUsed(val);
            updatePersistentRAFSpaceLimit();
          }
        },
        true);
    return sortOrder + 1;
  }

  private int registerEncryptTempBuckets(SubConfig nodeConfig, int sortOrder) {
    nodeConfig.register(
        "encryptTempBuckets",
        true,
        sortOrder,
        true,
        false,
        "NodeClientCore.encryptTempBuckets",
        "NodeClientCore.encryptTempBucketsLong",
        new BooleanCallback() {

          @Override
          public Boolean get() {
            return (tempBucketFactory == null || tempBucketFactory.isEncrypting());
          }

          @Override
          public void set(Boolean val) {
            if (get().equals(val) || (tempBucketFactory == null)) return;
            tempBucketFactory.setEncryption(val);
          }
        });
    return sortOrder + 1;
  }

  private int registerEncryptPersistentTempBuckets(SubConfig nodeConfig, int sortOrder) {
    nodeConfig.register(
        CFG_ENCRYPT_PERSISTENT_TEMP_BUCKETS,
        true,
        sortOrder,
        true,
        false,
        "NodeClientCore.encryptPersistentTempBuckets",
        "NodeClientCore.encryptPersistentTempBucketsLong",
        new BooleanCallback() {

          @Override
          public Boolean get() {
            return (persistentTempBucketFactory == null
                || persistentTempBucketFactory.isEncrypting());
          }

          @Override
          public void set(Boolean val) {
            if (get().equals(val) || (persistentTempBucketFactory == null)) return;
            persistentTempBucketFactory.setEncryption(val);
            persistentRAFFactory.setEncryption(val);
          }
        });
    return sortOrder + 1;
  }

  private void deleteLegacyTempDirIfPresent(Node node) {
    File oldTemp = node.runDir().file("temp-" + node.getDarknetPortNumber());
    if (oldTemp.exists() && oldTemp.isDirectory() && !FileUtil.equals(tempDir.dir, oldTemp)) {
      LOG.info("Deleting old temporary dir: {}", oldTemp);
      try {
        FileUtil.secureDeleteAll(oldTemp);
      } catch (IOException _) {
        // Ignore.
      }
    }
  }

  private Path resolveDefaultCacheDir() {
    AppEnv appEnv = new AppEnv();
    if (appEnv.isServiceMode()) {
      ServiceDirs serviceDirs = new ServiceDirs();
      Resolved resolved = serviceDirs.resolve();
      return resolved.getCacheDir();
    } else {
      AppDirs dirs = new AppDirs();
      Resolved resolved = dirs.resolve();
      return resolved.getCacheDir();
    }
  }

  private Path resolveDefaultDataDir() {
    AppEnv appEnv = new AppEnv();
    if (appEnv.isServiceMode()) {
      ServiceDirs serviceDirs = new ServiceDirs();
      Resolved resolved = serviceDirs.resolve();
      return resolved.getDataDir();
    } else {
      AppDirs dirs = new AppDirs();
      Resolved resolved = dirs.resolve();
      return resolved.getDataDir();
    }
  }

  private int registerLazyStartDatastoreChecker(SubConfig nodeConfig, int sortOrder) {
    nodeConfig.register(
        "lazyStartDatastoreChecker",
        false,
        sortOrder,
        true,
        false,
        "NodeClientCore.lazyStartDatastoreChecker",
        "NodeClientCore.lazyStartDatastoreCheckerLong",
        new BooleanCallback() {

          @Override
          public Boolean get() {
            synchronized (NodeClientCore.this) {
              return lazyStartDatastoreChecker;
            }
          }

          @Override
          public void set(Boolean val) throws NodeNeedRestartException {
            synchronized (NodeClientCore.this) {
              final boolean newValue = Boolean.TRUE.equals(val);
              if (newValue != lazyStartDatastoreChecker) {
                lazyStartDatastoreChecker = newValue;
                throw new NodeNeedRestartException(
                    l10n("lazyStartDatastoreCheckerMustRestartNode"));
              }
            }
          }
        });
    lazyStartDatastoreChecker = nodeConfig.getBoolean("lazyStartDatastoreChecker");
    return sortOrder + 1;
  }

  /**
   * Returns whether downloads are globally disabled by configuration.
   *
   * <p>When disabled, no target directory is considered eligible, regardless of the allowlist.
   *
   * @return {@code true} when all downloads are disabled.
   */
  public boolean isDownloadDisabled() {
    return downloadDisabled;
  }

  /**
   * Configures directories where downloads may be written.
   *
   * <p>Recognized entries: - {@code "all"}: allow any destination. - {@code downloads}: allow the
   * configured downloads directory. - any other string is treated as a filesystem path.
   *
   * <p>Passing an empty array disables downloads.
   *
   * @param val allowlist entries as described above.
   */
  protected synchronized void setDownloadAllowedDirs(String[] val) {
    int x = 0;
    downloadAllowedEverywhere = false;
    includeDownloadDir = false;
    downloadDisabled = false;
    int i;
    downloadAllowedDirs = new File[val.length];
    for (i = 0; i < downloadAllowedDirs.length; i++) {
      String s = val[i];
      if (s.equals(DOWNLOADS_DIR_NAME)) includeDownloadDir = true;
      else if (s.equals("all")) downloadAllowedEverywhere = true;
      else downloadAllowedDirs[x++] = new File(val[i]);
    }
    if (x != i) {
      downloadAllowedDirs = Arrays.copyOf(downloadAllowedDirs, x);
    }
    if (i == 0) {
      downloadDisabled = true;
    }
  }

  /**
   * Configures directories from which uploads may read.
   *
   * <p>Recognized entries: - {@code "all"}: allow any source. - any other string is treated as a
   * filesystem path.
   *
   * @param val allowlist entries as described above.
   */
  protected synchronized void setUploadAllowedDirs(String[] val) {
    int x = 0;
    int i;
    uploadAllowedEverywhere = false;
    uploadAllowedDirs = new File[val.length];
    for (i = 0; i < uploadAllowedDirs.length; i++) {
      String s = val[i];
      if (s.equals("all")) uploadAllowedEverywhere = true;
      else uploadAllowedDirs[x++] = new File(val[i]);
    }
    if (x != i) {
      uploadAllowedDirs = Arrays.copyOf(uploadAllowedDirs, x);
    }
  }

  /**
   * Starts client-layer services and resumes persisted requests.
   *
   * <p>Side effects: - Starts request starters, the datastore checker, FCP/TMCI servers (when
   * configured), and plugins. - Schedules asynchronous completion to migrate legacy buckets and
   * resume pending requests.
   */
  public void start() {

    persister.start();

    requestStarters.start();

    storeChecker.start();
    if (fcpServer != null) fcpServer.maybeStart();
    node.getPluginManager().start();
    node.getIpDetector().ipDetectorManager.start();
    if (tmci != null) tmci.start();

    node.getExecutor()
        .execute(
            new PrioRunnable() {

              @Override
              public void run() {
                LOG.info("Resuming persistent requests");
                if (node.getDatabaseKey() != null) {
                  try {
                    finishInitStorage();
                  } catch (Exception t) {
                    LOG.error("Failed to migrate and/or cleanup persistent temp buckets: {}", t, t);
                    // Start the rest of the node anyway ...
                  }
                }
                LOG.info("Completed startup: All persistent requests resumed or restarted");
                alerts.unregister(startingUpAlert);
              }

              @Override
              public int getPriority() {
                return NativeThread.PriorityLevel.LOW_PRIORITY.value;
              }
            },
            "Startup completion thread");
  }

  /**
   * Generates a random UID for requests.
   *
   * <p>Note: {@code -1} is reserved internally and is never returned. If a peer uses {@code -1} it
   * is merely scheduled more slowly (round-robin with no-UID messages).
   */
  long makeUID() {
    while (true) {
      long uid = random.nextLong();
      if (uid != -1) return uid;
    }
  }

  /**
   * Starts an asynchronous fetch for a key.
   *
   * <p>If the data is found locally the listener is notified and no network request is started. If
   * a request is started, the listener receives completion or failure callbacks; some successful
   * outcomes may be delivered via the pending-keys mechanism instead of the listener.
   *
   * @param key key to fetch.
   * @param offersOnly when {@code true}, fetch only from nodes that have offered the key (via
   *     GetOfferedKeys); no regular routing is used.
   * @param listener callback for completion and most failure cases.
   * @param canReadClientCache whether the request may read the client cache.
   * @param canWriteClientCache whether the request may write the client cache.
   * @param realTimeFlag {@code true} for latency-optimized requests; {@code false} for
   *     throughput-optimized (bulk) requests.
   * @param localOnly when {@code true}, check only the datastore and do not create a network
   *     request on miss.
   * @param ignoreStore when {@code true}, skip the datastore and create a request immediately.
   */
  public void asyncGet(
      final Key key,
      boolean offersOnly,
      final RequestCompletionListener listener,
      boolean canReadClientCache,
      boolean canWriteClientCache,
      final boolean realTimeFlag,
      boolean localOnly,
      boolean ignoreStore) {
    final long uid = makeUID();
    final boolean isSSK = key instanceof NodeSSK;
    final RequestTag tag =
        new RequestTag(isSSK, RequestTag.START.ASYNC_GET, null, realTimeFlag, uid, node);
    if (!tracker.lockUID(uid, isSSK, false, false, true, realTimeFlag, tag)) {
      LOG.error(MSG_CANNOT_LOCK_UID + "{}" + MSG_BROKEN_PRNG, uid);
      listener.onFailed(
          new LowLevelGetException(
              LowLevelGetException.INTERNAL_ERROR,
              "Could not lock random UID - serious PRNG problem???"));
      return;
    }
    tag.setAccepted();
    short htl = node.maxHTL();
    // If another node requested it within the ULPR period at a lower HTL, that may allow
    // us to cache it in the datastore. Find the lowest HTL fetching the key in that period,
    // and use that for purposes of deciding whether to cache it in the store.
    if (offersOnly) {
      htl = node.getFailureTable().minOfferedHTL(key, htl);
      if (LOG.isDebugEnabled()) LOG.debug("Using old HTL for GetOfferedKey: {}", htl);
    }
    final long startTime = System.currentTimeMillis();
    asyncGet(
        key,
        offersOnly,
        uid,
        new RequestSenderListener() {

          private boolean rejectedOverload;

          @Override
          public void onCHKTransferBegins() {
            // Ignore
          }

          @Override
          public void onReceivedRejectOverload() {
            synchronized (this) {
              if (rejectedOverload) return;
              rejectedOverload = true;
            }
            requestStarters.rejectedOverload(isSSK, false, realTimeFlag);
          }

          @Override
          public void onDataFoundLocally() {
            tag.unlockHandler();
            listener.onSucceeded();
          }

          /**
           * The RequestSender finished.
           *
           * @param status The completion status code reported by the sender.
           * @param fromOfferedKey {@code true} if this completion originated from an offered-key
           *     fetch path (GetOfferedKeys); {@code false} for a normal fetch.
           */
          @Override
          public void onRequestSenderFinished(
              int status, boolean fromOfferedKey, RequestSender rs) {
            tag.unlockHandler();
            boolean rejectedOverloadLocal;
            synchronized (this) {
              rejectedOverloadLocal = this.rejectedOverload;
            }
            handleAsyncGetFinished(
                isSSK, listener, startTime, key, realTimeFlag, rs, rejectedOverloadLocal);
          }

          @Override
          public void onNotStarted(boolean internalError) {
            if (internalError)
              listener.onFailed(new LowLevelGetException(LowLevelGetException.INTERNAL_ERROR));
            else
              listener.onFailed(
                  new LowLevelGetException(LowLevelGetException.DATA_NOT_FOUND_IN_STORE));
          }
        },
        tag,
        canReadClientCache,
        canWriteClientCache,
        htl,
        realTimeFlag,
        localOnly,
        ignoreStore);
  }

  /**
   * Start an asynchronous fetch of the key in question, which will complete to the datastore. It
   * will not decode the data because we don't provide a ClientKey. It will not return anything and
   * will run asynchronously. Caller is responsible for unlocking the UID.
   *
   * @param key The key being fetched.
   * @param offersOnly If true, only fetch the key from nodes that have offered it, using
   *     GetOfferedKeys, don't do a normal fetch for it.
   * @param uid The UID of the request. This should already be locked, see the tag.
   * @param tag The RequestTag for the request. In case of an error when starting it we will unlock
   *     it, but in other cases the listener should unlock it.
   * @param listener Will be called by the request sender, if a request is started. However, for
   *     example, if we fetch it from the store, it will be returned via the tripPendingKeys
   *     mechanism.
   * @param canReadClientCache Can this request read the client-cache?
   * @param canWriteClientCache Can this request write the client-cache?
   * @param htl The HTL to start the request at. See the caller, this can be modified in the case of
   *     fetching an offered key.
   * @param realTimeFlag Is this a real-time request? False = this is a bulk request.
   * @param localOnly If true, only check the datastore, don't create a request if nothing is found.
   * @param ignoreStore If true, don't check the datastore, create a request immediately.
   */
  @SuppressWarnings("java:S1181")
  void asyncGet(
      Key key,
      boolean offersOnly,
      long uid,
      RequestSenderListener listener,
      RequestTag tag,
      boolean canReadClientCache,
      boolean canWriteClientCache,
      short htl,
      boolean realTimeFlag,
      boolean localOnly,
      boolean ignoreStore) {
    try {
      Object o =
          node.makeRequestSender(
              key,
              htl,
              uid,
              tag,
              null,
              Node.RequestSenderOptions.of(
                  localOnly,
                  ignoreStore,
                  offersOnly,
                  canReadClientCache,
                  canWriteClientCache,
                  realTimeFlag));
      if (o instanceof KeyBlock) {
        tag.setServedFromDatastore();
        listener.onDataFoundLocally();
        return; // Already have it.
      }
      if (o == null) {
        listener.onNotStarted(false);
        tag.unlockHandler();
        return;
      }
      RequestSender rs = (RequestSender) o;
      rs.addListener(listener);
      if (rs.uid != uid) tag.unlockHandler();
      // Else it has started a request.
      if (LOG.isDebugEnabled()) LOG.debug("Started {} for {} for {}", o, uid, key);
    } catch (RuntimeException | Error e) {
      LOG.error("Caught error trying to start request: {}", e, e);
      listener.onNotStarted(true);
    }
  }

  /**
   * Synchronously fetches a block for a client key.
   *
   * <p>Depending on {@code localOnly} and {@code ignoreStore}, this may read from the datastore or
   * perform a network request. On success, returns a verified client block.
   *
   * @param key client key (CHK or SSK).
   * @param localOnly when {@code true}, check only the datastore and do not create a network
   *     request on miss.
   * @param ignoreStore when {@code true}, skip the datastore and create a request immediately.
   * @param canWriteClientCache whether the request may write the client cache.
   * @param realTimeFlag {@code true} for latency-optimized requests; {@code false} for bulk.
   * @return verified client block.
   * @throws LowLevelGetException on not found, transfer failure, verify failure, or internal error.
   */
  public ClientKeyBlock realGetKey(
      ClientKey key,
      boolean localOnly,
      boolean ignoreStore,
      boolean canWriteClientCache,
      boolean realTimeFlag)
      throws LowLevelGetException {
    return switch (key) {
      case ClientCHK hK ->
          realGetCHK(hK, localOnly, ignoreStore, canWriteClientCache, realTimeFlag);
      case ClientSSK sK ->
          realGetSSK(sK, localOnly, ignoreStore, canWriteClientCache, realTimeFlag);
      default -> throw new IllegalArgumentException("Not a CHK or SSK: " + key);
    };
  }

  /**
   * Fetches a CHK block, optionally via the network.
   *
   * @param key the client CHK to fetch.
   * @param localOnly when {@code true}, check only the datastore and do not create a network
   *     request on miss.
   * @param ignoreStore when {@code true}, skip the datastore and create a network request
   *     immediately.
   * @param canWriteClientCache whether the request may write the client cache. Reads from the
   *     client cache are always allowed for local requests; some callers disable writes to avoid
   *     cache pollution.
   * @param realTimeFlag {@code true} for latency-optimized routing; {@code false} for bulk.
   * @return the verified client CHK block.
   * @throws LowLevelGetException if the data is not found, recently failed, transfer fails, verify
   *     fails, or on internal error.
   */
  ClientCHKBlock realGetCHK(
      ClientCHK key,
      boolean localOnly,
      boolean ignoreStore,
      boolean canWriteClientCache,
      boolean realTimeFlag)
      throws LowLevelGetException {
    long startTime = System.currentTimeMillis();
    long uid = makeUID();
    RequestTag tag = new RequestTag(false, RequestTag.START.LOCAL, null, realTimeFlag, uid, node);
    if (!tracker.lockUID(uid, false, false, false, true, realTimeFlag, tag)) {
      LOG.error(MSG_CANNOT_LOCK_UID + "{}" + MSG_BROKEN_PRNG, uid);
      throw new LowLevelGetException(LowLevelGetException.INTERNAL_ERROR);
    }
    tag.setAccepted();
    RequestSender rs;
    try {
      Object o =
          node.makeRequestSender(
              key.getNodeCHK(),
              node.maxHTL(),
              uid,
              tag,
              null,
              Node.RequestSenderOptions.of(
                  localOnly, ignoreStore, false, true, canWriteClientCache, realTimeFlag));
      if (o instanceof CHKBlock block)
        try {
          tag.setServedFromDatastore();
          return new ClientCHKBlock(block, key);
        } catch (CHKVerifyException e) {
          LOG.error(LOG_DOES_NOT_VERIFY + "{}", e, e);
          throw new LowLevelGetException(LowLevelGetException.DECODE_FAILED);
        }
      if (o == null) throw new LowLevelGetException(LowLevelGetException.DATA_NOT_FOUND_IN_STORE);
      rs = (RequestSender) o;
      return processChkRequestLoop(rs, key, startTime, realTimeFlag);
    } finally {
      tag.unlockHandler();
    }
  }

  private ClientCHKBlock processChkRequestLoop(
      RequestSender rs, ClientCHK key, long startTime, boolean realTimeFlag)
      throws LowLevelGetException {
    boolean rejectedOverload = false;
    short waitStatus = 0;
    while (true) {
      waitStatus = rs.waitUntilStatusChange(waitStatus);
      rejectedOverload =
          checkAndReportRejectedOverload(rejectedOverload, waitStatus, false, realTimeFlag);

      int status = rs.getStatus();
      if (status == RequestSender.NOT_FINISHED) continue;

      maybeReportFetchCosts(false, rs, status);

      if (status == RequestSender.TIMED_OUT
          || status == RequestSender.GENERATED_REJECTED_OVERLOAD
          || (rs.hasForwarded() && isForwardedTerminalStatus(status))) {
        maybeHandleTimeoutOrForwarded(
            false, realTimeFlag, startTime, key.getNodeCHK(), rs, status, rejectedOverload);
      }

      ClientCHKBlock maybe = tryReturnChkBlock(rs, key, status);
      if (maybe != null) return maybe;
      throwForGetStatus(status, rs);
    }
  }

  private boolean checkAndReportRejectedOverload(
      boolean alreadyRejected, short waitStatus, boolean isSSK, boolean realTimeFlag) {
    if (!alreadyRejected && (waitStatus & RequestSender.WAIT_REJECTED_OVERLOAD) != 0) {
      requestStarters.rejectedOverload(isSSK, false, realTimeFlag);
      return true;
    }
    return alreadyRejected;
  }

  private void maybeReportFetchCosts(boolean isSSK, RequestSender rs, int status) {
    if (isNonErrorStatus(status)) {
      reportFetchCosts(isSSK, rs, status);
    }
  }

  private void maybeHandleTimeoutOrForwarded(
      boolean isSSK,
      boolean realTimeFlag,
      long startTime,
      Key key,
      RequestSender rs,
      int status,
      boolean rejectedOverload) {
    if (status == RequestSender.TIMED_OUT || status == RequestSender.GENERATED_REJECTED_OVERLOAD) {
      handleTimeoutOrRejected(isSSK, realTimeFlag, startTime, key, rejectedOverload);
    } else if (rs.hasForwarded() && isForwardedTerminalStatus(status)) {
      handleForwardedStatuses(isSSK, realTimeFlag, startTime, key, status);
    }
  }

  private ClientCHKBlock tryReturnChkBlock(RequestSender rs, ClientCHK key, int status)
      throws LowLevelGetException {
    if (status == RequestSender.SUCCESS)
      try {
        return new ClientCHKBlock(rs.getPRB().getBlock(), rs.getHeaders(), key, true);
      } catch (CHKVerifyException e) {
        LOG.error(LOG_DOES_NOT_VERIFY + "{}", e, e);
        throw new LowLevelGetException(LowLevelGetException.DECODE_FAILED);
      } catch (AbortedException e) {
        LOG.error("Impossible: {}", e, e);
        throw new LowLevelGetException(LowLevelGetException.INTERNAL_ERROR);
      }
    return null;
  }

  private void throwForGetStatus(int status, RequestSender rs) throws LowLevelGetException {
    switch (status) {
      case RequestSender.NOT_FINISHED:
        LOG.error("RS still running in get!: {}", rs);
        throw new LowLevelGetException(LowLevelGetException.INTERNAL_ERROR);
      case RequestSender.DATA_NOT_FOUND:
        throw new LowLevelGetException(LowLevelGetException.DATA_NOT_FOUND);
      case RequestSender.RECENTLY_FAILED:
        throw new LowLevelGetException(LowLevelGetException.RECENTLY_FAILED);
      case RequestSender.ROUTE_NOT_FOUND:
        throw new LowLevelGetException(LowLevelGetException.ROUTE_NOT_FOUND);
      case RequestSender.TRANSFER_FAILED, RequestSender.GET_OFFER_TRANSFER_FAILED:
        throw new LowLevelGetException(LowLevelGetException.TRANSFER_FAILED);
      case RequestSender.VERIFY_FAILURE, RequestSender.GET_OFFER_VERIFY_FAILURE:
        throw new LowLevelGetException(LowLevelGetException.VERIFY_FAILED);
      case RequestSender.GENERATED_REJECTED_OVERLOAD, RequestSender.TIMED_OUT:
        throw new LowLevelGetException(LowLevelGetException.REJECTED_OVERLOAD);
      case RequestSender.INTERNAL_ERROR:
      default:
        LOG.error("Unknown RequestSender code in get: {} on {}", status, rs);
        throw new LowLevelGetException(LowLevelGetException.INTERNAL_ERROR);
    }
  }

  ClientSSKBlock realGetSSK(
      ClientSSK key,
      boolean localOnly,
      boolean ignoreStore,
      boolean canWriteClientCache,
      boolean realTimeFlag)
      throws LowLevelGetException {
    long startTime = System.currentTimeMillis();
    long uid = makeUID();
    RequestTag tag = new RequestTag(true, RequestTag.START.LOCAL, null, realTimeFlag, uid, node);
    if (!tracker.lockUID(uid, true, false, false, true, realTimeFlag, tag)) {
      LOG.error(MSG_CANNOT_LOCK_UID + "{}" + MSG_BROKEN_PRNG, uid);
      throw new LowLevelGetException(LowLevelGetException.INTERNAL_ERROR);
    }
    tag.setAccepted();
    RequestSender rs;
    try {
      Object o =
          node.makeRequestSender(
              key.getNodeKey(true),
              node.maxHTL(),
              uid,
              tag,
              null,
              Node.RequestSenderOptions.of(
                  localOnly, ignoreStore, false, true, canWriteClientCache, realTimeFlag));
      if (o instanceof SSKBlock block)
        try {
          tag.setServedFromDatastore();
          key.setPublicKey(block.getPubKey());
          return ClientSSKBlock.construct(block, key);
        } catch (SSKVerifyException e) {
          LOG.error(LOG_DOES_NOT_VERIFY + "{}", e, e);
          throw new LowLevelGetException(LowLevelGetException.DECODE_FAILED);
        }
      if (o == null) throw new LowLevelGetException(LowLevelGetException.DATA_NOT_FOUND_IN_STORE);
      rs = (RequestSender) o;
      return processSskRequestLoop(rs, key, startTime, realTimeFlag);
    } finally {
      tag.unlockHandler();
    }
  }

  private ClientSSKBlock processSskRequestLoop(
      RequestSender rs, ClientSSK key, long startTime, boolean realTimeFlag)
      throws LowLevelGetException {
    boolean rejectedOverload = false;
    short waitStatus = 0;
    while (true) {
      waitStatus = rs.waitUntilStatusChange(waitStatus);
      rejectedOverload =
          checkAndReportRejectedOverload(rejectedOverload, waitStatus, true, realTimeFlag);

      int status = rs.getStatus();
      if (status == RequestSender.NOT_FINISHED) continue;

      maybeReportFetchCosts(true, rs, status);

      if (status == RequestSender.TIMED_OUT
          || status == RequestSender.GENERATED_REJECTED_OVERLOAD
          || (rs.hasForwarded() && isForwardedTerminalStatus(status))) {
        maybeHandleTimeoutOrForwarded(
            true, realTimeFlag, startTime, key.getNodeKey(true), rs, status, rejectedOverload);
      }

      if (status == RequestSender.SUCCESS) {
        try {
          SSKBlock block = rs.getSSKBlock();
          key.setPublicKey(block.getPubKey());
          return ClientSSKBlock.construct(block, key);
        } catch (SSKVerifyException e) {
          LOG.error(LOG_DOES_NOT_VERIFY + "{}", e, e);
          throw new LowLevelGetException(LowLevelGetException.DECODE_FAILED);
        }
      }
      if (status == RequestSender.TRANSFER_FAILED
          || status == RequestSender.GET_OFFER_TRANSFER_FAILED) {
        LOG.error("Unexpected transfer failure on an SSK for uid {}", (Object) null);
      }
      throwForGetStatus(status, rs);
    }
  }

  /**
   * Inserts a block into the network.
   *
   * <p>Accepts either CHK or SSK blocks. Reinserts may be performed depending on the block type and
   * flags.
   *
   * @param block block to insert.
   * @param canWriteClientCache whether the insert may update the client cache.
   * @param forkOnCacheable whether to fork when the block is cacheable.
   * @param preferInsert whether to prefer insert to other strategies when applicable.
   * @param ignoreLowBackoff whether to ignore low backoff during routing.
   * @param realTimeFlag {@code true} for latency-optimized; {@code false} for bulk.
   * @throws LowLevelPutException on route failure, overload, or internal error.
   */
  public void realPut(
      KeyBlock block,
      boolean canWriteClientCache,
      boolean forkOnCacheable,
      boolean preferInsert,
      boolean ignoreLowBackoff,
      boolean realTimeFlag)
      throws LowLevelPutException {
    switch (block) {
      case CHKBlock kBlock1 ->
          realPutCHK(
              kBlock1,
              canWriteClientCache,
              forkOnCacheable,
              preferInsert,
              ignoreLowBackoff,
              realTimeFlag);
      case SSKBlock kBlock ->
          realPutSSK(
              kBlock,
              canWriteClientCache,
              forkOnCacheable,
              preferInsert,
              ignoreLowBackoff,
              realTimeFlag);
      default -> throw new IllegalArgumentException("Unknown put type " + block.getClass());
    }
  }

  public void realPutCHK(
      CHKBlock block,
      boolean canWriteClientCache,
      boolean forkOnCacheable,
      boolean preferInsert,
      boolean ignoreLowBackoff,
      boolean realTimeFlag)
      throws LowLevelPutException {
    byte[] data = block.getData();
    byte[] headers = block.getHeaders();
    PartiallyReceivedBlock prb =
        new PartiallyReceivedBlock(Node.PACKETS_IN_BLOCK, Node.PACKET_SIZE, data);
    CHKInsertSender is;
    long uid = makeUID();
    InsertTag tag = new InsertTag(false, InsertTag.START.LOCAL, null, realTimeFlag, uid, node);
    if (!tracker.lockUID(uid, false, true, false, true, realTimeFlag, tag)) {
      LOG.error(MSG_CANNOT_LOCK_UID + "{}" + MSG_BROKEN_PRNG, uid);
      throw new LowLevelPutException(LowLevelPutException.INTERNAL_ERROR);
    }
    tag.setAccepted();
    try {
      long startTime = System.currentTimeMillis();
      is =
          node.makeInsertSender(
              block.getKey(),
              node.maxHTL(),
              uid,
              tag,
              null,
              Node.ChkInsertOptions.of(headers, prb)
                  .withFromStore(false)
                  .withCanWriteClientCache(canWriteClientCache)
                  .withForkOnCacheable(forkOnCacheable)
                  .withPreferInsert(preferInsert)
                  .withIgnoreLowBackoff(ignoreLowBackoff)
                  .withRealTimeFlag(realTimeFlag));
      boolean hasReceivedRejectedOverload = awaitChkCompletion(is, realTimeFlag);

      if (LOG.isDebugEnabled())
        LOG.debug(
            "Completed {} overload={} {}", uid, hasReceivedRejectedOverload, is.getStatusString());

      maybeReportChkCompleted(is, uid, startTime, realTimeFlag, block);

      // Get status explicitly, *after* completed(), so that it will be RECEIVE_FAILED if the
      // receive failed.
      int status = is.getStatus();
      reportChkInsertCosts(status, is);
      storeChkLocally(is, block, canWriteClientCache);

      logChkInsertResult(status, is, block);
      if (status != CHKInsertSender.SUCCESS) {
        throwForChkPutStatus(is);
      }
    } finally {
      tag.unlockHandler();
    }
  }

  private void maybeReportChkCompleted(
      CHKInsertSender is, long uid, long startTime, boolean realTimeFlag, CHKBlock block) {
    if (is.sentRequest()
        && (is.uid == uid)
        && ((is.getStatus() == CHKInsertSender.ROUTE_NOT_FOUND)
            || (is.getStatus() == CHKInsertSender.SUCCESS))) {
      long endTime = System.currentTimeMillis();
      long len = endTime - startTime;
      requestStarters.getThrottle(false, true, realTimeFlag).successfulCompletion(len);
      requestStarters.requestCompleted(false, true, block.getKey(), realTimeFlag);
    }
  }

  private void reportChkInsertCosts(int status, CHKInsertSender is) {
    if (status != CHKInsertSender.TIMED_OUT
        && status != CHKInsertSender.GENERATED_REJECTED_OVERLOAD
        && status != CHKInsertSender.INTERNAL_ERROR
        && status != CHKInsertSender.ROUTE_REALLY_NOT_FOUND) {
      int sent = is.getTotalSentBytes();
      int received = is.getTotalReceivedBytes();
      if (LOG.isDebugEnabled())
        LOG.debug("Local CHK insert cost {}/{}" + LOG_BYTES_OPEN + "{})", sent, received, status);
      nodeStats.localChkInsertBytesSentAverage.report(sent);
      nodeStats.localChkInsertBytesReceivedAverage.report(received);
      if (status == CHKInsertSender.SUCCESS)
        nodeStats.successfulChkInsertBytesSentAverage.report(sent);
    }
  }

  private void storeChkLocally(CHKInsertSender is, CHKBlock block, boolean canWriteClientCache) {
    boolean deep =
        node.shouldStoreDeep(block.getKey(), null, is == null ? new PeerNode[0] : is.getRoutedTo());
    try {
      node.store(block, deep, canWriteClientCache, false, false);
    } catch (KeyCollisionException _) {
      // CHKs don't collide
    }
  }

  private void logChkInsertResult(int status, CHKInsertSender is, CHKBlock block) {
    if (status == CHKInsertSender.SUCCESS) {
      LOG.info("Succeeded inserting {}", block);
    } else {
      String msg = "Failed inserting " + block + " : " + is.getStatusString();
      if (status == CHKInsertSender.ROUTE_NOT_FOUND)
        msg +=
            " - this is normal on small networks; the data will still be propagated, but it can't"
                + " find the 20+ nodes needed for full success";
      if (is.getStatus() != CHKInsertSender.ROUTE_NOT_FOUND) LOG.error(msg);
      else LOG.info(msg);
    }
  }

  private boolean awaitChkCompletion(CHKInsertSender is, boolean realTimeFlag) {
    boolean overloaded = awaitChkInitialStatus(is, realTimeFlag);
    return awaitChkFinalCompletion(is, realTimeFlag, overloaded);
  }

  private boolean awaitChkInitialStatus(CHKInsertSender is, boolean realTimeFlag) {
    boolean hasReceivedRejectedOverload = false;
    while (true) {
      if (is.getStatus() == CHKInsertSender.NOT_FINISHED) {
        is.waitIfNotFinished(SECONDS.toMillis(5));
      }
      if (is.getStatus() != CHKInsertSender.NOT_FINISHED) break;
      if ((!hasReceivedRejectedOverload) && is.receivedRejectedOverload()) {
        hasReceivedRejectedOverload = true;
        requestStarters.rejectedOverload(false, true, realTimeFlag);
      }
    }
    return hasReceivedRejectedOverload;
  }

  private boolean awaitChkFinalCompletion(
      CHKInsertSender is, boolean realTimeFlag, boolean hasReceivedRejectedOverload) {
    while (!is.completed()) {
      is.waitIfNotCompleted(SECONDS.toMillis(10));
      if (is.anyTransfersFailed() && (!hasReceivedRejectedOverload)) {
        hasReceivedRejectedOverload = true; // not strictly true but same effect
        requestStarters.rejectedOverload(false, true, realTimeFlag);
      }
    }
    return hasReceivedRejectedOverload;
  }

  private void throwForChkPutStatus(CHKInsertSender is) throws LowLevelPutException {
    switch (is.getStatus()) {
      case CHKInsertSender.NOT_FINISHED:
        LOG.error("IS still running in putCHK!: {}", is);
        throw new LowLevelPutException(LowLevelPutException.INTERNAL_ERROR);
      case CHKInsertSender.GENERATED_REJECTED_OVERLOAD, CHKInsertSender.TIMED_OUT:
        throw new LowLevelPutException(LowLevelPutException.REJECTED_OVERLOAD);
      case CHKInsertSender.ROUTE_NOT_FOUND:
        throw new LowLevelPutException(LowLevelPutException.ROUTE_NOT_FOUND);
      case CHKInsertSender.ROUTE_REALLY_NOT_FOUND:
        throw new LowLevelPutException(LowLevelPutException.ROUTE_REALLY_NOT_FOUND);
      case CHKInsertSender.INTERNAL_ERROR:
      default:
        LOG.error("Unknown CHKInsertSender code in putCHK: {} on {}", is.getStatus(), is);
        throw new LowLevelPutException(LowLevelPutException.INTERNAL_ERROR);
    }
  }

  /**
   * Inserts an SSK block.
   *
   * @param block SSK block to insert.
   * @param canWriteClientCache whether the insert may update the client cache.
   * @param forkOnCacheable whether to fork when the block is cacheable.
   * @param preferInsert whether to prefer insert to other strategies when applicable.
   * @param ignoreLowBackoff whether to ignore low backoff during routing.
   * @param realTimeFlag {@code true} for latency-optimized; {@code false} for bulk.
   * @throws LowLevelPutException on collision, route failure, overload, or internal error.
   */
  public void realPutSSK(
      SSKBlock block,
      boolean canWriteClientCache,
      boolean forkOnCacheable,
      boolean preferInsert,
      boolean ignoreLowBackoff,
      boolean realTimeFlag)
      throws LowLevelPutException {
    SSKInsertSender is;
    long uid = makeUID();
    InsertTag tag = new InsertTag(true, InsertTag.START.LOCAL, null, realTimeFlag, uid, node);
    if (!tracker.lockUID(uid, true, true, false, true, realTimeFlag, tag)) {
      LOG.error(MSG_CANNOT_LOCK_UID + "{}" + MSG_BROKEN_PRNG, uid);
      throw new LowLevelPutException(LowLevelPutException.INTERNAL_ERROR);
    }
    tag.setAccepted();
    try {
      long startTime = System.currentTimeMillis();
      // Be consistent: use the client cache to check for collisions as this is a local insert.
      SSKBlock altBlock =
          node.fetch(block.getKey(), false, true, canWriteClientCache, false, false, null);
      if (altBlock != null && !altBlock.equals(block)) throw new LowLevelPutException(altBlock);
      is =
          node.makeInsertSender(
              block,
              node.maxHTL(),
              uid,
              tag,
              null,
              Node.SskInsertOptions.of()
                  .withFromStore(false)
                  .withCanWriteClientCache(canWriteClientCache)
                  .withCanWriteDatastore(false)
                  .withForkOnCacheable(forkOnCacheable)
                  .withPreferInsert(preferInsert)
                  .withIgnoreLowBackoff(ignoreLowBackoff)
                  .withRealTimeFlag(realTimeFlag));
      boolean hasReceivedRejectedOverload = awaitSskCompletion(is, realTimeFlag);

      if (LOG.isDebugEnabled())
        LOG.debug(
            "Completed {} overload={} {}", uid, hasReceivedRejectedOverload, is.getStatusString());

      // Finished?
      maybeReportSskCompleted(is, uid, startTime, realTimeFlag, block, hasReceivedRejectedOverload);

      int status = is.getStatus();

      reportSskInsertCosts(status, is);
      handleSskCollisionOrStore(is, block, canWriteClientCache);

      logSskInsertResult(status, is, block);
      if (status != SSKInsertSender.SUCCESS) {
        throwForSskPutStatus(is);
      }
    } finally {
      tag.unlockHandler();
    }
  }

  private boolean awaitSskCompletion(SSKInsertSender is, boolean realTimeFlag) {
    boolean overloaded = awaitSskInitialStatus(is, realTimeFlag);
    return awaitSskFinalCompletion(is, overloaded);
  }

  private boolean awaitSskInitialStatus(SSKInsertSender is, boolean realTimeFlag) {
    boolean hasReceivedRejectedOverload = false;
    while (true) {
      if (is.getStatus() == SSKInsertSender.NOT_FINISHED) {
        is.waitIfNotFinished(SECONDS.toMillis(5));
      }
      if (is.getStatus() != SSKInsertSender.NOT_FINISHED) break;
      if ((!hasReceivedRejectedOverload) && is.receivedRejectedOverload()) {
        hasReceivedRejectedOverload = true;
        requestStarters.rejectedOverload(true, true, realTimeFlag);
      }
    }
    return hasReceivedRejectedOverload;
  }

  private boolean awaitSskFinalCompletion(SSKInsertSender is, boolean hasReceivedRejectedOverload) {
    while (is.getStatus() == SSKInsertSender.NOT_FINISHED) {
      is.waitIfNotFinished(SECONDS.toMillis(10));
    }
    return hasReceivedRejectedOverload;
  }

  private void throwForSskPutStatus(SSKInsertSender is) throws LowLevelPutException {
    switch (is.getStatus()) {
      case SSKInsertSender.NOT_FINISHED:
        LOG.error("IS still running in putCHK!: {}", is);
        throw new LowLevelPutException(LowLevelPutException.INTERNAL_ERROR);
      case SSKInsertSender.GENERATED_REJECTED_OVERLOAD, SSKInsertSender.TIMED_OUT:
        throw new LowLevelPutException(LowLevelPutException.REJECTED_OVERLOAD);
      case SSKInsertSender.ROUTE_NOT_FOUND:
        throw new LowLevelPutException(LowLevelPutException.ROUTE_NOT_FOUND);
      case SSKInsertSender.ROUTE_REALLY_NOT_FOUND:
        throw new LowLevelPutException(LowLevelPutException.ROUTE_REALLY_NOT_FOUND);
      case SSKInsertSender.INTERNAL_ERROR:
      default:
        LOG.error("Unknown CHKInsertSender code in putSSK: {} on {}", is.getStatus(), is);
        throw new LowLevelPutException(LowLevelPutException.INTERNAL_ERROR);
    }
  }

  private void reportSskInsertCosts(int status, SSKInsertSender is) {
    if (status != CHKInsertSender.TIMED_OUT
        && status != CHKInsertSender.GENERATED_REJECTED_OVERLOAD
        && status != CHKInsertSender.INTERNAL_ERROR
        && status != CHKInsertSender.ROUTE_REALLY_NOT_FOUND) {
      int sent = is.getTotalSentBytes();
      int received = is.getTotalReceivedBytes();
      if (LOG.isDebugEnabled())
        LOG.debug("Local SSK insert cost {}/{}" + LOG_BYTES_OPEN + "{})", sent, received, status);
      nodeStats.localSskInsertBytesSentAverage.report(sent);
      nodeStats.localSskInsertBytesReceivedAverage.report(received);
      if (status == SSKInsertSender.SUCCESS)
        nodeStats.successfulSskInsertBytesSentAverage.report(sent);
    }
  }

  private void maybeReportSskCompleted(
      SSKInsertSender is,
      long uid,
      long startTime,
      boolean realTimeFlag,
      SSKBlock block,
      boolean hasReceivedRejectedOverload) {
    if (!hasReceivedRejectedOverload
        && is.sentRequest()
        && (is.uid == uid)
        && ((is.getStatus() == SSKInsertSender.ROUTE_NOT_FOUND)
            || (is.getStatus() == SSKInsertSender.SUCCESS))) {
      long endTime = System.currentTimeMillis();
      long rtt = endTime - startTime;
      requestStarters.requestCompleted(true, true, block.getKey(), realTimeFlag);
      requestStarters.getThrottle(true, true, realTimeFlag).successfulCompletion(rtt);
    }
  }

  private void handleSskCollisionOrStore(
      SSKInsertSender is, SSKBlock block, boolean canWriteClientCache) throws LowLevelPutException {
    boolean deep =
        node.shouldStoreDeep(block.getKey(), null, is == null ? new PeerNode[0] : is.getRoutedTo());

    if (is != null && is.hasCollided()) {
      SSKBlock collided = is.getBlock();
      try {
        node.storeInsert(collided, deep, true, canWriteClientCache, false);
      } catch (KeyCollisionException e) {
        LOG.info("collision race? is={}", is, e);
      }
      throw new LowLevelPutException(collided);
    }
    try {
      node.storeInsert(block, deep, false, canWriteClientCache, false);
    } catch (KeyCollisionException e) {
      NodeSSK key = block.getKey();
      KeyBlock collided = node.fetch(key, true, canWriteClientCache, false, false, null);
      if (collided == null) {
        LOG.error("Collided but no key?!");
        try {
          node.store(block, false, canWriteClientCache, false, false);
        } catch (KeyCollisionException _) {
          LOG.error("Collided but no key and still collided!");
          throw new LowLevelPutException(
              LowLevelPutException.INTERNAL_ERROR,
              "Collided, can't find block, but still collides!",
              e);
        }
      }
      throw new LowLevelPutException(collided);
    }
  }

  private void logSskInsertResult(int status, SSKInsertSender is, SSKBlock block) {
    if (status == SSKInsertSender.SUCCESS) {
      LOG.info("Succeeded inserting {}", block);
    } else {
      String msg = "Failed inserting " + block + " : " + is.getStatusString();
      if (status == CHKInsertSender.ROUTE_NOT_FOUND)
        msg +=
            " - this is normal on small networks; the data will still be propagated, but it can't"
                + " find the 20+ nodes needed for full success";
      if (is.getStatus() != SSKInsertSender.ROUTE_NOT_FOUND) LOG.error(msg);
      else LOG.info(msg);
    }
  }

  /**
   * Creates a high-level client bound to this core.
   *
   * @param prioClass priority class for requests started by the client.
   * @param forceDontIgnoreTooManyPathComponents whether to disable path-component pruning for
   *     requests that would otherwise ignore excessive path components.
   * @param realTimeFlag {@code true} for latency-optimized requests; {@code false} for
   *     throughput-optimized (bulk) requests. Fewer latency-optimized requests are accepted, but
   *     they tend to complete faster; bulk requests may run more continuously.
   * @return a configured {@link HighLevelSimpleClient} instance.
   */
  public HighLevelSimpleClient makeClient(
      short prioClass, boolean forceDontIgnoreTooManyPathComponents, boolean realTimeFlag) {
    return new HighLevelSimpleClientImpl(
        this,
        tempBucketFactory,
        random,
        prioClass,
        forceDontIgnoreTooManyPathComponents,
        realTimeFlag);
  }

  /** Returns the FCP server, or {@code null} when disabled. */
  public FCPServer getFCPServer() {
    return fcpServer;
  }

  /** Returns the FProxy toadlet when available. */
  public FProxyToadlet getFProxy() {
    return fproxyServlet;
  }

  /** Returns the HTTP toadlet container for client UI endpoints. */
  public SimpleToadletServer getToadletContainer() {
    return toadletContainer;
  }

  /**
   * Returns the link filter exception provider of the node. At the moment this is the {@link
   * #getToadletContainer() toadlet container}.
   *
   * @return The link filter exception provider
   */
  public LinkFilterExceptionProvider getLinkFilterExceptionProvider() {
    return toadletContainer;
  }

  /** Returns the Text Mode Client Interface (TMCI) server, or {@code null} when disabled. */
  public TextModeClientInterfaceServer getTextModeClientInterface() {
    return tmci;
  }

  /** Sets the active FProxy toadlet instance. */
  public void setFProxy(FProxyToadlet fproxy) {
    this.fproxyServlet = fproxy;
  }

  /** Returns the direct (in-process) TMCI instance, if set. */
  public TextModeClientInterface getDirectTMCI() {
    return directTMCI;
  }

  /** Sets the direct (in-process) TMCI instance. */
  public void setDirectTMCI(TextModeClientInterface i) {
    this.directTMCI = i;
  }

  /** Returns the configured downloads directory. */
  public File getDownloadsDir() {
    return downloadsDir.dir();
  }

  /** Returns the program-directory wrapper for the downloads directory. */
  public ProgramDirectory downloadsDir() {
    return downloadsDir;
  }

  /** Returns the queue used for healing reinserts. */
  @SuppressWarnings("unused")
  public HealingQueue getHealingQueue() {
    return healingQueue;
  }

  public void queueRandomReinsert(KeyBlock block) {
    SimpleSendableInsert ssi =
        new SimpleSendableInsert(this, block, RequestStarter.MAXIMUM_PRIORITY_CLASS);
    if (LOG.isDebugEnabled()) LOG.debug("Queueing random reinsert for {} : {}", block, ssi);
    ssi.schedule();
  }

  /** Persists the current configuration to disk. */
  public void storeConfig() {
    LOG.info("Trying to write config to disk");
    node.getConfig().store();
  }

  /** Returns whether the node runs in testnet mode. */
  @SuppressWarnings("unused")
  public boolean isTestnetEnabled() {
    return Node.isTestnetEnabled();
  }

  /** Returns whether advanced-mode UI features are enabled in FProxy. */
  public boolean isAdvancedModeEnabled() {
    return (getToadletContainer() != null) && getToadletContainer().isAdvancedModeEnabled();
  }

  /** Returns whether JavaScript is enabled in FProxy. */
  public boolean isFProxyJavascriptEnabled() {
    return (getToadletContainer() != null) && getToadletContainer().isFProxyJavascriptEnabled();
  }

  /** Returns the node's user-visible name. */
  public String getMyName() {
    return node.getMyName();
  }

  /**
   * Creates a read filter callback bound to the HTTP UI context.
   *
   * @param uri source URI for the filter.
   * @param cb sink invoked for each found URI.
   * @return a {@link FilterCallback} suitable for content filtering.
   */
  public FilterCallback createFilterCallback(URI uri, FoundURICallback cb) {
    if (LOG.isDebugEnabled()) LOG.debug("Creating filter callback: {}, {}", uri, cb);
    return new GenericReadFilterCallback(uri, cb, null, toadletContainer);
  }

  /** Returns the configured maximum number of background USK fetchers. */
  @SuppressWarnings("unused")
  public int maxBackgroundUSKFetchers() {
    return maxBackgroundUSKFetchers;
  }

  /**
   * Returns whether a file path is permitted as a download target.
   *
   * <p>Respects the physical threat level (denies at {@code MAXIMUM}) and the configured allowlist
   * including the downloads directory when enabled.
   *
   * @param filename target file path.
   * @return {@code true} when writing under {@code filename} is allowed.
   */
  public boolean allowDownloadTo(File filename) {
    PHYSICAL_THREAT_LEVEL physicalThreatLevel = node.getSecurityLevels().getPhysicalThreatLevel();
    if (physicalThreatLevel == PHYSICAL_THREAT_LEVEL.MAXIMUM) return false;
    synchronized (this) {
      if (downloadAllowedEverywhere) return true;
      if (includeDownloadDir && FileUtil.isParent(getDownloadsDir(), filename)) return true;
      for (File dir : downloadAllowedDirs) {
        if (dir == null) {
          // Debug mysterious NPE...
          LOG.error("Null in upload allowed dirs???");
          continue;
        }
        if (FileUtil.isParent(dir, filename)) return true;
      }
      return false;
    }
  }

  /**
   * Returns whether a file path is permitted as an upload source according to the configured
   * allowlist.
   *
   * @param filename source file path.
   * @return {@code true} when reading from {@code filename} is allowed.
   */
  public synchronized boolean allowUploadFrom(File filename) {
    if (uploadAllowedEverywhere) return true;
    for (File dir : uploadAllowedDirs) {
      if (dir == null) {
        // Debug mysterious NPE...
        LOG.error("Null in upload allowed dirs???");
        continue;
      }
      if (FileUtil.isParent(dir, filename)) return true;
    }
    return false;
  }

  /** Returns the current allowlist for download destinations. */
  public synchronized File[] getAllowedDownloadDirs() {
    return downloadAllowedDirs;
  }

  /** Returns the current allowlist for upload sources. */
  public synchronized File[] getAllowedUploadDirs() {
    return uploadAllowedDirs;
  }

  /**
   * Serializes client throttle state to a field set for persistence.
   *
   * @return throttles encoded as a {@link SimpleFieldSet}.
   */
  @Override
  public SimpleFieldSet persistThrottlesToFieldSet() {
    return requestStarters.persistToFieldSet();
  }

  /** Returns the node's shared ticker for timing and scheduling. */
  public Ticker getTicker() {
    return node.getTicker();
  }

  /** Returns the node's priority-aware executor for background tasks. */
  public PriorityAwareExecutor getExecutor() {
    return node.getExecutor();
  }

  /** Returns the directory used for persistent temporary buckets. */
  public File getPersistentTempDir() {
    return persistentTempDir.dir();
  }

  /** Returns the directory used for ephemeral temporary buckets. */
  public File getTempDir() {
    return tempDir.dir();
  }

  /**
   * Queues a key that has been offered by peers to be fetched opportunistically.
   *
   * @param key key to queue.
   * @param realTime whether to queue on the real-time scheduler.
   */
  public void queueOfferedKey(Key key, boolean realTime) {
    ClientRequestScheduler sched =
        requestStarters.getScheduler(key instanceof NodeSSK, false, realTime);
    sched.queueOfferedKey(key, realTime);
  }

  /** Removes a previously queued offered key from both bulk and real-time schedulers. */
  public void dequeueOfferedKey(Key key) {
    ClientRequestScheduler sched =
        requestStarters.getScheduler(key instanceof NodeSSK, false, false);
    sched.dequeueOfferedKey(key);
    sched = requestStarters.getScheduler(key instanceof NodeSSK, false, true);
    sched.dequeueOfferedKey(key);
  }

  /** Returns the bookmark manager used by the HTTP UI. */
  public BookmarkManager getBookmarkManager() {
    return toadletContainer.getBookmarks();
  }

  /** Returns the list of configured bookmark URIs. */
  public FreenetURI[] getBookmarkURIs() {
    return toadletContainer.getBookmarkURIs();
  }

  /** Returns the total number of requests currently queued across schedulers. */
  public long countQueuedRequests() {
    return requestStarters.countQueuedRequests();
  }

  /** Returns the global cap on background USK fetchers. */
  public static int getMaxBackgroundUSKFetchers() {
    return maxBackgroundUSKFetchers;
  }

  // Security note: If tunneling or similar distance-start mechanisms are introduced,
  // revisit this behavior. See RequestHandler onAbort() handler.
  /**
   * Returns whether any fetch scheduler wants the given key.
   *
   * @param key key to test.
   * @return {@code true} if either real-time or bulk scheduler wants the key.
   */
  public boolean wantKey(Key key) {
    boolean isSSK = key instanceof NodeSSK;
    if (this.clientContext.getFetchScheduler(isSSK, true).wantKey(key)) return true;
    return this.clientContext.getFetchScheduler(isSSK, false).wantKey(key);
  }

  /**
   * Estimates the recency of failures for routing decisions.
   *
   * <p>Performs a local probe equivalent to how {@link RequestSender} considers recent failures for
   * a key at the originator, ensuring comparable behavior to running requests.
   *
   * @param key target key.
   * @param realTime when {@code true}, use real-time routing heuristics; otherwise bulk.
   * @return a non-negative value indicating how recently the key failed (units are internal).
   */
  public long checkRecentlyFailed(Key key, boolean realTime) {
    RecentlyFailedReturn r = new RecentlyFailedReturn();
    // Mirror originator behavior by decrementing HTL here so results match RequestSender’s
    // routing heuristics. If originator rules change, revisit this.
    short origHTL = node.decrementHTL(null, node.maxHTL());
    node.getPeers()
        .closerPeer(
            null,
            new HashSet<>(),
            key.toNormalizedDouble(),
            true,
            false,
            -1,
            null,
            2.0,
            key,
            origHTL,
            0,
            true,
            realTime,
            r,
            false,
            System.currentTimeMillis(),
            node.enableNewLoadManagement(realTime));
    return r.recentlyFailed();
  }

  /** Returns the plugin stores accessor for this node. */
  public PluginStores getPluginStores() {
    return pluginStores;
  }

  /** Minimum free-disk threshold for long-running jobs, in bytes. */
  public synchronized long getMinDiskFreeLongTerm() {
    return minDiskFreeLongTerm;
  }

  /** Minimum free-disk threshold for short, disk-heavy jobs, in bytes. */
  public synchronized long getMinDiskFreeShortTerm() {
    return minDiskFreeShortTerm;
  }

  /**
   * Returns whether the client-layer database has been killed or not loaded.
   *
   * @return {@code true} if persistence is unavailable.
   */
  public boolean killedDatabase() {
    return this.getClientLayerPersister().isKilledOrNotLoaded();
  }

  /** Returns the set of currently persisted FCP requests. */
  public ClientRequest[] getPersistentRequests() {
    return fcpPersistentRoot.getPersistentRequests();
  }

  /**
   * Installs the persistent master secret for encrypted resources and factories.
   *
   * @param persistentSecret master secret to use.
   */
  public void setupMasterSecret(MasterSecret persistentSecret) {
    if (getClientContext().getPersistentMasterSecret() == null)
      getClientContext().setPersistentMasterSecret(persistentSecret);
    getPersistentTempBucketFactory().setMasterSecret(persistentSecret);
    persistentRAFFactory.setMasterSecret(persistentSecret);
  }

  /** Returns whether the client-layer database has been loaded. */
  public boolean loadedDatabase() {
    return getClientLayerPersister().hasLoaded();
  }

  /** Returns the component that persists bandwidth statistics. */
  public PersistentStatsPutter getBandwidthStatsPutter() {
    return bandwidthStatsPutter;
  }

  /** Returns the USK manager. */
  public USKManager getUskManager() {
    return uskManager;
  }

  /** Returns the group of request starters and schedulers. */
  public RequestStarterGroup getRequestStarters() {
    return requestStarters;
  }

  /** Returns the anti-CSRF token expected by HTTP handlers. */
  public String getFormPassword() {
    return formPassword;
  }

  /** Returns the generator used for temporary filenames. */
  public FilenameGenerator getTempFilenameGenerator() {
    return tempFilenameGenerator;
  }

  /** Returns the generator used for persistent temporary filenames. */
  public FilenameGenerator getPersistentFilenameGenerator() {
    return persistentFilenameGenerator;
  }

  /** Returns the factory for ephemeral temporary buckets. */
  public TempBucketFactory getTempBucketFactory() {
    return tempBucketFactory;
  }

  /** Returns the factory for persistent temporary buckets. */
  public PersistentTempBucketFactory getPersistentTempBucketFactory() {
    return persistentTempBucketFactory;
  }

  /** Returns the client-layer persister. */
  public ClientLayerPersister getClientLayerPersister() {
    return clientLayerPersister;
  }

  /** Returns the owning node. */
  public Node getNode() {
    return node;
  }

  /** Returns the node statistics sink used for reporting costs and outcomes. */
  public NodeStats getNodeStats() {
    return nodeStats;
  }

  /** Returns the non-cryptographic random source used by this component. */
  public RandomSource getRandom() {
    return random;
  }

  /** Returns the user-alert manager. */
  public UserAlertManager getAlerts() {
    return alerts;
  }

  /** Returns the datastore consistency checker. */
  public DatastoreChecker getStoreChecker() {
    return storeChecker;
  }

  /** Returns the client context shared with higher-level client APIs. */
  public ClientContext getClientContext() {
    return clientContext;
  }
}
